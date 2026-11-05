"""Pinned local CPU TinyBERT cross-encoder in a persistent isolated subprocess.

Only ranking features use bounded token windows. Outputs contain source IDs and
verified original offsets, never rewritten/truncated payload sources. The final
delivery controller returns whole source IDs. No external inference/API calls.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
REVISION = "858a1ac046a05663a35367eac852d7f76feeefdd"
CODE_COMMIT = "11f7a40d625f2de047c371c81c6f477386c18bb1"
PINNED_RUNTIME = {"numpy": "1.26.4", "onnxruntime": "1.22.1", "tokenizers": "0.21.4"}


def verify_assets(root):
    root = Path(root).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("model_revision") != REVISION or manifest.get("code_commit") != CODE_COMMIT:
        raise ValueError("reranker_revision_not_pinned")
    for relative, digest in manifest["file_sha256"].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("reranker_asset_integrity_failure")
    models = [root / relative for relative in manifest["file_sha256"]
              if Path(relative).name == "flashrank-TinyBERT-L-2-v2.onnx"]
    if len(models) != 1:
        raise ValueError("exactly_one_pinned_onnx_model_required")
    return manifest, models[0]


def _window_spans(tokenizer, query, source, max_length):
    text = source["text"]
    query_tokens = len(tokenizer.encode(query, add_special_tokens=False).ids)
    budget = max_length - query_tokens - 3  # BERT [CLS] query [SEP] text [SEP].
    if budget < 16:
        raise ValueError("query_too_long_for_safe_ranking_windows")
    tokens = tokenizer.encode(text, add_special_tokens=False)
    offsets = [(a, b) for a, b in tokens.offsets if b > a]
    if not offsets:
        return []
    boundaries = [match.end() for match in re.finditer(r'[.!?。！？]+["\'”’\)\]]*(?:\s+|$)|\n+', text)]
    cursor, windows = 0, []
    while cursor < len(offsets):
        end_token = min(len(offsets), cursor + budget)
        start, end = offsets[cursor][0], offsets[end_token - 1][1]
        sentence_ends = [stop for stop in boundaries if start < stop <= end]
        if sentence_ends and end_token < len(offsets):
            stop = max(sentence_ends)
            usable = [i + 1 for i in range(cursor, end_token) if offsets[i][1] <= stop]
            if usable:
                end_token = max(usable)
                end = offsets[end_token - 1][1]
        # Re-tokenising a slice may change its first wordpiece. Check actual
        # PAIR length rather than assuming the source-token arithmetic is exact.
        encoding = tokenizer.encode(query, text[start:end])
        while len(encoding.ids) > max_length and end_token > cursor + 1:
            end_token -= 1
            end = offsets[end_token - 1][1]
            encoding = tokenizer.encode(query, text[start:end])
        if len(encoding.ids) > max_length:
            raise ValueError("ranking_pair_cannot_fit_without_truncation")
        windows.append({"source_id": source["source_id"], "start": start, "end": end,
                        "text_sha256": hashlib.sha256(text[start:end].encode("utf-8")).hexdigest(),
                        "pair_tokens": len(encoding.ids), "source_token_start": cursor,
                        "source_token_end": end_token, "source_total_tokens": len(offsets),
                        "encoding": encoding})
        cursor = end_token
    return windows


def worker(asset_root, vendor, max_length, threads):
    # This process starts with stdlib only; target packages never replace imports
    # in the host/SQLite/Flash process or modify its system Python environment.
    sys.path.insert(0, str(Path(vendor).resolve()))
    import importlib.metadata
    import numpy as np
    import onnxruntime as ort
    import tokenizers
    for name, version in PINNED_RUNTIME.items():
        if importlib.metadata.version(name) != version:
            raise ValueError("unexpected_reranker_dependency_version")
    for module in (np, ort, tokenizers):
        if not Path(module.__file__).resolve().is_relative_to(Path(vendor).resolve()):
            raise ValueError("reranker_dependency_outside_isolated_target")
    started = time.perf_counter()
    manifest, model_path = verify_assets(asset_root)
    model_dir = model_path.parent
    tokenizer = tokenizers.Tokenizer.from_file(str(model_dir / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    options = ort.SessionOptions()
    options.intra_op_num_threads, options.inter_op_num_threads = threads, 1
    session = ort.InferenceSession(str(model_path), sess_options=options, providers=["CPUExecutionProvider"])
    input_names = {item.name for item in session.get_inputs()}
    pad_id = json.loads((model_dir / "config.json").read_text(encoding="utf-8")).get("pad_token_id", 0)
    print(json.dumps({"status": "ready", "model_revision": REVISION, "code_commit": CODE_COMMIT,
                      "archive_sha256": manifest["archive_sha256"], "model_license": manifest["model_license"],
                      "providers": session.get_providers(), "max_pair_tokens": max_length,
                      "startup_ms": (time.perf_counter() - started) * 1000,
                      "runtime_versions": PINNED_RUNTIME}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request.get("op") == "close":
                break
            cpu_started, wall_started = time.process_time(), time.perf_counter()
            query, sources = request["question"], request["sources"]
            if not isinstance(query, str) or not query.strip() or not isinstance(sources, list):
                raise ValueError("invalid_local_rank_request")
            windows = []
            for source in sources:
                windows.extend(_window_spans(tokenizer, query, source, max_length))
            scores = []
            for offset in range(0, len(windows), 16):
                batch = windows[offset:offset + 16]
                width = max(len(row["encoding"].ids) for row in batch)
                ids = np.full((len(batch), width), pad_id, dtype=np.int64)
                mask, types = np.zeros_like(ids), np.zeros_like(ids)
                for i, row in enumerate(batch):
                    encoded = row["encoding"]
                    size = len(encoded.ids)
                    ids[i, :size], mask[i, :size], types[i, :size] = encoded.ids, 1, encoded.type_ids
                arrays = {"input_ids": ids, "attention_mask": mask, "token_type_ids": types}
                output = session.run(None, {name: arrays[name] for name in input_names})[0]
                if output.ndim == 1 or output.shape[1] == 1:
                    values = 1 / (1 + np.exp(-np.clip(output.reshape(-1), -50, 50)))
                else:
                    shifted = output - np.max(output, axis=1, keepdims=True)
                    exp = np.exp(shifted)
                    values = exp[:, 1] / exp.sum(axis=1)
                scores.extend(float(score) for score in values)
            by_source = {}
            for row, score in zip(windows, scores):
                row.pop("encoding")
                row["score"], row["truncated"] = score, False
                by_source[row["source_id"]] = max(by_source.get(row["source_id"], 0.0), score)
            print(json.dumps({"status": "ok", "source_scores": by_source, "windows": windows,
                              "cpu_ms": (time.process_time() - cpu_started) * 1000,
                              "wall_ms": (time.perf_counter() - wall_started) * 1000,
                              "score_is_support_or_permission_proof": False}), flush=True)
        except Exception as exc:
            print(json.dumps({"status": "error", "error": str(exc) if isinstance(exc, ValueError)
                              else type(exc).__name__}), flush=True)


class TinyBERTReranker:
    """Call score_sources(question, ALREADY-authorized source records)."""
    def __init__(self, asset_root=None, vendor=None, *, max_length=512, threads=2, timeout=60):
        if type(max_length) is not int or not 32 <= max_length <= 512:
            raise ValueError("ranking_max_length_must_be_32_to_512")
        self.asset_root, self.vendor = Path(asset_root or HERE / "reranker_assets"), Path(vendor or HERE / "reranker_vendor")
        verify_assets(self.asset_root)
        self.timeout, self._queue = timeout, queue.Queue()
        self.process = subprocess.Popen([sys.executable, "-u", "-B", "-X", "utf8", str(Path(__file__).resolve()),
                                         "--worker", "--assets", str(self.asset_root), "--vendor", str(self.vendor),
                                         "--max-length", str(max_length), "--threads", str(threads)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, encoding="utf-8", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        def receive():
            try:
                for line in self.process.stdout:
                    self._queue.put(line)
            except (OSError, ValueError):
                # close() may close the pipe after stopping this owned worker.
                pass
            finally:
                self._queue.put(None)
        self._reader = threading.Thread(target=receive, daemon=True)
        self._reader.start()
        try:
            self.metadata = self._read()
            if self.metadata.get("status") != "ready":
                raise ValueError("local_reranker_not_ready")
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            line = self._queue.get(timeout=self.timeout)
        except queue.Empty:
            raise RuntimeError("local_reranker_timeout") from None
        if line is None:
            raise RuntimeError("local_reranker_worker_exited")
        result = json.loads(line)
        if result.get("status") == "error":
            raise ValueError(result["error"])
        return result

    def score_sources(self, question, sources):
        payload = {"op": "score", "question": question,
                   "sources": [{"source_id": s["source_id"], "text": s["text"]} for s in sources]}
        self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        return self._read()

    def close(self):
        process = getattr(self, "process", None)
        if process is None:
            return
        try:
            if process.poll() is None:
                try:
                    process.stdin.write('{"op":"close"}\n')
                    process.stdin.flush()
                    process.wait(timeout=3)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    # Only this instance's owned Popen is stopped. A worker may
                    # have exited between the failed write and this check.
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
        finally:
            reader = getattr(self, "_reader", None)
            if reader is not None and reader is not threading.current_thread():
                reader.join(timeout=1)
            # Popen.wait() does not close its Python pipe wrappers. Also close
            # these when the worker had already exited before close() was called.
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--assets", type=Path, default=HERE / "reranker_assets")
    parser.add_argument("--vendor", type=Path, default=HERE / "reranker_vendor")
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    if args.worker:
        worker(args.assets, args.vendor, args.max_length, args.threads)
