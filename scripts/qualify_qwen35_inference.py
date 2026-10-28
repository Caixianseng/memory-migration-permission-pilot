"""One exclusive, loopback-only inference qualification; never an accuracy test."""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.qwen35_occurrence import ENDPOINT, MODEL, Qwen35OccurrenceAgent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-receipt", required=True, type=Path)
    args = parser.parse_args()
    receipt_path = args.model_receipt.resolve()
    if not receipt_path.is_relative_to(ROOT / "results"):
        raise ValueError("receipt_scope")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
    if not (receipt["status"] == "assets_verified" and receipt["model"] == MODEL
            and receipt["version"] == "0.40.8" and receipt["endpoint"] == ENDPOINT):
        raise ValueError("asset_qualification_required")
    directory = receipt_path.parent
    save(directory / "inference_started.json", {
        "asset_receipt_sha256": digest(receipt_path), "max_generation_posts": 1,
        "formal_texts": 0, "script_sha256": digest(Path(__file__))})
    policy = json.loads((ROOT / "results/source_annotation_20261028_run_01/plan.json").read_text(encoding="utf-8"))["policy"]
    posts, health, captured = 0, {}, {}
    started = time.monotonic()

    def transport(method, path, body=None):
        nonlocal posts
        allowed = ((method, path) in {("GET", "/api/version"), ("GET", "/api/tags")}
                   or (method, path) == ("POST", "/api/chat"))
        if not allowed:
            raise ValueError("unexpected_qualification_request")
        encoded = None
        if method == "POST":
            if posts or body.get("model") != MODEL or body.get("think") is not False:
                raise ValueError("qualification_generation_limit")
            posts += 1
            encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            with (directory / "inference_request.json").open("xb") as stream:
                stream.write(encoded)
        conn = http.client.HTTPConnection("127.0.0.1", 11435, timeout=180)
        try:
            conn.request(method, path, encoded, {"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read(1048577)
            if method == "POST":
                with (directory / "inference_response.json").open("xb") as stream:
                    stream.write(raw)
            if response.status != 200 or len(raw) > 1048576:
                raise ValueError("qualification_http_or_size_failure")
            value = json.loads(raw.decode("utf-8"))
            if method == "GET":
                health[path] = value
            else:
                captured.update(value)
            return value
        finally:
            conn.close()

    try:
        agent = Qwen35OccurrenceAgent(expected_digest=receipt["model_digest"], transport=transport)
        result = agent(text="The public note says the desk is wooden.",
                       source_id="qwen35_runtime_qualification", policy=policy, rule_findings=[])
        save(directory / "inference_health.json", health)
        save(directory / "inference_adapter_result.json", result)
        token_counts_valid = (type(captured.get("prompt_eval_count")) is int
                              and 0 <= captured["prompt_eval_count"] <= 4096
                              and type(captured.get("eval_count")) is int
                              and 0 <= captured["eval_count"] <= 1024)
        qualified = (posts == 1 and result["local_calls"] == 1
                     and result["local_calls_complete"] is True and result["status"] == "ok"
                     and result["findings"] == [] and not result["errors"]
                     and captured.get("done") is True and captured.get("done_reason") == "stop"
                     and not captured.get("message", {}).get("thinking")
                     and not captured.get("message", {}).get("tool_calls") and token_counts_valid)
        value = {"status": "qualified" if qualified else "failed", "model": MODEL,
                 "model_digest": receipt["model_digest"], "version": "0.40.8", "endpoint": ENDPOINT,
                 "generation_calls": posts, "formal_texts": 0, "cloud_calls": 0,
                 "thinking_disabled": qualified, "json_schema_valid": qualified,
                 "token_counts_valid": token_counts_valid,
                 "complete_generation": qualified, "elapsed_seconds": time.monotonic()-started,
                 "prompt_eval_count": captured.get("prompt_eval_count"), "eval_count": captured.get("eval_count"),
                 "asset_receipt_sha256": digest(receipt_path), "adapter_identity": agent.cache_identity(),
                 "scope": "One public format/runtime check; not a formal case or privacy accuracy result."}
        for kind in ("request", "response"):
            path = directory / ("inference_" + kind + ".json")
            value[kind + "_file"] = path.name
            value[kind + "_sha256"] = digest(path) if path.exists() else None
        save(directory / "inference_qualification.json", value)
        print(json.dumps({k: value[k] for k in ("status", "generation_calls", "elapsed_seconds", "prompt_eval_count", "eval_count")}))
        if not qualified:
            raise SystemExit(1)
    except Exception as error:
        save(directory / "inference_failure.json", {"error_type": type(error).__name__,
             "generation_post_attempts": posts, "formal_texts": 0, "elapsed_seconds": time.monotonic()-started})
        raise


if __name__ == "__main__":
    main()
