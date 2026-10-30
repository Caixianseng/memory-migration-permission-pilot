"""Author ACORN binary with actual host read/transfer masks; no model calls.

One-hot vectors are an interface instrument, not semantic embeddings. We check
candidate legality and restoration, not the truth of a downstream QA answer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from experiments.algorithm_ports_20261029.dual_gate import HandoffSession
from experiments.algorithm_ports_20261029.make_tasks import generate

ROOT = Path(__file__).resolve().parents[2]


def run(binary: Path, output: Path):
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "running", "model_calls": 0, "phases": [],
        "scope": "one-hot interface qualification, not semantic embeddings or QA",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    try:
        case = generate(7319265, count=1)[0][0]
        host = HandoffSession(case, output / "host_state")
        records = host.records
        indices = {row["record_id"]: i for i, row in enumerate(records)}
        n = len(records)
        vectors = [[int(i == j) for j in range(n)] for i in range(n)]
        first_legal = host.eligible()[0][0]
        target = indices[first_legal["record_id"]]
        query = vectors[target]
        env = os.environ.copy()
        toolchain = ROOT / ".runtime/algorithm_ports/acorn_toolchain/unpacked"
        env["PATH"] = os.pathsep.join([str(toolchain / "openblas/bin"),
            str(toolchain / "w64devkit/w64devkit/bin"), env.get("PATH", "")])
        env["OMP_NUM_THREADS"] = env["OPENBLAS_NUM_THREADS"] = "1"

        def token(request):
            return request["prepared"]["payload"]["memories"][0]["text"].split("customer code ")[1].rstrip(".")

        def phase(name):
            allowed = {indices[r["record_id"]] for r in host.eligible()[0]}
            payload = {"vectors": vectors, "queries": [query],
                "masks": [[int(i in allowed) for i in range(n)]], "k": 1}
            source = output / (name + "_input.json")
            destination = output / (name + "_output.json")
            source.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            result = subprocess.run([str(binary), "--input", str(source.resolve()),
                "--output", str(destination.resolve())], env=env, capture_output=True,
                text=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            (output / (name + "_process.json")).write_text(json.dumps({
                "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr},
                indent=2) + "\n", encoding="utf-8")
            if result.returncode != 0:
                raise RuntimeError("acorn_binary_exit_" + str(result.returncode))
            raw = json.loads(destination.read_text(encoding="utf-8"))
            answers = raw["acorn"]
            assert len(answers) == 1 and isinstance(answers[0]["ids"], list)
            values = answers[0]["ids"]
            assert all(type(i) is int and (i == -1 or 0 <= i < n) for i in values)
            selected = [i for i in values if i >= 0]
            assert len(selected) <= 1 and len(selected) == len(set(selected))
            # No silent host-side postfilter may hide a candidate error.
            assert set(selected) <= allowed, "acorn_unauthorized_candidate"
            assert bool(selected) == bool(allowed), "acorn_unexpected_missing_candidate"
            row = {"phase": name, "mask": payload["masks"][0],
                "candidate_ids": selected, "illegal_candidates": 0,
                "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "output_sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}
            if selected:
                selected_record = records[selected[0]]
                request = host.prepare([selected_record], "acorn-" + name)
                restored = host.restore(token(request), request)
                assert restored["status"] == "ok"
                expected = host.rows[selected_record["source"]["source_id"]]["protected_value"]
                assert restored["answer"] == expected
                row["host_restoration"] = "ok"
            else:
                row["host_restoration"] = "no_candidate_no_delivery"
            receipt["phases"].append(row)
            return selected

        assert phase("before_revoke") == [target]
        old = host.prepare([first_legal], "acorn-old")
        host.revoke(first_legal["source"]["source_id"])
        try:
            host.restore(token(old), old)
        except (ValueError, PermissionError):
            receipt["old_packet_blocked"] = True
        else:
            raise AssertionError("old_packet_still_accepted")
        phase("after_revoke")
        for record in list(host.eligible()[0]):
            host.revoke(record["source"]["source_id"])
        assert phase("no_allowed_records") == []
        try:
            host.prepare([first_legal], "acorn-stale-candidate")
        except (ValueError, PermissionError):
            receipt["forced_stale_candidate_blocked"] = True
        else:
            raise AssertionError("stale_candidate_bypasses_current_authority")
        receipt["status"] = "passed"
    except Exception as exc:
        receipt.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        (output / "integration.json").write_text(json.dumps(receipt, ensure_ascii=False,
            indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": receipt["status"], "phases": len(receipt["phases"]), "model_calls": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.output)
