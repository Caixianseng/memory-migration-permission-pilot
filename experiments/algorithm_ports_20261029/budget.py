"""Attempt-before-POST accounting against the existing shared research ceiling."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "results/qoder_harness_plan_20261029/resource_ledger.json"


def charge_generation(*, phase, run_id):
    if not isinstance(run_id, str) or not run_id.startswith("algorithm_ports_ltt:"):
        raise ValueError("invalid_port_run_id")
    lock = LEDGER.with_name("algorithm_ports_budget.lock")
    descriptor = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        os.close(descriptor)
        ledger = json.loads(LEDGER.read_text(encoding="utf-8-sig"))
        actual, journal = ledger["actual"], ledger["attempt_journal"]
        used = sum(row.get("kind") == "generation" and
                   str(row.get("run", "")).startswith("algorithm_ports_ltt:") for row in journal)
        if actual["generation"] >= min(200, ledger["ceiling"]["generation"]) or used >= 84:
            raise RuntimeError("generation_budget_exhausted")
        actual["generation"] += 1
        journal.append({"charged_before_attempt": True, "kind": "generation",
                        "ordinal": actual["generation"], "phase": phase, "run": run_id})
        counts = ledger["phase_attempts"].setdefault(phase, {"extraction": 0, "generation": 0})
        counts["generation"] += 1
        temporary = LEDGER.with_name("algorithm_ports_budget.pending.json")
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(ledger, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, LEDGER)
        return {"global_ordinal": actual["generation"], "new_port_attempts": used + 1}
    finally:
        lock.unlink(missing_ok=True)
