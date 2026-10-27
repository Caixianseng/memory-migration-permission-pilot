"""Replay four sealed relation-detector arms through existing redaction tracing.

No models, native backend, or cloud calls. Gold is parsed only after traces close.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import relation_probe_scoring as original
from scripts import relation_redaction_audit as audit

RUNS = (
    ("relation_occurrence_probe_20261027_run_01", 72,
     "849ab4ca2cf2e4e21692b5532252f6f13c79ae0f92e320675bb2ea7286f4b8e2",
     "77afb0f74fc0342cefcd03293be816c98f1088266a467dcee07e6f32a0f62cea"),
    ("native_span_attribute_probe_20261027_run_01", 24,
     "aba68b46136b8078c23b5a07d861328903f009f143b8775a7e59667f5eaff0fe",
     "bebcefc64cb08d65fecfde915e845d02f2ed088659a152145c94372596441670"),
)
ARMS = (*original.ARMS, "native_span_attributes")
MATERIAL = ROOT / "examples/relation_occurrence_probe_20261027"
SOURCE_FILES = ("scripts/run_relation_redaction_audit.py", "scripts/relation_redaction_audit.py",
                "tests/test_relation_redaction_audit.py")
# A previously documented test-only transport isolation fix, never a replay dependency.
HISTORICAL_TEST_DRIFT = {
    "run": "relation_occurrence_probe_20261027_run_01", "file": "tests/test_relation_occurrence_probe.py",
    "historical_sha256": "a4f6307ece2637e1806649cdf6f855dad77299b5374d085dc946a7a128e906a1",
    "current_sha256": "aed4f6d8338d92a2b4d3dcff95517e62906237d7c7f04a56a048cc2a6f6e5d14",
    "commit": "ff49beab15b3e2fbb873b3c0a897e4652a9d680e",
    "executed_by_audit": False,
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def inspect_inputs():
    files, frozen_sources, policies, rows = {}, {}, None, []
    for name, count, plan_sha, closed_sha in RUNS:
        folder = ROOT / "results" / name
        if sha(folder / "plan.json") != plan_sha or sha(folder / "prediction_phase_closed.json") != closed_sha:
            raise ValueError("original_closure_changed")
        plan = json.loads((folder / "plan.json").read_text(encoding="utf-8"))
        closed = json.loads((folder / "prediction_phase_closed.json").read_text(encoding="utf-8"))
        if sha(folder / "predictions.json") != closed["predictions_sha256"]:
            raise ValueError("original_predictions_changed")
        source_table = plan.get("sources", plan.get("source_sha256"))
        for relative, digest in source_table.items():
            archive = folder / "implementation" / relative
            if sha(archive) != digest:
                raise ValueError("original_source_archive_changed")
            current = sha(ROOT / relative)
            if current != digest:
                if (name, relative, digest, current) != tuple(HISTORICAL_TEST_DRIFT[k] for k in
                        ("run", "file", "historical_sha256", "current_sha256")):
                    raise ValueError("original_implementation_changed")
                files[archive.relative_to(ROOT).as_posix()] = digest
            if frozen_sources.get(relative, current) != current:
                raise ValueError("original_implementation_changed")
            frozen_sources[relative] = current
        if (sha(MATERIAL / "runtime.json") != plan["runtime_sha256"]
                or sha(MATERIAL / "evaluation.json") != plan.get("reference_sha256", plan.get("reference_opaque_sha256"))):
            raise ValueError("original_material_changed")
        if policies is not None and policies != plan["policies"]:
            raise ValueError("policy_contract_mismatch")
        policies = plan["policies"]
        incoming = json.loads((folder / "predictions.json").read_text(encoding="utf-8"))
        if len(incoming) != count:
            raise ValueError("original_row_count_mismatch")
        rows.extend(incoming)
        for filename in ("plan.json", "prediction_phase_closed.json", "predictions.json"):
            path = folder / filename
            files[path.relative_to(ROOT).as_posix()] = sha(path)
    expected = {(i, p, a) for i in range(12) for p in original.PROFILES for a in ARMS}
    actual = [(r["cell"]["text_index"], r["cell"]["profile"], r["cell"]["arm"]) for r in rows]
    if len(actual) != 96 or set(actual) != expected:
        raise ValueError("original_grid_incomplete")
    for filename in ("runtime.json", "evaluation.json"):
        path = MATERIAL / filename
        files[path.relative_to(ROOT).as_posix()] = sha(path)
    for relative in SOURCE_FILES:
        frozen_sources[relative] = sha(ROOT / relative)
    return files, frozen_sources, policies, rows


def make_plan(output):
    if not output.is_relative_to(ROOT / "results"):
        raise ValueError("output_outside_results")
    files, sources, policies, _ = inspect_inputs()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(MATERIAL / "runtime.json", output / "runtime.json")
    shutil.copyfile(MATERIAL / "evaluation.json", output / "evaluation.opaque.json")
    for relative in sources:
        destination = output / "implementation" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    plan = {"schema": "four_arm_redaction_audit_v1", "input_files": files, "sources": sources,
            "documented_historical_test_drift": HISTORICAL_TEST_DRIFT,
            "policies": policies, "rows": 96, "model_calls": 0, "network_calls": 0,
            "reference_parsed": False, "method": "Existing strict masking_intervals and score_mask; exact nonce-normalized replay binding.",
            "scope": "Post hoc audit on previously exposed development data; no model optimization or new benchmark."}
    save(output / "plan.json", plan)
    return {"status": "planned", "plan_sha256": sha(output / "plan.json")}


def verify(output, expected):
    if sha(output / "plan.json") != expected:
        raise ValueError("audit_plan_changed")
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    files, sources, policies, rows = inspect_inputs()
    if (files != plan["input_files"] or sources != plan["sources"] or policies != plan["policies"]
            or plan["documented_historical_test_drift"] != HISTORICAL_TEST_DRIFT):
        raise ValueError("audit_frozen_input_changed")
    for relative, digest in sources.items():
        if sha(output / "implementation" / relative) != digest:
            raise ValueError("audit_archive_changed")
    for filename, original_name in (("runtime.json", "runtime.json"), ("evaluation.opaque.json", "evaluation.json")):
        if sha(output / filename) != sha(MATERIAL / original_name):
            raise ValueError("audit_material_copy_changed")
    return plan, rows


def summarize(scored):
    groups = {}
    for row in scored:
        score = row["score"]
        key = row["cell"]["profile"] + "/" + row["cell"]["arm"]
        g = groups.setdefault(key, {"observations": 0, "aligned": 0, "blocked": 0,
            "known": 0, "known_ready": 0, "known_blocked": 0, "unknown": 0, "unknown_ready": 0,
            "known_ready_fully_protected": 0, "known_ready_incomplete_masking": 0,
            "known_ready_gold_spans": 0, "fully_masked_spans": 0, "partially_masked_spans": 0,
            "unmasked_spans": 0, "not_ready_gold_spans": 0, "masked_unprotected_characters": 0})
        g["observations"] += 1
        g[row["trace"]["status"]] += 1
        if not score["reference_known"]:
            g["unknown"] += 1
            g["unknown_ready"] += int(score["ready"])
        else:
            g["known"] += 1
            if score["ready"]:
                g["known_ready"] += 1
                protected = score["all_reference_spans_masked_and_ready"]
                g["known_ready_fully_protected"] += int(protected)
                g["known_ready_incomplete_masking"] += int(not protected)
                g["known_ready_gold_spans"] += score["gold_spans"]
                for field in ("fully_masked_spans", "partially_masked_spans", "unmasked_spans", "masked_unprotected_characters"):
                    g[field] += score[field]
            else:
                g["known_blocked"] += 1
                g["not_ready_gold_spans"] += score["gold_spans"]
    for g in groups.values():
        g["incomplete_masking_rate_known_ready"] = (
            g["known_ready_incomplete_masking"] / g["known_ready"] if g["known_ready"] else None)
    return groups


def execute(output, expected):
    plan, rows = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected})
    started = time.monotonic()
    state = {"status": "started", "new_model_calls": 0, "reference_parsed": False}
    traces = []
    with patch("socket.socket.connect", side_effect=RuntimeError("network_forbidden")) as sock, \
         patch("socket.create_connection", side_effect=RuntimeError("network_forbidden")) as connect, \
         patch("urllib.request.urlopen", side_effect=RuntimeError("network_forbidden")) as url:
        try:
            texts = json.loads((output / "runtime.json").read_text(encoding="utf-8"))["texts"]
            if len(texts) != 12:
                raise ValueError("audit_runtime_count_changed")
            for row in rows:
                cell = row["cell"]
                trace = audit.audit_observation(texts[cell["text_index"]], plan["policies"][cell["profile"]], row)
                traces.append({"cell": cell, "trace": trace})
            save(output / "traces.json", traces)
            verify(output, expected)
            attempts = sock.call_count + connect.call_count + url.call_count
            if attempts:
                raise RuntimeError("audit_unexpected_network")
            save(output / "traces_closed.json", {"traces_sha256": sha(output / "traces.json"), "rows": len(traces),
                 "reference_parsed": False, "new_model_calls": 0, "network_attempts": attempts, "plan_sha256": expected})
            reference = json.loads((output / "evaluation.opaque.json").read_text(encoding="utf-8"))
            state["reference_parsed"] = True
            refs = original._validate_reference(reference, texts)
            scored = []
            for item in traces:
                cell = item["cell"]
                expected_decision = refs[cell["text_index"]]["expected"][cell["profile"]]
                scored.append({**item, "score": audit.score_observation(texts[cell["text_index"]], item["trace"], expected_decision)})
            save(output / "scored_rows.json", scored)
            verify(output, expected)
            closed = json.loads((output / "traces_closed.json").read_text(encoding="utf-8"))
            if sha(output / "traces.json") != closed["traces_sha256"]:
                raise ValueError("audit_closed_traces_changed")
            report = {"schema": "four_arm_redaction_audit_v1", "status": "complete", "rows": len(scored),
                "plan_sha256": expected, "traces_sha256": sha(output / "traces.json"),
                "closure_sha256": sha(output / "traces_closed.json"), "new_model_calls": 0, "network_attempts": attempts,
                "mapping_persisted": False, "prediction_changed": False,
                "by_profile_arm": summarize(scored),
                "note": "Original metrics retained; independent full/partial/unmasked coverage is supplementary post hoc evidence.",
                "wall_seconds": time.monotonic() - started}
            save(output / "report.json", report)
            state.update(status="complete", rows=len(traces))
            return report
        except Exception as exc:
            state.update(status="stopped", error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            state.update(rows=len(traces), wall_seconds=time.monotonic()-started,
                         network_attempts=sock.call_count+connect.call_count+url.call_count)
            save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-plan-sha")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan-only", action="store_true")
    group.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    result = make_plan(args.output.resolve()) if args.plan_only else execute(args.output.resolve(), args.expected_plan_sha)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
