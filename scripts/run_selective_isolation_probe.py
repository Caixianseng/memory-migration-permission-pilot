"""Zero-model, post-hoc isolation comparison on sealed native predictions.

No gold drives selection. Restoration capabilities remain in memory until the
traces close, then gold supplies oracle reachability probes, not model answers.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study import privacy
from memory_migration_study.privacy_payload_eval import masking_intervals
from memory_migration_study import selective_memory_isolation as isolation
from scripts import relation_probe_scoring as original

ARCHIVE = ROOT / "results/native_span_attribute_probe_20261027_run_01"
MATERIAL = ROOT / "examples/relation_occurrence_probe_20261027"
PLAN_SHA = "aba68b46136b8078c23b5a07d861328903f009f143b8775a7e59667f5eaff0fe"
CLOSED_SHA = "bebcefc64cb08d65fecfde915e845d02f2ed088659a152145c94372596441670"
STRATEGIES = ("request", "record", "sentence", "position")
NEW_SOURCES = ("memory_migration_study/selective_memory_isolation.py",
               "tests/test_selective_memory_isolation.py",
               "scripts/run_selective_isolation_probe.py",
               "tests/test_selective_isolation_probe.py")
VERSION = "selective_isolation_probe_v1"
INSTRUMENT_REVISION = 2
ACTOR = "isolation_fixture_user"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def grid():
    """Pairs are fixed by original order, never chosen using reference labels."""
    bundles = [("single", [i]) for i in range(12)] + [("pair", [i, i+1]) for i in range(0, 12, 2)]
    return [{"bundle": kind, "text_indices": indices, "profile": profile, "strategy": strategy}
            for kind, indices in bundles for profile in original.PROFILES for strategy in STRATEGIES]


def inspect_inputs():
    if sha(ARCHIVE / "plan.json") != PLAN_SHA or sha(ARCHIVE / "prediction_phase_closed.json") != CLOSED_SHA:
        raise ValueError("original_closure_changed")
    plan = json.loads((ARCHIVE / "plan.json").read_text(encoding="utf-8"))
    closed = json.loads((ARCHIVE / "prediction_phase_closed.json").read_text(encoding="utf-8"))
    files, sources = {}, dict(plan["sources"])
    for filename, digest in {"predictions.json": closed["predictions_sha256"],
                             "shared_evidence.json": closed["evidence_sha256"],
                             **closed["capture_sha256"]}.items():
        if sha(ARCHIVE / filename) != digest:
            raise ValueError("original_evidence_changed")
        files[(ARCHIVE / filename).relative_to(ROOT).as_posix()] = digest
    for filename in ("plan.json", "prediction_phase_closed.json"):
        files[(ARCHIVE / filename).relative_to(ROOT).as_posix()] = sha(ARCHIVE / filename)
    for relative, digest in sources.items():
        if sha(ARCHIVE / "implementation" / relative) != digest or sha(ROOT / relative) != digest:
            raise ValueError("original_implementation_changed:" + relative)
    for filename, field in (("runtime.json", "runtime_sha256"), ("evaluation.json", "reference_sha256")):
        if sha(MATERIAL / filename) != plan[field]:
            raise ValueError("original_material_changed")
        files[(MATERIAL / filename).relative_to(ROOT).as_posix()] = plan[field]
    for relative in NEW_SOURCES:
        sources[relative] = sha(ROOT / relative)
    rows = json.loads((ARCHIVE / "predictions.json").read_text(encoding="utf-8"))
    keys = [(r["cell"]["text_index"], r["cell"]["profile"]) for r in rows]
    if len(keys) != 24 or set(keys) != {(i, p) for i in range(12) for p in original.PROFILES}:
        raise ValueError("original_grid_changed")
    return files, sources, plan["policies"], {(r["cell"]["text_index"], r["cell"]["profile"]): r for r in rows}


def make_plan(output):
    if not output.is_relative_to(ROOT / "results"):
        raise ValueError("output_outside_results")
    files, sources, policies, _ = inspect_inputs()
    output.mkdir(parents=True, exist_ok=False)
    for source, name in (("runtime.json", "runtime.json"), ("evaluation.json", "evaluation.opaque.json")):
        shutil.copyfile(MATERIAL / source, output / name)
    for relative in sources:
        dest = output / "implementation" / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, dest)
    plan = {"schema": VERSION, "instrument_revision": INSTRUMENT_REVISION, "input_files": files, "sources": sources, "policies": policies, "grid": grid(),
            "new_model_calls": 0, "network_calls": 0, "reference_parsed": False,
            "query": "", "unique_exposed_texts": 12, "sealed_detector_projections": 24,
            "dependency_scope": "Controlled host fixture declares each complete source independent; IDs alone do not prove independence.",
            "fine_grained_modes": "Unsupported without boundary evidence; fall back to whole-record isolation.",
            "expected_limit": "Strict has no qualified source; broad may preserve the other source of a coverage-failed pair. Partial-name misses remain.",
            "score_contract": "After trace closure, measure source-offset mask coverage and oracle-supplied fact restoration; never model answer accuracy.",
            "sample_scope": "Post hoc diagnostic: 144 executions reuse 12 exposed texts; no independent holdout or statistical inference."}
    save(output / "plan.json", plan)
    return {"status": "planned", "plan_sha256": sha(output / "plan.json")}


def verify(output, expected):
    if sha(output / "plan.json") != expected:
        raise ValueError("isolation_plan_changed")
    plan = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    files, sources, policies, rows = inspect_inputs()
    if files != plan["input_files"] or sources != plan["sources"] or policies != plan["policies"] or grid() != plan["grid"]:
        raise ValueError("isolation_input_changed")
    for relative, digest in sources.items():
        if sha(output / "implementation" / relative) != digest:
            raise ValueError("isolation_archive_changed")
    for filename, original_name in (("runtime.json", "runtime.json"), ("evaluation.opaque.json", "evaluation.json")):
        if sha(output / filename) != sha(MATERIAL / original_name):
            raise ValueError("isolation_material_changed")
    return plan, rows


class FrozenReplay:
    max_local_calls = 1

    def __init__(self, payload, policy, responses):
        self.sources = privacy._sources(payload)
        self.policy = privacy._policy(policy)
        self.responses = deepcopy(responses)
        self.calls = []

    def __call__(self, *, text, source_id, policy, rule_findings):
        if (source_id not in self.responses or self.sources.get(source_id) != text
                or privacy._policy(policy) != self.policy or rule_findings != [] or source_id in self.calls):
            raise ValueError("frozen_response_binding_mismatch")
        self.calls.append(source_id)
        result = deepcopy(self.responses[source_id])
        result.update(local_calls=0, elapsed_seconds=0.0)
        return result


def authorize(source_ids, policy):
    return lambda sid, actor, version: sid in source_ids and actor == ACTOR and version == policy["version"]


def retained_footprint(memories, prepared):
    """Bind output order and capability text to the original complete records."""
    cap = prepared["mapping"]
    original_text = {m["source_id"]: m["text"] for m in memories}
    kept = [m["source_id"] for m in memories if m["source_id"] in cap._memories]
    outputs = prepared["payload"]["memories"]
    if not kept or len(outputs) != len(kept) or set(cap._memories) != set(kept):
        raise ValueError("isolation_payload_mapping_count_mismatch")
    footprint = {}
    for ordinal, (sid, masked) in enumerate(zip(kept, outputs), 1):
        if cap._memories[sid] != original_text[sid] or masked["source_id"] != f"m_{cap._nonce}_{ordinal}":
            raise ValueError("isolation_source_alignment_mismatch")
        footprint[sid] = [list(pair) for pair in masking_intervals(original_text[sid], masked["text"], cap._entries)]
    if any(set(entry.sources) - set(kept) for entry in cap._entries.values()):
        raise ValueError("quarantined_source_in_capability")
    return kept, footprint


def capture(cell, texts, policy, rows):
    memories, responses, original_status = [], {}, {}
    for i in cell["text_indices"]:
        row = rows[(i, cell["profile"])]
        original._validate_status(row, texts[i])
        original._validate_preparation(row, texts[i])
        sid = f"source_{i:02d}"
        memories.append({"source_id": sid, "text": texts[i]})
        responses[sid] = row["response"]
        original_status[sid] = {"status": row["status"], "errors": row["response"].get("errors", []),
                                "relation_errors": row["response"].get("relation_errors", [])}
    source = {"query": "", "memories": memories}
    ids = {m["source_id"] for m in memories}
    request_id = "isolation-" + original._hash(cell)[:24]
    groups = isolation.bind_dependency_groups(source, policy, [[privacy.QUERY_SOURCE]] + [[m["source_id"]] for m in memories])
    replay = FrozenReplay(source, policy, responses)
    prepared = isolation.prepare_selective_private_payload(source, policy, replay, actor_id=ACTOR,
        request_id=request_id, authorizer=authorize(ids, policy), strategy=cell["strategy"], dependency_groups=groups)
    details = prepared["isolation"]
    if details["local_calls"] != 0 or details["local_calls_complete"] is not True:
        raise ValueError("replay_model_accounting_changed")
    cap = prepared.get("mapping")
    kept, footprint = [], {}
    ready = prepared["status"] == "ok"
    if ready:
        if details["egress"]["status"] != "ok":
            raise ValueError("ready_without_egress_check")
        if not isinstance(cap, privacy.RestorationMap):
            raise ValueError("missing_restoration_capability")
        if prepared["payload"]["query"] != "":
            raise ValueError("isolation_query_changed")
        kept, footprint = retained_footprint(memories, prepared)
    elif cap is not None or prepared.get("payload") is not None:
        raise ValueError("blocked_result_has_payload_or_capability")
    trace = {"schema": VERSION, "cell": cell, "request_id": request_id, "source_sha256": original._hash(source),
             "policy_sha256": original._hash(privacy._policy(policy)), "status": prepared["status"],
             "error": prepared["error"], "metadata": deepcopy(prepared["metadata"]),
             "isolation": deepcopy(details),
             "original_status": original_status, "ready": ready, "kept_source_ids": kept,
             "mask_footprint": footprint, "retained_intervals": {sid: [[0, len(cap._memories[sid])]] for sid in kept},
             "replayed_source_ids": replay.calls, "new_model_calls": 0, "mapping_persisted": False}
    trace["trace_sha256"] = original._hash(trace)
    return trace, cap


def score(trace, cap, references, texts, policy):
    """Only called after trace closure. Oracle values never affect preparation."""
    if trace["trace_sha256"] != original._hash({k: v for k, v in trace.items() if k != "trace_sha256"}):
        raise ValueError("trace_changed")
    indices, profile = trace["cell"]["text_indices"], trace["cell"]["profile"]
    ids = {f"source_{i:02d}" for i in indices}
    facts, spans, source_results = [], [], []
    for i in indices:
        sid, ref = f"source_{i:02d}", references[i]
        kept = trace["ready"] and sid in trace["kept_source_ids"]
        state = "retained" if kept else ("record_quarantined" if trace["ready"] else "request_not_ready")
        covered = {n for lo, hi in trace["mask_footprint"].get(sid, []) for n in range(lo, hi)}
        truth = ref["expected"][profile]
        sensitive_chars = set()
        for start, end, _ in original._spans(truth["spans"], texts[i], reference=True):
            positions = set(range(start, end))
            sensitive_chars |= positions
            level = ("fully_masked" if positions <= covered else "partially_masked" if positions & covered else "unmasked") if kept else state
            spans.append({"source_id": sid, "start": start, "end": end, "state": level})
        fact = ref["allowed_fact"]
        positions = set(range(fact["start"], fact["end"]))
        plain_retained = kept and not bool(positions & covered)
        restored = privacy.restore_answer(fact["text"], cap, actor_id=ACTOR, request_id=trace["request_id"],
            policy_version=policy["version"], sensitivity_policy=policy, authorizer=authorize(ids, policy)) if trace["ready"] else None
        correct = restored is not None and restored["status"] == "ok" and restored["answer"] == fact["text"]
        facts.append({"source_id": sid, "start": fact["start"], "end": fact["end"], "original_fact_plainly_retained": plain_retained,
                      "restore_status": restored["status"] if restored else "not_ready", "restore_error": restored["error"] if restored else None,
                      "oracle_fact_restorable": bool(correct), "original_fact_retained_and_restorable": plain_retained and bool(correct),
                      "restored_via_other_source": bool(correct) and not kept})
        source_results.append({"source_id": sid, "state": state, "reference_known": truth["decision"] != "needs_review",
                               "masked_unprotected_characters": len(covered-sensitive_chars) if kept and truth["decision"] != "needs_review" else None})
    incomplete = sum(x["state"] in {"partially_masked", "unmasked"} for x in spans)
    unknown_retained = any(x["state"] == "retained" and not x["reference_known"] for x in source_results)
    return {"cell": trace["cell"], "trace_sha256": trace["trace_sha256"], "ready": trace["ready"],
            "sources": source_results, "spans": spans, "facts": facts, "retained_incomplete_spans": incomplete,
            "ready_with_complete_known_masking": bool(trace["ready"] and not incomplete and not unknown_retained),
            "probe_answer_origin": "evaluation_oracle", "model_generated_answer": False}


def summarize(scored):
    groups = {}
    for row in scored:
        cell = row["cell"]
        key = "/".join(cell[k] for k in ("bundle", "profile", "strategy"))
        g = groups.setdefault(key, {k: 0 for k in ("requests", "ready_requests", "original_sources", "retained_sources", "quarantined_sources_in_ready_requests",
            "sources_in_not_ready_requests", "original_facts", "original_facts_plainly_retained", "original_facts_retained_and_restorable", "ready_requests_with_complete_known_masking",
            "fully_masked_spans", "partially_masked_spans", "unmasked_spans", "quarantined_spans_in_ready_requests", "spans_in_not_ready_requests", "masked_unprotected_characters", "overmask_evaluable_sources")})
        g["requests"] += 1
        g["ready_requests"] += int(row["ready"])
        g["ready_requests_with_complete_known_masking"] += int(row["ready_with_complete_known_masking"])
        g["original_sources"] += len(row["sources"])
        g["original_facts"] += len(row["facts"])
        g["original_facts_plainly_retained"] += sum(f["original_fact_plainly_retained"] for f in row["facts"])
        g["original_facts_retained_and_restorable"] += sum(f["original_fact_retained_and_restorable"] for f in row["facts"])
        for source in row["sources"]:
            g[{"retained": "retained_sources", "record_quarantined": "quarantined_sources_in_ready_requests", "request_not_ready": "sources_in_not_ready_requests"}[source["state"]]] += 1
            if source["masked_unprotected_characters"] is not None:
                g["overmask_evaluable_sources"] += 1
                g["masked_unprotected_characters"] += source["masked_unprotected_characters"]
        for span in row["spans"]:
            g[{"fully_masked": "fully_masked_spans", "partially_masked": "partially_masked_spans", "unmasked": "unmasked_spans",
               "record_quarantined": "quarantined_spans_in_ready_requests", "request_not_ready": "spans_in_not_ready_requests"}[span["state"]]] += 1
    for g in groups.values():
        if g["overmask_evaluable_sources"] == 0:
            g["masked_unprotected_characters"] = None
    return groups


def execute(output, expected):
    plan, rows = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected})
    started = time.monotonic()
    traces, caps = [], []
    state = {"status": "started", "new_model_calls": 0, "reference_parsed": False}
    with patch("socket.socket.connect", side_effect=RuntimeError("network_forbidden")) as sock, \
         patch("socket.create_connection", side_effect=RuntimeError("network_forbidden")) as connect, \
         patch("urllib.request.urlopen", side_effect=RuntimeError("network_forbidden")) as url:
        try:
            texts = json.loads((output / "runtime.json").read_text(encoding="utf-8"))["texts"]
            if len(texts) != 12:
                raise ValueError("runtime_count_changed")
            for cell in plan["grid"]:
                trace, cap = capture(cell, texts, plan["policies"][cell["profile"]], rows)
                traces.append(trace)
                caps.append(cap)
            save(output / "traces.json", traces)
            verify(output, expected)
            attempts = sock.call_count + connect.call_count + url.call_count
            if attempts:
                raise RuntimeError("unexpected_network")
            save(output / "traces_closed.json", {"traces_sha256": sha(output / "traces.json"), "rows": len(traces),
                "reference_parsed": False, "new_model_calls": 0, "network_attempts": attempts, "plan_sha256": expected})
            reference = json.loads((output / "evaluation.opaque.json").read_text(encoding="utf-8"))
            state["reference_parsed"] = True
            refs = original._validate_reference(reference, texts)
            scored = [score(t, cap, refs, texts, plan["policies"][t["cell"]["profile"]]) for t, cap in zip(traces, caps)]
            save(output / "scored_rows.json", scored)
            verify(output, expected)
            closed = json.loads((output / "traces_closed.json").read_text(encoding="utf-8"))
            if sha(output / "traces.json") != closed["traces_sha256"]:
                raise ValueError("closed_trace_changed")
            attempts = sock.call_count + connect.call_count + url.call_count
            if attempts:
                raise RuntimeError("unexpected_network_during_scoring")
            report = {"schema": VERSION, "instrument_revision": INSTRUMENT_REVISION, "status": "complete", "executions": len(traces), "unique_exposed_texts": 12,
                      "plan_sha256": expected, "traces_sha256": sha(output / "traces.json"), "closure_sha256": sha(output / "traces_closed.json"),
                      "by_bundle_profile_strategy": summarize(scored), "new_model_calls": 0, "network_attempts": attempts,
                      "mapping_persisted": False, "query": "", "model_task_accuracy": None, "independent_holdout": False,
                      "sentence_and_position_are_record_fallbacks": True, "wall_seconds": time.monotonic()-started}
            save(output / "report.json", report)
            state.update(status="complete")
            return report
        except Exception as exc:
            state.update(status="stopped", error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            caps.clear()
            state.update(rows=len(traces), network_attempts=sock.call_count+connect.call_count+url.call_count, wall_seconds=time.monotonic()-started)
            save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-plan-sha")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    result = make_plan(args.output.resolve()) if args.plan_only else execute(args.output.resolve(), args.expected_plan_sha)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
