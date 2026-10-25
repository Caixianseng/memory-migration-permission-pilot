"""Offline consistency audit of the exposed 120-case syntax-candidate diagnostic.

No model, encoder or network requests. Candidate coverage is not privacy recall.
The archived evaluation bytes are decoded only after the proposal closure has
been checked. An isolated replay also observes this order in the frozen driver;
neither hashes nor replay prove that historical files resist coordinated edits.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
VERSION = "independent_open_container_diagnostic_verification_v1"
PARSER_VERSION = "typed_seeded_open_container_candidates_v1"
ARCHIVE_SHA256 = "330d31c9e70980631dd3b67dc8a059512af77693e39870c2b8570b696effce43"
FROZEN = {
    "memory_migration_study/open_container_candidates.py": "a4cd5082bb43573a6d1e26770f4786f394b427555e1febc0bce4978253ed30f8",
    "memory_migration_study/candidate_proposals.py": "32be4b9a305f43e8f9701c3b50c822f0a98b13411c2d12dd57a2692dc4b9e323",
    "memory_migration_study/privacy.py": "c6db0bb46c983c6f42d35a3fe028f35309905e5c447e5de9260d927e10dac7e9",
    "scripts/run_open_container_diagnostic.py": "da75a5c916f20301721f367022c68c14d9ba16be96ba0d82c6e95c9afd9cd8ce",
}
SPLITS = {"development": 80, "heldout": 40}
ARTIFACTS = ("plan.json", "parent_materials.json", "parent_model_phase_closed.json",
             "unscored_rows.json", "proposal_phase_closed.json", "rows.json", "report.json")
ROW_FIELDS = {"case_id", "split", "language", "baseline", "prior_pool", "proposals"}
FORBIDDEN_UNSCORED = {"gold", "score", "scores", "coverage", "accepted", "answers", "accepted_complete_exact"}
ERRORS = (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
          AssertionError, StopIteration, ImportError, RecursionError, zipfile.BadZipFile)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def same(first, second):
    return compact(first) == compact(second)


def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def read(path):
    return loads(Path(path).read_bytes())


def unscored_only(value):
    if isinstance(value, dict):
        return not (set(value) & FORBIDDEN_UNSCORED) and all(unscored_only(v) for v in value.values())
    return not isinstance(value, list) or all(unscored_only(v) for v in value)


def _archive(path):
    raw = Path(path).read_bytes()
    if sha(raw) != ARCHIVE_SHA256:
        raise ValueError("wrong_fixed_public_archive")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or sum(i.file_size for i in z.infolist()) > 80 * 1024 * 1024:
            raise ValueError("invalid_archive")
        blobs = {name: z.read(name) for name in names}
    manifest = loads(blobs["PUBLIC_ARTIFACT_MANIFEST.json"])
    if set(manifest["files"]) != set(blobs) - {"PUBLIC_ARTIFACT_MANIFEST.json", "README.txt"}:
        raise ValueError("invalid_archive_manifest")
    if any(sha(blobs[name]) != digest for name, digest in manifest["files"].items()):
        raise ValueError("archive_member_changed")
    # Evaluation data remain bytes here, including while hashing all members.
    return blobs


def _sources(payload):
    if set(payload) != {"query", "memories"}:
        raise ValueError("payload_fields")
    sources = {"__query__": payload["query"]}
    for item in payload["memories"]:
        if set(item) != {"source_id", "text"} or item["source_id"] in sources:
            raise ValueError("source_fields")
        sources[item["source_id"]] = item["text"]
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in sources.items()):
        raise ValueError("source_types")
    return sources


def _policy(policy):
    registry = sorted({(i["category"], i["value"]) for i in policy.get("entity_registry", [])})
    return {"version": policy["version"], "protected_categories": list(dict.fromkeys(policy["protected_categories"])),
        "policy_id": policy.get("policy_id", policy["version"]), "max_text_chars": policy.get("max_text_chars", 6000),
        "instructions": policy.get("instructions", ""),
        "entity_registry": [{"category": category, "value": value} for category, value in registry]}


def _exact(item, sources):
    sid, start, end = item["source_id"], item["start"], item["end"]
    return (sid in sources and type(start) is int and type(end) is int
        and 0 <= start < end <= len(sources[sid]) and item["quote"] == sources[sid][start:end])


def _keys(items, category=True):
    fields = ("source_id", "start", "end", "category") if category else ("source_id", "start", "end")
    return {tuple(item[k] for k in fields) for item in items}


def _coverage(row, gold_findings):
    """Independent newness: compare against ALL old intervals, never just gold."""
    expected = _keys(gold_findings)
    old_spans = _keys(row["prior_pool"]["candidates"], category=False)
    covered_before = {g for g in expected if g[:3] in old_spans}
    proposals = _keys(row["proposals"]["completions"])
    qualified = proposals if row["proposals"]["status"] == "candidates_only" and row["proposals"]["complete"] else set()
    new = {candidate for candidate in proposals if candidate[:3] not in old_spans}
    return {"gold_spans": len(expected), "prior_pool_covered": len(covered_before),
        "all_proposal_union_covered": len(expected & (covered_before | proposals)),
        "fully_qualified_union_covered": len(expected & (covered_before | qualified)),
        "new_exact_gold_candidates": len(new & expected), "new_nongold_candidates": len(new - expected),
        "total_completion_candidates": len(proposals), "baseline_findings_changed": False}


def _span_coverage(row, gold_findings):
    """Category-agnostic candidate representation; this is never detector P/R."""
    gold = _keys(gold_findings, category=False)
    old = _keys(row["prior_pool"]["candidates"], category=False)
    proposed = _keys(row["proposals"]["completions"], category=False)
    qualified = proposed if row["proposals"]["status"] == "candidates_only" and row["proposals"]["complete"] else set()
    return {"gold_intervals": len(gold), "prior_intervals_covered": len(gold & old),
        "all_union_intervals_covered": len(gold & (old | proposed)),
        "qualified_union_intervals_covered": len(gold & (old | qualified)),
        "new_gold_intervals": len((proposed - old) & gold),
        "new_nongold_intervals": len(proposed - old - gold),
        "completion_intervals_already_in_prior_pool": len(proposed & old)}


def _summary(rows):
    result = {}
    for split in SPLITS:
        selected = [r for r in rows if r["split"] == split]
        result[split] = {"materials": len(selected),
            "statuses": dict(Counter(r["proposals"]["status"] for r in selected)),
            **{key: sum(r["coverage"][key] for r in selected)
               for key in selected[0]["coverage"] if key != "baseline_findings_changed"},
            "errors": dict(Counter(e for r in selected for e in r["proposals"]["errors"]))}
    return result


def _phase_order(source):
    tree = ast.parse(source)
    run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    closure = [n.lineno for n in ast.walk(run) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == "save"
        and n.args and "proposal_phase_closed.json" in ast.unparse(n.args[0])]
    gold = [n.lineno for n in ast.walk(run) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "json" and n.func.attr == "loads"
        and "evaluation.json" in ast.unparse(n)]
    proposals = [n.lineno for n in ast.walk(run) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == "propose_open_container_candidates"]
    return len(closure) == len(gold) == len(proposals) == 1 and proposals[0] < closure[0] < gold[0]


def _driver_replay(parent, archive, gold_blobs, original_rows, original_report):
    """Replay only hash-pinned current code with all sockets blocked.

    The original run is untouched. The generated temporary directory is checked
    to remain under results before its context manager removes it.
    """
    spec = importlib.util.spec_from_file_location("_open_container_audit_driver", ROOT / "scripts/run_open_container_diagnostic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    network, gold_loads, violations = [], [], []
    original_loads = json.loads
    gold_hashes = {sha(raw) for raw in gold_blobs}
    with tempfile.TemporaryDirectory(prefix="verify_open_container_", dir=ROOT / "results") as name:
        temporary = Path(name).resolve()
        if not temporary.is_relative_to((ROOT / "results").resolve()):
            raise ValueError("temporary_scope")
        replay = temporary / "replay"
        def guarded_loads(raw, *args, **kwargs):
            data = raw.encode("utf-8") if isinstance(raw, str) else raw
            if isinstance(data, (bytes, bytearray)) and sha(data) in gold_hashes:
                closed_path = replay / "proposal_phase_closed.json"
                unscored = replay / "unscored_rows.json"
                if not closed_path.is_file() or not unscored.is_file():
                    violations.append("gold_before_proposal_close")
                    raise AssertionError("gold_before_proposal_close")
                closed = original_loads(closed_path.read_bytes())
                if closed.get("closed") is not True or closed.get("rows_sha256") != sha(unscored.read_bytes()):
                    violations.append("gold_without_bound_unscored")
                    raise AssertionError("gold_without_bound_unscored")
                gold_loads.append("after_bound_close")
            return original_loads(raw, *args, **kwargs)
        def deny(*_args, **_kwargs):
            network.append("blocked")
            raise AssertionError("verification_network_forbidden")
        with patch.object(socket.socket, "connect", deny), patch.object(socket, "create_connection", deny), patch.object(json, "loads", guarded_loads):
            report = module.run(replay, flat=parent, archive=archive)
            rows = read(replay / "unscored_rows.json")
        return {"same_unscored_rows": same(rows, original_rows), "same_report": same(report, original_report),
            "gold_decodes": len(gold_loads), "gold_before_close": len(violations), "network_attempts": len(network),
            "inner_network_attempts": report["network_attempts"], "model_calls": report["new_model_calls"]}


def verify(run, *, archive=None, parent=None, earlier=None):
    run = Path(run).resolve()
    archive = Path(archive).resolve() if archive else ROOT / "benchmarks/artifacts/context_candidate_detection_20261026_v2.zip"
    parent = Path(parent).resolve() if parent else ROOT / "results/flat_candidate_detection_20261026_v1"
    earlier = [Path(p).resolve() for p in earlier] if earlier is not None else [
        ROOT / "results/open_container_development_20261026_v1", ROOT / "results/open_container_development_20261026_v2"]
    checks, phase, summary, spans = [], "inputs", {}, {}
    def check(name, value):
        try:
            passed = bool(value() if callable(value) else value)
        except ERRORS:
            passed = False
        checks.append({"check": name, "passed": passed})
        return passed
    def finish(**extra):
        return {"version": VERSION, "status": "passed" if checks and all(c["passed"] for c in checks) else "failed",
            "phase": phase, "checks": checks, "summary": summary, "span_only_summary": spans,
            "verification_model_calls": 0, "verification_encoder_calls": 0, "method_acceptance": False,
            "independent_acceptance": False, "default_changed": False,
            "scope": "Old 80 development and 40 already exposed regression; syntax-candidate coverage only.",
            "limitations": ["Not final sensitivity precision/recall, authorized QA, native transfer or novelty evidence.",
                "Same-parser replay checks evidence consistency, not an independent semantic parser or semantic atomicity.",
                "Hash/closure/source-order checks and guarded replay do not prove historical resistance to coordinated edits.",
                "Optional completion categories and category-agnostic interval coverage are reported separately."], **extra}
    try:
        if not check("run_and_parent_inside_results", run.is_relative_to((ROOT / "results").resolve())
                     and parent.is_relative_to((ROOT / "results").resolve())):
            return finish()
        before = {name: sha((run / name).read_bytes()) for name in ARTIFACTS}
        blobs = _archive(archive)
        check("fixed_public_archive_all_member_hashes", True)
        plan = read(run / "plan.json")
        if not check("frozen_implementation_manifest_and_current_bytes", plan["implementation_sha256"] == FROZEN
                     and all(sha((ROOT / path).read_bytes()) == digest for path, digest in FROZEN.items())):
            return finish()
        check("plan_zero_models_exposed_120_not_acceptance", plan["version"] == PARSER_VERSION
            and plan["materials"] == 120 and plan["fixed_archive_sha256"] == ARCHIVE_SHA256
            and plan["new_model_calls"] == 0 and plan["default_changed"] is False
            and plan["semantic_atomicity_proven"] is False)
        check("driver_proposals_closed_before_gold_static_order", _phase_order((ROOT / "scripts/run_open_container_diagnostic.py").read_text(encoding="utf-8")))
        check("copied_parent_files_exact", all(
            sha((run / ("parent_" + name)).read_bytes()) == digest == sha((parent / name).read_bytes())
            for name, digest in plan["parent_files"].items())
            and set(plan["parent_files"]) == {"materials.json", "model_phase_closed.json"})
        parent_closed = read(run / "parent_model_phase_closed.json")
        check("parent_closed_all_bound_artifacts_unchanged", parent_closed["model_phase_closed"] is True
            and all(not Path(name).is_absolute() and ".." not in Path(name).parts
                and sha((parent / name).read_bytes()) == digest
                for name, digest in parent_closed["artifact_sha256"].items()))
        parent_rows = read(run / "parent_materials.json")
        parent_by_id = {r["case_id"]: r for r in parent_rows}
        check("parent_120_unique_unscored_materials_bound", len(parent_rows) == len(parent_by_id) == 120
            and unscored_only(parent_rows)
            and parent_closed["artifact_sha256"]["materials.json"] == sha((run / "parent_materials.json").read_bytes()))
        cases = []
        for split, count in SPLITS.items():
            values = loads(blobs[split + "/runtime.json"])
            check(split + "_fixed_runtime_bytes_and_count", len(values) == count
                and blobs[split + "/runtime.json"] == (parent / split / "runtime.json").read_bytes())
            cases.extend(dict(r, split=split) for r in values)
        by_id = {c["case_id"]: c for c in cases}
        unscored = read(run / "unscored_rows.json")
        row_by_id = {r["case_id"]: r for r in unscored}
        check("120_unique_complete_unscored_denominator", len(unscored) == len(row_by_id) == len(by_id) == 120
            and set(row_by_id) == set(by_id) == set(parent_by_id) and unscored_only(unscored))
        closed = read(run / "proposal_phase_closed.json")
        if not check("proposal_phase_closed_binds_all_unscored_before_scoring", closed["closed"] is True
                     and closed["rows_sha256"] == before["unscored_rows.json"]
                     and closed["new_model_calls"] == closed["network_attempts"] == 0
                     and closed["implementation_unchanged"] is True):
            return finish()
        phase = "parser_replay_before_gold"
        from memory_migration_study.open_container_candidates import propose_open_container_candidates, validate_open_container_candidates
        attempts = []
        def deny(*_args, **_kwargs):
            attempts.append("blocked")
            raise AssertionError("verification_network_forbidden")
        with patch.object(socket.socket, "connect", deny), patch.object(socket, "create_connection", deny):
            for case in cases:
                cid = case["case_id"]
                row, original = row_by_id[cid], parent_by_id[cid]
                sources = _sources(case["payload"])
                result = row["proposals"]
                check(cid + ":complete_original_baseline_and_pool_retained", set(row) == ROW_FIELDS
                    and row["split"] == case["split"] and row["language"] == case["language"]
                    and same(row["baseline"], original["boundary_baseline"])
                    and same(row["prior_pool"], original["boundary_pool"]))
                replayed = propose_open_container_candidates(case["payload"], case["policy"], deepcopy(row["baseline"]["findings"]))
                validate_open_container_candidates(case["payload"], case["policy"], row["baseline"]["findings"], result)
                check(cid + ":complete_parser_recompute", same(result, replayed)
                    and "findings" not in result and result["kind"] == "syntax_candidates_only"
                    and result["local_calls"] == 0 and result["inference_kind"] == "deterministic")
                check(cid + ":independent_source_payload_policy_seed_hashes", result["payload_sha256"] == sha(compact(case["payload"]))
                    and result["full_policy_sha256"] == sha(compact(case["policy"]))
                    and result["policy_sha256"] == sha(compact(_policy(case["policy"])))
                    and result["existing_findings_sha256"] == sha(compact(row["baseline"]["findings"]))
                    and result["source_sha256"] == {sid: sha(text.encode("utf-8")) for sid, text in sources.items()})
                decisions = result["decisions"]
                normalized = [{"source_id": f["source_id"], "start": f["start"], "end": f["end"],
                    "quote": sources[f["source_id"]][f["start"]:f["end"]], "category": f["category"]}
                    for f in row["baseline"]["findings"]]
                check(cid + ":every_seed_retained_and_completions_exact_not_sensitive_decisions",
                    len(decisions) == len(normalized)
                    and [d["seed"] for d in decisions] == normalized and all(d["retained"] is True for d in decisions)
                    and all(_exact(p, sources) and p["source_sha256"] == result["source_sha256"][p["source_id"]]
                        and p["category"] in case["policy"]["protected_categories"]
                        and p["semantic_atomicity"] == "unverified" for p in result["completions"])
                    and all(_exact(p, sources) for p in row["prior_pool"]["candidates"]))
        check("parser_replay_no_network_attempts", attempts == [])
        phase = "independent_scoring_after_close"
        gold = {}
        for split in SPLITS:
            gold.update(loads(blobs[split + "/evaluation.json"]))
        check("gold_full_denominator_only_decoded_after_bound_proposal_close", set(gold) == set(by_id))
        scored = []
        span_rows = []
        saved = read(run / "rows.json")
        saved_by_id = {r["case_id"]: r for r in saved}
        check("120_unique_scored_rows_no_missing_or_extra_cases", len(saved) == len(saved_by_id) == 120 and set(saved_by_id) == set(by_id))
        for row in unscored:
            cid = row["case_id"]
            coverage = _coverage(row, gold[cid]["findings"])
            expected = dict(row, coverage=coverage)
            check(cid + ":independent_full_pool_newness_and_full_scored_row", same(expected, saved_by_id[cid]))
            scored.append(expected)
            span_rows.append((row["split"], _span_coverage(row, gold[cid]["findings"])))
        summary = _summary(scored)
        report = read(run / "report.json")
        check("report_matches_independent_all_denominator_scoring", same(summary, report["summary"]))
        check("report_no_privacy_or_cost_or_acceptance_claim", set(report) == {"version", "summary", "new_model_calls",
            "new_encoder_calls", "cloud_calls", "new_api_cost_cny", "network_attempts", "default_changed",
            "final_detection_unchanged", "independent_acceptance", "semantic_atomicity_proven", "implementation_unchanged", "scope"}
            and report["scope"] == "candidate representation coverage only; not privacy recall, precision, legal QA, native transfer or novelty"
            and report["version"] == PARSER_VERSION
            and all(report[k] == 0 for k in ("new_model_calls", "new_encoder_calls", "cloud_calls", "new_api_cost_cny", "network_attempts"))
            and all(report[k] is False for k in ("default_changed", "independent_acceptance", "semantic_atomicity_proven"))
            and report["final_detection_unchanged"] is True and report["implementation_unchanged"] is True)
        for split in SPLITS:
            selected = [value for name, value in span_rows if name == split]
            spans[split] = {key: sum(value[key] for value in selected) for key in selected[0]}
            check(split + "_optional_type_and_interval_coverage_agree_on_this_batch",
                spans[split]["gold_intervals"] == summary[split]["gold_spans"]
                and spans[split]["prior_intervals_covered"] == summary[split]["prior_pool_covered"]
                and spans[split]["all_union_intervals_covered"] == summary[split]["all_proposal_union_covered"]
                and spans[split]["qualified_union_intervals_covered"] == summary[split]["fully_qualified_union_covered"]
                and spans[split]["new_gold_intervals"] == summary[split]["new_exact_gold_candidates"]
                and spans[split]["new_nongold_intervals"] == summary[split]["new_nongold_candidates"])
        phase = "earlier_failed_and_score_only_runs"
        earlier_receipts = []
        for previous in earlier:
            if not previous.is_relative_to((ROOT / "results").resolve()):
                raise ValueError("earlier_scope")
            old_plan = read(previous / "plan.json")
            old_closed = read(previous / "proposal_phase_closed.json")
            name = previous.name
            check(name + ":same_exact_unscored_predictions_and_parser_dependencies", old_closed["closed"] is True
                and old_closed["rows_sha256"] == sha((previous / "unscored_rows.json").read_bytes()) == before["unscored_rows.json"]
                and (previous / "unscored_rows.json").read_bytes() == (run / "unscored_rows.json").read_bytes()
                and all(old_plan["implementation_sha256"][path] == digest for path, digest in FROZEN.items()
                        if path != "scripts/run_open_container_diagnostic.py"))
            failure = previous / "scoring_failure.json"
            if name.endswith("_v1"):
                check(name + ":original_scoring_failure_preserved_not_a_new_model_run", failure.is_file()
                    and not (previous / "rows.json").exists() and not (previous / "report.json").exists())
            earlier_receipts.append({"run_name": name, "unscored_sha256": sha((previous / "unscored_rows.json").read_bytes()),
                "parser_sha256": old_plan["implementation_sha256"]["memory_migration_study/open_container_candidates.py"],
                "scoring_failure_preserved": failure.is_file(), "scoring_failure_sha256": sha(failure.read_bytes()) if failure.is_file() else None})
        phase = "guarded_full_driver_replay"
        replay = _driver_replay(parent, archive, [blobs[s + "/evaluation.json"] for s in SPLITS], unscored, report)
        check("full_driver_replay_identical_120_proposals_and_report", replay["same_unscored_rows"] and replay["same_report"])
        check("full_driver_replay_gold_decodes_only_after_bound_close_zero_network_models", replay["gold_decodes"] == 2
            and replay["gold_before_close"] == replay["network_attempts"] == replay["inner_network_attempts"] == replay["model_calls"] == 0)
        phase = "final_integrity"
        check("all_original_run_artifacts_unchanged_during_audit", all(sha((run / name).read_bytes()) == digest for name, digest in before.items()))
        check("all_frozen_sources_unchanged_during_audit", all(sha((ROOT / name).read_bytes()) == digest for name, digest in FROZEN.items()))
        return finish(artifact_sha256=before, frozen_implementation_sha256=FROZEN,
            earlier_runs=earlier_receipts, guarded_driver_replay=replay,
            candidate_statistical_units={"materials": 120, "development": 80, "already_exposed_regression": 40,
                "new_independent_materials": 0, "fresh64_accessed": False})
    except ERRORS as exc:
        check("artifact_structure_or_replay_complete", False)
        return finish(error_type=type(exc).__name__, error_code="offline_artifact_or_replay_failure")


def self_test():
    def row(old, completions, *, complete=True):
        return {"prior_pool": {"candidates": old}, "proposals": {"completions": completions,
            "status": "candidates_only" if complete else "needs_review", "complete": complete}}
    def item(start, category="PERSON"):
        return {"source_id": "synthetic", "start": start, "end": start + 1, "category": category}
    tests = {}
    g, n = item(1), item(3)
    tests["nongold_completion_already_in_full_prior_is_not_new"] = _coverage(row([n], [n]), [g])["new_nongold_candidates"] == 0
    tests["novel_nongold_completion_is_new"] = _coverage(row([], [n]), [g])["new_nongold_candidates"] == 1
    tests["novel_exact_gold_completion_is_new"] = _coverage(row([], [g]), [g])["new_exact_gold_candidates"] == 1
    tests["existing_interval_other_optional_type_is_still_not_new"] = _coverage(row([item(3, "ORG")], [n]), [g])["new_nongold_candidates"] == 0
    review = _coverage(row([], [g], complete=False), [g])
    tests["partial_review_proposal_not_qualified"] = review["all_proposal_union_covered"] == 1 and review["fully_qualified_union_covered"] == 0
    wrong_hint = row([], [item(1, "ORG")])
    tests["span_coverage_not_equal_type_classification"] = _span_coverage(wrong_hint, [g])["new_gold_intervals"] == 1 and _coverage(wrong_hint, [g])["new_exact_gold_candidates"] == 0
    tests["duplicate_completion_not_counted_twice"] = _coverage(row([], [g, g]), [g])["new_exact_gold_candidates"] == 1
    return {"status": "passed" if all(tests.values()) else "failed", "tests": tests,
        "model_calls": 0, "network_calls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--parent", type=Path)
    parser.add_argument("--earlier", type=Path, action="append")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] == "passed" else 1
    if args.run is None or args.output is None:
        parser.error("--run and --output required")
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "results").resolve()) or output.exists():
        parser.error("new output file under results required; existing receipts are never overwritten")
    result = verify(args.run, archive=args.archive, parent=args.parent, earlier=args.earlier)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    passed = sum(c["passed"] for c in result["checks"])
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]), "passed": passed,
        "failed": len(result["checks"]) - passed, "summary": result["summary"],
        "verification_model_calls": 0, "method_acceptance": False,
        "receipt": output.relative_to(ROOT).as_posix()}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
