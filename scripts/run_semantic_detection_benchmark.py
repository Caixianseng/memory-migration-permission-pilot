"""Frozen five-condition, local-only nine-category detection comparison.

Runtime inputs are consumed before gold is parsed. Non-ok detections accept no
predictions in the main score; retained validated candidates are scored separately.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from memory_migration_study.local_detector import LocalSensitivityAgent
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import CATEGORIES, _policy, _sources, detect_sensitive

ARMS = ("rules", "qwen_agent", "qwen_combined", "gliner_combined", "union_combined")
VERSION = "semantic_detection_comparison_v2_union"
INFERENCE_KINDS = ("local_encoder", "local_generation", "unknown")


class CountingAgent:
    """Observe trusted adapter accounting without altering its detection output.

    A union must provide its own typed counts. Its total is never guessed to be
    entirely encoding or generation. Missing/mismatched accounting stays visible.
    """
    def __init__(self, agent, kind):
        self.agent, self.kind, self.observations = agent, kind, []

    @property
    def max_local_calls(self):
        # Limits come from the trusted callable, never from model output. In
        # particular, a union permits one encoding plus up to two generations.
        return getattr(self.agent, "max_local_calls", 2)

    def __call__(self, **kwargs):
        observation = {"inference_counts": {kind: 0 for kind in INFERENCE_KINDS},
                       "complete": False, "errors": [], "unclassified_reported_calls": 0}
        self.observations.append(observation)
        try:
            response = self.agent(**kwargs)
        except Exception:
            observation["errors"].append("adapter_raised_call_count_unknown")
            raise
        calls = response.get("local_calls") if isinstance(response, dict) else None
        valid_calls = type(calls) is int and calls >= 0
        typed = response.get("inference_counts") if isinstance(response, dict) else None
        if typed is not None:
            if (isinstance(typed, dict) and {"local_encoder", "local_generation"} <= set(typed) <= set(INFERENCE_KINDS)
                    and all(type(value) is int and value >= 0 for value in typed.values())):
                observation["inference_counts"] = {kind: typed.get(kind, 0) for kind in INFERENCE_KINDS}
                observation["complete"] = (valid_calls and sum(typed.values()) == calls
                                           and response.get("local_calls_complete", True) is True)
                if not observation["complete"]:
                    observation["errors"].append("typed_total_mismatch")
            else:
                observation["errors"].append("invalid_typed_accounting")
                observation["unclassified_reported_calls"] = calls if valid_calls else 0
                observation["inference_counts"]["unknown"] = observation["unclassified_reported_calls"]
        elif self.kind in INFERENCE_KINDS and valid_calls:
            observation["inference_counts"][self.kind] = calls
            observation["complete"] = response.get("local_calls_complete", True) is True
            if not observation["complete"]:
                observation["errors"].append("adapter_reported_incomplete_calls")
        else:
            observation["errors"].append("union_typed_accounting_missing")
            observation["unclassified_reported_calls"] = calls if valid_calls else 0
            observation["inference_counts"]["unknown"] = observation["unclassified_reported_calls"]
        typed = observation["inference_counts"]
        if typed["unknown"]:
            observation["complete"] = False
            observation["unclassified_reported_calls"] = typed["unknown"]
            observation["errors"].append("unknown_inference_kind")
        if typed["local_encoder"] > 1 or typed["local_generation"] > 2:
            # Preserve the actual declared values rather than clipping repairs.
            observation["complete"] = False
            observation["errors"].append("per_source_adapter_budget_exceeded")
        if isinstance(response, dict) and isinstance(response.get("member_observations"), list):
            observation["member_observations"] = copy.deepcopy(response["member_observations"])
        return response

    def accounting(self, detection):
        typed = {kind: sum(o["inference_counts"][kind] for o in self.observations) for kind in INFERENCE_KINDS}
        matches = detection.get("local_calls") == sum(typed.values())
        return {"inference_counts": typed, "observations": self.observations,
                "complete": all(o["complete"] for o in self.observations)
                            and detection.get("local_calls_complete", False) and matches,
                "host_local_calls": detection.get("local_calls"), "host_total_matches_typed": matches,
                "unclassified_reported_calls": sum(o["unclassified_reported_calls"] for o in self.observations)}


def selected_arms(arms=None):
    if arms is None:
        return ARMS
    if (not isinstance(arms, (list, tuple)) or not arms or len(set(arms)) != len(arms)
            or any(arm not in ARMS for arm in arms)):
        raise ValueError("invalid_arm_selection")
    return tuple(arm for arm in ARMS if arm in arms)


def save(path, obj):
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def counts(predicted, expected):
    tp, fp, fn = len(predicted & expected), len(predicted - expected), len(expected - predicted)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def finding_keys(findings, payload, *, strict=False):
    sources = _sources(payload)
    keys, invalid, duplicates = set(), 0, 0
    for finding in findings:
        if not isinstance(finding, dict):
            invalid += 1
            continue
        sid, start, end, category = (finding.get(k) for k in ("source_id", "start", "end", "category"))
        if (not isinstance(sid, str) or sid not in sources or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(sources[sid]) or category not in CATEGORIES):
            invalid += 1
            continue
        key = (sid, start, end, category)
        duplicates += key in keys
        keys.add(key)
    if strict and (invalid or duplicates):
        raise ValueError("invalid_or_duplicate_gold_span")
    return keys, invalid, duplicates


def score_detection(detection, gold, payload):
    """Exact full spans; failed material cannot disappear from recall denominator."""
    expected, _, _ = finding_keys(gold["findings"], payload, strict=True)
    candidates, invalid, duplicate = finding_keys(detection.get("findings", []), payload)
    accepted = candidates if detection.get("status") == "ok" and not invalid else set()
    return {"accepted": counts(accepted, expected), "validated_candidate": counts(candidates, expected),
            "invalid_candidate_count": invalid, "duplicate_candidate_count": duplicate,
            "accepted_complete_exact": detection.get("status") == "ok" and not invalid and accepted == expected,
            "gold_spans": len(expected), "accepted_spans": len(accepted), "validated_candidate_spans": len(candidates),
            "by_category": {category: {"accepted": counts({p for p in accepted if p[3] == category},
                                                         {p for p in expected if p[3] == category}),
                                       "validated_candidate": counts({p for p in candidates if p[3] == category},
                                                                    {p for p in expected if p[3] == category})}
                            for category in sorted(CATEGORIES)}}


def sum_counts(scores):
    total = {key: sum(s[key] for s in scores) for key in ("tp", "fp", "fn")}
    tp, fp, fn = (total[k] for k in ("tp", "fp", "fn"))
    total.update(precision=tp / (tp + fp) if tp + fp else None, recall=tp / (tp + fn) if tp + fn else None)
    return total


def summarize(rows, arms=None):
    result = {}
    for arm in selected_arms(arms):
        selected = [r for r in rows if r["arm"] == arm]
        def group(items):
            main = sum_counts([r["score"]["accepted"] for r in items])
            return {"materials": len(items), "accepted": main,
                    "validated_candidate": sum_counts([r["score"]["validated_candidate"] for r in items]),
                    "ok": sum(r["detection"]["status"] == "ok" for r in items),
                    "needs_review": sum(r["detection"]["status"] == "needs_review" for r in items),
                    "other_non_ok": sum(r["detection"]["status"] not in {"ok", "needs_review"} for r in items),
                    "complete_exact_materials": sum(r["score"]["accepted_complete_exact"] for r in items),
                    "errors": dict(sorted(Counter(e for r in items for e in r["detection"].get("errors", [])).items())),
                    "incomplete_call_accounting": sum(not r["accounting"]["complete"] for r in items),
                    "unclassified_reported_calls": sum(r["accounting"]["unclassified_reported_calls"] for r in items),
                    "accounting_errors": dict(sorted(Counter(e for r in items for o in r["accounting"]["observations"]
                                                               for e in o["errors"]).items())),
                    "qwen_generations_reported": sum(r["qwen_generations"] for r in items),
                    "encoder_invocations_reported": sum(r["encoder_invocations"] for r in items),
                    "wall_seconds": round(sum(r["wall_seconds"] for r in items), 6),
                    "reported_agent_seconds": round(sum(r["detection"].get("agent_elapsed_seconds", 0) for r in items), 6),
                    "recall95_precision90_met": (main["recall"] is not None and main["recall"] >= .95
                                                 and main["precision"] is not None and main["precision"] >= .90)}
        metrics = group(selected)
        metrics["by_language"] = {lang: group([r for r in selected if r["language"] == lang]) for lang in ("en", "zh")}
        metrics["by_policy_scope"] = {scope: group([r for r in selected if r["policy_scope"] == scope])
                                      for scope in ("private_type", "public_empty")}
        metrics["by_category"] = {cat: {channel: sum_counts([r["score"]["by_category"][cat][channel] for r in selected])
                                                   for channel in ("accepted", "validated_candidate")}
                                  for cat in sorted(CATEGORIES)}
        pairs = {}
        for row in selected:
            if row.get("policy_pair_id"):
                pairs.setdefault(row["policy_pair_id"], []).append(row)
        metrics["policy_pairs"] = {"pairs": len(pairs),
            "complete_two_material_pairs": sum(len(pair) == 2 for pair in pairs.values()),
            "both_materials_complete_exact": sum(len(pair) == 2 and all(r["score"]["accepted_complete_exact"] for r in pair)
                                                 for pair in pairs.values()),
            "private_non_ok_pairs": sum(any(r["policy_scope"] == "private_type" and r["detection"]["status"] != "ok" for r in pair)
                                         for pair in pairs.values()),
            "public_false_positive_pairs": sum(any(r["policy_scope"] == "public_empty" and r["score"]["accepted"]["fp"] > 0 for r in pair)
                                                for pair in pairs.values())}
        result[arm] = metrics
    return result


def recheck_saved_accounting(run_dir, output):
    """Repair only cost classification from saved union member observations.

    This does not load models or gold, change predictions, rejudge failures, or
    overwrite the original report. Old host caps may have lost the union total;
    complete member counts independently prove a recoverable classified total.
    """
    run_dir, output = Path(run_dir), Path(output)
    if output.exists():
        raise FileExistsError("accounting_recheck_output_already_exists")
    report_path, rows_path = run_dir / "report.json", run_dir / "rows.json"
    report_hash, rows_hash = sha(report_path), sha(rows_path)
    original = json.loads(report_path.read_text(encoding="utf-8"))
    saved_rows = json.loads(rows_path.read_text(encoding="utf-8"))
    if original["rows"] != saved_rows:
        raise ValueError("saved_report_row_mismatch")
    rows = copy.deepcopy(saved_rows)
    changed, old_host_incomplete, old_host_mismatch = 0, 0, 0
    for row in rows:
        if row["arm"] != "union_combined":
            continue
        old = row["accounting"]
        observations = []
        for observation in old["observations"]:
            typed = {kind: 0 for kind in INFERENCE_KINDS}
            members = observation.get("member_observations")
            complete, errors = isinstance(members, list) and len(members) == 2, []
            if not complete:
                errors.append("saved_member_contract_missing")
            for index, member in enumerate(members if isinstance(members, list) else []):
                if not isinstance(member, dict):
                    complete = False
                    errors.append("saved_member_accounting_invalid")
                    continue
                kind, calls = member.get("inference_kind"), member.get("local_calls")
                valid = (member.get("index") == index and kind == ("local_encoder", "local_generation")[index]
                         if index < 2 else False)
                if type(calls) is int and calls >= 0 and kind in INFERENCE_KINDS:
                    typed[kind] += calls
                if (not valid or type(calls) is not int or calls < 0 or kind not in INFERENCE_KINDS
                        or member.get("local_calls_complete") is not True):
                    complete = False
                    errors.append("saved_member_accounting_invalid")
                    continue
                if calls > (1 if kind == "local_encoder" else 2):
                    complete = False
                    errors.append("saved_member_budget_exceeded")
            observations.append({"inference_counts": typed, "complete": complete, "errors": sorted(set(errors)),
                "unclassified_reported_calls": typed["unknown"],
                "member_observations": copy.deepcopy(members),
                "original_counter_errors": observation.get("errors", [])})
        typed = {kind: sum(o["inference_counts"][kind] for o in observations) for kind in INFERENCE_KINDS}
        host = row["detection"].get("local_calls")
        matches = host == sum(typed.values())
        host_complete = row["detection"].get("local_calls_complete", False)
        old_host_incomplete += not host_complete
        old_host_mismatch += not matches
        corrected = {"inference_counts": typed, "observations": observations,
            "complete": all(o["complete"] for o in observations),
            "host_local_calls": host, "host_total_matches_typed": matches,
            "original_host_call_accounting_complete": host_complete,
            "unclassified_reported_calls": sum(o["unclassified_reported_calls"] for o in observations),
            "basis": "Independent reconstruction from saved, explicitly typed member observations; original host counts are preserved separately."}
        changed += old != corrected or row["qwen_generations"] != typed["local_generation"] or row["encoder_invocations"] != typed["local_encoder"]
        row["accounting"] = corrected
        row["qwen_generations"], row["encoder_invocations"] = typed["local_generation"], typed["local_encoder"]
    predictions_unchanged = all(new["detection"] == old["detection"] and new["score"] == old["score"]
                                for new, old in zip(rows, saved_rows))
    if not predictions_unchanged or sha(report_path) != report_hash or sha(rows_path) != rows_hash:
        raise ValueError("original_evidence_changed_during_recheck")
    arms = [arm for arm in ARMS if any(r["arm"] == arm for r in rows)]
    result = {"version": "semantic_detection_accounting_recheck_v1", "original_report_sha256": report_hash,
        "original_rows_sha256": rows_hash, "recheck_script_sha256": sha(__file__),
        "rows": rows, "arms": summarize(rows, arms), "corrected_union_rows": changed,
        "original_host_incomplete_union_rows": old_host_incomplete, "original_host_mismatched_union_rows": old_host_mismatch,
        "predictions_and_scores_unchanged": predictions_unchanged,
        "complete_reconstructed_call_accounting": all(r["accounting"]["complete"] for r in rows),
        "qwen_generations_recomputed": sum(r["qwen_generations"] for r in rows),
        "encoder_invocations_recomputed": sum(r["encoder_invocations"] for r in rows),
        "unclassified_reported_calls": sum(r["accounting"]["unclassified_reported_calls"] for r in rows),
        "new_model_calls": 0, "new_api_cost_cny": 0,
        "scope": "Cost-only reclassification from archived per-member counts. Original raw report, detection statuses, spans, errors and scores remain unchanged. Recoverable member totals do not retroactively repair the original host counter or constitute a new model experiment."}
    output.parent.mkdir(parents=True, exist_ok=True)
    save(output, result)
    return result


def run(data_root, split, output, config, model_root, *, baseline=None, runtime_model=None, progress=None,
        arms=None, union_factory=None):
    if split not in {"development", "heldout"}:
        raise ValueError("invalid_split")
    arms = selected_arms(arms)
    data_root, output = Path(data_root), Path(output)
    manifest = json.loads((data_root / "manifest.json").read_text(encoding="utf-8"))
    runtime_path, gold_path = data_root / split / "runtime.json", data_root / split / "evaluation.json"
    for path in (runtime_path, gold_path):
        if sha(path) != manifest["files"][path.relative_to(data_root).as_posix()]["sha256"]:
            raise ValueError("frozen_input_hash_mismatch")
    # Hash gold bytes for preregistration; do not parse or expose labels here.
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    if len({r["case_id"] for r in runtime}) != len(runtime):
        raise ValueError("duplicate_case_identity")
    for record in runtime:
        if set(record) != {"case_id", "language", "template_family", "policy", "payload"}:
            raise ValueError("runtime_fields_must_exclude_gold")
        _sources(record["payload"])
        _policy(record["policy"])
    package = Path(__file__).resolve().parents[1] / "memory_migration_study"
    before = {p.name: sha(p) for p in package.glob("*.py")}
    script_before = sha(__file__)
    output.mkdir(parents=True, exist_ok=False)
    archive = output / "implementation"
    archive.mkdir()
    for path in package.glob("*.py"):
        shutil.copy2(path, archive / path.name)
    shutil.copy2(__file__, output / "executed_benchmark.py")
    shutil.copy2(runtime_path, output / "runtime.json")
    save(output / "plan.json", {"version": VERSION, "split": split, "arms": list(arms), "config": config,
        "runtime_sha256": sha(runtime_path), "evaluation_sha256": sha(gold_path), "manifest_sha256": sha(data_root / "manifest.json"),
        "package_sha256": before, "script_sha256": script_before, "gliner_splitter": "cjk_aware", "gliner_threshold": .5,
        "randomization": "Per-case Random(version + case_id).shuffle(all selected arms)",
        "union_contract": "Independent GLiNER + Qwen, no threshold tuning or span deletion; any member non-ok must keep union non-ok. Typed inference_counts, including generation repairs, are observed without clipping.",
        "main_score": "Exact source_id/start/end/category sets. Non-ok accepts zero predictions; gold FN retained.",
        "candidate_score": "Only host-validated findings retained in detect_sensitive output; not raw rejected model text.",
        "targets": {"sensitive_span_recall": .95, "sensitive_span_precision": .90},
        "split_statistics": manifest["splits"][split]})
    init_started = time.monotonic()
    identities = {}
    if any(arm in arms for arm in ("qwen_agent", "qwen_combined", "union_combined")):
        baseline = baseline or LocalSensitivityAgent(config)
        if hasattr(baseline, "health"):
            baseline.health()
        identities["qwen"] = baseline.cache_identity()
    ner = None
    if any(arm in arms for arm in ("gliner_combined", "union_combined")):
        runtime_model = runtime_model or LocalNerRuntime(model_root)
        ner = GlinerEntityAgent(runtime_model, approved_policies=[r["policy"] for r in runtime], splitter="cjk_aware", threshold=.5)
        identities["gliner"] = ner.cache_identity()
    union = None
    if "union_combined" in arms:
        if union_factory is None:
            from memory_migration_study.union_detector import IndependentUnionDetector
            union_factory = IndependentUnionDetector
        union = union_factory(first=ner, second=baseline, member_kinds=("local_encoder", "local_generation"))
        identities["union"] = union.cache_identity()
    save(output / "detectors.json", dict(identities, initialization_seconds=time.monotonic() - init_started))
    methods = {"rules": ("rules", None, None), "qwen_agent": ("agent", baseline, "local_generation"),
               "qwen_combined": ("combined", baseline, "local_generation"),
               "gliner_combined": ("combined", ner, "local_encoder"),
               "union_combined": ("combined", union, "independent_union")}
    rows = []
    for record in runtime:
        order = list(arms)
        random.Random(VERSION + record["case_id"]).shuffle(order)
        for arm in order:
            mode, detector, kind = methods[arm]
            observer = CountingAgent(detector, kind) if detector is not None else None
            started = time.monotonic()
            result = detect_sensitive(record["payload"], record["policy"], mode=mode, agent=observer)
            accounting = (observer.accounting(result) if observer is not None else
                          {"inference_counts": {k: 0 for k in INFERENCE_KINDS}, "observations": [],
                           "complete": True, "host_local_calls": 0, "host_total_matches_typed": True,
                           "unclassified_reported_calls": 0})
            rows.append({"case_id": record["case_id"], "language": record["language"], "template_family": record["template_family"],
                "arm": arm, "policy_scope": "private_type" if record["policy"]["protected_categories"] else "public_empty",
                "detection": result, "wall_seconds": time.monotonic() - started, "accounting": accounting,
                "qwen_generations": accounting["inference_counts"]["local_generation"],
                "encoder_invocations": accounting["inference_counts"]["local_encoder"]})
            save(output / "rows.json", rows)
            if progress:
                progress({"completed": len(rows), "expected": len(runtime) * len(arms), "arm": arm,
                          "case_id": record["case_id"], "status": result["status"]})
    # The model loop is finished. Only now load labels and compute every score.
    if sha(gold_path) != manifest["files"][f"{split}/evaluation.json"]["sha256"]:
        raise ValueError("gold_changed_during_execution")
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    if set(gold) != {r["case_id"] for r in runtime}:
        raise ValueError("gold_runtime_identity_mismatch")
    by_id = {r["case_id"]: r for r in runtime}
    for row in rows:
        expected = gold[row["case_id"]]
        row["score"] = score_detection(row["detection"], expected, by_id[row["case_id"]]["payload"])
        row["policy_pair_id"] = expected.get("policy_pair_id")
    shutil.copy2(gold_path, output / "evaluation.json")
    after = {p.name: sha(p) for p in package.glob("*.py")}
    summary = summarize(rows, arms)
    report = {"version": VERSION, "split": split, "material_count": len(runtime), "rows": rows, "arms": summary,
        "implementation_unchanged": before == after and script_before == sha(__file__),
        "qwen_generations_reported": sum(r["qwen_generations"] for r in rows),
        "encoder_invocations_reported": sum(r["encoder_invocations"] for r in rows),
        "unclassified_reported_calls": sum(r["accounting"]["unclassified_reported_calls"] for r in rows),
        "complete_call_accounting": all(r["accounting"]["complete"] for r in rows),
        "cloud_calls": 0, "new_api_cost_cny": 0,
        "scope": "Authored synthetic nine-type materials, not enterprise or public-standard data. Heldout has only 20 positive spans and 3 template families; 40 materials include 18 paired public/private payloads, not 40 independent contents. Development has 80 materials. Per-language/category/pair results and non-ok failures remain visible. Main 95/90 targets are development gates, not a privacy proof or full-project completion. Call counts are reported observations; incomplete accounting is explicit."}
    save(output / "rows.json", rows)
    save(output / "report.json", report)
    save(output / "summary.json", {k: v for k, v in report.items() if k != "rows"})
    return report


def install_network_guard(network):
    def audit(event, values):
        if event == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["blocked_external_connections"] += 1
                raise RuntimeError("external_network_disabled_for_inference")
            network["allowed_loopback_connections"] += 1
    sys.addaudithook(audit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("development", "heldout"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/local_privacy_detector.json"))
    parser.add_argument("--model-root", type=Path, default=Path(".runtime/github_ner"))
    parser.add_argument("--data-root", type=Path, default=Path("examples/privacy_semantics_v1/detection"))
    parser.add_argument("--arms", choices=ARMS, nargs="+", default=None)
    args = parser.parse_args()
    network = {"allowed_loopback_connections": 0, "blocked_external_connections": 0}
    install_network_guard(network)
    existed = args.output.exists()
    try:
        report = run(args.data_root, args.split, args.output, json.loads(args.config.read_text(encoding="utf-8")), args.model_root, arms=args.arms,
                     progress=lambda r: print(json.dumps(r, ensure_ascii=False), flush=True))
        print(json.dumps({"output": str(args.output), "arms": report["arms"], "network": network}, ensure_ascii=False))
    finally:
        if not existed and args.output.is_dir():
            save(args.output / "network_audit.json", network)
