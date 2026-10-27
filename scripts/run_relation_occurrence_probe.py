"""Freeze and run a bounded, local relation/occurrence development comparison.

Model observations and actual prepared payloads close before reference parsing.
No default detector, old experiment, native client, or cloud service is changed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_ontology_contract_probe as common
from scripts import relation_probe_scoring as scoring
from memory_migration_study import occurrence_qwen as qwen
from memory_migration_study import relation_occurrence as relation
from memory_migration_study.local_detector import _strict_json
from memory_migration_study.ner_detector import LocalNerRuntime
from memory_migration_study.nli_candidate import PinnedNLIRuntime
from memory_migration_study.privacy import _digest, _policy
from memory_migration_study.sensitivity_contract import bind_category_contract

VERSION = "relation_occurrence_probe_v1"
ARMS = ("occurrence_qwen", "gliner_relation", "nli_relation")
PROFILES = common.PROFILES
LIMITS = {"texts": 12, "opportunities": 72, "qwen_posts": 48,
          "ner_proposals": 12, "gliner_classifications": 24, "nli_pairs": 96,
          "max_candidates": 2, "wall_seconds": 1200, "cloud_calls": 0, "native_calls": 0}
FILES = ("scripts/run_relation_occurrence_probe.py", "scripts/relation_probe_scoring.py",
         "scripts/run_ontology_contract_probe.py", "scripts/qualify_mdeberta_nli_runtime_v2.py",
         "scripts/qualify_mdeberta_nli_runtime_v3.py", "configs/mdeberta_nli_assets_v1.json",
         "tests/test_relation_occurrence.py", "tests/test_occurrence_qwen.py",
         "tests/test_relation_probe_scoring.py", "tests/test_relation_occurrence_probe.py")


def require(condition, code):
    if not condition:
        raise ValueError("relation_probe_" + code)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_texts(path):
    data = read_json(path)
    require(set(data) == {"schema_version", "texts"}
            and data["schema_version"] == "relation_occurrence_probe_runtime_v1"
            and isinstance(data["texts"], list) and len(data["texts"]) == 12
            and all(isinstance(text, str) and text.strip() for text in data["texts"])
            and len(set(data["texts"])) == 12, "runtime_invalid")
    return data["texts"]


def source_hashes():
    paths = {path.relative_to(ROOT).as_posix() for path in (ROOT / "memory_migration_study").glob("*.py")}
    return {name: common.sha(ROOT / name) for name in sorted(paths | set(FILES))}


def make_policies():
    return {profile: _policy(bind_category_contract({"version": "relation_probe_policy_v1",
        "policy_id": "relation_probe", "protected_categories": ["CUSTOMER"],
        "max_text_chars": 6000, "instructions": common.SCOPE, "entity_registry": []}, profile))
        for profile in PROFILES}


def qwen_preflight(texts, policies):
    requests = []
    for index, text in enumerate(texts):
        for profile, policy in policies.items():
            data, trusted = qwen.OccurrenceQwenAgent._validate_inputs(text, "probe", policy, [])
            messages, version = qwen.OccurrenceQwenAgent._prepare_messages(data, trusted)
            repaired = [*messages, {"role": "user", "content": qwen.REPAIR_PROMPT}]
            first = qwen.OccurrenceQwenAgent._request_budget(messages)
            second = qwen.OccurrenceQwenAgent._request_budget(repaired, repair=True)
            requests.append({"text_index": index, "profile": profile, "version": version,
                             "messages_sha256": _digest(messages), "initial_bound": first,
                             "repair_bound": second, "fits": max(first, second) <= 4096})
    require(all(row["fits"] for row in requests), "qwen_input_budget_exceeded")
    return requests


def freeze(output, materials, prereg):
    output, materials, prereg = Path(output).resolve(), Path(materials).resolve(), Path(prereg).resolve()
    require(not output.exists(), "output_exists")
    texts, policies = read_texts(materials / "runtime.json"), make_policies()
    preflight = qwen_preflight(texts, policies)
    sources = source_hashes()
    assets = common.checked_assets(ROOT / ".runtime/github_ner")
    nli_health = PinnedNLIRuntime({"max_forwards": LIMITS["nli_pairs"]}).health()
    plan = {"version": VERSION, "status": "frozen_not_executed", "limits": LIMITS,
            "source_sha256": sources, "assets": assets, "nli_health": nli_health,
            "runtime_sha256": common.sha(materials / "runtime.json"),
            "reference_opaque_sha256": common.sha(materials / "evaluation.json"),
            "prereg_sha256": common.sha(prereg), "policies": policies, "qwen_preflight": preflight,
            "source_id": "probe", "threads": 2, "interop_threads": 2,
            "shared_evidence": "One proposal pool and one evidence result per encoder arm per text, reused for both policies; not independent inferences.",
            "reference_rule": "Parse only after 72 raw predictions and actual preparation outputs close.",
            "scoring_rule": "Known-positive review/invalid retains FN; blocked payload is not useful success; no masked-value transport to cloud.",
            "stop_rule": "Unknown engineering, asset, binding, accounting or budget errors stop. Registered coverage and model-output failures remain unsuccessful observations without outer retries."}
    output.mkdir(parents=True)
    for name in sources:
        destination = output / "implementation" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    shutil.copy2(materials / "runtime.json", output / "runtime.json")
    shutil.copy2(materials / "evaluation.json", output / "evaluation.opaque.json")
    shutil.copy2(prereg, output / "preregistration.md")
    common.save_exclusive(output / "plan.json", plan)
    return {"status": plan["status"], "plan_sha256": common.sha(output / "plan.json"),
            "source_files": len(sources), "model_calls": 0}


def verify(output, plan_hash):
    output = Path(output)
    require(common.sha(output / "plan.json") == plan_hash, "plan_changed")
    plan = read_json(output / "plan.json")
    require(plan["version"] == VERSION and plan["limits"] == LIMITS, "contract_changed")
    require(source_hashes() == plan["source_sha256"], "source_changed")
    common.verify_implementation_archive(output, plan["source_sha256"])
    for name, key in (("runtime.json", "runtime_sha256"), ("evaluation.opaque.json", "reference_opaque_sha256"),
                      ("preregistration.md", "prereg_sha256")):
        require(common.sha(output / name) == plan[key], "material_changed")
    texts = read_texts(output / "runtime.json")
    require(make_policies() == plan["policies"] and qwen_preflight(texts, plan["policies"]) == plan["qwen_preflight"],
            "policy_or_input_changed")
    return plan, texts


class Budget:
    def __init__(self):
        self.started, self.posts = time.monotonic(), 0

    def check(self):
        require(time.monotonic() - self.started < LIMITS["wall_seconds"], "wall_budget_exceeded")

    def generation(self):
        self.check()
        require(self.posts < LIMITS["qwen_posts"], "post_budget_exceeded")
        self.posts += 1


def qwen_status(response, events, cell, text):
    if response.get("status") == "ok" and response.get("errors") == []:
        return "ok"
    if response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"]:
        return "needs_review"
    if (response.get("status") == "needs_review" and response.get("errors") == ["input_budget_exceeded"]
            and response.get("local_calls") == 0):
        return "coverage_review"
    posts = [event for event in events if event["method"] == "POST" and event["cell"] == cell]
    if (response.get("status") == "needs_review" and response.get("errors") == ["format_or_span_invalid"]
            and response.get("local_calls") == 2 and len(posts) == 2):
        for event in posts:
            raw = event.get("decoded_response", {})
            message = raw.get("message", {})
            if (event.get("error_type") or raw.get("done") is not True or raw.get("done_reason") != "stop"
                    or raw.get("model") != qwen.MODEL or not isinstance(message, dict)
                    or not isinstance(message.get("content"), str) or message.get("thinking") or message.get("tool_calls")):
                return "engineering_error"
            try:
                qwen.OccurrenceQwenAgent._validate_output(_strict_json(message["content"]), text, ["CUSTOMER"])
            except (ValueError, TypeError, KeyError):
                pass
            else:
                return "engineering_error"
        return "model_output_invalid"
    return "engineering_error"


def evidence_status(pool, evidence, response):
    require(pool.get("error_kind") != "engineering" and evidence.get("error_kind") != "engineering", "encoder_engineering_error")
    if pool.get("error_kind") == "coverage" or evidence.get("error_kind") == "coverage":
        require(response.get("status") == "needs_review", "coverage_was_accepted")
        return "coverage_review"
    require(pool.get("status") == evidence.get("status") == "ok", "encoder_status_invalid")
    if response.get("status") == "ok" and response.get("errors") == []:
        return "ok"
    require(response.get("status") == "needs_review" and response.get("errors") == ["semantic_uncertainty"],
            "decision_status_invalid")
    return "needs_review"


def close_predictions(output, plan_hash, rows, shared, captures, counts, *, budget=None):
    output = Path(output)
    if budget is not None:
        budget.check()
    plan, texts = verify(output, plan_hash)
    expected = {(i, p, a) for i in range(12) for p in PROFILES for a in ARMS}
    require(len(rows) == 72 and {(r["cell"]["text_index"], r["cell"]["profile"], r["cell"]["arm"]) for r in rows} == expected,
            "prediction_inventory_incomplete")
    common.save_exclusive(output / "predictions.json", rows)
    common.save_exclusive(output / "shared_evidence.json", shared)
    capture_hashes = {name: common.sha(output / name) for name in captures}
    closure = {"version": VERSION, "plan_sha256": plan_hash, "reference_parsed": False,
               "opportunities": 72, "predictions_sha256": common.sha(output / "predictions.json"),
               "shared_evidence_sha256": common.sha(output / "shared_evidence.json"),
               "capture_sha256": capture_hashes, "counts": counts,
               "source_and_archive_verified": True, "closed_at_unix": time.time()}
    common.save_exclusive(output / "prediction_phase_closed.json", closure)
    closure_hash = common.sha(output / "prediction_phase_closed.json")
    if budget is not None:
        budget.check()
    # FIRST reference parse: no score or reference-dependent preparation precedes this line.
    reference = read_json(output / "evaluation.opaque.json")
    require(reference.get("runtime_sha256") == plan["runtime_sha256"], "reference_runtime_mismatch")
    scored = scoring.score_rows(rows, reference, texts)
    if budget is not None:
        budget.check()
    verify(output, plan_hash)
    require(common.sha(output / "predictions.json") == closure["predictions_sha256"]
            and common.sha(output / "prediction_phase_closed.json") == closure_hash
            and common.sha(output / "shared_evidence.json") == closure["shared_evidence_sha256"]
            and all(common.sha(output / name) == value for name, value in capture_hashes.items()), "closed_evidence_changed")
    common.save_exclusive(output / "scored_rows.json", scored["scored_rows"])
    return {"version": VERSION, "status": "complete", "plan_sha256": plan_hash,
            "predictions_sha256": closure["predictions_sha256"], "closure_sha256": closure_hash,
            "counts": counts, "opportunities": 72, "texts": 12,
            "status_inventory": dict(Counter(row["status"] for row in rows)),
            "by_profile_arm": scored["by_profile_arm"], "cloud_calls": 0, "native_calls": 0,
            "scope": "New development diagnostic, not independent64 acceptance or established algorithm novelty."}


def execute(output, plan_hash):
    output = Path(output).resolve()
    require(not (output / "execution.json").exists(), "already_started")
    plan, texts = verify(output, plan_hash)
    require(common.checked_assets(plan["assets"]["root"]) == plan["assets"], "ner_assets_changed")
    nli = PinnedNLIRuntime({"max_forwards": LIMITS["nli_pairs"]})
    require(nli.health() == plan["nli_health"], "nli_health_changed")
    budget, rows, shared = Budget(), [], []
    network = {"loopback_connect_attempts": 0, "blocked_connects": 0}
    common.install_network_guard(network)
    execution = {"status": "started", "plan_sha256": plan_hash, "reference_parsed": False}
    common.save_exclusive(output / "execution.json", execution)
    encoder_events, nli_events, active = [], [], {"text_index": None}
    captures = ("http_transport_capture.json", "encoder_capture.json", "nli_capture.json")
    for name in captures:
        common.save_exclusive(output / name, [])
    try:
        import torch
        torch.set_num_threads(plan["threads"])
        if torch.get_num_interop_threads() != plan["interop_threads"]:
            torch.set_num_interop_threads(plan["interop_threads"])
        torch.manual_seed(42)
        actual_ner = LocalNerRuntime(plan["assets"]["root"], threads=plan["threads"])
        def capture_encoder(event):
            encoder_events.append({"text_index": active["text_index"], "event": copy.deepcopy(event)})
            common.save(output / "encoder_capture.json", encoder_events)
            budget.check()
        encoder = relation.GlinerOccurrenceRuntime(actual_ner, max_proposals=LIMITS["ner_proposals"],
                                                   max_classifications=LIMITS["gliner_classifications"],
                                                   on_capture=capture_encoder)
        original_predict = nli.predict
        def captured_predict(inputs):
            budget.check()
            event = {"text_index": active["text_index"], "inputs": copy.deepcopy(inputs),
                     "input_sha256": _digest(inputs), "before": nli.snapshot_counts()}
            nli_events.append(event)
            try:
                result = original_predict(inputs)
                event["decoded_response"] = copy.deepcopy(result)
                return result
            except Exception as exc:
                event["error_type"] = type(exc).__name__
                raise
            finally:
                event["after"] = nli.snapshot_counts()
                common.save(output / "nli_capture.json", nli_events)
                budget.check()
        nli.predict = captured_predict
        local = qwen.OccurrenceQwenAgent()
        transport = common.CapturedTransport(local._transport, budget, output)
        local.transport = transport
        common.save_exclusive(output / "identities.json", {"qwen_health": local.health(),
                              "qwen": local.cache_identity(), "ner": actual_ner.identity, "nli": nli.health()})
        for index, text in enumerate(texts):
            budget.check()
            verify(output, plan_hash)
            active["text_index"] = index
            pool = relation.propose(text, runtime=encoder)
            require(pool.get("error_kind") != "engineering", "proposal_engineering_error")
            gliner = relation.classify_gliner(text, pool, runtime=encoder, scope=common.SCOPE)
            nli_evidence = relation.classify_nli(text, pool, runtime=nli, scope=common.SCOPE)
            require(gliner.get("error_kind") != "engineering" and nli_evidence.get("error_kind") != "engineering",
                    "evidence_engineering_error")
            shared.append({"text_index": index, "pool": pool, "gliner": gliner, "nli": nli_evidence})
            common.save(output / "shared_progress.json", shared)
            profiles = PROFILES if index % 2 == 0 else tuple(reversed(PROFILES))
            for profile in profiles:
                policy = plan["policies"][profile]
                for arm in ARMS:
                    cell = {"text_index": index, "profile": profile, "arm": arm}
                    if arm == ARMS[0]:
                        transport.cell = cell
                        before = budget.posts
                        response = local(text=text, source_id="probe", policy=copy.deepcopy(policy), rule_findings=[])
                        status = qwen_status(response, transport.events, cell, text)
                        require(response.get("local_calls") == budget.posts - before, "qwen_accounting_mismatch")
                    else:
                        evidence = gliner if arm == ARMS[1] else nli_evidence
                        response = relation.decide(text, policy, pool, evidence)
                        status = evidence_status(pool, evidence, response)
                    common.exact_findings(response, text)
                    row = {"cell": cell, "response": response, "status": status}
                    rows.append(row)
                    common.save(output / "rows.json", rows)
                    require(status != "engineering_error", "qwen_engineering_error")
                    row["preparation"] = scoring.prepare_observation(text, policy, response)
                    common.save(output / "rows.json", rows)
                    budget.check()
                    print(json.dumps({"completed": len(rows), **cell, "status": status,
                                      "qwen_posts": budget.posts, "nli_forwards": nli.snapshot_counts()["classifier_forward_calls"]}), flush=True)
        encoder_counts, nli_counts = encoder.snapshot_counts(), nli.snapshot_counts()
        require(encoder_counts["proposal_infer_invocations"] == 12
                and encoder_counts["classification_extract_invocations"] <= LIMITS["gliner_classifications"],
                "encoder_accounting_mismatch")
        require(nli_counts["classifier_forward_calls"] == nli_counts["encoder_forward_calls"] == len(nli_events)
                and nli_counts["blocked_forward_entries"] == 0 and len(nli_events) <= 96,
                "nli_accounting_mismatch")
        require(sum(row["response"]["local_calls"] for row in rows if row["cell"]["arm"] == ARMS[0]) == budget.posts
                == sum(event["method"] == "POST" for event in transport.events), "post_accounting_mismatch")
        require(sum(item["pool"]["inference_counts"]["proposal_infer_invocations"] for item in shared) == 12
                and sum(item["gliner"]["inference_counts"]["classification_extract_invocations"] for item in shared)
                == encoder_counts["classification_extract_invocations"]
                and sum(item["nli"]["inference_counts"]["nli_predict_invocations"] for item in shared) == len(nli_events),
                "shared_evidence_accounting_mismatch")
        counts = {"qwen_posts": budget.posts, "nli": nli_counts, "encoder": encoder_counts,
                  "ner_and_classification_events": len(encoder_events), "nli_capture_events": len(nli_events)}
        budget.check()
        require(common.checked_assets(plan["assets"]["root"]) == plan["assets"] and nli.health() == plan["nli_health"],
                "post_execution_assets_changed")
        report = close_predictions(output, plan_hash, rows, shared, captures, counts, budget=budget)
        report.update(network=network, wall_seconds=time.monotonic() - budget.started)
        common.save_exclusive(output / "report.json", report)
        execution.update(status="complete", reference_parsed=True)
        return report
    except Exception as exc:
        execution.update(status="stopped", error_type=type(exc).__name__,
                         error_code=str(exc) if str(exc).startswith("relation_probe_") else "relation_probe_execution_error")
        raise
    finally:
        execution.update(opportunities=len(rows), qwen_posts=budget.posts, nli=nli.snapshot_counts(),
                         wall_seconds=time.monotonic() - budget.started, network=network)
        common.save(output / "execution.json", execution)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--materials", type=Path, default=ROOT / "examples/relation_occurrence_probe_20261027")
    parser.add_argument("--prereg", type=Path, default=ROOT / "docs/关系证据与出现位置_小实验预注册_2026-10-27.md")
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args()
    if args.plan_only:
        result = freeze(args.output, args.materials, args.prereg)
    else:
        if not args.expected_plan_sha256:
            parser.error("--execute requires --expected-plan-sha256")
        result = execute(args.output, args.expected_plan_sha256)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
