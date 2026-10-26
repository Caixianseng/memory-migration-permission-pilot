"""Frozen bounded development diagnosis: real native migration x privacy.

No backend/model is started by import or --plan. --execute requires the exact
plan hash. Eight isolated native instances, <=200 HTTP requests each; exactly
48 registered answer opportunities, no retry, paid/cloud/building calls zero.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import importlib.metadata
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_native_api_read_handoff as base
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code
from memory_migration_study.authority_freshness import SQLiteStateWitness, SignedSnapshotStore
from memory_migration_study.current_authority import CurrentMemoryAuthority, CurrentReadDecision
from memory_migration_study.focused_semantic_reader import (CONDITIONS, POLICY, OPTIONS, SCHEMA, SYSTEM,
    canonical, digest, require, candidates, assert_pair, label_spans, make_capability, model_body, call_arm, ModelBudget)
from memory_migration_study.local_detector import LocalSensitivityAgent, MODEL, DIGEST, VERSION

VERSION_ID = "focused_semantic_native_2x2_development_20261027_v1"
MATERIAL = ROOT / "examples/focused_semantic_20261027/development.json"
REFERENCE = ROOT / "examples/focused_semantic_20261027/scoring_reference.json"
ACTORS = ("owner", "alice_reader", "alice_worker", "bob_reader", "bob_worker")
KEYS = ("readonly", "managed")


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def validate_material(material):
    require(set(material) == {"version", "stories"} and len(material["stories"]) == 4, "four_development_stories_required")
    require({s["language"] for s in material["stories"]} == {"en", "zh"}, "bilingual_material_required")
    for story in material["stories"]:
        require(set(story) == {"id", "language", "source_backend", "target_backend", "objects", "facts", "questions", "sensitive_values"}, "runtime_material_fields_invalid")
        require((story["source_backend"], story["target_backend"]) in {("webui", "cognee"), ("cognee", "webui")}, "direction_invalid")
        require(len(story["questions"]) == 3 and all(set(q) == {"id", "text"} for q in story["questions"]), "three_natural_questions_without_scoring_fields_required")
        bodies = {x["key"]: x["text"] for x in story["objects"]}
        require(len(story["objects"]) == 2 and len(set(story["sensitive_values"])) >= 4, "two_objects_and_complete_registry_required")
        candidates(story, bodies)
    require(all(sum(s["language"] == lang for s in material["stories"]) == 2 for lang in ("en", "zh")), "balanced_languages_required")
    require(sum(s["source_backend"] == "webui" for s in material["stories"]) == 2, "balanced_directions_required")


def call_order(story_index, question_index):
    # Twelve questions give each condition three appearances at each position.
    offset = (story_index * 3 + question_index) % 4
    return list(CONDITIONS[offset:] + CONDITIONS[:offset])


def build_plan():
    expected = {"jsonschema": "4.26.0", "fastapi": "0.136.3", "httpx": "0.28.1", "starlette": "1.9.0"}
    require({k: importlib.metadata.version(k) for k in expected} == expected and sys.version_info[:3] == (3, 12, 7), "qualified_host_required")
    material = base.parse(MATERIAL.read_bytes()); validate_material(material)
    qualified = base.build_plan()
    files = {Path(p) for p in qualified["code_sha256"]}
    files.update((ROOT / "memory_migration_study").glob("*.py"))
    files.add(Path(__file__))
    files.update(ROOT / "tests" / name for name in ("test_focused_semantic_reader.py", "test_focused_semantic_scoring.py"))
    instances = {}
    for story in material["stories"]:
        for arm in ("source", "target"):
            instances[story["id"] + "." + arm] = {"backend": story[arm + "_backend"],
                "state": str((Path(tempfile.gettempdir()) / ("focused_semantic_" + uuid.uuid4().hex)).resolve())}
    worksheet = {"per_source_instance_upper_bound": 180, "per_target_instance_upper_bound": 150,
        "init_max": 18, "object_write_max": 10, "initial_grants": 2, "owner_export": 2,
        "initial_effective_matrix": 8, "explicit_webui_acl_max": 2,
        "private_prepare_per_question_source_reads_max": 8,
        "all_arm_dispatch_per_question_source_reads_max": 8,
        "all_arm_restore_per_question_source_reads_max": 12,
        "engineering_controls_and_requalification_source_reads_max": 54,
        "explanation": "18+10+2+2+8+2+3*(8+8+12)+54=180; target <=150. Hard cap remains 200 each; guards preempt every HTTP request."}
    return {"version": VERSION_ID, "host_python": str(Path(sys.executable).resolve()), "host_dependencies": expected,
        "material_path": str(MATERIAL.resolve()), "material_sha256": base.file_sha(MATERIAL),
        "reference_path": str(REFERENCE.resolve()), "reference_sha256": base.file_sha(REFERENCE),
        "code_sha256": {str(p.resolve()): base.file_sha(p) for p in sorted(files)},
        "asset_sha256": qualified["asset_sha256"],
        "workers": {"webui": qualified["workers"]["source"], "cognee": qualified["workers"]["target"]},
        "pythons": {"webui": qualified["pythons"]["source"], "cognee": qualified["pythons"]["target"]},
        "wheel": qualified["wheel"], "legacy": qualified["legacy"], "instances": instances,
        "native_instances": 8, "native_http_cap_per_instance": 200, "max_total_native_http": 1600,
        "budget_worksheet": worksheet, "max_model_calls": 48, "paid_calls": 0, "cloud_calls": 0,
        "building_and_labeling_model_calls": 0, "native_generation_calls": 0, "native_embedding_calls": 0,
        "model": MODEL, "digest": DIGEST, "runtime": VERSION, "endpoint": "http://127.0.0.1:11435",
        "options": OPTIONS, "schema_sha256": digest(SCHEMA), "system_sha256": digest(SYSTEM.encode()),
        "retries": 0, "concurrency": 1, "max_elapsed_seconds": 3600,
        "ordered_questions": [{"story_id": s["id"], "question_id": q["id"], "conditions": call_order(i, j)}
            for i, s in enumerate(material["stories"]) for j, q in enumerate(s["questions"])],
        "scope": "four newly authored exposed development stories; ordinary composite native accounts; exact-ID raw retrieval; no unseen acceptance or algorithm novelty",
        "operator_consent": "explicit user authorized synthetic native copy and bounded local model calls; native export/share authority not asserted",
        "sharing_boundary": "only visible per-question aliases and candidate order; independent source/target API bytes, identities, grants, signed records, preparation and restoration capabilities",
        "freshness": "serial current actual source reads; target arms also current target reads; not atomic distributed revocation"}


def verify_inputs(plan, *, assets=False):
    require(base.file_sha(MATERIAL) == plan["material_sha256"] and base.file_sha(REFERENCE) == plan["reference_sha256"], "frozen_material_or_reference_changed")
    for path, expected in plan["code_sha256"].items():
        require(base.file_sha(path) == expected, "frozen_code_changed")
    if assets:
        for path, expected in plan["asset_sha256"].items():
            require(base.file_sha(path) == expected, "frozen_asset_changed")


class NativeRun:
    def __init__(self, plan, output):
        self.plan, self.output = plan, Path(output)
        self.workers, self.summaries, self.events, self.registries = {}, {}, [], {}
        self.started = time.monotonic()

    def call(self, name, phase, command, body):
        verify_inputs(self.plan)
        require(time.monotonic() - self.started < self.plan["max_elapsed_seconds"], "elapsed_budget_exhausted")
        try:
            result = self.workers[name].call(command, body)
            self.events.append({"instance": name, "phase": phase, "command": command, "input": deepcopy(body), "result": deepcopy(result)})
        except Exception as error:
            self.events.append({"instance": name, "phase": phase, "command": command, "error": type(error).__name__})
            raise
        if command in {"read_raw", "list_data", "grant", "revoke"}:
            base.checked_trace(result, body["actor"])
        return result

    def launch(self, name):
        verify_inputs(self.plan, assets=True)
        item = self.plan["instances"][name]; backend = item["backend"]
        require(not Path(item["state"]).exists() and Path(item["state"]).parent.resolve() == Path(tempfile.gettempdir()).resolve(), "fresh_isolated_state_required")
        args = ["--state", item["state"], "--http-cap", "200"]
        if backend == "cognee":
            args += ["--wheel", self.plan["wheel"], "--legacy-project", self.plan["legacy"], "--expected-worker-sha256", base.TARGET_SHA]
        # No injectable RPC factory: fake workers cannot earn native status.
        self.workers[name] = WorkerRPC(self.plan["pythons"][backend], self.plan["workers"][backend], args, timeout=240)
        result = self.call(name, "init", "init", {})
        identities = result["identities"]
        require(set(identities) == set(ACTORS) and len({p["id"] for p in identities.values()}) == 5, "five_native_identities_required")
        require(all(p.get("role") == "user" if backend == "webui" else p.get("is_superuser") is False for p in identities.values()), "native_ordinary_accounts_required")
        prior = {p["id"] for summary in self.summaries.values() for p in summary["identities"].values()}
        require(prior.isdisjoint(p["id"] for p in identities.values()), "native_identity_collision")
        self.summaries[name] = {"identities": identities}

    def setup(self, name, bodies):
        for key in KEYS:
            self.call(name, "write", "create_dataset", {"actor": "owner", "dataset": key})
            self.call(name, "write", "add_exact_fact", {"actor": "owner", "dataset": key, "fact_key": key, "text": bodies[key]})
        self.summaries[name] = self.call(name, "bindings", "summary", {})

    def mutate(self, name, operation, key):
        result = self.call(name, "engineering_control_" + operation, operation,
            {"actor": "owner", "recipient": "alice_reader", "dataset": key, "permission": "read"})
        require(result["status"] == 200, "native_acl_mutation_failed")

    def read(self, name, actor, key, phase):
        result = self.call(name, phase, "read_raw", {"actor": actor, "dataset": key, "fact_key": key})
        trace, raw = base.checked_trace(result, actor)
        if result["status"] == 200:
            require(0 < len(raw.encode()) <= 4096 and raw == raw.strip(), "actual_raw_body_invalid")
            return {"decision": "allow", "text": raw, "sha256": digest(raw.encode()), "index": trace["index"]}
        parsed = base.parse(raw)
        complete = raw + "\n" + canonical(parsed).decode("utf-8")
        require(not any(value in complete for value in self.registries.get(name, [])), "denial_contains_registered_sensitive_value")
        require(result["status"] in {403, 404} and isinstance(parsed, dict)
                and isinstance(parsed.get("detail", parsed.get("message")), str), "native_read_unknown")
        return {"decision": "deny", "text": None, "index": trace["index"]}

    def qualify(self, name, expected_bodies, story):
        actual, matrix, acl = {}, [], {}
        for key in KEYS:
            owner = self.read(name, "owner", key, "owner_actual_export")
            require(owner["decision"] == "allow" and owner["text"] == expected_bodies[key], "actual_owner_bytes_not_expected")
            actual[key] = owner["text"]
            if self.plan["instances"][name]["backend"] == "webui":
                result = self.call(name, "explicit_policy", "list_data", {"actor": "owner", "dataset": key})
                require(base.source_note(base.parse(result["trace"]["native_raw_body"]), summary=self.summaries[name], dataset=key) == {"alice_reader"}, "explicit_acl_not_exact")
                acl[key] = result["trace"]["native_body_sha256"]
            for actor in ACTORS[1:]:
                read = self.read(name, actor, key, "effective_matrix")
                require(read["decision"] == ("allow" if actor == "alice_reader" else "deny"), "effective_read_relation_mismatch")
                if actor == "alice_reader":
                    require(read["text"] == actual[key], "reader_bytes_changed")
                matrix.append({"actor": actor, "object_key": key, "decision": read["decision"], "index": read["index"]})
        return actual, {"instance": name, "backend": self.plan["instances"][name]["backend"],
            "actual_bodies": actual, "body_sha256": digest(actual), "identities": self.summaries[name]["identities"],
            "effective_relations": matrix, "explicit_webui_acl_hashes": acl,
            "complete_cognee_acl_exported": False, "native_export_share_authority_verified": False,
            "atomic_snapshot": False, "candidate_order": [f["id"] for f in candidates(story, actual)]}

    def close(self):
        for name, worker in self.workers.items():
            try:
                self.summaries[name] = self.call(name, "final", "summary", {})
                self.call(name, "close", "close", {})
            except Exception:
                pass
            finally:
                worker.terminate()
        return self.summaries


class ArmSession:
    def __init__(self, run, output, story, arm, bodies, witness, store):
        self.run, self.story, self.arm, self.bodies = run, story, arm, dict(bodies)
        self.name = story["id"] + "." + arm
        self.backend = run.plan["instances"][self.name]["backend"]
        self.principal = {"user_id": "synthetic.alice", "agent_id": "synthetic.reader"}
        self.unknown = False
        self.object_bindings = {key: {"backend": self.backend, "native_identity": run.summaries[self.name]["identities"]["alice_reader"]["id"],
            "container": run.summaries[self.name]["datasets"][key]["id"], "object": run.summaries[self.name]["facts"][key]["id"]} for key in KEYS}
        self.authority = CurrentMemoryAuthority.provision(secrets.token_bytes(32), namespace=self.name,
            witness=witness, snapshot_store=store, live_authorizer=self.live)
        self.records = [self.authority.build_record({"source_id": story["id"] + "." + key, "text": bodies[key]},
            {"text": bodies[key], "source_start": 0, "source_end": len(bodies[key]),
             "findings": label_spans(bodies[key], story["sensitive_values"])}, POLICY,
            owner_id="synthetic.operator", agent_id="synthetic.builder", builder_version="focused-fixed-complete-labels-v1",
            allowed_principals=[self.principal]) for key in KEYS]

    def live(self, request):
        decision = "unknown"
        if request.principal.to_dict() != self.principal or request.source_id not in {self.story["id"] + "." + k for k in KEYS} or self.unknown:
            return CurrentReadDecision.for_request(request, decision)
        key = request.source_id.rsplit(".", 1)[1]
        try:
            names = [self.story["id"] + ".source"] + ([self.name] if self.arm == "target" else [])
            decisions = []
            for name in names:
                observed = self.run.read(name, "alice_reader", key, "current_request_authorization")
                if observed["decision"] == "allow" and observed["text"] != self.bodies[key]:
                    return CurrentReadDecision.for_request(request, "unknown")
                decisions.append(observed["decision"])
            decision = "deny" if "deny" in decisions else "allow"
        except Exception:
            decision = "unknown"
        return CurrentReadDecision.for_request(request, decision)


def engineering_controls(run, story, sessions, source_candidates, target_candidates):
    question = story["questions"][0]
    source = make_capability(story, question, "S1", sessions["source"], source_candidates)
    target = make_capability(story, question, "T1", sessions["target"], target_candidates)
    rows = []
    def restore(cap):
        return cap.restore("F2", story_id=story["id"], question_id=question["id"], condition=cap.condition, request_id=cap.request_id)
    run.mutate(story["id"] + ".target", "revoke", "readonly")
    require(restore(target)["authorization"]["decision"] == "deny" and restore(source)["status"] == "ok", "target_only_revoke_control_failed")
    rows.append({"control": "target_only_revoke", "T": "deny", "S": "allow", "model_calls": 0})
    run.mutate(story["id"] + ".target", "grant", "readonly")
    run.mutate(story["id"] + ".source", "revoke", "readonly")
    require(restore(target)["authorization"]["decision"] == "deny" and restore(source)["authorization"]["decision"] == "deny", "source_revoke_control_failed")
    rows.append({"control": "source_revoke", "T": "deny", "S": "deny", "model_calls": 0})
    run.mutate(story["id"] + ".source", "grant", "readonly")
    sessions["source"].unknown = True
    require(source.check()["decision"] == "unknown", "unknown_control_failed")
    sessions["source"].unknown = False
    rows.append({"control": "authorizer_unavailable_fault_injection", "decision": "unknown", "native_qualification_claim": False, "model_calls": 0})
    for name, principal in (("cross_user", {"user_id": "synthetic.bob", "agent_id": "synthetic.reader"}),
                            ("cross_agent", {"user_id": "synthetic.alice", "agent_id": "synthetic.worker"})):
        result = sessions["source"].authority.access_decision(source.records[0], actor_id=principal["user_id"], agent_id=principal["agent_id"], policy_version=POLICY["version"])
        require(result["decision"] == "deny", "cross_principal_control_failed")
        rows.append({"control": name, "decision": "deny", "model_calls": 0})
    require(source.check()["decision"] == target.check()["decision"] == "allow", "post_control_requalification_failed")
    source.closed = target.closed = True
    return rows


def execute(plan, output):
    verify_inputs(plan, assets=True)
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    save(output / "frozen_plan.json", plan)
    archive_code([Path(p) for p in plan["code_sha256"]], plan["code_sha256"], output / "code")
    # Reference bytes are hashed/copied while opaque, never parsed until closure.
    (output / "material.json").write_bytes(MATERIAL.read_bytes())
    (output / "opaque_scoring_reference.json").write_bytes(REFERENCE.read_bytes())
    material = base.parse(MATERIAL.read_bytes())
    budget, predictions, qualifications, controls, errors, actual_order = ModelBudget(48), [], [], [], [], []
    run = NativeRun(plan, output)
    witness = SQLiteStateWitness(output / "witness.sqlite", create=True)
    store = SignedSnapshotStore(output / "snapshots")
    health = None
    try:
        health = LocalSensitivityAgent().health()
        for si, story in enumerate(material["stories"]):
            try:
                source_name, target_name = (story["id"] + "." + arm for arm in ("source", "target"))
                run.registries[source_name] = run.registries[target_name] = list(story["sensitive_values"])
                run.launch(source_name)
                run.setup(source_name, {x["key"]: x["text"] for x in story["objects"]})
                for key in KEYS: run.mutate(source_name, "grant", key)
                source_bodies, receipt = run.qualify(source_name, {x["key"]: x["text"] for x in story["objects"]}, story)
                qualifications.append(receipt)
                run.launch(target_name); run.setup(target_name, source_bodies)
                for key in KEYS: run.mutate(target_name, "grant", key)
                target_bodies, receipt = run.qualify(target_name, source_bodies, story)
                qualifications.append(receipt)
                sc, tc = candidates(story, source_bodies), candidates(story, target_bodies)
                assert_pair(sc, tc)
                print(json.dumps({"stage": "native_qualified", "story_id": story["id"], "instances": 2}), flush=True)
                sessions = {arm: ArmSession(run, output, story, arm, bodies, witness, store)
                            for arm, bodies in (("source", source_bodies), ("target", target_bodies))}
                controls.extend({"story_id": story["id"], **r} for r in engineering_controls(run, story, sessions, sc, tc))
                for qi, question in enumerate(story["questions"]):
                    caps = {condition: make_capability(story, question, condition,
                        sessions["source" if condition.startswith("S") else "target"], sc if condition.startswith("S") else tc)
                        for condition in CONDITIONS}
                    nonce = secrets.token_hex(12).upper()
                    bodies = {condition: model_body(cap, question, nonce if condition.endswith("1") else None) for condition, cap in caps.items()}
                    require(canonical(bodies["S0"]) == canonical(bodies["T0"]), "raw_pair_wire_mismatch")
                    require(canonical(bodies["S1"]) == canonical(bodies["T1"]), "private_pair_wire_mismatch")
                    for condition in call_order(si, qi):
                        index = len(actual_order); actual_order.append({"index": index, "story_id": story["id"], "question_id": question["id"], "condition": condition})
                        row = call_arm(caps[condition], bodies[condition], story, question, budget)
                        row["call_order_index"] = index
                        predictions.append(row)
                        save(output / f"prediction_{index:02d}.json", row)
                    # Neither source nor target private capability survives this question.
                    for cap in caps.values(): cap.closed = True
                print(json.dumps({"stage": "story_model_phase_complete", "story_id": story["id"], "cumulative_model_calls": budget.attempted}), flush=True)
            except Exception as error:
                errors.append({"story_id": story["id"], "failure_class": "native_or_processing_unverified", "error": str(error) if isinstance(error, ValueError) else type(error).__name__})
                print(json.dumps({"stage": "story_failed", "story_id": story["id"], "error": errors[-1]["error"]}), flush=True)
            finally:
                # Stop already-used workers, keeping each story physically isolated.
                for name in list(run.workers):
                    if name.startswith(story["id"] + "."):
                        try:
                            run.summaries[name] = run.call(name, "story_final", "summary", {})
                            run.call(name, "close", "close", {})
                        finally:
                            run.workers.pop(name).terminate()
    except Exception as error:
        errors.append({"failure_class": "experiment_infrastructure", "error": str(error) if isinstance(error, ValueError) else type(error).__name__})
    finally:
        run.close()
    # Preserve all 48 opportunities even after an infrastructure/qualification stop.
    existing = {(r["story_id"], r["question_id"], r["condition"]) for r in predictions}
    for story in material["stories"]:
        for question in story["questions"]:
            for condition in CONDITIONS:
                if (story["id"], question["id"], condition) not in existing:
                    predictions.append({"story_id": story["id"], "question_id": question["id"], "condition": condition,
                        "status": "not_run", "answer_id": None, "failure_class": "native_qualification_or_infrastructure_unverified", "model_calls": 0, "request_sha256": None})
    raw_predictions = canonical(predictions)
    (output / "predictions.json").write_bytes(raw_predictions)
    save(output / "prediction_phase_closed.json", {"closed": True, "predictions_sha256": digest(raw_predictions),
        "model_calls": budget.attempted, "model_cap": 48, "closed_before_reference_parse": True})
    verify_inputs(plan)
    # First parse of scoring-reference contents within the experiment.
    from memory_migration_study.focused_semantic_scoring import score
    reference = base.parse((output / "opaque_scoring_reference.json").read_bytes())
    metrics = score(predictions, reference)
    native_counts = {name: len(summary.get("native_requests", [])) for name, summary in run.summaries.items()}
    native_guards = {name: {k: summary.get(k) for k in ("generation_attempts", "embedding_attempts", "network_events", "client_credential_values_persisted", "native_auth_storage_unmodified")} for name, summary in run.summaries.items()}
    require(all(n <= 200 for n in native_counts.values()) and sum(native_counts.values()) <= 1600, "native_budget_contract_violated")
    require(all(s.get("generation_attempts") == s.get("embedding_attempts") == 0 for s in run.summaries.values()), "native_inference_contract_violated")
    save(output / "qualifications.json", qualifications); save(output / "engineering_controls.json", controls)
    save(output / "native_events.json", run.events); save(output / "native_summaries.json", run.summaries)
    save(output / "actual_call_order.json", actual_order); save(output / "metrics.json", metrics)
    report = {"version": VERSION_ID, "plan_sha256": digest(plan), "predictions_sha256": digest(raw_predictions),
        "health": health, "model_calls": budget.attempted, "max_model_calls": 48,
        "native_http_counts": native_counts, "native_http_total": sum(native_counts.values()), "native_http_cap": 1600,
        "native_guards": native_guards, "paid_calls": 0, "cloud_calls": 0, "building_and_labeling_model_calls": 0,
        "qualification_instances": len(qualifications), "errors": errors, "metrics": metrics,
        "fixed_complete_labels_are_detection_evidence": False, "independent_unseen_acceptance": False,
        "new_algorithm_advantage": False, "shared_view_scope": plan["sharing_boundary"],
        "elapsed_seconds": round(time.monotonic() - run.started, 3),
        "registered_sensitive_privacy_requests_scanned": sum(r.get("request_boundary", {}).get("full_request_observed") is True and r["condition"].endswith("1") for r in predictions),
        "evidence": {p.name: base.file_sha(p) for p in output.iterdir() if p.is_file()}}
    report["execution_complete"] = (not errors and len(qualifications) == 8 and budget.attempted == 48
        and len(predictions) == 48 and all(r["status"] == "ok" for r in predictions)
        and len(native_counts) == 8 and all(s.get("native_auth_storage_unmodified") is True
        and s.get("client_credential_values_persisted") is False for s in run.summaries.values()))
    report["semantic_success_is_separate_from_execution_complete"] = True
    save(output / "summary.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path); parser.add_argument("--execute", type=Path)
    parser.add_argument("--approved-sha256"); parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.plan:
        plan = build_plan(); save(args.plan, plan)
        print(json.dumps({"plan": str(args.plan.resolve()), "sha256": digest(plan), "model_cap": 48, "native_cap": 1600}))
    else:
        require(args.execute is not None and args.output is not None, "plan_or_execute_required")
        plan = base.parse(args.execute.read_bytes())
        require(args.approved_sha256 == digest(plan), "approved_plan_hash_required")
        report = execute(plan, args.output)
        print(json.dumps({"output": str(args.output.resolve()), "model_calls": report["model_calls"], "native_http": report["native_http_total"], "errors": report["errors"]}, ensure_ascii=False))
        if not report["execution_complete"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
