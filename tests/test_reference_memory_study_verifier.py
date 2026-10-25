"""Self-authored offline evidence fixtures; no corpus, weights or API access."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.reference_memory import propose_fact_pool, PURPOSE, SYSTEM_PROMPT
from memory_migration_study.budget import MEMORY_PROMPTS
from memory_migration_study.memory_builder import SYSTEM_PROMPT as JOINT_SYSTEM_PROMPT
from scripts import verify_reference_memory_study as verifier


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


class ReferenceEvidenceFixture:
    """Fake generations are explicitly synthetic ledger entries, never measurements."""
    def __init__(self, root):
        self.run, self.corpus = root/"run", root/"corpus"
        self.run.mkdir()
        (self.corpus/"development").mkdir(parents=True)
        self.runtime, self.evaluation, self.pools, self.builds, self.stores, self.rows, self.events = [], {}, [], [], [], [], []
        for n in range(8):
            sid, org = f"self_story_{n}", f"Invented Organization {n}"
            source = {"source_id": f"self_source_{n}", "text": f"Customer: {org}\nStatus: shipped"}
            tasks = [{"task_id": f"task_{i}", "actor_id": "owner" if i < 4 else "outsider", "query": "Who is the client?"} for i in range(5)]
            story = {"story_id": sid, "language": "en" if n % 2 else "zh", "template_family": f"self_template_{n % 4}",
                "source": source, "tasks": tasks, "policy": {"version": "self_v1", "protected_categories": ["CUSTOMER"]}}
            self.runtime.append(story)
            start = source["text"].index(org)
            self.evaluation[sid] = {"answers": {t["task_id"]: org for t in tasks if t["actor_id"] == "owner"},
                "sensitive_spans": [{"start": start, "end": start+len(org), "category": "CUSTOMER"}]}
            pool = propose_fact_pool(source["text"], source["source_id"])
            self.pools.append({"story_id": sid, "pool": pool})
            authority = MemoryLabelAuthority(b"self-authored-test-key-32-bytes!!"*2)
            for arm in verifier.ARMS:
                selected = pool["candidates"] if arm == "retain_all" else pool["candidates"][:1]
                if arm == "coverage":
                    selected = [{"fid": "not_reference", "start": 0, "end": len(source["text"])}]
                facts = []
                for c in selected:
                    a, b = c["start"], c["end"]
                    findings = ([{"start": start-a, "end": start+len(org)-a, "category": "CUSTOMER"}]
                        if a <= start < start+len(org) <= b else [])
                    facts.append({"text": source["text"][a:b], "source_start": a, "source_end": b, "findings": findings, "status": "ok"})
                calls = int(arm in {"old_joint_quote", "reference_id", "reference_quote"})
                encoder = 0 if arm == "old_joint_quote" else len(facts)
                built = {"status": "ok", "facts": facts, "builder_version": "self_fixture_v1", "local_calls": calls}
                if arm in verifier.REFERENCE:
                    built.update(pool=deepcopy(pool), selected_fids=[c["fid"] for c in selected],
                        detector_local_counts={"local_encoder": encoder, "local_generation": 0, "unknown": 0},
                        selector_local_counts={"local_encoder": 0, "local_generation": calls, "unknown": 0})
                records = [authority.build_record(source, fact, story["policy"], owner_id="owner", readers=["owner"],
                    agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"]) for fact in facts]
                if calls:
                    self.build_event(story, arm, pool, selected)
                if arm in {"reference_id", "reference_quote"}:
                    event = self.events[-2]
                    built["selection_attempts"] = [{"attempt": 1, "request_sha256": event["request_sha256"],
                        "input_budget_upper_bound": len(json.dumps(event["request"], ensure_ascii=False, separators=(",", ":")).encode())+320+1024,
                        "prompt_eval_count": 100, "eval_count": 10}]
                item = dict(built, raw_build_status="ok", story_id=sid, language=story["language"], builder=arm,
                    generation_calls_observed=calls, inference_counts={"local_encoder": encoder, "local_generation": 0, "unknown": 0},
                    stored_characters=sum(len(r["text"]) for r in records),
                    stored_record_json_bytes=len(json.dumps(records, ensure_ascii=False).encode()),
                    stored_source_copy_characters=sum(len(r["source"]["text"]) for r in records), source_characters=len(source["text"]),
                    candidate_pool_json_bytes=len(json.dumps(pool, ensure_ascii=False).encode()) if arm in verifier.REFERENCE else 0,
                    construction_result_json_bytes=len(json.dumps(built, ensure_ascii=False).encode()))
                self.builds.append(item)
                self.stores.append({"story_id": sid, "builder": arm, "records": records})
                token = "[PVT_"+f"{n:024X}"+"_CUSTOMER_1]"
                for task in tasks:
                    legal = task["actor_id"] == "owner"
                    row = {"story_id": sid, "task_id": task["task_id"], "language": story["language"], "template_family": story["template_family"],
                        "actor_id": task["actor_id"], "arm": arm, "mode": "migration", "privacy_pipeline": "legacy", "intent_applied": False,
                        "build_status": "ok", "prepare_status": "ok" if legal else "blocked", "answer_calls": int(legal),
                        "module_authorization_error": None if legal else "principal_not_authorized", "detector_calls": len(records)+1 if legal else 0,
                        "inference_counts": {"local_encoder": len(records)+1 if legal else 0, "local_generation": 0, "unknown": 0},
                        "model_answer": token[1:-1] if legal else None, "final_answer": None,
                        "restoration_status": "blocked" if legal else None, "secondary_serialization_registered": True,
                        "required_fact_retained": bool(legal)}
                    if legal:
                        outbound = {"query": task["query"], "memories": [{"source_id": r["record_id"], "text": r["text"].replace(org, token)} for r in records]}
                        row.update(answer_status="ok", outbound=outbound, actual_payload_sha256=verifier.digest(outbound),
                            secondary_serialization={"decision": "added_outer_brackets", "canonical_answer": token,
                                "final_answer": org, "restoration_status": "ok", "restoration_error": None})
                        self.event("answer", arm, sid, task["task_id"], {"model": verifier.MODEL,
                            "messages": [{"role": "system", "content": MEMORY_PROMPTS["memory_fact_query_v2"]},
                                {"role": "user", "content": json.dumps(outbound, ensure_ascii=False, separators=(",", ":"))}],
                            "stream": False, "keep_alive": "30m", "options": {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42}}, token[1:-1])
                        row["masking"] = verifier.independent_masking(story, task, self.evaluation[sid], records, outbound, False)
                    else:
                        row["masking"] = verifier.blocked_masking(story, self.evaluation[sid], records)
                    row["score"] = verifier.independent_score(row, self.evaluation[sid])
                    self.rows.append(row)
        self.write_base()

    def event(self, stage, arm, sid, tid, body, content):
        n = 1+sum(e["phase"] == "request" for e in self.events)
        context = {"index": n, "stage": stage, "arm": arm, "story_id": sid, "task_id": tid, "request_sha256": verifier.digest(body)}
        wire = json.dumps(body, ensure_ascii=False).encode()
        self.events.append(dict(context, phase="request", request=body, scope="synthetic_development_local_only",
            wire_json_utf8_bytes=len(wire), wire_json_utf8_sha256=verifier.sha(wire), wire_encoding="self fixture JSON body only"))
        response = {"model": verifier.MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": content},
            "prompt_eval_count": 100, "eval_count": 10}
        self.events.append(dict(context, phase="response", response=response, response_sha256=verifier.digest(response),
            actual_usage_within_budget=True, elapsed_seconds=0.01))

    def build_event(self, story, arm, pool, selected):
        source = story["source"]["text"]
        if arm == "old_joint_quote":
            trusted = {k: verifier.normalized_policy(story["policy"])[k] for k in ("version", "protected_categories", "instructions")}
            system = JOINT_SYSTEM_PROMPT+"\nTrusted sensitivity policy JSON:\n"+json.dumps(trusted, ensure_ascii=False, separators=(",", ":"))
            body = {"messages": [{"role": "system", "content": system},
                {"role": "user", "content": json.dumps({"text": source})}], "format": {}}
            content = json.dumps({"status": "ok", "facts": []})
        else:
            field = "selected_fids" if arm == "reference_id" else "selected_quotes"
            candidates = [{"fid": c["fid"], "text": source[c["start"]:c["end"]]} for c in pool["candidates"]]
            enum = [c["fid"] if arm == "reference_id" else c["text"] for c in candidates]
            body = {"messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps({"purpose": PURPOSE, "candidates": candidates}, ensure_ascii=False, separators=(",", ":"))}],
                "format": {"type": "object", "additionalProperties": False, "required": ["status", field], "properties": {
                    "status": {"type": "string", "enum": ["ok", "needs_review"]},
                    field: {"type": "array", "maxItems": 8, "uniqueItems": True, "items": {"type": "string", "enum": enum}}}}}
            content = json.dumps({"status": "ok", field: [c["fid"] if arm == "reference_id" else source[c["start"]:c["end"]] for c in selected]})
        body.update(model=verifier.MODEL, stream=False, keep_alive="30m", options={"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42})
        self.event("build", arm, story["story_id"], None, body, content)

    def write_base(self):
        config = {"endpoint": "http://127.0.0.1:11435", "model": verifier.MODEL, "expected_version": "0.40.8", "expected_digest": verifier.MODEL_DIGEST, "timeout_seconds": 120}
        save(self.corpus/"development/runtime.json", self.runtime)
        save(self.corpus/"development/evaluation.json", self.evaluation)
        paths = list((verifier.ROOT/"memory_migration_study").glob("*.py"))+[verifier.ROOT/"scripts/run_reference_memory_study.py", verifier.ROOT/"scripts/run_boundary_transfer_diagnostic.py"]
        hashes = {}
        for path in paths:
            rel = path.relative_to(verifier.ROOT)
            destination = self.run/"implementation"/rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            hashes[str(rel)] = verifier.sha(path.read_bytes())
        plan = {"version": verifier.VERSION, "score_schema_version": 2, "split": "development", "arms": {a: [a, "migration", False] for a in verifier.ARMS},
            "expected_rows": 200, "legal_per_arm": 32, "outsider_per_arm": 8, "privacy_pipeline": "legacy", "transfer_mode": "migration", "query_intent": False,
            "ordering_seed": 2026102507, "evaluation_timing": "after_all_model_processing", "generation_limits": {"total": 208, "answers": 160, "builders": 48, "per_model_builder_per_story": 2},
            "runtime_sha256": verifier.sha((self.corpus/"development/runtime.json").read_bytes()),
            "evaluation_sha256": verifier.sha((self.corpus/"development/evaluation.json").read_bytes()), "config_sha256": verifier.digest(config),
            "implementation_sha256": hashes, "scope": "Self-authored fake transport fixture; no actual model executions."}
        identity = {"local_generation": {"endpoint": config["endpoint"], "model": verifier.MODEL, "version": "0.40.8", "digest": verifier.MODEL_DIGEST},
            "ner_initialization_seconds": 0.01, "ner": {"code_revision": "ca4f68235b50fe4c3ecf3876851d748fe4b15c6c", "model_revision": "cf5593a5d45e3bbf204b9df621b13b1c0cf25ee3",
                "model_id": "fastino/gliner2.5-multi-v1", "weights_sha256": "a"*64, "files_sha256": "b"*64, "device": "cpu"}, "detector": {}}
        for name, value in (("plan", plan), ("runtime", self.runtime), ("evaluation", self.evaluation), ("config", config), ("runtime_identity", identity), ("pools", self.pools), ("builds", self.builds), ("record_store", self.stores), ("rows", self.rows)):
            save(self.run/(name+".json"), value)
        self.summaries(plan)

    def summaries(self, plan=None):
        plan = plan or json.loads((self.run/"plan.json").read_bytes())
        requests = [e for e in self.events if e["phase"] == "request"]
        responses = [e for e in self.events if e["phase"] == "response"]
        network = {"loopback_connections": len(requests)+2, "external_attempts_blocked": 0}
        audit = {"completed": True, "registered_protocol": verifier.VERSION, "recovery_mapping_recorded": False,
            "physical_generation_attempts": len(requests), "responses": len(responses), "transport_errors": len(requests)-len(responses),
            "actual_token_budget_violations": 0, "registered_generation_cap": 208, "cloud_calls": 0, "new_api_cost_cny": 0, "network": network}
        report = {"version": verifier.VERSION, "registered_rows": 200, "recorded_rows": 200, "source_stories": 8, "template_families": 4,
            "arms": verifier.independent_aggregate(self.rows, self.builds), "generation_calls_observed": len(requests),
            "builder_generations": sum(b["generation_calls_observed"] for b in self.builds), "answer_generations": sum(r["answer_calls"] for r in self.rows),
            "build_encoder_calls": sum(b["inference_counts"]["local_encoder"] for b in self.builds), "migration_encoder_calls": sum(r["inference_counts"]["local_encoder"] for r in self.rows),
            "request_wire_json_bytes": sum(e["wire_json_utf8_bytes"] for e in requests),
            "prompt_eval_count_sum": sum(e["response"]["prompt_eval_count"] for e in responses), "eval_count_sum": sum(e["response"]["eval_count"] for e in responses),
            "construction_bytes_by_arm": {a: {k: sum(b[k] for b in self.builds if b["builder"] == a) for k in ("candidate_pool_json_bytes", "construction_result_json_bytes")} for a in verifier.ARMS},
            "detector_call_accounting_complete": True, "implementation_unchanged": True, "cloud_calls": 0, "new_api_cost_cny": 0, "scope": plan["scope"]}
        for name, value in (("transport_audit", audit), ("network_audit", network), ("report", report)):
            save(self.run/(name+".json"), value)
        (self.run/"request_transport.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False)+"\n" for e in self.events), encoding="utf-8")


class ReferenceMemoryVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ReferenceEvidenceFixture(Path(self.temp.name))

    def check(self):
        return verifier.verify(self.fixture.run, corpus=self.fixture.corpus)

    def mutate(self, filename, edit):
        path = self.fixture.run/filename
        value = json.loads(path.read_bytes())
        edit(value)
        save(path, value)

    def test_full_matrix_and_primary_secondary_are_separate(self):
        result = self.check()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["registered_rows"], 200)
        self.assertEqual(result["literal_masking_requests_checked"], 160)
        self.assertEqual(result["physical_generation_attempts"], 184)
        self.assertEqual(result["verification_model_calls"], 0)
        self.assertEqual(result["physical_costs_by_arm"]["reference_id"]["build"]["physical_generation_attempts"], 8)
        self.assertEqual(sum(c[stage]["physical_generation_attempts"] for c in result["physical_costs_by_arm"].values() for stage in ("build", "answer")), 184)
        self.assertTrue(all(cell["correct"] == 0 and cell["secondary_serialization_correct"] == 32 and cell["outsider_blocked"] == 8 for cell in result["arms"].values()))

    def test_missing_task_is_not_dropped_from_denominator(self):
        self.mutate("rows.json", lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "task_matrix_denominator"):
            self.check()

    def test_recomputed_score_rejects_report_or_row_tampering(self):
        self.mutate("rows.json", lambda rows: rows[0]["score"].update(correct=True))
        with self.assertRaisesRegex(ValueError, "independent_score_mismatch"):
            self.check()

    def test_masking_uses_actual_payload_and_rejects_false_perfect_score(self):
        def change(rows):
            rows[0]["outbound"]["memories"][0]["text"] = self.fixture.stores[0]["records"][0]["text"]
        self.mutate("rows.json", change)
        with self.assertRaisesRegex(ValueError, "independent_masking_mismatch"):
            self.check()

    def test_outsider_requires_actual_authority_denial(self):
        self.mutate("rows.json", lambda rows: rows[4].update(module_authorization_error="guessed_denial"))
        with self.assertRaisesRegex(ValueError, "outsider_not_actual_authority_denial"):
            self.check()

    def test_pool_public_hash_does_not_allow_wrong_span(self):
        def change(pools):
            pool = pools[0]["pool"]
            pool["candidates"][0]["end"] -= 1
            pool["pool_sha256"] = verifier.digest({k: v for k, v in pool.items() if k != "pool_sha256"})
        self.mutate("pools.json", change)
        with self.assertRaisesRegex(ValueError, "pool_candidate_text"):
            self.check()

    def test_same_pool_reference_baseline_is_enforced(self):
        self.mutate("builds.json", lambda builds: builds[1]["pool"].update(version="different_pool"))
        with self.assertRaisesRegex(ValueError, "build_volume|reference_pool_changed"):
            self.check()

    def test_failed_build_cannot_deploy_old_candidate_records(self):
        self.mutate("builds.json", lambda builds: builds[0].update(status="needs_review"))
        with self.assertRaisesRegex(ValueError, "failed_build_deployed_records"):
            self.check()

    def test_secondary_must_only_add_current_outer_brackets(self):
        self.mutate("rows.json", lambda rows: rows[0]["secondary_serialization"].update(canonical_answer="invented answer"))
        with self.assertRaisesRegex(ValueError, "secondary_changed_unregistered_answer"):
            self.check()

    def test_wire_bytes_checked_against_recorded_body(self):
        self.fixture.events[0]["wire_json_utf8_bytes"] += 1
        self.fixture.summaries()
        with self.assertRaisesRegex(ValueError, "wire_json_bytes"):
            self.check()

    def test_missing_failed_or_response_terminal_is_not_ignored(self):
        self.fixture.events.pop(1)
        self.fixture.summaries()
        with self.assertRaisesRegex(ValueError, "physical_request_denominator"):
            self.check()

    def test_raw_answer_bound_to_response(self):
        self.mutate("rows.json", lambda rows: rows[0].update(model_answer="UNKNOWN"))
        with self.assertRaisesRegex(ValueError, "secondary_changed_unregistered_answer|unknown_promoted_to_answer|raw_model_answer_changed"):
            self.check()

    def test_secondary_success_cannot_replace_primary_result(self):
        def change(rows):
            rows[0]["final_answer"] = rows[0]["secondary_serialization"]["final_answer"]
            rows[0]["restoration_status"] = "ok"
        self.mutate("rows.json", change)
        with self.assertRaisesRegex(ValueError, "primary_promoted_from_secondary"):
            self.check()

    def test_exact_fact_access_grant_scope_cannot_change(self):
        self.mutate("record_store.json", lambda stores: stores[0]["records"][0]["access"].update(source_start=1))
        with self.assertRaisesRegex(ValueError, "grant_content_or_principal_binding"):
            self.check()

    def test_serialized_map_or_key_is_rejected(self):
        self.mutate("rows.json", lambda rows: rows[0].update(restoration_map={}))
        with self.assertRaisesRegex(ValueError, "serialized_secret_or_map_field"):
            self.check()

    def test_invalid_json_boolean_count_is_not_integer_one(self):
        self.mutate("rows.json", lambda rows: rows[0]["inference_counts"].update(local_encoder=True))
        with self.assertRaisesRegex(ValueError, "row_inference_count"):
            self.check()

    def test_selected_ids_must_come_from_recorded_model_output(self):
        request = next(e for e in self.fixture.events if e["phase"] == "request" and e["arm"] == "reference_id" and e["stage"] == "build")
        response = next(e for e in self.fixture.events if e["phase"] == "response" and e["index"] == request["index"])
        response["response"]["message"]["content"] = json.dumps({"status": "ok", "selected_fids": ["F0002"]})
        response["response_sha256"] = verifier.digest(response["response"])
        self.fixture.summaries()
        with self.assertRaisesRegex(ValueError, "raw_selector_fids_changed"):
            self.check()

    def test_successful_verification_keeps_failed_build_all_five_tasks(self):
        # A failed deterministic coverage build has no POST or deployable facts;
        # all four legal failures and its outsider task must remain registered.
        sid, arm = self.fixture.runtime[0]["story_id"], "coverage"
        built = next(b for b in self.fixture.builds if b["story_id"] == sid and b["builder"] == arm)
        built.update(status="needs_review", raw_build_status="needs_review", facts=[], stored_characters=0,
            stored_record_json_bytes=2, stored_source_copy_characters=0)
        raw = {k: v for k, v in built.items() if k not in verifier.HARNESS_BUILD_FIELDS}
        built["construction_result_json_bytes"] = len(json.dumps(raw, ensure_ascii=False).encode())
        next(s for s in self.fixture.stores if s["story_id"] == sid and s["builder"] == arm)["records"] = []
        for row in self.fixture.rows:
            if row["story_id"] == sid and row["arm"] == arm:
                row.update(build_status="needs_review", prepare_status="blocked", answer_calls=0, detector_calls=0,
                    module_authorization_error=None, model_answer=None, final_answer=None, restoration_status=None,
                    inference_counts={"local_encoder": 0, "local_generation": 0, "unknown": 0}, required_fact_retained=False)
                for key in ("outbound", "actual_payload_sha256", "answer_status", "secondary_serialization"):
                    row.pop(key, None)
                row["masking"] = verifier.blocked_masking(self.fixture.runtime[0], self.fixture.evaluation[sid], [])
                row["score"] = verifier.independent_score(row, self.fixture.evaluation[sid])
        self.fixture.events = [e for e in self.fixture.events if not (e["story_id"] == sid and e["arm"] == arm)]
        next_index, indices = 0, {}
        for event in self.fixture.events:
            if event["phase"] == "request":
                next_index += 1
                indices[event["index"]] = next_index
            event["index"] = indices[event["index"]]
        for name, value in (("builds", self.fixture.builds), ("record_store", self.fixture.stores), ("rows", self.fixture.rows)):
            save(self.fixture.run/(name+".json"), value)
        self.fixture.summaries()
        result = self.check()
        self.assertEqual(result["registered_rows"], 200)
        self.assertEqual(result["arms"]["coverage"]["build_stories"], 8)
        self.assertEqual(result["arms"]["coverage"]["build_successes"], 7)
        self.assertEqual(result["arms"]["coverage"]["build_block"], 4)
        self.assertEqual(result["arms"]["coverage"]["legal_tasks"], 32)


if __name__ == "__main__":
    unittest.main()
