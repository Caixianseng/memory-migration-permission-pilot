"""Real semantic-study harness on eight authored stories and protocol fakes.

The injected POST ledger measures fake callback invocations, never actual
network/model execution. Production builders, signature checks, JSON handoff,
semantic refiner, privacy preparation, restoration and scoring are exercised.
"""
from contextlib import nullcontext
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from tests.test_reference_memory_study import (FakeServer, authored, load_module, ROOT)
from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_labels import MemoryLabelAuthority


harness = load_module("policy_semantic_study_under_test", ROOT/"scripts/run_policy_semantic_study.py")


class SemanticFakeServer(FakeServer):
    def __init__(self, *, union_failure=False, build_failure=False, hostile_answers=False, bare_tokens=False):
        super().__init__(bare_tokens=bare_tokens)
        self.union_failure, self.build_failure, self.hostile_answers = union_failure, build_failure, hostile_answers

    def transport(self, client, method, path, body=None):
        if method != "POST":
            return super().transport(client, method, path, body)
        if self.gold_parsed:
            raise AssertionError("generation after evaluation parse")
        properties = body.get("format", {}).get("properties", {})
        data = json.loads(body["messages"][1]["content"])
        if "verdicts" in properties:
            result = {"verdicts": [{"cid": c["cid"], "role": "value", "quote": c["quote"]}
                                    for c in data["candidates"]]}
        elif "findings" in properties:
            # Independent local detector consumes only its actual source text.
            result = {"status": "needs_review" if self.union_failure else "ok", "findings": []}
            if not self.union_failure:
                result["findings"] = [{"quote": data["text"][s["start"]:s["end"]], "category": s["category"]}
                                      for s in authored.candidate_spans(data["text"])]
        elif self.build_failure and "selected_fids" in properties:
            result = {"status": "needs_review", "selected_fids": []}
        elif self.hostile_answers and "memories" in data:
            # Adversarial fixture outputs, independent of scoring material.
            # A refusal containing a raw secret is not a successful refusal.
            content = ("I cannot share Cedar Foundry" if "email" in data["query"].casefold()
                       else "Unsupported invented fact")
            result = None
        elif "memories" in data:
            # Accept both the original one-line fixture and actual two-record
            # JSON transfers. The answer is derived only from outbound text.
            text = "\n".join(m["text"] for m in data["memories"])
            query = data["query"].casefold()
            expression = (r"Contact: (.+?)\.$" if "email" in query else
                          r"Status: (.+?);\s+Contact:" if "status" in query else
                          r"Customer: (.+?);\s+Status:")
            match = re.search(expression, text)
            content = match.group(1) if match else "UNKNOWN"
            if self.bare_tokens and re.fullmatch(r"\[PVT_[^\[\]]+\]", content):
                content = content[1:-1]
            result = None
        else:
            return super().transport(client, method, path, body)
        self.posts.append(copy.deepcopy(body))
        return {"model": MODEL, "done": True, "done_reason": "stop",
            "message": {"role": "assistant", "content": content if result is None else json.dumps(result)},
            "prompt_eval_count": 100, "eval_count": 20}


class PolicySemanticStudyTests(unittest.TestCase):
    def run_authored(self, *, root=None, union_failure=False, build_failure=False,
                     hostile_answers=False, bare_tokens=False):
        base_runtime, base_gold = authored.fixture()
        runtime, evaluation = [], {}
        for index in range(8):
            story = copy.deepcopy(base_runtime[0])
            story["story_id"] = sid = f"authored-policy-semantic-{index}"
            story["source"]["source_id"] = f"authored-policy-source-{index}"
            runtime.append(story)
            evaluation[sid] = copy.deepcopy(base_gold["authored-fixture"])
            if index == 0:
                # At least one real handoff has two independently signed facts;
                # a regression validating only the first record must be caught.
                story["source"]["text"] = story["source"]["text"].replace("; Status:", ";\nStatus:")
                evaluation[sid]["sensitive_spans"] = [{k: span[k] for k in ("start", "end")}
                    for span in authored.candidate_spans(story["source"]["text"])]
        server = SemanticFakeServer(union_failure=union_failure, build_failure=build_failure,
            hostile_answers=hostile_answers, bare_tokens=bare_tokens)
        ner, progress, signed, gold_reads = authored.FakeNerRuntime(), [], {}, []
        real_build, real_loads = MemoryLabelAuthority.build_record, json.loads

        def record_build(authority, *args, **kwargs):
            record = real_build(authority, *args, **kwargs)
            signed[record["record_id"]] = (authority, record)
            return record

        def guarded_loads(value, *args, **kwargs):
            marker = authored.CANARY.encode() if isinstance(value, bytes) else authored.CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertTrue(observer.model_phase_closed)
                self.assertEqual(len(progress), 200)
                self.assertTrue(all(row["scored"] is False for row in progress))
                server.gold_parsed = True
                gold_reads.append(len(server.posts))
            return real_loads(value, *args, **kwargs)

        context = tempfile.TemporaryDirectory() if root is None else nullcontext(root)
        with context as directory:
            directory = Path(directory)
            split = directory/"corpus/development"
            split.mkdir(parents=True)
            for name, data in (("runtime", runtime), ("evaluation", evaluation)):
                (split/(name+".json")).write_text(json.dumps(data), encoding="utf-8")
            originals = {p.name: p.read_bytes() for p in split.iterdir()}
            output = directory/"output"
            observer = harness.SemanticTransport(output, server.transport)
            with patch.object(harness, "LocalNerRuntime", return_value=ner), \
                 patch.object(MemoryLabelAuthority, "build_record", new=record_build), \
                 patch.object(json, "loads", new=guarded_loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), \
                 observer.installed():
                report = harness.run(directory/"corpus", output, "no-model-assets", {}, observer, progress=progress.append)
            data = {name: real_loads((output/(name+".json")).read_bytes()) for name in
                    ("rows", "builds", "record_store", "pools", "plan", "auth_events")}
            events = [real_loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(originals, {p.name: p.read_bytes() for p in split.iterdir()})
            self.assertEqual((len(data["rows"]), len(data["builds"]), len(data["record_store"])), (200, 8, 8))
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            self.assertEqual(observer.attempts, len(server.posts))
            self.assertEqual(report["total_encoder_calls"], len(ner.calls))
            self.assertEqual(gold_reads, [len(server.posts)])
            self.assertTrue(observer.model_phase_closed)
            self.assertEqual(observer.closed_phase_attempts, 0)
            self.assertTrue(report["implementation_unchanged"])
            self.assertTrue(report["detector_call_accounting_complete"])
            self.assertEqual([e["sequence"] for e in data["auth_events"]], list(range(1, len(data["auth_events"])+1)))
            closed = [e for e in data["auth_events"] if e["kind"] == "model_phase_closed"]
            self.assertEqual(len(closed), 1)
            self.assertEqual(closed[0]["actual_generation_attempts"], len(server.posts))
            self.assertEqual(closed[0], data["auth_events"][-1])
            requests = [e for e in events if e["phase"] == "request"]
            self.assertEqual(len(requests), len(server.posts))
            self.assertEqual(sum(r["prepare_generation_calls_observed"]+r["answer_calls"] for r in data["rows"])
                +sum(b["generation_calls_observed"] for b in data["builds"]), len(server.posts))
            serialized = json.dumps({"posts": server.posts, "ner": ner.calls})
            for forbidden in (authored.CANARY, authored.OUTSIDER_QUERY, '"answers"', '"sensitive_spans"',
                              '"access"', '"authority_domain"', '"grants_sha256"'):
                self.assertNotIn(forbidden, serialized)
            for row in data["rows"]:
                self.assertEqual(row["score"], harness.score(row, evaluation[row["story_id"]]))
            return report, data, events, server, signed

    def test_five_arms_shared_receipt_cache_auth_order_and_closed_scoring(self):
        report, data, events, server, signed = self.run_authored()
        self.assertEqual({(r["story_id"], r["task_id"], r["arm"]) for r in data["rows"]},
            {(f"authored-policy-semantic-{i}", task, arm) for i in range(8)
             for task in ("name", "status", "repeat", "mail", "outsider") for arm in harness.ARMS})
        self.assertEqual((report["builder_generations"], report["semantic_shared_generations"],
                          report["union_detection_generations"], report["answer_generations"]), (8, 32, 41, 160))
        self.assertEqual(len(server.posts), 241)
        for cell in report["arms"].values():
            self.assertEqual((cell["legal_tasks"], cell["correct"], cell["outsider_blocked"]), (32, 32, 8))
        union_rows = [r for r in data["rows"] if r["arm"] == "union" and r["actor_id"] == "owner"]
        self.assertEqual(sum(r["prepare_metadata"]["detection_cache"]["hits"] for r in union_rows), 27)
        self.assertEqual(sum(r["prepare_generation_calls_observed"] for r in union_rows), 41)
        journal = data["auth_events"]
        callbacks = [e for e in journal if e["kind"] == "semantic_callback_start"]
        self.assertEqual(len(callbacks), 96)
        self.assertTrue(any(len(e["record_ids"]) == 2 for e in journal if e["kind"] == "prepare_start"))
        for callback in callbacks:
            operation = callback["operation"]
            start = next(e for e in journal if e["kind"] == "prepare_start" and e["operation"] == operation)
            checked = [e for e in journal if start["sequence"] < e["sequence"] < callback["sequence"]
                       and e["operation"] == operation and e["kind"] == "access_check"]
            self.assertEqual({e["record_id"] for e in checked}, set(start["record_ids"]))
            self.assertTrue(all(e["error"] is None and e["actor_id"] == "owner" and e["agent_id"] == "target-agent" for e in checked))
            self.assertGreaterEqual(len(checked), 2*len(start["record_ids"]))
            self.assertEqual(callback["baseline_spans_sha256"], harness._digest(callback["baseline_spans"]))
        for story_id in {r["story_id"] for r in data["rows"]}:
            for task_id in ("name", "status", "repeat", "mail"):
                endings = [e for e in journal if e["kind"] == "semantic_callback_end"
                           and e["operation"].startswith(f"{story_id}:{task_id}:")]
                self.assertEqual(len(endings), 3)
                self.assertEqual(sorted(e["new_generation_attempts"] for e in endings), [0, 0, 1])
                self.assertEqual(len({e["semantic_audit"]["receipt_sha256"] for e in endings}), 1)
        outsider_operations = {e["operation"] for e in journal if e["kind"] == "prepare_start" and e["actor_id"] == "outsider"}
        self.assertEqual(len(outsider_operations), 40)
        self.assertFalse(any(e["operation"] in outsider_operations for e in callbacks))
        self.assertFalse(any(e["task_id"] == "outsider" for e in events))
        for store in data["record_store"]:
            for record in store["records"]:
                authority, original = signed[record["record_id"]]
                self.assertIsNot(record, original)
                self.assertIsNone(authority.validate_access(record, actor_id="owner", agent_id="target-agent"))

    def test_failed_union_is_not_cached_or_removed_from_task_denominator(self):
        report, data, _, _, _ = self.run_authored(union_failure=True)
        cell = report["arms"]["union"]
        self.assertEqual((cell["registered_tasks"], cell["legal_tasks"], cell["ready"], cell["preprocessing_block"]), (40, 32, 0, 32))
        self.assertEqual((cell["outsider_blocked"], cell["answer_calls"], cell["correct"]), (8, 0, 0))
        rows = [r for r in data["rows"] if r["arm"] == "union" and r["actor_id"] == "owner"]
        self.assertTrue(all(r["prepare_metadata"]["detection_cache"]["hits"] == 0 for r in rows))
        self.assertEqual(report["union_detection_generations"], 68)
        self.assertEqual(report["answer_generations"], 128)
        self.assertEqual(report["semantic_shared_generations"], 32)
        for arm in ("baseline", "roles", "completion", "joint"):
            self.assertEqual(report["arms"][arm]["correct"], 32)

    def test_shared_construction_failure_retains_all_200_tasks(self):
        report, data, _, _, _ = self.run_authored(build_failure=True)
        self.assertEqual((report["builder_generations"], report["semantic_shared_generations"], report["answer_generations"]), (8, 0, 0))
        self.assertTrue(all(not store["records"] for store in data["record_store"]))
        self.assertFalse(any(e["kind"] == "semantic_callback_start" for e in data["auth_events"]))
        for cell in report["arms"].values():
            self.assertEqual((cell["registered_tasks"], cell["legal_tasks"], cell["build_block"], cell["ready"]), (40, 32, 32, 0))
            self.assertEqual(cell["outsider_blocked"], 0)  # Missing memory is not an actual authorization denial.
        self.assertTrue(all(r["prepare_error"] == "memory_build_unavailable" for r in data["rows"]))

    def test_strict_secondary_is_separate_and_reuses_one_model_answer(self):
        report, data, _, server, _ = self.run_authored(bare_tokens=True)
        self.assertEqual((report["answer_generations"], len(server.posts)), (160, 241))
        for cell in report["arms"].values():
            self.assertEqual((cell["correct"], cell["secondary_serialization_correct"]), (16, 32))
        repaired = [r for r in data["rows"] if r.get("secondary_serialization", {}).get("decision") == "added_outer_brackets"]
        self.assertEqual(len(repaired), 80)
        for row in repaired:
            self.assertEqual(row["restoration_status"], "blocked")
            self.assertIsNone(row["final_answer"])
            self.assertFalse(row["score"]["correct"])
            self.assertTrue(row["score"]["secondary_serialization_correct"])

    def test_private_refusal_and_unsupported_content_remain_blocked_in_both_scores(self):
        report, data, _, _, _ = self.run_authored(hostile_answers=True)
        for cell in report["arms"].values():
            self.assertEqual((cell["correct"], cell["secondary_serialization_correct"], cell["restoration_failure"]), (0, 0, 32))
        legal = [r for r in data["rows"] if r["actor_id"] == "owner"]
        private = [r for r in legal if r["task_id"] == "mail"]
        self.assertEqual(len(private), 40)
        self.assertTrue(all("Cedar Foundry" in r["model_answer"] and r["restoration_error"] == "raw_protected_value_in_answer" for r in private))
        for row in legal:
            self.assertIsNone(row["final_answer"])
            self.assertIsNone(row["secondary_serialization"]["final_answer"])
            self.assertEqual(row["secondary_serialization"]["decision"], "unchanged")
            self.assertEqual(row["secondary_serialization"]["restoration_status"], "blocked")


if __name__ == "__main__":
    unittest.main()
