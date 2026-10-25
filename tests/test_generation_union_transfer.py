"""Authored four-arm real pipeline regressions; no sockets, weights or APIs."""
import copy
import json
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import patch

from tests.test_reference_memory_study import FakeServer, authored, load_module, ROOT
from memory_migration_study.local_detector import MODEL
from memory_migration_study.memory_labels import (MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer)
from memory_migration_study.ner_detector import GlinerEntityAgent
from memory_migration_study.privacy import _TOKEN

harness = load_module("generation_union_under_test", ROOT/"scripts/run_generation_union_transfer.py")


class UnionWriteServer(FakeServer):
    def __init__(self, *, annotation_failure=False, hostile=False):
        super().__init__()
        self.annotation_failure, self.hostile, self.observer = annotation_failure, hostile, None

    def transport(self, client, method, path, body=None):
        if method != "POST":
            return super().transport(client, method, path, body)
        if self.gold_parsed:
            raise AssertionError("generation after gold parse")
        data = json.loads(body["messages"][1]["content"])
        properties = body.get("format", {}).get("properties", {})
        if "findings" in properties:
            failed = (self.annotation_failure and self.observer.context["stage"] == "write_annotation"
                      and self.observer.context["fact_index"] == 0)
            result = {"status": "needs_review" if failed else "ok", "findings": []}
            if not failed:
                result["findings"] = [{"quote": data["text"][s["start"]:s["end"]], "category": s["category"]}
                                      for s in authored.candidate_spans(data["text"])]
            content = json.dumps(result)
        elif "memories" in data:
            text = "\n".join(m["text"] for m in data["memories"])
            query = data["query"].casefold()
            if self.hostile and data["query"].startswith("Customer:"):
                content = _TOKEN.search(data["query"]).group()
            elif self.hostile and "email" in query:
                content = "I refuse but Cedar Foundry"
            else:
                expression = (r"Contact: (.+?)\.$" if "email" in query else
                              r"Status: (.+?);\s+Contact:" if "status" in query else
                              r"Customer: (.+?);\s+Status:")
                match = re.search(expression, text)
                content = match.group(1) if match else "UNKNOWN"
        else:
            return super().transport(client, method, path, body)
        self.posts.append(copy.deepcopy(body))
        return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": content},
                "prompt_eval_count": 100, "eval_count": 20}


class GenerationUnionTransferTests(unittest.TestCase):
    def run_authored(self, *, root=None, annotation_failure=False, hostile=False):
        runtime0, gold0 = authored.fixture()
        runtime, evaluation = [], {}
        for index in range(8):
            story = copy.deepcopy(runtime0[0])
            sid = story["story_id"] = f"authored-generation-union-{index}"
            story["source"]["source_id"] = f"authored-generation-source-{index}"
            runtime.append(story)
            evaluation[sid] = copy.deepcopy(gold0["authored-fixture"])
            if index == 0:
                story["source"]["text"] = story["source"]["text"].replace("; Status:", ";\nStatus:")
                evaluation[sid]["sensitive_spans"] = [{k: span[k] for k in ("start", "end")}
                    for span in authored.candidate_spans(story["source"]["text"])]
            if hostile:
                story["tasks"][0]["query"] = "Customer: UnsourcedAlias"
        server, ner = UnionWriteServer(annotation_failure=annotation_failure, hostile=hostile), authored.FakeNerRuntime()
        signed, progress, parses = {}, [], []
        real_build, real_loads = MemoryLabelAuthority.build_record, json.loads
        def build_record(authority, *args, **kwargs):
            record = real_build(authority, *args, **kwargs)
            signed[record["record_id"]] = authority
            return record
        def guarded_loads(value, *args, **kwargs):
            marker = authored.CANARY.encode() if isinstance(value, bytes) else authored.CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertTrue(observer.model_phase_closed)
                self.assertEqual(len(progress), 160)
                self.assertTrue(all(not row["scored"] for row in progress))
                server.gold_parsed = True
                parses.append(len(server.posts))
            return real_loads(value, *args, **kwargs)
        temporary = tempfile.TemporaryDirectory() if root is None else None
        try:
            root = Path(temporary.name if temporary else root)
            split = root/"corpus/development"
            split.mkdir(parents=True)
            for name, value in (("runtime", runtime), ("evaluation", evaluation)):
                (split/(name+".json")).write_text(json.dumps(value), encoding="utf-8")
            output = root/"output"
            observer = harness.TransferTransport(output, server.transport)
            server.observer = observer
            started = time.monotonic()
            with patch.object(harness, "LocalNerRuntime", return_value=ner), \
                 patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
                 patch.object(json, "loads", new=guarded_loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), observer.installed():
                report = harness.run(root/"corpus", output, "no-model-assets", {}, observer, progress=progress.append)
            network = {"loopback_connections": 0, "external_attempts_blocked": 0}
            audit = dict(observer.summary(), completed=True, elapsed_seconds=time.monotonic()-started,
                network=network, closed_phase_attempts=observer.closed_phase_attempts,
                registered_protocol=harness.VERSION, test_transport_only=True)
            (output/"transport_audit.json").write_text(json.dumps(audit), encoding="utf-8")
            (output/"network_audit.json").write_text(json.dumps(network), encoding="utf-8")
            data = {name: real_loads((output/(name+".json")).read_bytes()) for name in
                ("plan", "runtime", "runtime_identity", "rows", "builds", "label_sets", "record_store", "pools", "annotations", "fact_bindings", "auth_events")}
            events = [real_loads(line) for line in (output/"request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual((len(data["rows"]), len(data["builds"]), len(data["record_store"])), (160, 8, 16))
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            self.assertEqual(observer.attempts, len(server.posts))
            self.assertEqual(report["total_encoder_calls"], len(ner.calls))
            self.assertEqual(parses, [len(server.posts)])
            self.assertEqual(observer.closed_phase_attempts, 0)
            self.assertTrue(report["implementation_unchanged"])
            self.assertTrue(report["detector_call_accounting_complete"])
            self.assertEqual(sum(r["prepare_generation_calls_observed"]+r["answer_calls"] for r in data["rows"])
                +sum(b["generation_calls_observed"] for b in data["builds"])
                +sum(a["generation_calls_observed"] for a in data["annotations"]), len(server.posts))
            serialized = json.dumps({"posts": server.posts, "ner": ner.calls})
            for forbidden in (authored.CANARY, authored.OUTSIDER_QUERY, '"answers"', '"sensitive_spans"', '"access"', '"signature"'):
                self.assertNotIn(forbidden, serialized)
            for row in data["rows"]:
                self.assertEqual(row["score"], harness.score(row, evaluation[row["story_id"]]))
            return report, data, events, signed
        finally:
            if temporary:
                temporary.cleanup()

    def test_complete_shared_facts_dual_signed_labels_costs_and_original_responses(self):
        report, data, events, signed = self.run_authored()
        self.assertEqual({(r["story_id"], r["task_id"], r["arm"]) for r in data["rows"]},
            {(f"authored-generation-union-{i}", task, arm) for i in range(8)
             for task in ("name", "status", "repeat", "mail", "outsider") for arm in harness.ARMS})
        self.assertEqual(report["generation_calls_observed"], 186)
        self.assertEqual((report["builder_generations"], report["write_annotation_generations"],
                          report["union_migration_generations"], report["answer_generations"]), (8, 9, 41, 128))
        self.assertEqual(report["total_encoder_calls"], 227)
        self.assertEqual(report["per_arm_operation_costs"]["G"]["encoder_calls"], 32)
        self.assertEqual(report["per_arm_operation_costs"]["M"]["encoder_calls"], 68)
        self.assertEqual(report["per_arm_operation_costs"]["T"]["encoder_calls"], 68)
        self.assertEqual(report["per_arm_operation_costs"]["U"]["union_cache_hits"], 27)
        for cell in report["arms"].values():
            self.assertEqual((cell["registered_tasks"], cell["legal_tasks"], cell["correct"], cell["outsider_blocked"]), (40, 32, 32, 8))
        records = {r["record_id"]: r for store in data["record_store"] for r in store["records"]}
        for binding in data["fact_bindings"]:
            ner, union = records[binding["ner_record_id"]], records[binding["union_record_id"]]
            self.assertIs(signed[ner["record_id"]], signed[union["record_id"]])
            self.assertNotEqual(ner["record_id"], union["record_id"])
            for key in ("text", "source", "source_start", "source_end"):
                self.assertEqual(ner[key], union[key])
            self.assertEqual({k: v for k, v in ner["access"].items() if k != "record_id"},
                             {k: v for k, v in union["access"].items() if k != "record_id"})
            self.assertNotEqual(ner["label"]["detector_version"], union["label"]["detector_version"])
        requests = {e["index"]: e for e in events if e["phase"] == "request"}
        responses = {e["index"]: e for e in events if e["phase"] == "response"}
        for annotation in data["annotations"]:
            self.assertEqual(annotation["input_payload"]["query"], "")
            self.assertEqual(annotation["status"], "ok")
            self.assertEqual(annotation["generation_calls_observed"], 1)
            self.assertEqual(len(annotation["member_raw_outputs"]), 1)
            for index in annotation["request_indices"]:
                self.assertEqual(requests[index]["stage"], "write_annotation")
                self.assertEqual(requests[index]["fact_key"], annotation["fact_key"])
                self.assertEqual(json.loads(responses[index]["response"]["message"]["content"])["status"], "ok")
        for row in data["rows"]:
            if row["actor_id"] == "outsider":
                self.assertEqual((row["detector_calls"], row["answer_calls"]), (0, 0))
            elif row["arm"] in {"G", "T"}:
                self.assertTrue(all(c["label_valid"] for c in row["checks"]))
                self.assertEqual(row["prepare_metadata"]["label_requirements"]["expected_detector_version"],
                                 data["runtime_identity"]["union_detector_revision"])

    def test_one_failed_write_annotation_blocks_whole_union_set_without_ner_substitution(self):
        report, data, _, _ = self.run_authored(annotation_failure=True)
        self.assertEqual(report["write_annotation_generations"], 9)
        self.assertEqual(report["union_label_stories_ready"], 0)
        self.assertEqual((report["common_build_failures"], report["union_label_set_failures"]), (0, 8))
        self.assertTrue(all(not s["records"] for s in data["record_store"] if s["builder"] == "union"))
        self.assertTrue(any(a["status"] == "ok" and not a["eligible_for_store"] for a in data["annotations"]))
        for arm in ("G", "T"):
            self.assertEqual((report["arms"][arm]["legal_tasks"], report["arms"][arm]["build_block"],
                              report["arms"][arm]["answer_calls"]), (32, 32, 0))
        for arm in ("M", "U"):
            self.assertEqual(report["arms"][arm]["correct"], 32)
        self.assertTrue(all(r["prepare_error"] == "label_set_unavailable" for r in data["rows"] if r["arm"] in {"G", "T"}))
        self.assertTrue(all(r["common_build_status"] == "ok" and r["union_label_set_status"] == "needs_review" for r in data["rows"]))

    def test_tampered_union_label_uses_real_fallback_without_reissuing_grant(self):
        _, data, _, signed = self.run_authored()
        record = copy.deepcopy(next(s for s in data["record_store"] if s["builder"] == "union")["records"][0])
        grant = copy.deepcopy(record["access"])
        record["label_signature"] = "0"*64
        story = data["runtime"][0]
        runtime = authored.FakeNerRuntime()
        detector = GlinerEntityAgent(runtime, approved_policies=[story["policy"]])
        result = prepare_labeled_transfer([record], "", story["policy"], authority=signed[record["record_id"]],
            actor_id="owner", agent_id="target-agent", request_id="tampered-label", mode="generation", agent=detector,
            label_requirements={"expected_builder_version": data["builds"][0]["builder_version"],
                                "expected_detector_version": data["runtime_identity"]["union_detector_revision"]})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_signature_invalid")
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(len(runtime.calls), 1)
        self.assertEqual(record["access"], grant)

    def test_union_record_revocation_blocks_old_restore_and_replay(self):
        _, data, _, signed = self.run_authored()
        record = next(s for s in data["record_store"] if s["builder"] == "union")["records"][0]
        authority, story = signed[record["record_id"]], data["runtime"][0]
        def zero(**_):
            return {"status": "ok", "findings": [], "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}
        prepared = prepare_labeled_transfer([record], "", story["policy"], authority=authority,
            actor_id="owner", agent_id="target-agent", request_id="before-revoke", mode="generation", agent=zero)
        self.assertEqual(prepared["status"], "ok")
        token = _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()
        authority.revoke(record["record_id"])
        restored = restore_labeled_answer(token, prepared, [record], story["policy"], authority=authority,
            actor_id="owner", agent_id="target-agent", request_id="before-revoke")
        self.assertEqual(restored["error"], "grant_revoked")
        replay = prepare_labeled_transfer([record], "", story["policy"], authority=authority,
            actor_id="owner", agent_id="target-agent", request_id="before-revoke", mode="generation", agent=zero)
        self.assertEqual(replay["error"], "grant_revoked")
        self.assertEqual(replay["local_calls"], 0)

    def test_query_only_and_raw_private_refusal_cannot_be_promoted_by_secondary(self):
        report, data, _, _ = self.run_authored(hostile=True)
        for arm in harness.ARMS:
            self.assertEqual((report["arms"][arm]["correct"], report["arms"][arm]["secondary_serialization_correct"]), (16, 16))
        for row in data["rows"]:
            if row["actor_id"] != "owner" or row["task_id"] not in {"name", "mail"}:
                continue
            self.assertIsNone(row["final_answer"])
            self.assertIsNone(row["secondary_serialization"]["final_answer"])
            self.assertEqual(row["secondary_serialization"]["decision"], "unchanged")
            self.assertEqual(row["restoration_error"], "query_only_value_has_no_evidence" if row["task_id"] == "name" else "raw_protected_value_in_answer")


if __name__ == "__main__":
    unittest.main()
