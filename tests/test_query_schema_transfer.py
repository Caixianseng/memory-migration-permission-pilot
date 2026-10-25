"""Authored fixed-policy 96-cell study; injected encoder/transport, no models."""
from copy import deepcopy
import json
from pathlib import Path
import re
import secrets
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_query_schema_transfer as harness
from scripts import run_customer_schema_probe as probe
from memory_migration_study import privacy
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.ner_detector import LABELS
from tests.test_customer_schema_probe import FakeRuntime, FakeModel
from tests.test_span_answer_transfer import SpanServer, fixture

CANARY = "QUERY_SCHEMA_REFERENCE_NEVER_MODEL_7439"


class QueryModel(FakeModel):
    def extract_entities(self, text, labels, *, threshold, include_confidence, include_spans):
        self.calls.append({"text": text, "labels": deepcopy(labels), "threshold": threshold,
            "include_confidence": include_confidence, "include_spans": include_spans})
        if "ENCODER_ERROR" in text:
            raise RuntimeError("authored unavailable encoder")
        label = next(iter(labels))
        values = ["Cedar Foundry", "generic organization"] if label == "organization" else ["Cedar Foundry"]
        return {"entities": {label: [{"text": m.group(), "start": m.start(), "end": m.end(), "confidence": .99}
            for value in values for m in re.finditer(re.escape(value), text)]}}


class QueryRuntime(FakeRuntime):
    def __init__(self, root):
        super().__init__(root)
        self.model = QueryModel()


class QuerySchemaTransferTests(unittest.TestCase):
    def run_authored(self, *, root=None, annotation_failure=False, generic_query=False, oversized=False):
        runtime, evaluation = fixture()
        for story in runtime:
            story["policy"] = deepcopy(probe.POLICY)
            evaluation[story["story_id"]]["scoring_only_canary"] = CANARY
        if generic_query:
            runtime[0]["tasks"][0]["query"] = "Who is the customer generic organization?"
        if oversized:
            runtime[0]["tasks"][0]["query"] = "OVERSIZED Who is the customer?"
        ner = QueryRuntime("no weights")
        server = SpanServer(annotation_failure=annotation_failure)
        labels_before, real_loads, real_build, real_prepare = deepcopy(LABELS), json.loads, MemoryLabelAuthority.build_record, harness.prepare_labeled_transfer
        original_token_hex = secrets.token_hex
        progress, gold_parses, prepare_calls = [], [], []
        def build_record(authority, source, *args, **kwargs):
            record = real_build(authority, source, *args, **kwargs)
            server.authorities[server.observer.context["story_id"]] = (authority, source["source_id"])
            return record
        def prepare(records, query, policy, **kwargs):
            self.assertIs(secrets.token_hex, original_token_hex)
            self.assertIsNot(privacy.secrets, secrets)
            prepare_calls.append((kwargs["actor_id"], kwargs["request_id"], query, harness._digest(records)))
            return real_prepare(records, query, policy, **kwargs)
        def loads(value, *args, **kwargs):
            marker = CANARY.encode() if isinstance(value, bytes) else CANARY
            if isinstance(value, (str, bytes)) and marker in value:
                self.assertTrue(observer.model_phase_closed)
                self.assertEqual(len(progress), 96)
                self.assertTrue(all(not r["scored"] for r in progress))
                server.gold_parsed = True
                gold_parses.append(len(server.posts))
            return real_loads(value, *args, **kwargs)
        temporary = tempfile.TemporaryDirectory() if root is None else None
        try:
            root = Path(temporary.name if temporary else root)
            split = root/"corpus/development"
            split.mkdir(parents=True)
            for name, data in (("runtime", runtime), ("evaluation", evaluation)):
                (split/(name+".json")).write_text(json.dumps(data), encoding="utf-8")
            observer = harness.QueryTransport(root/"output", server.transport)
            server.observer = observer
            with patch.object(harness, "LocalNerRuntime", return_value=ner), patch.object(MemoryLabelAuthority, "build_record", new=build_record), \
                    patch.object(harness, "prepare_labeled_transfer", new=prepare), patch.object(json, "loads", new=loads), \
                    patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), observer.installed():
                report = harness.run(root/"corpus", root/"output", "no-assets", {}, observer, progress=progress.append)
            network = {"loopback_connections": 0, "external_attempts_blocked": 0}
            harness.save(root/"output/transport_audit.json", dict(observer.summary(), completed=True, test_transport_only=True,
                registered_protocol=harness.VERSION, closed_phase_attempts=observer.closed_phase_attempts, network=network))
            harness.save(root/"output/network_audit.json", network)
            data = {name: real_loads((root/"output"/(name+".json")).read_bytes()) for name in
                ("plan", "runtime", "rows", "paired_contexts", "query_encoder_events", "builds", "annotations", "record_store", "pools", "controls", "auth_events", "runtime_identity")}
            events = [real_loads(line) for line in (root/"output/request_transport.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(LABELS, labels_before)
            self.assertIs(privacy.secrets, secrets)
            self.assertIs(secrets.token_hex, original_token_hex)
            self.assertEqual((len(data["rows"]), len(data["paired_contexts"]), len(data["controls"])), (96, 48, 8))
            self.assertEqual(len({(r["story_id"], r["task_id"], r["arm"]) for r in data["rows"]}), 96)
            self.assertEqual(report["generation_calls_observed"], len(server.posts))
            self.assertEqual(report["total_encoder_calls"], len(ner.model.calls))
            self.assertEqual(report["query_model_extract_entities_calls"], sum(e["extract_entities_calls"] for e in data["query_encoder_events"]))
            self.assertEqual(gold_parses, [len(server.posts)])
            self.assertEqual(observer.closed_phase_attempts, 0)
            captured = json.dumps({"llm": server.posts, "encoder": ner.calls})
            for forbidden in (CANARY, "OUTSIDER_NEVER_SEND_417", '"answers"', '"sensitive_spans"', '"access_signature"', '"actor_id"', '"task_id"'):
                self.assertNotIn(forbidden, captured)
            self.assertTrue(all(e["source_id"] == "__query__" for e in data["query_encoder_events"]))
            return report, data, events, ner, server
        finally:
            if temporary:
                temporary.cleanup()

    def test_complete_96_matrix_common_signed_labels_nonce_and_actual_equal_body(self):
        report, data, events, ner, server = self.run_authored()
        self.assertEqual((report["builder_generations"], report["write_annotation_generations"], report["answer_generations"]), (8, 9, 80))
        self.assertEqual(report["query_prepare_encoder_calls"], {"A": 40, "B": 40})
        self.assertEqual(report["total_encoder_calls"], 98)
        requests = {e["index"]: e["request"] for e in events if e["phase"] == "request"}
        for pair in data["paired_contexts"]:
            rows = {r["arm"]: r for r in data["rows"] if r["context_id"] == pair["context_id"]}
            self.assertEqual(rows["A"]["request_sha256"], rows["B"]["request_sha256"])
            self.assertEqual(rows["A"]["paired_nonce_sha256"], rows["B"]["paired_nonce_sha256"])
            if pair["actor_id"] == "owner":
                self.assertEqual(rows["A"]["outbound"], rows["B"]["outbound"])
                self.assertEqual(requests[rows["A"]["answer_request_indices"][0]], requests[rows["B"]["answer_request_indices"][0]])
                self.assertEqual((rows["A"]["serialization_nonce_calls"], rows["B"]["serialization_nonce_calls"]), (1, 1))
                self.assertTrue(all(c["label_valid"] for c in rows["A"]["checks"]+rows["B"]["checks"]))
            else:
                self.assertTrue(all(r["answer_calls"] == r["serialization_nonce_calls"] == 0 and not r["query_encoder_event_indices"] for r in rows.values()))
        for arm in harness.ARMS:
            self.assertEqual(report["arms"][arm]["legal"]["correct"], 32)
            self.assertEqual(report["arms"][arm]["missing"]["correct"], 8)
            self.assertEqual(report["arms"][arm]["outsider"]["outsider_blocked"], 8)

    def test_only_query_schema_changes_raw_labels_and_no_production_global_mutation(self):
        _, data, _, ner, _ = self.run_authored(generic_query=True)
        observations = [e for e in data["query_encoder_events"] if "generic organization" in e["text"]]
        self.assertEqual({e["arm"] for e in observations}, {"A", "B"})
        for e in observations:
            self.assertEqual(e["requested_labels"], {LABELS["CUSTOMER"][0]: LABELS["CUSTOMER"][1]})
            expected_label = "organization" if e["arm"] == "A" else "customer organization"
            self.assertEqual(set(e["actual_labels"]), {expected_label})
            self.assertEqual(set(e["raw_result"]["entities"]), {expected_label})
            self.assertEqual(set(e["translated_result"]["entities"]), {"organization"})
            self.assertTrue(all(x["max_len"] is None and x["input_ids"] <= 512 for x in e["encoding_observations"]))
        rows = {r["arm"]: r for r in data["rows"] if r["story_id"] == "authored-span-0" and r["task_id"] == "name"}
        self.assertNotEqual(rows["A"]["outbound"]["query"], rows["B"]["outbound"]["query"])
        self.assertEqual(rows["A"]["records_sha256"], rows["B"]["records_sha256"])
        self.assertEqual({set(c["labels"]).pop() for c in ner.calls if c["text"].startswith("Customer:")}, {"organization"})

    def test_B_rejects_unapproved_business_policy_before_any_encoder_or_fallback(self):
        runtime, observations = QueryRuntime("none"), []
        agent = harness.QuerySchemaAgent(runtime, "B", observations)
        changed = {**probe.POLICY, "instructions": probe.POLICY["instructions"]+" Changed scope."}
        for source_id in ("__query__", "record-fallback"):
            result = agent(text="Cedar Foundry", source_id=source_id, policy=changed, rule_findings=[])
            self.assertEqual((result["status"], result["local_calls"], result["findings"]), ("needs_review", 0, []))
        self.assertFalse(runtime.calls or observations)
        self.assertEqual(agent.cache_identity()["query"]["runtime"]["actual_schema"], probe.schemas()["B"])

    def test_annotation_failure_and_encoded_overflow_keep_all_96_denominators(self):
        report, data, _, _, _ = self.run_authored(annotation_failure=True)
        self.assertEqual(report["common_build_failures"], 0)
        self.assertEqual(report["union_label_set_failures"], 8)
        self.assertEqual(report["answer_generations"], 0)
        self.assertTrue(any(a["status"] == "ok" and not a["eligible_for_store"] for a in data["annotations"]))
        for arm in harness.ARMS:
            self.assertEqual(report["arms"][arm]["legal"]["registered_tasks"], 32)
            self.assertEqual(report["arms"][arm]["missing"]["registered_tasks"], 8)
            self.assertEqual(report["arms"][arm]["missing"]["correct"], 0)
        report, data, _, _, _ = self.run_authored(oversized=True)
        self.assertEqual(report["answer_generations"], 78)
        rejected = [e for e in data["query_encoder_events"] if "OVERSIZED" in e["text"]]
        self.assertEqual(len(rejected), 2)
        self.assertTrue(all(e["status"] == "needs_review" and e["extract_entities_calls"] == 0 and e["encoding_observations"][0]["input_ids"] == 513 for e in rejected))
        self.assertEqual(report["query_model_extract_entities_calls"], 78)


if __name__ == "__main__":
    unittest.main()
