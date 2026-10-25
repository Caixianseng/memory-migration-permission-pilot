"""Meaningful fake-transport evidence tests; no study corpus or model weights."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_policy_semantic_study as verifier


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("policy_evidence_authored_helper", verifier.ROOT / "tests/test_reference_memory_study.py")
harness = load("policy_evidence_fake_harness", verifier.ROOT / "scripts/run_policy_semantic_study.py")


class SemanticServer(helper.FakeServer):
    def transport(self, client, method, path, body=None):
        if method == "POST" and "verdicts" in body.get("format", {}).get("properties", {}):
            self.posts.append(deepcopy(body))
            data = json.loads(body["messages"][1]["content"])
            content = {"verdicts": [{"cid": c["cid"], "role": "value", "quote": c["quote"]}
                                    for c in data["candidates"]]}
        elif method == "POST" and "findings" in body.get("format", {}).get("properties", {}):
            self.posts.append(deepcopy(body))
            data = json.loads(body["messages"][1]["content"])
            content = {"status": "ok", "findings": [{"quote": data["text"][s["start"]:s["end"]],
                "category": s["category"]} for s in helper.authored.candidate_spans(data["text"])]}
        else:
            return super().transport(client, method, path, body)
        return {"model": helper.MODEL, "done": True, "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(content)},
                "prompt_eval_count": 100, "eval_count": 20}


class PolicySemanticVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.corpus = cls.root / "corpus"
        split = cls.corpus / "development"
        split.mkdir(parents=True)
        raw, gold = helper.authored.fixture()
        stories, evaluation = [], {}
        for n in range(8):
            story = deepcopy(raw[0])
            sid = story["story_id"] = f"self_policy_{n}"
            story["source"]["source_id"] = f"self_policy_source_{n}"
            story["template_family"] = f"authored_family_{n % 4}"
            story["language"] = "en" if n % 2 else "zh"
            if n == 0:
                # A real second source candidate/record makes "all records
                # authorized before callback" stronger than a one-record test.
                story["source"]["text"] += "\nPublic operational note."
            stories.append(story)
            evaluation[sid] = deepcopy(gold["authored-fixture"])
        for name, data in (("runtime", stories), ("evaluation", evaluation)):
            (split / (name+".json")).write_text(json.dumps(data), encoding="utf-8")
        cls.evidence = cls.root / "original"
        server = SemanticServer()
        observer = harness.SemanticTransport(cls.evidence, server.transport)
        config = {"endpoint": "http://127.0.0.1:11435", "model": helper.MODEL,
            "expected_version": helper.VERSION, "expected_digest": helper.DIGEST, "timeout_seconds": 120}
        ner = helper.authored.FakeNerRuntime()
        # Real producer/authority/cache/receipts, injected inference callbacks.
        with patch.object(harness, "LocalNerRuntime", return_value=ner), \
             patch("socket.socket.connect", side_effect=AssertionError("network forbidden")), observer.installed():
            harness.run(cls.corpus, cls.evidence, "no-model-assets", config, observer)
        network = {"external_attempts_blocked": 0, "loopback_connections": 0}
        audit = dict(observer.summary(), completed=True, network=network,
            closed_phase_attempts=observer.closed_phase_attempts, registered_protocol=harness.VERSION)
        for name, data in (("transport_audit", audit), ("network_audit", network)):
            (cls.evidence / (name+".json")).write_text(json.dumps(data), encoding="utf-8")
        cls.fake_posts = len(server.posts)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy_run(self):
        directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(directory.cleanup)
        output = Path(directory.name) / "run"
        shutil.copytree(self.evidence, output)
        return output

    def mutate(self, directory, name, change):
        path = directory / (name+".json")
        data = json.loads(path.read_bytes())
        change(data)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def test_real_fake_transport_evidence_passes_and_shared_costs_are_not_tripled(self):
        receipt = verifier.verify(self.evidence, corpus=self.corpus)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["registered_rows"], 200)
        self.assertEqual(receipt["physical_generation_attempts"], self.fake_posts)
        self.assertEqual(receipt["verification_model_calls"], 0)
        for metrics in receipt["arms"].values():
            self.assertEqual((metrics["legal_tasks"], metrics["outsider_blocked"]), (32, 8))
        self.assertGreater(receipt["callbacks_checked"], 0)
        semantic_cost = sum(c["physical_calls"] for c in receipt["physical_costs_by_stage_and_observed_arm"] if c["stage"] == "semantic")
        self.assertGreater(semantic_cost, 0)
        self.assertLessEqual(semantic_cost, 32)

    def test_missing_row_and_inflated_summary_are_rejected(self):
        run = self.copy_run()
        self.mutate(run, "rows", lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "task_matrix_denominator"):
            verifier.verify(run, corpus=self.corpus)
        run = self.copy_run()
        self.mutate(run, "report", lambda report: report["arms"]["baseline"].__setitem__("correct", 99))
        with self.assertRaisesRegex(ValueError, "independent_aggregate_mismatch"):
            verifier.verify(run, corpus=self.corpus)

    def test_actual_wire_byte_tampering_is_rejected(self):
        run = self.copy_run()
        path = run / "request_transport.jsonl"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        next(e for e in events if e["phase"] == "request")["wire_json_utf8_bytes"] += 1
        path.write_text("".join(json.dumps(e)+"\n" for e in events), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "wire_bytes"):
            verifier.verify(run, corpus=self.corpus)

    def test_callback_before_real_authorization_is_rejected_even_with_contiguous_sequence(self):
        run = self.copy_run()
        def reorder(events):
            callback = next(e for e in events if e["kind"] == "semantic_callback_start")
            original = events.index(callback)
            first = next(i for i, e in enumerate(events) if e["kind"] == "prepare_start" and e["operation"] == callback["operation"])
            events.insert(first+1, events.pop(original))
            for i, event in enumerate(events):
                event["sequence"] = i+1
            end = next(e for e in events if e["kind"] == "semantic_callback_end" and e["operation"] == callback["operation"])
            end["callback_start_sequence"] = callback["sequence"]
        self.mutate(run, "auth_events", reorder)
        with self.assertRaisesRegex(ValueError, "semantic_before_authorization"):
            verifier.verify(run, corpus=self.corpus)

    def test_cache_hit_cannot_charge_same_shared_receipt_again(self):
        run = self.copy_run()
        target = []
        def recharge(rows):
            row = next(r for r in rows if r.get("detection", {}).get("policy_semantics", {}).get("cache_hit"))
            row["detection"]["policy_semantics"]["stage_local_counts"]["local_generation"] = 1
            target.append(f"{row['story_id']}:{row['task_id']}:{row['arm']}")
        self.mutate(run, "rows", recharge)
        def recharge_redundant_log(events):
            event = next(e for e in events if e["kind"] == "semantic_callback_end" and e["operation"] == target[0])
            event["semantic_audit"]["stage_local_counts"]["local_generation"] = 1
        # Even a coordinated edit of both redundant audit copies must fail
        # against the physical transport ledger, rather than pass by equality.
        self.mutate(run, "auth_events", recharge_redundant_log)
        with self.assertRaisesRegex(ValueError, "semantic_applied_costs"):
            verifier.verify(run, corpus=self.corpus)

    def test_archive_mutation_fails_but_current_source_drift_is_reported(self):
        run = self.copy_run()
        archive = run / "implementation/memory_migration_study/policy_semantics.py"
        archive.write_bytes(archive.read_bytes()+b"\n# corrupted frozen source\n")
        with self.assertRaisesRegex(ValueError, "archive_hash_changed"):
            verifier.verify(run, corpus=self.corpus)
        run = self.copy_run()
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            current = Path(temporary) / "current_project"
            shutil.copytree(run / "implementation", current)
            source = current / "memory_migration_study/policy_semantics.py"
            source.write_bytes(source.read_bytes()+b"\n# later development change\n")
            receipt = verifier.verify(run, corpus=self.corpus, project_root=current)
            self.assertEqual(receipt["status"], "passed")
            self.assertFalse(receipt["current_snapshot_identical"])


class ArchivedSchemaContractTests(unittest.TestCase):
    def source(self, directory, schema):
        path = Path(directory) / "literal_schema.py"
        path.write_text("ROLES = ('value', 'generic_role', 'field_label', 'other', 'uncertain')\n"
            "def _schema(cids, maximum):\n    return "+repr(schema)+"\n", encoding="utf-8")
        return path

    def test_both_exact_versions_and_mixed_schema_rejected_without_execution(self):
        roles = ["value", "generic_role", "field_label", "other", "uncertain"]
        cid = {"type": "string", "enum": ["C0001"]}
        common = {"type": "object", "additionalProperties": False, "required": ["cid", "role", "quote"]}
        legacy_item = dict(common, properties={"cid": cid, "role": {"type": "string", "enum": roles},
            "quote": {"type": ["string", "null"], "minLength": 1, "maxLength": 64}})
        value = dict(common, properties={"cid": cid, "role": {"type": "string", "enum": ["value"]},
            "quote": {"type": "string", "minLength": 1, "maxLength": 64}})
        nonvalue = dict(common, properties={"cid": cid, "role": {"type": "string", "enum": roles[1:]}, "quote": {"type": "null"}})
        outer = {"type": "object", "additionalProperties": False, "required": ["verdicts"],
            "properties": {"verdicts": {"type": "array", "minItems": 1, "maxItems": 1}}}
        with tempfile.TemporaryDirectory() as temporary:
            for version, item in (("policy_semantic_transfer_development_v1", legacy_item),
                                  ("policy_semantic_transfer_development_v2", {"anyOf": [value, nonvalue]})):
                schema = deepcopy(outer)
                schema["properties"]["verdicts"]["items"] = item
                path = self.source(temporary, schema)
                self.assertEqual(verifier.expected_semantic_schema(path, version, ["C0001"], 64), schema)
            schema["properties"]["verdicts"]["items"]["properties"] = legacy_item["properties"]
            path = self.source(temporary, schema)
            with self.assertRaisesRegex(ValueError, "archived_semantic_schema_contract"):
                verifier.expected_semantic_schema(path, version, ["C0001"], 64)
            marker = Path(temporary) / "must_not_exist"
            path.write_text("ROLES = "+repr(tuple(roles))+"\ndef _schema(cids, maximum):\n"
                "    return __import__('pathlib').Path("+repr(str(marker))+").write_text('executed')\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "nonliteral_archived_schema_expression"):
                verifier.expected_semantic_schema(path, version, ["C0001"], 64)
            self.assertFalse(marker.exists())

    def test_forged_success_nonvalue_string_is_rejected_by_host_contract(self):
        candidate = {"cid": "C0001", "source": "S1", "start": 0, "end": 8, "category": "CUSTOMER"}
        verdict = {"cid": "C0001", "role": "generic_role", "quote": "Acme Ltd"}
        raw = {"verdicts": [verdict]}
        receipt = {"status": "semantics_only", "verdicts": [deepcopy(verdict)],
            "grounded_verdicts": [{**verdict, "source_id": "memory", "start": 0, "end": 8, "category": "CUSTOMER"}]}
        with self.assertRaisesRegex(ValueError, "semantic_nonvalue_changed_span"):
            verifier.verify_grounded_verdicts(raw, receipt, [candidate], {"S1": "memory"}, {"memory": "Acme Ltd"})
        verdict["quote"] = None
        receipt["verdicts"] = [deepcopy(verdict)]
        receipt["grounded_verdicts"][0]["quote"] = None
        verifier.verify_grounded_verdicts(raw, receipt, [candidate], {"S1": "memory"}, {"memory": "Acme Ltd"})


if __name__ == "__main__":
    unittest.main()
