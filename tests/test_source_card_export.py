"""Pure fake-data checks; no model, credentials, or historical result dependency."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import export_source_card_artifact as exporter


class SourceCardExportTests(unittest.TestCase):
    def fixture(self):
        runtime = [{"story_id": "synthetic_" + str(i), "language": "en",
            "source": {"source_id": "synthetic_" + str(i), "text": "Customer: Fictional Example " + str(i)},
            "tasks": [{"task_id": "private", "query": "Which customer?"}]} for i in range(8)]
        evaluation = [{"story_id": s["story_id"], "synthetic": True} for s in runtime]
        store = [{"story_id": s["story_id"], "records": [{"source": dict(s["source"],
            sha256=exporter.sha(s["source"]["text"].encode())), "source_start": 0,
            "source_end": len(s["source"]["text"]), "text": s["source"]["text"]}]} for s in runtime]
        contexts = [{"story_id": s["story_id"], "task_id": "private", "original_query": "Which customer?"} for s in runtime]
        obj = {"runtime.json": runtime, "evaluation.json": evaluation, "record_store.json": store,
            "shared_contexts.json": contexts, "plan.json": {"missing_control": {"queries": {"en": "Which email?"}}},
            "independent_source_card_verification_v3.json": {"status": "passed", "verification_model_calls": 0,
                "checks": [{"check": "fake", "passed": True}]}}
        public = {"examples/privacy_semantics_v1/development/runtime.json": json.dumps(runtime).encode(),
            "examples/privacy_semantics_v1/development/evaluation.json": json.dumps(evaluation).encode()}
        return obj, public

    def test_exact_public_sources_queries_and_control(self):
        obj, public = self.fixture()
        obj["shared_contexts.json"].append({"story_id": "synthetic_0", "task_id": "missing_contact_email_control", "original_query": "Which email?"})
        exporter.validate_synthetic_binding(obj, public)
        for field, mutate in [
            ("record_store.json", lambda x: x[0]["records"][0]["source"].update(text="private canary")),
            ("record_store.json", lambda x: x[0]["records"][0].update(text="invented")),
            ("shared_contexts.json", lambda x: x[0].update(original_query="private canary")),
        ]:
            changed = copy.deepcopy(obj); mutate(changed[field])
            with self.assertRaises(ValueError): exporter.validate_synthetic_binding(changed, public)

    def test_receipt_cannot_claim_model_free_pass_with_failed_check(self):
        obj, public = self.fixture()
        for edit in [{"status": "failed"}, {"verification_model_calls": 1}, {"checks": [{"passed": False}]}, {"checks": []}]:
            changed = copy.deepcopy(obj); changed["independent_source_card_verification_v3.json"].update(edit)
            with self.assertRaises(ValueError): exporter.validate_synthetic_binding(changed, public)

    def test_private_objects_credentials_and_host_paths_blocked(self):
        for value in [{"mapping": []}, {"nested": [{"HMAC_KEY": "canary"}]},
            {"x": ("sk-" + "A" * 32)}, {"x": "C:\\Users\\private\\file"}, {"x": "/home/private/file"}]:
            with self.assertRaises(ValueError): exporter.inspect_json(value)
        exporter.inspect_json({"recovery_mapping_recorded": False, "label_signature": "0" * 64,
            "safe": "http://127.0.0.1:11435", "token": "[PVT_EXAMPLE]"})

    def test_byte_pin_bounds_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "one.json").write_bytes(b"{}")
            self.assertEqual(exporter.read_bound(root, "one.json", exporter.sha(b"{}")), b"{}")
            with self.assertRaises(ValueError): exporter.read_bound(root, "one.json", "0" * 64)
            for name in ["../one.json", "/one.json", "C:/one.json", "sub\\one.json"]:
                with self.assertRaises(ValueError): exporter.read_bound(root, name)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in [b'{"x":1,"x":2}', b'{"x":NaN}']:
            with self.assertRaises(ValueError): exporter.parse(data)


if __name__ == "__main__":
    unittest.main()
