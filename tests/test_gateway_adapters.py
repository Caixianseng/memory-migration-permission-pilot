"""Offline adapter contracts; prepared tests, no commercial clients required."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from agent_memory_gateway.adapters import (
    AdapterError, CONTEXT_SCHEMA, EXPORT_SCHEMA, export_receiver_context,
    import_memory_export, load_memory_export,
)
from agent_memory_gateway.service import GatewayService


class GatewayAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def document(self, source="workbuddy", target="deepseek_harness"):
        return {"schema": EXPORT_SCHEMA, "source_platform": source, "target_platform": target,
                "model": "declared-test-model", "sources": [
                    {"source_id": "S1", "text": "Synthetic project completes in December.",
                     "source_type": "controlled_fixture", "version": 1}],
                "memories": [{"memory_id": "M1", "content": "The project completes in December.",
                              "source_ids": ["S1"]}]}

    def write(self, document, name="export.json"):
        path = self.root/name
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return path

    def test_both_platform_directions_use_existing_service(self):
        for source, target in [("workbuddy", "deepseek_harness"), ("deepseek_harness", "workbuddy")]:
            with self.subTest(source=source):
                service = GatewayService(self.root/source)
                path = self.write(self.document(source, target), source+".json")
                imported = import_memory_export(service, path, sender_id="sender")
                self.assertEqual(imported["new_model_calls"], 0)
                self.assertFalse(imported["supplier_metadata_verified"])
                self.assertFalse(imported["persistent_delivery_performed"])
                self.assertEqual(service.get_permissions("receiver")["allowed_source_ids"], [])
                service.set_permissions("receiver", ["S1"])
                transfer = service.prepare_transfer("sender", "receiver", imported["memory_keys"], batch_id="batch")
                service.commit_transfer(transfer["transfer_id"])
                output = self.root/(source+"-context.json")
                receipt = export_receiver_context(service, recipient_id="receiver", batch_id="batch", output=output,
                                                  source_platform=source, target_platform=target)
                context = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(context["schema"], CONTEXT_SCHEMA)
                self.assertIn("December", context["memory"])
                self.assertNotIn("query_receipt", context)
                self.assertFalse(receipt["native_memory_imported"])
                self.assertEqual(receipt["new_model_calls"], 0)

    def test_source_metadata_is_stable_and_file_evidence_is_memory_scoped(self):
        service = GatewayService(self.root/"gateway")
        path = self.write(self.document())
        receipt = import_memory_export(service, path, sender_id="sender")
        agent = service._open_agent("sender")
        try:
            metadata = json.loads(agent.originals()[0]["metadata_json"])
            provenance = agent.get_memory("M1")["provenance"]
        finally:
            agent.close()
        self.assertEqual(metadata, {"source_type": "controlled_fixture",
                                    "registered_by": "explicit-json-export-adapter-v1"})
        self.assertEqual(provenance["evidence_hash"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(receipt["source_platform"], "workbuddy")
        self.assertEqual(receipt["claimed_model"], "declared-test-model")
        self.assertFalse(receipt["supplier_metadata_verified"])

    def test_new_derived_export_reuses_unchanged_original(self):
        """Normal initial/rebuild exports, not an additional fault scenario."""
        service = GatewayService(self.root/"gateway")
        first_path = self.write(self.document(), "initial.json")
        first = import_memory_export(service, first_path, sender_id="sender")
        rebuilt = self.document()
        rebuilt["model"] = "another-declared-model"
        rebuilt["memories"] = [{"memory_id": "M2", "content": "Completion month is December.",
                                 "source_ids": ["S1"]}]
        second_path = self.write(rebuilt, "legal-rebuild.json")
        second = import_memory_export(service, second_path, sender_id="sender")
        self.assertNotEqual(first["export_sha256"], second["export_sha256"])
        agent = service._open_agent("sender")
        try:
            self.assertEqual(len(agent.originals()), 1)
            original_metadata = json.loads(agent.originals()[0]["metadata_json"])
            initial_provenance = agent.get_memory("M1")["provenance"]
            rebuilt_provenance = agent.get_memory("M2")["provenance"]
        finally:
            agent.close()
        self.assertEqual(original_metadata, {"source_type": "controlled_fixture",
                                             "registered_by": "explicit-json-export-adapter-v1"})
        self.assertEqual(initial_provenance["evidence_hash"], first["export_sha256"])
        self.assertEqual(rebuilt_provenance["evidence_hash"], second["export_sha256"])
        self.assertNotEqual(initial_provenance["provided_provenance_sha256"],
                            rebuilt_provenance["provided_provenance_sha256"])
        self.assertEqual(service.get_permissions("receiver")["allowed_source_ids"], [])

    def test_invalid_later_memory_has_no_earlier_registration_effect(self):
        document = self.document()
        document["memories"].append({"memory_id": "M2", "content": "Unsupported assertion.", "source_ids": ["UNREGISTERED"]})
        service = Mock()
        with self.assertRaisesRegex(AdapterError, "export_source_outside_manifest"):
            import_memory_export(service, self.write(document), sender_id="sender")
        service.register_source.assert_not_called()
        service.create_memory.assert_not_called()

    def test_duplicate_json_key_rejected_without_side_effect(self):
        path = self.root/"duplicate.json"
        path.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
        service = Mock()
        with self.assertRaisesRegex(AdapterError, "duplicate_export_json_key"):
            import_memory_export(service, path, sender_id="sender")
        service.register_source.assert_not_called()

    def test_expected_platform_is_not_inferred_or_silently_changed(self):
        with self.assertRaisesRegex(AdapterError, "export_expected_platform_mismatch"):
            load_memory_export(self.write(self.document()), expected_source_platform="deepseek_harness")

    def test_credential_or_verification_metadata_is_not_an_import_contract(self):
        document = self.document()
        document["supplier_verified"] = True
        with self.assertRaisesRegex(AdapterError, "export_object_schema_invalid"):
            load_memory_export(self.write(document))

    def test_private_client_directory_is_not_a_source(self):
        private = self.root/"sdk.private"
        private.mkdir()
        path = private/"export.json"
        path.write_text(json.dumps(self.document()), encoding="utf-8")
        with self.assertRaisesRegex(AdapterError, "adapter_private_directory_forbidden"):
            load_memory_export(path)

    def test_context_export_never_overwrites_existing_output(self):
        output = self.root/"context.json"
        output.write_text("original", encoding="utf-8")
        service = Mock()
        service.retrieve_batch.return_value = {"memory": "Legal committed text."}
        with self.assertRaises(FileExistsError):
            export_receiver_context(service, recipient_id="receiver", batch_id="batch", output=output,
                                    source_platform="workbuddy", target_platform="deepseek_harness")
        self.assertEqual(output.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()
