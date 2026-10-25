"""Independent verifier regressions from real-pipeline, fake transport artifacts."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_generation_union_transfer as verifier
from tests import test_generation_union_transfer as authored
from memory_migration_study.local_detector import DIGEST, MODEL, VERSION


class GenerationUnionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.positive, cls.failure = cls.root/"positive", cls.root/"failure"
        actual_run = authored.harness.run
        def configured_run(corpus, output, model_root, config, observer, **kwargs):
            # Pin the real configuration via the existing producer input seam;
            # fake callback/model identity is never relabelled as measurements.
            pinned = {"endpoint": "http://127.0.0.1:11435", "model": MODEL, "expected_version": VERSION,
                      "expected_digest": DIGEST, "timeout_seconds": 120}
            return actual_run(corpus, output, model_root, pinned, observer, **kwargs)
        with patch.object(authored.harness, "run", side_effect=configured_run):
            authored.GenerationUnionTransferTests().run_authored(root=cls.positive)
            authored.GenerationUnionTransferTests().run_authored(root=cls.failure, annotation_failure=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy_positive(self):
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        destination = Path(temporary.name)/"output"
        shutil.copytree(self.positive/"output", destination)
        return destination

    def mutate(self, output, name, callback):
        path = output/(name+".json")
        value = json.loads(path.read_bytes())
        callback(value)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def verify(self, output):
        return verifier.verify(output, corpus=self.positive/"corpus")

    def test_full_pipeline_evidence_and_physical_shared_cost_partition(self):
        receipt = self.verify(self.positive/"output")
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual((receipt["registered_rows"], receipt["annotation_facts_checked"]), (160, 9))
        self.assertEqual(receipt["physical_generation_attempts"], 186)
        self.assertEqual(receipt["verification_model_calls"], 0)
        for metrics in receipt["arms"].values():
            self.assertEqual((metrics["legal_tasks"], metrics["correct"], metrics["outsider_blocked"]), (32, 32, 8))
        self.assertEqual(sum(c["physical_calls"] for c in receipt["physical_costs"]), 186)
        self.assertEqual(sum(c["physical_calls"] for c in receipt["physical_costs"] if c["stage"] == "build"), 8)

    def test_failed_annotation_keeps_full_denominators_and_never_becomes_clean_empty_label(self):
        receipt = verifier.verify(self.failure/"output", corpus=self.failure/"corpus")
        self.assertEqual(receipt["status"], "passed")
        for arm in ("G", "T"):
            self.assertEqual((receipt["arms"][arm]["legal_tasks"], receipt["arms"][arm]["build_block"],
                              receipt["arms"][arm]["outsider_blocked"]), (32, 32, 0))
        for arm in ("M", "U"):
            self.assertEqual(receipt["arms"][arm]["correct"], 32)

    def test_missing_matrix_row_and_shared_cost_double_charge_fail(self):
        output = self.copy_positive()
        self.mutate(output, "rows", lambda rows: rows.pop())
        with self.assertRaisesRegex(ValueError, "task_matrix_denominator"):
            self.verify(output)
        output = self.copy_positive()
        self.mutate(output, "report", lambda report: report.__setitem__("builder_generations", 16))
        with self.assertRaisesRegex(ValueError, "report_total_builder_generations"):
            self.verify(output)

    def test_actual_ner_seed_cannot_disappear_from_clean_union_annotation(self):
        output = self.copy_positive()
        def drop_seed(annotations):
            record = next(a for a in annotations if any(f["category"] == "CUSTOMER" for m in a["member_raw_outputs"] for f in m["response"]["findings"]))
            record["detection"]["findings"] = [f for f in record["detection"]["findings"] if f["category"] != "CUSTOMER"]
        self.mutate(output, "annotations", drop_seed)
        with self.assertRaisesRegex(ValueError, "seed_or_registry_closure_dropped"):
            self.verify(output)

    def test_source_binding_or_cross_family_record_swap_is_rejected(self):
        output = self.copy_positive()
        self.mutate(output, "fact_bindings", lambda bindings: bindings[0].__setitem__("source_end", bindings[0]["source_end"]-1))
        with self.assertRaisesRegex(ValueError, "fact_source_identity"):
            self.verify(output)
        output = self.copy_positive()
        def swap(events):
            start = next(e for e in events if e["kind"] == "prepare_start" and e["arm"] == "G")
            stores = json.loads((output/"record_store.json").read_bytes())
            ner = next(s["records"] for s in stores if s["story_id"] == start["story_id"] and s["builder"] == "ner")
            start["record_ids"] = [r["record_id"] for r in ner]
            start["record_set_sha256"] = verifier.digest(ner)
        self.mutate(output, "auth_events", swap)
        with self.assertRaisesRegex(ValueError, "auth_selected_record_set"):
            self.verify(output)


class ClosureCoverageTests(unittest.TestCase):
    def test_registry_and_ascii_boundary_repeat_obligations(self):
        sources = {"m": "Acme AcmeX camera", "__query__": "ACME"}
        policy = {"protected_categories": ["CUSTOMER"], "policy_id": "p", "entity_registry": [{"value": "Acme", "category": "CUSTOMER"}]}
        detection = {"findings": [{"source_id": sid, "start": a, "end": b, "category": "CUSTOMER", "policy_id": "p"}
            for sid, a, b in (("m", 0, 4), ("m", 5, 10), ("__query__", 0, 4))]}
        verifier.verify_coverage(detection, sources, [("m", 0, 4, "CUSTOMER")], policy)
        changed = deepcopy(detection)
        changed["findings"].pop()
        with self.assertRaisesRegex(ValueError, "seed_or_registry_closure_dropped"):
            verifier.verify_coverage(changed, sources, [("m", 0, 4, "CUSTOMER")], policy)


if __name__ == "__main__":
    unittest.main()
