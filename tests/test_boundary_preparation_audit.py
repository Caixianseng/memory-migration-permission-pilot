"""Tiny authored audit fixtures; never invokes detectors, LLMs or real corpora."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.privacy import detect_sensitive
from scripts import run_boundary_preparation_audit as audit


class BoundaryPreparationAuditTests(unittest.TestCase):
    def fixture(self, root):
        source, evaluation = root/"frozen", root/"evaluation.json"
        source.mkdir()
        runtime = [{"case_id": identity, "language": language, "template_family": "authored-"+identity,
            "policy": {"version": "audit-test", "protected_categories": categories},
            "payload": {"query": "", "memories": [{"source_id": "m", "text": text}]}}
            for identity, language, text, categories in (("ok", "en", "Customer: Larch Works", ["CUSTOMER"]),
                ("failed", "en", "Customer: Meadow Works", ["CUSTOMER"]), ("public", "zh", "状态：正常", []))]
        rows, gold = [], {}
        for case in runtime:
            text = case["payload"]["memories"][0]["text"]
            quote = {"ok": "Larch Works", "failed": "Meadow Works"}.get(case["case_id"])
            findings = [] if quote is None else [{"source_id": "m", "start": text.index(quote),
                "end": text.index(quote)+len(quote), "category": "CUSTOMER"}]
            gold[case["case_id"]] = {"findings": findings}
            def instrument(**kwargs):
                return {"status": "ok", "local_calls": 0, "errors": [], "elapsed_seconds": 0.0,
                    "findings": [{"quote": text[item["start"]:item["end"]], **{key: item[key]
                        for key in ("start", "end", "category")}} for item in findings]}
            detection = detect_sensitive(case["payload"], case["policy"], mode="agent", agent=instrument)
            if case["case_id"] == "failed":
                detection.update(status="needs_review", errors=["instrumented_failure"])
            rows.append({"case_id": case["case_id"], "arm": "boundary_refined", "detection": detection})
        for name, value in (("runtime.json", runtime), ("rows.json", rows), ("report.json", {"material_count": 3})):
            (source/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        evaluation.write_text(json.dumps(gold, ensure_ascii=False, indent=3)+"\n", encoding="utf-8")
        return source, evaluation, runtime, gold

    def assert_denominators(self, report):
        self.assertEqual(report["material_count"], 3)
        for arm in audit.ARMS:
            summary = report["arms"][arm]
            self.assertEqual(summary["registered_materials"], 3)
            self.assertEqual(summary["gold_spans"], 2)
            self.assertEqual(summary["fully_masked_spans"], 1)
            self.assertEqual(summary["unmasked_or_not_ready_spans"], 1)
            self.assertEqual(summary["detection_non_ok"], 1)
            self.assertEqual(summary["ready"], 2)
        self.assertEqual(report["new_inference_counts"], {"local_encoder": 0, "local_generation": 0, "unknown": 0})
        self.assertEqual(report["cloud_calls"], 0)
        self.assertEqual(report["overall_effectiveness_acceptance"], "not_established")
        self.assertTrue(report["source_unchanged"])
        self.assertFalse(report["mapping_persisted"])

    def test_real_old_new_preparation_fake_materials_gold_last_and_no_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, evaluation, _, _ = self.fixture(root)
            output, before = root/"audit", audit.source_hashes(source)
            gold_text = evaluation.read_text(encoding="utf-8")
            real_loads, observations = json.loads, []
            def guarded_loads(value, *args, **kwargs):
                if value == gold_text:
                    rows = real_loads((output/"rows.json").read_text(encoding="utf-8"))
                    self.assertEqual(len(rows), 6)
                    self.assertTrue(all("mask_footprint" in row for row in rows))
                    self.assertTrue((output/"witnesses.json").is_file())
                    self.assertTrue(all("mask_score" not in row for row in rows))
                    observations.append("labels_last")
                return real_loads(value, *args, **kwargs)
            with patch.object(audit.json, "loads", side_effect=guarded_loads), \
                 patch("socket.socket.connect", side_effect=AssertionError("network_forbidden")) as network, \
                 patch("memory_migration_study.ner_detector.LocalNerRuntime", side_effect=AssertionError("no_model")) as model:
                report = audit.run(source, output, evaluation_path=evaluation, expected_materials=3)
            model.assert_not_called()
            network.assert_not_called()
            self.assertEqual(observations, ["labels_last"])
            self.assert_denominators(report)
            self.assertEqual(audit.source_hashes(source), before)
            rows = real_loads((output/"rows.json").read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 6)
            for row in rows:
                if row["case_id"] == "ok":
                    self.assertEqual(row["mask_footprint"]["m"], [[10, 21]])
                    self.assertNotIn("Larch Works", row["prepared_payload"]["memories"][0]["text"])
                if row["case_id"] == "failed":
                    self.assertFalse(row["mask_score"]["ready"])
            serialized = (output/"rows.json").read_text(encoding="utf-8")+(output/"witnesses.json").read_text(encoding="utf-8")
            for forbidden in ('"mapping"', '"_entries"', '"_nonce"', '"entries"'):
                self.assertNotIn(forbidden, serialized)

    def test_authored_witnesses_distinguish_key_only_from_real_sources(self):
        with patch("socket.socket.connect", side_effect=AssertionError("network_forbidden")):
            witnesses = audit.witness_suite(audit.preparation_functions())
        self.assertEqual(len(witnesses["rows"]), 6)
        self.assertTrue(witnesses["legacy_query_key_only_allowed"])
        self.assertTrue(witnesses["boundary_expectations_met"], witnesses)
        index = {(row["case_id"], row["arm"]): row for row in witnesses["rows"]}
        blocked = index[("query_key_only", "boundary_prepare")]["observations"]["initial"]
        self.assertEqual(blocked["status"], "blocked")
        self.assertIsNone(blocked["answer_sha256"])
        for case in ("same_name_real_value", "independent_real_source"):
            self.assertEqual(index[(case, "boundary_prepare")]["observations"]["initial"]["status"], "ok")
        independent = index[("independent_real_source", "boundary_prepare")]["observations"]
        self.assertEqual(independent["key_only_source_revoked"]["status"], "ok")
        self.assertEqual(independent["real_source_revoked"]["status"], "blocked")
        self.assertTrue(all(row["expected_observations_met"] for row in witnesses["rows"]))

    def test_instrumentation_failure_keeps_every_sensitive_span_in_denominator(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, evaluation, _, _ = self.fixture(root)
            with patch.object(audit, "masking_intervals", side_effect=ValueError("instrumented_alignment_failure")):
                report = audit.run(source, root/"audit", evaluation_path=evaluation, expected_materials=3)
            for arm in audit.ARMS:
                self.assertEqual(report["arms"][arm]["registered_materials"], 3)
                self.assertEqual(report["arms"][arm]["gold_spans"], 2)
                self.assertEqual(report["arms"][arm]["unmasked_or_not_ready_spans"], 2)
                self.assertEqual(report["arms"][arm]["ready"], 0)
                self.assertEqual(report["arms"][arm]["instrumentation_errors"], 2)

    def test_preparation_exception_is_a_failed_row_not_a_dropped_material(self):
        functions = audit.preparation_functions()
        real_prepare = functions["boundary_prepare"]
        def broken_one(payload, detection, **kwargs):
            if payload["memories"][0]["text"] == "Customer: Larch Works":
                raise RuntimeError("raw_source_should_not_enter_error_logs")
            return real_prepare(payload, detection, **kwargs)
        functions["boundary_prepare"] = broken_one
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, evaluation, _, _ = self.fixture(root)
            with patch.object(audit, "preparation_functions", return_value=functions):
                report = audit.run(source, root/"audit", evaluation_path=evaluation, expected_materials=3)
            metrics = report["arms"]["boundary_prepare"]
            self.assertEqual(metrics["registered_materials"], 3)
            self.assertEqual(metrics["gold_spans"], 2)
            self.assertEqual(metrics["unmasked_or_not_ready_spans"], 2)
            self.assertEqual(metrics["preparation_exceptions"], 1)
            raw = (root/"audit"/"rows.json").read_text(encoding="utf-8")
            self.assertNotIn("raw_source_should_not_enter_error_logs", raw)

    def test_missing_duplicate_or_wrong_count_never_filters_materials(self):
        for error in ("count", "missing", "duplicate", "runtime_gold"):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source, evaluation, runtime, _ = self.fixture(root)
                if error in {"missing", "duplicate"}:
                    rows = json.loads((source/"rows.json").read_text(encoding="utf-8"))
                    rows = rows[:-1] if error == "missing" else rows+[copy.deepcopy(rows[0])]
                    (source/"rows.json").write_text(json.dumps(rows), encoding="utf-8")
                if error == "runtime_gold":
                    runtime[0]["expected_answer"] = "not_a_runtime_field"
                    (source/"runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
                with self.assertRaises(ValueError):
                    audit.run(source, root/"audit", evaluation_path=evaluation,
                              expected_materials=80 if error == "count" else 3)
                self.assertFalse((root/"audit").exists())

    def test_output_cannot_modify_source_and_runtime_must_match_frozen_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, evaluation, runtime, _ = self.fixture(root)
            before = audit.source_hashes(source)
            with self.assertRaises(ValueError):
                audit.run(source, source/"forbidden", evaluation_path=evaluation, expected_materials=3)
            self.assertEqual(audit.source_hashes(source), before)
            runtime[0]["payload"]["query"] = "changed"
            alternate = root/"runtime.json"
            alternate.write_text(json.dumps(runtime), encoding="utf-8")
            with self.assertRaises(ValueError):
                audit.run(source, root/"audit", runtime_path=alternate, evaluation_path=evaluation, expected_materials=3)

    def test_invalid_empty_or_duplicate_reference_spans_are_rejected_after_preparation(self):
        for change in ("empty", "duplicate", "wrong_source"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source, evaluation, _, gold = self.fixture(root)
                if change == "empty":
                    gold["ok"]["findings"][0]["end"] = gold["ok"]["findings"][0]["start"]
                elif change == "duplicate":
                    gold["ok"]["findings"] *= 2
                else:
                    gold["ok"]["findings"][0]["source_id"] = "unknown"
                evaluation.write_text(json.dumps(gold), encoding="utf-8")
                with self.assertRaises(ValueError):
                    audit.run(source, root/"audit", evaluation_path=evaluation, expected_materials=3)
                rows = json.loads((root/"audit"/"rows.json").read_text(encoding="utf-8"))
                self.assertEqual(len(rows), 6)
                self.assertTrue(all("mask_score" not in row for row in rows))
                self.assertFalse((root/"audit"/"report.json").exists())


if __name__ == "__main__":
    unittest.main()
