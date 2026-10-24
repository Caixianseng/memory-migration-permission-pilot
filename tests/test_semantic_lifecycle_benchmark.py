import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_semantic_lifecycle_benchmark as lifecycle


class Runtime:
    identity = {"model_id": "test-encoder", "weights_sha256": "0"*64}
    initialization_seconds = 0.0

    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def infer(self, text, labels, **kwargs):
        self.calls.append((text, copy.deepcopy(labels)))
        if self.fail:
            raise RuntimeError("injected failure")
        entities = {key: [] for key in labels}
        value = "Stone Vale Ltd."
        if value in text and "organization" in entities:
            start = text.index(value)
            entities["organization"].append({"text": value, "start": start, "end": start+len(value), "confidence": .99})
        return {"entities": entities}


def story():
    return {"story_id": "tiny-independent-fixture", "source": {"source_id": "fixture-source", "text": "Customer: Stone Vale Ltd.; Status: cleared."},
            "language": "en", "policy": {"version": "1", "protected_categories": ["CUSTOMER"]},
            "tasks": [{"task_id": "status", "actor_id": "owner", "query": "What is the status?"},
                      {"task_id": "denied", "actor_id": "outsider", "query": "Who is the customer?"}]}


class ActualLifecycleBenchmarkTests(unittest.TestCase):
    def run_fixture(self, *, fail=False, repetitions=(1, 3, 10)):
        runtime = Runtime(fail)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"corpus/development").mkdir(parents=True)
            (root/"corpus/development/runtime.json").write_text(json.dumps([story()]), encoding="utf-8")
            # No evaluation or heldout file exists. Reading either would fail.
            with patch.object(lifecycle, "LocalNerRuntime", return_value=runtime):
                report = lifecycle.run(root/"corpus", root/"output", "never-load-assets", repetitions=repetitions)
            files = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in (root/"output").glob("*.json")}
            self.assertTrue((root/"output/index.html").is_file())
            self.assertTrue((root/"output/executed_lifecycle_script.py").is_file())
            return report, files, runtime

    def test_actual_one_three_ten_transfers_include_setup_and_correct_cache_baseline(self):
        report, files, runtime = self.run_fixture()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["cells"]), 12)
        self.assertEqual(report["registered_preparations"], 56)
        self.assertEqual(report["executed_preparations"], 56)
        self.assertEqual(report["setup_encoder_calls"], 6)
        self.assertEqual(report["migration_encoder_calls"], 51)
        self.assertEqual(report["total_physical_encoder_calls"], len(runtime.calls))
        self.assertEqual(len(runtime.calls), 64)
        for cell in report["cells"]:
            n, arm = cell["requested_repetitions"], cell["arm"]
            self.assertEqual(len(cell["rows"]), n)
            self.assertEqual(cell["ready_transfers"], n)
            self.assertEqual(cell["prepare_calls_executed"], n)
            self.assertEqual(cell["setup_encoder_calls"], int(arm.startswith("generation")))
            expected = (1 if arm.startswith("generation") else 2) if arm.endswith("_cached") else n*(1 if arm.startswith("generation") else 2)
            self.assertEqual(cell["migration_encoder_calls"], expected)
            self.assertEqual(cell["total_physical_encoder_calls"], cell["setup_encoder_calls"]+expected)
            self.assertEqual(cell["cache_hits"], (n-1)*(1 if arm.startswith("generation") else 2) if arm.endswith("_cached") else 0)
            hashes = [value for row in cell["rows"] for value in row["token_sha256"]]
            self.assertEqual(len(hashes), len(set(hashes)))
            self.assertTrue(all(row["token_freshness_checked"] and row["reused_tokens"] == 0 for row in cell["rows"]))
            self.assertTrue(all(row["restore_probe"]["status"] == "ok" for row in cell["rows"]))
        self.assertEqual(report["model_answer_calls"], 0)
        self.assertEqual(report["cloud_calls"], 0)
        self.assertEqual(files["report.json"], report)

    def test_dynamic_changes_fallback_and_revocation_do_not_disable_independent_new_grants(self):
        report, _, _ = self.run_fixture(repetitions=(1,))
        dynamic = report["dynamic"]
        self.assertEqual(dynamic["status"], "passed")
        witnesses = {row["witness"]: row for row in dynamic["witnesses"]}
        self.assertEqual(set(witnesses), {"same_version_policy_change", "removed_label", "revoke_before_restore",
                                         "old_request_replay_after_revoke", "new_independent_grant"})
        self.assertTrue(all(row["passed"] for row in witnesses.values()))
        self.assertEqual(witnesses["same_version_policy_change"]["label_checks"][0]["fallback_reason"], "label_policy_changed")
        self.assertEqual(witnesses["removed_label"]["label_checks"][0]["fallback_reason"], "label_missing")
        revoked = witnesses["revoke_before_restore"]
        self.assertEqual(revoked["before_probe"]["status"], "ok")
        self.assertEqual(revoked["after_probe"]["error"], "grant_revoked")
        self.assertEqual(witnesses["old_request_replay_after_revoke"]["encoder_calls"], 0)
        self.assertEqual(witnesses["new_independent_grant"]["restore_probe"]["status"], "ok")

    def test_failure_is_not_cached_or_counted_as_a_completed_transfer(self):
        report, _, runtime = self.run_fixture(fail=True, repetitions=(3,))
        self.assertEqual(report["status"], "completed_with_failures")
        cells = {c["arm"]: c for c in report["cells"]}
        self.assertEqual(cells["migration"]["migration_encoder_calls"], 6)
        self.assertEqual(cells["migration_cached"]["migration_encoder_calls"], 6)
        self.assertEqual(cells["migration_cached"]["cache_hits"], 0)
        self.assertEqual(cells["generation"]["prepare_calls_executed"], 0)
        self.assertEqual(cells["generation_cached"]["prepare_calls_executed"], 0)
        self.assertEqual(report["dynamic"]["status"], "incomplete")
        self.assertEqual(report["total_physical_encoder_calls"], len(runtime.calls))
        self.assertTrue(all(c["ready_transfers"] == 0 for c in cells.values()))

    def test_receipts_do_not_serialize_maps_keys_tokens_or_restored_values(self):
        report, files, _ = self.run_fixture(repetitions=(1,))
        public_receipt = json.dumps({"report": report, "cells": files["cells.json"], "dynamic": files["dynamic.json"]})
        self.assertNotIn("[PVT_", public_receipt)
        self.assertNotIn("Stone Vale", public_receipt)
        self.assertNotIn('"mapping"', public_receipt)
        self.assertNotIn('"secret"', public_receipt)
        self.assertNotIn('"answer"', public_receipt)
        self.assertEqual(files["plan.json"]["split"], "development")
        self.assertIn("script_sha256", files["plan.json"])
        self.assertIn("implementation_sha256", files["plan.json"])

    def test_network_guard_blocks_external_and_permits_only_literal_loopback(self):
        counts, callback = lifecycle.network_audit()
        callback("socket.connect", (None, ("127.0.0.1", 11435)))
        callback("socket.connect", (None, ("::1", 11435, 0, 0)))
        for address in (("api.example.test", 443), ("localhost", 80), ("192.0.2.3", 443)):
            with self.assertRaises(RuntimeError):
                callback("socket.connect", (None, address))
        self.assertEqual(counts, {"loopback_connections": 2, "external_attempts_blocked": 3})

    def test_invalid_repetition_budget_rejected_without_loading_models(self):
        for repetitions in ((), (0,), (11,), (True,), (1, 1)):
            with self.assertRaises(ValueError):
                lifecycle.run("missing-corpus", "unused-output", "no-assets", repetitions=repetitions)

    def test_measured_timing_components_reconcile_without_latency_targets(self):
        report, files, _ = self.run_fixture(repetitions=(1, 3))
        for cell in report["cells"]:
            self.assertAlmostEqual(cell["prepare_wall_seconds"], sum(r["prepare_wall_seconds"] for r in cell["rows"]), places=9)
            self.assertAlmostEqual(cell["restore_instrument_wall_seconds"],
                                   sum(r["restore_probe"]["restore_wall_seconds"] for r in cell["rows"]), places=9)
            components = ("setup_wall_seconds", "prepare_wall_seconds", "restore_instrument_wall_seconds",
                          "iteration_instrumentation_wall_seconds", "cell_framework_wall_seconds")
            self.assertTrue(all(cell[key] >= 0 for key in components))
            self.assertAlmostEqual(cell["cell_wall_seconds"], sum(cell[key] for key in components), places=9)
            for row in cell["rows"]:
                self.assertAlmostEqual(row["iteration_wall_seconds"], row["prepare_wall_seconds"]
                    +row["restore_probe"]["restore_wall_seconds"]+row["instrumentation_wall_seconds"], places=9)
                self.assertTrue(row["restore_probe"]["restore_executed"])
        dynamic = report["dynamic"]
        self.assertAlmostEqual(dynamic["witnesses_wall_seconds"], sum(w["witness_wall_seconds"] for w in dynamic["witnesses"]), places=9)
        self.assertAlmostEqual(dynamic["dynamic_wall_seconds"], dynamic["setup_wall_seconds"]
                              +dynamic["witnesses_wall_seconds"]+dynamic["dynamic_framework_wall_seconds"], places=9)
        for witness in dynamic["witnesses"]:
            self.assertAlmostEqual(witness["witness_wall_seconds"], witness["prepare_wall_seconds"]
                +witness["restore_instrument_wall_seconds"]+witness["revoke_wall_seconds"]
                +witness["witness_framework_wall_seconds"], places=9)
        self.assertAlmostEqual(report["cells_wall_seconds"], sum(c["cell_wall_seconds"] for c in report["cells"]), places=9)
        total_parts = ("model_loading_and_asset_validation_wall_seconds", "cells_wall_seconds",
                       "dynamic_wall_seconds", "run_framework_and_intermediate_io_wall_seconds")
        self.assertTrue(all(report[key] >= 0 for key in total_parts))
        self.assertAlmostEqual(report["run_measured_wall_seconds"], sum(report[key] for key in total_parts), places=9)
        self.assertEqual(files["runtime_identity.json"]["model_loading_and_asset_validation_wall_seconds"],
                         report["model_loading_and_asset_validation_wall_seconds"])


if __name__ == "__main__":
    unittest.main()
