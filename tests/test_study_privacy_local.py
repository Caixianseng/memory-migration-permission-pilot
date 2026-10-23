import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.privacy_local import run_local_privacy_check
import test_study_privacy_experiment as experiment_tests


class LocalPrivacyCheckTests(unittest.TestCase):
    def test_local_only_roundtrip_does_not_claim_task_accuracy_or_load_cloud(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = experiment_tests.PrivacyExperimentTests().fixture(root)
            with patch("memory_migration_study.privacy_local.load_snapshot_bundle", return_value=bundle), \
                 patch("memory_migration_study.budget.ChatCompletionsConnector.__init__", side_effect=AssertionError("no cloud")):
                report = run_local_privacy_check(snapshot_path=args["snapshot_path"], policy=args["policy"],
                       detector_config={}, output=root / "local", agent=experiment_tests.SafeLocalAgent(),
                       sensitivity_audit={"version": "independent", "values": [{"value": "customer@example.test", "category": "EMAIL"}]})
            self.assertEqual(report["registered_tasks"], 7)
            self.assertEqual(report["ready_tasks"], 7)
            self.assertEqual(report["registered_value_residual_requests"], 0)
            self.assertEqual(report["token_checks_total"], 4)
            self.assertEqual(report["token_checks_passed"], 4)
            self.assertEqual(report["remote_model_calls"], 0)
            self.assertIsNone(report["task_correctness"])
            self.assertNotIn('"mapping":', (root / "local/report.json").read_text())

    def test_uncertainty_does_not_turn_all_blocked_into_zero_leak_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = experiment_tests.PrivacyExperimentTests().fixture(root)
            with patch("memory_migration_study.privacy_local.load_snapshot_bundle", return_value=bundle):
                report = run_local_privacy_check(snapshot_path=args["snapshot_path"], policy=args["policy"],
                       detector_config={}, output=root / "local", agent=lambda **kw: {"status": "needs_review", "findings": []})
            self.assertEqual(report["blocked_tasks"], 7)
            self.assertEqual(report["audited_ready_tasks"], 0)
            self.assertEqual(report["token_checks_total"], 0)
            self.assertTrue(all(row["remaining_audit_values"] is None for row in report["rows"]))

    def test_egress_recheck_reuses_matching_detections_without_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = experiment_tests.PrivacyExperimentTests().fixture(root)
            with patch("memory_migration_study.privacy_local.load_snapshot_bundle", return_value=bundle):
                common = dict(snapshot_path=args["snapshot_path"], policy=args["policy"], detector_config={})
                run_local_privacy_check(**common, output=root / "initial", agent=experiment_tests.SafeLocalAgent())
                def forbidden(**kwargs):
                    raise AssertionError("Cached replay must not call the detector")
                replay = run_local_privacy_check(**common, output=root / "replay", agent=forbidden,
                                                 reuse_detection_report=root / "initial/report.json")
                self.assertEqual(replay["ready_tasks"], 7)
                self.assertEqual(replay["detector_execution"], "cached_only_no_new_detector_calls")
                self.assertIsNone(replay["registered_value_residual_requests"])
                common["policy"] = dict(args["policy"], version="changed")
                with self.assertRaisesRegex(ValueError, "stale_local_detection_report"):
                    run_local_privacy_check(**common, output=root / "stale", agent=forbidden,
                                             reuse_detection_report=root / "initial/report.json")

    def test_corrupt_cache_cannot_trigger_hidden_detector_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, args = experiment_tests.PrivacyExperimentTests().fixture(root)
            with patch("memory_migration_study.privacy_local.load_snapshot_bundle", return_value=bundle):
                common = dict(snapshot_path=args["snapshot_path"], policy=args["policy"], detector_config={})
                run_local_privacy_check(**common, output=root / "initial", agent=experiment_tests.SafeLocalAgent())
                path = root / "initial/report.json"
                original = json.loads(path.read_text())
                for index, damaged in enumerate((None, {}, {"status": "ok", "payload_sha256": "wrong"})):
                    report = json.loads(json.dumps(original))
                    report["rows"][0]["detection"] = damaged
                    path.write_text(json.dumps(report))
                    with self.subTest(damaged=damaged), self.assertRaisesRegex(ValueError, "invalid_cached_local_detection"):
                        run_local_privacy_check(**common, output=root / f"corrupt-{index}",
                                               agent=lambda **kw: self.fail("must not infer"), reuse_detection_report=path)


if __name__ == "__main__":
    unittest.main()
