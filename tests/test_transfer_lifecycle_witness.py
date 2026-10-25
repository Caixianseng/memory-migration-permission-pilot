import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_transfer_lifecycle_witness as witness


class TransferLifecycleWitnessTests(unittest.TestCase):
    def test_actual_standard_authority_outcomes_identical_for_both_pipelines(self):
        report = witness.run_witness()
        self.assertTrue(report["all_checks_passed"], report["checks"])
        self.assertEqual([arm["privacy_pipeline"] for arm in report["arms"]], ["legacy", "boundary"])
        self.assertEqual(report["new_inference_counts"], {"local_encoder": 0, "local_generation": 0, "unknown": 0})
        self.assertFalse(report["runtime"]["model_loaded"])
        self.assertEqual(report["runtime"]["remote_calls"], 0)
        for arm in report["arms"]:
            self.assertEqual(arm["zero_model_detector_invocations"], 0)
            self.assertTrue(arm["pre_revocation"]["restore"]["fact_matches"])
            self.assertEqual(arm["pre_revocation"]["transfer"]["egress_status"], "ok")

    def test_exactly_two_grants_issued_before_first_revocation_no_later_regrant(self):
        events = []
        original_build = witness.MemoryLabelAuthority.build_record
        original_revoke = witness.MemoryLabelAuthority.revoke
        def build(authority, *args, **kwargs):
            events.append("issue")
            return original_build(authority, *args, **kwargs)
        def revoke(authority, record_id):
            events.append("revoke")
            return original_revoke(authority, record_id)
        with patch.object(witness.MemoryLabelAuthority, "build_record", new=build), \
                patch.object(witness.MemoryLabelAuthority, "revoke", new=revoke):
            report = witness.run_witness()
        self.assertEqual(events[:2], ["issue", "issue"])
        self.assertEqual(events.count("issue"), 2)
        self.assertTrue(all(event == "revoke" for event in events[2:]))
        self.assertEqual([row["issued_at_step"] for row in report["grant_receipts"]], [1, 2])
        self.assertTrue(all(arm["both_grants_preexist_revocation"] for arm in report["arms"]))
        first, second = report["grant_receipts"]
        self.assertNotEqual(first["source_id"], second["source_id"])
        self.assertNotEqual(first["source_sha256"], second["source_sha256"])
        self.assertEqual(first["fact_sha256"], second["fact_sha256"])
        self.assertIn("not_inferred_from_text", report["fixture_independence"])

    def test_old_prepared_and_old_request_block_but_original_G2_fresh_context_succeeds(self):
        report = witness.run_witness()
        original_G2_hash = report["grant_receipts"][1]["grant_sha256"]
        for arm in report["arms"]:
            revoked = arm["record_G1_revocation"]
            self.assertEqual(revoked["old_prepared_restore"]["error"], "grant_revoked")
            self.assertEqual(revoked["old_request_replay"]["error"], "grant_revoked")
            self.assertEqual(revoked["old_request_replay"]["local_calls"], 0)
            self.assertEqual(revoked["selected_existing_grants"], ["G2"])
            self.assertTrue(revoked["fresh_context_restore"]["fact_matches"])
            retained = next(row for row in revoked["current_access_checks"] if row["alias"] == "G2")
            self.assertTrue(retained["allowed"])
            self.assertEqual(retained["original_grant_sha256"], original_G2_hash)
            self.assertEqual(revoked["fresh_context_transfer"]["access_check_count"], 1)

    def test_source_epoch_and_policy_cases_are_separate_and_fail_for_expected_reason(self):
        report = witness.run_witness()
        for arm in report["arms"]:
            source = arm["source_G1_revocation"]
            self.assertEqual(source["old_prepared_restore"]["error"], "grant_revoked")
            self.assertEqual(source["selected_existing_grants"], ["G2"])
            self.assertTrue(source["fresh_context_restore"]["fact_matches"])
            self.assertEqual([row["allowed"] for row in source["current_access_checks"]], [False, True])
            for outcome in arm["epoch_change"].values():
                self.assertEqual(outcome["error"], "lifecycle_epoch_changed")
            policy = arm["same_version_policy_change"]
            self.assertEqual(policy["old_prepared_restore"]["error"], "restoration_policy_mismatch")
            self.assertNotEqual(policy["policy_sha256_before"], policy["policy_sha256_after"])

    def test_report_contains_receipts_not_key_map_token_answer_or_raw_records(self):
        fixed_key = b"ephemeral-test-key-do-not-write!!"
        original_bytes = witness.secrets.token_bytes
        # token_hex in ordinary record/token creation also uses token_bytes;
        # pin only the authority key, preserving distinct random identifiers.
        with patch.object(witness.secrets, "token_bytes", side_effect=lambda size=None:
                          fixed_key if size == 32 else original_bytes(size)):
            report = witness.run_witness()
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(fixed_key.decode(), serialized)
        self.assertNotIn(fixed_key.hex(), serialized)
        self.assertNotIn("[PVT_", serialized)
        self.assertNotIn(witness.FACT_VALUE, serialized)
        self.assertNotIn('"mapping"', serialized)
        self.assertNotIn('"access_signature"', serialized)
        self.assertNotIn('"source_start"', serialized)
        self.assertEqual(len(report["input_records_sha256"]), 64)
        self.assertTrue(all(len(value) == 64 for value in report["source_receipts"].values()))
        self.assertIn("not_new_algorithm_advantage", report["limitations"])

    def test_noop_revocation_is_detected_without_dropping_failed_arms(self):
        with patch.object(witness.MemoryLabelAuthority, "revoke", return_value=None):
            report = witness.run_witness()
        self.assertFalse(report["all_checks_passed"])
        self.assertEqual(len(report["arms"]), 2)
        self.assertFalse(report["checks"]["legacy:old_prepared_blocked"])
        self.assertFalse(report["checks"]["boundary:old_request_replay_blocked"])
        self.assertFalse(report["checks"]["legacy:existing_G2_restores"])

    def test_cli_saves_fresh_report_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"report.json"
            with patch("sys.argv", ["run_transfer_lifecycle_witness.py", "--output-dir", directory]), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(witness.main(), 0)
            saved = path.read_bytes()
            report = json.loads(saved)
            self.assertTrue(report["all_checks_passed"])
            with patch("sys.argv", ["run_transfer_lifecycle_witness.py", "--output-dir", directory]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                witness.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(path.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
