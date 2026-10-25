"""Pure synthetic audit-unit tests; no vendor, ASGI, or real result reads."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.verify_policy_projection_study import (Audit, AuditInputError, Oracle, case_body, digest,
    native_read, native_response, private_fields, strict_json, under, verify)


class ProjectionAuditTests(unittest.TestCase):
    def test_json_rejects_duplicate_keys_and_nonfinite(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', 'null broken'):
            with self.assertRaises(AuditInputError): strict_json(raw)
        self.assertEqual(strict_json('{"a":[1,null]}'), {"a": [1, None]})

    def test_chain_revocation_preserves_independent_root_and_expiry_is_exclusive(self):
        root = {"grant_id": "root", "object_id": "fact", "subject": "alice", "actions": ["read"],
            "not_before": 0, "expires_at": 30, "parent_grant_id": None}
        child = dict(root, grant_id="child", subject="bob", parent_grant_id="root", expires_at=20)
        independent = dict(root, grant_id="independent", subject="bob")
        oracle = Oracle({"grants": [root, child, independent], "job_manifests": [], "principals": []})
        state = {"time": 12, "policy_revision": 1, "registered_grants": ["root", "child", "independent"], "revoked_grants": []}
        body = {"operation": "read", "object_id": "fact"}
        self.assertEqual(oracle.decide("bob", body, state), ("allow", ["child", "independent"]))
        state["revoked_grants"] = ["root"]
        self.assertEqual(oracle.decide("bob", body, state), ("allow", ["independent"]))
        state["revoked_grants"] = []; state["time"] = 20
        self.assertFalse(oracle.valid("child", state))
        self.assertTrue(oracle.valid("independent", state))

    def test_request_translation_never_copies_scoring_or_actor(self):
        case = {"case_id": "P1", "expected": "allow", "group": "fake", "state_id": "initial", "actor": "alice",
            "operation": "share", "object_id": "fact", "recipient": "bob", "child_actions": ["read"], "child_expires_at": 20,
            "creates_grant": "grant.share"}
        original = case_body(case, {})
        changed = case_body(dict(case, expected="deny", case_id="P100", actor="another"), {})
        self.assertEqual(original, changed)
        self.assertFalse({"expected", "case_id", "actor", "creates_grant"} & set(original))

    def response_fixture(self, state):
        directory = state / "safe_responses"; directory.mkdir(parents=True)
        path = directory / "0000.bin"; path.write_bytes(b"SYNTHETIC_A")
        return {"index": 0, "status": 200, "response_checked": True, "execution_error": None,
            "started_ns": 1, "finished_ns": 2, "actor": "alice_reader", "authorization_present": True,
            "api_key_present": False, "cookie_present": False, "credential_response_omitted": False,
            "native_raw_body": "SYNTHETIC_A", "native_body_sha256": digest(b"SYNTHETIC_A"),
            "byte_count": 11, "native_response_file": str(path)}

    def test_native_raw_original_disk_hash_and_strict_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            row = self.response_fixture(state); audit = Audit()
            native_response(audit, row, state=state)
            self.assertEqual(audit.failures, [])
            row["native_response_file"] = str(state / "auth_private.db")
            native_response(audit, row, state=state)
            self.assertIn("native_raw_exact_allowlisted_path", [f["code"] for f in audit.failures])
            (state / "safe_responses/0000.bin").write_bytes(b"changed")
            audit = Audit(); native_response(audit, row, state=state)
            self.assertIn("native_raw_disk_bytes", [f["code"] for f in audit.failures])

    def test_credential_responses_never_open_or_accept_raw(self):
        row = {"index": 0, "status": 200, "response_checked": True, "execution_error": None,
            "started_ns": 1, "finished_ns": 2, "actor": None, "authorization_present": False,
            "api_key_present": False, "cookie_present": False, "credential_response_omitted": True}
        audit = Audit(); self.assertIsNone(native_response(audit, row, state=Path("missing")))
        self.assertFalse(audit.failures)
        row["native_raw_body"] = "never publish"
        native_response(audit, row, state=Path("missing"))
        self.assertTrue(audit.failures)

    def test_denial_containing_other_registered_fact_is_failure(self):
        facts = {"A": {"text": "SYNTHETIC_A"}, "B": {"text": "SYNTHETIC_B"}}
        audit = Audit(); native_read(audit, {"status": 403, "native_raw_body": '{"detail":"SYNTHETIC_B"}'}, "SYNTHETIC_A", facts, False)
        self.assertTrue(audit.failures)
        audit = Audit(); native_read(audit, {"status": 200, "native_raw_body": "null"}, "SYNTHETIC_A", facts, False)
        self.assertTrue(audit.failures)

    def test_private_keys_and_outside_paths_fail_closed(self):
        self.assertTrue(private_fields({"outer": [{"access_token": "fake"}]}))
        self.assertFalse(private_fields({"credential_handle": "alice.reader"}))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AuditInputError): under(Path(tmp).parent / "not_allowed", tmp)

    def test_incomplete_run_returns_fixed_failed_receipt_without_private_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = verify(tmp)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][-1]["code"], "audit_input_unreadable_or_contract_mismatch")
        self.assertNotIn("Traceback", json.dumps(result))
        self.assertNotIn(tmp, json.dumps(result))


if __name__ == "__main__": unittest.main()
