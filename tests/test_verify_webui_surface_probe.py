"""Eight standard-library adversarial fixtures; no native/scorer imports."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_webui_surface_probe as audit


def fixture():
    grants = [
        {"grant_id": "grant.readonly", "subject": "alice.reader", "object_id": "fact.readonly", "actions": ["read"], "not_before": 0, "expires_at": 30, "parent_grant_id": None},
        {"grant_id": "grant.root", "subject": "alice.reader", "object_id": "fact.managed", "actions": ["read", "share"], "not_before": 0, "expires_at": 30, "parent_grant_id": None},
        {"grant_id": "grant.independent", "subject": "bob.reader", "object_id": "fact.managed", "actions": ["read"], "not_before": 0, "expires_at": 30, "parent_grant_id": None},
    ]
    contract = {"principals": [{"principal_id": a.replace("_", ".", 1)} for a in audit.ACTORS[1:]],
        "grants": grants, "facts": [{"object_id": "fact.readonly", "text": "FAKE_SECRET_A71"}, {"object_id": "fact.managed", "text": "FAKE_SECRET_B92"}],
        "states": [{"state_id": "initial", "time": 10, "policy_revision": 1,
            "registered_grants": [g["grant_id"] for g in grants], "revoked_grants": []}]}
    summary = {"facts": {"readonly": {"id": "fake-file-A"}, "managed": {"id": "fake-file-B"}},
        "datasets": {"readonly": {"id": "fake-note-A"}, "managed": {"id": "fake-note-B"}}}
    return contract, summary


def response(value, *, actor, status=200, raw=False):
    body = value if raw else json.dumps(value)
    return {"status": status, "trace": {"index": 0, "actor": actor, "status": status,
        "native_raw_body": body, "native_body_sha256": audit.sha(body.encode()),
        "response_checked": True, "execution_error": None, "authorization_present": True,
        "api_key_present": False, "cookie_present": False}}


class IndependentSurfaceAuditTests(unittest.TestCase):
    def assess(self, result, *, operation="file_metadata", actor="alice_reader", arm="native_projection",
               phase="current_read_grants", oid="fact.readonly", owners=None):
        contract, summary = fixture()
        return audit.assess(result, {"actor": actor, "operation": operation, "object_id": oid, "phase": phase},
            arm=arm, contract=contract, summary=summary, owners=owners or {})

    def test_secret_in_rejection_checked_before_owner_ineligible_branch(self):
        result = response({"detail": "denied but FAKE_SECRET_A71"}, actor="alice_reader", status=404)
        verdict = self.assess(result, operation="file_content_html", arm="gateway_storage")
        self.assertTrue(verdict["safety_failure"])
        self.assertIs(verdict["safety_verdict"], False)
        self.assertEqual(verdict["forbidden_objects"], ["fact.readonly"])

    def test_null_cannot_be_owner_metadata_positive_or_denial(self):
        verdict = self.assess(response("null", actor="owner", raw=True), actor="owner")
        self.assertFalse(verdict["owner_qualified"])
        self.assertIsNone(verdict["safety_verdict"])
        self.assertTrue(verdict["unexpected_qualification_gap"])

    def test_wrong_native_actor_rejected_even_with_rehashed_body(self):
        result = response({"id": "fake-file-A", "user_id": "fake-owner", "filename": "a.txt"}, actor="bob_worker")
        with self.assertRaisesRegex(audit.AuditError, "wrong_actor"):
            self.assess(result, actor="alice_reader")

    def test_count_and_manifest_mismatch_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "physical_request_count_mismatch"):
            audit.require_count([{"index": i} for i in range(191)], "native_projection")
        manifest = audit.manifest()
        self.assertEqual(len(manifest), 145)
        self.assertEqual(sum(r["operation"] == "note_search_read" for r in manifest), 9)
        self.assertEqual(sum(r["operation"] == "note_search" for r in manifest), 6)
        self.assertEqual(len(audit.rpc_manifest()["native_projection"]), 173)
        self.assertEqual(len(audit.rpc_manifest()["gateway_storage"]), 168)

    def test_safe_response_scope_cannot_redirect_to_auth_store(self):
        with tempfile.TemporaryDirectory(prefix="webui_surface_fake_") as directory:
            state = Path(directory)
            (state / "safe_responses").mkdir()
            with patch.object(Path, "read_bytes", side_effect=AssertionError("must not read")):
                with self.assertRaisesRegex(audit.AuditError, "unsafe_response_path"):
                    audit.safe_response_path({"index": 0, "native_response_file": str(state / "auth.db")}, state)

    def test_source_authorization_and_G_confinement_are_distinct(self):
        contract, _ = fixture()
        initial = audit.fixture_states(contract)["current_read_grants"]
        self.assertEqual(audit.source_relations(contract, initial), {("alice_reader", "fact.readonly"), ("alice_reader", "fact.managed"), ("bob_reader", "fact.managed")})
        revoked = audit.fixture_states(contract)["alice_read_revoked"]
        self.assertEqual(audit.source_relations(contract, revoked), {("bob_reader", "fact.managed")})
        self.assertEqual(audit.direct_objects(contract, "current_read_grants", "gateway_storage", "alice_reader"), set())
        self.assertEqual(audit.direct_objects(contract, "current_read_grants", "native_projection", "alice_reader"), set(audit.OBJECTS))

    def test_write_read_note_views_and_owned_files_do_not_conflict(self):
        contract, _ = fixture()
        allowed = audit.direct_objects(contract, "current_read_grants", "native_projection", "alice_reader")
        self.assertEqual(audit.visible_objects("note_search", "alice_reader", allowed, None), set())
        self.assertEqual(audit.visible_objects("file_list", "alice_reader", allowed, None), set())
        self.assertEqual(audit.visible_objects("note_search_read", "alice_reader", allowed, None), set(audit.OBJECTS))
        default = self.assess(response({"items": [], "total": 0}, actor="alice_reader"), operation="note_search", oid=None,
            owners={"note_search|GLOBAL": {"qualified": True}})
        self.assertTrue(default["view_matches"])
        bad = self.assess(response({"items": [], "total": 0}, actor="alice_reader"), operation="note_search_read", oid=None,
            owners={"note_search_read|GLOBAL": {"qualified": True}})
        self.assertFalse(bad["view_matches"])

    def test_HTML_and_empty_extracted_content_never_become_privacy_success(self):
        html = self.assess(response({"detail": "not found"}, actor="owner", status=404), operation="file_content_html", actor="owner")
        data = self.assess(response({"content": ""}, actor="owner"), operation="file_data_content", actor="owner")
        self.assertIsNone(html["safety_verdict"])
        self.assertIsNone(data["safety_verdict"])
        self.assertFalse(html["owner_qualified"])
        self.assertFalse(data["owner_qualified"])


if __name__ == "__main__":
    unittest.main()
