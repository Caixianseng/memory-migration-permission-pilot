"""Pure fake transport protocol checks; no Cognee/model imports or execution."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from uuid import uuid4

from scripts.native_cognee_policy_worker import CogneePolicyWorker, SafeRecorder
from scripts.run_cognee_read_share_qualification import execute_protocol, read_classification, action_classification, fact_from_proposal, EXPECTED_VALUE
from tests.test_native_cognee_policy_worker import FakeClient, FakeResponse


class ProtocolClient(FakeClient):
    def __init__(self, identities, *, parent_reaches_child=False, leak=False):
        super().__init__(identities); self.parent_reaches_child = parent_reaches_child; self.leak = leak
    def request(self, method, path, headers, **kwargs):
        actor = self.bearers.get(headers.get("Authorization"))
        if self.leak and method == "POST" and path.startswith("/api/v1/permissions/datasets/") and actor == "assistant":
            self.grants[(kwargs["json"][0], path.rsplit("/", 1)[-1], "read")] = True
            return FakeResponse({"message": "Permission assigned to principal"}, 200, headers)
        if self.parent_reaches_child and actor == "assistant" and path.endswith("/raw") and "assistant_agent" in self.identities:
            ds = path.strip("/").split("/")[3]
            if self.grants.get((ds, self.identities["assistant_agent"]["id"], "read")):
                rid = path.strip("/").split("/")[5]
                return FakeResponse(self.facts[rid]["text"].encode(), 200, headers)
        response = super().request(method, path, headers, **kwargs)
        if response.status_code == 200 and path.startswith("/api/v1/permissions/datasets/"):
            return FakeResponse({"message": "Permission assigned to principal" if method == "POST" else "Permission revoked from principal"}, 200, headers)
        return response


class FakeRPC:
    def __init__(self, directory, *, parent_reaches_child=False, leak=False, child_unknown=False, auth_error_after_revoke=False):
        self.calls = []; self.child_unknown = child_unknown; self.auth_error_after_revoke = auth_error_after_revoke
        self.worker = CogneePolicyWorker(state=directory/"state", wheel=directory/"none.whl", legacy_project=directory, http_cap=48)
        self.worker.identities = {actor: {"id": str(uuid4()), "parent_user_id": None, "is_superuser": False,
            "credential_kind": "bearer"} for actor in ("owner", "assistant", "outsider")}
        self.client = ProtocolClient(deepcopy(self.worker.identities), parent_reaches_child=parent_reaches_child, leak=leak)
        self.worker.recorder = SafeRecorder(self.client, directory/"responses", max_requests=48)
        for actor in self.worker.identities:
            self.worker.recorder.bind(actor, "bearer", "fake-token-"+actor+"-long-local-only")
        self.worker._guard = Mock(); self.parent_was_revoked = False
    def call(self, command, data):
        self.calls.append({"command": command, "input": deepcopy(data)})
        if command == "create_child" and self.child_unknown: raise RuntimeError("fake child unavailable")
        if command == "revoke" and data["recipient"] == "assistant": self.parent_was_revoked = True
        result = self.worker(command, data)
        if self.auth_error_after_revoke and command == "read_raw" and data["actor"] == "assistant" and self.parent_was_revoked:
            result = response(401, {"detail": "authentication error"})
            result["trace"]["actor"] = "assistant"
        return result


def response(status, body):
    raw = body if isinstance(body, str) else json.dumps(body)
    return {"status": status, "trace": {"status": status, "native_raw_body": raw,
        "native_body_sha256": hashlib.sha256(raw.encode()).hexdigest(), "cookie_present": False,
        "authorization_present": True, "api_key_present": False, "response_checked": True, "execution_error": None}}


class CogneeReadShareQualificationTests(unittest.TestCase):
    def run_fake(self, **kwargs):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        rpc = FakeRPC(Path(temp.name), **kwargs)
        protocol = execute_protocol(rpc, {"text": EXPECTED_VALUE})
        return rpc, protocol

    def test_two_cycles_qualify_basics_and_record_independent_child(self):
        rpc, result = self.run_fake()
        self.assertIsNone(result["stop_reason"]); self.assertIsNone(result["child_unknown"])
        for key in ("basic_user_read", "read_not_share", "basic_user_revocation", "independent_child_read_retained", "final_owner_access", "final_outsider_denial"):
            self.assertIs(result["outcomes"][key], True)
        self.assertEqual(result["outcomes"]["child_initial_read"], "denied")
        self.assertLessEqual(len(rpc.worker.recorder.requests)+10, 48)
        additions = [x for x in rpc.calls if x["command"] == "add_exact_fact"]
        self.assertEqual(len(additions), 1); self.assertEqual(additions[0]["input"]["text"], EXPECTED_VALUE)

    def test_parent_child_reachability_is_observation_not_first_cycle_failure(self):
        _, result = self.run_fake(parent_reaches_child=True)
        self.assertIsNone(result["stop_reason"])
        self.assertTrue(result["outcomes"]["basic_user_revocation"])
        self.assertEqual(result["outcomes"]["parent_read_after_independent_child_grant"], "available")
        self.assertTrue(result["outcomes"]["independent_child_read_retained"])

    def test_child_unknown_does_not_erase_qualified_user_phases(self):
        _, result = self.run_fake(child_unknown=True)
        self.assertIsNone(result["stop_reason"]); self.assertIsNotNone(result["child_unknown"])
        self.assertTrue(result["outcomes"]["basic_user_revocation"])
        self.assertIsNone(result["outcomes"]["independent_child_read_retained"])

    def test_outsider_disclosure_immediately_stops_new_native_actions(self):
        rpc, result = self.run_fake(leak=True)
        self.assertEqual(result["stop_reason"], "unauthorized_fact_disclosure")
        self.assertEqual(rpc.calls[-1]["command"], "read_raw")
        self.assertEqual(rpc.calls[-1]["input"]["actor"], "outsider")
        self.assertFalse(any(x["command"] in {"create_child", "revoke"} for x in rpc.calls))

    def test_authentication_error_is_not_successful_revocation(self):
        _, result = self.run_fake(child_unknown=True, auth_error_after_revoke=True)
        self.assertEqual(result["stop_reason"], "raw_read_not_qualified")
        self.assertIsNone(result["outcomes"]["basic_user_revocation"])

    def test_null_malformed_and_secret_denial_have_distinct_states(self):
        self.assertEqual(read_classification(response(200, "null"), EXPECTED_VALUE)["state"], "null_response")
        self.assertEqual(read_classification(response(401, {"detail": "no"}), EXPECTED_VALUE)["state"], "authentication_error")
        secret = response(403, {"detail": EXPECTED_VALUE}); secret["trace"]["native_body_sha256"] = "0"*64
        observed = read_classification(secret, EXPECTED_VALUE)
        self.assertEqual(observed["state"], "unqualified_trace"); self.assertTrue(observed["full_content_observed"])
        self.assertEqual(action_classification(response(200, "null"), "grant"), "null_response")
        self.assertNotEqual(action_classification(response(200, {"message": "not applied"}), "grant"), "accepted_requires_postcondition")

    def test_source_projection_uses_only_exact_declared_readonly_fact(self):
        source = "PREFIX " + EXPECTED_VALUE + " OTHER VALUE"
        fact = {"object_id": "fact.readonly", "source_id": "source", "text": EXPECTED_VALUE,
            "source_start": 7, "source_end": 7+len(EXPECTED_VALUE), "content_sha256": hashlib.sha256(EXPECTED_VALUE.encode()).hexdigest()}
        proposal = {"facts": [fact], "sources": [{"source_id": "source", "text": source}]}
        self.assertEqual(fact_from_proposal(proposal), fact)
        wrong = deepcopy(proposal); wrong["facts"][0]["source_start"] += 1
        with self.assertRaises(ValueError): fact_from_proposal(wrong)

    def test_frozen_input_change_blocks_before_any_transport(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        rpc = FakeRPC(Path(temp.name))
        def changed(): raise ValueError("fake frozen source mismatch")
        result = execute_protocol(rpc, {"text": EXPECTED_VALUE}, pre_call=changed)
        self.assertEqual(rpc.calls, []); self.assertEqual(result["stop_reason"], "native_protocol_failed")


if __name__ == "__main__":
    unittest.main()
