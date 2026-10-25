"""HTTP identity boundary tests use an explicit fake policy, never a backend."""
from __future__ import annotations
import hashlib
import json
import unittest

from scripts.policy_projection_gateway_http import GatewayHTTP


class FakeGateway:
    def __init__(self): self.calls = []
    def dispatch(self, caller, body):
        if isinstance(body, bytes): body = json.loads(body)
        self.calls.append((caller, body))
        bad = not isinstance(body, dict) or "actor" in body
        return {"http_status": 400 if bad else 200, "decision": "deny" if bad else "allow"}


class GatewayHTTPTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGateway()
        self.principals = [
            {"principal_id": "alice.reader", "user_id": "alice", "agent_id": "reader"},
            {"principal_id": "alice.worker", "user_id": "alice", "agent_id": "worker"}]
        self.http = GatewayHTTP(self.fake, self.principals, max_requests=5)
        self.addCleanup(self.http.close)

    def test_distinct_bearers_bind_the_actual_tuple(self):
        for p in self.principals:
            row = self.http.request(p["principal_id"], identity=True)
            self.assertEqual(row["status"], 200)
            self.assertEqual(row["parsed"], {"user_id": p["user_id"], "agent_id": p["agent_id"]})
        self.http.request("alice.reader", {"operation": "read"})
        self.http.request("alice.worker", {"operation": "read"})
        self.assertEqual([c.agent_id for c, _ in self.fake.calls], ["reader", "worker"])

    def test_no_or_unknown_bearer_never_reaches_policy(self):
        self.assertEqual(self.http.request(None, {"operation": "read"})["status"], 401)
        self.assertEqual(self.http.request("alice.reader", {}, invalid_credential=True)["status"], 401)
        self.assertEqual(self.fake.calls, [])

    def test_body_cannot_replace_authenticated_actor(self):
        row = self.http.request("alice.reader", {"operation": "read", "actor": "alice.worker"})
        self.assertEqual(row["status"], 400)
        self.assertEqual(self.fake.calls[0][0].agent_id, "reader")

    def test_response_hash_and_http_budget_are_physical(self):
        for _ in range(5):
            row = self.http.request("alice.reader", {})
            self.assertEqual(hashlib.sha256(row["raw_body"].encode()).hexdigest(), row["response_body_sha256"])
        with self.assertRaisesRegex(ValueError, "budget_exhausted"):
            self.http.request("alice.reader", {})
        self.assertEqual(len(self.fake.calls), 5)

    def test_controller_routes_are_not_exposed(self):
        response = self.http._client.post("/admin/state", json={"time": 0})
        self.assertEqual(response.status_code, 404)

    def test_duplicates_and_unknown_handles_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "principal_registry"):
            GatewayHTTP(self.fake, self.principals * 2)
        with self.assertRaisesRegex(ValueError, "unknown_gateway"):
            self.http.request("someone.else", {})


if __name__ == "__main__": unittest.main()
