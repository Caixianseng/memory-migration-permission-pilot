"""End-to-end tests for the local Agent Memory Gateway."""
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from agent_memory_gateway.api import create_app

class GatewayApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.token = "test-token-" + ("x" * 40)
        self.client = TestClient(create_app(str(self.root / "gateway"), self.token))
        self.headers = {"Authorization": "Bearer " + self.token}

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def post(self, path, body):
        return self.client.post(path, json=body, headers=self.headers)

    def fixture(self):
        r = self.post("/v1/agents/agent-a/sources",
                      {"source_id":"project","text":"Project Aurora budget is 277 yuan."})
        self.assertEqual(r.status_code, 201, r.text)
        r = self.client.put("/v1/recipients/agent-b/permissions",
            json={"allowed_source_ids":["project"]}, headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        r = self.post("/v1/agents/agent-a/memories", {
            "memory_id":"summary","content":"Project Aurora has a budget of 277 yuan.",
            "source_ids":["project"],"provenance":{"generator":"synthetic-test"}})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["memory_key"]

    def prepare(self, batch="test-batch"):
        key = self.fixture()
        r = self.post("/v1/transfers", {"sender_id":"agent-a","recipient_id":"agent-b",
            "memory_refs":[key],"batch_id":batch})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["transfer_id"]

    def test_auth_and_health(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        self.assertEqual(self.client.get("/v1/recipients/agent-b/permissions").status_code, 401)

    def test_delivery_restart_readback_and_idempotent_retry(self):
        transfer_id = self.prepare("first-delivery")
        first = self.post(f"/v1/transfers/{transfer_id}/commit", {})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["new_persistent_acceptance"])
        self.assertFalse(first.json()["ack_contains_plaintext"])
        second = self.post(f"/v1/transfers/{transfer_id}/commit", {})
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json()["status"], "already_committed")
        self.assertFalse(second.json()["new_persistent_acceptance"])
        self.assertNotIn("memory", second.json())

        self.client.close()
        from agent_memory_gateway.api import create_app
        self.client = TestClient(create_app(str(self.root / "gateway"), self.token))
        state = self.client.get(f"/v1/transfers/{transfer_id}", headers=self.headers)
        self.assertEqual(state.json()["status"], "committed")
        batch = self.client.get("/v1/agents/agent-b/batches/first-delivery", headers=self.headers)
        self.assertEqual(batch.status_code, 200, batch.text)
        self.assertIn("277 yuan", batch.json()["memory"])
        audit = self.client.get("/v1/agents/agent-b/audit", headers=self.headers)
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertGreaterEqual(audit.json()["chain"]["events"], 2)

    def test_revoke_after_prepare_blocks_first_commit(self):
        transfer_id = self.prepare("must-be-blocked")
        r = self.client.put("/v1/recipients/agent-b/permissions",
            json={"allowed_source_ids":[]}, headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        state = self.client.get(f"/v1/transfers/{transfer_id}", headers=self.headers)
        self.assertEqual(state.json()["status"], "blocked")
        denied = self.post(f"/v1/transfers/{transfer_id}/commit", {})
        self.assertEqual(denied.status_code, 409, denied.text)
        self.assertEqual(denied.json()["detail"]["code"], "stale_policy_epoch")
        missing = self.client.get("/v1/agents/agent-b/batches/must-be-blocked", headers=self.headers)
        self.assertEqual(missing.status_code, 404)

    def test_unknown_source_grant_rejected(self):
        r = self.client.put("/v1/recipients/agent-b/permissions",
            json={"allowed_source_ids":["unknown"]}, headers=self.headers)
        self.assertEqual(r.status_code, 409)

    def test_spool_tampering_rejected(self):
        transfer_id = self.prepare("tamper")
        spool = self.root / "gateway" / "spool" / (transfer_id + ".json")
        raw = spool.read_bytes()
        spool.write_bytes(raw.replace(b"277 yuan", b"999 yuan"))
        denied = self.post(f"/v1/transfers/{transfer_id}/commit", {})
        self.assertEqual(denied.status_code, 409)
        self.assertEqual(denied.json()["detail"]["code"], "transfer_spool_canonical_encoding_invalid")

if __name__ == "__main__":
    unittest.main()
