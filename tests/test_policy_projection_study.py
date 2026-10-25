"""Explicit fake native transport + real reference HTTP protocol tests.

These tests never start a vendor process, use a model, or count as native
qualification. They verify state/side-effect/scoring separation before freezing.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_policy_projection_study import execute, request_body, NATIVE_ACTORS, SOURCE_FILE, build_plan


class FakeNativeRPC:
    def __init__(self, python, script, args, *, timeout=240, disclose=False, null_owner=False, bad_list=False):
        self.calls, self.requests, self.datasets, self.facts, self.acl = [], [], {}, {}, set()
        self.state = args[args.index("--state") + 1]
        self.gateway_arm = self.state.endswith("gateway")
        self.disclose, self.null_owner, self.bad_list = disclose, null_owner, bad_list
        self.actor = None
        self.identities = {p: {"id": "id-" + p, "is_superuser": False} for p in ["owner", *NATIVE_ACTORS.values()]}

    def trace(self, status, value):
        raw = value if isinstance(value, str) else json.dumps(value)
        row = {"index": len(self.requests), "status": status, "native_raw_body": raw,
            "native_body_sha256": hashlib.sha256(raw.encode()).hexdigest(), "response_checked": True,
            "execution_error": None, "cookie_present": False, "authorization_present": True,
            "api_key_present": False, "actor": self.actor}
        self.requests.append(deepcopy(row))
        return {"status": status, "trace": row}

    def summary(self):
        return {"identities": self.identities, "datasets": self.datasets, "facts": self.facts,
            "native_requests": self.requests, "network_events": [], "generation_attempts": 0,
            "embedding_attempts": 0, "client_credential_values_persisted": False}

    def allowed(self, actor, ds):
        return actor == "owner" or (actor, ds) in self.acl or (self.disclose and self.gateway_arm)

    def call(self, command, data):
        self.actor = data.get("actor")
        if command in {"init", "summary", "close"}:
            result = deepcopy(self.summary())
        elif command == "create_dataset":
            ds = data["dataset"]
            self.datasets[ds] = {"id": "dataset-" + ds, "owner": "owner"}
            result = self.trace(200, self.datasets[ds])
        elif command == "add_exact_fact":
            ds = data["dataset"]
            self.facts[data["fact_key"]] = {"id": "file-" + ds, "text": data["text"], "dataset": ds}
            result = self.trace(200, {"id": "file-" + ds})
        elif command in {"grant", "revoke"}:
            if data["actor"] != "owner":
                result = self.trace(403, {"error": "denied"})
            else:
                pair = (data["recipient"], data["dataset"])
                if command == "grant": self.acl.add(pair)
                else: self.acl.discard(pair)
                result = self.trace(200, {"message": "Permission assigned to principal" if command == "grant" else "Permission revoked from principal"})
        elif command == "read_raw":
            if self.null_owner and self.gateway_arm and data["actor"] == "owner":
                result = self.trace(200, "null")
            elif self.allowed(data["actor"], data["dataset"]):
                result = self.trace(200, self.facts[data["fact_key"]]["text"])
            else: result = self.trace(403, {"error": "denied"})
        elif command == "list_datasets":
            result = self.trace(200, None if self.bad_list else [row for ds, row in self.datasets.items() if self.allowed(data["actor"], ds)])
        elif command == "list_data":
            if self.allowed(data["actor"], data["dataset"]):
                result = self.trace(200, [row for row in self.facts.values() if row["dataset"] == data["dataset"]])
            else: result = self.trace(403, {"detail": "denied"})
        else: raise AssertionError("unknown fake RPC command: " + command)
        self.calls.append({"command": command, "data": deepcopy(data), "result": deepcopy(result)})
        return result

    def terminate(self): pass


class ProjectionStudyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        self.contract = json.loads(SOURCE_FILE.read_bytes())
        self.plan = {"target": "cognee", "python": "explicit-fake", "worker": "explicit-fake",
            "code_sha256": {"explicit-fake": "not-a-source-hash"}, "proposal_sha256": hashlib.sha256(SOURCE_FILE.read_bytes()).hexdigest(),
            "native_states": {"native_projection": "explicit-native", "gateway_storage": "explicit-gateway"},
            "wheel": "explicit-fake", "legacy": "explicit-fake", "arms": {"native_projection": "fake", "gateway_storage": "fake"}}

    def run_fake(self, **flags):
        with patch("scripts.run_policy_projection_study.verify_sha_table", return_value={"status": "passed"}):
            return execute(self.plan, self.output,
                rpc_factory=lambda *a, **kw: FakeNativeRPC(*a, **kw, **flags))

    def test_all_25_http_decisions_and_real_managed_side_effects(self):
        result = self.run_fake()
        self.assertEqual(result["status"], "qualified_with_declared_limits", result.get("failure"))
        self.assertEqual(result["source_matches"], 25)
        self.assertEqual(result["gateway_matches_with_effect"], 25)
        reads = sum(c["operation"] == "read" for c in self.contract["cases"])
        self.assertEqual(result["native_read_matches"], reads)
        self.assertEqual(result["native_unsupported_operations"], 25 - reads)
        rows = json.loads((self.output / "unscored_rows.json").read_bytes())
        self.assertNotIn("expected", rows[0])
        for row in rows:
            self.assertNotIn("expected", row["request_body"])
            self.assertNotIn("case_id", row["request_body"])
            self.assertNotIn("actor", row["request_body"])
        for cid in ("P07", "P11"):
            row = next(r for r in rows if r["case_id"] == cid)
            self.assertEqual(row["created_grant_recipient_read"]["parsed"]["decision"], "allow")
        self.assertEqual(len(json.loads((self.output / "sink_events.json").read_bytes())), 2)
        barriers = json.loads((self.output / "barriers.json").read_bytes())
        self.assertEqual([x["phase"] for x in barriers], ["initial", "with_children", "delegation_expired", "root_revoked", "all_managed_revoked"])
        self.assertTrue(all(len(x["all_eight_reads"]) == 8 for x in barriers))
        self.assertFalse(result["native_full_source_semantics_passed"])
        self.assertFalse(result["full_get_search_list_bypass_qualified"])

    def test_native_direct_bypass_failure_is_retained_and_stops(self):
        result = self.run_fake(disclose=True)
        self.assertEqual(result["status"], "incomplete_or_failed")
        self.assertIsNotNone(result["failure"])
        self.assertTrue((self.output / "rpc_receipts.json").is_file())
        self.assertLess(result["case_count"], 25)

    def test_http200_null_backend_is_not_safe_denial(self):
        result = self.run_fake(null_owner=True)
        self.assertEqual(result["status"], "incomplete_or_failed")
        self.assertLess(result["case_count"], 25)
        self.assertNotEqual(result["failure"], None)
        rows = json.loads((self.output / "unscored_rows.json").read_bytes())
        if rows:
            self.assertEqual(rows[0]["gateway_http"]["parsed"]["decision"], "error")
            self.assertGreaterEqual(rows[0]["gateway_http"]["status"], 500)

    def test_operation_conversion_never_uses_scoring_expected(self):
        for case in self.contract["cases"]:
            changed = dict(case, expected="allow" if case["expected"] != "allow" else "deny")
            self.assertEqual(request_body(case, self.contract), request_body(changed, self.contract))

    def test_null_container_list_is_unqualified_not_empty_safe_list(self):
        result = self.run_fake(bad_list=True)
        self.assertEqual(result["status"], "incomplete_or_failed")
        self.assertEqual(result["failure"]["code"], "native_list_array_schema_unqualified")

    def test_deny_with_secret_and_empty_delivered_ids_is_not_success(self):
        from scripts.policy_projection_gateway_http import GatewayHTTP
        original = GatewayHTTP.request
        def corrupted(http, principal_id, body=None, **kwargs):
            row = original(http, principal_id, body, **kwargs)
            if (body and body.get("operation") == "read" and body.get("object_id") == "fact.readonly"
                    and principal_id == "bob.reader" and "actor" not in body):
                row["parsed"]["hidden"] = "SYNTHETIC_VALUE_A71"
                row["parsed"]["delivered_fact_ids"] = []
                row["raw_body"] = json.dumps(row["parsed"])
                row["response_body_sha256"] = hashlib.sha256(row["raw_body"].encode()).hexdigest()
            return row
        with patch.object(GatewayHTTP, "request", corrupted):
            result = self.run_fake()
        self.assertEqual(result["status"], "incomplete_or_failed")
        self.assertLess(result["gateway_matches_with_effect"], 25)

    def test_nonjson_gateway_error_still_produces_report_receipt(self):
        from scripts.policy_projection_gateway_http import GatewayHTTP
        original = GatewayHTTP.request
        def broken(http, principal_id, body=None, **kwargs):
            row = original(http, principal_id, body, **kwargs)
            if (body and body.get("operation") == "read" and "actor" not in body
                    and principal_id == "alice.reader"):
                row.update(status=500, parsed=None, raw_body="Internal Server Error")
            return row
        with patch.object(GatewayHTTP, "request", broken):
            result = self.run_fake()
        self.assertEqual(result["status"], "incomplete_or_failed")
        self.assertTrue((self.output / "report.json").is_file())
        self.assertEqual(result["gateway_matches_with_effect"], 0)

    def test_frozen_plan_roundtrip_preserves_json_types(self):
        # Plan shape is testable without provisioning a vendor interpreter or
        # downloading a wheel in a fresh Git clone.
        with patch("pathlib.Path.is_file", return_value=True), patch("scripts.run_policy_projection_study.sha", return_value="1" * 64):
            plan = build_plan("cognee")
            serialized = json.loads(json.dumps(plan))
            self.assertEqual(plan, serialized)
            self.assertEqual(build_plan("cognee", approved=serialized), serialized)


if __name__ == "__main__": unittest.main()
