"""Explicit fake native transports and real ASGI gateway; no model execution."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_review_native_read_chain as m


class NativeFixture:
    def __init__(self, python, script, args, *, timeout, registry, fault=None):
        self.name = args[args.index("--state") + 1]
        self.direction, self.arm = self.name.split(".")
        self.backend = script.removeprefix("fake_")
        self.cap = int(args[args.index("--http-cap") + 1])
        self.registry, self.fault, self.calls, self.requests = registry, fault, [], []
        self.datasets, self.facts, self.acl = {}, {}, set()
        self.identities = {a: {"id": self.name + ":user:" + a, "credential_kind": "bearer",
            **({"role": "user"} if self.backend == "open_webui" else {"is_superuser": False})}
            for a in ("owner", *m.ACTORS)}
        registry[self.name] = self

    def trace(self, value, actor="owner", status=200):
        if len(self.requests) >= self.cap:
            raise AssertionError("fake hard cap exceeded")
        raw = value if isinstance(value, str) else json.dumps(value)
        trace = {"index": len(self.requests), "actor": actor, "status": status, "response_checked": True,
            "execution_error": None, "authorization_present": True, "api_key_present": False,
            "cookie_present": False, "native_raw_body": raw, "native_body_sha256": m.original.sha(raw.encode()),
            "byte_count": len(raw.encode())}
        self.requests.append(trace)
        return {"status": status, "trace": deepcopy(trace)}

    def summary(self):
        return {"identities": deepcopy(self.identities), "datasets": deepcopy(self.datasets), "facts": deepcopy(self.facts),
            "native_requests": deepcopy(self.requests), "generation_attempts": 0, "embedding_attempts": 0,
            "network_events": [], "client_credential_values_persisted": False}

    def allowed(self, actor, ds):
        return actor == "owner" or (actor, ds) in self.acl

    def note(self, ds):
        grants = [{"id": "grant-" + actor + "-" + ds, "resource_type": "note",
            "resource_id": self.datasets[ds]["id"], "principal_type": "user",
            "principal_id": self.identities[actor]["id"], "permission": "read", "created_at": 1}
            for actor, dataset in sorted(self.acl) if dataset == ds]
        if self.fault == "unknown_acl" and grants:
            grants[0]["principal_type"] = "group"
        return {"id": self.datasets[ds]["id"], "user_id": self.identities["owner"]["id"],
            "data": {"content": {"md": ""}, "files": [{"type": "file", "id": self.facts[ds]["id"]}]},
            "access_grants": grants, "write_access": True, "meta": None}

    def call(self, command, data):
        if command == "init":
            self.trace({"native_identity_setup": "test-only"})
            result = {"identities": deepcopy(self.identities)}
        elif command in {"summary", "close"}:
            result = self.summary()
        elif command == "create_dataset":
            ds = data["dataset"]
            self.datasets[ds] = {"id": self.name + ":dataset:" + ds, "owner": "owner"}
            result = self.trace(self.datasets[ds])
        elif command == "add_exact_fact":
            ds = data["dataset"]
            if self.arm != "source":
                exported = [c["result"]["trace"]["native_raw_body"] for c in self.registry[self.direction + ".source"].calls
                    if c["command"] == "read_raw" and c["input"]["actor"] == "owner"]
                if data["text"] not in exported:
                    raise AssertionError("target bytes absent from actual source export")
            self.facts[ds] = {"id": self.name + ":data:" + ds, "dataset": ds, "text": data["text"]}
            result = self.trace(data["text"])
        elif command in {"grant", "revoke"}:
            pair = data["recipient"], data["dataset"]
            if command == "grant":
                self.acl.add(pair)
            else:
                self.acl.discard(pair)
            result = self.trace(self.note(data["dataset"]) if self.backend == "open_webui" else
                {"message": "Permission assigned to principal" if command == "grant" else "Permission revoked from principal"})
        elif command == "list_data":
            result = self.trace(self.note(data["dataset"]), data["actor"])
        elif command == "read_raw":
            actor, ds = data["actor"], data["dataset"]
            if self.arm == "source" and actor == "owner" and self.fault == "source_error":
                result = self.trace({"detail": "synthetic infrastructure failure"}, actor, 500)
            elif self.arm == "G" and actor != "owner" and self.fault == "g_bypass":
                result = self.trace(self.facts[ds]["text"], actor)
            elif self.allowed(actor, ds):
                result = self.trace(self.facts[ds]["text"], actor)
            else:
                detail = self.facts[ds]["text"] if self.fault == "deny_contains_secret" else "Forbidden"
                result = self.trace({"detail": detail}, actor, 403)
        else:
            raise AssertionError("unsupported fake native command")
        self.calls.append({"command": command, "input": deepcopy(data), "result": deepcopy(result)})
        return result

    def terminate(self):
        pass


class ReviewNativeReadChainTests(unittest.TestCase):
    def test_missing_host_dependency_stops_before_asset_qualification_or_native_launch(self):
        with patch.object(m.importlib.metadata, "version", side_effect=m.importlib.metadata.PackageNotFoundError), \
                patch.object(m.original, "build_plan") as native_plan:
            with self.assertRaisesRegex(m.ChainStop, "host_dependencies_missing_before_native_launch"):
                m.build_plan()
            native_plan.assert_not_called()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        contract = m.original.parse(m.original.CONTRACT.read_bytes())
        self.plan = {"facts": contract["facts"], "principals": contract["principals"],
            "operator_consent": {"approved_for_controlled_synthetic_copy": True},
            "workers": {b: "fake_" + b for b in ("open_webui", "cognee")},
            "pythons": {b: "fake-python" for b in ("open_webui", "cognee")}, "wheel": "fake-wheel", "legacy": "fake-legacy",
            "native_http_cap_per_instance": 200, "max_elapsed_seconds": 60, "rpc_timeout_seconds": 3,
            "max_consumer_calls": 192, "max_consumer_model_calls": 0,
            "max_source_rechecks_per_consumer": 8,
            "instances": {d + "." + a: {"state": d + "." + a, "backend": source if a == "source" else target}
                for d, (source, target) in m.DIRECTIONS.items() for a in ("source", "N", "G")}}

    def execute(self, *, fault=None, consumer=None):
        registry = {}; out = self.root / "run"; out.mkdir()
        result = m.execute(self.plan, out, rpc_factory=lambda *args, **kwargs:
            NativeFixture(*args, registry=registry, fault=fault, **kwargs), input_check=lambda *a, **k: None,
            consumer=consumer)
        return result, registry, out

    def test_both_directions_actual_export_and_equal_N_G_reads_with_independent_legal_fact(self):
        result, registry, out = self.execute()
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(result["registered_cells"], 48)
        self.assertEqual(result["direct_matched_cells"], 48)
        self.assertEqual(result["consumer_calls"], 0)
        self.assertFalse(result["downstream_effectiveness_evaluated"])
        self.assertFalse(result["old_four_vector_nulls_closed"])
        self.assertEqual(len(registry), 6)
        for direction in m.DIRECTIONS:
            self.assertEqual(registry[direction + ".N"].acl, {("alice_reader", "managed"), ("bob_reader", "managed")})
            self.assertEqual(registry[direction + ".G"].acl, set())
        cells = json.loads((out / "cells.json").read_text(encoding="utf-8"))
        for row in cells:
            self.assertEqual(row["source_status"], row["N_status"])
            self.assertEqual(row["source_status"], row["G_status"])
            self.assertEqual(row["G_native_direct_status"], "denied")
        barriers = json.loads((out / "barriers.json").read_text(encoding="utf-8"))
        self.assertEqual(len(barriers), 6)
        self.assertTrue(all(not b["N_changes"] for b in barriers if b["phase"] == "old_packet_replay"))
        all_http = json.loads((out / "gateway_all_transport.json").read_text(encoding="utf-8"))
        self.assertEqual([len(requests) for requests in all_http], [29, 29])
        self.assertTrue(all(requests[4]["status"] == 401 for requests in all_http))

    def test_same_callback_and_no_forbidden_or_nomemory_plaintext_enters_consumer(self):
        contexts = []
        def consumer(context):
            contexts.append(context)
            if not context["read_allowed"] or context["condition"] == "none":
                self.assertIsNone(context["memory_text"])
            if not context["read_allowed"] or context["condition"] == "none":
                self.assertIsNone(context["source_content"])
            self.assertEqual(set(context["principal"]), {"user_id", "agent_id"})
            self.assertNotIn("expected_answer", context)
            self.assertNotIn("credentials", context)
            return {"status": "ok", "kind": "instrumentation", "model_calls": 0, "answer": "UNKNOWN"}
        consumer.max_model_calls_per_context = 0
        result, _, _ = self.execute(consumer=consumer)
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(result["consumer_calls"], 192)
        self.assertEqual(len(contexts), 192)
        self.assertEqual(result["consumer_reported_model_calls"], 0)
        self.assertFalse(result["downstream_effectiveness_evaluated"])
        for start in range(0, len(contexts), 4):
            group = contexts[start:start+4]
            self.assertEqual([x["condition"] for x in group], list(m.CONDITIONS))
            self.assertEqual(len({x["query"] for x in group}), 1)
            self.assertEqual(len({json.dumps(x["principal"], sort_keys=True) for x in group}), 1)

    def test_source_transport_failure_is_unknown_and_all_registered_cells_are_retained(self):
        result, registry, out = self.execute(fault="source_error")
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "native_auth_or_execution_error")
        self.assertEqual(list(registry), ["webui_to_cognee.source"])
        self.assertEqual(len(json.loads((out / "cells.json").read_text())), 48)
        self.assertEqual(result["not_run_cells"], 48)

    def test_current_source_callable_is_real_bounded_and_expires_after_callback(self):
        saved = []
        def consumer(context):
            check = context["current_source_read"]
            result = check(context["principal"], context["object_id"])
            self.assertEqual(result["decision"], "allow" if context["read_allowed"] else "deny")
            self.assertEqual(check({"user_id": "unrelated", "agent_id": "unrelated"}, context["object_id"])["decision"], "unknown")
            saved.append((check, context["principal"], context["object_id"]))
            return {"status": "ok", "kind": "instrumentation", "model_calls": 0}
        consumer.max_model_calls_per_context = 0
        # One extra native request per callback uses 96 per source, within cap.
        result, registry, out = self.execute(consumer=consumer)
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(len(saved), 192)
        for check, principal, oid in saved:
            self.assertEqual(check(principal, oid), {"decision": "unknown", "code": "consumer_scope_closed"})
        for direction in m.DIRECTIONS:
            calls = registry[direction + ".source"].calls
            self.assertEqual(sum(c["command"] == "read_raw" for c in calls), 126)
        for row in json.loads((out / "cells.json").read_text()):
            self.assertTrue(all(x["native_source_rechecks"] == 1 for x in row["consumer"].values()))

    def test_unknown_source_acl_does_not_start_targets(self):
        result, registry, _ = self.execute(fault="unknown_acl")
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "source_acl_unrepresentable_principal_or_action")
        self.assertEqual(list(registry), ["webui_to_cognee.source"])

    def test_native_G_bypass_is_a_safety_failure_not_gateway_success(self):
        result, _, out = self.execute(fault="g_bypass")
        self.assertEqual(result["failure"]["code"], "gateway_native_owner_credentials_not_confined")
        cells = json.loads((out / "cells.json").read_text())
        failed = [x for x in cells if x["status"] == "safety_failure"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["failure_class"], "native_gateway_confinement_failure")

    def test_refusal_still_containing_secret_is_never_counted_as_native_denial(self):
        result, _, _ = self.execute(fault="deny_contains_secret")
        self.assertEqual(result["failure"]["code"], "denial_contains_registered_secret")
        self.assertEqual(result["new_unauthorized_disclosure_cells"], 1)
        self.assertEqual(result["safety_failure_cells"], 1)
        self.assertEqual(result["direct_matched_cells"], 0)

    def test_undeclared_consumer_is_not_invoked_when_model_budget_is_zero(self):
        side_effects = []
        def consumer(context):
            side_effects.append("would-send-model-request")
            return {"status": "ok", "model_calls": 1}
        result, _, out = self.execute(consumer=consumer)
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(result["direct_matched_cells"], 48)
        self.assertEqual(result["consumer_calls"], 0)
        self.assertEqual(result["consumer_reported_model_calls"], 0)
        self.assertEqual(side_effects, [])
        rows = json.loads((out / "cells.json").read_text())
        self.assertEqual(len(rows), 48)
        receipts = [receipt for row in rows for receipt in row["consumer"].values()]
        self.assertEqual(len(receipts), 192)
        self.assertTrue(all(r["status"] == "not_run" and r["failure_class"] == "budget_blocked"
                            and r["error"] == "consumer_model_budget_exhausted" for r in receipts))

    def test_declared_model_reservation_is_checked_before_next_callback(self):
        self.plan["max_consumer_model_calls"] = 1
        side_effects = []
        def consumer(context):
            self.assertEqual(context["remaining_model_calls"], 1)
            self.assertEqual(context["reserved_model_calls"], 1)
            side_effects.append("mock-send")
            return {"status": "ok", "model_calls": 1}
        consumer.max_model_calls_for_context = lambda ctx: 1
        result, _, out = self.execute(consumer=consumer)
        self.assertEqual(result["status"], "fake_protocol_completed", result["failure"])
        self.assertEqual(side_effects, ["mock-send"])
        self.assertEqual(result["consumer_calls"], 1)
        self.assertEqual(result["consumer_reported_model_calls"], 1)
        receipts = [r for row in json.loads((out / "cells.json").read_text()) for r in row["consumer"].values()]
        self.assertEqual(sum(r.get("failure_class") == "budget_blocked" for r in receipts), 191)

    def test_last_callback_exceeding_its_zero_declaration_preserves_budget_reason(self):
        calls = []
        def consumer(context):
            calls.append(context["condition"])
            return {"status": "ok", "model_calls": int(len(calls) == 192)}
        consumer.max_model_calls_per_context = 0
        result, _, out = self.execute(consumer=consumer)
        self.assertEqual(len(calls), 192)
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "consumer_model_budget_contract_violation")
        self.assertEqual(result["consumer_reported_model_calls"], 1)
        rows = json.loads((out / "cells.json").read_text())
        self.assertEqual(len(rows), 48)
        self.assertEqual(rows[-1]["consumer"]["none"]["error"], "consumer_model_budget_contract_violation")

    def test_last_callback_invalid_receipt_preserves_contract_error(self):
        calls = []
        def consumer(context):
            calls.append(context["condition"])
            return {"status": "invalid" if len(calls) == 192 else "ok", "model_calls": 0}
        consumer.max_model_calls_per_context = 0
        result, _, out = self.execute(consumer=consumer)
        self.assertEqual(len(calls), 192)
        self.assertEqual(result["failure"]["code"], "consumer_receipt_invalid")
        rows = json.loads((out / "cells.json").read_text())
        self.assertEqual(rows[-1]["consumer"]["none"]["error"], "consumer_receipt_invalid")

    def test_last_callback_exception_keeps_safe_exception_class(self):
        calls = []
        def consumer(context):
            calls.append(context["condition"])
            if len(calls) == 192:
                raise RuntimeError("test-only exception body should not be persisted")
            return {"status": "ok", "model_calls": 0}
        consumer.max_model_calls_per_context = 0
        result, _, out = self.execute(consumer=consumer)
        self.assertEqual(len(calls), 192)
        self.assertEqual(result["failure"]["code"], "consumer_execution_unknown")
        rows = json.loads((out / "cells.json").read_text())
        self.assertEqual(rows[-1]["consumer"]["none"]["error"], "RuntimeError")

    def _gateway_fault_run(self, corrupt):
        original_dispatch = m.PolicyProjectionGateway.dispatch
        facts = {row["object_id"]: row["text"] for row in self.plan["facts"]}
        def dispatch(gateway, caller, raw):
            reply = original_dispatch(gateway, caller, raw)
            request = json.loads(raw)
            if reply.get("decision") == "deny" and request.get("object_id") in facts:
                corrupt(reply, request["object_id"], facts[request["object_id"]])
            return reply
        with patch.object(m.PolicyProjectionGateway, "dispatch", dispatch):
            return self.execute()

    def test_gateway_denial_still_containing_secret_is_a_safety_failure(self):
        def corrupt(reply, oid, secret):
            reply["data"] = {"object_id": oid, "text": secret}
        result, _, out = self._gateway_fault_run(corrupt)
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "gateway_denial_contains_registered_secret")
        self.assertEqual(result["safety_failure_cells"], 1)
        self.assertEqual(result["new_unauthorized_disclosure_cells"], 1)
        rows = json.loads((out / "cells.json").read_text())
        self.assertEqual(len(rows), 48)
        self.assertTrue(any(r.get("failure_class") == "new_unauthorized_disclosure" for r in rows))

    def test_gateway_denial_secret_in_other_field_is_detected_from_complete_body(self):
        def corrupt(reply, oid, secret):
            self.assertIsNone(reply["data"])
            reply["reason"] = secret
        result, _, _ = self._gateway_fault_run(corrupt)
        self.assertEqual(result["failure"]["code"], "gateway_denial_contains_registered_secret")
        self.assertEqual(result["new_unauthorized_disclosure_cells"], 1)

    def test_gateway_json_escape_spelling_does_not_hide_a_decoded_secret(self):
        original_request = m.GatewayHTTP.request
        secrets = [row["text"] for row in self.plan["facts"]]
        def request(client, *args, **kwargs):
            result = original_request(client, *args, **kwargs)
            parsed = result.get("parsed")
            if result["status"] == 403 and isinstance(parsed, dict) and parsed.get("decision") == "deny":
                secret = secrets[0]
                parsed["reason"] = secret
                escaped = "\\u%04x" % ord(secret[0]) + secret[1:]
                result["raw_body"] = json.dumps(parsed).replace(secret, escaped)
                self.assertNotIn(secret, result["raw_body"])
                self.assertEqual(json.loads(result["raw_body"])["reason"], secret)
            return result
        with patch.object(m.GatewayHTTP, "request", request):
            result, _, _ = self.execute()
        self.assertEqual(result["failure"]["code"], "gateway_denial_contains_registered_secret")
        self.assertEqual(result["new_unauthorized_disclosure_cells"], 1)

    def test_gateway_http_status_must_match_decision(self):
        def corrupt(reply, oid, secret):
            reply["http_status"] = 200
        result, _, _ = self._gateway_fault_run(corrupt)
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "gateway_read_unknown")

    def test_gateway_denial_must_have_no_delivered_ids(self):
        def corrupt(reply, oid, secret):
            reply["delivered_fact_ids"] = [oid]
        result, _, _ = self._gateway_fault_run(corrupt)
        self.assertEqual(result["status"], "unverified_or_incomplete")
        self.assertEqual(result["failure"]["code"], "gateway_denial_payload_present")

    def test_unapproved_copy_stops_before_launch(self):
        self.plan["operator_consent"]["approved_for_controlled_synthetic_copy"] = False
        result, registry, _ = self.execute()
        self.assertEqual(result["failure"]["code"], "explicit_synthetic_copy_consent_required")
        self.assertEqual(registry, {})


if __name__ == "__main__":
    unittest.main()
