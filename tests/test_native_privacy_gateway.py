"""Fake-only native privacy gate checks; no client, model or credentials."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import native_privacy_gateway as gw
from memory_migration_study.native_agent_protocol import NativeAgentBroker

VALUE = "Granite Mutual"
SOURCE_ONLY = "SOURCE_ONLY_PRIVATE_CANARY_7391"


class NativePrivacyGatewayTests(unittest.TestCase):
    def setUp(self):
        gw.RESULTS_ROOT.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="native_privacy_fake_", dir=gw.RESULTS_ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "recipient_workspace"
        self.workspace.mkdir(); (self.workspace / ".git").mkdir()
        source = "Customer = " + VALUE + "\nSource only = " + SOURCE_ONLY
        start = source.index(VALUE)
        self.raw = {"record_id": "r1", "text": VALUE,
                    "source": {"source_id": "trusted-source", "text": source},
                    "source_start": start, "source_end": start + len(VALUE),
                    "source_readers": ["A", "B"], "recipient_readers": ["A", "B"],
                    "target_readers": ["A", "B"], "export_allowed": True, "copy_allowed": True}
        self.case = {"case_id": "gateway", "actors": [
            {"actor_id": "A", "user_id": "alice", "agent_id": "AgentA", "workspace_id": "source-workspace"},
            {"actor_id": "B", "user_id": "alice", "agent_id": "AgentB", "workspace_id": self.workspace.name},
            {"actor_id": "other", "user_id": "mallory", "agent_id": "AgentB", "workspace_id": "other-workspace"}],
            "records": [self.raw]}
        self.broker = NativeAgentBroker(self.case, key=b"x" * 32)
        self.packet = self.broker.export(["r1"], sender_actor_id="A", recipient_actor_id="B", transfer_id="handoff")
        self.policy = {"version": "privacy-v1", "protected_categories": ["CUSTOMER", "PROJECT"],
                       "instructions": "Protect declared business identifiers.",
                       "entity_registry": [{"value": VALUE, "category": "CUSTOMER"}]}
        self.allowed = True
        self.auth_calls = []

    def authorizer(self, rid, actor, version):
        self.auth_calls.append((rid, actor, version))
        return self.allowed and rid == "r1" and actor == "B" and version == "privacy-v1"

    def arguments(self):
        return {"broker": self.broker, "sender_actor_id": "A", "actor_id": "B", "agent_id": "AgentB",
                "workspace": self.workspace, "request_id": "request-1", "authorizer": self.authorizer}

    def prepare(self, query="Who is " + VALUE + "?", **changes):
        options = self.arguments(); options.update(changes)
        return gw.prepare_native_private_memory(self.packet, query, self.policy, **options)

    def ready(self, **changes):
        result = self.prepare(**changes)
        self.assertEqual(result["status"], "ok", result)
        (self.workspace / "AGENTS.md").write_text(result["agents_md"], encoding="utf-8", newline="\n")
        token = gw._TOKEN.search(result["agents_md"]).group()
        return result, token

    def finish(self, result, answer, policy=None, **changes):
        arguments = self.arguments(); arguments.update(changes)
        return gw.restore_native_private_answer(answer, result["request"], self.policy if policy is None else policy,
                                                **arguments)

    def test_real_existing_pipeline_roundtrip_without_writing_raw_value(self):
        result = self.prepare()
        self.assertEqual(result["status"], "ok", result)
        self.assertFalse((self.workspace / "AGENTS.md").exists())
        self.assertNotIn(VALUE, result["agents_md"] + result["question"] + json.dumps(result["metadata"]))
        self.assertNotIn(SOURCE_ONLY, result["agents_md"] + result["question"])
        (self.workspace / "AGENTS.md").write_text(result["agents_md"], encoding="utf-8")
        token = gw._TOKEN.search(result["agents_md"]).group()
        restored = self.finish(result, token)
        self.assertEqual(restored["answer"], VALUE)
        self.assertEqual(restored["enforcement_scope"], "external_gated")
        self.assertIs(restored["native_acl"], False)
        self.assertGreaterEqual(len(self.auth_calls), 3)
        self.assertEqual(list(self.workspace.rglob("*.log")), [])

    def test_query_is_synchronously_masked_but_not_exported(self):
        result, token = self.ready()
        state = json.loads(result["request"]._state)
        self.assertNotIn(VALUE, state["prepared_payload"]["query"])
        self.assertIn(token, state["prepared_payload"]["query"])
        self.assertEqual(result["question"], gw.QUESTION)
        self.assertNotIn("Who is", result["agents_md"])

    def test_both_native_question_and_agents_pass_existing_egress(self):
        with patch.object(gw, "validate_outbound", wraps=gw.validate_outbound) as validate:
            result = self.prepare()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(validate.call_count, 2)
        native = validate.call_args_list[-1].args[1]["payload"]
        self.assertEqual(native["query"], result["question"])
        self.assertEqual(native["memories"][0]["text"], result["agents_md"])

    def test_detection_is_not_called_before_current_authorization(self):
        self.allowed = False
        with patch.object(gw, "detect_sensitive") as detect:
            result = self.prepare()
        self.assertEqual(result["error"], "current_record_authorization_failed")
        detect.assert_not_called()

    def test_unknown_rechecks_authority_and_is_consumed(self):
        result, _ = self.ready()
        self.allowed = False
        finished = self.finish(result, "UNKNOWN")
        self.assertEqual(finished["error"], "current_record_authorization_failed")
        self.allowed = True
        self.assertEqual(self.finish(result, "UNKNOWN")["error"], "native_request_unknown_or_replayed")

    def test_unknown_with_valid_authority_remains_unknown(self):
        result, _ = self.ready()
        self.assertEqual(self.finish(result, "UNKNOWN")["answer"], "UNKNOWN")

    def test_broker_revocation_blocks_unknown_and_exact_token(self):
        result, token = self.ready()
        self.broker.revoke("r1")
        self.assertEqual(self.finish(result, token)["error"], "broker_record_revoked")
        self.assertEqual(self.finish(result, "UNKNOWN")["error"], "native_request_unknown_or_replayed")

    def test_record_version_change_blocks_old_packet(self):
        result, token = self.ready()
        self.broker.replace_record(deepcopy(self.raw))
        self.assertEqual(self.finish(result, token)["error"], "broker_packet_current_fact_or_grant_changed")

    def test_same_version_full_policy_change_is_blocked(self):
        result, token = self.ready()
        changed = deepcopy(self.policy); changed["instructions"] += " Changed."
        self.assertEqual(self.finish(result, token, policy=changed)["error"], "native_request_scope_changed")

    def test_cross_actor_agent_request_are_blocked(self):
        for change in ({"actor_id": "other"}, {"agent_id": "WrongAgent"}, {"request_id": "another-request"}):
            with self.subTest(change=change):
                memory = self.workspace / "AGENTS.md"
                if memory.exists(): memory.unlink()
                result, token = self.ready()
                self.assertEqual(self.finish(result, token, **change)["status"], "blocked")

    def test_same_basename_at_another_canonical_path_is_blocked(self):
        result, token = self.ready()
        other = self.base / "elsewhere" / self.workspace.name
        other.mkdir(parents=True); (other / ".git").mkdir()
        (other / "AGENTS.md").write_text(result["agents_md"], encoding="utf-8")
        self.assertEqual(self.finish(result, token, workspace=other)["error"], "native_request_scope_changed")

    def test_workspace_basename_must_match_signed_audience(self):
        other = self.base / "wrong-workspace"
        other.mkdir(); (other / ".git").mkdir()
        self.assertEqual(self.prepare(workspace=other)["error"], "workspace_binding_invalid")

    def test_fresh_workspace_and_git_boundary_are_required(self):
        (self.workspace / "AGENTS.md").write_text(VALUE, encoding="utf-8")
        self.assertEqual(self.prepare()["error"], "target_workspace_not_fresh")
        (self.workspace / "AGENTS.md").unlink(); (self.workspace / ".git").rmdir()
        self.assertEqual(self.prepare()["error"], "workspace_git_boundary_missing")

    def test_extra_context_and_dangling_native_memory_link_are_rejected(self):
        (self.workspace / "answers.json").write_text("not an allowed native input", encoding="utf-8")
        self.assertEqual(self.prepare()["error"], "unexpected_native_context")
        (self.workspace / "answers.json").unlink()
        original = Path.is_symlink
        def linked(path):
            return path.name == "AGENTS.md" or original(path)
        with patch.object(Path, "is_symlink", linked):
            self.assertEqual(self.prepare()["error"], "target_workspace_not_fresh")

    def test_missing_and_unknown_policy_fields_are_rejected(self):
        for policy in ({}, {**self.policy, "expected_answer": VALUE},
                       {k: v for k, v in self.policy.items() if k != "instructions"}):
            with self.subTest(policy=policy):
                self.policy, old = policy, self.policy
                self.assertEqual(self.prepare()["error"], "policy_missing_or_unknown_fields")
                self.policy = old

    def test_packet_unknown_fields_are_not_ignored(self):
        self.packet["extra"] = "unexpected"
        self.assertEqual(self.prepare()["error"], "broker_packet_schema_fields")

    def test_multiple_packet_facts_are_not_cropped(self):
        case = deepcopy(self.case)
        second = deepcopy(self.raw); second["record_id"] = "r2"
        case["records"].append(second)
        broker = NativeAgentBroker(case, key=b"y" * 32)
        packet = broker.export(["r1", "r2"], sender_actor_id="A", recipient_actor_id="B", transfer_id="many")
        result = gw.prepare_native_private_memory(packet, "Who?", self.policy,
            **{**self.arguments(), "broker": broker, "authorizer": lambda *_: True})
        self.assertEqual(result["error"], "single_exact_value_required")
        self.assertIsNone(result["request"])

    def test_detector_needs_review_does_not_export_anything(self):
        def detector(**_):
            return {"status": "needs_review", "findings": [], "local_calls": 0,
                    "elapsed_seconds": 0.0, "errors": ["semantic_uncertainty"]}
        result = self.prepare(detector=detector, mode="agent")
        self.assertEqual(result["error"], "sensitive_detection_requires_review")
        self.assertIsNone(result["agents_md"])

    def test_injected_detector_uses_original_local_contract_without_gold(self):
        observed = []
        def detector(**input):
            observed.append(input)
            findings = [{"quote": VALUE, "category": "CUSTOMER"}] if VALUE in input["text"] else []
            return {"status": "ok", "findings": findings, "local_calls": 0,
                    "elapsed_seconds": 0.0, "errors": []}
        self.policy.pop("entity_registry")
        result = self.prepare(detector=detector, mode="agent")
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(len(observed), 2)
        self.assertEqual(set(observed[0]), {"text", "source_id", "policy", "rule_findings"})
        self.assertNotIn("expected_answer", json.dumps(observed))

    def test_unmasked_or_partial_value_is_blocked_not_silently_exported(self):
        self.policy.pop("entity_registry")
        self.assertEqual(self.prepare()["error"], "single_masked_value_required")

    def test_query_only_token_is_not_an_exported_answer(self):
        self.policy["entity_registry"].append({"value": "SecretProject", "category": "PROJECT"})
        result, _ = self.ready(query="What about SecretProject?")
        state = json.loads(result["request"]._state)
        query_token = gw._TOKEN.search(state["prepared_payload"]["query"]).group()
        self.assertNotIn(query_token, result["agents_md"])
        self.assertEqual(self.finish(result, query_token)["error"], "native_answer_not_single_exported_value")

    def test_unknown_embedded_or_raw_secrets_cannot_bypass_restore(self):
        answers = ("[PVT_" + "B" * 24 + "_CUSTOMER_1]", "Refused: " + VALUE,
                   "Refused but " + VALUE, VALUE)
        for answer in answers:
            with self.subTest(answer=answer):
                memory = self.workspace / "AGENTS.md"
                if memory.exists(): memory.unlink()
                result, _ = self.ready()
                finished = self.finish(result, answer)
                self.assertEqual(finished["status"], "blocked")
                self.assertIsNone(finished["answer"])

    def test_installed_native_memory_is_bound_and_missing_is_not_accepted(self):
        result = self.prepare(); token = gw._TOKEN.search(result["agents_md"]).group()
        self.assertEqual(self.finish(result, token)["error"], "native_memory_not_installed_or_changed")
        result, token = self.ready()
        (self.workspace / "AGENTS.md").write_text("UNKNOWN", encoding="utf-8")
        self.assertEqual(self.finish(result, token)["error"], "native_memory_not_installed_or_changed")

    def test_handle_is_opaque_not_serializable_and_not_replayable(self):
        result, token = self.ready()
        request = result["request"]
        self.assertNotIn(VALUE, repr(request))
        for dump in (json.dumps, pickle.dumps):
            with self.assertRaises(TypeError): dump(request)
        with self.assertRaises(AttributeError): request._state = b"forged"
        self.assertEqual(self.finish(result, token)["answer"], VALUE)
        self.assertEqual(self.finish(result, token)["error"], "native_request_unknown_or_replayed")

    def test_unregistered_clone_and_tampered_hmac_are_rejected(self):
        result, token = self.ready(); request = result["request"]
        clone = gw.NativePrivateRequest(request._state, request._mapping, request._mac)
        self.assertEqual(self.finish({"request": clone}, token)["error"], "native_request_unknown_or_replayed")
        object.__setattr__(request, "_mac", b"x" * 32)
        self.assertEqual(self.finish(result, token)["error"], "native_request_integrity_invalid")

    def test_private_map_mutation_is_rejected(self):
        result, token = self.ready()
        mapping = result["request"]._mapping
        mapping._entries[token] = replace(mapping._entries[token], value="FORGED VALUE")
        self.assertEqual(self.finish(result, token)["error"], "native_request_integrity_invalid")


if __name__ == "__main__":
    unittest.main()
