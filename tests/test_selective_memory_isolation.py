"""Synthetic safety checks for optional whole-record isolation, no real models."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import privacy
from memory_migration_study import selective_memory_isolation as isolation


def response(status="ok", *, findings=None, calls=1, error="semantic_uncertainty"):
    return {"status": status, "findings": findings or [], "errors": [] if status == "ok" else [error],
            "local_calls": calls, "elapsed_seconds": 0.01}


class Agent:
    max_local_calls = 1

    def __init__(self, outcomes=None):
        self.outcomes, self.calls = outcomes or {}, []

    def __call__(self, **kwargs):
        self.calls.append(deepcopy(kwargs))
        value = self.outcomes.get(kwargs["source_id"], response())
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


class SelectiveMemoryIsolationTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.policy = {"version": "v1", "protected_categories": ["CUSTOMER"]}
        self.payload = {"query": "What is the public colour?", "memories": [
            {"source_id": "uncertain", "text": "Orchid Consortium owns the hidden amber contract."},
            {"source_id": "public", "text": "The public colour is blue."}]}
        self.live = {"uncertain", "public"}
        self.auth_events = []

    def authorize(self, sid, actor, version):
        self.auth_events.append(sid)
        return sid in self.live and actor == "owner" and version == "v1"

    def contract(self, payload=None, groups=None):
        payload = payload or self.payload
        return isolation.bind_dependency_groups(payload, self.policy,
            groups or [[sid] for sid in privacy._sources(payload)])

    def prepare(self, agent, *, payload=None, policy=None, strategy="record", groups=True, **kwargs):
        payload = payload or self.payload
        binding = self.contract(payload) if groups is True else groups
        return isolation.prepare_selective_private_payload(payload, policy or self.policy, agent,
            actor_id="owner", request_id="request", authorizer=self.authorize,
            strategy=strategy, dependency_groups=binding, **kwargs)

    def restore(self, value, prepared):
        return privacy.restore_answer(value, prepared["mapping"], actor_id="owner", request_id="request",
            policy_version="v1", authorizer=self.authorize, sensitivity_policy=self.policy)

    def test_record_isolation_makes_new_map_without_any_quarantined_literal_evidence(self):
        agent = Agent({"uncertain": response("needs_review")})
        result = self.prepare(agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["isolation"]["quarantined_source_ids"], ["uncertain"])
        self.assertEqual(result["isolation"]["kept_source_ids"], ["public"])
        self.assertEqual(set(result["mapping"]._memories), {"public"})
        self.assertNotIn("Orchid", json.dumps(result["payload"]))
        for phrase in ("Orchid Consortium", "hidden amber contract", "amber"):
            self.assertEqual(self.restore(phrase, result)["error"], "literal_has_no_memory_evidence")
        self.assertEqual(self.restore("blue", result)["answer"], "blue")
        self.assertEqual(len(agent.calls), 3)
        self.assertEqual(result["isolation"]["local_calls"], 3)
        self.assertEqual(result["isolation"]["agent_invocations"], 3)
        self.assertEqual(result["isolation"]["cache_replay_invocations"], 2)
        self.assertEqual(self.auth_events[:2], ["uncertain", "public"])
        self.assertTrue(all(call["rule_findings"] == [] for call in agent.calls))

    def test_request_default_does_not_silently_enable_isolation(self):
        result = isolation.prepare_selective_private_payload(self.payload, self.policy,
            Agent({"uncertain": response("needs_review")}), actor_id="owner", request_id="request",
            authorizer=self.authorize, dependency_groups=self.contract())
        self.assertEqual(result["error"], "request_source_detection_incomplete")
        self.assertIsNone(result["mapping"])
        self.assertEqual(result["isolation"]["effective_strategy"], "request")

    def test_no_independence_declaration_conservatively_blocks_whole_request(self):
        result = self.prepare(Agent({"uncertain": response("needs_review")}), groups=None)
        self.assertEqual(result["error"], "query_depends_on_quarantined_memory")
        self.assertEqual(result["isolation"]["dependency_mode"], "all_sources_dependent")
        self.assertIsNone(result["payload"])

    def test_dependency_group_quarantines_good_records_that_depend_on_bad_record(self):
        payload = deepcopy(self.payload)
        payload["memories"].append({"source_id": "independent", "text": "The independent value is green."})
        self.live.add("independent")
        contract = self.contract(payload, [["__query__"], ["uncertain", "public"], ["independent"]])
        result = self.prepare(Agent({"uncertain": response("needs_review")}), payload=payload, groups=contract)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(set(result["mapping"]._memories), {"independent"})
        self.assertEqual(result["isolation"]["quarantined_source_ids"], ["uncertain", "public"])
        self.assertEqual(self.restore("blue", result)["error"], "literal_has_no_memory_evidence")

    def test_query_uncertainty_and_query_dependency_always_block(self):
        result = self.prepare(Agent({"__query__": response("needs_review")}))
        self.assertEqual(result["error"], "query_detection_incomplete")
        contract = self.contract(groups=[["__query__", "uncertain"], ["public"]])
        result = self.prepare(Agent({"uncertain": response("needs_review")}), groups=contract)
        self.assertEqual(result["error"], "query_depends_on_quarantined_memory")

    def test_all_memories_quarantined_is_not_successful_empty_context(self):
        result = self.prepare(Agent({sid: response("needs_review") for sid in ("uncertain", "public")}))
        self.assertEqual(result["error"], "all_memories_quarantined")
        self.assertIsNone(result["payload"])

    def test_unauthed_source_cannot_be_hidden_by_isolation_and_no_agent_is_called(self):
        self.live.remove("uncertain")
        agent = Agent({"uncertain": response("needs_review")})
        result = self.prepare(agent)
        self.assertEqual(result["error"], "memory_authorization_failed")
        self.assertEqual(agent.calls, [])

    def test_source_coverage_limit_is_quarantinable_but_preserves_original_reason(self):
        raw = response("needs_review", calls=0, error="input_budget_exceeded")
        raw["relation_errors"] = ["candidate_budget_exceeded"]
        result = self.prepare(Agent({"uncertain": raw}))
        self.assertEqual(result["status"], "ok")
        detail = next(row for row in result["isolation"]["source_outcomes"] if row["source_id"] == "uncertain")
        self.assertEqual(detail["failure_kind"], "coverage")
        self.assertEqual(detail["relation_errors"], ["candidate_budget_exceeded"])
        self.assertIn("input_budget_exceeded", detail["errors"])
        self.assertEqual(result["isolation"]["local_calls"], 2)

    def test_global_errors_schema_and_wrong_source_binding_never_become_isolated_success(self):
        variants = [response("needs_review", error=error) for error in (
            "local_transport_failed", "format_or_span_invalid", "invalid_input_or_policy", "local_health_failed")]
        variants += [dict(response(), source_id="public"), dict(response(), policy_sha256="0"*64),
                     dict(response(), local_calls_complete=False), dict(response(), permissions=["public"]),
                     response("needs_review", findings=[{"quote": "not present", "category": "CUSTOMER", "start": 0, "end": 11}])]
        for raw in variants:
            with self.subTest(raw=raw):
                result = self.prepare(Agent({"uncertain": raw}))
                self.assertEqual(result["status"], "needs_review")
                self.assertIsNone(result["mapping"])
                self.assertEqual(result["isolation"]["source_outcomes"][-1]["failure_kind"], "global")

    def test_exception_or_unverifiable_accounting_keeps_failure_and_observed_call_count(self):
        for raw in (RuntimeError("private error detail"), dict(response(), local_calls="1")):
            result = self.prepare(Agent({"uncertain": raw}))
            self.assertEqual(result["status"], "needs_review")
            self.assertFalse(result["isolation"]["local_calls_complete"])
            self.assertEqual(result["isolation"]["local_calls"], 1)  # query's completed call
            self.assertEqual(result["isolation"]["agent_invocations"], 2)
            self.assertNotIn("private error detail", json.dumps(result["isolation"]))

    def test_declared_incomplete_accounting_and_property_errors_are_not_hidden(self):
        result = self.prepare(Agent({"uncertain": dict(response(), local_calls_complete=False)}))
        self.assertEqual(result["error"], "invalid_agent_accounting")
        self.assertFalse(result["isolation"]["local_calls_complete"])
        class BrokenContract:
            @property
            def max_local_calls(self):
                raise ValueError("private source text")
        result = self.prepare(BrokenContract())
        self.assertEqual(result["error"], "invalid_input_or_policy")
        self.assertNotIn("private source text", json.dumps(result))

    def test_total_budget_is_checked_before_any_agent_entry(self):
        agent = Agent()
        result = self.prepare(agent, max_local_calls=2)
        self.assertEqual(result["error"], "total_call_budget_exceeded")
        self.assertEqual(agent.calls, [])

    def test_unsupported_fine_grained_strategies_are_explicit_record_fallbacks(self):
        for strategy in ("sentence", "position"):
            result = self.prepare(Agent({"uncertain": response("needs_review")}), strategy=strategy)
            self.assertEqual(result["status"], "ok")
            self.assertFalse(result["isolation"]["strategy_supported"])
            self.assertEqual(result["isolation"]["effective_strategy"], "record")
            self.assertEqual(result["isolation"]["fallback_reason"], "unsupported_complete_boundary_contract")
            self.assertEqual(set(result["mapping"]._memories), {"public"})

    def test_quarantined_token_and_query_only_token_cannot_restore(self):
        old_detection = privacy.detect_sensitive(self.payload, self.policy, mode="agent", agent=Agent({
            "uncertain": response(findings=[{"quote": "Orchid Consortium", "category": "CUSTOMER", "start": 0, "end": 17}])}))
        old = privacy.prepare_private_payload(self.payload, old_detection, actor_id="owner", request_id="request",
            policy_version="v1", authorizer=self.authorize, sensitivity_policy=self.policy)
        old_token = next(iter(old["mapping"]._entries))
        result = self.prepare(Agent({"uncertain": response("needs_review")}))
        self.assertEqual(self.restore(old_token, result)["error"], "unknown_or_embedded_token")
        payload = deepcopy(self.payload)
        payload["query"] = "Is Orchid Consortium allowed?"
        agent = Agent({"uncertain": response("needs_review"), "__query__": response(findings=[{
            "quote": "Orchid Consortium", "category": "CUSTOMER", "start": 3, "end": 20}])})
        result = self.prepare(agent, payload=payload)
        token = next(iter(result["mapping"]._entries))
        self.assertEqual(result["mapping"]._entries[token].sources, ())
        self.assertEqual(self.restore(token, result)["error"], "query_only_value_has_no_evidence")

    def test_revocation_before_restoration_is_enforced_for_literal_and_token(self):
        payload = deepcopy(self.payload)
        payload["memories"][1]["text"] = "Maple Circle has colour blue."
        agent = Agent({"uncertain": response("needs_review"), "public": response(findings=[{
            "quote": "Maple Circle", "category": "CUSTOMER", "start": 0, "end": 12}])})
        result = self.prepare(agent, payload=payload)
        token = next(iter(result["mapping"]._entries))
        self.assertEqual(self.restore(token, result)["answer"], "Maple Circle")
        self.live.remove("public")
        self.assertEqual(self.restore(token, result)["error"], "restoration_authorization_failed")
        self.assertEqual(self.restore("blue", result)["error"], "restoration_authorization_failed")

    def test_revocation_during_detection_cannot_be_hidden_by_quarantine(self):
        parent = self
        class Revoking(Agent):
            def __call__(self, **kwargs):
                raw = super().__call__(**kwargs)
                if kwargs["source_id"] == "uncertain":
                    parent.live.remove("uncertain")
                return raw
        result = self.prepare(Revoking({"uncertain": response("needs_review")}))
        self.assertEqual(result["error"], "memory_authorization_changed")
        self.assertIsNone(result["mapping"])

    def test_dependency_binding_and_partition_are_not_guessed_or_reused_after_changes(self):
        contract = self.contract()
        changed = deepcopy(self.payload)
        changed["memories"][1]["text"] += " altered"
        result = self.prepare(Agent(), payload=changed, groups=contract)
        self.assertEqual(result["error"], "dependency_binding_mismatch")
        for groups in ([["__query__"], ["uncertain"]], [["__query__"], ["uncertain", "public"], ["public"]]):
            with self.assertRaises(ValueError):
                self.contract(groups=groups)

    def test_reserved_input_and_invalid_review_findings_are_never_silently_discarded(self):
        payload = deepcopy(self.payload)
        payload["memories"][0]["text"] += " [PVT_forged]"
        agent = Agent({"uncertain": response("needs_review")})
        result = self.prepare(agent, payload=payload)
        self.assertEqual(result["error"], "reserved_token_in_input")
        self.assertEqual(agent.calls, [])

    def test_metadata_contains_no_text_or_mapping_and_original_inputs_are_stable(self):
        before = deepcopy(self.payload)
        result = self.prepare(Agent({"uncertain": response("needs_review")}))
        self.assertEqual(self.payload, before)
        diagnostics = json.dumps({"metadata": result["metadata"], "isolation": result["isolation"]})
        for private in ("Orchid Consortium", "hidden amber contract", "public colour", "_entries", "[PVT_"):
            self.assertNotIn(private, diagnostics)
        with self.assertRaises(TypeError):
            json.dumps(result["mapping"])


if __name__ == "__main__":
    unittest.main()
