"""Pure fake-transport tests for an optional, unvalidated semantic wrapper."""
import copy
import json
import unittest

from memory_migration_study import candidate_adjudicator as roles
from memory_migration_study import local_detector as runtime
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.privacy import detect_sensitive, restore_answer
from memory_migration_study.semantic_refinement import refine_semantics
from memory_migration_study.span_completion import LocalSpanCompleter


class FakeTransport:
    def __init__(self, content):
        self.content, self.posts = content, []

    def __call__(self, method, path, body=None):
        if (method, path) == ("GET", "/api/version"):
            return {"version": runtime.VERSION}
        if (method, path) == ("GET", "/api/tags"):
            return {"models": [{"name": runtime.MODEL, "digest": runtime.DIGEST}]}
        if (method, path) != ("POST", "/api/chat"):
            raise AssertionError("unexpected_network_route")
        self.posts.append(copy.deepcopy(body))
        return {"model": runtime.MODEL, "done": True, "done_reason": "stop", "message":
            {"role": "assistant", "content": json.dumps(self.content, ensure_ascii=False)},
            "prompt_eval_count": 200, "eval_count": 60}


class SemanticRefinementTests(unittest.TestCase):
    def policy(self, categories=None):
        return {"version": "semantic-wrapper-test", "protected_categories":
                ["CUSTOMER", "PROJECT"] if categories is None else categories}

    def fixture(self, text="A customer is a role. Birch is the actual name.", *, query="", spans=None, policy=None):
        payload = {"query": query, "memories": [{"source_id": "m", "text": text}]}
        policy = policy or self.policy()
        spans = spans if spans is not None else [("m", "customer", "CUSTOMER"), ("m", "Birch", "CUSTOMER")]
        by_source = {"m": [], "__query__": []}
        for sid, quote, category in spans:
            source = query if sid == "__query__" else text
            start = source.index(quote)
            by_source[sid].append({"quote": quote, "start": start, "end": start+len(quote), "category": category})
        def instrument(**kwargs):
            return {"status": "ok", "errors": [], "findings": by_source[kwargs["source_id"]],
                    "local_calls": 0, "elapsed_seconds": 0.0}
        baseline = detect_sensitive(payload, policy, agent=instrument, mode="agent")
        self.assertEqual(baseline["status"], "ok", baseline)
        pool = propose_candidates(payload, policy, baseline["findings"])
        self.assertEqual(pool["status"], "candidates_only", pool)
        return payload, policy, baseline, pool

    def adjudicate(self, payload, policy, pool, decide=None):
        rows = []
        for candidate in pool["candidates"]:
            role = decide(candidate) if decide else ("generic_role" if candidate["quote"].casefold() == "customer" else "value")
            rows.append({"cid": candidate["cid"], "role": role,
                         "category": candidate["proposed_category"] if role == "value" else None})
        transport = FakeTransport({"verdicts": rows})
        result = roles.LocalCandidateAdjudicator(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(len(transport.posts), 0 if not pool["candidates"] else 1)
        return result

    def complete(self, payload, policy, pool, quote):
        rows = [{"cid": candidate["cid"], "quote": quote(candidate) if callable(quote) else quote}
                for candidate in pool["candidates"] if candidate["proposed_category"] in
                {"PERSON", "ADDRESS", "CUSTOMER", "PROJECT"}]
        transport = FakeTransport({"completions": rows})
        return LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)

    def keys(self, result):
        return {(item["source_id"], item["start"], item["end"], item["category"]) for item in result["findings"]}

    def test_bound_roles_filter_only_exact_candidate_and_keep_historical_cost(self):
        payload, policy, base, pool = self.fixture()
        adjudication = self.adjudicate(payload, policy, pool)
        before = copy.deepcopy((payload, policy, base, pool, adjudication))
        result = refine_semantics(payload, policy, base, pool=pool, adjudication=adjudication)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual((payload, policy, base, pool, adjudication), before)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(payload["memories"][0]["text"][result["findings"][0]["start"]:result["findings"][0]["end"]], "Birch")
        for field in ("local_calls", "local_calls_complete", "agent_elapsed_seconds", "agent_observations"):
            self.assertEqual(result[field], base[field])
        self.assertEqual(result["local_counts"], {"local_encoder": 0, "local_generation": 1, "unknown": 0})
        self.assertTrue(result["local_counts_complete"])
        self.assertTrue(result["semantic_refinement"]["optional_unvalidated"])

    def test_failed_baseline_or_stage_cannot_upgrade(self):
        payload, policy, base, pool = self.fixture()
        adjudication = self.adjudicate(payload, policy, pool)
        for broken in (dict(base, status="needs_review"), dict(base, errors=["local_failure"]),
                       dict(base, local_calls_complete=False), dict(base, local_calls=True)):
            self.assertEqual(refine_semantics(payload, policy, broken, pool=pool,
                                             adjudication=adjudication)["status"], "needs_review")
        for changed in ({"status": "needs_review"}, {"errors": ["semantic_uncertainty"]}, {"error": "failure"}):
            self.assertEqual(refine_semantics(payload, policy, base, pool=pool,
                adjudication=dict(adjudication, **changed))["status"], "needs_review")

    def test_pool_payload_fullpolicy_and_model_bindings_are_strict(self):
        payload, policy, base, pool = self.fixture()
        adjudication = self.adjudicate(payload, policy, pool)
        for key in ("payload_sha256", "policy_sha256", "full_policy_sha256", "pool_sha256", "digest", "model", "runtime"):
            with self.subTest(key=key):
                self.assertEqual(refine_semantics(payload, policy, base, pool=pool,
                    adjudication=dict(adjudication, **{key: "wrong"}))["status"], "needs_review")
        changed_policy = dict(policy, extra_host_policy="same normalized policy, different complete content")
        self.assertEqual(refine_semantics(payload, changed_policy, base, pool=pool,
                                         adjudication=adjudication)["status"], "needs_review")
        changed_pool = copy.deepcopy(pool)
        changed_pool["candidates"][0]["source_id"] = "__query__"
        self.assertEqual(refine_semantics(payload, policy, base, pool=changed_pool,
                                         adjudication=adjudication)["status"], "needs_review")

    def test_current_pool_cannot_omit_or_substitute_baseline_occurrences(self):
        payload, policy, base, _ = self.fixture()
        partial = propose_candidates(payload, policy, base["findings"][1:])
        adjudication = self.adjudicate(payload, policy, partial, decide=lambda candidate: "value")
        result = refine_semantics(payload, policy, base, pool=partial, adjudication=adjudication)
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("semantic_pool_not_current_baseline", result["errors"])

    def test_unknown_duplicate_missing_uncertain_and_category_switch_are_rejected(self):
        payload, policy, base, pool = self.fixture()
        original = self.adjudicate(payload, policy, pool)
        for mutation in ("unknown", "duplicate", "missing", "uncertain", "category", "extra", "fake_source", "unknown_role"):
            changed = copy.deepcopy(original)
            if mutation == "unknown":
                changed["verdicts"][0]["cid"] = "C9999"
            elif mutation == "duplicate":
                changed["verdicts"][1] = copy.deepcopy(changed["verdicts"][0])
            elif mutation == "missing":
                changed["verdicts"].pop()
            elif mutation == "uncertain":
                changed["verdicts"][0].update(role="uncertain", category=None)
            elif mutation == "category":
                changed["verdicts"][1]["category"] = "PROJECT"
                changed["findings"][0]["category"] = "PROJECT"
            elif mutation == "fake_source":
                changed["findings"][0]["source_id"] = "__query__"
            elif mutation == "unknown_role":
                changed["verdicts"][0]["role"] = "administrator"
            else:
                changed["verdicts"][0]["permissions"] = "admin"
            with self.subTest(mutation=mutation):
                self.assertEqual(refine_semantics(payload, policy, base, pool=pool,
                                                 adjudication=changed)["status"], "needs_review")

    def test_negative_roles_cannot_remove_other_five_sensitive_classes(self):
        text = "customer; 900 USD; 2035-06-28; 123456789012345678; audit@example.test; +1 212 555 0100"
        spans = [("m", quote, cat) for quote, cat in (("customer", "CUSTOMER"), ("900 USD", "AMOUNT"),
            ("2035-06-28", "DATE"), ("123456789012345678", "ID"), ("audit@example.test", "EMAIL"),
            ("+1 212 555 0100", "PHONE"))]
        payload, policy, base, pool = self.fixture(text, spans=spans,
            policy=self.policy(["CUSTOMER", "AMOUNT", "DATE", "ID", "EMAIL", "PHONE"]))
        adjudication = self.adjudicate(payload, policy, pool, decide=lambda candidate: "generic_role")
        result = refine_semantics(payload, policy, base, pool=pool, adjudication=adjudication)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual({item["category"] for item in result["findings"]}, {"AMOUNT", "DATE", "ID", "EMAIL", "PHONE"})

    def test_current_registry_is_independent_of_negative_roles(self):
        policy = dict(self.policy(), entity_registry=[{"value": "customer", "category": "CUSTOMER"}])
        payload, policy, base, pool = self.fixture(policy=policy)
        result = refine_semantics(payload, policy, base, pool=pool,
                                 adjudication=self.adjudicate(payload, policy, pool))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(self.keys(result), self.keys(base))
        self.assertEqual(result["semantic_refinement"]["registry_occurrences_retained"], 1)

    def test_identical_value_can_repropagate_removed_field_key_and_is_reported(self):
        text = "客户：客户"
        payload, policy, base, pool = self.fixture(text, spans=[("m", "客户", "CUSTOMER")], policy=self.policy(["CUSTOMER"]))
        adjudication = self.adjudicate(payload, policy, pool,
            decide=lambda candidate: "field_label" if candidate["start"] == 0 else "value")
        result = refine_semantics(payload, policy, base, pool=pool, adjudication=adjudication)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(self.keys(result), self.keys(base))
        self.assertEqual(len(result["semantic_refinement"]["closure_reintroduced_removed_occurrences"]), 1)

    def test_query_only_span_keeps_query_identity_and_cannot_restore(self):
        from memory_migration_study.boundary_preparation import prepare_boundary_payload
        payload, policy, base, pool = self.fixture("Status: ready", query="Birch", spans=[("__query__", "Birch", "CUSTOMER")])
        result = refine_semantics(payload, policy, base, pool=pool,
            adjudication=self.adjudicate(payload, policy, pool, decide=lambda candidate: "value"))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual({item["source_id"] for item in result["findings"]}, {"__query__"})
        prepared = prepare_boundary_payload(payload, result, actor_id="owner", request_id="query-test",
            policy_version=policy["version"], sensitivity_policy=policy, authorizer=lambda *args: True)
        self.assertEqual(prepared["status"], "ok", prepared)
        restored = restore_answer(prepared["payload"]["query"], prepared["mapping"], actor_id="owner",
            request_id="query-test", policy_version=policy["version"], sensitivity_policy=policy,
            authorizer=lambda *args: True)
        self.assertEqual(restored["status"], "blocked")
        self.assertEqual(restored["error"], "query_only_value_has_no_evidence")

    def test_role_module_cannot_promote_an_untyped_quoted_candidate(self):
        payload, policy, base, pool = self.fixture('The note says "Birch".', spans=[])
        adjudication = self.adjudicate(payload, policy, pool, decide=lambda candidate: "other")
        adjudication["verdicts"][0].update(role="value", category="CUSTOMER")
        _, adjudication["findings"] = roles._validate_verdicts({"verdicts": adjudication["verdicts"]}, pool,
                                                             policy["protected_categories"])
        result = refine_semantics(payload, policy, base, pool=pool, adjudication=adjudication)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["findings"], [])

    def test_completion_keeps_other_categories_and_rejects_tampered_grounding(self):
        text = "客户：青桐公司；Budget: 900 USD"
        payload, policy, base, pool = self.fixture(text,
            spans=[("m", "公司", "CUSTOMER"), ("m", "900 USD", "AMOUNT")], policy=self.policy(["CUSTOMER", "AMOUNT"]))
        completion = self.complete(payload, policy, pool, "青桐公司")
        self.assertEqual(completion["status"], "completed_only", completion)
        result = refine_semantics(payload, policy, base, pool=pool, completion=completion)
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(any(text[item["start"]:item["end"]] == "青桐公司" for item in result["findings"]))
        self.assertTrue(any(item["category"] == "AMOUNT" for item in result["findings"]))
        for field, value in (("source_id", "__query__"), ("start", 0), ("category", "AMOUNT"), ("cid", "C9999")):
            broken = copy.deepcopy(completion)
            broken["completions"][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(refine_semantics(payload, policy, base, pool=pool, completion=broken)["status"], "needs_review")
        broken = copy.deepcopy(completion)
        broken["findings"] = broken["findings"][:-1]
        self.assertEqual(refine_semantics(payload, policy, base, pool=pool, completion=broken)["status"], "needs_review")

    def test_complete_then_role_requires_a_new_pool_and_does_not_sum_prior_cost(self):
        payload, policy, base, old_pool = self.fixture("客户：青桐公司", spans=[("m", "公司", "CUSTOMER")])
        completed = refine_semantics(payload, policy, base, pool=old_pool,
                                    completion=self.complete(payload, policy, old_pool, "青桐公司"))
        self.assertEqual(completed["status"], "ok", completed)
        old_roles = self.adjudicate(payload, policy, old_pool, decide=lambda candidate: "value")
        self.assertEqual(refine_semantics(payload, policy, completed, pool=old_pool,
                                         adjudication=old_roles)["status"], "needs_review")
        fresh_pool = propose_candidates(payload, policy, completed["findings"])
        fresh_roles = self.adjudicate(payload, policy, fresh_pool, decide=lambda candidate: "value")
        final = refine_semantics(payload, policy, completed, pool=fresh_pool, adjudication=fresh_roles)
        self.assertEqual(final["status"], "ok", final)
        self.assertEqual(completed["local_counts"]["local_generation"], 1)
        self.assertEqual(final["local_counts"]["local_generation"], 1)
        self.assertEqual(final["local_calls"], base["local_calls"])

    def test_invalid_and_overbudget_costs_are_preserved_and_fail_closed(self):
        payload, policy, base, pool = self.fixture()
        original = self.adjudicate(payload, policy, pool)
        for count, typed in ((3, {"local_encoder": 0, "local_generation": 3, "unknown": 0}),
                             (1, {"local_encoder": 0, "local_generation": 0, "unknown": 1})):
            changed = dict(original, local_calls=count, generation_attempts=count, local_counts=typed)
            result = refine_semantics(payload, policy, base, pool=pool, adjudication=changed)
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["local_counts"], typed)
            self.assertFalse(result["local_counts_complete"])
        self.assertEqual(refine_semantics(payload, policy, base, pool=pool)["status"], "needs_review")
        self.assertEqual(refine_semantics(payload, policy, base, pool=pool, completion=original,
                                         adjudication=original)["status"], "needs_review")

    def test_missing_physical_attempts_do_not_claim_complete_cost_accounting(self):
        payload, policy, base, pool = self.fixture()
        original = self.adjudicate(payload, policy, pool)
        changed = dict(original, attempts=[])
        result = refine_semantics(payload, policy, base, pool=pool, adjudication=changed)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["local_counts"]["local_generation"], 1)
        self.assertFalse(result["local_counts_complete"])


if __name__ == "__main__":
    unittest.main()
