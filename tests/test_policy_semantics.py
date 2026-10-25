"""No model loading: actual new agent/refiner with fake loopback responses."""
import copy
import json
import unittest

from memory_migration_study import policy_semantics as semantic
from memory_migration_study.boundary_preparation import prepare_boundary_payload
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.privacy import _digest, detect_sensitive, restore_answer
from tests.test_candidate_adjudicator import FakeTransport, envelope


class PolicySemanticTests(unittest.TestCase):
    def test_discriminated_schema_rejects_role_quote_mismatches_without_conditionals(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("optional independent jsonschema validator is not installed")
        cids = ["C0001"]
        schema = semantic._schema(cids, 32)
        Draft202012Validator.check_schema(schema)
        validate = Draft202012Validator(schema).is_valid
        items = schema["properties"]["verdicts"]["items"]
        self.assertEqual(set(items), {"anyOf"})
        self.assertEqual(len(items["anyOf"]), 2)
        for branch in items["anyOf"]:
            self.assertEqual(set(branch), {"type", "additionalProperties", "required", "properties"})
            self.assertEqual(branch["type"], "object")
            self.assertFalse(branch["additionalProperties"])
            self.assertEqual(set(branch["required"]), {"cid", "role", "quote"})
            self.assertEqual(branch["properties"]["cid"]["enum"], cids)
        def body(role, quote, **extras):
            return {"verdicts": [{"cid": "C0001", "role": role, "quote": quote, **extras}]}
        self.assertTrue(validate(body("value", "Self-authored organization")))
        for quote in (None, "", "X"*33):
            self.assertFalse(validate(body("value", quote)))
        for role in semantic.ROLES[1:]:
            self.assertTrue(validate(body(role, None)))
            for quote in ("null", "Self-authored organization", ""):
                self.assertFalse(validate(body(role, quote)))
        self.assertFalse(validate(body("value", "Name", authorized=True)))
        self.assertFalse(validate({"verdicts": [{"cid": "foreign", "role": "value", "quote": "Name"}]}))
        self.assertEqual(cids, ["C0001"])

    def fixture(self, text="A customer is a role. Birch Group Ltd. is the name.", *, query="", spans=None, policy=None):
        payload = {"query": query, "memories": [{"source_id": "m", "text": text}]}
        policy = policy or {"version": "policy-semantics-tests", "protected_categories": ["CUSTOMER", "PROJECT", "AMOUNT"]}
        spans = spans if spans is not None else [("m", "customer", "CUSTOMER"), ("m", "Ltd.", "CUSTOMER")]
        by_source = {"m": [], "__query__": []}
        for sid, quote, category in spans:
            source = query if sid == "__query__" else text
            start = source.index(quote)
            by_source[sid].append({"quote": quote, "start": start, "end": start+len(quote), "category": category})
        def instrument(**kwargs):
            return {"status": "ok", "errors": [], "local_calls": 0, "elapsed_seconds": 0.0,
                "findings": by_source[kwargs["source_id"]]}
        base = detect_sensitive(payload, policy, agent=instrument, mode="agent")
        self.assertEqual(base["status"], "ok", base)
        base["inference_counts"] = {"local_encoder": 0, "local_generation": 0, "unknown": 0}
        pool = propose_candidates(payload, policy, base["findings"])
        self.assertEqual(pool["status"], "candidates_only", pool)
        return payload, policy, base, pool

    def rows(self, pool, decide=None):
        rows = []
        for candidate in pool["candidates"]:
            if candidate["proposed_category"] not in semantic.SEMANTIC_CATEGORIES:
                continue
            role, quote = decide(candidate) if decide else (
                ("generic_role", None) if candidate["quote"].casefold() == "customer" else ("value", "Birch Group Ltd."))
            rows.append({"cid": candidate["cid"], "role": role, "quote": quote})
        return {"verdicts": rows}

    def agent(self, responses, config=None):
        transport = FakeTransport([envelope(row) if not isinstance(row, Exception) else row for row in responses])
        return semantic.LocalPolicySemanticAgent(config, transport), transport

    def test_joint_role_and_full_boundary_are_grounded_without_category_output(self):
        payload, policy, base, pool = self.fixture()
        agent, transport = self.agent([self.rows(pool)])
        original = copy.deepcopy((payload, policy, pool))
        receipt = agent(payload=payload, policy=policy, pool=pool)
        self.assertEqual(receipt["status"], "semantics_only", receipt)
        self.assertEqual((payload, policy, pool), original)
        self.assertEqual(len(receipt["grounded_verdicts"]), 2)
        value = next(row for row in receipt["grounded_verdicts"] if row["role"] == "value")
        self.assertEqual(value["quote"], "Birch Group Ltd.")
        self.assertEqual(value["category"], "CUSTOMER")
        self.assertEqual(payload["memories"][0]["text"][value["start"]:value["end"]], value["quote"])
        self.assertEqual(receipt["local_counts"], {"local_encoder": 0, "local_generation": 1, "unknown": 0})
        self.assertEqual(transport.posts[0]["options"], semantic.OPTIONS)
        self.assertEqual(receipt["full_policy_sha256"], _digest(policy))
        data = json.loads(transport.posts[0]["messages"][1]["content"])
        self.assertEqual([row["text"] for row in data["sources"]], [payload["query"], payload["memories"][0]["text"]])
        self.assertEqual(len(data["candidates"]), 2)
        for row in data["candidates"]:
            self.assertEqual(set(row), {"cid", "source", "start", "end", "quote", "category"})
            self.assertEqual(payload["memories"][0]["text"][row["start"]:row["end"]], row["quote"])
            self.assertNotIn("before", row)
            self.assertNotIn("after", row)
        for row in receipt["verdicts"]:
            self.assertEqual(set(row), {"cid", "role", "quote"})

    def test_three_modes_share_one_receipt_but_apply_separate_counterfactuals(self):
        payload, policy, base, pool = self.fixture()
        agent, transport = self.agent([self.rows(pool)])
        refiner = semantic.PolicySemanticRefiner(agent)
        originals = copy.deepcopy((payload, policy, base))
        results = [refiner(payload, policy, base, actor_id="u", agent_id="B", mode=mode)
                   for mode in ("roles", "completion", "joint")]
        self.assertTrue(all(result["status"] == "ok" for result in results), results)
        self.assertEqual(len(transport.posts), 1)
        self.assertEqual([row["semantic_local_counts"]["local_generation"] for row in results], [1, 0, 0])
        self.assertEqual([row["policy_semantics"]["cache_hit"] for row in results], [False, True, True])
        self.assertEqual([len(row["policy_semantics"]["removed"]) for row in results], [1, 0, 1])
        self.assertEqual([len(row["policy_semantics"]["expanded"]) for row in results], [0, 1, 1])
        for row in results:
            self.assertEqual(row["agent_observations"][:len(base["agent_observations"])], base["agent_observations"])
            self.assertEqual(row["baseline_detection_sha256"], _digest(base))
        self.assertEqual((payload, policy, base), originals)
        results[0]["policy_semantics"]["receipt"]["verdicts"].clear()
        again = refiner(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(again["status"], "ok")
        self.assertEqual(len(transport.posts), 1)

    def test_typed_baseline_cost_and_observation_prefix_preserved(self):
        payload, policy, base, pool = self.fixture()
        base["local_calls"] = 2
        base["agent_observations"] = [{"local_calls": 2, "elapsed_seconds": 0.2}]
        base["agent_elapsed_seconds"] = 0.2
        base["inference_counts"] = {"local_encoder": 2, "local_generation": 0, "unknown": 0}
        agent, _ = self.agent([self.rows(pool)])
        refiner = semantic.PolicySemanticRefiner(agent)
        result = refiner(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["local_calls"], 3)
        self.assertEqual(result["inference_counts"], {"local_encoder": 2, "local_generation": 1, "unknown": 0})
        self.assertEqual(result["agent_observations"][0], base["agent_observations"][0])
        hit = refiner(payload, policy, base, actor_id="u", agent_id="B", mode="roles")
        self.assertEqual(hit["local_calls"], 2)
        self.assertEqual(hit["agent_observations"], base["agent_observations"])

    def test_cache_binds_actor_agent_lifecycle_payload_policy_and_spans_not_elapsed(self):
        payload, policy, base, pool = self.fixture()
        agent, transport = self.agent([self.rows(pool)]*8)
        refiner = semantic.PolicySemanticRefiner(agent)
        scope = {"authority_domain": "a", "lifecycle_sha256": "b", "grants_sha256": "c"}
        first = refiner(payload, policy, base, actor_id="u", agent_id="B", cache_scope=scope)
        self.assertEqual(first["cache_scope_sha256"], _digest(scope))
        changed_timing = dict(base, agent_elapsed_seconds=3.0)
        self.assertTrue(refiner(payload, policy, changed_timing, actor_id="u", agent_id="B", cache_scope=scope)["policy_semantics"]["cache_hit"])
        for actor, agent_id, current_scope in (("v", "B", scope), ("u", "C", scope),
                ("u", "B", dict(scope, lifecycle_sha256="revoked")),
                ("u", "B", dict(scope, authority_domain="other"))):
            result = refiner(payload, policy, base, actor_id=actor, agent_id=agent_id, cache_scope=current_scope)
            self.assertFalse(result["policy_semantics"]["cache_hit"])
        self.assertEqual(len(transport.posts), 5)
        body = json.dumps(transport.posts)
        self.assertNotIn("authority_domain", body)
        self.assertNotIn("grants_sha256", body)

    def test_failed_unknown_or_tampered_baseline_never_calls_agent(self):
        payload, policy, base, pool = self.fixture()
        agent, transport = self.agent([])
        variants = [dict(base, status="needs_review"), dict(base, errors=["existing_failure"]),
            dict(base, local_calls_complete=False), dict(base, local_calls=True),
            dict(base, payload_sha256="wrong"), dict(base, policy_sha256="wrong"),
            dict(base, full_policy_sha256="wrong"), dict(base, protected_categories=["PERSON"])]
        unknown = copy.deepcopy(base)
        unknown.update(local_calls=1, agent_observations=[{"local_calls": 1}],
            inference_counts={"local_encoder": 0, "local_generation": 0, "unknown": 1})
        variants.append(unknown)
        for variant in variants:
            result = semantic.PolicySemanticRefiner(agent)(payload, policy, variant, actor_id="u", agent_id="B")
            self.assertEqual(result["status"], "needs_review", result)
        self.assertEqual(transport.requests, [])

    def test_uncertainty_is_terminal_in_all_modes_and_shared_as_failure(self):
        payload, policy, base, pool = self.fixture()
        data = self.rows(pool, lambda c: ("uncertain", None))
        agent, transport = self.agent([data, self.rows(pool)])
        refiner = semantic.PolicySemanticRefiner(agent)
        for index, mode in enumerate(("joint", "roles", "completion")):
            result = refiner(payload, policy, base, actor_id="u", agent_id="B", mode=mode)
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["semantic_local_counts"]["local_generation"], int(index == 0))
            self.assertEqual(result["policy_semantics"]["receipt"]["error"], "semantic_uncertainty")
        self.assertEqual(len(transport.posts), 1)
        data["owner"] = "admin"
        agent, transport = self.agent([data, self.rows(pool)])
        self.assertEqual(agent(payload=payload, policy=policy, pool=pool)["error"], "semantic_uncertainty")
        self.assertEqual(len(transport.posts), 1)

    def test_one_format_or_location_repair_keeps_role_and_counts_both_posts(self):
        payload, policy, base, pool = self.fixture()
        wrong = self.rows(pool, lambda c: ("generic_role", None) if c["quote"] == "customer" else ("value", "Wrong Group Ltd."))
        for invalid in ("not json", wrong):
            agent, transport = self.agent([invalid, self.rows(pool)])
            result = agent(payload=payload, policy=policy, pool=pool)
            self.assertEqual(result["status"], "semantics_only", result)
            self.assertEqual(result["local_calls"], 2)
            self.assertEqual(len(result["attempts"]), 2)
            self.assertEqual(transport.posts[0]["messages"][:2], transport.posts[1]["messages"][:2])
            self.assertEqual(transport.posts[0]["format"], transport.posts[1]["format"])
        changed = self.rows(pool, lambda c: ("other", None))
        agent, transport = self.agent([wrong, changed])
        self.assertEqual(agent(payload=payload, policy=policy, pool=pool)["error"], "repair_changed_role")
        self.assertEqual(len(transport.posts), 2)

    def test_host_never_coerces_wrong_role_quote_pair_and_uncertain_is_terminal(self):
        payload, policy, base, pool = self.fixture()
        for role, quote, calls in (("generic_role", "customer", 2), ("field_label", "customer", 2),
                                  ("other", "customer", 2), ("uncertain", "customer", 1),
                                  ("value", None, 2), ("value", "", 2)):
            invalid = self.rows(pool, lambda candidate: (role, quote))
            before = copy.deepcopy(invalid)
            agent, transport = self.agent([invalid, invalid])
            receipt = agent(payload=payload, policy=policy, pool=pool)
            self.assertEqual(receipt["status"], "needs_review", (role, receipt))
            self.assertEqual(receipt["grounded_verdicts"], [])
            self.assertEqual(receipt["verdicts"], [])
            self.assertEqual(len(transport.posts), calls)
            self.assertEqual(receipt["local_calls"], calls)
            self.assertEqual(invalid, before)
            if role == "uncertain":
                self.assertEqual(receipt["error"], "semantic_uncertainty")

    def test_pair_format_repair_cannot_change_a_previously_chosen_generic_role_to_value(self):
        payload, policy, base, pool = self.fixture()
        invalid = self.rows(pool, lambda candidate: ("generic_role", candidate["quote"]))
        changed_role = self.rows(pool, lambda candidate: ("value", "Birch Group Ltd."))
        agent, transport = self.agent([invalid, changed_role])
        receipt = agent(payload=payload, policy=policy, pool=pool)
        self.assertEqual(receipt["status"], "needs_review")
        self.assertEqual(receipt["error"], "repair_changed_role")
        self.assertEqual(receipt["grounded_verdicts"], [])
        self.assertEqual(len(transport.posts), 2)

    def test_duplicate_unknown_missing_extra_authority_and_trailing_json_rejected(self):
        payload, policy, base, pool = self.fixture()
        good = self.rows(pool)
        cases = [{"verdicts": []}, {"verdicts": good["verdicts"]*2},
            {"verdicts": [dict(good["verdicts"][0], cid="unknown"), good["verdicts"][1]]},
            {"verdicts": [dict(good["verdicts"][0], category="PROJECT"), good["verdicts"][1]]},
            dict(good, owner="admin"), json.dumps(good)+" SECRET", '{"verdicts":[],"verdicts":[]}']
        for invalid in cases:
            agent, transport = self.agent([invalid, invalid])
            result = agent(payload=payload, policy=policy, pool=pool)
            self.assertEqual(result["status"], "needs_review", result)
            self.assertEqual(result["grounded_verdicts"], [])
            self.assertEqual(len(transport.posts), 2)

    def test_cross_field_source_or_missing_original_seed_never_ground(self):
        payload, policy, base, pool = self.fixture(text="Customer: Birch Group Ltd.\nProject: P-8", spans=[("m", "Ltd.", "CUSTOMER")])
        for quote, calls in (("Customer: Birch Group Ltd.", 1), ("Birch Group Ltd.\nProject: P-8", 1),
                             ("Birch Group", 2), ("Other Ltd.", 2)):
            bad = self.rows(pool, lambda c: ("value", quote))
            agent, transport = self.agent([bad, bad])
            result = agent(payload=payload, policy=policy, pool=pool)
            self.assertEqual(result["status"], "needs_review", result)
            self.assertEqual(len(transport.posts), calls)

    def test_repeated_value_occurrence_and_nonsemantic_amount_preserved(self):
        text = "Birch Group Ltd. was first. Birch Group Ltd. was second. 120 USD"
        payload, policy, base, _ = self.fixture(text=text, spans=[("m", "Ltd.", "CUSTOMER"), ("m", "120 USD", "AMOUNT")])
        pool = propose_candidates(payload, policy, base["findings"])
        agent, _ = self.agent([self.rows(pool, lambda c: ("value", "Birch Group Ltd."))])
        result = semantic.PolicySemanticRefiner(agent)(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(any(row["category"] == "AMOUNT" for row in result["findings"]))
        self.assertTrue(all(row["source_id"] == "m" for row in result["findings"]))

    def test_compact_input_keeps_full_sources_and_disambiguates_equal_values_by_offset(self):
        text = "Birch Group Ltd. was first. Birch Group Ltd. was second."
        payload, policy, _, _ = self.fixture(text=text, spans=[])
        starts = [text.index("Ltd."), text.rindex("Ltd.")]
        pool = propose_candidates(payload, policy, [{"source_id": "m", "start": start,
            "end": start+4, "category": "CUSTOMER"} for start in starts])
        agent, transport = self.agent([self.rows(pool, lambda row: ("value", "Birch Group Ltd."))])
        receipt = agent(payload=payload, policy=policy, pool=pool)
        self.assertEqual(receipt["status"], "semantics_only", receipt)
        self.assertEqual([row["start"] for row in receipt["grounded_verdicts"]], [text.index("Birch"), text.rindex("Birch")])
        data = json.loads(transport.posts[0]["messages"][1]["content"])
        self.assertEqual(data["sources"][1]["text"], text)
        self.assertEqual([row["start"] for row in data["candidates"]], starts)
        self.assertEqual([row["quote"] for row in data["candidates"]], ["Ltd.", "Ltd."])
        self.assertEqual(len(data["candidates"]), 2)

    def test_explicit_registry_cannot_be_deleted_and_is_not_forwarded(self):
        policy = {"version": "registry", "protected_categories": ["CUSTOMER"],
            "entity_registry": [{"value": "Birch", "category": "CUSTOMER"}]}
        payload, policy, base, pool = self.fixture(text="Birch is the name.", spans=[("m", "Birch", "CUSTOMER")], policy=policy)
        agent, transport = self.agent([self.rows(pool, lambda c: ("other", None))])
        result = semantic.PolicySemanticRefiner(agent)(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(any(row["category"] == "CUSTOMER" for row in result["findings"]))
        self.assertGreater(result["policy_semantics"]["registry_occurrences_retained"], 0)
        self.assertNotIn("entity_registry", json.dumps(transport.posts))

    def test_no_semantic_candidates_needs_no_model_or_health(self):
        payload, policy, base, pool = self.fixture(text="Budget is 120 USD.", spans=[("m", "120 USD", "AMOUNT")])
        agent, transport = self.agent([])
        result = semantic.PolicySemanticRefiner(agent)(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["semantic_local_counts"], dict.fromkeys(semantic.KINDS, 0))
        self.assertEqual(transport.requests, [])

    def test_input_and_runtime_budget_or_envelope_fail_without_hidden_cost(self):
        payload, policy, base, pool = self.fixture(text="X"*4000+" Ltd.", spans=[("m", "Ltd.", "CUSTOMER")])
        agent, transport = self.agent([])
        self.assertEqual(agent(payload=payload, policy=policy, pool=pool)["error"], "input_budget_exceeded")
        self.assertEqual(transport.requests, [])
        payload, policy, base, pool = self.fixture()
        for change in ({"model": "wrong"}, {"done": False}, {"prompt_eval_count": 3073}, {"eval_count": 1025}):
            transport = FakeTransport([envelope(self.rows(pool), **change)])
            receipt = semantic.LocalPolicySemanticAgent(transport=transport)(payload=payload, policy=policy, pool=pool)
            self.assertEqual(receipt["status"], "needs_review")
            self.assertEqual(receipt["local_calls"], 1)
            self.assertEqual(receipt["local_counts"]["local_generation"], 1)
        agent, transport = self.agent([OSError("offline")])
        self.assertEqual(agent(payload=payload, policy=policy, pool=pool)["local_calls"], 1)

    def test_receipt_hash_span_or_category_tampering_rejected_without_cache(self):
        payload, policy, base, pool = self.fixture()
        for field in ("payload_sha256", "full_policy_sha256", "pool_sha256", "input_sha256", "request_identity_sha256", "config_sha256"):
            real, transport = self.agent([self.rows(pool)])
            receipt = real(payload=payload, policy=policy, pool=pool)
            receipt[field] = "0"*64
            class Altered:
                cache_identity = real.cache_identity
                def __call__(self, **kwargs):
                    return copy.deepcopy(receipt)
            result = semantic.PolicySemanticRefiner(Altered())(payload, policy, base, actor_id="u", agent_id="B")
            self.assertEqual(result["status"], "needs_review", field)

    def test_same_word_key_and_actual_value_remain_separate_and_live_authority_still_applies(self):
        for text, legitimate in (("Customer:", False), ("Customer: Customer", True)):
            payload, policy, base, pool = self.fixture(text=text, query="Customer: Customer",
                spans=[("m", "Customer", "CUSTOMER"), ("__query__", "Customer", "CUSTOMER")])
            data = self.rows(pool, lambda c: ("field_label", None) if c["start"] == 0 else ("value", "Customer"))
            agent, transport = self.agent([data])
            result = semantic.PolicySemanticRefiner(agent)(payload, policy, base, actor_id="u", agent_id="B")
            self.assertEqual(result["status"], "ok", result)
            # Legacy closure may bring a filtered key back. This is recorded,
            # and later business-value evidence filtering remains indispensable.
            self.assertTrue(result["policy_semantics"]["removed"])
            authorized = lambda sid, actor, version: actor == "u" and sid == "m"
            prepared = prepare_boundary_payload(payload, result, actor_id="u", request_id="r1",
                policy_version=policy["version"], authorizer=authorized, sensitivity_policy=policy)
            self.assertEqual(prepared["status"], "ok", prepared)
            token = next(token for token, entry in prepared["mapping"]._entries.items() if entry.value == "Customer")
            options = {"actor_id": "u", "request_id": "r1", "policy_version": policy["version"],
                "authorizer": authorized, "sensitivity_policy": policy}
            restored = restore_answer(token, prepared["mapping"], **options)
            if legitimate:
                self.assertEqual(restored["answer"], "Customer")
            else:
                self.assertEqual(restored["error"], "query_only_value_has_no_evidence")
            for changed in ({"actor_id": "other"}, {"request_id": "r2"},
                            {"authorizer": lambda *args: False}):
                denied = restore_answer(token, prepared["mapping"], **(options | changed))
                self.assertEqual(denied["status"], "blocked")
            self.assertEqual(restore_answer("I refuse, but Customer", prepared["mapping"], **options)["status"], "blocked")
            self.assertEqual(len(transport.posts), 1)

    def test_payload_full_policy_and_current_spans_change_cache_identity(self):
        payload, policy, base, pool = self.fixture()
        agent, transport = self.agent([self.rows(pool)]*5)
        refiner = semantic.PolicySemanticRefiner(agent)
        original = refiner(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(original["status"], "ok")
        changed_policy = dict(policy, host_policy_note="independent full-policy change")
        policy_result = refiner(payload, changed_policy, base, actor_id="u", agent_id="B")
        self.assertFalse(policy_result["policy_semantics"]["cache_hit"])
        self.assertNotEqual(policy_result["policy_semantics"]["cache_key_sha256"], original["policy_semantics"]["cache_key_sha256"])
        changed_payload, changed_policy, changed_base, changed_pool = self.fixture(query="Which name?")
        current = refiner(changed_payload, changed_policy, changed_base, actor_id="u", agent_id="B")
        self.assertFalse(current["policy_semantics"]["cache_hit"])
        # A changed baseline span set uses a fresh joint pool/receipt as well.
        shorter = copy.deepcopy(base)
        shorter["findings"] = shorter["findings"][:1]
        current = refiner(payload, policy, shorter, actor_id="u", agent_id="B")
        self.assertFalse(current["policy_semantics"]["cache_hit"])
        self.assertEqual(len(transport.posts), 5)  # final deliberately mismatched fake response gets one format repair

    def test_malformed_cost_or_wrong_grounded_category_never_produces_success(self):
        payload, policy, base, pool = self.fixture()
        for mutate in (lambda row: row.update(local_counts={"local_encoder": 0, "local_generation": 0, "unknown": 1}),
                       lambda row: row.update(local_calls_complete=False),
                       lambda row: row["grounded_verdicts"][-1].update(category="PROJECT"),
                       lambda row: row["grounded_verdicts"][-1].update(start=False),
                       lambda row: row["attempts"][0].update(request_sha256="0"*64)):
            real, _ = self.agent([self.rows(pool)])
            receipt = real(payload=payload, policy=policy, pool=pool)
            mutate(receipt)
            class Altered:
                cache_identity = real.cache_identity
                def __call__(self, **kwargs):
                    return copy.deepcopy(receipt)
            result = semantic.PolicySemanticRefiner(Altered())(payload, policy, base, actor_id="u", agent_id="B")
            self.assertEqual(result["status"], "needs_review")

    def test_query_cannot_supply_an_expanded_memory_entity_in_another_source(self):
        payload, policy, base, pool = self.fixture(text="The name ends in Ltd.", query="Birch Group Ltd.",
            spans=[("m", "Ltd.", "CUSTOMER")])
        data = self.rows(pool, lambda c: ("value", "Birch Group Ltd."))
        agent, transport = self.agent([data, data])
        result = semantic.PolicySemanticRefiner(agent)(payload, policy, base, actor_id="u", agent_id="B")
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"], base["findings"])
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(len(transport.posts), 2)

    def test_foreign_or_reserved_input_and_model_pins_rejected_without_post(self):
        for config in ({"endpoint": "https://example.com"}, {"model": "other"},
                       {"expected_digest": "0"*64}, {"num_predict": 9999}, {"max_candidates": True}):
            with self.assertRaises(ValueError):
                self.agent([], config)
        payload, policy, base, pool = self.fixture()
        broken = copy.deepcopy(pool)
        broken["candidates"][0]["source_id"] = "foreign"
        agent, transport = self.agent([])
        self.assertEqual(agent(payload=payload, policy=policy, pool=broken)["status"], "needs_review")
        self.assertEqual(transport.requests, [])
        payload["query"] = "[PVT_0123456789abcdef01234567_CUSTOMER_1]"
        pool = propose_candidates(payload, policy, base["findings"])
        result = agent(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["error"], "reserved_token_in_input")
        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()
