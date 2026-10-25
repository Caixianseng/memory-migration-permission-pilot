import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from memory_migration_study import span_completion as completion
from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.span_completion import LocalSpanCompleter
from tests.test_candidate_adjudicator import FakeTransport, envelope


class SpanCompletionTests(unittest.TestCase):
    def fixture(self, text="Customer: Birch Group Ltd.", quote="Ltd.", category="CUSTOMER", start=None):
        payload = {"query": "", "memories": [{"source_id": "m", "text": text}]}
        policy = {"version": "span-test", "protected_categories": [category]}
        start = text.index(quote) if start is None else start
        pool = propose_candidates(payload, policy, [{"source_id": "m", "start": start, "end": start+len(quote),
                                                     "quote": quote, "category": category}])
        return payload, policy, pool

    def run_case(self, quote, *, fixture=None, config=None):
        payload, policy, pool = fixture or self.fixture()
        response = {"completions": [{"cid": candidate["cid"], "quote": quote} for candidate in pool["candidates"]
                                    if candidate["proposed_category"] in completion.SEMANTIC_CATEGORIES]}
        transport = FakeTransport([envelope(response)])
        result = LocalSpanCompleter(config, transport)(payload=payload, policy=policy, pool=pool)
        return result, transport

    def test_four_semantic_types_expand_exact_complete_source_span(self):
        cases = [("Person: 林青禾", "青", "PERSON", "林青禾"),
                 ("Address: Building 4, Unit 9, 12 North Road", "North Road", "ADDRESS", "Building 4, Unit 9, 12 North Road"),
                 ("Customer: Birch Group Ltd.", "Ltd.", "CUSTOMER", "Birch Group Ltd."),
                 ("Project: 云杉-42特别计划", "42", "PROJECT", "云杉-42特别计划")]
        for text, seed, category, full in cases:
            with self.subTest(category=category):
                payload, policy, pool = self.fixture(text, seed, category)
                result, transport = self.run_case(full, fixture=(payload, policy, pool))
                self.assertEqual(result["status"], "completed_only")
                self.assertEqual(result["local_calls"], 1)
                item = result["findings"][0]
                self.assertEqual((item["quote"], item["category"], item["source_id"]), (full, category, "m"))
                self.assertEqual(text[item["start"]:item["end"]], full)
                original = pool["candidates"][0]
                self.assertTrue(item["start"] <= original["start"] < original["end"] <= item["end"])
                self.assertEqual(result["local_counts"], {"local_generation": 1, "local_encoder": 0, "unknown": 0})
                self.assertEqual(transport.posts[0]["options"], completion.OPTIONS)
                self.assertNotIn("tools", transport.posts[0])

    def test_repeated_identical_quotes_located_by_containing_original_offset(self):
        text = "Customer: Birch Group\nCustomer: Birch Group"
        payload, policy, _ = self.fixture(text, "Group")
        findings = [{"source_id": "m", "start": start, "end": start+5, "category": "CUSTOMER"}
                    for start in (text.index("Group"), text.rindex("Group"))]
        pool = propose_candidates(payload, policy, findings)
        result, _ = self.run_case("Birch Group", fixture=(payload, policy, pool))
        self.assertEqual(result["status"], "completed_only")
        self.assertEqual([row["start"] for row in result["completions"]], [text.index("Birch"), text.rindex("Birch")])

    def test_other_source_normalization_or_omitting_seed_cannot_ground(self):
        for quote in ("Alder Group Ltd.", "BirchGroup Ltd.", "Birch Group", "BIRCH GROUP LTD."):
            with self.subTest(quote=quote):
                payload, policy, pool = self.fixture()
                payload["memories"].append({"source_id": "other", "text": "Alder Group Ltd."})
                original = pool["candidates"][0]
                pool = propose_candidates(payload, policy, [{"source_id": "m", "start": original["start"],
                    "end": original["end"], "category": "CUSTOMER"}])
                row = {"completions": [{"cid": "C0001", "quote": quote}]}
                transport = FakeTransport([envelope(row), envelope(row)])
                result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["local_calls"], 1)

    def test_overlapping_occurrences_covering_target_are_ambiguous_not_guessed(self):
        fixture = self.fixture("aaaaa", "a", "PROJECT", start=2)
        payload, policy, pool = fixture
        row = {"completions": [{"cid": "C0001", "quote": "aaa"}]}
        transport = FakeTransport([envelope(row), envelope(row)])
        result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["local_calls"], 1)

    def test_expansion_cannot_include_key_neighboring_field_or_explanation(self):
        text = "Customer: Birch Group Ltd.\nProject: P-8"
        payload, policy, pool = self.fixture(text)
        for quote in ("Customer: Birch Group Ltd.", text, "Birch Group Ltd.\nProject: P-8"):
            with self.subTest(quote=quote):
                row = {"completions": [{"cid": "C0001", "quote": quote}]}
                transport = FakeTransport([envelope(row), envelope(row)])
                result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["local_calls"], 1)

    def test_existing_complete_candidate_can_remain_exactly_unchanged(self):
        fixture = self.fixture(quote="Birch Group Ltd.")
        result, _ = self.run_case("Birch Group Ltd.", fixture=fixture)
        self.assertEqual(result["status"], "completed_only")
        self.assertEqual(result["findings"][0]["start"], fixture[2]["candidates"][0]["start"])
        self.assertEqual(result["findings"][0]["end"], fixture[2]["candidates"][0]["end"])

    def test_semantic_uncertainty_no_retry_and_nonsemantic_not_partial_success(self):
        payload, policy, pool = self.fixture()
        policy["protected_categories"].append("AMOUNT")
        payload["memories"][0]["text"] += "\nBudget: 120 USD"
        text = payload["memories"][0]["text"]
        candidates = [{"source_id": "m", "start": text.index("Ltd."), "end": text.index("Ltd.")+4, "category": "CUSTOMER"},
                      {"source_id": "m", "start": text.index("120 USD"), "end": len(text), "category": "AMOUNT"}]
        pool = propose_candidates(payload, policy, candidates)
        result, transport = self.run_case(None, fixture=(payload, policy, pool))
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["error"], "semantic_uncertainty")
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(transport.posts), 1)

    def test_nonsemantic_typed_pass_through_and_untyped_not_assigned_category(self):
        payload = {"query": "", "memories": [{"source_id": "m", "text": 'Budget: 120 USD; Note: “Unclassified”'}]}
        policy = {"version": "nonsemantic", "protected_categories": ["AMOUNT", "CUSTOMER"]}
        text = payload["memories"][0]["text"]
        pool = propose_candidates(payload, policy, [{"source_id": "m", "start": text.index("120 USD"),
                                                   "end": text.index("120 USD")+7, "category": "AMOUNT"}])
        transport = FakeTransport([])
        result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["status"], "completed_only")
        self.assertEqual([(f["category"], f["quote"]) for f in result["findings"]], [("AMOUNT", "120 USD")])
        self.assertEqual(len(result["untyped_candidates"]), 1)
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(transport.requests, [])

    def test_unknown_missing_duplicate_cid_or_category_authority_keys_fail_schema(self):
        payload, policy, pool = self.fixture()
        cases = [{"completions": []}, {"completions": [{"cid": "C9999", "quote": "Birch Group Ltd."}]},
                 {"completions": [{"cid": "C0001", "quote": "Birch Group Ltd.", "category": "PROJECT"}]},
                 {"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}], "permissions": ["all"]},
                 {"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}]*2}]
        for row in cases:
            with self.subTest(row=row):
                transport = FakeTransport([envelope(row), envelope(row)])
                result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["error"], "format_or_span_invalid")
                self.assertEqual(result["local_calls"], 2)

    def test_repair_only_fixed_feedback_and_actual_counts_recorded(self):
        payload, policy, pool = self.fixture()
        transport = FakeTransport([envelope("MODEL_RESPONSE_SECRET"),
            envelope({"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}]})])
        result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["status"], "completed_only")
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(transport.posts[1]["messages"][:-1], transport.posts[0]["messages"])
        self.assertEqual(transport.posts[1]["messages"][-1]["content"], completion.REPAIR_PROMPT)
        self.assertNotIn("MODEL_RESPONSE_SECRET", json.dumps(transport.posts[1]))
        self.assertNotIn("MODEL_RESPONSE_SECRET", json.dumps(result))
        self.assertEqual(result["attempts"][0]["prompt_eval_count"], 300)

    def test_full_policy_pool_and_source_binding_no_gold_registry_in_model(self):
        payload, policy, pool = self.fixture()
        seed = {key: pool["candidates"][0][key] for key in ("source_id", "start", "end")}
        seed["category"] = "CUSTOMER"
        policy.update(gold="SCORING_ONLY_CANARY", entity_registry=[{"category": "CUSTOMER", "value": "REGISTRY_CANARY"}])
        pool = propose_candidates(payload, policy, [seed])
        row = {"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}]}
        transport = FakeTransport([envelope(row), envelope(row)])
        client = LocalSpanCompleter(transport=transport)
        first = client(payload=payload, policy=policy, pool=pool)
        other_policy = {**policy, "gold": "OTHER_SCORING_CANARY"}
        stale = client(payload=payload, policy=other_policy, pool=pool)
        self.assertEqual(stale["local_calls"], 0)
        self.assertEqual(stale["status"], "needs_review")
        fresh_pool = propose_candidates(payload, other_policy, [seed])
        second = client(payload=payload, policy=other_policy, pool=fresh_pool)
        self.assertEqual(first["input_sha256"], second["input_sha256"])
        self.assertNotEqual(first["request_identity_sha256"], second["request_identity_sha256"])
        encoded = json.dumps(transport.posts)
        self.assertNotIn("SCORING_ONLY_CANARY", encoded)
        self.assertNotIn("OTHER_SCORING_CANARY", encoded)
        self.assertNotIn("REGISTRY_CANARY", encoded)

    def test_input_and_repair_budgets_no_truncation_and_model_limit(self):
        payload, policy, pool = self.fixture()
        policy["instructions"] = "x"*2000
        seed = {key: pool["candidates"][0][key] for key in ("source_id", "start", "end")}
        pool = propose_candidates(payload, policy, [dict(seed, category="CUSTOMER")])
        transport = FakeTransport([])
        result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["error"], "input_budget_exceeded")
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(transport.requests, [])
        good, _ = self.run_case("Birch Group Ltd.")
        overhead = completion.CHAT_OVERHEAD+completion.CONTEXT_TOKENS-good["input_budget_upper_bound"]-1
        payload, policy, pool = self.fixture()
        transport = FakeTransport([envelope("invalid-json")])
        with patch.object(completion, "CHAT_OVERHEAD", overhead):
            result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["error"], "repair_budget_exceeded")
        self.assertEqual(result["local_calls"], 1)

    def test_bad_envelope_usage_transport_never_format_retried(self):
        payload, policy, pool = self.fixture()
        good = envelope({"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}]})
        cases = [RuntimeError("DO_NOT_LOG_SECRET"), {**good, "model": "remote"}, {**good, "done": False},
                 {**good, "eval_count": 1025}, {**good, "prompt_eval_count": True},
                 {**good, "message": {"role": "assistant", "content": "x", "thinking": "hidden"}}]
        for response in cases:
            with self.subTest(response=type(response)):
                transport = FakeTransport([response])
                result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["local_calls"], 1)
                self.assertNotIn("DO_NOT_LOG_SECRET", json.dumps(result))

    def test_inputs_unchanged_and_only_fixed_source_fingerprint_file_reads(self):
        payload, policy, pool = self.fixture()
        original = copy.deepcopy((payload, policy, pool))
        allowed = {Path(module.__file__) for module in (completion, completion.binding, completion.proposals,
                                                       completion.fields, completion.runtime)}
        def source_read(path):
            self.assertIn(path, allowed)
            return b"fixed-offline-source-fingerprint"
        transport = FakeTransport([envelope({"completions": [{"cid": "C0001", "quote": "Birch Group Ltd."}]})])
        with patch.object(Path, "read_bytes", autospec=True, side_effect=source_read), \
                patch("builtins.open", side_effect=AssertionError("No gold/data/files")):
            result = LocalSpanCompleter(transport=transport)(payload=payload, policy=policy, pool=pool)
        self.assertEqual(result["status"], "completed_only")
        self.assertEqual((payload, policy, pool), original)
        for config in ({"endpoint": "https://example.test"}, {"model": "other"}, {"max_quote_chars": 257},
                       {"max_semantic_candidates": 17}, {"tools": ["upload"]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                LocalSpanCompleter(config, transport=FakeTransport([]))


if __name__ == "__main__":
    unittest.main()
