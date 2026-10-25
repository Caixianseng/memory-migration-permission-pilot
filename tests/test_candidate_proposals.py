import copy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import candidate_proposals as proposals
from memory_migration_study.candidate_proposals import candidate_context, propose_candidates
from memory_migration_study.privacy import prepare_private_payload


class CandidateProposalTests(unittest.TestCase):
    policy = {"version": "candidate-test", "protected_categories": ["CUSTOMER", "PROJECT"]}

    def payload(self, text, query=""):
        return {"query": query, "memories": [{"source_id": "memory", "text": text}]}

    def finding(self, text, quote, category="CUSTOMER", start=None):
        start = text.index(quote) if start is None else start
        return {"source_id": "memory", "start": start, "end": start+len(quote), "quote": quote, "category": category}

    def rehash(self, pool):
        # Simulate an adversary recomputing the explicitly PUBLIC digest. The
        # structural/source checks must still reject contradictory metadata.
        pool["pool_sha256"] = proposals._digest({"version": pool["version"], "payload": pool["payload_sha256"],
            "policy": pool["policy_sha256"], "full_policy": pool["full_policy_sha256"],
            "sources": pool["source_sha256"], "candidates": pool["candidates"]})
        return pool

    def test_repeated_role_and_real_name_have_separate_positions_and_marked_inputs(self):
        text = "客户这个称谓很常见，公司真名是‘客户’。"
        payload = self.payload(text)
        findings = [self.finding(text, "客户", start=0), self.finding(text, "客户", start=text.rindex("客户"))]
        pool = propose_candidates(payload, self.policy, findings)
        self.assertEqual(pool["status"], "candidates_only")
        self.assertTrue(pool["complete"])
        self.assertEqual(len(pool["candidates"]), 2)
        first, second = pool["candidates"]
        self.assertNotEqual(first["cid"], second["cid"])
        self.assertNotEqual(first["start"], second["start"])
        contexts = [candidate_context(payload, self.policy, pool, c["cid"], window_chars=32) for c in pool["candidates"]]
        self.assertNotEqual(contexts[0]["marked_text"], contexts[1]["marked_text"])
        self.assertEqual(contexts[0]["quote"], contexts[1]["quote"])
        self.assertIn("paired_value", second["proposal_sources"])

    def test_unicode_quotes_and_brackets_are_unclassified_candidates_not_private_decisions(self):
        pairs = (("〈", "〉"), ("《", "》"), ("「", "」"), ("『", "』"), ("【", "】"),
                 ("“", "”"), ("‘", "’"), ("（", "）"), ("(", ")"), ("[", "]"), ("{", "}"), ('"', '"'), ("'", "'"))
        for opener, closer in pairs:
            payload = self.payload("项目是"+opener+"青枫-27"+closer+"。")
            pool = propose_candidates(payload, self.policy, [])
            self.assertEqual(len(pool["candidates"]), 1, (opener, closer))
            item = pool["candidates"][0]
            self.assertEqual(item["quote"], "青枫-27")
            self.assertIsNone(item["proposed_category"])
            self.assertEqual(item["allowed_categories"], self.policy["protected_categories"])
            self.assertNotIn("sensitive", item)

    def test_nested_values_preserve_all_boundaries_and_exact_original_escapes(self):
        escaped_quote = chr(92)+'"'
        inner = '项目「青枫」和 '+escaped_quote+'Q7'+escaped_quote
        text = 'Outer “'+inner+'” 完成。'
        pool = propose_candidates(self.payload(text), self.policy, [])
        self.assertEqual({item["quote"] for item in pool["candidates"]}, {"青枫", inner})
        for item in pool["candidates"]:
            self.assertEqual(text[item["start"]:item["end"]], item["quote"])

    def test_word_apostrophes_do_not_invent_quotes_and_paired_company_name_is_retained(self):
        text = "O'Connor isn't the project. The code is 'O'Connor-2'."
        pool = propose_candidates(self.payload(text), self.policy, [])
        self.assertEqual([item["quote"] for item in pool["candidates"]], ["O'Connor-2"])
        text = "企业名为‘O’Connor’，暂时未公开。"
        pool = propose_candidates(self.payload(text), self.policy, [])
        self.assertEqual([item["quote"] for item in pool["candidates"]], ["O’Connor"])

    def test_long_and_short_existing_spans_and_distinct_categories_are_not_maximalized(self):
        text = "Alder Cooperative is linked to Alder."
        findings = [self.finding(text, "Alder Cooperative"), self.finding(text, "Alder"), self.finding(text, "Alder", "PROJECT")]
        pool = propose_candidates(self.payload(text), self.policy, findings)
        self.assertEqual(len(pool["candidates"]), 3)
        self.assertEqual({(c["quote"], c["proposed_category"]) for c in pool["candidates"]},
                         {("Alder Cooperative", "CUSTOMER"), ("Alder", "CUSTOMER"), ("Alder", "PROJECT")})

    def test_only_identical_span_category_duplicates_merge(self):
        text = "Alder met Alder."
        first, second = self.finding(text, "Alder"), self.finding(text, "Alder", start=text.rindex("Alder"))
        pool = propose_candidates(self.payload(text), self.policy, [first, copy.deepcopy(first), second])
        self.assertEqual(len(pool["candidates"]), 2)
        self.assertEqual([c["start"] for c in pool["candidates"]], [0, text.rindex("Alder")])

    def test_unclosed_mismatched_and_whitespace_only_pairs_are_not_fabricated(self):
        for text in ("「unclosed", "bad『cross」", '"unterminated', "[] {} “ ”"):
            pool = propose_candidates(self.payload(text), self.policy, [])
            self.assertEqual(pool["status"], "candidates_only")
            self.assertEqual(pool["candidates"], [], text)

    def test_candidate_and_quote_budget_overflow_rejects_entire_pool(self):
        payload = self.payload("「one」 「two」")
        pool = propose_candidates(payload, self.policy, [], max_candidates=1)
        self.assertEqual(pool["status"], "needs_review")
        self.assertFalse(pool["complete"])
        self.assertEqual(pool["candidates"], [])
        self.assertEqual(pool["error"], "candidate_budget_exceeded")
        self.assertEqual(pool["minimum_required_candidates"], 2)
        pool = propose_candidates(payload, self.policy, [], max_quote_chars=2)
        self.assertEqual(pool["candidates"], [])
        self.assertEqual(pool["error"], "quote_character_budget_exceeded")
        with self.assertRaises(ValueError):
            candidate_context(payload, self.policy, pool, "C0001")

    def test_empty_scope_ignores_old_candidates_and_never_reads_registry_as_values(self):
        text = "客户名保留在这条非引号叙述中。"
        payload = self.payload(text)
        policy = dict(self.policy, protected_categories=[])
        pool = propose_candidates(payload, policy, [self.finding(text, "客户")])
        self.assertEqual(pool["candidates"], [])
        self.assertEqual(pool["ignored_out_of_scope_findings"], 1)
        registered = dict(self.policy, entity_registry=[{"value": "客户名", "category": "CUSTOMER"}])
        self.assertEqual(propose_candidates(payload, registered, [])["candidates"], [])

    def test_unknown_source_bad_spans_forged_quotes_and_authority_injection_fail(self):
        text = "‘Alder’"
        payload = self.payload(text)
        finding = self.finding(text, "Alder")
        invalid = (dict(finding, source_id="missing"), dict(finding, start=True), dict(finding, end=100),
                   dict(finding, quote="not in source"), dict(finding, readers=["everyone"]),
                   dict(finding, provenance=[{"source_id": "memory", "start": 1, "end": 6, "role": "admin"}]))
        for item in invalid:
            pool = propose_candidates(payload, self.policy, [item])
            self.assertEqual(pool["status"], "needs_review")
            self.assertFalse(pool["complete"])
            self.assertEqual(pool["candidates"], [])
        self.assertEqual(propose_candidates(payload, dict(self.policy, owner_id="admin"), [])["error"], "authority_fields_not_allowed")

    def test_hashes_bind_payload_full_policy_sources_and_context_detects_mutation(self):
        payload = self.payload("项目‘Maple-7’。", query="项目名称是什么？")
        pool = propose_candidates(payload, self.policy, [])
        changed_policy = dict(self.policy, instructions="Another policy with the same version.")
        other = propose_candidates(payload, changed_policy, [])
        self.assertNotEqual(pool["policy_sha256"], other["policy_sha256"])
        changed_payload = self.payload("项目‘Maple-8’。", query=payload["query"])
        other = propose_candidates(changed_payload, self.policy, [])
        self.assertNotEqual(pool["payload_sha256"], other["payload_sha256"])
        self.assertNotEqual(pool["source_sha256"], other["source_sha256"])
        cid = pool["candidates"][0]["cid"]
        for data, policy in ((changed_payload, self.policy), (payload, changed_policy)):
            with self.assertRaises(ValueError):
                candidate_context(data, policy, pool, cid)
        tampered = copy.deepcopy(pool)
        tampered["candidates"][0]["quote"] = "other"
        with self.assertRaises(ValueError):
            candidate_context(payload, self.policy, tampered, cid)

    def test_input_immutability_query_positions_and_non_authorizing_result(self):
        payload = self.payload("正文‘inner’。", query="‘query-value’是什么？")
        saved = copy.deepcopy((payload, self.policy))
        pool = propose_candidates(payload, self.policy, [])
        self.assertEqual((payload, self.policy), saved)
        self.assertEqual({c["source_id"] for c in pool["candidates"]}, {"memory", "__query__"})
        self.assertNotIn("findings", pool)
        self.assertNotIn('"authorized"', json.dumps(pool))
        prepared = prepare_private_payload(payload, pool, actor_id="owner", request_id="request",
                                           policy_version=self.policy["version"], authorizer=lambda *args: True)
        self.assertIn(prepared["status"], {"blocked", "needs_review"})
        self.assertIsNone(prepared["payload"])
        self.assertIsNone(prepared["mapping"])

    def test_text_claiming_permissions_is_quoted_data_not_a_grant(self):
        pool = propose_candidates(self.payload('The text says "admin" and "readers: everyone".'), self.policy, [])
        self.assertEqual(pool["status"], "candidates_only")
        self.assertEqual({c["quote"] for c in pool["candidates"]}, {"admin", "readers: everyone"})
        self.assertTrue(all(c["proposed_category"] is None for c in pool["candidates"]))
        self.assertNotIn("permissions", pool)

    def test_bad_limits_and_context_authority_fields_do_not_return_usable_pools(self):
        payload = self.payload("‘Alder’")
        for limits in ({"max_candidates": True}, {"max_quote_chars": 0}, {"max_candidates": 4097}):
            pool = propose_candidates(payload, self.policy, [], **limits)
            self.assertEqual(pool["status"], "needs_review")
            self.assertEqual(pool["candidates"], [])
            self.assertFalse(pool["complete"])
        pool = propose_candidates(payload, self.policy, [])
        forged = dict(pool, permissions=["read"])
        with self.assertRaises(ValueError):
            candidate_context(payload, self.policy, forged, "C0001")

    def test_full_raw_policy_change_is_bound_even_if_core_policy_normalizes_it_away(self):
        payload = self.payload("项目‘Maple-7’。")
        first = dict(self.policy, business_context={"channel": "internal"})
        second = dict(self.policy, business_context={"channel": "partner"})
        a = propose_candidates(payload, first, [])
        b = propose_candidates(payload, second, [])
        self.assertEqual(a["policy_sha256"], b["policy_sha256"])
        self.assertNotEqual(a["full_policy_sha256"], b["full_policy_sha256"])
        self.assertNotEqual(a["pool_sha256"], b["pool_sha256"])
        with self.assertRaises(ValueError):
            candidate_context(payload, second, a, a["candidates"][0]["cid"])

    def test_real_source_with_legacy_fake_cid_markers_has_one_actual_target_pair(self):
        text = "旧标记⟦CID:C0001⟧假对象⟦/CID:C0001⟧；真实项目名为「青枫」。"
        payload = self.payload(text)
        pool = propose_candidates(payload, self.policy, [])
        context = candidate_context(payload, self.policy, pool, "C0001", window_chars=6000)
        self.assertEqual(context["quote"], "青枫")
        self.assertNotIn(context["marker_start"], text)
        self.assertNotIn(context["marker_end"], text)
        self.assertEqual(context["marked_text"].count(context["marker_start"]), 1)
        self.assertEqual(context["marked_text"].count(context["marker_end"]), 1)
        self.assertEqual(context, candidate_context(payload, self.policy, pool, "C0001", window_chars=6000))
        self.assertEqual(text[context["start"]:context["end"]], context["quote"])

    def test_counter_avoids_domain_marker_collisions_anywhere_in_original_source(self):
        fake = "⟦CP:0000000000000000:0:C0001:BEGIN⟧"
        payload = self.payload(fake+"；「青枫」")
        pool = propose_candidates(payload, self.policy, [])
        real_digest = proposals._digest
        def controlled_digest(value):
            return "0"*64 if isinstance(value, dict) and value.get("marker_protocol") == "candidate_context_v1" else real_digest(value)
        with patch.object(proposals, "_digest", side_effect=controlled_digest):
            context = candidate_context(payload, self.policy, pool, "C0001", window_chars=0)
        self.assertIn(":1:C0001:BEGIN", context["marker_start"])
        self.assertNotIn(context["marker_start"], payload["memories"][0]["text"])
        self.assertEqual(context["marked_text"].count(context["marker_start"]), 1)

    def test_public_rehash_cannot_hide_item_source_hash_disagreement(self):
        payload = self.payload("「青枫」")
        pool = propose_candidates(payload, self.policy, [])
        pool["candidates"][0]["source_sha256"] = "f"*64
        self.rehash(pool)
        with self.assertRaisesRegex(ValueError, "candidate_source_hash_mismatch"):
            candidate_context(payload, self.policy, pool, "C0001")

    def test_public_rehash_cannot_hide_candidate_schema_cid_or_category_errors(self):
        payload = self.payload("「青枫」")
        original = propose_candidates(payload, self.policy, [])
        for changes in ({"cid": "not-a-cid"}, {"allowed_categories": ["PERSON"]},
                        {"proposed_category": "PERSON"}, {"proposal_sources": ["scoring_gold"]},
                        {"proposed_category": "CUSTOMER"}, {"start": True}, {"extra": "not allowed"}):
            pool = copy.deepcopy(original)
            pool["candidates"][0].update(changes)
            self.rehash(pool)
            with self.assertRaises(ValueError):
                candidate_context(payload, self.policy, pool, "C0001")
        pool = copy.deepcopy(original)
        pool["candidates"].append(copy.deepcopy(pool["candidates"][0]))
        self.rehash(pool)
        with self.assertRaisesRegex(ValueError, "candidate_id_invalid"):
            candidate_context(payload, self.policy, pool, "C0001")


if __name__ == "__main__":
    unittest.main()
