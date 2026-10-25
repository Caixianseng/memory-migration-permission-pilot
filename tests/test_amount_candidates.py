import copy
import unittest

from memory_migration_study.amount_candidates import complete_amount_findings
from memory_migration_study.candidate_proposals import _exact_reference, propose_candidates
from memory_migration_study.privacy import _digest, _sources


class AmountCandidateTests(unittest.TestCase):
    def policy(self, categories=None):
        return {"version": "amount-test", "protected_categories": ["AMOUNT"] if categories is None else categories}

    def payload(self, text, query=""):
        return {"query": query, "memories": [{"source_id": "m", "text": text}]}

    def span(self, text, quote, *, start=None, source_id="m", category="AMOUNT"):
        start = text.index(quote) if start is None else start
        self.assertEqual(text[start:start+len(quote)], quote)
        return {"source_id": source_id, "start": start, "end": start+len(quote), "quote": quote, "category": category}

    def complete(self, text, left, right):
        payload = self.payload(text)
        findings = [self.span(text, left), self.span(text, right)]
        return complete_amount_findings(payload, self.policy(), findings)

    def test_chinese_prefix_and_suffix_complete_exact_with_provenance(self):
        text = "预算：人民币318,600元；状态：待批。"
        result = self.complete(text, "人民币318,600", "318,600元")
        self.assertEqual(result["status"], "candidates_only")
        self.assertTrue(result["complete"])
        self.assertEqual([row["quote"] for row in result["findings"]], ["人民币318,600元"])
        self.assertEqual(len(result["findings"][0]["provenance"]), 2)
        for row in result["findings"]:
            _exact_reference(row, _sources(self.payload(text)), category_required=True)

    def test_english_double_currency_is_literal_and_proposal_compatible(self):
        text = "Budget: USD 410,000 USD; status: ready"
        result = self.complete(text, "USD 410,000", "410,000 USD")
        self.assertEqual([row["quote"] for row in result["findings"]], ["USD 410,000 USD"])
        pool = propose_candidates(self.payload(text), self.policy(), result["findings"])
        self.assertEqual(pool["status"], "candidates_only")
        self.assertEqual(pool["candidates"][0]["quote"], "USD 410,000 USD")

    def test_aliases_decimal_and_horizontal_spacing(self):
        for text, left, right in [("RMB 12.50 yuan", "RMB 12.50", "12.50 yuan"),
                                  ("eur\t34.25 欧元", "eur\t34.25", "34.25 欧元"),
                                  ("£8 British pounds", "£8", "8 British pounds"),
                                  ("US$0.50美元", "US$0.50", "0.50美元"),
                                  ("CNY 2万元", "CNY 2万", "2万元")]:
            with self.subTest(text=text):
                self.assertEqual([row["quote"] for row in self.complete(text, left, right)["findings"]], [text])

    def test_conflicting_currencies_are_not_merged(self):
        for text, left, right in [("USD 100 CNY", "USD 100", "100 CNY"),
                                  ("EUR100美元", "EUR100", "100美元")]:
            result = self.complete(text, left, right)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["unmerged_reasons"], {"incompatible_currencies": 1})

    def test_two_independent_amounts_and_equal_numbers_do_not_merge(self):
        text = "USD100; 100美元"
        self.assertEqual(self.complete(text, "USD100", "100美元")["findings"], [])
        text = "USD100 USD200 USD"
        findings = [self.span(text, "USD100"), self.span(text, "200 USD")]
        self.assertEqual(complete_amount_findings(self.payload(text), self.policy(), findings)["findings"], [])

    def test_equal_value_distinct_positions_each_complete_separately(self):
        text = "人民币100元；人民币100元"
        findings = [self.span(text, "人民币100", start=0), self.span(text, "100元", start=3),
                    self.span(text, "人民币100", start=8), self.span(text, "100元", start=11)]
        result = complete_amount_findings(self.payload(text), self.policy(), findings)
        self.assertEqual([(row["start"], row["end"]) for row in result["findings"]], [(0, 7), (8, 15)])

    def test_same_text_different_sources_cannot_complete(self):
        text = "USD100 USD"
        payload = {"query": "", "memories": [{"source_id": "a", "text": text}, {"source_id": "b", "text": text}]}
        findings = [self.span(text, "USD100", source_id="a"), self.span(text, "100 USD", source_id="b")]
        self.assertEqual(complete_amount_findings(payload, self.policy(), findings)["findings"], [])

    def test_query_is_a_bound_source_not_memory_evidence(self):
        text = "USD100 USD"
        payload = self.payload("", query=text)
        findings = [self.span(text, "USD100", source_id="__query__"), self.span(text, "100 USD", source_id="__query__")]
        result = complete_amount_findings(payload, self.policy(), findings)
        self.assertEqual(result["findings"][0]["source_id"], "__query__")
        self.assertEqual(set(result["source_sha256"]), {"__query__", "m"})

    def test_cross_line_field_and_prose_spans_are_not_completed(self):
        for text, left, right in [("USD\n100 USD", "USD\n100", "100 USD"),
                                  ("USD100\nUSD", "USD100", "100\nUSD"),
                                  ("USD100; Currency: USD", "USD100", "100; Currency: USD"),
                                  ("USD100 to USD200", "USD100 to USD", "100 to USD200")]:
            with self.subTest(text=text):
                self.assertEqual(self.complete(text, left, right)["findings"], [])

    def test_illegal_number_formats_remain_original_unmerged(self):
        for number in ("12,34", "01", "1.2.3", "1e3", "-100", "1,000,00", "１２０", "1.", "1,2345"):
            text = "USD"+number+" USD"
            with self.subTest(number=number):
                result = self.complete(text, "USD"+number, number+" USD")
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["unmerged_crossing_pairs"], 1)

    def test_partial_identifier_boundary_and_mismatched_numeric_positions(self):
        text = "XUSD100 USD"
        self.assertEqual(self.complete(text, "USD100", "100 USD")["findings"], [])
        text = "USD1000 USD"
        self.assertEqual(self.complete(text, "USD1000", "000 USD")["findings"], [])
        text = "USD1234 USD"
        result = self.complete(text, "USD1234", "234 USD")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["unmerged_reasons"], {"different_numeric_intervals": 1})
        text = "USD100 USDX"
        self.assertEqual(self.complete(text, "USD100", "100 USD")["findings"], [])

    def test_unicode_case_confusables_do_not_expand_alias_vocabulary(self):
        text = "Brıtısh pounds100 GBP"
        self.assertEqual(self.complete(text, "Brıtısh pounds100", "100 GBP")["findings"], [])

    def test_nested_duplicates_and_existing_complete_not_added(self):
        text = "USD100 USD"
        findings = [self.span(text, "USD100"), self.span(text, "100 USD")]
        duplicate = complete_amount_findings(self.payload(text), self.policy(), findings+findings)
        self.assertEqual(len(duplicate["findings"]), 1)
        self.assertEqual(duplicate["inspected_amount_findings"], 2)
        result = complete_amount_findings(self.payload(text), self.policy(), findings+[self.span(text, text)])
        self.assertEqual(result["findings"], [])

    def test_non_amount_scope_empty_scope_and_unrelated_category(self):
        text = "USD100 USD"
        findings = [self.span(text, "USD100"), self.span(text, "100 USD")]
        for categories in ([], ["CUSTOMER"]):
            result = complete_amount_findings(self.payload(text), self.policy(categories), findings)
            self.assertEqual(result["status"], "candidates_only")
            self.assertEqual(result["findings"], [])
        findings[1]["category"] = "CUSTOMER"
        self.assertEqual(complete_amount_findings(self.payload(text), self.policy(), findings)["findings"], [])

    def test_input_unchanged_full_bindings_and_registry_not_used(self):
        text = "USD100 USD"
        payload, policy = self.payload(text), self.policy()
        policy["entity_registry"] = [{"value": "invented", "category": "AMOUNT"}]
        findings = [self.span(text, "USD100"), self.span(text, "100 USD")]
        before = copy.deepcopy((payload, policy, findings))
        result = complete_amount_findings(payload, policy, findings)
        self.assertEqual((payload, policy, findings), before)
        self.assertEqual(result["payload_sha256"], _digest(payload))
        self.assertEqual(result["full_policy_sha256"], _digest(policy))
        self.assertEqual(result["existing_findings_sha256"], _digest(findings))
        self.assertEqual(len(result["grammar_sha256"]), 64)
        no_findings = complete_amount_findings(self.payload("invented"), policy, [])
        self.assertEqual(no_findings["findings"], [])

    def test_budget_overflow_discards_whole_new_pool(self):
        text = "USD100 USD; EUR200 EUR"
        findings = [self.span(text, part) for part in ("USD100", "100 USD", "EUR200", "200 EUR")]
        result = complete_amount_findings(self.payload(text), self.policy(), findings, max_candidates=1)
        self.assertEqual(result["status"], "needs_review")
        self.assertFalse(result["complete"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["minimum_required_candidates"], 2)

    def test_invalid_input_or_authority_needs_review(self):
        text = "USD100 USD"
        good = [self.span(text, "USD100"), self.span(text, "100 USD")]
        variants = [dict(good[0], quote="different"), dict(good[0], start=True),
                    dict(good[0], source_id="absent"), dict(good[0], owner_id="admin"),
                    dict(good[0], extra="unsupported")]
        for bad in variants:
            result = complete_amount_findings(self.payload(text), self.policy(), [bad, good[1]])
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["findings"], [])
        for limit in (0, True, 4097, "1"):
            self.assertEqual(complete_amount_findings(self.payload(text), self.policy(), good,
                                                     max_candidates=limit)["status"], "needs_review")
        self.assertEqual(complete_amount_findings(self.payload(text), self.policy(), good*2049)["error"],
                         "input_candidate_budget_exceeded")

    def test_policy_and_source_changes_have_distinct_bindings(self):
        text = "USD100 USD"
        findings = [self.span(text, "USD100"), self.span(text, "100 USD")]
        first = complete_amount_findings(self.payload(text), self.policy(), findings)
        changed_policy = dict(self.policy(), instructions="different independent business instructions")
        second = complete_amount_findings(self.payload(text), changed_policy, findings)
        self.assertNotEqual(first["full_policy_sha256"], second["full_policy_sha256"])
        third = complete_amount_findings(self.payload(text+"!"), self.policy(), findings)
        self.assertNotEqual(first["payload_sha256"], third["payload_sha256"])
        self.assertNotEqual(first["source_sha256"], third["source_sha256"])


if __name__ == "__main__":
    unittest.main()
