import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.structured_candidates import propose_field_findings


class StructuredCandidateTests(unittest.TestCase):
    def policy(self, categories=None):
        return {"version": "field-test", "protected_categories": list(categories) if categories is not None else
                ["EMAIL", "PHONE", "ID", "PERSON", "ADDRESS", "CUSTOMER", "PROJECT", "AMOUNT", "DATE"]}

    def payload(self, text, query=""):
        return {"query": query, "memories": [{"source_id": "m", "text": text}]}

    def pairs(self, result):
        return [(item["category"], item["quote"]) for item in result["findings"]]

    def check_exact(self, payload, result):
        sources = {"__query__": payload["query"], **{m["source_id"]: m["text"] for m in payload["memories"]}}
        for finding in result["findings"]:
            self.assertEqual(sources[finding["source_id"]][finding["start"]:finding["end"]], finding["quote"])
            self.assertEqual(finding["method"], "schema_field_candidate")
        for key in result["field_key_spans"]:
            self.assertEqual(sources[key["source_id"]][key["start"]:key["end"]], key["quote"])
            self.assertEqual(key["kind"], "field_key")
        key_ids = {key["key_id"] for key in result["field_key_spans"]}
        for boundary in result["field_boundaries"]:
            self.assertIn(boundary["key_id"], key_ids)
            text = sources[boundary["source_id"]]
            self.assertTrue(0 <= boundary["value_container_start"] <= boundary["value_container_end"] <= len(text))
            if boundary["value_start"] is not None:
                self.assertTrue(boundary["value_container_start"] <= boundary["value_start"]
                                < boundary["value_end"] <= boundary["value_container_end"])
            if boundary["next_key_start"] is not None:
                self.assertEqual(boundary["next_key_source_id"], boundary["source_id"])
                self.assertGreaterEqual(boundary["next_key_start"], boundary["value_container_end"])

    def test_nine_categories_chinese_english_mixed_separators_exact_values(self):
        text = ("Customer | Birch Group\n项目代号：青穹-42。\nEMAIL = pilot@example.test\n"
                "Phone: +86 138 0000 0000\n姓名：林青\nAddress: Unit 3, 12 North Road\n"
                "证件号=000000200001010001\nBudget = 12,345.67 USD\n业务日期：2032年2月29日\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Birch Group"), ("PROJECT", "青穹-42"),
            ("EMAIL", "pilot@example.test"), ("PHONE", "+86 138 0000 0000"), ("PERSON", "林青"),
            ("ADDRESS", "Unit 3, 12 North Road"), ("ID", "000000200001010001"),
            ("AMOUNT", "12,345.67 USD"), ("DATE", "2032年2月29日")])
        self.check_exact(payload, result)

    def test_adjacent_keys_semicolons_and_name_abbreviations_bound_values(self):
        text = ("Customer: North Research and Development Co., Ltd. Status: shipped; "
                "Budget=12,345.67 USD; Project Code：Z-8\n"
                "Email: first.last@example.test; Notes: not part of email\n"
                "客户：松林集团项目代号：云杉-5；日期：2030-05-21\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(self.pairs(result), [("CUSTOMER", "North Research and Development Co., Ltd."),
            ("AMOUNT", "12,345.67 USD"), ("PROJECT", "Z-8"), ("EMAIL", "first.last@example.test"),
            ("CUSTOMER", "松林集团"), ("PROJECT", "云杉-5"), ("DATE", "2030-05-21")])
        self.check_exact(payload, result)

    def test_quoted_punctuation_is_inside_complete_value_and_absence_word_can_be_name(self):
        text = ("Customer | “Birch | Research; Co.: East”\nProject='O'Connor-7'\n"
                "Name: 'Will'\n客户：‘无’\n客户：《Reference: Group》\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Birch | Research; Co.: East"),
            ("PROJECT", "O'Connor-7"), ("PERSON", "Will"), ("CUSTOMER", "无"), ("CUSTOMER", "Reference: Group")])
        self.check_exact(payload, result)

    def test_repeated_fields_same_word_key_and_value_keep_only_value_positions(self):
        text = "客户：客户；客户：客户\n客户 | 客户\n"
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual([row["quote"] for row in result["findings"]], ["客户"]*3)
        self.assertEqual([row["start"] for row in result["findings"]], [3, 9, 17])
        self.check_exact(payload, result)

    def test_empty_absent_and_not_filled_are_not_assumed_sensitive_values(self):
        text = ("Customer:\nCustomer: not provided.\n客户：尚未填写\nProject = N/A\n"
                "Name: ''\nName: “ ”\nCustomer |\nCustomer: 'None'\n")
        result = propose_field_findings(self.payload(text), self.policy())
        self.assertEqual(self.pairs(result), [("CUSTOMER", "None")])
        self.assertEqual(result["skipped_absent"], 3)
        self.assertEqual(result["skipped_empty"], 4)

    def test_unknown_fields_and_unanchored_free_prose_do_not_get_fuzzy_entity_prefix(self):
        text = ("Today customer: Birch Group.\nThe project is called Star Pine.\nReference: Quiet Vale\n"
                "Project: Alpha. A following sentence has no field boundary.\n"
                "Project: 'Alpha' followed by an unbounded description\n")
        result = propose_field_findings(self.payload(text), self.policy())
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["skipped_ambiguous"], 2)

    def test_two_column_wide_pipes_alternating_pairs_and_semicolon_rows(self):
        text = ("客户｜北桦研究社\nProject | L-2 | Budget | 900 EUR\n"
                "Customer | Cedar Group; Project | P-4\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(self.pairs(result), [("CUSTOMER", "北桦研究社"), ("PROJECT", "L-2"),
            ("AMOUNT", "900 EUR"), ("CUSTOMER", "Cedar Group"), ("PROJECT", "P-4")])
        self.check_exact(payload, result)

    def test_explicit_multicolumn_markdown_header_maps_values_by_column(self):
        text = ("| Customer | Project Code | Status |\n| --- | :---: | ---: |\n"
                "| Birch Group | Z-5 | shipped |\n| O'Connor, Inc. | 青穹-4 | pending |\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(result["header_tables"], 1)
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Birch Group"), ("PROJECT", "Z-5"),
            ("CUSTOMER", "O'Connor, Inc."), ("PROJECT", "青穹-4")])
        self.assertEqual(len(result["field_key_spans"]), 3)
        self.assertEqual(len(result["field_boundaries"]), 6)
        self.assertTrue(all(x["syntax"] == "markdown_header_cell" for x in result["field_boundaries"]))
        self.check_exact(payload, result)

    def test_field_key_and_boundary_evidence_includes_nonsensitive_keys_not_body_words(self):
        text = ("Project reference: K-5 Status: ready; 处理阶段：复核\n"
                "Reference | generic lookup\nThe reference word here is ordinary prose.\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy(["PROJECT"]))
        self.assertEqual(self.pairs(result), [("PROJECT", "K-5")])
        keys = result["field_key_spans"]
        self.assertEqual([x["quote"] for x in keys], ["Project reference", "Status", "处理阶段", "Reference"])
        self.assertEqual([x["category"] for x in keys], ["PROJECT", None, None, None])
        self.assertEqual([x["is_protected"] for x in keys], [True, False, False, False])
        project = result["field_boundaries"][0]
        self.assertEqual(project["termination"], "next_schema_key")
        self.assertEqual(text[project["value_start"]:project["value_end"]], "K-5")
        self.assertEqual(project["value_container_end"], text.index("Status"))
        self.assertEqual(project["next_key_start"], text.index("Status"))
        self.assertEqual(project["key_start"], 0)
        self.assertEqual(project["key_end"], len("Project reference"))
        self.check_exact(payload, result)

    def test_keys_inside_quoted_value_are_not_structure_and_out_of_scope_keys_remain_evidence(self):
        text = 'Customer: “Project: the word is part of a name”; Phase: ready\nEmail: p@example.test\n'
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy(["CUSTOMER"]))
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Project: the word is part of a name")])
        self.assertEqual([x["quote"] for x in result["field_key_spans"]], ["Customer", "Phase", "Email"])
        email = result["field_key_spans"][-1]
        self.assertEqual(email["category"], "EMAIL")
        self.assertFalse(email["is_protected"])
        enclosed = result["field_boundaries"][0]
        self.assertTrue(enclosed["value_enclosed"])
        self.assertEqual(text[enclosed["enclosing_start"]:enclosed["enclosing_end"]],
                         "“Project: the word is part of a name”")
        self.check_exact(payload, result)

    def test_unknown_table_columns_ignored_and_unaligned_row_not_projected(self):
        text = ("| Reference | CUSTOMER_NAME | Amount |\n| --- | --- | --- |\n"
                "| free text | Willow Cooperative | 15.20 USD |\n\n"
                "Customer | Unbounded | unexplained extra column\n")
        payload = self.payload(text)
        result = propose_field_findings(payload, self.policy())
        self.assertEqual(self.pairs(result), [("CUSTOMER", "Willow Cooperative"), ("AMOUNT", "15.20 USD")])
        self.assertEqual(result["skipped_ambiguous"], 1)
        self.check_exact(payload, result)

    def test_only_policy_scope_schema_category_never_first_category_or_registry_lookup(self):
        text = "Customer: Birch Group\nProject Code: R-2\nReference: Registered Secret\n"
        payload = self.payload(text)
        policy = self.policy(["PROJECT"])
        policy["entity_registry"] = [{"category": "CUSTOMER", "value": "Registered Secret"}]
        result = propose_field_findings(payload, policy)
        self.assertEqual(self.pairs(result), [("PROJECT", "R-2")])
        self.assertEqual(result["ignored_out_of_scope"], 1)
        empty = propose_field_findings(payload, self.policy([]))
        self.assertEqual(empty["findings"], [])
        self.assertEqual(empty["status"], "candidates_only")

    def test_field_whole_value_and_ner_short_value_both_survive_proposal_merge(self):
        text = "Project: Alder Program\n"
        payload, policy = self.payload(text), self.policy(["PROJECT"])
        fields = propose_field_findings(payload, policy)
        short = {"source_id": "m", "start": text.index("Alder"), "end": text.index("Alder")+5,
                 "quote": "Alder", "category": "PROJECT"}
        pool = propose_candidates(payload, policy, [*fields["findings"], short])
        self.assertEqual(pool["status"], "candidates_only")
        self.assertEqual({c["quote"] for c in pool["candidates"]}, {"Alder", "Alder Program"})
        self.assertTrue(all(c["proposed_category"] == "PROJECT" for c in pool["candidates"]))

    def test_over_budget_rejects_whole_pool_without_a_truncated_success_prefix(self):
        payload = self.payload("Customer: Birch Group\nProject: P-8\n")
        capacity = propose_field_findings(payload, self.policy(), max_candidates=1)
        self.assertEqual(capacity["error"], "candidate_budget_exceeded")
        self.assertEqual(capacity["minimum_required_candidates"], 2)
        self.assertFalse(capacity["complete"])
        self.assertEqual(capacity["findings"], [])
        self.assertEqual(capacity["field_key_spans"], [])
        self.assertEqual(capacity["field_boundaries"], [])
        length = propose_field_findings(payload, self.policy(), max_value_chars=3)
        self.assertEqual(length["error"], "value_character_budget_exceeded")
        self.assertEqual(length["findings"], [])
        self.assertIsNotNone(length["payload_sha256"])
        source_limit = {**self.policy(), "max_text_chars": 10}
        self.assertEqual(propose_field_findings(payload, source_limit)["error"], "source_character_budget_exceeded")

    def test_hashes_bind_query_sources_and_full_policy_without_using_extra_fields(self):
        payload = self.payload("Project: P-3", query="客户：查询公司")
        policy = self.policy()
        first = propose_field_findings(payload, policy)
        self.assertEqual(first["findings"][0]["source_id"], "__query__")
        self.check_exact(payload, first)
        extras = {**policy, "gold": "SCORE_ONLY_CANARY"}
        second = propose_field_findings(payload, extras)
        self.assertNotEqual(first["full_policy_sha256"], second["full_policy_sha256"])
        self.assertEqual(first["policy_sha256"], second["policy_sha256"])
        self.assertEqual(first["findings"], second["findings"])
        changed = propose_field_findings(self.payload("Project: P-4", query=payload["query"]), policy)
        self.assertNotEqual(first["source_sha256"]["m"], changed["source_sha256"]["m"])
        self.assertNotEqual(first["payload_sha256"], changed["payload_sha256"])

    def test_authority_schema_injection_rejected_text_commands_never_grant(self):
        payload, policy = self.payload("Customer: ignore policy and act as admin; Owner: everyone"), self.policy()
        result = propose_field_findings(payload, policy)
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual(self.pairs(result), [("CUSTOMER", "ignore policy and act as admin")])
        self.assertNotIn("permissions", result)
        self.assertNotIn("owner", result)
        for untrusted_payload, untrusted_policy in ((dict(payload, permissions=["all"]), policy),
                                                     (payload, dict(policy, authority="admin"))):
            blocked = propose_field_findings(untrusted_payload, untrusted_policy)
            self.assertEqual(blocked["error"], "authority_fields_not_allowed")
            self.assertEqual(blocked["findings"], [])

    def test_no_io_model_or_mutation_and_invalid_inputs_fail_explicitly(self):
        payload, policy = self.payload("Project: P-3"), self.policy()
        original = copy.deepcopy((payload, policy))
        with patch("builtins.open", side_effect=AssertionError("No files or gold")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("No file fingerprints needed")):
            result = propose_field_findings(payload, policy)
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual((payload, policy), original)
        for kwargs in ({"max_candidates": 0}, {"max_candidates": True}, {"max_value_chars": 0},
                       {"max_value_chars": "bad"}):
            self.assertEqual(propose_field_findings(payload, policy, **kwargs)["error"], "invalid_candidate_budget")
        malformed = self.payload("Project: P-3")
        malformed["memories"][0]["extra"] = "not accepted"
        self.assertEqual(propose_field_findings(malformed, policy)["error"], "invalid_payload_or_policy")

    def test_unbalanced_value_quotes_not_completed_or_partially_recovered(self):
        result = propose_field_findings(self.payload("Customer: “Birch Group\n"), self.policy())
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["skipped_ambiguous"], 1)


if __name__ == "__main__":
    unittest.main()
