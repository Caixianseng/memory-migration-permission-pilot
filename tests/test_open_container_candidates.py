import copy
import json
import random
import string
import unittest
from unittest.mock import patch

from memory_migration_study.open_container_candidates import (
    DEFAULT_CONFIG, MAX_INPUT_FINDINGS, VERSION, propose_open_container_candidates,
    validate_open_container_candidates,
)


class OpenContainerCandidateTests(unittest.TestCase):
    def payload(self, text, *, query="", sid="opaque-source"):
        return {"query": query, "memories": [{"source_id": sid, "text": text}]}

    def policy(self, categories=None):
        return {"version": "independent-container-fixture-v1", "protected_categories":
                list(categories) if categories is not None else ["CUSTOMER", "PROJECT", "PERSON"]}

    def seed(self, text, quote, category="CUSTOMER", *, start=None, sid="opaque-source"):
        start = text.index(quote) if start is None else start
        return {"source_id": sid, "start": start, "end": start+len(quote),
                "quote": quote, "category": category, "method": "independent_fixture"}

    def run_case(self, text, seeds, *, policy=None, config=None, query=""):
        payload = self.payload(text, query=query)
        policy = self.policy() if policy is None else policy
        result = propose_open_container_candidates(payload, policy, seeds, config=config)
        self.assertEqual(validate_open_container_candidates(payload, policy, seeds,
            json.loads(json.dumps(result)), config=config), result)
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(result["version"], VERSION)
        self.assertNotIn("findings", result)
        self.assertTrue(all(d["retained"] for d in result["decisions"]))
        self.assertEqual(len(result["decisions"]), len(seeds))
        sources = {"__query__": query, "opaque-source": text}
        for candidate in result["completions"]:
            self.assertEqual(sources[candidate["source_id"]][candidate["start"]:candidate["end"]], candidate["quote"])
            self.assertEqual(candidate["semantic_atomicity"], "unverified")
            self.assertTrue(candidate["seed_ids"])
        return result

    def test_random_unknown_keys_and_names_have_no_name_or_alias_dependency(self):
        rng = random.Random(95031)
        for _ in range(60):
            key = "栏"+"".join(rng.choices(string.ascii_letters, k=12))+"字段"
            value = "".join(rng.choices("榛砚茵沅栩岚霜苇澄岑", k=7))+"研制合作社"
            text = key+"："+value
            with self.subTest(key=key):
                result = self.run_case(text, [self.seed(text, "合作社")])
                self.assertEqual(result["status"], "candidates_only")
                self.assertEqual([c["quote"] for c in result["completions"]], [value])
                self.assertEqual(result["decisions"][0]["action"], "proposed_completion")

    def test_sensitive_person_key_is_retained_not_declared_public(self):
        text = "Emira Solano = approved"
        result = self.run_case(text, [self.seed(text, "Emira Solano", "PERSON")])
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["decisions"][0]["role"], "key")
        self.assertEqual(result["decisions"][0]["action"], "unchanged")
        self.assertEqual(result["decisions"][0]["seed"]["quote"], "Emira Solano")

    def test_project_name_inside_key_is_not_replaced_by_status(self):
        text = "Project Citrine-27 = approved"
        result = self.run_case(text, [self.seed(text, "Citrine-27", "PROJECT")])
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["decisions"][0]["reason"], "key_occurrence_retained")

    def test_reference_key_and_actual_reference_value_have_distinct_roles(self):
        text = "Project reference = Reference Group\nReference is mentioned elsewhere."
        seeds = [self.seed(text, "reference", "PROJECT"),
                 self.seed(text, "Reference", "PROJECT"),
                 self.seed(text, "Reference", "PROJECT", start=text.rindex("Reference"))]
        result = self.run_case(text, seeds)
        self.assertEqual([d["role"] for d in result["decisions"]], ["key", "value", "unparsed"])
        self.assertEqual([d["action"] for d in result["decisions"]], ["unchanged", "proposed_completion", "unchanged"])
        self.assertEqual([c["quote"] for c in result["completions"]], ["Reference Group"])

    def test_role_word_can_be_the_exact_named_value(self):
        for value in ["客户", "Reference", "client"]:
            text = "随机登记字段："+value
            result = self.run_case(text, [self.seed(text, value)])
            self.assertEqual(result["decisions"][0]["reason"], "already_exact_value")
            self.assertEqual(result["decisions"][0]["seed"]["quote"], value)

    def test_no_typed_seed_does_not_create_category_or_completion(self):
        result = self.run_case("Unlisted field: Solstice Design Guild", [])
        self.assertEqual(len(result["containers"]), 1)
        self.assertNotIn("category", result["containers"][0])
        self.assertEqual(result["completions"], [])

    def test_key_and_value_categories_do_not_compete(self):
        text = "Nerio Vila: Ardent Devices Group"
        seeds = [self.seed(text, "Nerio Vila", "PERSON"), self.seed(text, "Group")]
        result = self.run_case(text, seeds)
        self.assertEqual(result["status"], "candidates_only")
        self.assertEqual(result["completions"][0]["category"], "CUSTOMER")
        self.assertEqual(result["decisions"][0]["action"], "unchanged")

    def test_two_non_nested_entities_require_review(self):
        text = "Unlisted field: Morrow Guild and Trillium Works"
        result = self.run_case(text, [self.seed(text, "Morrow Guild"), self.seed(text, "Trillium Works")])
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["errors"], ["multiple_non_nested_seeds"])

    def test_crossing_overlapping_seeds_are_not_merged_into_one_entity(self):
        text = "Unlisted field: ABCDEFGHI"
        result = self.run_case(text, [self.seed(text, "ABCDE"), self.seed(text, "DEFGH")])
        self.assertEqual(result["completions"], [])
        self.assertIn("multiple_non_nested_seeds", result["errors"])

    def test_nested_and_duplicate_seeds_share_one_completion(self):
        text = "Unlisted field: Ardent Research Guild"
        seeds = [self.seed(text, "Research Guild"), self.seed(text, "Guild"), self.seed(text, "Guild")]
        result = self.run_case(text, seeds)
        self.assertEqual(len(result["completions"]), 1)
        self.assertEqual(result["completions"][0]["seed_ids"], ["S0001", "S0002", "S0003"])

    def test_competing_types_do_not_silently_choose_a_category(self):
        text = "Unlisted field: Ardent Research Guild"
        result = self.run_case(text, [self.seed(text, "Guild"), self.seed(text, "Guild", "PROJECT")])
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["errors"], ["competing_categories"])

    def test_seed_crossing_delimiter_blocks_completion_but_is_retained(self):
        text = "Unlisted field: Ardent Research Guild"
        seeds = [self.seed(text, "field: Ardent"), self.seed(text, "Guild")]
        result = self.run_case(text, seeds)
        self.assertEqual(result["completions"], [])
        self.assertTrue(all(d["action"] == "needs_review" for d in result["decisions"]))

    def test_balanced_wrappers_preserve_offsets_and_do_not_certify_atomicity(self):
        for left, right in [('"', '"'), ("“", "”"), ("〈", "〉"), ("【", "】"), ("(", ")"), ("[", "]")]:
            text = "  Unlisted field = "+left+"Linden Research Guild"+right+"  \r\n"
            with self.subTest(wrapper=left):
                result = self.run_case(text, [self.seed(text, "Guild")])
                self.assertEqual(result["completions"][0]["quote"], "Linden Research Guild")
                self.assertEqual(result["containers"][0]["semantic_atomicity"], "unverified")

    def test_quoted_punctuation_is_literal_not_a_nested_field_or_list(self):
        text = 'Unlisted field: “Key: Russet, Ltd.”'
        result = self.run_case(text, [self.seed(text, "Ltd.")])
        self.assertEqual(result["completions"][0]["quote"], "Key: Russet, Ltd.")
        self.assertEqual(result["completions"][0]["semantic_atomicity"], "unverified")

    def test_in_word_apostrophes_are_not_unclosed_quotes(self):
        text = "Unlisted field: O'Neil Research Guild"
        result = self.run_case(text, [self.seed(text, "Guild")])
        self.assertEqual(result["completions"][0]["quote"], "O'Neil Research Guild")

    def test_escaped_quotes_preserve_raw_characters(self):
        text = 'Unlisted field: "Sol\\"ara Research Guild"'
        result = self.run_case(text, [self.seed(text, "Guild")])
        self.assertEqual(result["completions"][0]["quote"], 'Sol\\"ara Research Guild')

    def test_unbalanced_or_mismatched_wrappers_require_review(self):
        for value in ['“Linden Guild', '[Linden Guild)', 'Linden Guild\\']:
            text = "Unlisted field: "+value
            with self.subTest(value=value):
                result = self.run_case(text, [self.seed(text, "Guild")])
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["completions"], [])
                self.assertIn("unbalanced_quote_or_bracket", result["errors"])

    def test_multiline_quotes_are_never_joined_or_truncated(self):
        text = 'Unlisted field: “Linden\nResearch Guild”'
        result = self.run_case(text, [self.seed(text, "Guild")])
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["status"], "needs_review")

    def test_multiple_fields_lists_json_and_tables_are_not_single_values(self):
        for text in ['X: Linden Guild; Y: approved', 'X: Linden Guild, Other Lab',
                     'X: [Linden Guild, Other Lab]', 'X: {"name": "Linden Guild"}',
                     '{"X": "Linden Guild"}', '| X | Linden Guild |',
                     'X: Linden Guild = approved']:
            with self.subTest(text=text):
                result = self.run_case(text, [self.seed(text, "Guild")])
                self.assertEqual(result["completions"], [])
                self.assertEqual(result["status"], "needs_review")

    def test_unpunctuated_clause_is_not_promoted_to_semantic_entity(self):
        text = "随手备注：该联合社已经同意后续复核"
        result = self.run_case(text, [self.seed(text, "联合社")])
        self.assertEqual(result["completions"][0]["quote"], "该联合社已经同意后续复核")
        self.assertEqual(result["completions"][0]["semantic_atomicity"], "unverified")
        self.assertNotIn("findings", result)
        self.assertNotIn("authorized", result)

    def test_two_unpunctuated_entities_are_reviewed_by_seed_geometry(self):
        text = "随手备注：甲研究会联系乙合作社"
        result = self.run_case(text, [self.seed(text, "甲研究会"), self.seed(text, "乙合作社")])
        self.assertEqual(result["completions"], [])
        self.assertEqual(result["errors"], ["multiple_non_nested_seeds"])

    def test_budget_failures_clear_all_containers_and_completions(self):
        cases = [("Good: Linden Guild\nSecond: Pine Lab", {"max_containers": 1}, "container_budget_exceeded"),
                 ("Good: Linden Guild\nLongerKey: Pine Lab", {"max_key_chars": 5}, "key_character_budget_exceeded"),
                 ("Good: Linden Guild\nSecond: ABCDEFGHIJKLMNOPQRSTUVW", {"max_value_chars": 20}, "value_character_budget_exceeded"),
                 ("Good: Linden Guild", {"max_input_chars": 10}, "input_character_budget_exceeded")]
        for text, config, error in cases:
            with self.subTest(error=error):
                result = self.run_case(text, [self.seed(text, "Guild")], config=config)
                self.assertEqual(result["containers"], [])
                self.assertEqual(result["completions"], [])
                self.assertEqual(result["errors"], [error])
                self.assertFalse(result["complete"])

    def test_total_input_budget_counts_query_and_all_sources(self):
        text = "X: Linden Guild"
        result = self.run_case(text, [self.seed(text, "Guild")], query="Q"*10,
                               config={"max_input_chars": len(text)+9})
        self.assertEqual(result["errors"], ["input_character_budget_exceeded"])

    def test_invalid_config_cannot_relax_caps_or_use_bool_integers(self):
        for config in [{"max_containers": 129}, {"max_key_chars": 81}, {"max_value_chars": 257},
                       {"max_input_chars": 4097}, {"max_containers": True}, {"max_containers": 0},
                       {"permit_all": True}, []]:
            with self.subTest(config=config):
                result = propose_open_container_candidates(self.payload("X: a"), self.policy(), [], config=config)
                self.assertEqual(result["errors"], ["invalid_config"])
                self.assertEqual(result["containers"], [])

    def test_invalid_input_finding_binding_cannot_supply_fake_evidence_or_authority(self):
        text = "X: Linden Guild"
        original = self.seed(text, "Guild")
        mutations = [dict(original, quote="Fake"), dict(original, start=True), dict(original, source_id="elsewhere"),
                     dict(original, policy_id="another"), dict(original, category="EMAIL"),
                     dict(original, source_sha256="a"*64), dict(original, authorized=True),
                     dict(original, provenance=[{"source_id": "opaque-source", "start": 0, "end": 1, "quote": "bad"}])]
        for seed in mutations:
            with self.subTest(seed=seed):
                result = propose_open_container_candidates(self.payload(text), self.policy(), [seed])
                self.assertEqual(result["errors"], ["invalid_payload_policy_or_findings"])
                self.assertEqual(result["completions"], [])

    def test_full_failure_for_seed_budget_and_duplicate_source_identity(self):
        text = "X: Linden Guild";seed = self.seed(text, "Guild")
        result = propose_open_container_candidates(self.payload(text), self.policy(), [seed]*(MAX_INPUT_FINDINGS+1))
        self.assertEqual(result["errors"], ["input_finding_budget_exceeded"])
        payload = self.payload(text);payload["memories"].append(dict(payload["memories"][0]))
        result = propose_open_container_candidates(payload, self.policy(), [seed])
        self.assertEqual(result["errors"], ["invalid_payload_policy_or_findings"])

    def test_verifier_recomputes_positions_roles_types_and_closed_shape(self):
        text = "X: Linden Guild";payload=self.payload(text);policy=self.policy();seeds=[self.seed(text, "Guild")]
        result = propose_open_container_candidates(payload, policy, seeds)
        modifications = [lambda r:r.update(authorization="allow"), lambda r:r.update(complete=1),
                         lambda r:r["source_sha256"].update({"opaque-source":"0"*64}),
                         lambda r:r["containers"][0].update(key_end=2),
                         lambda r:r["decisions"][0].update(role="key"),
                         lambda r:r["completions"][0].update(category="PROJECT"),
                         lambda r:r["completions"][0].update(semantic_atomicity="proven"),
                         lambda r:r["completions"][0].update(start=0),
                         lambda r:r["completions"][0].update(seed_ids=[])]
        for change in modifications:
            tampered = copy.deepcopy(result);change(tampered)
            with self.assertRaisesRegex(ValueError, "^open_container_evidence_mismatch$"):
                validate_open_container_candidates(payload, policy, seeds, tampered)

    def test_saved_evidence_is_bound_to_full_policy_sources_seeds_and_config(self):
        text="X: Linden Guild";payload=self.payload(text);policy=self.policy();seeds=[self.seed(text, "Guild")]
        result=propose_open_container_candidates(payload,policy,seeds)
        changed_payload=copy.deepcopy(payload);changed_payload["query"]="new query"
        changed_policy=dict(policy, instructions="new policy instruction")
        changed_seed=dict(seeds[0], method="different production detector")
        for p,q,s,cfg in [(changed_payload,policy,seeds,None),(payload,changed_policy,seeds,None),
                          (payload,policy,[changed_seed],None),(payload,policy,seeds,{"max_key_chars":79})]:
            with self.assertRaisesRegex(ValueError,"^open_container_evidence_mismatch$"):
                validate_open_container_candidates(p,q,s,result,config=cfg)

    def test_source_id_is_binding_only_not_a_semantic_feature(self):
        text="Unknown: Linden Guild";policy=self.policy()
        outputs=[]
        for sid in ["opaque-1","case_customer_gold_private", "story_public_project"]:
            payload=self.payload(text,sid=sid);seed=self.seed(text,"Guild",sid=sid)
            result=propose_open_container_candidates(payload,policy,[seed])
            outputs.append((result["completions"][0]["quote"],result["completions"][0]["category"],
                            result["decisions"][0]["action"]))
        self.assertEqual(outputs,[outputs[0]]*3)

    def test_inputs_unchanged_and_no_runtime_io(self):
        text="Unknown: Linden Guild";args=(self.payload(text),self.policy(),[self.seed(text,"Guild")])
        before=copy.deepcopy(args)
        with patch("builtins.open", side_effect=AssertionError("file access")), \
             patch("socket.socket", side_effect=AssertionError("network access")):
            first=propose_open_container_candidates(*args)
            second=validate_open_container_candidates(*args,first)
        self.assertEqual(first,second)
        self.assertEqual(args,before)
        self.assertEqual(dict(DEFAULT_CONFIG),{"max_containers":128,"max_key_chars":80,"max_value_chars":256,"max_input_chars":4096})


if __name__ == "__main__":
    unittest.main()
