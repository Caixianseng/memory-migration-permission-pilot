"""Data contract checks only: this module never invokes a detector or model."""
import copy
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.privacy_corpus import CATEGORIES, _digest, validate_corpus
from memory_migration_study.privacy_corpus_v3 import (
    FAMILIES, POLICY_INSTRUCTIONS, _values, build_corpus, validate_v3, write_corpus,
)


class PrivacyCorpusV3ContractTests(unittest.TestCase):
    def setUp(self):
        self.runtime, self.evaluation = build_corpus()
        self.cases = {c["case_id"]: c for c in self.runtime["cases"]}
        self.gold = {r["case_id"]: r["findings"] for r in self.evaluation["cases"]}

    def texts(self, case):
        return {"__query__": case["payload"]["query"],
                **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}

    def test_balanced_case_language_and_split_units(self):
        cases = list(self.cases.values())
        self.assertEqual(len(cases), 80)
        self.assertEqual(Counter(c["language"] for c in cases), {"zh": 40, "en": 40})
        self.assertEqual(Counter(c["split"] for c in cases), {"dev": 40, "heldout": 40})
        self.assertEqual(Counter((c["split"], c["language"]) for c in cases),
                         {("dev", "zh"): 20, ("dev", "en"): 20,
                          ("heldout", "zh"): 20, ("heldout", "en"): 20})
        self.assertEqual(len({c["template_family"] for c in cases}), 20)
        self.assertEqual(len({c["story_id"] for c in cases}), 78)
        for field in ("template_family", "story_id"):
            dev = {c[field] for c in cases if c["split"] == "dev"}
            heldout = {c[field] for c in cases if c["split"] == "heldout"}
            self.assertFalse(dev & heldout)
        self.assertEqual(build_corpus(), (self.runtime, self.evaluation))

    def test_scorer_compatibility_and_no_answer_bearing_detection_inputs(self):
        validate_corpus(self.runtime, self.evaluation)
        self.assertIsNone(self.evaluation["human_review"])
        self.assertEqual(self.evaluation["runtime_sha256"], _digest(self.runtime))
        self.assertEqual(self.runtime["entity_registry_condition"], "unregistered_only")
        for case in self.cases.values():
            self.assertEqual(case["entity_registration"], "unregistered")
            self.assertEqual(set(case["payload"]), {"query", "memories"})
            policy = case["sensitivity_policy"]
            self.assertEqual(set(policy), {"version", "protected_categories", "instructions"})
            self.assertEqual(policy["instructions"], POLICY_INSTRUCTIONS)
            self.assertFalse(set(case) & {"findings", "answer", "expected", "evaluation", "entity_registry"})
            self.assertTrue(all(set(m) == {"source_id", "text"} for m in case["payload"]["memories"]))

    def test_annotations_are_nonoverlapping_complete_source_bound_values(self):
        categories = set()
        for case_id, findings in self.gold.items():
            case = self.cases[case_id]
            texts = self.texts(case)
            occupied = set()
            for span in findings:
                source, start, end, category = (span[k] for k in ("source_id", "start", "end", "category"))
                self.assertIn(source, texts)
                self.assertTrue(0 <= start < end <= len(texts[source]))
                self.assertIn(category, case["sensitivity_policy"]["protected_categories"])
                value = texts[source][start:end]
                self.assertEqual(value, value.strip())
                self.assertTrue(value)
                positions = {(source, i) for i in range(start, end)}
                self.assertFalse(occupied & positions)
                occupied |= positions
                categories.add(category)
        self.assertEqual(categories, set(CATEGORIES))

    def test_all_named_values_including_public_negatives_are_split_disjoint(self):
        surface_values = {"dev": set(), "heldout": set()}
        for i, (_, split) in enumerate(FAMILIES):
            for language in ("zh", "en"):
                for variant in range(2):
                    values = _values(language, i, variant)
                    surface_values[split].update(values[k] for k in
                        ("PERSON", "CUSTOMER", "CUSTOMER_ALT", "PROJECT", "PROJECT_ALT", "ADDRESS", "EMAIL", "ID", "PHONE"))
        self.assertTrue(surface_values["dev"] and surface_values["heldout"])
        self.assertFalse(surface_values["dev"] & surface_values["heldout"])

    def test_repeated_values_are_labeled_in_query_and_every_memory_occurrence(self):
        selected = [c for c in self.cases.values() if "repeated_value" in c["features"]]
        self.assertTrue(selected)
        for case in selected:
            texts = self.texts(case)
            findings = self.gold[case["case_id"]]
            values = {texts[s["source_id"]][s["start"]:s["end"]] for s in findings}
            self.assertTrue(any(s["source_id"] == "__query__" for s in findings))
            for value in values:
                expected = set()
                for source_id, text in texts.items():
                    offset = 0
                    while (start := text.find(value, offset)) >= 0:
                        expected.add((source_id, start, start + len(value)))
                        offset = start + len(value)
                actual = {(s["source_id"], s["start"], s["end"]) for s in findings
                          if texts[s["source_id"]][s["start"]:s["end"]] == value}
                self.assertEqual(actual, expected)

    def test_independent_prefix_names_remain_two_complete_entities(self):
        selected = [c for c in self.cases.values() if "near_prefix_independent_entities" in c["features"]]
        self.assertTrue(selected)
        for case in selected:
            texts = self.texts(case)
            values = {texts[s["source_id"]][s["start"]:s["end"]] for s in self.gold[case["case_id"]]
                      if s["category"] in {"PROJECT", "CUSTOMER"}}
            pairs = [(a, b) for a in values for b in values if a != b and b.startswith(a)]
            self.assertTrue(pairs)
            # Prefix membership is semantic ambiguity, not overlapping annotations.
            for source_id, text in texts.items():
                spans = [s for s in self.gold[case["case_id"]] if s["source_id"] == source_id]
                for a in spans:
                    for b in spans:
                        if a != b:
                            self.assertTrue(a["end"] <= b["start"] or b["end"] <= a["start"])

    def test_unit_and_identifier_suffixes_are_integral_to_gold(self):
        coverage = set()
        for case in self.cases.values():
            texts = self.texts(case)
            for span in self.gold[case["case_id"]]:
                value = texts[span["source_id"]][span["start"]:span["end"]]
                if span["category"] == "ADDRESS":
                    self.assertTrue("B单元1203室" in value or value.startswith("Unit 2B, "))
                    coverage.add("unit")
                if span["category"] == "PROJECT":
                    self.assertRegex(value, r"[0-9]{3}-[AC]7B?$")
                    coverage.add("ascii_code")
                if span["category"] == "CUSTOMER":
                    self.assertTrue("乙字" in value or "No. " in value)
                    coverage.add("organization_number")
        self.assertEqual(coverage, {"unit", "ascii_code", "organization_number"})

    def test_public_and_malicious_claims_do_not_override_trusted_scope(self):
        for feature in ("public_claim_protected", "malicious_policy_override"):
            selected = [c for c in self.cases.values() if feature in c["features"]]
            self.assertTrue(selected)
            self.assertTrue(all(self.gold[c["case_id"]] for c in selected))
            self.assertTrue(all(c["sensitivity_policy"]["protected_categories"] for c in selected))
        public = [c for c in self.cases.values() if "genuinely_public_policy" in c["features"]]
        self.assertEqual(len(public), 8)
        self.assertTrue(all(c["sensitivity_policy"]["protected_categories"] == [] for c in public))
        self.assertTrue(all(self.gold[c["case_id"]] == [] for c in public))

    def test_policy_twins_share_text_and_story_only_within_heldout(self):
        for language in ("zh", "en"):
            a, b = [self.cases[f"archived_scope_pair_v3-{language}-{j}"] for j in (0, 1)]
            self.assertEqual(a["split"], "heldout")
            self.assertEqual(a["story_id"], b["story_id"])
            self.assertEqual(a["payload"], b["payload"])
            self.assertTrue(self.gold[a["case_id"]])
            self.assertFalse(self.gold[b["case_id"]])
            self.assertNotEqual(a["sensitivity_policy"]["version"], b["sensitivity_policy"]["version"])

    def test_freeze_binds_files_generator_and_counts_without_inference(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_corpus(Path(temporary), frozen_at_utc="2026-10-23T00:00:00+00:00")
            manifest = json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["case_count"], 80)
            self.assertEqual(manifest["expected_heldout_cases"], 40)
            self.assertEqual(manifest["story_count"], 78)
            self.assertTrue(manifest["frozen_before_detection"])
            self.assertFalse(manifest["detector_run_at_freeze"])
            self.assertTrue(manifest["named_surface_values_split_disjoint"])
            self.assertIsNone(manifest["human_review"])
            for name in ("runtime", "evaluation"):
                data = Path(paths[name]).read_bytes()
                self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(manifest[f"{name}_sha256"], _digest(json.loads(data)))
            with self.assertRaisesRegex(FileExistsError, "destination_already_exists"):
                write_corpus(Path(temporary))

    def test_tampering_and_answer_bearing_policy_fields_are_rejected(self):
        changed = copy.deepcopy(self.runtime)
        changed["cases"][0]["payload"]["query"] += " changed"
        with self.assertRaisesRegex(ValueError, "gold_runtime_hash_mismatch"):
            validate_v3(changed, self.evaluation)
        for forbidden in ("entity_registry", "answer", "findings"):
            changed = copy.deepcopy(self.runtime)
            changed["cases"][0]["sensitivity_policy"][forbidden] = []
            gold = copy.deepcopy(self.evaluation)
            gold["runtime_sha256"] = _digest(changed)
            with self.assertRaisesRegex(ValueError, "must_not_embed"):
                validate_v3(changed, gold)


if __name__ == "__main__":
    unittest.main()
