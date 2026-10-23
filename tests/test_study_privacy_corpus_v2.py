import copy
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.privacy_corpus import _digest, validate_corpus
from memory_migration_study.privacy_corpus_v2 import (
    CATEGORIES, POLICY_INSTRUCTIONS, build_corpus, validate_v2, write_corpus,
)


class IndependentPrivacyCorpusTests(unittest.TestCase):
    def setUp(self):
        self.runtime, self.evaluation = build_corpus()
        self.cases = {case["case_id"]: case for case in self.runtime["cases"]}
        self.gold = {row["case_id"]: row["findings"] for row in self.evaluation["cases"]}

    def test_counts_balance_and_disjoint_independent_units(self):
        cases = list(self.cases.values())
        self.assertEqual(len(cases), 96)
        self.assertEqual(Counter(case["language"] for case in cases), {"zh": 48, "en": 48})
        self.assertEqual(Counter(case["split"] for case in cases), {"dev": 48, "heldout": 48})
        self.assertEqual(len({case["template_family"] for case in cases}), 16)
        self.assertEqual(len({case["story_id"] for case in cases}), 94)
        for field in ("story_id", "template_family"):
            dev = {case[field] for case in cases if case["split"] == "dev"}
            heldout = {case[field] for case in cases if case["split"] == "heldout"}
            self.assertFalse(dev & heldout)
        self.assertEqual(build_corpus(), (self.runtime, self.evaluation))

    def test_scoring_schema_compatible_and_gold_excluded_from_runtime_inputs(self):
        validate_corpus(self.runtime, self.evaluation)
        self.assertIsNone(self.evaluation["human_review"])
        self.assertEqual(self.evaluation["runtime_sha256"], _digest(self.runtime))
        for case in self.cases.values():
            self.assertEqual(case["entity_registration"], "unregistered")
            self.assertEqual(set(case["payload"]), {"query", "memories"})
            self.assertEqual(set(case["sensitivity_policy"]),
                             {"version", "protected_categories", "instructions"})
            self.assertEqual(case["sensitivity_policy"]["instructions"], POLICY_INSTRUCTIONS)
            for memory in case["payload"]["memories"]:
                self.assertEqual(set(memory), {"source_id", "text"})
            self.assertFalse(set(case) & {"findings", "answer", "expected", "evaluation"})

    def test_all_categories_have_valid_source_bound_spans_and_no_overlap(self):
        observed = set()
        for case_id, spans in self.gold.items():
            case = self.cases[case_id]
            texts = {"__query__": case["payload"]["query"],
                     **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}
            occupied = set()
            for span in spans:
                source, start, end, category = (span[k] for k in ("source_id", "start", "end", "category"))
                self.assertIn(source, texts)
                self.assertTrue(0 <= start < end <= len(texts[source]))
                self.assertEqual(texts[source][start:end], texts[source][start:end].strip())
                self.assertIn(category, case["sensitivity_policy"]["protected_categories"])
                positions = {(source, i) for i in range(start, end)}
                self.assertFalse(occupied & positions)
                occupied |= positions
                observed.add(category)
        self.assertEqual(observed, set(CATEGORIES))

    def test_policy_twins_change_gold_while_runtime_text_is_identical(self):
        for language in ("zh", "en"):
            a, b = (self.cases[f"policy_scope_twins_v2-{language}-{j}"] for j in (0, 1))
            self.assertEqual(a["payload"], b["payload"])
            self.assertEqual(a["story_id"], b["story_id"])
            self.assertTrue(self.gold[a["case_id"]])
            self.assertEqual(self.gold[b["case_id"]], [])
            self.assertNotEqual(a["sensitivity_policy"]["version"], b["sensitivity_policy"]["version"])

    def test_repeated_cross_source_values_have_distinct_occurrence_labels(self):
        examples = [case for case in self.cases.values()
                    if "cross_query_memory" in case["features"]
                    and "repeated_value" in case["features"]
                    and self.gold[case["case_id"]]]
        self.assertTrue(examples)
        for case in examples:
            texts = {"__query__": case["payload"]["query"],
                     **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}
            spans = self.gold[case["case_id"]]
            values = {texts[s["source_id"]][s["start"]:s["end"]] for s in spans}
            for value in values:
                # Every exact occurrence of an annotated value must be labeled.
                expected = set()
                for source_id, text in texts.items():
                    offset = 0
                    while (start := text.find(value, offset)) >= 0:
                        expected.add((source_id, start, start + len(value)))
                        offset = start + len(value)
                actual = {(s["source_id"], s["start"], s["end"]) for s in spans
                          if texts[s["source_id"]][s["start"]:s["end"]] == value}
                self.assertEqual(expected, actual)

    def test_public_or_malicious_text_does_not_remove_trusted_scope(self):
        for feature in ("public_claim_protected", "malicious_policy_override"):
            rows = [c for c in self.cases.values() if feature in c["features"]]
            self.assertTrue(rows)
            self.assertTrue(all(self.gold[c["case_id"]] for c in rows))
            self.assertTrue(all(c["sensitivity_policy"]["protected_categories"] for c in rows))
        negatives = [c for c in self.cases.values() if "outside_trusted_scope" in c["features"]]
        self.assertTrue(negatives)
        self.assertTrue(all(self.gold[c["case_id"]] == [] for c in negatives))

    def test_business_surface_values_are_unseen_across_splits(self):
        values = {"dev": set(), "heldout": set()}
        for case_id, spans in self.gold.items():
            case = self.cases[case_id]
            texts = {"__query__": case["payload"]["query"],
                     **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}
            for span in spans:
                if span["category"] in {"CUSTOMER", "PROJECT"}:
                    values[case["split"]].add(texts[span["source_id"]][span["start"]:span["end"]])
        self.assertTrue(values["dev"] and values["heldout"])
        self.assertFalse(values["dev"] & values["heldout"])

    def test_freeze_manifest_binds_bytes_and_canonical_content_without_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_corpus(Path(tmp), frozen_at_utc="2026-10-23T00:00:00+00:00")
            manifest = json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["case_count"], 96)
            self.assertEqual(manifest["expected_heldout_cases"], 48)
            self.assertTrue(manifest["frozen_before_detection"])
            self.assertFalse(manifest["detector_run_at_freeze"])
            self.assertIsNone(manifest["human_review"])
            for name in ("runtime", "evaluation"):
                data = Path(paths[name]).read_bytes()
                self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(manifest[f"{name}_sha256"], _digest(json.loads(data)))
            with self.assertRaisesRegex(FileExistsError, "destination_already_exists"):
                write_corpus(Path(tmp))

    def test_tampering_breaks_runtime_binding_and_extra_policy_fields_rejected(self):
        mutated = copy.deepcopy(self.runtime)
        mutated["cases"][0]["payload"]["query"] += "changed"
        with self.assertRaisesRegex(ValueError, "gold_runtime_hash_mismatch"):
            validate_v2(mutated, self.evaluation)
        mutated = copy.deepcopy(self.runtime)
        mutated["cases"][0]["sensitivity_policy"]["entity_registry"] = []
        evaluation = copy.deepcopy(self.evaluation)
        evaluation["runtime_sha256"] = _digest(mutated)
        with self.assertRaisesRegex(ValueError, "must_not_embed"):
            validate_v2(mutated, evaluation)


if __name__ == "__main__":
    unittest.main()
