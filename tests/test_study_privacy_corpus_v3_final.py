"""Pure data contract tests for the final holdout; no model calls."""
import copy
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.privacy_corpus import CATEGORIES, _digest, validate_corpus
from memory_migration_study.privacy_corpus_v3_final import (
    POLICY_INSTRUCTIONS, build_corpus, validate_final, write_corpus,
)


class FinalPrivacyHoldoutTests(unittest.TestCase):
    def setUp(self):
        self.runtime, self.evaluation = build_corpus()
        self.cases = {c["case_id"]: c for c in self.runtime["cases"]}
        self.gold = {r["case_id"]: r["findings"] for r in self.evaluation["cases"]}

    def texts(self, case):
        return {"__query__": case["payload"]["query"], **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}

    def test_exact_final_holdout_size_and_independent_stories(self):
        self.assertEqual(len(self.cases), 40)
        self.assertEqual(Counter(c["language"] for c in self.cases.values()), {"zh": 20, "en": 20})
        self.assertEqual({c["split"] for c in self.cases.values()}, {"heldout"})
        self.assertEqual(len({c["story_id"] for c in self.cases.values()}), 40)
        self.assertEqual(len({c["template_family"] for c in self.cases.values()}), 10)
        self.assertEqual(build_corpus(), (self.runtime, self.evaluation))

    def test_runtime_contract_never_embeds_scoring_labels_or_lexicon(self):
        validate_corpus(self.runtime, self.evaluation)
        for case in self.cases.values():
            self.assertEqual(case["entity_registration"], "unregistered")
            self.assertEqual(set(case["payload"]), {"query", "memories"})
            self.assertFalse(set(case) & {"findings", "answer", "expected", "entity_registry"})
            self.assertEqual(set(case["sensitivity_policy"]), {"version", "protected_categories", "instructions"})
            self.assertEqual(case["sensitivity_policy"]["instructions"], POLICY_INSTRUCTIONS)
            self.assertTrue(all(set(m) == {"source_id", "text"} for m in case["payload"]["memories"]))

    def test_valid_nonoverlapping_complete_value_spans_cover_all_categories(self):
        observed = set()
        for case_id, spans in self.gold.items():
            texts = self.texts(self.cases[case_id])
            occupied = set()
            for s in spans:
                sid, start, end, category = (s[k] for k in ("source_id", "start", "end", "category"))
                self.assertTrue(0 <= start < end <= len(texts[sid]))
                value = texts[sid][start:end]
                self.assertEqual(value, value.strip())
                positions = {(sid, n) for n in range(start, end)}
                self.assertFalse(occupied & positions)
                occupied |= positions
                observed.add(category)
                if category == "CUSTOMER":
                    self.assertRegex(value, r"(?:第[0-9]{3}号|No\. [0-9]{3})$")
                if category == "ADDRESS":
                    self.assertTrue(value.endswith("C单元502室") or value.startswith("Unit 5C, "))
                if category == "PROJECT":
                    self.assertRegex(value, r"[0-9]{3}QA?$")
        self.assertEqual(observed, set(CATEGORIES))

    def test_query_repetitions_and_independent_near_prefix_entities(self):
        for case in self.cases.values():
            if "repeated_value" not in case["features"]:
                continue
            texts = self.texts(case)
            spans = self.gold[case["case_id"]]
            self.assertTrue(any(s["source_id"] == "__query__" for s in spans))
            values = {texts[s["source_id"]][s["start"]:s["end"]] for s in spans}
            if "near_prefix_independent_entities" in case["features"]:
                self.assertTrue(any(a != b and b.startswith(a) for a in values for b in values))
                continue  # A full independent entity may itself contain the shorter code.
            for value in values:
                expected = {(sid, start, start + len(value)) for sid, text in texts.items()
                            for start in range(len(text)) if text.startswith(value, start)}
                actual = {(s["source_id"], s["start"], s["end"]) for s in spans
                          if texts[s["source_id"]][s["start"]:s["end"]] == value}
                self.assertEqual(actual, expected)

    def test_true_negative_scope_and_publicity_claims_are_distinct(self):
        public = [c for c in self.cases.values() if "genuinely_public_policy" in c["features"]]
        clean = [c for c in self.cases.values() if "genuinely_no_sensitive_values" in c["features"]]
        claimed = [c for c in self.cases.values() if "public_claim_protected" in c["features"]]
        self.assertEqual((len(public), len(clean), len(claimed)), (4, 4, 4))
        self.assertTrue(all(not c["sensitivity_policy"]["protected_categories"] and not self.gold[c["case_id"]] for c in public))
        self.assertTrue(all(set(c["sensitivity_policy"]["protected_categories"]) == set(CATEGORIES) and not self.gold[c["case_id"]] for c in clean))
        self.assertTrue(all(c["sensitivity_policy"]["protected_categories"] and self.gold[c["case_id"]] for c in claimed))

    def test_new_names_and_texts_do_not_reuse_previous_v3(self):
        prior_dir = Path(__file__).resolve().parents[1] / "examples" / "privacy_eval_v3"
        prior_runtime = json.loads((prior_dir / "runtime.json").read_text(encoding="utf-8"))
        prior_gold = json.loads((prior_dir / "evaluation.json").read_text(encoding="utf-8"))
        prior_cases = {c["case_id"]: c for c in prior_runtime["cases"]}
        prior_texts = {text for c in prior_cases.values() for text in self.texts(c).values()}
        current_texts = {text for c in self.cases.values() for text in self.texts(c).values()}
        self.assertFalse(prior_texts & current_texts)
        named = {"PERSON", "CUSTOMER", "PROJECT", "ADDRESS", "EMAIL", "PHONE", "ID"}
        def values(cases, rows):
            return {self.texts(cases[r["case_id"]])[s["source_id"]][s["start"]:s["end"]]
                    for r in rows for s in r["findings"] if s["category"] in named}
        self.assertFalse(values(prior_cases, prior_gold["cases"]) & values(self.cases, self.evaluation["cases"]))

    def test_freeze_manifest_binds_bytes_and_prevents_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_corpus(Path(temporary), frozen_at_utc="2026-10-23T16:00:00+00:00")
            manifest = json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual((manifest["case_count"], manifest["expected_heldout_cases"], manifest["development_cases"]), (40, 40, 0))
            self.assertFalse(manifest["detector_run_at_freeze"])
            self.assertTrue(manifest["frozen_before_detection"])
            self.assertTrue(manifest["not_for_retuning"])
            for name in ("runtime", "evaluation"):
                data = Path(paths[name]).read_bytes()
                self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(manifest[f"{name}_sha256"], _digest(json.loads(data)))
            with self.assertRaises(FileExistsError):
                write_corpus(Path(temporary))
        changed = copy.deepcopy(self.runtime)
        changed["cases"][0]["sensitivity_policy"]["answer"] = "must not be runtime input"
        gold = copy.deepcopy(self.evaluation)
        gold["runtime_sha256"] = _digest(changed)
        with self.assertRaisesRegex(ValueError, "must_not_embed"):
            validate_final(changed, gold)


if __name__ == "__main__":
    unittest.main()
