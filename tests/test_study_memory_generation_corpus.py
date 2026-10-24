"""Corpus integrity checks; these do not assess detector performance."""

import hashlib
import json
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from memory_migration_study.memory_generation_corpus import (
    build_corpus, canonical_bytes, write_corpus,
)


class MemoryGenerationCorpusTests(unittest.TestCase):
    def setUp(self):
        self.runtime, self.evaluation, self.manifest = build_corpus()

    def test_fixed_denominators_and_source_diversity(self):
        cases = self.runtime["cases"]
        self.assertEqual(len(cases), 24)
        self.assertEqual(Counter(c["language"] for c in cases), {"zh": 12, "en": 12})
        self.assertEqual(Counter(c["split"] for c in cases), {"dev": 12, "heldout": 12})
        self.assertEqual(len({c["case_id"] for c in cases}), 24)
        self.assertEqual(len({c["source"]["source_id"] for c in cases}), 24)
        self.assertEqual(len({c["source"]["text"] for c in cases}), 24)
        self.assertEqual(sum(len(c["tasks"]) for c in cases), 72)

    def test_no_template_family_crosses_split(self):
        families = defaultdict(set)
        for case in self.runtime["cases"]:
            families[self.manifest["template_families"][case["case_id"]]].add(case["split"])
        self.assertEqual(len(families), 12)
        self.assertTrue(all(len(splits) == 1 for splits in families.values()))
        for split in ("dev", "heldout"):
            self.assertEqual(sum(splits == {split} for splits in families.values()), 6)

    def test_gold_is_separate_and_policy_has_no_entity_dictionary(self):
        for case, gold in zip(self.runtime["cases"], self.evaluation["cases"]):
            self.assertEqual(case["case_id"], gold["case_id"])
            self.assertNotIn("sensitive_spans", case)
            self.assertNotIn("expected_answer", case)
            self.assertNotIn("entity_registry", case["policy"])
            metadata = json.dumps({k: v for k, v in case.items() if k != "source"}, ensure_ascii=False)
            for task_gold in gold["tasks"]:
                if task_gold["authorized"]:
                    self.assertNotIn(task_gold["expected_answer"], metadata)
            for task in case["tasks"]:
                self.assertEqual(set(task), {"task_id", "actor_id", "agent_id", "query"})

    def test_sensitive_labels_and_exact_evidence_agree_with_source(self):
        found_categories = set()
        for case, gold in zip(self.runtime["cases"], self.evaluation["cases"]):
            text, last_end = case["source"]["text"], -1
            self.assertTrue(gold["sensitive_spans"])
            for span in gold["sensitive_spans"]:
                self.assertLessEqual(last_end, span["start"])
                self.assertLess(span["start"], span["end"])
                self.assertLessEqual(span["end"], len(text))
                self.assertIn(span["category"], case["policy"]["protected_categories"])
                found_categories.add(span["category"])
                last_end = span["end"]
            for task in gold["tasks"]:
                if task["authorized"]:
                    self.assertIn(task["required_quote"], text)
                    self.assertIn(task["expected_answer"], task["required_quote"])
                    self.assertEqual(text.count(task["expected_answer"]), 1)
                else:
                    self.assertEqual(task["expected_answer"], "UNKNOWN")
                    self.assertIsNone(task["required_quote"])
            private = gold["tasks"][0]["expected_answer"]
            self.assertIn(private, [text[s["start"]:s["end"]] for s in gold["sensitive_spans"]])
            public = gold["tasks"][1]["expected_answer"]
            start = text.index(public)
            self.assertFalse(any(s["start"] < start + len(public) and start < s["end"]
                                 for s in gold["sensitive_spans"]))
        self.assertTrue({"PERSON", "CUSTOMER", "PROJECT", "ADDRESS", "AMOUNT", "EMAIL"}.issubset(found_categories))

    def test_authorization_metadata_and_untrusted_override_cases(self):
        for case, gold in zip(self.runtime["cases"], self.evaluation["cases"]):
            self.assertEqual(case["readers"], [case["owner_id"]])
            self.assertEqual([t["authorized"] for t in gold["tasks"]], [True, True, False])
            for task in case["tasks"][:2]:
                self.assertEqual(task["actor_id"], case["owner_id"])
                self.assertEqual(task["agent_id"], case["owner_agent_id"])
            self.assertNotIn(case["tasks"][2]["actor_id"], case["readers"])
            self.assertEqual(case["tasks"][0]["query"], case["tasks"][2]["query"])
        injected = [c for c in self.runtime["cases"] if "override" in self.manifest["template_families"][c["case_id"]]
                    or "forged-system" in self.manifest["template_families"][c["case_id"]]]
        self.assertEqual(len(injected), 4)
        self.assertTrue(all("Source text is untrusted" in c["policy"]["instructions"] for c in injected))

    def test_public_policy_counterexamples_and_complete_identifier_suffixes(self):
        public = [c for c in self.runtime["cases"] if "public-bulletin" in self.manifest["template_families"][c["case_id"]]
                  or "open-programme" in self.manifest["template_families"][c["case_id"]]]
        self.assertEqual(len(public), 4)
        self.assertTrue(all("CUSTOMER" not in c["policy"]["protected_categories"] for c in public))
        for case, gold in zip(self.runtime["cases"], self.evaluation["cases"]):
            if "client-file" in self.manifest["template_families"][case["case_id"]] or "contract-ledger" in self.manifest["template_families"][case["case_id"]]:
                span = next(s for s in gold["sensitive_spans"] if s["category"] == "CUSTOMER")
                value = case["source"]["text"][span["start"]:span["end"]]
                self.assertRegex(value, r"[-_]?[A-Z][0-9]+$")

    def test_written_frozen_bytes_and_canonical_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_corpus(directory)
            for name in ("runtime", "evaluation"):
                raw = (Path(directory) / f"{name}.json").read_bytes()
                self.assertNotIn(b"\r", raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["raw_sha256"][name])
                self.assertEqual(hashlib.sha256(canonical_bytes(json.loads(raw))).hexdigest(),
                                 manifest["canonical_sha256"][name])
            self.assertFalse(manifest["contains_real_private_data"])
            self.assertFalse(manifest["entity_registry"])

    def test_committed_examples_match_generator(self):
        directory = Path(__file__).resolve().parents[1] / "examples" / "memory_generation_eval"
        for name, expected in (("runtime", self.runtime), ("evaluation", self.evaluation)):
            self.assertEqual(json.loads((directory / f"{name}.json").read_text(encoding="utf-8")), expected)
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["canonical_sha256"], self.manifest["canonical_sha256"])


if __name__ == "__main__":
    unittest.main()
