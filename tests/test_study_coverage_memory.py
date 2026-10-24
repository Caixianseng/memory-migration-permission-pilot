import copy
import json
import unittest

from memory_migration_study.coverage_memory import CoverageMemoryBuilder, verify_coverage_certificate
from memory_migration_study.memory_labels import MemoryLabelAuthority


class Detector:
    def __init__(self, value=None, category="CUSTOMER"):
        self.calls, self.value, self.category = [], value, category
        self.error, self.malformed, self.extra = False, False, {}

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        if self.error:
            return {"status": "needs_review", "findings": [], "errors": ["semantic_uncertainty"],
                    "local_calls": 1, "elapsed_seconds": .1}
        text = kwargs["text"]
        findings = []
        if self.value and self.value in text:
            a = text.index(self.value)
            findings = [{"quote": self.value, "category": self.category,
                         "start": 999 if self.malformed else a, "end": a+len(self.value)}]
        return {"status": "ok", "findings": findings, "errors": [], "local_calls": 1,
                "elapsed_seconds": .1, **self.extra}


class CoverageMemoryTests(unittest.TestCase):
    policy = {"version": "test", "protected_categories": ["CUSTOMER"], "instructions": "Names are sensitive."}

    def build(self, text, detector=None, **limits):
        return CoverageMemoryBuilder(detector or Detector(), **limits)(text=text, source_id="source", policy=self.policy)

    def assert_coverage(self, text, result):
        self.assertTrue(verify_coverage_certificate(text, result["coverage"]))
        for fact, span in zip(result["facts"], result["coverage"]["spans"]):
            self.assertEqual(fact["text"], text[span["start"]:span["end"]])
        self.assertEqual(result["coverage"]["omitted_non_whitespace_characters"], 0)

    def test_mixed_paragraphs_keep_original_text_duplicates_and_whitespace_difference(self):
        text = " 甲方已确认。English result is ready.\r\n \r\n重复。\n重复。\n"
        result = self.build(text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([f["text"] for f in result["facts"]], [" 甲方已确认。English result is ready.", "重复。", "重复。"])
        self.assertFalse(result["coverage"]["all_characters_covered"])
        self.assertTrue(all(s["whitespace_only"] for s in result["coverage"]["omitted_spans"]))
        self.assert_coverage(text, result)

    def test_sentence_boundaries_pack_long_chinese_and_english_paragraphs(self):
        for text in ("甲方已到。乙方已走！丙方待定？", "Ready now. Done later! Pause here?"):
            result = self.build(text, max_chunk_chars=15)
            self.assertEqual(result["status"], "ok")
            self.assertTrue(all(len(f["text"]) <= 15 for f in result["facts"]))
            self.assertEqual("".join(f["text"] for f in result["facts"]), text)
            self.assert_coverage(text, result)

    def test_unbreakable_sentence_never_truncates_or_slices_entity(self):
        detector = Detector()
        text = "一条无法按句界切分的超长正文"*3
        result = self.build(text, detector, max_chunk_chars=10)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["errors"], ["unbreakable_sentence_exceeds_chunk_limit"])
        self.assertEqual(result["facts"], [])
        self.assertEqual(detector.calls, [])
        self.assertEqual(result["coverage"]["omitted_characters"], len(text))
        self.assertTrue(verify_coverage_certificate(text, result["coverage"]))

    def test_capacity_and_total_character_limits_reject_whole_layout_without_calls(self):
        for limits, code in (({"max_chunks": 1}, "chunk_count_budget_exceeded"),
                             ({"max_total_chars": 4}, "retained_character_budget_exceeded"),
                             ({"max_source_chars": 4}, "source_character_budget_exceeded")):
            detector = Detector()
            result = self.build("Alpha\nBeta", detector, **limits)
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["errors"], [code])
            self.assertEqual(result["facts"], [])
            self.assertEqual(detector.calls, [])

    def test_sensitive_positions_are_chunk_relative_and_authority_accepts_exact_source(self):
        text = "状态已确认。\n客户是青禾器材合作社，配送已完成。"
        detector = Detector("青禾器材合作社")
        result = self.build(text, detector)
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(result["builder_local_calls"], 0)
        fact = result["facts"][1]
        finding = fact["findings"][0]
        self.assertEqual(fact["text"][finding["start"]:finding["end"]], "青禾器材合作社")
        self.assertEqual(text[fact["source_start"]+finding["start"]:fact["source_start"]+finding["end"]], "青禾器材合作社")
        authority = MemoryLabelAuthority(b"x"*32)
        record = authority.build_record({"source_id": "source", "text": text}, fact, self.policy,
            owner_id="owner", readers=["owner"], agent_id="builder", builder_version=result["builder_version"])
        self.assertEqual(authority.validate_label(record, self.policy), None)
        self.assert_coverage(text, result)

    def test_rule_findings_are_validated_and_retained_without_local_calls_for_public_policy(self):
        text = "Contact user@example.org."
        result = CoverageMemoryBuilder()(text=text, source_id="source",
            policy={"version": "mail", "protected_categories": ["EMAIL"]})
        self.assertEqual(result["status"], "needs_review")
        # Rules cannot silently substitute for the requested semantic detector.
        self.assertEqual(result["local_calls"], 0)
        public = CoverageMemoryBuilder()(text=text, source_id="source",
            policy={"version": "public", "protected_categories": []})
        self.assertEqual(public["status"], "ok")
        self.assertEqual(public["local_calls"], 0)

    def test_detector_cannot_create_permissions_or_change_source(self):
        detector = Detector("Acorn Works")
        detector.extra = {"owner_id": "attacker", "readers": ["public"], "public": True,
                          "source_id": "forged", "facts": [{"text": "fabricated"}]}
        result = self.build("Customer: Acorn Works.", detector)
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("attacker", json.dumps(result))
        self.assertNotIn("forged", json.dumps(result))
        self.assertEqual(result["facts"][0]["text"], "Customer: Acorn Works.")
        self.assertEqual(set(detector.calls[0]), {"text", "source_id", "policy", "rule_findings"})

    def test_bad_label_positions_force_review_and_never_become_signed_candidates(self):
        detector = Detector("Acorn Works")
        detector.malformed = True
        text = "Customer: Acorn Works."
        result = self.build(text, detector)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["facts"][0]["status"], "needs_review")
        self.assertEqual(result["facts"][0]["findings"], [])
        self.assertFalse(result["accepted_for_store"])
        self.assert_coverage(text, result)

    def test_detection_failure_keeps_source_coverage_statistics(self):
        detector = Detector()
        detector.error = True
        text = "首段事实。\nSecond fact."
        result = self.build(text, detector)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(len(result["facts"]), 2)
        self.assertTrue(result["coverage"]["all_non_whitespace_covered"])
        self.assert_coverage(text, result)

    def test_missing_call_accounting_is_not_an_accepted_detection(self):
        def detector(**kwargs):
            return {"status": "ok", "findings": []}
        result = self.build("One factual paragraph.", detector)
        self.assertEqual(result["status"], "needs_review")
        self.assertFalse(result["local_calls_complete"])

    def test_certificate_detects_rewrite_overlap_and_false_coverage_claims(self):
        text = "Alpha.\nBeta."
        cert = self.build(text)["coverage"]
        self.assertFalse(verify_coverage_certificate(text+"x", cert))
        forged = copy.deepcopy(cert)
        forged["retained_characters"] += 1
        self.assertFalse(verify_coverage_certificate(text, forged))
        forged = copy.deepcopy(cert)
        forged["spans"][1]["start"] = 0
        self.assertFalse(verify_coverage_certificate(text, forged))
        forged = copy.deepcopy(cert)
        forged["spans"][0]["start"] = True
        self.assertFalse(verify_coverage_certificate(text, forged))

    def test_policy_limit_input_and_configuration_are_checked_before_detector(self):
        detector = Detector()
        result = CoverageMemoryBuilder(detector)(text="Long unbreakable unit", source_id="source",
            policy=dict(self.policy, max_text_chars=4))
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(detector.calls, [])
        for limits in ({"max_chunks": True}, {"max_source_chars": 6001}, {"max_total_chars": 0}):
            with self.assertRaises(ValueError):
                CoverageMemoryBuilder(detector, **limits)
        for text in (None, "", " \r\n "):
            self.assertEqual(self.build(text)["status"], "needs_review")


if __name__ == "__main__":
    unittest.main()
