"""Strict CUSTOMER transfer composition; all detectors are local test doubles."""
import copy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import memory_labels
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer
from memory_migration_study.privacy import detect_sensitive
from memory_migration_study.sensitivity_contract import (
    ANY_SPECIFIC_ORGANIZATION, STRICT_CUSTOMER_RELATION, bind_category_contract,
)


MODES = ("migration", "generation", "two_stage")


class CompleteDetector:
    """Records exact sources and supplies only explicit fixture decisions."""
    max_local_calls = 1

    def __init__(self, findings=None, review_texts=()):
        self.findings = findings or {}
        self.review_texts = set(review_texts)
        self.inputs = []

    def __call__(self, **arguments):
        self.inputs.append(copy.deepcopy(arguments))
        text = arguments["text"]
        review = text in self.review_texts
        return {"status": "needs_review" if review else "ok",
                "findings": [{"quote": name, "category": category}
                             for name, category in self.findings.items() if name in text],
                "errors": ["semantic_uncertainty"] if review else [],
                "local_calls": 1, "elapsed_seconds": 0.01}


class StrictLabeledTransferContractTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(b"strict-transfer-tests-authority-32-bytes")
        self.legacy = {"version": "same-version", "protected_categories": ["CUSTOMER", "EMAIL"],
                       "instructions": "Business scope: our commercial transactions."}
        self.policy = bind_category_contract(self.legacy, STRICT_CUSTOMER_RELATION)
        self.text = "Our customer is River Glass Ltd. Contact ada@example.test."
        self.name = "River Glass Ltd."
        self.query = "Please summarize the record."

    def record(self, *, text=None, positives=None, policy=None):
        text = self.text if text is None else text
        positives = [self.name] if positives is None else positives
        findings = [{"start": text.index(name), "end": text.index(name) + len(name), "category": "CUSTOMER"}
                    for name in positives]
        return self.authority.build_record(
            {"source_id": "source", "text": text},
            {"text": text, "source_start": 0, "source_end": len(text), "findings": findings},
            self.policy if policy is None else policy,
            owner_id="owner", readers=[], agent_id="agent", builder_version="unit-v1")

    def transfer(self, record, *, mode="migration", agent=None, policy=None, query=None):
        return prepare_labeled_transfer([record], self.query if query is None else query,
            self.policy if policy is None else policy, authority=self.authority,
            actor_id="owner", agent_id="agent", request_id="request", mode=mode, agent=agent)

    def test_all_strict_modes_cover_query_and_signed_memory_before_prepare(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                record = self.record()
                agent = CompleteDetector({self.name: "CUSTOMER"})
                result = self.transfer(record, mode=mode, agent=agent)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["detection"]["errors"], [])
                self.assertEqual(result["egress"]["status"], "ok")
                self.assertEqual(result["local_calls"], 2)
                self.assertEqual({row["source_id"] for row in agent.inputs}, {"__query__", record["record_id"]})
                self.assertTrue(result["checks"][0]["label_valid"])
                self.assertTrue(all(row["policy"]["category_contract"] == self.policy["category_contract"]
                                    and row["rule_findings"] == [] for row in agent.inputs))
                outbound = json.dumps(result["payload"])
                self.assertNotIn(self.name, outbound)
                self.assertNotIn("ada@example.test", outbound)

    def test_generation_signed_empty_label_cannot_replace_complete_detection(self):
        record = self.record(positives=[])
        agent = CompleteDetector({self.name: "CUSTOMER"})
        result = self.transfer(record, mode="generation", agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["checks"][0]["label_valid"])
        self.assertEqual(result["metadata"]["fallback_count"], 0)
        self.assertEqual(result["local_calls"], 2)
        self.assertIn(record["record_id"], [row["source_id"] for row in agent.inputs])
        self.assertNotIn(self.name, json.dumps(result["payload"]))

    def test_all_strict_modes_without_detector_remain_blocked_despite_signed_labels(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                result = self.transfer(self.record(), mode=mode)
                self.assertEqual(result["status"], "needs_review")
                self.assertIsNone(result["payload"])
                self.assertIn("local_agent_required", result["detection"]["errors"])
                self.assertIn("unsupported_category_contract", result["detection"]["errors"])
                self.assertEqual(result["local_calls"], 0)

    def test_unknown_relation_blocks_all_modes_and_preserves_review(self):
        text = "The registered organization is River Glass Ltd.; customer relation is unrecorded."
        for mode in MODES:
            with self.subTest(mode=mode):
                agent = CompleteDetector(review_texts=[text])
                result = self.transfer(self.record(text=text, positives=[]), mode=mode, agent=agent)
                self.assertEqual(result["status"], "needs_review")
                self.assertIsNone(result["payload"])
                self.assertIn("semantic_uncertainty", result["detection"]["errors"])
                self.assertIn("unsupported_category_contract", result["detection"]["errors"])
                self.assertEqual(result["local_calls"], 2)

    def test_explicit_noncustomer_can_complete_without_field_heuristic_reappearing(self):
        text = "Customer: River Glass Ltd.; relation: never our customer."
        for mode in MODES:
            with self.subTest(mode=mode):
                result = self.transfer(self.record(text=text, positives=[]), mode=mode, agent=CompleteDetector())
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["detection"]["findings"], [])
                self.assertIn(self.name, json.dumps(result["payload"]))

    def test_registry_and_signed_positive_constraints_survive_empty_semantic_detection(self):
        policy = dict(self.policy, entity_registry=[{"value": "Harbor Archive", "category": "CUSTOMER"}])
        text = self.text + " Harbor Archive is also listed."
        for mode in ("generation", "two_stage"):
            with self.subTest(mode=mode):
                result = self.transfer(self.record(text=text, policy=policy), mode=mode,
                                       policy=policy, agent=CompleteDetector())
                self.assertEqual(result["status"], "ok")
                outbound = json.dumps(result["payload"])
                self.assertNotIn(self.name, outbound)
                self.assertNotIn("Harbor Archive", outbound)
                self.assertTrue(any(f["method"] == "generation_label" for f in result["detection"]["findings"]))
                self.assertTrue(any(f["method"] == "registry" for f in result["detection"]["findings"]))

    def test_binding_or_incomplete_cost_cannot_fill_strict_coverage_gap(self):
        for changes in ({"payload_sha256": "0" * 64}, {"policy_sha256": "0" * 64},
                        {"local_calls_complete": False}):
            with self.subTest(changes=changes):
                def corrupted(*args, **kwargs):
                    result = detect_sensitive(*args, **kwargs)
                    if kwargs.get("mode") == "combined":
                        result.update(changes)
                    return result
                with patch.object(memory_labels, "detect_sensitive", side_effect=corrupted):
                    result = self.transfer(self.record(), agent=CompleteDetector({self.name: "CUSTOMER"}))
                self.assertEqual(result["status"], "needs_review")
                self.assertIsNone(result["payload"])
                self.assertIn("unsupported_category_contract", result["detection"]["errors"])

    def test_other_base_safety_errors_survive_successful_full_semantic_coverage(self):
        def extra_rule_error(*args, **kwargs):
            result = detect_sensitive(*args, **kwargs)
            if kwargs.get("mode") == "rules":
                result["errors"].append("reserved_token_in_input")
            return result
        with patch.object(memory_labels, "detect_sensitive", side_effect=extra_rule_error):
            result = self.transfer(self.record(), agent=CompleteDetector({self.name: "CUSTOMER"}))
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])
        self.assertEqual(result["detection"]["errors"], ["reserved_token_in_input"])

    def test_legacy_and_broad_generation_reuse_and_other_modes_keep_existing_cost(self):
        broad = bind_category_contract(self.legacy, ANY_SPECIFIC_ORGANIZATION)
        for policy in (self.legacy, broad):
            for mode in MODES:
                with self.subTest(profile=policy.get("category_contract"), mode=mode):
                    record = self.record(policy=policy)
                    agent = CompleteDetector({self.name: "CUSTOMER"}) if mode != "generation" else None
                    result = self.transfer(record, mode=mode, policy=policy, query="", agent=agent)
                    self.assertEqual(result["status"], "ok")
                    self.assertEqual(result["local_calls"], 0 if mode == "generation" else 1)


if __name__ == "__main__":
    unittest.main()
