"""Synthetic zero-model redaction replay checks with network disabled."""
from copy import deepcopy
import json
import re
import unittest
from unittest.mock import patch

from memory_migration_study import privacy
from memory_migration_study.relation_occurrence import BUSINESS_SCOPE
from memory_migration_study.sensitivity_contract import bind_category_contract
from scripts import relation_probe_scoring as original
from scripts import relation_redaction_audit as audit


class RelationRedactionAuditTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.policy = bind_category_contract({"version": "test-v1", "protected_categories": ["CUSTOMER"],
            "instructions": BUSINESS_SCOPE, "entity_registry": []}, "any_specific_organization")

    def row(self, text, quotes=(), *, status="ok", error=None):
        findings = [{"start": start, "end": start+len(quote), "quote": quote, "category": "CUSTOMER"}
                    for quote, start in quotes]
        response = {"status": "ok" if status == "ok" else "needs_review", "findings": findings,
                    "errors": [error or "semantic_uncertainty"] if status != "ok" else [],
                    "local_calls": 0, "elapsed_seconds": 0.0}
        return {"cell": {"text_index": 0, "profile": "any_specific_organization", "arm": "fixture"},
                "response": response, "status": status,
                "preparation": original.prepare_observation(text, self.policy, response)}

    def reference(self, text, spans=(), decision="sensitive"):
        findings = [{"text": value, "start": start, "end": start+len(value), "category": "CUSTOMER"}
                    for value, start in spans]
        return {"decision": decision, "spans": findings, "must_mask_values": list(dict.fromkeys(x["text"] for x in findings))}

    def rehash_payload(self, row):
        row["preparation"]["metadata"]["payload_sha256"] = original._hash(row["preparation"]["payload"])

    def test_partial_chinese_name_scores_partial_despite_complete_value_absence(self):
        text = "客户是青河仪表联盟，状态正常。"
        row = self.row(text, [("联盟", text.index("联盟"))])
        trace = audit.audit_observation(text, self.policy, row)
        score = audit.score_observation(text, trace, self.reference(text, [("青河仪表联盟", 3)]))
        self.assertEqual(trace["status"], "aligned")
        self.assertEqual((score["fully_masked_spans"], score["partially_masked_spans"], score["unmasked_spans"]), (0, 1, 0))
        self.assertEqual(score["masked_unprotected_characters"], 0)
        self.assertFalse(score["all_reference_spans_masked_and_ready"])
        self.assertEqual(trace["egress"]["status"], "ok")
        self.assertEqual(trace["acl_negative_control"]["status"], "rejected")

    def test_full_none_and_negative_controls_have_distinct_coverage(self):
        text = "客户是青河联盟。"
        truth = self.reference(text, [("青河联盟", 3)])
        for quotes, full, none in (([("青河联盟", 3)], 1, 0), ([], 0, 1)):
            with self.subTest(quotes=quotes):
                trace = audit.audit_observation(text, self.policy, self.row(text, quotes))
                score = audit.score_observation(text, trace, truth)
                self.assertEqual((score["fully_masked_spans"], score["unmasked_spans"]), (full, none))
        trace = audit.audit_observation(text, self.policy, self.row(text, [("青河联盟", 3)]))
        public = audit.score_observation(text, trace, self.reference(text, decision="not_sensitive"))
        self.assertEqual(public["masked_unprotected_characters"], 4)

    def test_repeated_same_name_uses_actual_propagation_and_counts_public_overmask(self):
        text = "青河联盟是客户；词典示例也写青河联盟。"
        row = self.row(text, [("青河联盟", 0)])
        trace = audit.audit_observation(text, self.policy, row)
        self.assertEqual(trace["mask_footprint"]["probe"], [[0, 4], [14, 18]])
        score = audit.score_observation(text, trace, self.reference(text, [("青河联盟", 0)]))
        self.assertEqual(score["fully_masked_spans"], 1)
        self.assertEqual(score["masked_unprotected_characters"], 4)

    def test_forged_plaintext_nonce_token_and_source_are_not_normalized_away(self):
        text = "青河联盟是客户，颜色蓝色。"
        pristine = self.row(text, [("青河联盟", 0)])
        for mutation in ("plaintext", "mixed_nonce", "category", "index", "source", "malformed"):
            with self.subTest(mutation=mutation):
                row = deepcopy(pristine)
                memory = row["preparation"]["payload"]["memories"][0]
                if mutation == "plaintext": memory["text"] += " changed"
                elif mutation == "mixed_nonce": memory["text"] = re.sub(r"PVT_[A-F0-9]{24}", "PVT_"+"A"*24, memory["text"])
                elif mutation == "category": memory["text"] = memory["text"].replace("_CUSTOMER_", "_PERSON_")
                elif mutation == "index": memory["text"] = memory["text"].replace("_1]", "_2]")
                elif mutation == "source": memory["source_id"] = memory["source_id"].removesuffix("_1")+"_2"
                else: memory["text"] = memory["text"].replace("[PVT_", "[pvt_")
                self.rehash_payload(row)
                with self.assertRaises(ValueError):
                    audit.audit_observation(text, self.policy, row)

    def test_same_nonce_hex_in_plaintext_is_not_normalized(self):
        text = "Literal " + "A"*24 + " is public; 青河联盟 is a customer."
        with patch.object(privacy.secrets, "token_hex", return_value="A"*24):
            row = self.row(text, [("青河联盟", text.index("青河联盟"))])
        with patch.object(privacy.secrets, "token_hex", return_value="B"*24):
            trace = audit.audit_observation(text, self.policy, row)
        self.assertEqual(trace["status"], "aligned")
        row["preparation"]["payload"]["memories"][0]["text"] = row["preparation"]["payload"]["memories"][0]["text"].replace("Literal " + "A"*24, "Literal " + "B"*24)
        self.rehash_payload(row)
        with self.assertRaises(ValueError):
            audit.audit_observation(text, self.policy, row)

    def test_policy_source_detection_metadata_or_binding_changes_reject(self):
        text = "青河联盟是客户。"
        pristine = self.row(text, [("青河联盟", 0)])
        for mutation in ("policy", "source", "detection", "metadata", "binding"):
            with self.subTest(mutation=mutation):
                row, policy = deepcopy(pristine), deepcopy(self.policy)
                if mutation == "policy": policy["instructions"] += " Changed scope."
                elif mutation == "source": row["preparation"]["binding"]["source_id"] = "other"
                elif mutation == "detection": row["preparation"]["detection"]["strategy"] += " altered"
                elif mutation == "metadata": row["preparation"]["metadata"]["replacement_count"] += 1
                else: row["preparation"]["binding"]["response_sha256"] = "0"*64
                with self.assertRaises(ValueError):
                    audit.audit_observation(text, policy, row)

    def test_review_and_coverage_remain_blocked_and_keep_denominator(self):
        text = "青河联盟是客户。"
        for status, error in (("needs_review", "semantic_uncertainty"), ("coverage_review", "input_budget_exceeded")):
            with self.subTest(status=status):
                row = self.row(text, status=status, error=error)
                trace = audit.audit_observation(text, self.policy, row)
                score = audit.score_observation(text, trace, self.reference(text, [("青河联盟", 0)]))
                self.assertEqual(trace["status"], "blocked")
                self.assertEqual(trace["mask_footprint"], {})
                self.assertEqual(trace["prepare_calls"], 1)
                self.assertIsNone(score["fully_masked_spans"])
                self.assertIsNone(score["unmasked_spans"])
                self.assertEqual(score["unmasked_or_not_ready_spans"], 1)
                self.assertFalse(score["all_reference_spans_masked_and_ready"])

    def test_unknown_reference_never_claims_zero_leak_or_overmask(self):
        text = "青河联盟出现在简介中。"
        for status in ("ok", "needs_review"):
            row = self.row(text, status=status)
            trace = audit.audit_observation(text, self.policy, row)
            score = audit.score_observation(text, trace, self.reference(text, decision="needs_review"))
            self.assertFalse(score["reference_known"])
            for key in ("fully_masked_spans", "partially_masked_spans", "unmasked_spans", "masked_unprotected_characters"):
                self.assertIsNone(score[key])

    def test_no_mapping_or_token_values_escape_and_inputs_are_unchanged(self):
        text = "青河联盟是客户。"
        row = self.row(text, [("青河联盟", 0)])
        before, function = deepcopy(row), privacy.prepare_private_payload
        trace = audit.audit_observation(text, self.policy, row)
        self.assertEqual(row, before)
        self.assertIs(privacy.prepare_private_payload, function)
        serialized = json.dumps(trace, ensure_ascii=False, allow_nan=False)
        self.assertNotIn("青河联盟", serialized)
        self.assertNotIn("[PVT_", serialized)
        self.assertNotIn("_entries", serialized)
        self.assertFalse(trace["mapping_persisted"])
        self.assertEqual(trace["new_model_calls"], 0)

    def test_trace_and_score_are_json_roundtrip_stable(self):
        text = "青河联盟是客户。"
        row = json.loads(json.dumps(self.row(text, [("青河联盟", 0)])))
        trace = audit.audit_observation(text, self.policy, row)
        restored = json.loads(json.dumps(trace, ensure_ascii=False, allow_nan=False))
        self.assertEqual(trace, restored)
        truth = self.reference(text, [("青河联盟", 0)])
        score = audit.score_observation(text, restored, truth)
        self.assertEqual(score, json.loads(json.dumps(score, allow_nan=False)))

    def test_missing_preparation_and_bad_alignment_cannot_become_safe(self):
        text = "青河联盟是客户。"
        row = self.row(text, [("青河联盟", 0)])
        missing = deepcopy(row)
        del missing["preparation"]
        with self.assertRaises(ValueError):
            audit.audit_observation(text, self.policy, missing)
        original_prepare = privacy.prepare_private_payload
        with patch.object(audit, "masking_intervals", side_effect=ValueError("alignment_failed")):
            with self.assertRaises(ValueError):
                audit.audit_observation(text, self.policy, row)
        self.assertIs(privacy.prepare_private_payload, original_prepare)

    def test_changed_gold_changes_only_scores_not_frozen_trace(self):
        text = "青河联盟是客户。"
        row = self.row(text, [("青河联盟", 0)])
        trace = audit.audit_observation(text, self.policy, row)
        saved = deepcopy(trace)
        sensitive = audit.score_observation(text, trace, self.reference(text, [("青河联盟", 0)]))
        public = audit.score_observation(text, trace, self.reference(text, decision="not_sensitive"))
        self.assertEqual(sensitive["masked_unprotected_characters"], 0)
        self.assertEqual(public["masked_unprotected_characters"], 4)
        self.assertEqual(trace, saved)
        trace["mask_footprint"]["probe"][0][1] -= 1
        with self.assertRaises(ValueError):
            audit.score_observation(text, trace, self.reference(text, [("青河联盟", 0)]))


if __name__ == "__main__":
    unittest.main()
