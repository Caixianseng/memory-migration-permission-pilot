"""Flat decisions keep format protections and the original authorization gate."""
import unittest
from memory_migration_study.candidate_decision import LocalCandidateDecision
from memory_migration_study.candidate_decision_detection import compose_decision_detection
from memory_migration_study.privacy import prepare_private_payload
from tests.test_context_typed_detection import fixture
from tests.test_context_candidate_typing import FakeTransport, envelope


def classify(case, choose):
    payload, policy, baseline, pool = case
    decisions = [{"cid": c["cid"], "decision": choose(c)} for c in pool["candidates"]]
    return LocalCandidateDecision(transport=FakeTransport([envelope(decisions)])).classify(payload, policy, pool)


class CandidateDecisionDetectionTests(unittest.TestCase):
    def test_full_untyped_name_and_semantic_heading_use_same_gate(self):
        case = fixture("Project reference <N7-Field>.", ["PROJECT"])
        stage = classify(case, lambda c: "FIELD_LABEL" if c["quote"] == "reference" else "VALUE_PROJECT")
        result = compose_decision_detection(*case, stage)
        text = case[0]["memories"][0]["text"]
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual([text[f["start"]:f["end"]] for f in result["findings"]], ["N7-Field"])
        self.assertEqual(result["candidate_decision"]["closure_reintroduced_removed"], [])

    def test_hard_format_protection_survives_other_decision(self):
        case = fixture("Email: team@example.test", ["EMAIL"])
        result = compose_decision_detection(*case, classify(case, lambda c: "OTHER"))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual([f["category"] for f in result["findings"]], ["EMAIL"])

    def test_uncertain_is_not_clean_empty(self):
        case = fixture("Name <Cedar Vale>.", ["CUSTOMER"])
        result = compose_decision_detection(*case, classify(case, lambda c: "UNCERTAIN"))
        self.assertEqual(result["status"], "needs_review")

    def test_new_value_never_supplies_permission(self):
        case = fixture("Name <Cedar Vale>.", ["CUSTOMER"])
        result = compose_decision_detection(*case, classify(case, lambda c: "VALUE_CUSTOMER"))
        prepared = prepare_private_payload(case[0], result, actor_id="outsider", request_id="request",
            policy_version=case[1]["version"], sensitivity_policy=case[1], authorizer=lambda *args: False)
        self.assertEqual(prepared["status"], "needs_review")
        self.assertIsNone(prepared["mapping"])


if __name__ == "__main__":
    unittest.main()
