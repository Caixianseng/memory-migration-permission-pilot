"""No models: contextual decisions cannot remove hard protections or grant access."""
from copy import deepcopy
import unittest

from memory_migration_study.candidate_proposals import propose_candidates
from memory_migration_study.context_candidate_typing import CATEGORY_TYPES, LocalContextCandidateTyper
from memory_migration_study.context_typed_detection import compose_typed_detection
from memory_migration_study.privacy import detect_sensitive, prepare_private_payload
from tests.test_context_candidate_typing import FakeTransport, envelope


def fixture(text, categories, registry=None):
    payload = {"query": "", "memories": [{"source_id": "m1", "text": text}]}
    policy = {"version": "v1", "protected_categories": categories,
              "instructions": "Protect specific values, not generic headings."}
    if registry is not None:
        policy["entity_registry"] = registry
    baseline = detect_sensitive(payload, policy, mode="rules")
    pool = propose_candidates(payload, policy, baseline["findings"], max_candidates=16)
    return payload, policy, baseline, pool


def stage_for(case, select):
    payload, policy, baseline, pool = case
    rows = []
    for i, candidate in enumerate(pool["candidates"]):
        role, category = select(candidate)
        rows.append({"cid": candidate["cid"], "mention_role": role,
                     "entity_type": CATEGORY_TYPES[category] if category else "other", "category": category,
                     "evidence_ids": ["E" + str(i + 1).zfill(4)]})
    transport = FakeTransport([envelope({"verdicts": rows})])
    return LocalContextCandidateTyper(transport=transport).classify(payload, policy, pool)


class ContextTypedDetectionTests(unittest.TestCase):
    def test_untyped_promotion_and_shared_verdict_ablation(self):
        case = fixture("Registered name <Amber North>.", ["CUSTOMER"])
        stage = stage_for(case, lambda c: ("value", "CUSTOMER"))
        self.assertEqual(stage["status"], "typing_only", stage)
        full = compose_typed_detection(*case, stage)
        seeded = compose_typed_detection(*case, stage, promote_untyped=False)
        self.assertEqual(full["status"], "ok", full)
        self.assertEqual([f["category"] for f in full["findings"]], ["CUSTOMER"])
        self.assertEqual(seeded["findings"], [])
        self.assertEqual(full["local_calls"], 1)

    def test_semantic_rule_not_silently_readded(self):
        case = fixture("Project reference <Z7-A> is private.", ["PROJECT"])
        stage = stage_for(case, lambda c: ("field_label", None) if c["quote"] == "reference" else ("value", "PROJECT"))
        result = compose_typed_detection(*case, stage)
        text = case[0]["memories"][0]["text"]
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual([text[f["start"]:f["end"]] for f in result["findings"]], ["Z7-A"])
        self.assertEqual(result["context_typing"]["closure_reintroduced_removed"], [])

    def test_format_protections_survive_nonvalue_verdict(self):
        case = fixture("Email: user@example.test", ["EMAIL"])
        stage = stage_for(case, lambda c: ("other", None))
        result = compose_typed_detection(*case, stage)
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(result["findings"])
        self.assertTrue(result["context_typing"]["retained_immutable"])

    def test_registry_policy_cannot_be_downgraded_through_this_text_only_stage(self):
        case = fixture("Name <Amber North>.", ["CUSTOMER"], [{"value": "Amber North", "category": "CUSTOMER"}])
        stage = stage_for(case, lambda c: ("other", None))
        self.assertEqual(stage["local_calls"], 0)
        result = compose_typed_detection(*case, stage)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"], case[2]["findings"])

    def test_uncertainty_and_binding_tamper_fail_closed(self):
        case = fixture("Name <Amber North>.", ["CUSTOMER"])
        stage = stage_for(case, lambda c: ("uncertain", None))
        self.assertEqual(compose_typed_detection(*case, stage)["status"], "needs_review")
        valid = stage_for(case, lambda c: ("value", "CUSTOMER"))
        for field in ("payload_sha256", "policy_sha256"):
            changed = list(deepcopy(case))
            changed[2][field] = "0" * 64
            self.assertEqual(compose_typed_detection(*changed, valid)["status"], "needs_review")

    def test_detection_success_still_requires_original_source_authorization(self):
        case = fixture("Name <Amber North>.", ["CUSTOMER"])
        stage = stage_for(case, lambda c: ("value", "CUSTOMER"))
        detection = compose_typed_detection(*case, stage)
        result = prepare_private_payload(case[0], detection, actor_id="bob", request_id="r1",
            policy_version="v1", sensitivity_policy=case[1], authorizer=lambda *args: False)
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["mapping"])


if __name__ == "__main__":
    unittest.main()
