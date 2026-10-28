"""Offline sampling-wrapper tests; every model/health response is synthetic."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import qwen35_sampling as module
from memory_migration_study import qwen35_occurrence as legacy
from tests.test_qwen35_occurrence import FakeLocal, DIGEST
from memory_migration_study.sensitivity_contract import bind_category_contract, STRICT_CUSTOMER_RELATION


class Qwen35SamplingTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)
        self.text = "Moss is a word. Moss is our customer."
        self.policy = bind_category_contract({"version": "sampling-unit", "protected_categories": ["CUSTOMER"],
            "instructions": "Business scope: our company."}, STRICT_CUSTOMER_RELATION)
        self.args = {"text": self.text, "source_id": "unit-source", "policy": self.policy, "rule_findings": []}

    def positive(self):
        return {"status": "ok", "findings": [{"quote": "Moss", "occurrence": 2, "category": "CUSTOMER"}]}

    def test_pure_builder_changes_only_presence_and_does_not_mutate_legacy(self):
        for repair in (False, True):
            original = legacy.build_request(**self.args, repair=repair)
            for arm, penalty in module.ARMS.items():
                changed = module.build_request(**self.args, arm=arm, repair=repair)
                self.assertEqual(changed["options"].pop("presence_penalty"), penalty)
                self.assertEqual(changed, original)
            self.assertNotIn("presence_penalty", original["options"])
        self.assertEqual(legacy.OPTIONS, {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42})

    def test_inherited_call_sends_identical_frozen_wire_and_current_identity(self):
        for arm, penalty in module.ARMS.items():
            fake = FakeLocal([self.positive()])
            agent = module.SamplingQwen35Agent(arm=arm, expected_digest=DIGEST, transport=fake)
            result = agent(**self.args)
            expected = module.build_request(**self.args, arm=arm)
            self.assertEqual(json.dumps(fake.posts[0], ensure_ascii=False, allow_nan=False),
                             json.dumps(expected, ensure_ascii=False, allow_nan=False))
            self.assertEqual([r[:2] for r in fake.requests], [("GET", "/api/version"), ("GET", "/api/tags"), ("POST", "/api/chat")])
            self.assertEqual(result["findings"][0]["start"], self.text.rindex("Moss"))
            self.assertEqual(result["sampling_identity"], agent.cache_identity())
            self.assertEqual(result["sampling_identity"]["options"]["presence_penalty"], penalty)
            self.assertEqual(result["sampling_identity"]["prompt_sha256"], legacy.Qwen35OccurrenceAgent(expected_digest=DIGEST).cache_identity()["prompt_sha256"])
            self.assertEqual(result["local_calls"], 1)

    def test_repair_is_the_original_second_request_without_failed_output(self):
        fake = FakeLocal([{"status": "ok", "findings": [{"quote": "Mose", "occurrence": 2, "category": "CUSTOMER"}]}, self.positive()])
        result = module.SamplingQwen35Agent(arm="presence_zero", expected_digest=DIGEST, transport=fake)(**self.args)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 2)
        for n, body in enumerate(fake.posts):
            self.assertEqual(body, module.build_request(**self.args, arm="presence_zero", repair=bool(n)))
        self.assertNotIn("Mose", json.dumps(fake.posts[1]))

    def test_bad_second_span_stops_at_two_and_semantic_unknown_does_not_retry(self):
        invalid = {"status": "ok", "findings": [{"quote": "Absent", "occurrence": 1, "category": "CUSTOMER"}]}
        fake = FakeLocal([invalid, invalid, self.positive()])
        result = module.SamplingQwen35Agent(arm="presence_15", expected_digest=DIGEST, transport=fake)(**self.args)
        self.assertEqual((result["status"], result["local_calls"]), ("needs_review", 2))
        self.assertEqual(result["errors"], ["format_or_span_invalid"])
        self.assertEqual(len(fake.posts), 2)
        fake = FakeLocal([{"status": "needs_review", "findings": []}])
        result = module.SamplingQwen35Agent(arm="presence_zero", expected_digest=DIGEST, transport=fake)(**self.args)
        self.assertEqual((result["errors"], result["local_calls"]), (["semantic_uncertainty"], 1))

    def test_transport_and_health_failures_are_not_new_repair_opportunities(self):
        fake = FakeLocal([RuntimeError("synthetic_failure")])
        result = module.SamplingQwen35Agent(arm="presence_zero", expected_digest=DIGEST, transport=fake)(**self.args)
        self.assertEqual((result["errors"], result["local_calls"]), (["local_transport_failed"], 1))
        fake = FakeLocal(version="wrong")
        result = module.SamplingQwen35Agent(arm="presence_15", expected_digest=DIGEST, transport=fake)(**self.args)
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(fake.posts, [])

    def test_wrapper_reuses_parent_call_instead_of_reimplementing_flow(self):
        minimal = {"status": "needs_review", "findings": [], "errors": ["synthetic"], "local_calls": 0}
        with patch.object(legacy.Qwen35OccurrenceAgent, "__call__", return_value=minimal) as parent:
            result = module.SamplingQwen35Agent(arm="presence_zero", expected_digest=DIGEST, transport=FakeLocal())(**self.args)
        parent.assert_called_once_with(**self.args)
        self.assertEqual({k: result[k] for k in minimal}, minimal)
        self.assertNotIn("sampling_identity", minimal)

    def test_unknown_arm_and_already_modified_options_fail_without_transport(self):
        for arm in (None, True, 0, "zero", "presence_0", ""):
            with self.subTest(arm=arm), self.assertRaisesRegex(ValueError, "unsupported_sampling_arm"):
                module.SamplingQwen35Agent(arm=arm, expected_digest=DIGEST, transport=FakeLocal())
        request = legacy.build_request(**self.args)
        before = deepcopy(request)
        module.explicit_request(request, "presence_zero")
        self.assertEqual(request, before)
        request["options"]["presence_penalty"] = 1.5
        with self.assertRaisesRegex(ValueError, "legacy_presence_already_explicit"):
            module.explicit_request(request, "presence_zero")


if __name__ == "__main__":
    unittest.main()
