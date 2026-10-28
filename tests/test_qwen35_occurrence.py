"""Frozen-method Qwen3.5 adapter contracts using synthetic transport only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from memory_migration_study import local_detector as local
from memory_migration_study import occurrence_qwen as old
from memory_migration_study import qwen35_occurrence as module
from memory_migration_study.sensitivity_contract import STRICT_CUSTOMER_RELATION, bind_category_contract


DIGEST = "a" * 64  # Synthetic test identity, never a real qualification claim.


class FakeLocal:
    def __init__(self, replies=None, *, model=module.MODEL, digest=DIGEST, version=module.RUNTIME_VERSION):
        self.requests, self.replies = [], list(replies or [{"status": "ok", "findings": []}])
        self.model, self.digest, self.version = model, digest, version

    def __call__(self, method, path, body=None):
        self.requests.append((method, path, deepcopy(body)))
        if path == "/api/version":
            return {"version": self.version}
        if path == "/api/tags":
            return {"models": [{"name": self.model, "digest": self.digest}]}
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, tuple):
            return deepcopy(reply[0])
        return {"model": self.model, "done": True, "done_reason": "stop",
                "message": {"content": reply if isinstance(reply, str) else json.dumps(reply)}}

    @property
    def posts(self):
        return [row[2] for row in self.requests if row[0] == "POST"]


class Qwen35OccurrenceTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)
        self.policy = bind_category_contract({"version": "unit-v1", "protected_categories": ["CUSTOMER"],
            "instructions": "Business scope: our company."}, STRICT_CUSTOMER_RELATION)
        self.text = "Moss is a word. Our customer is Moss."

    def invoke(self, fake=None, **changes):
        fake = FakeLocal() if fake is None else fake
        args = {"text": self.text, "source_id": "unit-source", "policy": self.policy, "rule_findings": []}
        args.update(changes)
        return module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=fake)(**args)

    def positive(self, *, occurrence=2):
        return {"status": "ok", "findings": [{"quote": "Moss", "occurrence": occurrence, "category": "CUSTOMER"}]}

    def test_requires_real_full_new_digest_and_fixed_runtime(self):
        for digest in (None, "", "a" * 12, "a" * 63, "a" * 65, "g" * 64, "A" * 64,
                       "sha256:" + DIGEST, local.DIGEST):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "qualified_qwen35_digest_required"):
                module.Qwen35OccurrenceAgent(expected_digest=digest)
        with self.assertRaisesRegex(ValueError, "pinned_runtime_required"):
            module.Qwen35OccurrenceAgent(expected_digest=DIGEST, expected_version="different")
        for timeout in (True, 0, 181, "120"):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "invalid_local_timeout"):
                module.Qwen35OccurrenceAgent(expected_digest=DIGEST, timeout_seconds=timeout)

    def test_original_generic_config_does_not_support_new_model(self):
        with self.assertRaisesRegex(ValueError, "pinned_local_model_required"):
            local.LocalSensitivityAgent({"model": module.MODEL})
        self.assertEqual(old.MODEL, local.MODEL)
        self.assertNotEqual(old.MODEL, module.MODEL)

    def test_uses_true_new_model_and_think_false_with_identical_frozen_messages_schema_options(self):
        previous = FakeLocal([self.positive()], model=old.MODEL, digest=old.DIGEST, version=old.VERSION)
        current = FakeLocal([self.positive()])
        args = {"text": self.text, "source_id": "unit-source", "policy": self.policy, "rule_findings": []}
        before = old.OccurrenceQwenAgent(transport=previous)(**args)
        after = module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=current)(**args)
        self.assertEqual(before["status"], "ok")
        self.assertEqual(after["status"], "ok")
        self.assertEqual(before["findings"], after["findings"])
        old_body, new_body = previous.posts[0], current.posts[0]
        self.assertEqual({k: v for k, v in new_body.items() if k not in {"model", "think"}},
                         {k: v for k, v in old_body.items() if k != "model"})
        self.assertNotIn("think", old_body)
        self.assertEqual(new_body["model"], "qwen3.5:4b-q4_K_M")
        self.assertIs(new_body["think"], False)
        self.assertEqual(after["model"], module.MODEL)
        self.assertEqual(after["digest"], DIGEST)
        self.assertEqual((after["local_calls"], after["local_calls_complete"]), (1, True))
        self.assertIs(after["think"], False)

    def test_health_checks_actual_tag_full_digest_and_version_without_alias(self):
        fake = FakeLocal(digest="sha256:" + DIGEST)
        agent = module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=fake)
        self.assertEqual(agent.health(), {"version": "0.40.8", "model": module.MODEL,
            "digest": DIGEST, "endpoint": "http://127.0.0.1:11435"})
        self.assertEqual([row[:2] for row in fake.requests], [("GET", "/api/version"), ("GET", "/api/tags")])
        for changes in ({"model": old.MODEL}, {"digest": local.DIGEST}, {"digest": DIGEST[:12]}, {"version": "bad"}):
            with self.subTest(changes=changes):
                fake = FakeLocal(**changes)
                result = self.invoke(fake)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["errors"], ["local_health_failed"])
                self.assertEqual(result["local_calls"], 0)
                self.assertEqual(fake.posts, [])

    def test_duplicate_or_malformed_tag_inventory_fails_closed(self):
        for tags in ({"models": [{"name": module.MODEL, "digest": DIGEST}] * 2},
                     {"models": None}, None, {"models": [{"name": module.MODEL, "digest": None}]}):
            with self.subTest(tags=tags):
                fake = FakeLocal()
                def transport(method, path, body=None):
                    return tags if path == "/api/tags" else fake(method, path, body)
                result = self.invoke(transport)
                self.assertEqual(result["errors"], ["local_health_failed"])
                self.assertEqual(result["local_calls"], 0)

    def test_successful_repair_is_same_prompt_one_append_and_two_real_calls(self):
        previous = FakeLocal(["{invalid", self.positive()], model=old.MODEL, digest=old.DIGEST, version=old.VERSION)
        current = FakeLocal(["{invalid", self.positive()])
        args = {"text": self.text, "source_id": "unit-source", "policy": self.policy, "rule_findings": []}
        before = old.OccurrenceQwenAgent(transport=previous)(**args)
        after = module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=current)(**args)
        self.assertEqual(before["findings"], after["findings"])
        self.assertEqual(after["status"], "ok")
        self.assertEqual((after["local_calls"], after["local_calls_complete"]), (2, True))
        self.assertEqual(len(current.posts), 2)
        self.assertEqual(current.posts[1]["messages"], previous.posts[1]["messages"])
        self.assertEqual(current.posts[1]["messages"], current.posts[0]["messages"] +
                         [{"role": "user", "content": old.REPAIR_PROMPT}])
        self.assertTrue(all(body["model"] == module.MODEL and body["think"] is False for body in current.posts))

    def test_pure_build_request_matches_both_actual_initial_and_repair_requests(self):
        fake = FakeLocal(["{invalid", self.positive()])
        source_policy = deepcopy(self.policy)
        expected = [module.build_request(self.text, "unit-source", self.policy, [], repair=repair)
                    for repair in (False, True)]
        self.assertEqual(fake.requests, [])
        self.invoke(fake)
        self.assertEqual(fake.posts, expected)
        self.assertEqual(self.policy, source_policy)
        expected[0]["messages"][0]["content"] = "mutated external freeze object"
        self.assertNotEqual(expected[0], module.build_request(self.text, "unit-source", self.policy, []))
        with self.assertRaisesRegex(ValueError, "input_budget_exceeded"):
            module.build_request("x" * 6001, "unit-source", self.policy, [])
        with self.assertRaisesRegex(ValueError, "invalid_input"):
            module.build_request(self.text, "unit-source", self.policy, [], repair=1)

    def test_two_invalid_outputs_never_trigger_third_call(self):
        fake = FakeLocal(["{invalid", self.positive(occurrence=True), self.positive()])
        result = self.invoke(fake)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["errors"], ["format_or_span_invalid"])
        self.assertEqual((result["local_calls"], result["local_calls_complete"]), (2, True))
        self.assertEqual(len(fake.posts), 2)

    def test_thinking_tools_incomplete_and_wrong_model_outputs_do_not_repair(self):
        good = {"model": module.MODEL, "done": True, "done_reason": "stop", "message": {"content": "{}"}}
        cases = [dict(good, model=old.MODEL), dict(good, done=False), dict(good, done_reason="length"),
                 dict(good, message={"content": "{}", "thinking": "private"}),
                 dict(good, message={"content": "{}", "tool_calls": [{"name": "export"}]}),
                 dict(good, message={"content": None})]
        for raw in cases:
            with self.subTest(raw=raw):
                fake = FakeLocal([(raw,), self.positive()])
                result = self.invoke(fake)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["findings"], [])
                self.assertEqual((result["local_calls"], result["local_calls_complete"]), (1, True))
                self.assertEqual(len(fake.posts), 1)

    def test_semantic_unknown_remains_review_without_repair(self):
        fake = FakeLocal([{"status": "needs_review", "findings": []}])
        result = self.invoke(fake)
        self.assertEqual(result["errors"], ["semantic_uncertainty"])
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["status"], "needs_review")

    def test_transport_attempt_is_accounted_once_and_never_retried(self):
        fake = FakeLocal([RuntimeError("private failure"), self.positive()])
        result = self.invoke(fake)
        self.assertEqual(result["errors"], ["local_transport_failed"])
        self.assertEqual((result["local_calls"], result["local_calls_complete"]), (1, True))
        self.assertEqual(len(fake.posts), 1)
        self.assertNotIn("private failure", json.dumps(result))

    def test_invalid_input_policy_and_byte_budget_generate_zero_calls(self):
        for changes in ({"text": ""}, {"policy": {"version": "unit", "protected_categories": ["CUSTOMER"]}},
                        {"text": "x" * 6001}, {"text": "界" * 2000},
                        {"rule_findings": [{"start": True, "end": 5, "category": "CUSTOMER"}]}):
            with self.subTest(changes=changes):
                fake = FakeLocal()
                result = self.invoke(fake, **changes)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual((result["local_calls"], result["local_calls_complete"]), (0, True))
                self.assertEqual(fake.requests, [])

    def test_inherited_helpers_are_identical_and_policy_category_schema_is_retained(self):
        agent = module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=FakeLocal())
        for name in ("_validate_inputs", "_prepare_messages", "_validate_output", "_request_budget"):
            self.assertIs(getattr(type(agent), name), getattr(old.OccurrenceQwenAgent, name))
        fake = FakeLocal()
        self.invoke(fake)
        self.assertEqual(fake.posts[0]["format"], old._policy_schema(["CUSTOMER"]))
        self.assertEqual(fake.posts[0]["options"], {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42})

    def test_cache_identity_serializes_real_pins_and_explicit_runtime_option(self):
        identity = module.Qwen35OccurrenceAgent(expected_digest=DIGEST, transport=FakeLocal()).cache_identity()
        self.assertEqual(json.loads(json.dumps(identity)), identity)
        self.assertEqual((identity["model"], identity["digest"], identity["runtime"]), (module.MODEL, DIGEST, "0.40.8"))
        self.assertIs(identity["think"], False)
        self.assertEqual(identity["max_local_calls"], 2)
        self.assertEqual(identity["options"], module.OPTIONS)
        self.assertEqual(identity["prompt_sha256"], hashlib.sha256(old.SYSTEM_PROMPT.encode()).hexdigest())
        self.assertEqual(identity["repair_prompt_sha256"], hashlib.sha256(old.REPAIR_PROMPT.encode()).hexdigest())
        self.assertEqual(identity["occurrence_implementation_sha256"], hashlib.sha256(Path(old.__file__).read_bytes()).hexdigest())
        self.assertNotEqual(identity["implementation_sha256"], identity["occurrence_implementation_sha256"])

    def test_full_text_can_find_an_occurrence_without_any_rule_candidates(self):
        fake = FakeLocal([self.positive()])
        result = self.invoke(fake, rule_findings=[])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"][0]["start"], self.text.rindex("Moss"))
        self.assertEqual(json.loads(fake.posts[0]["messages"][1]["content"])["local_candidates"], [])


if __name__ == "__main__":
    unittest.main()
