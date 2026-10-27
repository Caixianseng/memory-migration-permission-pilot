"""Synthetic occurrence/guideline contracts; no model or evaluation material."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from memory_migration_study import occurrence_qwen as module
from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.sensitivity_contract import (
    ANY_SPECIFIC_ORGANIZATION, STRICT_CUSTOMER_RELATION, bind_category_contract,
)


class FakeLocal:
    def __init__(self, replies=None):
        self.replies = list(replies or [{"status": "ok", "findings": []}])
        self.requests = []
        self.version, self.digest = module.VERSION, module.DIGEST

    def __call__(self, method, path, body=None):
        self.requests.append((method, path, deepcopy(body)))
        if path == "/api/version":
            return {"version": self.version}
        if path == "/api/tags":
            return {"models": [{"name": module.MODEL, "digest": self.digest}]}
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, tuple):
            return reply[0]
        return {"model": module.MODEL, "done": True, "done_reason": "stop",
                "message": {"content": reply if isinstance(reply, str) else json.dumps(reply)}}


class OccurrenceQwenTests(unittest.TestCase):
    def policy(self, profile=ANY_SPECIFIC_ORGANIZATION, categories=None):
        return bind_category_contract({"version": "synthetic-v1", "protected_categories":
            ["CUSTOMER"] if categories is None else categories,
            "instructions": "Business scope: our company."}, profile)

    def invoke(self, fake, **changes):
        arguments = {"text": "Marker appears; Marker is an organization.", "source_id": "private-source-id",
                     "policy": self.policy(), "rule_findings": []}
        arguments.update(changes)
        return module.OccurrenceQwenAgent(transport=fake)(**arguments)

    def finding(self, quote="Marker", occurrence=2, category="CUSTOMER"):
        return {"quote": quote, "occurrence": occurrence, "category": category}

    def test_selects_only_the_requested_exact_occurrence(self):
        text = "Marker appears; Marker is an organization."
        fake = FakeLocal([{"status": "ok", "findings": [self.finding()]}])
        result = self.invoke(fake, text=text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [{"start": text.rindex("Marker"), "end": text.rindex("Marker") + 6,
                                             "quote": "Marker", "category": "CUSTOMER"}])
        self.assertEqual(result["local_calls"], 1)

    def test_generic_use_and_actual_name_can_have_the_same_surface_form(self):
        text = "customer is a role; the registered organization is named customer."
        result = self.invoke(FakeLocal([{"status": "ok", "findings": [self.finding("customer")]}]), text=text)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["start"], text.rindex("customer"))

    def test_unicode_codepoints_and_overlapping_matches_are_exact(self):
        text = "😀甲乙甲乙甲"
        output = module.OccurrenceQwenAgent._validate_output(
            {"status": "ok", "findings": [self.finding("甲乙甲", 2)]}, text, ["CUSTOMER"])
        self.assertEqual(output["findings"][0], {"start": 3, "end": 6, "quote": "甲乙甲", "category": "CUSTOMER"})

    def test_wrapper_only_repair_preserves_occurrence_without_fuzzy_matching(self):
        text = "Marker then Marker"
        output = module.OccurrenceQwenAgent._validate_output(
            {"status": "ok", "findings": [self.finding('  “Marker”.  ')]}, text, ["CUSTOMER"])
        self.assertEqual(output["findings"][0]["start"], text.rindex("Marker"))
        self.assertEqual(output["quote_wrapper_repairs"], 1)
        for quote in ("marker", "Mar ker", "Marker! suffix"):
            with self.subTest(quote=quote), self.assertRaisesRegex(ValueError, "invalid_span"):
                module.OccurrenceQwenAgent._validate_output(
                    {"status": "ok", "findings": [self.finding(quote, 1)]}, text, ["CUSTOMER"])

    def test_invalid_ordinal_does_not_fall_back_to_first_or_all_matches(self):
        for occurrence in (True, 0, -1, 3, 1.0, "2"):
            with self.subTest(occurrence=occurrence):
                bad = {"status": "ok", "findings": [self.finding(occurrence=occurrence)]}
                result = self.invoke(FakeLocal([bad, bad]))
                self.assertEqual(result["errors"], ["format_or_span_invalid"])
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["local_calls"], 2)
                self.assertEqual([d["code"] for d in result["diagnostics"]], ["invalid_span", "invalid_span"])

    def test_one_fixed_repair_uses_no_previous_model_output(self):
        bad = {"status": "ok", "findings": [self.finding("INVENTED_REPLY_ONLY", 1)]}
        good = {"status": "ok", "findings": [self.finding()]}
        fake = FakeLocal([bad, good])
        result = self.invoke(fake)
        posts = [body for method, _, body in fake.requests if method == "POST"]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(posts[1]["messages"], posts[0]["messages"] + [{"role": "user", "content": module.REPAIR_PROMPT}])
        self.assertNotIn("INVENTED_REPLY_ONLY", json.dumps(posts))

    def test_full_fixed_guidelines_and_profile_are_in_the_actual_system_request(self):
        for profile in (STRICT_CUSTOMER_RELATION, ANY_SPECIFIC_ORGANIZATION):
            with self.subTest(profile=profile):
                fake = FakeLocal()
                policy = self.policy(profile)
                result = self.invoke(fake, policy=policy)
                request = fake.requests[-1][2]
                system = request["messages"][0]["content"]
                trusted = json.loads(system.split("\n\nTrusted sensitivity policy JSON:\n")[1])
                self.assertEqual(trusted["category_contract"], policy["category_contract"])
                self.assertEqual(trusted["instructions"], policy["instructions"])
                self.assertTrue(system.startswith(module.SYSTEM_PROMPT))
                self.assertNotIn("private-source-id", json.dumps(request))
                self.assertEqual(request["options"], {"num_ctx": 4096, "num_predict": 1024, "temperature": 0, "seed": 42})
                self.assertNotIn("tools", request)
                self.assertIn(profile, result["prompt_version"])
                item = request["format"]["properties"]["findings"]["items"]
                self.assertEqual(set(item["required"]), {"quote", "occurrence", "category"})
                self.assertEqual(item["properties"]["category"]["enum"], ["CUSTOMER"])

    def test_semantic_review_is_not_repaired_or_promoted_to_success(self):
        fake = FakeLocal([{"status": "needs_review", "findings": []}])
        result = self.invoke(fake, policy=self.policy(STRICT_CUSTOMER_RELATION))
        self.assertEqual(result["errors"], ["semantic_uncertainty"])
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["local_calls"], 1)
        self.assertIn("do not review solely because it is unknown", module.SYSTEM_PROMPT)

    def test_missing_or_changed_contract_and_extra_policy_fields_never_call_transport(self):
        policies = [{"version": "v1", "protected_categories": ["CUSTOMER"]}, self.policy(), self.policy()]
        policies[1]["category_contract"]["definitions"]["CUSTOMER"] = "Different meaning"
        policies[2]["evaluation_answer"] = "DO_NOT_FORWARD"
        for policy in policies:
            with self.subTest(policy=policy):
                fake = FakeLocal()
                result = self.invoke(fake, policy=policy)
                self.assertEqual(result["errors"], ["invalid_category_contract"])
                self.assertEqual(result["local_calls"], 0)
                self.assertEqual(fake.requests, [])

    def test_invalid_schema_category_and_duplicate_json_get_only_one_repair(self):
        invalid = [
            {"status": "ok", "findings": [{"quote": "Marker", "category": "CUSTOMER"}]},
            {"status": "ok", "findings": [self.finding(category="PERSON")]},
            '{"status":"ok","status":"ok","findings":[]}',
        ]
        for value in invalid:
            with self.subTest(value=value):
                result = self.invoke(FakeLocal([value, value]))
                self.assertEqual(result["errors"], ["format_or_span_invalid"])
                self.assertEqual(result["local_calls"], 2)

    def test_envelope_failures_are_not_output_failures_and_never_repair(self):
        baseline = {"model": module.MODEL, "done": True, "done_reason": "stop", "message": {"content": "{}"}}
        variants = [dict(baseline, model="wrong"), dict(baseline, done_reason="length"),
                    dict(baseline, message={}), dict(baseline, message={"content": {}}),
                    dict(baseline, message={"content": "{}", "tool_calls": ["forbidden"]})]
        for envelope in variants:
            with self.subTest(envelope=envelope):
                result = self.invoke(FakeLocal([(envelope,)]))
                self.assertEqual(result["local_calls"], 1)
                self.assertEqual(result["diagnostics"][0]["stage"], "envelope")
                self.assertNotIn("format_or_span_invalid", result["errors"])

    def test_health_transport_and_input_budget_failures_remain_distinct(self):
        fake = FakeLocal(); fake.digest = "wrong"
        result = self.invoke(fake)
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(result["errors"], ["local_health_failed"])
        fake = FakeLocal([RuntimeError("PRIVATE_EXCEPTION_TEXT")])
        result = self.invoke(fake)
        self.assertEqual(result["errors"], ["local_transport_failed"])
        self.assertEqual(result["diagnostics"][0]["stage"], "transport")
        self.assertNotIn("PRIVATE_EXCEPTION_TEXT", json.dumps(result))
        fake = FakeLocal()
        result = self.invoke(fake, text="秘密" * 3000)
        self.assertEqual(result["errors"], ["input_budget_exceeded"])
        self.assertEqual(fake.requests, [])

    def test_repair_budget_is_checked_before_a_second_post(self):
        policy = self.policy(STRICT_CUSTOMER_RELATION)
        data, trusted = module.OccurrenceQwenAgent._validate_inputs("x", "probe", policy, [])
        messages, _ = module.OccurrenceQwenAgent._prepare_messages(data, trusted)
        text = "x" * (4096 - module.OccurrenceQwenAgent._request_budget(messages) + 1)
        fake = FakeLocal([{"status": "ok", "findings": [self.finding("absent", 1)]}])
        result = self.invoke(fake, text=text, policy=policy)
        self.assertEqual(result["errors"], ["repair_budget_exceeded"])
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(sum(method == "POST" for method, _, _ in fake.requests), 1)
        self.assertEqual(result["diagnostics"][-1]["stage"], "budget")

    def test_pins_loopback_model_runtime_and_digest(self):
        for config in ({"endpoint": "https://external.example"}, {"model": "different"},
                       {"expected_version": "wrong"}, {"expected_digest": "wrong"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                module.OccurrenceQwenAgent(config)

    def test_duplicate_selected_findings_are_deduplicated_without_expansion(self):
        output = module.OccurrenceQwenAgent._validate_output(
            {"status": "ok", "findings": [self.finding(), self.finding()]},
            "Marker then Marker", ["CUSTOMER"])
        self.assertEqual(len(output["findings"]), 1)

    def test_cache_identity_binds_new_source_prompt_schema_and_full_policy(self):
        fake = FakeLocal([{"status": "ok", "findings": [self.finding()]}] * 2)
        agent = module.OccurrenceQwenAgent(transport=fake)
        identity = agent.cache_identity()
        self.assertEqual(identity["implementation_sha256"], hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
        self.assertEqual(identity["prompt_sha256"], hashlib.sha256(module.SYSTEM_PROMPT.encode()).hexdigest())
        self.assertIn("schema_sha256", identity)
        wrapped = DetectionCache().bind(agent, scope={"owner": "synthetic"})
        arguments = {"text": "Marker then Marker", "source_id": "record", "rule_findings": []}
        first = wrapped(policy=self.policy(), **arguments)
        warm = wrapped(policy=self.policy(), **arguments)
        changed = wrapped(policy=self.policy(STRICT_CUSTOMER_RELATION), **arguments)
        self.assertEqual([first["local_calls"], warm["local_calls"], changed["local_calls"]], [1, 0, 1])
        self.assertEqual(warm["findings"], [{"quote": "Marker", "start": 12, "end": 18, "category": "CUSTOMER"}])


if __name__ == "__main__":
    unittest.main()
