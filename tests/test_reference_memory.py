"""Bound candidate construction/selection using fake local transports only."""
import copy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import reference_memory as reference
from memory_migration_study.local_detector import MODEL, DIGEST, VERSION
from memory_migration_study.memory_labels import MemoryLabelAuthority


class FakeTransport:
    def __init__(self, replies):
        self.replies, self.requests = list(replies), []
    def __call__(self, method, path, body=None):
        self.requests.append((method, path, copy.deepcopy(body)))
        if (method, path) == ("GET", "/api/version"):
            return {"version": VERSION}
        if (method, path) == ("GET", "/api/tags"):
            return {"models": [{"name": MODEL, "digest": DIGEST}]}
        if (method, path) != ("POST", "/api/chat"):
            raise AssertionError("unknown_fake_route")
        reply = self.replies.pop(0)
        if callable(reply):
            reply = reply(body)
        if isinstance(reply, Exception):
            raise reply
        return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant",
            "content": reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False)},
            "prompt_eval_count": 240, "eval_count": 60}
    @property
    def posts(self):
        return [request[2] for request in self.requests if request[:2] == ("POST", "/api/chat")]


class FakeDetector:
    max_local_calls = 1
    def __init__(self, fail_quote=None, unknown=False):
        self.calls, self.fail_quote, self.unknown = [], fail_quote, unknown
    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        findings = [] if self.fail_quote is None else [{"quote": self.fail_quote, "category": "CUSTOMER"}]
        return {"status": "ok", "errors": [], "findings": findings, "local_calls": 1, "elapsed_seconds": 0.0,
            "inference_counts": {"local_encoder": 0 if self.unknown else 1,
                                 "local_generation": 0, "unknown": 1 if self.unknown else 0}}


class ReferenceMemoryTests(unittest.TestCase):
    text = "Customer: Cedar Foundry\nStatus: ready\nDate: 2035-08-24"
    policy = {"version": "reference-test", "protected_categories": ["CUSTOMER", "DATE"]}
    def builder(self, mode="select", replies=None, detector=None, **kwargs):
        detector = detector or FakeDetector()
        transport = FakeTransport(replies or [])
        builder = reference.ReferenceMemoryBuilder(mode=mode, detector=detector, transport=transport, **kwargs)
        return builder, transport, detector

    def test_whole_fields_company_periods_decimals_and_unicode_are_not_split(self):
        text = "Customer: Alder Co., Ltd.; Budget=410,000.50 USD.\r\n客户：青河集团；状态：待审\n"
        pool = reference.propose_fact_pool(text, "source")
        self.assertEqual(pool["status"], "candidates_only")
        self.assertEqual([text[item["start"]:item["end"]] for item in pool["candidates"]], text.splitlines())
        self.assertTrue(pool["coverage"]["all_non_whitespace_covered"])
        self.assertEqual(pool["coverage"]["omitted_non_whitespace_characters"], 0)
        self.assertTrue(reference.verify_fact_pool(text, "source", pool))

    def test_table_header_rows_and_multiline_quotation_stay_in_one_block(self):
        text = "Name | Status\n--- | ---\nCedar | ready\nFooter: public"
        pool = reference.propose_fact_pool(text, "source")
        values = [text[item["start"]:item["end"]] for item in pool["candidates"]]
        self.assertEqual(values, ["Name | Status\n--- | ---\nCedar | ready", "Footer: public"])
        text = "客户：“青河\n联合集团”\n状态：待审"
        pool = reference.propose_fact_pool(text, "source")
        self.assertEqual([text[item["start"]:item["end"]] for item in pool["candidates"]], ["客户：“青河\n联合集团”", "状态：待审"])

    def test_overflow_unbalanced_or_blank_source_never_returns_a_usable_prefix(self):
        for text, limits, error in (("a\nb", {"max_candidates": 1}, "candidate_count_budget_exceeded"),
                                   ("abc", {"max_fact_chars": 2}, "fact_character_budget_exceeded"),
                                   ("abcdef", {"max_source_chars": 3}, "source_character_budget_exceeded"),
                                   ("a\nb", {"max_total_chars": 1}, "retained_character_budget_exceeded"),
                                   ('客户：“unclosed', {}, "unbalanced_source_delimiters"),
                                   ("  \n", {}, "invalid_source")):
            with self.subTest(error=error):
                pool = reference.propose_fact_pool(text, "source", limits=limits)
                self.assertEqual(pool["status"], "needs_review")
                self.assertFalse(pool["complete"])
                self.assertEqual(pool["error"], error)
        pool = reference.propose_fact_pool("a\nb", "source", limits={"max_candidates": 1})
        self.assertEqual(len(pool["candidates"]), 2)  # diagnostic complete pool, never a hidden prefix

    def test_pool_binds_source_id_offsets_hashes_configuration_without_mutation(self):
        pool = reference.propose_fact_pool(self.text, "source")
        for field in ("source_id", "source_sha256", "configuration_sha256", "pool_sha256"):
            broken = copy.deepcopy(pool)
            broken[field] = "changed"
            self.assertFalse(reference.verify_fact_pool(self.text, "source", broken))
        broken = copy.deepcopy(pool)
        broken["candidates"][0]["start"] += 1
        builder, transport, detector = self.builder(replies=[{"status": "ok", "selected_fids": ["F0001"]}])
        result = builder(text=self.text, source_id="source", policy=self.policy, pool=broken)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(transport.requests, [])
        self.assertEqual(detector.calls, [])

    def test_pool_binding_rejects_boolean_integer_type_tampering(self):
        pool = reference.propose_fact_pool(self.text, "source")
        for mutate in (
            lambda value: value["candidates"][0].update(start=False),
            lambda value: value.update(complete=1),
            lambda value: value["coverage"].update(all_non_whitespace_covered=1),
        ):
            broken = copy.deepcopy(pool)
            mutate(broken)
            # Its stored digest is deliberately unchanged. Dict equality alone
            # would accept these boolean/integer substitutions.
            self.assertEqual(broken, pool)
            self.assertFalse(reference.verify_fact_pool(self.text, "source", broken))
            builder, transport, detector = self.builder(replies=[])
            result = builder(text=self.text, source_id="source", policy=self.policy, pool=broken)
            self.assertEqual(result["status"], "needs_review")
            self.assertIn("fact_pool_binding_invalid", result["errors"])
            self.assertEqual(transport.requests, [])
            self.assertEqual(detector.calls, [])

    def test_select_ids_recovers_host_spans_then_independent_labels_and_public_status(self):
        pool = reference.propose_fact_pool(self.text, "source")
        before = copy.deepcopy(pool)
        builder, transport, detector = self.builder(replies=[{"status": "ok", "selected_fids": ["F0002", "F0001"]}])
        result = builder(text=self.text, source_id="source", policy=self.policy, pool=pool)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(pool, before)
        self.assertEqual(result["selected_fids"], ["F0001", "F0002"])
        self.assertEqual([fact["text"] for fact in result["facts"]], self.text.splitlines()[:2])
        self.assertEqual(result["facts"][1]["findings"], [])
        self.assertTrue(result["facts"][0]["findings"])
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["local_counts"], {"local_encoder": 2, "local_generation": 1, "unknown": 0})
        self.assertEqual(result["total_local_calls"], 3)
        self.assertTrue(result["local_calls_complete"])
        self.assertEqual(len(detector.calls), 2)
        request_data = json.loads(transport.posts[0]["messages"][1]["content"])
        self.assertEqual(set(request_data), {"purpose", "candidates"})
        self.assertEqual(set(request_data["candidates"][0]), {"fid", "text"})
        authority = MemoryLabelAuthority(b"a"*32)
        for fact in result["facts"]:
            record = authority.build_record({"source_id": "source", "text": self.text}, fact, self.policy,
                owner_id="owner", readers=["owner"], agent_id="A", allowed_agent_ids=["B"], builder_version=result["builder_version"])
            self.assertIsNone(authority.validate_access(record, actor_id="owner", agent_id="B", policy_version=self.policy["version"]))

    def test_retain_all_same_pool_no_selector_client_health_or_generation(self):
        detector = FakeDetector()
        with patch.object(reference, "LocalSensitivityAgent", side_effect=AssertionError("retain_all_has_no_selector")):
            builder = reference.ReferenceMemoryBuilder(mode="retain_all", detector=detector)
        result = builder(text=self.text, source_id="source", policy=self.policy)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["local_calls"], 0)
        self.assertEqual(result["selector_local_counts"]["local_generation"], 0)
        self.assertEqual(result["detector_local_counts"]["local_encoder"], 3)
        self.assertEqual(len(result["facts"]), 3)

    def test_quote_select_uses_same_model_input_and_same_pool_as_id_select(self):
        pool = reference.propose_fact_pool(self.text, "source")
        chosen = self.text.splitlines()[1]
        first, ft, _ = self.builder(replies=[{"status": "ok", "selected_fids": ["F0002"]}])
        second, qt, _ = self.builder(mode="quote_select", replies=[{"status": "ok", "selected_quotes": [chosen]}])
        a = first(text=self.text, source_id="source", policy=self.policy, pool=pool)
        b = second(text=self.text, source_id="source", policy=self.policy, pool=pool)
        self.assertEqual(a["status"], b["status"])
        self.assertEqual(a["facts"], b["facts"])
        self.assertEqual(ft.posts[0]["messages"], qt.posts[0]["messages"])
        self.assertEqual(a["pool"]["pool_sha256"], b["pool"]["pool_sha256"])

    def test_equal_quotes_are_ambiguous_but_fid_keeps_selected_source_occurrence(self):
        text = "Repeated fact\nRepeated fact"
        quote, transport, _ = self.builder(mode="quote_select", replies=[{"status": "ok", "selected_quotes": ["Repeated fact"]}])
        rejected = quote(text=text, source_id="source", policy=self.policy)
        self.assertEqual(rejected["status"], "needs_review")
        self.assertIn("ambiguous_selected_quote", rejected["errors"])
        self.assertEqual(len(transport.posts), 1)
        ids, _, _ = self.builder(replies=[{"status": "ok", "selected_fids": ["F0002"]}])
        accepted = ids(text=text, source_id="source", policy=self.policy)
        self.assertEqual(accepted["status"], "ok", accepted)
        self.assertEqual(accepted["facts"][0]["source_start"], len("Repeated fact\n"))

    def test_unknown_duplicate_authority_and_parent_claims_are_never_accepted(self):
        invalid = [{"status": "ok", "selected_fids": ["F9999"]}, {"status": "ok", "selected_fids": ["F0001", "F0001"]},
            {"status": "ok", "selected_fids": ["F0001"], "permissions": "admin"},
            {"status": "ok", "selected_fids": ["F0001"], "source_id": "forged-parent"},
            '{"status":"ok","status":"ok","selected_fids":["F0001"]}']
        for value in invalid:
            with self.subTest(reply=value):
                builder, transport, detector = self.builder(replies=[value, value])
                result = builder(text=self.text, source_id="source", policy=self.policy)
                self.assertEqual(result["status"], "needs_review")
                self.assertFalse(result["accepted_for_store"])
                self.assertEqual(result["facts"], [])
                self.assertEqual(detector.calls, [])
                self.assertEqual(len(transport.posts), 2)

    def test_exactly_one_format_repair_preserves_source_pool_and_usage_records(self):
        builder, transport, _ = self.builder(replies=["not json", {"status": "ok", "selected_fids": ["F0001"]}])
        result = builder(text=self.text, source_id="source", policy=self.policy)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["selector_local_calls"], 2)
        self.assertEqual(len(result["selection_attempts"]), 2)
        self.assertEqual(transport.posts[0]["messages"][1], transport.posts[1]["messages"][1])
        self.assertEqual(transport.posts[0]["format"], transport.posts[1]["format"])
        self.assertTrue(all(attempt["prompt_eval_count"] == 240 for attempt in result["selection_attempts"]))

    def test_explicit_needs_review_and_empty_ok_do_not_trigger_success_repair(self):
        for reply in ({"status": "needs_review", "selected_fids": []},
                      {"status": "needs_review", "selected_fids": ["F0001"], "extra": "invalid but still uncertain"},
                      {"status": "ok", "selected_fids": []}):
            builder, transport, detector = self.builder(replies=[reply, {"status": "ok", "selected_fids": ["F0001"]}])
            result = builder(text=self.text, source_id="source", policy=self.policy)
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(len(transport.posts), 1)
            self.assertEqual(detector.calls, [])

    def test_invalid_review_authority_schema_is_distinct_and_never_repaired(self):
        for mode, field in (("select", "selected_fids"), ("quote_select", "selected_quotes")):
            for review, expected in (({"status": "needs_review", field: []}, "selector_needs_review"),
                                     ({"status": "needs_review", field: [], "owner": "admin"}, "selector_invalid_review_schema"),
                                     ({"status": "needs_review", "owner": "admin"}, "selector_invalid_review_schema")):
                builder, transport, detector = self.builder(mode=mode, replies=[review, {"status": "ok", field: []}])
                result = builder(text=self.text, source_id="source", policy=self.policy)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["errors"], [expected])
                self.assertEqual(result["selection_status"], "needs_review" if expected == "selector_needs_review" else "invalid_review_schema")
                self.assertEqual(len(transport.posts), 1)
                self.assertEqual(result["selector_local_calls"], 1)
                self.assertEqual(result["facts"], [])
                self.assertEqual(detector.calls, [])

    def test_fact_label_cannot_borrow_another_facts_value_or_hide_unknown_cost(self):
        for detector in (FakeDetector(fail_quote="Cedar Foundry"), FakeDetector(unknown=True)):
            builder, _, _ = self.builder(replies=[{"status": "ok", "selected_fids": ["F0002"]}], detector=detector)
            result = builder(text=self.text, source_id="source", policy=self.policy)
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["facts"], [])
            self.assertEqual(len(result["candidate_facts"]), 1)
            self.assertEqual(result["candidate_facts"][0]["status"], "needs_review")
            if detector.unknown:
                self.assertEqual(result["local_counts"]["unknown"], 1)
                self.assertFalse(result["local_calls_complete"])

    def test_full_serialized_budget_is_checked_before_health_or_post(self):
        text = "\n".join("X"*900 for _ in range(3))
        for mode in ("select", "quote_select"):
            builder, transport, detector = self.builder(mode=mode)
            result = builder(text=text, source_id="source", policy=self.policy)
            self.assertEqual(result["status"], "needs_review")
            self.assertIn("selector_input_budget_exceeded", result["errors"])
            self.assertEqual(transport.requests, [])
            self.assertEqual(detector.calls, [])
            self.assertEqual(result["local_calls"], 0)

    def test_selector_never_receives_policy_registry_scoring_or_auth_fields(self):
        policy = dict(self.policy, instructions="POLICY_CANARY", scoring_answer="GOLD_CANARY",
                      entity_registry=[{"value": "REGISTRY_CANARY", "category": "CUSTOMER"}])
        builder, transport, _ = self.builder(replies=[{"status": "ok", "selected_fids": ["F0002"]}])
        result = builder(text=self.text, source_id="source", policy=policy)
        self.assertEqual(result["status"], "ok", result)
        encoded = json.dumps(transport.posts)
        for value in ("POLICY_CANARY", "GOLD_CANARY", "REGISTRY_CANARY", "source_id", "source_start", "findings"):
            self.assertNotIn(value, encoded)


if __name__ == "__main__":
    unittest.main()
