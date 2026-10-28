"""Offline source annotation, exact projection, and signed receiving contracts."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer
from memory_migration_study.occurrence_qwen import OccurrenceQwenAgent, MODEL, VERSION, DIGEST
from memory_migration_study.privacy import _policy
from memory_migration_study.sensitivity_contract import (
    ANY_SPECIFIC_ORGANIZATION, STRICT_CUSTOMER_RELATION, bind_category_contract,
)
from memory_migration_study.source_annotation import annotate_and_build_records


class Detector:
    max_local_calls = 2

    def __init__(self, response=None):
        self.inputs = []
        self.response = response if response is not None else {
            "status": "ok", "findings": [], "errors": [], "local_calls": 1, "elapsed_seconds": 0.01}

    def __call__(self, **arguments):
        self.inputs.append(deepcopy(arguments))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class SourceAnnotationTests(unittest.TestCase):
    def setUp(self):
        self.network = patch("urllib.request.urlopen", side_effect=AssertionError("network_forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.authority = MemoryLabelAuthority(b"source-annotation-test-authority-32-bytes")
        self.policy = bind_category_contract({"version": "unit-v1", "protected_categories": ["CUSTOMER"],
            "instructions": "Business scope: our company."}, STRICT_CUSTOMER_RELATION)
        self.text = "Marker is a generic word. Our customer is Marker."
        self.source = {"source_id": "source-unit", "text": self.text}
        self.facts = [self.fact(0, len(self.text))]

    def fact(self, start, end, findings=None):
        return {"text": self.text[start:end], "source_start": start, "source_end": end,
                "findings": [] if findings is None else findings}

    def finding(self, start=None, end=None, quote=None):
        start = self.text.rindex("Marker") if start is None else start
        end = start + 6 if end is None else end
        return {"start": start, "end": end, "quote": self.text[start:end] if quote is None else quote,
                "category": "CUSTOMER"}

    def detect(self, findings=None, **changes):
        response = {"status": "ok", "findings": [self.finding()] if findings is None else findings,
                    "errors": [], "local_calls": 1, "elapsed_seconds": 0.01}
        response.update(changes)
        return Detector(response)

    def invoke(self, *, agent=None, **changes):
        arguments = {"source": self.source, "facts": self.facts, "policy": self.policy,
            "agent": self.detect() if agent is None else agent, "authority": self.authority,
            "owner_id": "owner", "agent_id": "source-agent",
            "allowed_principals": [{"user_id": "owner", "agent_id": "receiver-agent"}],
            "builder_version": "builder-v1", "detector_version": "detector-v1"}
        arguments.update(changes)
        return annotate_and_build_records(**arguments)

    def transfer(self, records, *, agent=None, **changes):
        args = {"authority": self.authority, "actor_id": "owner", "agent_id": "receiver-agent",
                "request_id": "request-unit", "mode": "two_stage", "agent": Detector() if agent is None else agent}
        args.update(changes)
        return prepare_labeled_transfer(records, "", self.policy, **args)

    def assert_review(self, result):
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["records"], [])
        self.assertTrue(result["errors"])

    def test_full_source_single_call_normalized_policy_and_response_snapshot(self):
        agent = self.detect()
        result = self.invoke(agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(agent.inputs, [{"text": self.text, "source_id": self.source["source_id"],
                                       "policy": _policy(self.policy), "rule_findings": []}])
        self.assertEqual(result["source_response"], agent.response)
        agent.response["findings"].clear()
        self.assertEqual(len(result["source_response"]["findings"]), 1)
        self.assertTrue(result["local_calls_complete"])
        self.assertEqual(result["local_calls"], 1)
        self.assertEqual(result["agent_elapsed_seconds"], 0.01)
        self.assertEqual(result["annotation_state"], "positive")

    def test_equal_words_project_only_selected_source_occurrence(self):
        cut = self.text.index(" Our")
        result = self.invoke(facts=[self.fact(0, cut), self.fact(cut, len(self.text))])
        self.assertEqual(result["status"], "ok")
        first, second = result["records"]
        self.assertEqual(first["label"]["findings"], [])
        self.assertEqual(second["label"]["findings"], [{"start": self.text.rindex("Marker") - cut,
            "end": self.text.rindex("Marker") + 6 - cut, "category": "CUSTOMER"}])
        self.assertEqual(result["projection"]["projected_source_finding_count"], 1)

    def test_outside_selected_fact_is_counted_without_relocating_equal_text(self):
        result = self.invoke(facts=[self.fact(0, 6)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["records"][0]["label"]["findings"], [])
        self.assertEqual(result["projection"]["unprojected_source_finding_count"], 1)

    def test_source_positive_remains_protected_when_receiver_returns_empty(self):
        result = self.transfer(self.invoke()["records"])
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("Marker", json.dumps(result["payload"]))
        self.assertTrue(any(row["method"] == "generation_label" for row in result["detection"]["findings"]))

    def test_existing_positive_constraints_are_unioned_and_deduplicated(self):
        existing = [{"start": 0, "end": 6, "category": "CUSTOMER"}, self.finding()]
        result = self.invoke(facts=[self.fact(0, len(self.text), existing)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["records"][0]["label"]["findings"]), 2)
        self.assertEqual(result["projection"]["facts"][0]["existing_positive_count"], 2)

    def test_observed_empty_is_assessed_but_never_certifies_completeness(self):
        result = self.invoke(agent=self.detect([]))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["annotation_state"], "observed_empty")
        self.assertEqual(result["projection"]["assessment"], "assessed_completeness_unproven")
        self.assertIs(result["projection"]["semantic_completeness_proven"], False)
        self.assertEqual(result["records"][0]["label"]["findings"], [])

    def test_unknown_error_or_nonempty_errors_never_become_clean_signed_records(self):
        for changes in ({"status": "unknown"}, {"status": "needs_review"}, {"status": "error"},
                        {"errors": ["semantic_uncertainty"]}, {"errors": "bad"}, {"errors": None}):
            with self.subTest(changes=changes):
                agent = self.detect([], **changes)
                result = self.invoke(agent=agent)
                self.assert_review(result)
                self.assertEqual(result["source_response"], agent.response)
                self.assertEqual(result["local_calls"], 1)

    def test_receiver_unknown_cannot_be_overridden_by_signed_source_positive(self):
        records = self.invoke()["records"]
        result = self.transfer(records, agent=self.detect([], status="needs_review", errors=["semantic_uncertainty"]))
        self.assertEqual(result["status"], "needs_review")
        self.assertIsNone(result["payload"])

    def test_receiver_false_positive_is_still_protected_by_union(self):
        result = self.transfer(self.invoke()["records"], agent=self.detect([self.finding(0)]))
        self.assertEqual(result["status"], "ok")
        spans = {(row["start"], row["end"]) for row in result["detection"]["findings"]}
        self.assertIn((0, 6), spans)
        self.assertIn((self.text.rindex("Marker"), self.text.rindex("Marker") + 6), spans)

    def test_source_label_crossing_fact_boundary_requires_review_without_clipping(self):
        at = self.text.rindex("Marker")
        for facts in ([self.fact(0, at + 3)], [self.fact(0, at + 3), self.fact(at + 3, len(self.text))],
                      [self.fact(at + 2, len(self.text))]):
            with self.subTest(facts=facts), patch.object(self.authority, "build_record", wraps=self.authority.build_record) as sign:
                result = self.invoke(facts=facts)
                self.assert_review(result)
                self.assertIn("source_finding_crosses_fact_boundary", result["errors"])
                sign.assert_not_called()

    def test_all_facts_are_validated_before_detector_or_signing(self):
        for changes in ({"text": "changed"}, {"source_start": True}, {"source_end": 99999},
                        {"source_end": 0}, {"source_start": -1}, {"status": "needs_review"}, {"findings": None}):
            with self.subTest(changes=changes):
                agent = self.detect()
                facts = [self.fact(0, 6), dict(self.fact(7, len(self.text)), **changes)]
                self.assert_review(self.invoke(agent=agent, facts=facts))
                self.assertEqual(agent.inputs, [])

    def test_duplicate_overlapping_or_empty_facts_require_review(self):
        for facts in ([], None, "facts", [self.facts[0], self.facts[0]],
                      [self.fact(0, 20), self.fact(10, len(self.text))],
                      [self.facts[0], self.fact(0, 6)]):
            with self.subTest(facts=facts):
                agent = self.detect()
                self.assert_review(self.invoke(agent=agent, facts=facts))
                self.assertEqual(agent.inputs, [])

    def test_invalid_source_findings_schema_type_quote_category_and_bool_offsets(self):
        for finding in (None, [], {"quote": "Marker", "category": "CUSTOMER"},
                        dict(self.finding(), start=True), dict(self.finding(), end=False),
                        dict(self.finding(), start="41"), dict(self.finding(), quote="marker"),
                        dict(self.finding(), category="EMAIL"), dict(self.finding(), category=[]),
                        dict(self.finding(), end=99999), dict(self.finding(), occurrence=2)):
            with self.subTest(finding=finding):
                self.assert_review(self.invoke(agent=self.detect([finding])))

    def test_duplicate_and_partially_crossing_source_annotations_require_review(self):
        for findings in ([self.finding(), self.finding()],
                         [self.finding(0, 6), self.finding(3, 10)]):
            with self.subTest(findings=findings):
                self.assert_review(self.invoke(agent=self.detect(findings)))

    def test_invalid_existing_fact_positives_are_not_signed(self):
        for findings in ([dict(self.finding(0), quote="wrong")], [dict(self.finding(0), start=True)],
                         [self.finding(0), self.finding(0)], [self.finding(0, 6), self.finding(3, 10)],
                         [dict(self.finding(0), category="EMAIL")]):
            with self.subTest(findings=findings):
                agent = self.detect()
                self.assert_review(self.invoke(agent=agent, facts=[self.fact(0, len(self.text), findings)]))
                self.assertEqual(agent.inputs, [])

    def test_existing_and_projected_positives_cannot_partially_cross_in_final_union(self):
        existing = [{"start": 0, "end": 6, "category": "CUSTOMER"}]
        agent = self.detect([self.finding(3, 10)])
        with patch.object(self.authority, "build_record", wraps=self.authority.build_record) as sign:
            result = self.invoke(agent=agent, facts=[self.fact(0, len(self.text), existing)])
        self.assert_review(result)
        self.assertEqual(len(agent.inputs), 1)
        sign.assert_not_called()

    def test_only_fixed_strict_customer_policy_is_supported(self):
        broad = bind_category_contract({"version": "unit-v1", "protected_categories": ["CUSTOMER"]},
                                       ANY_SPECIFIC_ORGANIZATION)
        for policy in (dict(self.policy, protected_categories=["CUSTOMER", "EMAIL"]),
                       dict(self.policy, protected_categories=[]), broad,
                       {"version": "unit-v1", "protected_categories": ["CUSTOMER"]},
                       dict(self.policy, category_contract={"ontology_id": STRICT_CUSTOMER_RELATION}), None):
            with self.subTest(policy=policy):
                agent = self.detect()
                self.assert_review(self.invoke(agent=agent, policy=policy))
                self.assertEqual(agent.inputs, [])

    def test_invalid_source_identity_type_empty_and_budget_are_rejected(self):
        for source in (None, [], {"source_id": "__query__", "text": self.text},
                       {"source_id": "", "text": self.text}, {"source_id": "source", "text": None},
                       {"source_id": "source", "text": ""}, {"source_id": "source", "text": "x" * 6001}):
            with self.subTest(source=source):
                agent = self.detect()
                self.assert_review(self.invoke(agent=agent, source=source))
                self.assertEqual(agent.inputs, [])

    def test_unicode_codepoint_projection_and_touching_boundaries_remain_exact(self):
        text = "😀甲乙甲乙甲"
        source = {"source_id": "unicode-source", "text": text}
        facts = [{"text": text[:3], "source_start": 0, "source_end": 3, "findings": []},
                 {"text": text[3:], "source_start": 3, "source_end": len(text), "findings": []}]
        agent = self.detect([{"start": 3, "end": 6, "quote": "甲乙甲", "category": "CUSTOMER"}])
        result = self.invoke(source=source, facts=facts, agent=agent)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["records"][0]["label"]["findings"], [])
        self.assertEqual(result["records"][1]["label"]["findings"],
                         [{"start": 0, "end": 3, "category": "CUSTOMER"}])

    def test_invalid_costs_and_explicit_incomplete_report_are_refused(self):
        cases = [{"local_calls": value} for value in (None, True, -1, 3, "1", 1.0)]
        cases += [{"elapsed_seconds": value} for value in (None, True, -1, "1", float("nan"), float("inf"), 10 ** 1000)]
        cases += [{"local_calls_complete": value} for value in (False, 1, "true", None)]
        for changes in cases:
            with self.subTest(changes=changes):
                result = self.invoke(agent=self.detect([], **changes))
                self.assert_review(result)
                self.assertFalse(result["local_calls_complete"])

    def test_explicit_complete_cost_and_repaired_two_call_report_are_preserved(self):
        result = self.invoke(agent=self.detect(local_calls=2, local_calls_complete=True))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(result["projection"]["cost_completeness_basis"], "explicit_adapter_report")

    def test_missing_or_invalid_trusted_call_bound_is_not_inferred(self):
        for bound in (None, True, 0, -1, 5, "2"):
            with self.subTest(bound=bound):
                agent = self.detect()
                agent.max_local_calls = bound
                result = self.invoke(agent=agent)
                self.assert_review(result)
                self.assertEqual(result["annotation_state"], "unavailable")
                self.assertFalse(result["local_calls_complete"])
                self.assertEqual(agent.inputs, [])

    def test_exception_invalid_response_and_missing_fields_fail_closed(self):
        for response in (RuntimeError("failed"), "{invalid", [], None, {},
                         {"status": "ok", "findings": []}):
            with self.subTest(response=response):
                agent = Detector()
                agent.response = response
                self.assert_review(self.invoke(agent=agent))

    def test_source_and_fact_content_and_signed_label_tampering_are_detected(self):
        record = self.invoke()["records"][0]
        changed = deepcopy(record)
        changed["source"]["text"] += " changed"
        self.assertEqual(self.transfer([changed])["error"], "source_identity_changed")
        changed = deepcopy(record)
        changed["text"] = "different"
        self.assertEqual(self.transfer([changed])["status"], "blocked")
        changed = deepcopy(record)
        changed["label"]["findings"] = []
        self.assertEqual(self.authority.validate_label(changed, self.policy), "label_signature_invalid")
        # Existing two-stage behavior repairs invalid sensitivity metadata using
        # a current detector; the unchanged exact fact access grant still gates it.
        repaired = self.transfer([changed], agent=self.detect())
        self.assertEqual(repaired["status"], "ok")
        self.assertNotIn("Marker", json.dumps(repaired["payload"]))

    def test_cross_user_agent_revocation_and_current_authorization_still_gate_access(self):
        record = self.invoke()["records"][0]
        for changes in ({"actor_id": "outsider"}, {"agent_id": "source-agent"}):
            with self.subTest(changes=changes):
                agent = Detector()
                result = self.transfer([record], agent=agent, **changes)
                self.assertEqual(result["error"], "principal_not_authorized")
                self.assertEqual(agent.inputs, [])
        self.assertEqual(self.transfer([record], authorizer=lambda *args: False)["error"], "current_authorization_failed")
        self.authority.revoke(record["record_id"])
        self.assertEqual(self.transfer([record])["error"], "grant_revoked")

    def test_forged_fields_in_source_fact_and_response_cannot_authorize_anyone(self):
        forged = {"owner_id": "outsider", "readers": ["outsider"], "public": True,
                  "allowed_principals": [{"user_id": "outsider", "agent_id": "evil"}]}
        result = self.invoke(source=dict(self.source, **forged), facts=[dict(self.facts[0], **forged)],
                             agent=self.detect(**forged))
        self.assertEqual(result["status"], "ok")
        record = result["records"][0]
        self.assertEqual(record["access"]["owner_id"], "owner")
        self.assertEqual(record["access"]["principal_scope"]["principals"],
                         [{"user_id": "owner", "agent_id": "receiver-agent"}])
        self.assertEqual(self.transfer([record], actor_id="outsider", agent_id="evil")["error"], "principal_not_authorized")

    def test_trusted_metadata_is_validated_before_detector(self):
        for changes in ({"allowed_principals": []}, {"allowed_principals": forged_pairs()},
                        {"owner_id": ""}, {"builder_version": "bad version"}, {"detector_version": None},
                        {"authority": None}):
            with self.subTest(changes=changes):
                agent = self.detect()
                self.assert_review(self.invoke(agent=agent, **changes))
                self.assertEqual(agent.inputs, [])

    def test_existing_occurrence_agent_without_new_complete_field_is_compatible(self):
        def transport(method, path, body=None):
            if path == "/api/version":
                return {"version": VERSION}
            if path == "/api/tags":
                return {"models": [{"name": MODEL, "digest": DIGEST}]}
            self.assertEqual(path, "/api/chat")
            return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"content": json.dumps(
                {"status": "ok", "findings": [{"quote": "Marker", "occurrence": 2, "category": "CUSTOMER"}]})}}
        result = self.invoke(agent=OccurrenceQwenAgent(transport=transport))
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("local_calls_complete", result["source_response"])
        self.assertTrue(result["local_calls_complete"])
        self.assertEqual(result["records"][0]["label"]["findings"][0]["start"], self.text.rindex("Marker"))

    def test_occurrence_agent_invalid_json_keeps_two_call_cost_and_signs_nothing(self):
        def transport(method, path, body=None):
            if path == "/api/version":
                return {"version": VERSION}
            if path == "/api/tags":
                return {"models": [{"name": MODEL, "digest": DIGEST}]}
            return {"model": MODEL, "done": True, "done_reason": "stop",
                    "message": {"content": "{invalid"}}
        result = self.invoke(agent=OccurrenceQwenAgent(transport=transport))
        self.assert_review(result)
        self.assertEqual(result["source_response"]["errors"], ["format_or_span_invalid"])
        self.assertEqual(result["local_calls"], 2)
        self.assertTrue(result["local_calls_complete"])


def forged_pairs():
    return [{"user_id": "owner", "agent_id": "receiver-agent", "public": True}]


if __name__ == "__main__":
    unittest.main()
