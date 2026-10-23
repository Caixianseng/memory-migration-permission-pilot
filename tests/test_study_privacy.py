import copy
import dataclasses
import json
import pickle
import re
import unittest
from unittest.mock import patch

from memory_migration_study.privacy import detect_sensitive, prepare_private_payload, restore_answer


def policy(*cats):
    return {"version": "v1", "protected_categories": list(cats)}


def payload(text, query="Who is the customer?", source_id="memory-1"):
    return {"query": query, "memories": [{"source_id": source_id, "text": text}]}


def yes(source_id, actor_id, version):
    return source_id != "denied" and actor_id == "owner" and version == "v1"


def prepare(data, p, **kwargs):
    detection = detect_sensitive(data, p, mode="rules")
    return prepare_private_payload(data, detection, actor_id="owner", request_id="r1", policy_version="v1",
                                   authorizer=yes, **kwargs)


def restore(value, prepared, **kwargs):
    args = {"actor_id": "owner", "request_id": "r1", "policy_version": "v1", "authorizer": yes}
    args.update(kwargs)
    return restore_answer(value, prepared["mapping"], **args)


def tokens(prepared):
    return re.findall(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]", json.dumps(prepared["payload"]))


class PrivacyTests(unittest.TestCase):
    def test_rules_identity_and_business_without_answer_literals(self):
        data = payload("姓名：沈星禾；邮箱：shen@example.test；电话：13900001001；客户：青杉实验社；项目：枫叶-103；预算：262,000 USD；日期：2026年6月23日。")
        found = detect_sensitive(data, policy("PERSON", "EMAIL", "PHONE", "CUSTOMER", "PROJECT", "AMOUNT", "DATE"), mode="rules")
        self.assertEqual(found["status"], "ok")
        self.assertEqual({f["category"] for f in found["findings"]}, {"PERSON", "EMAIL", "PHONE", "CUSTOMER", "PROJECT", "AMOUNT", "DATE"})

    def test_public_policy_does_not_turn_entity_into_sensitive_data(self):
        data = payload("Email: visible@example.test; Customer: Public Office.")
        self.assertEqual(detect_sensitive(data, policy(), mode="rules")["findings"], [])

    def test_query_and_repeated_values_masked_consistently(self):
        data = payload("Customer: Orchid Mutual; Email: orchid@example.test; orchid@example.test",
                       "Is Orchid Mutual using orchid@example.test?")
        prepared = prepare(data, policy("CUSTOMER", "EMAIL"))
        self.assertEqual(prepared["status"], "ok")
        serialized = json.dumps(prepared["payload"])
        self.assertNotIn("Orchid Mutual", serialized)
        self.assertNotIn("orchid@example.test", serialized)
        self.assertEqual(prepared["metadata"]["token_count"], 2)
        self.assertEqual(prepared["metadata"]["replacement_count"], 5)
        self.assertEqual(len(set(tokens(prepared))), 2)

    def test_query_only_values_never_become_evidence(self):
        data = {"query": "Customer: Invented Customer", "memories": []}
        prepared = prepare(data, policy("CUSTOMER"))
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(restore(tokens(prepared)[0], prepared)["error"], "query_only_value_has_no_evidence")
        self.assertEqual(restore("UNKNOWN", prepared)["status"], "ok")

    def test_case_changed_query_does_not_bypass_known_sensitive_value(self):
        data = payload("Customer: Orchid Mutual", query="Does ORCHID MUTUAL have a contract?")
        prepared = prepare(data, policy("CUSTOMER"))
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("orchid mutual", json.dumps(prepared["payload"]).lower())
        self.assertEqual(len(set(tokens(prepared))), 1)
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "Orchid Mutual")

    def test_incidental_nonce_substring_is_not_mistaken_for_raw_value_leak(self):
        data = payload("Name: A", query="")
        with patch("memory_migration_study.privacy.secrets.token_hex", return_value="a" * 24):
            prepared = prepare(data, policy("PERSON"))
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "A")

    def test_authorized_restore_and_changed_scope_or_revocation(self):
        prepared = prepare(payload("Customer: Private Cooperative."), policy("CUSTOMER"))
        token = tokens(prepared)[0]
        self.assertEqual(restore(token, prepared)["answer"], "Private Cooperative")
        for args in ({"actor_id": "outsider"}, {"request_id": "other"}, {"policy_version": "v2"}):
            self.assertEqual(restore(token, prepared, **args)["error"], "restoration_scope_mismatch")
        self.assertEqual(restore(token, prepared, authorizer=lambda *args: False)["error"], "restoration_authorization_failed")

    def test_preparation_requires_authorization_before_cloud_export(self):
        data = payload("Customer: Private Cooperative", source_id="denied")
        self.assertEqual(prepare(data, policy("CUSTOMER"))["error"], "memory_authorization_failed")

    def test_tokens_are_random_and_cannot_cross_requests(self):
        data = payload("Customer: Private Cooperative")
        first, second = prepare(data, policy("CUSTOMER")), prepare(data, policy("CUSTOMER"))
        self.assertNotEqual(tokens(first), tokens(second))
        self.assertEqual(restore(tokens(first)[0], second)["error"], "unknown_or_embedded_token")
        self.assertEqual(restore("I cannot tell you " + tokens(first)[0], first)["error"], "unknown_or_embedded_token")

    def test_source_ids_do_not_leak(self):
        prepared = prepare(payload("Public fact", source_id="private@example.test"), policy())
        self.assertNotIn("private@example.test", json.dumps(prepared["payload"]))

    def test_map_does_not_appear_in_repr_json_pickle_or_dataclass_export(self):
        prepared = prepare(payload("Customer: Private Cooperative"), policy("CUSTOMER"))
        mapping = prepared["mapping"]
        self.assertNotIn("Private Cooperative", repr(prepared))
        self.assertNotIn("owner", repr(mapping))
        for operation in (json.dumps, pickle.dumps, dataclasses.asdict):
            with self.assertRaises(TypeError):
                operation(mapping)
        self.assertFalse(hasattr(mapping, "__dict__"))

    def test_refusal_containing_secret_and_partial_secret_blocked(self):
        prepared = prepare(payload("Customer: Private Cooperative; Status: active."), policy("CUSTOMER"))
        self.assertEqual(restore("I cannot tell you Private Cooperative", prepared)["error"], "raw_protected_value_in_answer")
        self.assertEqual(restore("Private", prepared)["error"], "literal_has_no_memory_evidence")
        self.assertEqual(restore("active", prepared)["answer"], "active")
        self.assertEqual(restore("inactive", prepared)["error"], "literal_has_no_memory_evidence")

    def test_overlaps_union_without_leaking_suffix(self):
        data = payload("Customer: North Gate Cooperative", query="Who is the customer?")
        def agent(**kwargs):
            if kwargs["source_id"] == "__query__":
                return {"status": "ok", "findings": []}
            return {"status": "ok", "findings": [{"quote": "Gate Cooperative", "category": "PERSON"}]}
        detected = detect_sensitive(data, policy("CUSTOMER", "PERSON"), agent=agent)
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1", policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(prepared["metadata"]["token_count"], 1)
        self.assertNotIn("Gate", json.dumps(prepared["payload"]))
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "North Gate Cooperative")

    def test_agent_contract_never_receives_labels(self):
        seen = []
        def agent(**kwargs):
            seen.append(kwargs)
            return {"status": "ok", "findings": []}
        data = payload("Name: Alice Moss", query="")
        detect_sensitive(data, {**policy("PERSON"), "expected_answer": "gold-must-not-pass"}, agent=agent)
        self.assertNotIn("gold-must-not-pass", json.dumps(seen))
        self.assertEqual(set(seen[0]), {"text", "source_id", "policy", "rule_findings"})
        bad_data = {**data, "evaluation": {"answer": "gold"}}
        self.assertEqual(detect_sensitive(bad_data, policy("PERSON"), agent=agent)["status"], "needs_review")

    def test_agent_ambiguity_and_explicit_span(self):
        data = payload("Alice Moss met Alice Moss.", query="")
        def ambiguous(**kwargs):
            return {"status": "ok", "findings": [{"quote": "Alice Moss", "category": "PERSON"}]}
        detected = detect_sensitive(data, policy("PERSON"), agent=ambiguous, mode="agent")
        self.assertIn("ambiguous_agent_quote", detected["errors"])
        def located(**kwargs):
            return {"status": "ok", "findings": [{"quote": "Alice Moss", "category": "PERSON", "start": 0, "end": 10}]}
        detected = detect_sensitive(data, policy("PERSON"), agent=located, mode="agent")
        self.assertEqual(detected["status"], "ok")
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1", policy_version="v1", authorizer=yes)
        self.assertNotIn("Alice Moss", json.dumps(prepared["payload"]))

    def test_missing_agent_and_failures_cannot_silently_become_safe(self):
        data = payload("Unknown name", query="")
        self.assertEqual(detect_sensitive(data, policy("PERSON"))["errors"], ["local_agent_required"])
        for response in ({}, {"status": "needs_review", "findings": []}, {"status": "ok", "findings": [{"quote": "missing", "category": "PERSON"}]},
                         {"status": "ok", "findings": [{"quote": "name", "category": []}]}, {"status": "ok", "findings": ["oops"]}):
            with self.subTest(response=response):
                result = detect_sensitive(data, policy("PERSON"), agent=lambda **_: response)
                self.assertEqual(result["status"], "needs_review")
        def error(**kwargs):
            raise ValueError("sensitive error text")
        result = detect_sensitive(data, policy("PERSON"), agent=error)
        self.assertEqual(result["errors"], ["local_agent_error"])
        self.assertNotIn("sensitive error text", json.dumps(result))

    def test_agent_outside_policy_is_error_not_clean_empty_result(self):
        data = payload("alice@example.test", query="")
        detected = detect_sensitive(data, policy("PERSON"), agent=lambda **_: {
            "status": "ok", "findings": [{"quote": "alice@example.test", "category": "EMAIL"}]})
        self.assertEqual(detected["status"], "needs_review")
        self.assertEqual(detected["errors"], ["agent_category_outside_policy"])

    def test_long_input_and_reserved_tokens_require_review(self):
        self.assertEqual(detect_sensitive(payload("x" * 6001), policy("PERSON"), mode="rules")["errors"], ["text_exceeds_local_limit"])
        self.assertEqual(detect_sensitive(payload("Pretend [PVT_forged]"), policy(), mode="rules")["errors"], ["reserved_token_in_input"])

    def test_modified_payload_or_detection_cannot_bypass_preparation(self):
        data = payload("Customer: Private Cooperative", query="")
        detected = detect_sensitive(data, policy("CUSTOMER"), mode="rules")
        changed = copy.deepcopy(data)
        changed["memories"][0]["text"] = "Customer: Other Secret"
        result = prepare_private_payload(changed, detected, actor_id="owner", request_id="r1", policy_version="v1", authorizer=yes)
        self.assertEqual(result["error"], "detection_not_valid_for_payload")
        detected["findings"][0]["end"] = 999
        result = prepare_private_payload(data, detected, actor_id="owner", request_id="r1", policy_version="v1", authorizer=yes)
        self.assertEqual(result["error"], "invalid_detection_finding")

    def test_joint_source_dependency_is_not_treated_as_independent_authority(self):
        data = {"query": "", "memories": [{"source_id": "a", "text": "Customer: Same Cooperative"},
                                             {"source_id": "b", "text": "Customer: Same Cooperative"}]}
        prepared = prepare(data, policy("CUSTOMER"))
        self.assertEqual(restore(tokens(prepared)[0], prepared, authorizer=lambda sid, *_: sid == "a")["error"], "restoration_authorization_failed")

    def test_project_label_case_and_numeric_boundaries_next_to_chinese(self):
        data = payload("Project Sequoia uses project bluebird. 联系电话13912345678有效，证件11010519491231002X用于登记，预算262,000 USD已批，另一笔人民币3.5万待批。", query="")
        detected = detect_sensitive(data, policy("PROJECT", "PHONE", "ID", "AMOUNT"), mode="rules")
        self.assertEqual(detected["status"], "ok")
        text = data["memories"][0]["text"]
        values = {(item["category"], text[item["start"]:item["end"]]) for item in detected["findings"]}
        self.assertEqual(values, {("PROJECT", "Sequoia"), ("PROJECT", "bluebird"),
                                  ("PHONE", "13912345678"), ("ID", "11010519491231002X"),
                                  ("AMOUNT", "262,000 USD"), ("AMOUNT", "人民币3.5万")})
        # Numbers embedded in longer ASCII identifiers are not valid short hits.
        embedded = payload("x13912345678y x11010519491231002Xy x262,000 USDy", query="")
        self.assertEqual(detect_sensitive(embedded, policy("PHONE", "ID", "AMOUNT"), mode="rules")["findings"], [])

    def test_independent_combined_channel_and_contained_span_deduplication(self):
        seen = []
        data = payload("Phone +86 13912345678; Amount USD 262,000; Project Sequoia", query="")
        def agent(**kwargs):
            seen.append(kwargs)
            return {"status": "ok", "findings": [{"quote": "13912345678", "category": "PHONE"},
                                                    {"quote": "000", "category": "AMOUNT"}]}
        detected = detect_sensitive(data, policy("PHONE", "AMOUNT", "PROJECT"), agent=agent)
        self.assertEqual(detected["status"], "ok")
        self.assertEqual(detected["strategy"], "independent_union_boundary_propagation_v3")
        self.assertTrue(all(item["rule_findings"] == [] for item in seen))
        text = data["memories"][0]["text"]
        self.assertEqual([(f["category"], text[f["start"]:f["end"]]) for f in detected["findings"]],
                         [("PHONE", "+86 13912345678"), ("AMOUNT", "USD 262,000"), ("PROJECT", "Sequoia")])

    def test_independent_business_registry_masks_query_and_memory_with_authorized_spelling(self):
        p = {**policy("CUSTOMER", "PROJECT"), "entity_registry": [
            {"value": "Cedarcrest Assurance", "category": "CUSTOMER"},
            {"value": "Sequoia-42", "category": "PROJECT"}]}
        data = payload("We signed with Cedarcrest Assurance under Sequoia-42.",
                       query="Does CEDARCREST ASSURANCE sponsor Sequoia-42?")
        detection = detect_sensitive(data, p, mode="rules")
        self.assertEqual(detection["status"], "ok")
        self.assertEqual(len(detection["findings"]), 4)
        self.assertTrue(all(f["method"] == "registry" for f in detection["findings"]))
        prepared = prepare_private_payload(data, detection, actor_id="owner", request_id="r1",
                                           policy_version="v1", authorizer=yes, sensitivity_policy=p)
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("cedarcrest assurance", json.dumps(prepared["payload"]).casefold())
        self.assertNotIn("sequoia-42", json.dumps(prepared["payload"]).casefold())
        self.assertEqual(restore(tokens(prepared)[0], prepared, sensitivity_policy=p)["answer"], "Cedarcrest Assurance")
        # The vocabulary cannot grant rights, and nonprotected categories remain public.
        self.assertEqual(prepare_private_payload(data, detection, actor_id="outsider", request_id="r1",
                         policy_version="v1", authorizer=yes, sensitivity_policy=p)["error"], "memory_authorization_failed")
        self.assertEqual(detect_sensitive(data, {**p, "protected_categories": []}, mode="rules")["findings"], [])

    def test_registry_is_exactly_validated_and_policy_content_bound_even_at_same_version(self):
        p = {**policy("CUSTOMER"), "entity_registry": [{"value": "Cedarcrest Assurance", "category": "CUSTOMER"}]}
        data = payload("Cedarcrest Assurance approved it.", query="")
        detection = detect_sensitive(data, p, mode="rules")
        other = {**p, "entity_registry": [{"value": "Other Office", "category": "CUSTOMER"}]}
        self.assertNotEqual(detection["policy_sha256"], detect_sensitive(data, other, mode="rules")["policy_sha256"])
        self.assertEqual(prepare_private_payload(data, detection, actor_id="owner", request_id="r1",
                         policy_version="v1", authorizer=yes, sensitivity_policy=other)["error"], "detection_policy_mismatch")
        prepared = prepare_private_payload(data, detection, actor_id="owner", request_id="r1",
                                           policy_version="v1", authorizer=yes, sensitivity_policy=p)
        self.assertEqual(restore(tokens(prepared)[0], prepared, sensitivity_policy=other)["error"], "restoration_policy_mismatch")
        self.assertEqual(prepared["metadata"]["policy_sha256"], detection["policy_sha256"])
        for registry in ({"value": "name"}, [{"value": "", "category": "CUSTOMER"}],
                         [{"value": "name", "category": []}], [{"value": "name", "category": "CUSTOMER", "answer": "gold"}]):
            with self.subTest(registry=registry):
                result = detect_sensitive(data, {**p, "entity_registry": registry}, mode="rules")
                self.assertEqual(result["errors"], ["invalid_policy_entity_registry"])

    def test_safe_error_codes_and_repaired_diagnostics_never_echo_raw_text(self):
        data = payload("Unstructured record", query="")
        response = {"status": "needs_review", "findings": [], "errors": ["format_or_span_invalid", "Secret Error Content"],
                    "diagnostics": [{"attempt": 1, "stage": "output", "code": "invalid_span", "raw": "Secret Error Content"},
                                    {"attempt": 2, "stage": "output", "code": "Secret Error Content"}]}
        detected = detect_sensitive(data, policy("PERSON"), agent=lambda **_: response)
        self.assertIn("format_or_span_invalid", detected["errors"])
        self.assertIn("local_agent_unrecognized_error", detected["errors"])
        self.assertNotIn("Secret Error Content", json.dumps(detected))
        self.assertEqual(detected["agent_observations"][0]["diagnostics"][0],
                         {"attempt": 1, "stage": "output", "code": "invalid_span"})
        repaired = detect_sensitive(data, policy("PERSON"), agent=lambda **_: {
            "status": "ok", "findings": [], "errors": [],
            "diagnostics": [{"attempt": 1, "stage": "output", "code": "invalid_span"}]})
        self.assertEqual(repaired["status"], "ok")
        self.assertEqual(repaired["errors"], [])
        self.assertTrue(repaired["agent_observations"][0]["diagnostics"])

    def test_quote_wrapper_repair_telemetry_is_bounded_without_raw_text(self):
        data = payload("Unstructured record", query="")
        for value in (0, 2, 32):
            detected = detect_sensitive(data, policy("PERSON"), agent=lambda **_: {
                "status": "ok", "findings": [], "quote_wrapper_repairs": value})
            self.assertEqual(detected["agent_observations"][0]["quote_wrapper_repairs"], value)
        for value in (-1, 33, True, "Secret Repair Content"):
            detected = detect_sensitive(data, policy("PERSON"), agent=lambda **_: {
                "status": "ok", "findings": [], "quote_wrapper_repairs": value})
            self.assertNotIn("quote_wrapper_repairs", detected["agent_observations"][0])
            self.assertNotIn("Secret Repair Content", json.dumps(detected))

    def test_agent_cannot_mutate_the_bound_sensitivity_policy(self):
        data = payload("Customer: Cedarcrest Assurance", query="")
        p = policy("CUSTOMER")
        def agent(**kwargs):
            kwargs["policy"]["protected_categories"].clear()
            return {"status": "ok", "findings": []}
        detected = detect_sensitive(data, p, agent=agent)
        self.assertEqual(detected["protected_categories"], ["CUSTOMER"])
        self.assertEqual(len(detected["findings"]), 1)
        self.assertEqual(p["protected_categories"], ["CUSTOMER"])

    def test_mapping_binds_original_query_even_when_memory_objects_are_identical(self):
        first = payload("Customer: Cedarcrest Assurance", query="Who is the customer?")
        second = payload("Customer: Cedarcrest Assurance", query="What is the project budget?")
        p = policy("CUSTOMER")
        first_detection = detect_sensitive(first, p, mode="rules")
        second_detection = detect_sensitive(second, p, mode="rules")
        first_prepared, second_prepared = prepare(first, p), prepare(second, p)
        self.assertEqual(first_prepared["mapping"]._memories, second_prepared["mapping"]._memories)
        self.assertEqual(first_prepared["mapping"]._source_payload_sha256, first_detection["payload_sha256"])
        self.assertEqual(second_prepared["mapping"]._source_payload_sha256, second_detection["payload_sha256"])
        self.assertNotEqual(first_prepared["mapping"]._source_payload_sha256, second_prepared["mapping"]._source_payload_sha256)
        self.assertEqual(prepare_private_payload(second, first_detection, actor_id="owner", request_id="r1",
                         policy_version="v1", authorizer=yes, sensitivity_policy=p)["error"], "detection_not_valid_for_payload")

    def test_partial_verified_ascii_entity_closes_without_swallowing_prose(self):
        for category in ("PERSON", "CUSTOMER", "PROJECT", "ADDRESS"):
            with self.subTest(category=category):
                data = payload("NorthAlder_42 is active.", query="")
                def agent(**_):
                    return {"status": "ok", "findings": [{"quote": "Alder", "category": category}]}
                detected = detect_sensitive(data, policy(category), agent=agent, mode="agent")
                self.assertEqual(detected["status"], "ok")
                item, = detected["findings"]
                self.assertEqual(data["memories"][0]["text"][item["start"]:item["end"]], "NorthAlder_42")
                self.assertEqual(item["method"], "agent+boundary")
                self.assertEqual(item["provenance"][0]["start"], 5)
                prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
                    policy_version="v1", authorizer=yes, sensitivity_policy=policy(category))
                self.assertEqual(prepared["status"], "ok")
                self.assertTrue(prepared["payload"]["memories"][0]["text"].endswith(" is active."))
                self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "NorthAlder_42")

    def test_chinese_entity_closure_includes_ascii_code_and_stops_at_chinese_prose(self):
        data = payload("蓝杉Q9_4已获批准。", query="蓝杉Q9_4是否启动？")
        def agent(**kwargs):
            return {"status": "ok", "findings": [{"quote": "蓝杉", "category": "PROJECT"}]
                    if kwargs["source_id"] == "memory-1" else []}
        detected = detect_sensitive(data, policy("PROJECT"), agent=agent, mode="agent")
        sources = {"__query__": data["query"], "memory-1": data["memories"][0]["text"]}
        self.assertEqual([sources[f["source_id"]][f["start"]:f["end"]] for f in detected["findings"]],
                         ["蓝杉Q9_4", "蓝杉Q9_4"])
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(prepared["metadata"]["token_count"], 1)
        self.assertTrue(prepared["payload"]["memories"][0]["text"].endswith("已获批准。"))
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "蓝杉Q9_4")

    def test_detector_propagates_validated_values_across_query_and_memories(self):
        data = {"query": "Is ALICE MOSS attending?", "memories": [
            {"source_id": "a", "text": "Name: Alice Moss"},
            {"source_id": "b", "text": "Alice Moss attended."}]}
        detected = detect_sensitive(data, policy("PERSON"), mode="rules")
        self.assertEqual(detected["status"], "ok")
        by_source = {f["source_id"]: f for f in detected["findings"]}
        self.assertEqual(set(by_source), {"__query__", "a", "b"})
        self.assertEqual(by_source["__query__"]["method"], "propagated")
        self.assertEqual(by_source["__query__"]["provenance"][0]["source_id"], "a")
        self.assertEqual(by_source["b"]["method"], "propagated")
        self.assertEqual(detect_sensitive(data, policy(), mode="rules")["findings"], [])
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["metadata"]["token_count"], 1)
        self.assertEqual(prepared["metadata"]["replacement_count"], 3)
        self.assertEqual(restore(tokens(prepared)[0], prepared, authorizer=lambda sid, *_: sid == "a")["error"],
                         "restoration_authorization_failed")

    def test_chinese_name_with_short_ascii_code_is_not_an_ascii_short_name(self):
        data = payload("项目：蓝杉Q9", query="蓝杉Q94启动了吗？")
        detected = detect_sensitive(data, policy("PROJECT"), mode="rules")
        query_finding, = [f for f in detected["findings"] if f["source_id"] == "__query__"]
        self.assertEqual(data["query"][query_finding["start"]:query_finding["end"]], "蓝杉Q94")
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(prepared["metadata"]["token_count"], 2)
        self.assertEqual(restore(tokens(prepared)[0], prepared)["error"], "query_only_value_has_no_evidence")

    def test_extended_occurrence_has_independent_token_and_source_evidence(self):
        data = {"query": "Compare Alder and Aldermark.", "memories": [
            {"source_id": "a", "text": "Customer: Alder"},
            {"source_id": "b", "text": "Aldermark is active."}]}
        detected = detect_sensitive(data, policy("CUSTOMER"), mode="rules")
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["status"], "ok")
        first = re.search(r"\[PVT_[^\]]+\]", prepared["payload"]["memories"][0]["text"])[0]
        second = re.search(r"\[PVT_[^\]]+\]", prepared["payload"]["memories"][1]["text"])[0]
        self.assertNotEqual(first, second)
        self.assertEqual(restore(first, prepared, authorizer=lambda sid, *_: sid == "a")["answer"], "Alder")
        self.assertEqual(restore(second, prepared, authorizer=lambda sid, *_: sid == "b")["answer"], "Aldermark")
        self.assertEqual(restore(second, prepared, authorizer=lambda sid, *_: sid == "a")["error"],
                         "restoration_authorization_failed")
        query_only = payload("Customer: Alder", query="Who represents Aldermark?")
        only = prepare(query_only, policy("CUSTOMER"))
        token = re.search(r"\[PVT_[^\]]+\]", only["payload"]["query"])[0]
        self.assertEqual(restore(token, only)["error"], "query_only_value_has_no_evidence")

    def test_short_ascii_names_do_not_mask_ordinary_words_or_block_public_literals(self):
        data = payload("Name: A; Status: camera", query="Can camera see A?")
        prepared = prepare(data, policy("PERSON"))
        self.assertEqual(prepared["status"], "ok")
        self.assertTrue(prepared["payload"]["query"].startswith("Can camera see "))
        self.assertIn("Status: camera", prepared["payload"]["memories"][0]["text"])
        self.assertEqual(restore("camera", prepared)["answer"], "camera")
        self.assertEqual(restore("A", prepared)["error"], "raw_protected_value_in_answer")

    def test_propagation_does_not_promote_unverified_interior_substrings_to_names(self):
        data = payload("Customer: Alder", query="Is NorthAldermark active?")
        detected = detect_sensitive(data, policy("CUSTOMER"), mode="rules")
        self.assertEqual({f["source_id"] for f in detected["findings"]}, {"memory-1"})
        # Unknown semantic compounds remain for the independent egress guard to
        # review; this detector cannot assert that the interior match is a name.

    def test_prepare_recloses_trusted_older_partial_findings_before_restoration(self):
        data = payload("Aldermark is active.", query="")
        p = policy("CUSTOMER")
        detected = detect_sensitive(data, p, mode="rules")
        detected["findings"] = [{"source_id": "memory-1", "start": 0, "end": 5,
                                 "category": "CUSTOMER", "policy_id": "v1", "method": "agent"}]
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes, sensitivity_policy=p)
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("mark", prepared["payload"]["memories"][0]["text"])
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "Aldermark")

    def test_email_ascii_boundaries_work_next_to_chinese_labels_and_prose(self):
        data = payload("联系邮箱hana.moss@example.test仅供内部使用。", query="邮箱hana.moss@example.test有效吗？")
        detected = detect_sensitive(data, policy("EMAIL"), mode="rules")
        self.assertEqual(detected["status"], "ok")
        self.assertEqual(len(detected["findings"]), 2)
        prepared = prepare_private_payload(data, detected, actor_id="owner", request_id="r1",
            policy_version="v1", authorizer=yes)
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn("hana.moss", json.dumps(prepared["payload"]))
        self.assertTrue(prepared["payload"]["memories"][0]["text"].endswith("仅供内部使用。"))
        self.assertEqual(restore(tokens(prepared)[0], prepared)["answer"], "hana.moss@example.test")


if __name__ == "__main__":
    unittest.main()
