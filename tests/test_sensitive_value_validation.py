import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import privacy as original
from memory_migration_study import value_validation as validation
from scripts.validate_sensitive_payload import run as run_cli


# Fictitious region, no name/person binding. Independently fixed check vector:
# MOD11-2 remainder 2 maps to X; 2000-02-29 is a Gregorian leap day.
SYNTHETIC_VALID = "99000020000229001X"


def synthetic_cn18(birthday):
    # Test-side power-of-two formula, independent of the implementation's
    # explicit weight table and remainder-character lookup.
    first = "990000"+birthday+"001"
    remainder = sum(int(digit)*pow(2, 17-index, 11) for index, digit in enumerate(first)) % 11
    check = (12-remainder) % 11
    return first+("X" if check == 10 else str(check))


class SensitiveValueValidationTests(unittest.TestCase):
    def policy(self, *categories):
        return {"version": "validation-test", "protected_categories": list(categories)}

    def payload(self, value, *, in_query=False):
        return {"query": "证件号："+value if in_query else "", "memories": [] if in_query else
                [{"source_id": "memory", "text": "证件号："+value+"；状态：已核验。"}]}

    def test_fixed_fictitious_checksum_vector_and_lowercase_x(self):
        self.assertEqual(synthetic_cn18("20000229"), SYNTHETIC_VALID)
        for value in (SYNTHETIC_VALID, SYNTHETIC_VALID.lower()):
            self.assertEqual(validation.validate_value(value, "ID"),
                             {"format": "valid", "checksum": "valid", "calendar": "valid"})

    def test_bad_checksum_is_separate_from_format_and_birthday(self):
        checked = validation.validate_value(SYNTHETIC_VALID[:-1]+"0", "ID")
        self.assertEqual(checked, {"format": "valid", "checksum": "invalid", "calendar": "valid"})

    def test_impossible_birthday_leap_day_and_month_do_not_change_checksum_result(self):
        for birthday in ("20230229", "19000229", "20261301", "20260431", "00000101"):
            checked = validation.validate_value(synthetic_cn18(birthday), "ID")
            self.assertEqual(checked["checksum"], "valid")
            self.assertEqual(checked["calendar"], "invalid", birthday)
        self.assertEqual(validation.validate_value(synthetic_cn18("20000229"), "ID")["calendar"], "valid")

    def test_other_document_systems_are_unchecked_not_declared_invalid_cn18(self):
        for value in ("A1234567", "123456789012345", "123-45-6789", "not-an-id"):
            self.assertEqual(validation.validate_value(value, "ID"),
                             {"format": "unchecked", "checksum": "unchecked", "calendar": "unchecked"})

    def test_numeric_chinese_and_english_dates_use_gregorian_calendar(self):
        valid = ("2000-02-29", "2024/2/29", "2024年2月29日", "February 29, 2024", "february 29 2024")
        invalid = ("1900-02-29", "2023年2月29日", "2026-13-01", "April 31, 2026", "2026年0月1日")
        for value in valid:
            self.assertEqual(validation.validate_value(value, "DATE"),
                             {"format": "valid", "checksum": "not_applicable", "calendar": "valid"}, value)
        for value in invalid:
            self.assertEqual(validation.validate_value(value, "DATE")["calendar"], "invalid", value)
        self.assertEqual(validation.validate_value("next week", "DATE")["calendar"], "unchecked")

    def test_email_is_offline_supported_syntax_not_dns_or_delivery(self):
        self.assertEqual(validation.validate_value("a.b+tag@example.test", "EMAIL")["format"], "valid")
        for value in (".a@example.test", "a..b@example.test", "a@-example.test", "a@example-.test", "a@@example.test"):
            self.assertEqual(validation.validate_value(value, "EMAIL")["format"], "invalid", value)
        for value in ('"a b"@example.test', "a@localhost", "用户@example.test"):
            self.assertEqual(validation.validate_value(value, "EMAIL")["format"], "unchecked", value)

    def test_phone_is_offline_shape_not_carrier_or_ownership(self):
        for value in ("13900001001", "+1 (202) 555-0123", "+86 13900001001"):
            self.assertEqual(validation.validate_value(value, "PHONE")["format"], "valid", value)
        for value in ("call-me", "123", "(202 555-0123", "202) 555-0123("):
            self.assertEqual(validation.validate_value(value, "PHONE")["format"], "invalid", value)

    def test_unsupported_categories_or_input_types_never_receive_a_fake_valid_status(self):
        self.assertEqual(validation.validate_value("Some Company", "CUSTOMER"),
                         {"format": "not_applicable", "checksum": "not_applicable", "calendar": "not_applicable"})
        for value, category in ((None, "ID"), ("anything", "UNKNOWN"), ("anything", None)):
            self.assertEqual(validation.validate_value(value, category),
                             {"format": "unchecked", "checksum": "unchecked", "calendar": "unchecked"})

    def test_wrapper_delegates_and_postprocessing_does_not_mutate_inputs_or_original_result(self):
        payload, policy = self.payload(SYNTHETIC_VALID), self.policy("ID")
        baseline = original.detect_sensitive(payload, policy, mode="rules")
        saved = copy.deepcopy((payload, policy, baseline))
        with patch.object(validation._core, "detect_sensitive", return_value=baseline) as delegated:
            result = validation.detect_sensitive(payload, policy, mode="rules")
        delegated.assert_called_once_with(payload, policy, mode="rules", agent=None)
        self.assertEqual((payload, policy, baseline), saved)
        self.assertEqual({k: result[k] for k in baseline}, baseline)
        self.assertIsNot(result["findings"], baseline["findings"])
        self.assertEqual(result["validation_annotations"][0]["checksum"], "valid")
        result["findings"][0]["start"] = 0
        self.assertEqual((payload, policy, baseline), saved)

    def test_invalid_sensitive_value_still_masks_and_only_authorized_scope_restores(self):
        invalid = SYNTHETIC_VALID[:-1]+"0"
        payload, policy = self.payload(invalid), self.policy("ID")
        detected = validation.detect_sensitive(payload, policy, mode="rules")
        self.assertEqual(detected["status"], "ok")
        self.assertEqual(detected["validation_annotations"][0]["checksum"], "invalid")
        authorize = lambda source, actor, version: source == "memory" and actor == "owner" and version == policy["version"]
        prepared = original.prepare_private_payload(payload, detected, actor_id="owner", request_id="request",
            policy_version=policy["version"], authorizer=authorize)
        self.assertEqual(prepared["status"], "ok")
        self.assertNotIn(invalid, json.dumps(prepared["payload"]))
        token = re.search(r"\[PVT_[^\]]+\]", prepared["payload"]["memories"][0]["text"])[0]
        restored = original.restore_answer(token, prepared["mapping"], actor_id="owner", request_id="request",
            policy_version=policy["version"], authorizer=authorize)
        self.assertEqual(restored["answer"], invalid)
        denied = original.restore_answer(token, prepared["mapping"], actor_id="outsider", request_id="request",
            policy_version=policy["version"], authorizer=authorize)
        self.assertEqual(denied["status"], "blocked")

    def test_annotations_contain_only_references_and_fixed_states_not_raw_values(self):
        result = validation.detect_sensitive(self.payload(SYNTHETIC_VALID), self.policy("ID"), mode="rules")
        encoded = json.dumps(result["validation_annotations"])
        self.assertNotIn(SYNTHETIC_VALID, encoded)
        self.assertNotIn("20000229", encoded)
        self.assertNotIn('"quote"', encoded)
        self.assertNotIn('"mapping"', encoded)
        self.assertEqual(set(result["validation_annotations"][0]),
                         {"source_id", "start", "end", "category", "status", "validation_error", "format", "checksum", "calendar"})

    def test_query_source_is_annotated_without_creating_memory_evidence(self):
        payload, policy = self.payload(SYNTHETIC_VALID, in_query=True), self.policy("ID")
        result = validation.detect_sensitive(payload, policy, mode="rules")
        self.assertEqual(result["validation_annotations"][0]["source_id"], "__query__")
        self.assertEqual(result["validation_annotations"][0]["checksum"], "valid")
        self.assertEqual(payload["memories"], [])
        public = validation.detect_sensitive(payload, self.policy(), mode="rules")
        self.assertEqual(public["findings"], [])
        self.assertEqual(public["validation_annotations"], [])

    def test_unknown_source_bad_offsets_and_extra_fields_are_explicit_annotation_errors(self):
        payload, policy = self.payload(SYNTHETIC_VALID), self.policy("ID")
        baseline = original.detect_sensitive(payload, policy, mode="rules")
        cases = (({"source_id": "missing"}, "unknown_source"), ({"start": True}, "invalid_finding"),
                 ({"end": 999}, "invalid_location"), ({"start": -1}, "invalid_location"),
                 ({"secret": SYNTHETIC_VALID}, "invalid_finding"))
        for changes, error in cases:
            detection = copy.deepcopy(baseline)
            detection["findings"][0].update(changes)
            saved = copy.deepcopy(detection)
            result = validation.annotate_detection(payload, detection)
            annotation = result["validation_annotations"][0]
            self.assertEqual(annotation["validation_error"], error)
            self.assertEqual(annotation["status"], "validation_error")
            self.assertTrue(all(annotation[k] == "unchecked" for k in ("format", "checksum", "calendar")))
            self.assertEqual(detection, saved)
            self.assertEqual(result["status"], baseline["status"])
            self.assertEqual(result["findings"], detection["findings"])
            self.assertNotIn(SYNTHETIC_VALID, json.dumps(result["validation_annotations"]))

    def test_payload_binding_and_protected_category_scope_are_required(self):
        payload, policy = self.payload(SYNTHETIC_VALID), self.policy("ID")
        baseline = original.detect_sensitive(payload, policy, mode="rules")
        changed = copy.deepcopy(payload)
        changed["memories"][0]["text"] += " changed"
        self.assertEqual(validation.annotate_detection(changed, baseline)["validation_annotations"][0]["validation_error"], "payload_binding_mismatch")
        for changes, error in (({"protected_categories": []}, "category_outside_policy"),
                               ({"protected_categories": None}, "policy_scope_unavailable"),
                               ({"payload_sha256": None}, "payload_binding_unavailable")):
            detected = dict(baseline, **changes)
            self.assertEqual(validation.annotate_detection(payload, detected)["validation_annotations"][0]["validation_error"], error)

    def test_malformed_container_or_payload_preserves_original_detection_and_reports_error(self):
        payload = self.payload(SYNTHETIC_VALID)
        baseline = original.detect_sensitive(payload, self.policy("ID"), mode="rules")
        malformed = dict(baseline, findings={"not": "a-list"})
        result = validation.annotate_detection(payload, malformed)
        self.assertEqual(result["findings"], malformed["findings"])
        self.assertEqual(result["validation_annotations"][0]["validation_error"], "invalid_finding")
        result = validation.annotate_detection({"query": "missing memories"}, baseline)
        self.assertEqual(result["status"], baseline["status"])
        self.assertEqual(result["findings"], baseline["findings"])
        self.assertEqual(result["validation_annotations"][0]["validation_error"], "invalid_payload")
        with self.assertRaises(ValueError):
            validation.annotate_detection(payload, [])

    def test_rules_cli_uses_no_model_and_preserves_protected_invalid_candidate(self):
        invalid = SYNTHETIC_VALID[:-1]+"0"
        content = {"payload": self.payload(invalid), "policy": self.policy("ID")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"input.json", root/"output.json"
            source.write_text(json.dumps(content), encoding="utf-8")
            with patch("memory_migration_study.local_detector.LocalSensitivityAgent", side_effect=AssertionError("no model allowed")):
                result = run_cli(source, output)
            self.assertEqual(result["local_calls"], 0)
            self.assertEqual(result["validation_annotations"][0]["checksum"], "invalid")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
            self.assertEqual(json.loads(source.read_text(encoding="utf-8")), content)
            with self.assertRaises(ValueError):
                run_cli(source, output)
            with self.assertRaises(ValueError):
                run_cli(source, source)

    def test_optional_cli_agent_is_explicit_local_detector_and_rejects_extra_input_fields(self):
        content = {"payload": self.payload(SYNTHETIC_VALID), "policy": self.policy("ID")}
        seen = []
        def fake_local(**kwargs):
            seen.append(kwargs)
            return {"status": "ok", "findings": [], "errors": [], "local_calls": 1, "elapsed_seconds": 0.0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, config = root/"input.json", root/"output.json", root/"config.json"
            source.write_text(json.dumps(content), encoding="utf-8")
            config.write_text("{}", encoding="utf-8")
            with patch("memory_migration_study.local_detector.LocalSensitivityAgent", return_value=fake_local) as local:
                result = run_cli(source, output, with_local_agent=True, detector_config=config)
            local.assert_called_once_with({})
            self.assertEqual(result["local_calls"], 1)
            self.assertEqual(len(seen), 1)
            self.assertEqual(set(seen[0]), {"text", "source_id", "policy", "rule_findings"})
            source.write_text(json.dumps(dict(content, evaluation="never model input")), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_cli(source, root/"new-output.json")


if __name__ == "__main__":
    unittest.main()
