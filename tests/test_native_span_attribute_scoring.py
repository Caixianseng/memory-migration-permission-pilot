"""Synthetic, offline scoring checks; never load real probe material or models."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import native_span_attribute_scoring as scoring
from scripts import relation_probe_scoring as original
from scripts import run_native_span_attribute_probe as runner
from tests.test_relation_probe_scoring import fixture, policy, response


def native_fixture():
    texts, reference, rows = fixture(12)
    selected = copy.deepcopy([row for row in rows if row["cell"]["arm"] == original.ARMS[0]])
    for row in selected:
        row["cell"]["arm"] = scoring.ARM
    return texts, reference, selected


def replace_row(rows, texts, index, profile, observed, status):
    row = next(row for row in rows if row["cell"] == {
        "text_index": index, "profile": profile, "arm": scoring.ARM})
    row.update(response=observed, status=status,
               preparation=original.prepare_observation(texts[index], policy(profile), observed))
    return row


class NativeSpanAttributeScoringTests(unittest.TestCase):
    def setUp(self):
        # Guard the actual possible entry points, not the old Qwen transport stub.
        self.guards = []
        for target in ("socket.create_connection", "socket.socket.connect",
                       "urllib.request.urlopen", "scripts.run_native_span_attribute_probe.LocalNerRuntime",
                       "memory_migration_study.native_span_attributes.NativeSpanAttributeRuntime"):
            guard = patch(target, side_effect=AssertionError("offline_scoring_must_not_call_" + target))
            self.guards.append(guard.start())
            self.addCleanup(guard.stop)

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def assert_common_metrics_match_original(self, rows, reference, texts):
        result = scoring.score_rows(rows, reference, texts)
        expanded = []
        for row in rows:
            for arm in original.ARMS:
                duplicate = copy.deepcopy(row)
                duplicate["cell"]["arm"] = arm
                expanded.append(duplicate)
        baseline = original.score_rows(expanded, reference, texts)
        for profile in original.PROFILES:
            actual = result["by_profile_arm"][profile + "/" + scoring.ARM]
            expected = baseline["by_profile_arm"][profile + "/" + original.ARMS[0]]
            self.assertLessEqual(set(actual), set(expected))
            self.assertEqual(actual, {name: expected[name] for name in actual})
        by_cell = {(row["cell"]["text_index"], row["cell"]["profile"]): row for row in baseline["scored_rows"]
                   if row["cell"]["arm"] == original.ARMS[0]}
        for row in result["scored_rows"]:
            expected = by_cell[(row["cell"]["text_index"], row["cell"]["profile"])]["score"]
            self.assertLessEqual(set(row["score"]), set(expected))
            self.assertEqual(row["score"], {name: expected[name] for name in row["score"]})
        self.assertEqual(result["reference_object_sha256"], baseline["reference_object_sha256"])
        self.assertEqual(result["new_model_calls"], 0)
        return result

    def test_complete_single_arm_grid_matches_original_public_metrics(self):
        texts, reference, rows = native_fixture()
        result = self.assert_common_metrics_match_original(rows, reference, texts)
        self.assertEqual(result["rows"], 24)
        self.assertEqual(len(result["by_profile_arm"]), 2)
        strict = result["by_profile_arm"][original.PROFILES[0] + "/" + scoring.ARM]
        broad = result["by_profile_arm"][original.PROFILES[1] + "/" + scoring.ARM]
        self.assertEqual((strict["tp"], strict["fp"], strict["fn"]), (10, 0, 0))
        self.assertEqual(strict["determinate_cells"], 11)
        self.assertEqual(strict["unknown_review_matches"], 1)
        self.assertEqual((broad["tp"], broad["fp"], broad["fn"]), (12, 0, 0))

    def test_incomplete_duplicate_and_wrong_grid_reject_before_reference_access(self):
        texts, _, rows = native_fixture()
        class Opaque(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("reference_read_before_complete_prediction_grid")
        variants = [rows[:-1], rows + [copy.deepcopy(rows[0])]]
        duplicate = copy.deepcopy(rows)
        duplicate[-1] = copy.deepcopy(duplicate[0])
        variants.append(duplicate)
        for field, value in (("arm", "other_arm"), ("profile", "unknown_profile"), ("text_index", 12)):
            changed = copy.deepcopy(rows)
            changed[0]["cell"][field] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(cells=len(changed)), self.assertRaisesRegex(ValueError, "incomplete_grid"):
                scoring.score_rows(changed, Opaque(), texts)
        with self.assertRaisesRegex(ValueError, "incomplete_grid"):
            scoring.score_rows(rows, Opaque(), texts[:-1])

    def test_boolean_index_and_extra_cell_field_rejected(self):
        texts, reference, rows = native_fixture()
        for update in ({"text_index": False}, {"unexpected": "metadata"}):
            changed = copy.deepcopy(rows)
            changed[0]["cell"].update(update)
            with self.subTest(update=update), self.assertRaisesRegex(ValueError, "invalid_cell"):
                scoring.score_rows(changed, reference, texts)

    def test_reference_bindings_quotes_and_required_values_are_validated(self):
        texts, reference, rows = native_fixture()
        mutations = (
            lambda ref: ref.update(runtime_sha256="0" * 64),
            lambda ref: ref["profile_contract_sha256"].update({original.PROFILES[0]: "0" * 64}),
            lambda ref: ref["cases"][0].update(text_sha256="0" * 64),
            lambda ref: ref["cases"][0].update(expected=None),
            lambda ref: ref["cases"][0]["expected"][original.PROFILES[0]]["spans"][0].update(text="not from source"),
            lambda ref: ref["cases"][0]["allowed_fact"].update(start=0),
            lambda ref: ref["cases"][0]["expected"][original.PROFILES[0]].update(must_mask_values=[]),
        )
        for number, mutate in enumerate(mutations):
            changed = copy.deepcopy(reference)
            mutate(changed)
            with self.subTest(mutation=number), self.assertRaises(ValueError):
                scoring.score_rows(rows, changed, texts)
        with self.assertRaises(ValueError):
            scoring.score_rows(rows, reference, [texts[0] + "!", *texts[1:]])

    def test_preparation_response_acl_and_no_new_call_bindings_are_validated(self):
        texts, reference, rows = native_fixture()
        mutations = (
            lambda row: row["response"].update(local_calls=99),
            lambda row: row["preparation"]["binding"].update(source_id="wrong-source"),
            lambda row: row["preparation"]["metadata"].update(payload_sha256="0" * 64),
            lambda row: row["preparation"]["detection"].update(policy_sha256="0" * 64),
            lambda row: row["preparation"]["detection"].update(local_calls=1),
            lambda row: row["preparation"]["acl_negative_control"].update(status="not_exercised"),
            lambda row: row["preparation"].update(mapping=None),
            lambda row: row["preparation"].update(new_model_calls=1),
        )
        for number, mutate in enumerate(mutations):
            changed = copy.deepcopy(rows)
            mutate(changed[0])
            with self.subTest(mutation=number), self.assertRaises(ValueError):
                scoring.score_rows(changed, reference, texts)

    def test_blocked_positive_is_missed_and_failure_is_not_correct_unknown_review(self):
        failure_kinds = (("needs_review", "semantic_uncertainty", 1),
                         ("unsupported", "unsupported_category_contract", 0),
                         ("coverage_review", "input_budget_exceeded", 0),
                         ("engineering_error", "local_failure", 0),
                         ("model_output_invalid", "format_or_span_invalid", 1),
                         ("invalid", "invalid_input_or_policy", 0))
        for status, error, calls in failure_kinds:
            with self.subTest(status=status):
                texts, reference, rows = native_fixture()
                profile = original.PROFILES[0]
                for index in (0, 1):
                    # Even a finding in a review response is not a usable positive.
                    name = "Fixture Office 0" if index == 0 and status == "needs_review" else None
                    observed = response(texts[index], name, status="needs_review", errors=[error], calls=calls)
                    replace_row(rows, texts, index, profile, observed, status)
                result = self.assert_common_metrics_match_original(rows, reference, texts)
                group = result["by_profile_arm"][profile + "/" + scoring.ARM]
                self.assertEqual(group["fn"], 1)
                self.assertEqual(group["determinate_exact_matches"], 10)
                self.assertEqual(group["determinate_processable_cells"], 10)
                self.assertEqual(group["required_raw_leak_cells"], 0)
                self.assertEqual(group["acl_not_exercised"], 2)
                self.assertEqual(group["unknown_review_matches"], int(status == "needs_review"))

    def test_review_label_cannot_hide_engineering_failure(self):
        texts, reference, rows = native_fixture()
        replace_row(rows, texts, 0, original.PROFILES[0],
                    response(texts[0], status="needs_review", errors=["local_failure"]), "needs_review")
        with self.assertRaisesRegex(ValueError, "status_response_mismatch"):
            scoring.score_rows(rows, reference, texts)

    def test_missed_raw_value_counts_fn_and_case_insensitive_payload_leak(self):
        texts, reference, rows = native_fixture()
        profile = original.PROFILES[0]
        row = replace_row(rows, texts, 0, profile, response(texts[0]), "ok")
        row["preparation"]["payload"]["memories"][0]["text"] = texts[0].upper()
        row["preparation"]["metadata"]["payload_sha256"] = original._hash(row["preparation"]["payload"])
        result = self.assert_common_metrics_match_original(rows, reference, texts)
        group = result["by_profile_arm"][profile + "/" + scoring.ARM]
        self.assertEqual((group["tp"], group["fp"], group["fn"]), (9, 0, 1))
        self.assertEqual(group["required_raw_leak_cells"], 1)
        self.assertEqual(group["required_raw_leak_rate_all"], 1 / 12)
        self.assertEqual(group["required_raw_leak_rate_sent"], 1 / 11)
        self.assertFalse(result["scored_rows"][0]["score"]["allowed_fact_retained"])

    def test_whole_text_mask_is_not_exact_detection_or_legal_fact_retention(self):
        texts, reference, rows = native_fixture()
        profile = original.PROFILES[0]
        replace_row(rows, texts, 0, profile, response(texts[0], texts[0]), "ok")
        result = self.assert_common_metrics_match_original(rows, reference, texts)
        group = result["by_profile_arm"][profile + "/" + scoring.ARM]
        self.assertEqual((group["tp"], group["fp"], group["fn"]), (9, 1, 1))
        self.assertEqual(group["required_raw_leak_cells"], 0)
        self.assertEqual(group["determinate_allowed_fact_retained_cells"], 10)
        self.assertFalse(result["scored_rows"][0]["score"]["determinate_exact_match"])

    def test_all_blocked_has_no_sent_rate_and_does_not_gain_utility_or_acl_credit(self):
        texts, reference, rows = native_fixture()
        for row in rows:
            index, profile = row["cell"]["text_index"], row["cell"]["profile"]
            replace_row(rows, texts, index, profile,
                        response(texts[index], status="needs_review", errors=["semantic_uncertainty"]), "needs_review")
        result = self.assert_common_metrics_match_original(rows, reference, texts)
        for group in result["by_profile_arm"].values():
            self.assertEqual(group["payload_sent_cells"], 0)
            self.assertIsNone(group["required_raw_leak_rate_sent"])
            self.assertIsNone(group["precision"])
            self.assertEqual(group["recall"], 0.0)
            self.assertEqual(group["required_raw_leak_rate_all"], 0.0)
            self.assertEqual(group["determinate_exact_matches"], 0)
            self.assertEqual(group["determinate_processable_cells"], 0)
            self.assertEqual(group["determinate_allowed_fact_retained_cells"], 0)
            self.assertEqual(group["acl_exercised"], 0)
            self.assertEqual(group["acl_not_exercised"], 12)
        self.assertIn('"required_raw_leak_rate_sent": null', json.dumps(result))

    def test_no_positive_gold_produces_null_precision_and_recall(self):
        texts, reference, rows = native_fixture()
        strict, broad = original.PROFILES
        # Rewrite only this authored fixture into a genuinely all-negative strict set.
        for index, case in enumerate(reference["cases"]):
            name, fact = "Fixture Office " + str(index), case["allowed_fact"]["text"]
            text = name + " has never been our customer. " + fact
            texts[index] = text
            case["text_sha256"] = original._text_hash(text)
            case["allowed_fact"].update(start=text.index(fact), end=text.index(fact) + len(fact))
            case["expected"][strict] = {"decision": "not_sensitive", "spans": [], "must_mask_values": []}
            replace_row(rows, texts, index, strict, response(text), "ok")
            replace_row(rows, texts, index, broad, response(text, name), "ok")
        reference["runtime_sha256"] = original._runtime_hash(texts)
        result = self.assert_common_metrics_match_original(rows, reference, texts)
        group = result["by_profile_arm"][strict + "/" + scoring.ARM]
        self.assertEqual((group["tp"], group["fp"], group["fn"]), (0, 0, 0))
        self.assertIsNone(group["precision"])
        self.assertIsNone(group["recall"])
        self.assertEqual(group["determinate_exact_matches"], 12)

    def test_inputs_are_unchanged_and_results_do_not_alias_them(self):
        texts, reference, rows = native_fixture()
        before = copy.deepcopy((texts, reference, rows))
        result = scoring.score_rows(rows, reference, texts)
        self.assertEqual((texts, reference, rows), before)
        result["scored_rows"][0]["response"]["findings"].clear()
        result["scored_rows"][0]["preparation"]["payload"]["memories"][0]["text"] = "changed output"
        self.assertEqual((texts, reference, rows), before)

    def test_scoring_needs_no_file_access(self):
        texts, reference, rows = native_fixture()
        with patch("builtins.open", side_effect=AssertionError("file_access_forbidden")) as opened, \
             patch.object(Path, "read_text", side_effect=AssertionError("file_access_forbidden")) as read_text, \
             patch.object(Path, "read_bytes", side_effect=AssertionError("file_access_forbidden")) as read_bytes:
            result = scoring.score_rows(rows, reference, texts)
        self.assertEqual(result["new_model_calls"], 0)
        opened.assert_not_called()
        read_text.assert_not_called()
        read_bytes.assert_not_called()

    def test_nested_counts_require_exact_integer_entries_and_consistent_bounds(self):
        zero = {name: 0 for name in runner.native.COUNTERS}
        runner.verify_counts(zero, completed=0, nonempty=0)
        valid = {"extract_invocations": 12, "encoder_forward_entries": 12,
                 "attribute_attach_entries": 12, "explicit_span_score_entries": 9}
        runner.verify_counts(valid, completed=12, nonempty=9)
        runner.verify_counts(valid, completed=12)
        for change in ({"extract_invocations": 11}, {"encoder_forward_entries": 11},
                       {"attribute_attach_entries": 11}, {"explicit_span_score_entries": 13},
                       {"explicit_span_score_entries": -1}, {"encoder_forward_entries": True},
                       {"unexpected_entry": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.verify_counts({**valid, **change}, completed=12)
        missing = dict(valid)
        missing.pop("explicit_span_score_entries")
        with self.assertRaises(ValueError):
            runner.verify_counts(missing, completed=12)
        with self.assertRaises(ValueError):
            runner.verify_counts(valid, completed=12, nonempty=8)


if __name__ == "__main__":
    unittest.main()
