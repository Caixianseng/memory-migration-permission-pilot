import unittest
import copy
import json
import re
from types import SimpleNamespace

from memory_migration_study import privacy as privacy_core, privacy_egress
from memory_migration_study.privacy_corpus import _digest, validate_corpus
from memory_migration_study.privacy_payload_eval import evaluate_prepared_payloads, masking_intervals


class MaskTraceTests(unittest.TestCase):
    def test_repeated_values_and_case_variants_align_actual_coverage(self):
        token = "[PVT_" + "A" * 24 + "_PERSON_1]"
        source = "Arden met ARDEN in the room."
        masked = token + " met " + token + " in the room."
        spans = masking_intervals(source, masked, {token: SimpleNamespace(value="Arden")})
        self.assertEqual(spans, [(0, 5), (10, 15)])

    def test_partial_suffix_is_left_uncovered(self):
        token = "[PVT_" + "A" * 24 + "_PROJECT_1]"
        self.assertEqual(masking_intervals("Orchidmark", token + "mark", {token: SimpleNamespace(value="Orchid")}), [(0, 6)])

    def test_unknown_tokens_or_modified_plaintext_cannot_score_as_safe(self):
        token = "[PVT_" + "A" * 24 + "_PROJECT_1]"
        with self.assertRaisesRegex(ValueError, "unknown_token"):
            masking_intervals("Orchid", token, {})
        with self.assertRaisesRegex(ValueError, "unaligned"):
            masking_intervals("Orchid is ready", "Changed " + token, {token: SimpleNamespace(value="Orchid")})


class PreparedPayloadScoringTests(unittest.TestCase):
    @staticmethod
    def make_case(case_id, text, query="", categories=("CUSTOMER",)):
        return {"case_id": case_id, "language": "en", "split": "dev",
                "story_id": case_id, "template_family": case_id,
                "payload": {"query": query, "memories": [{"source_id": case_id + "-m0", "text": text}]},
                "sensitivity_policy": {"version": "instrument-test-v1", "protected_categories": list(categories)}}

    @staticmethod
    def spans_for(case, value, category):
        texts = {"__query__": case["payload"]["query"],
                 **{m["source_id"]: m["text"] for m in case["payload"]["memories"]}}
        spans = []
        for source_id, text in texts.items():
            offset = 0
            while (start := text.lower().find(value.lower(), offset)) >= 0:
                spans.append({"source_id": source_id, "start": start, "end": start + len(value), "category": category})
                offset = start + len(value)
        return spans

    @staticmethod
    def rules_cache(cases):
        entries = {}
        for case in cases:
            source, policy = case["payload"], case["sensitivity_policy"]
            # No detector inference is added by scoring: a rules-only result is
            # deliberately put under the same cache key used by combined runs.
            detected = privacy_core.detect_sensitive(source, policy, mode="rules")
            key = _digest({"case_id": case["case_id"], "payload": source, "policy": policy, "mode": "combined"})
            entries[key] = {"result": detected}
        return {"entries": entries}

    def test_real_preparation_propagates_query_values_and_keeps_review_in_denominator(self):
        ready = self.make_case("ready", "Customer: Acacia Ledger Union; Status: active.",
                               "Does ACACIA LEDGER UNION mean Acacia Ledger Union?")
        blocked = self.make_case("review", "Name: Zelda Vale; [PVT_forged]", categories=("PERSON",))
        runtime = {"schema_version": 1, "cases": [ready, blocked]}
        evaluation = {"runtime_sha256": _digest(runtime), "cases": [
            {"case_id": "ready", "findings": self.spans_for(ready, "Acacia Ledger Union", "CUSTOMER")},
            {"case_id": "review", "findings": self.spans_for(blocked, "Zelda Vale", "PERSON")},
        ]}
        cache = self.rules_cache(runtime["cases"])
        self.assertEqual({item["result"]["status"] for item in cache["entries"].values()}, {"ok", "needs_review"})
        captured = {}

        def checked_prepare(source, detected, **kwargs):
            # Evaluation labels, answers and evaluation metadata never become
            # arguments to core preparation, even though the scorer holds them.
            self.assertEqual(set(source), {"query", "memories"})
            self.assertEqual(set(kwargs), {"actor_id", "request_id", "policy_version", "sensitivity_policy", "authorizer"})
            self.assertEqual(set(kwargs["sensitivity_policy"]), {"version", "protected_categories"})
            case_id = source["memories"][0]["source_id"].removesuffix("-m0")
            prepared = privacy_core.prepare_private_payload(source, detected, **kwargs)
            captured.setdefault(case_id, []).append({"status": prepared["status"], "payload": copy.deepcopy(prepared["payload"])})
            return prepared

        def checked_egress(source, prepared, detected, policy):
            self.assertEqual(set(source), {"query", "memories"})
            self.assertEqual(set(policy), {"version", "protected_categories"})
            self.assertNotIn("evaluation", prepared)
            self.assertNotIn("evaluation", detected)
            self.assertNotIn("expected_answer", detected)
            return privacy_egress.validate_outbound(source, prepared, detected, policy)

        modules = {"privacy_module": SimpleNamespace(prepare_private_payload=checked_prepare),
                   "egress_module": SimpleNamespace(validate_outbound=checked_egress)}
        report = evaluate_prepared_payloads(runtime, evaluation, cache, **modules)
        rows = {row["case_id"]: row for row in report["rows"]}
        self.assertEqual(rows["ready"]["status"], "ready")
        self.assertEqual(rows["ready"]["complete_masked_spans"], 3)
        self.assertEqual(rows["ready"]["partial_masked_spans"], 0)
        self.assertEqual(rows["ready"]["unmasked_spans"], 0)
        self.assertTrue(rows["ready"]["all_sensitive_spans_masked"])
        outbound = json.dumps(captured["ready"][0]["payload"]).lower()
        self.assertNotIn("acacia ledger union", outbound)
        self.assertEqual(outbound.count("[pvt_"), 3)
        self.assertEqual(rows["review"]["status"], "blocked")
        self.assertIsNone(rows["review"]["all_sensitive_spans_masked"])
        self.assertIsNone(rows["review"]["complete_masked_spans"])
        summary = next(s for s in report["summaries"] if s["split"] == "all")
        self.assertEqual((summary["registered_cases"], summary["ready_cases"], summary["blocked_cases"]), (2, 1, 1))
        self.assertEqual(summary["ready_gold_spans"], 3)
        self.assertEqual(report["remote_model_calls"], 0)
        self.assertEqual(report["additional_detector_calls"], 0)
        self.assertFalse(report["mapping_persisted"])

        # Deliberately alter scorer labels, leaving the runtime and cached
        # detection untouched. Only scores may change, never masking behavior.
        alternative_gold = copy.deepcopy(evaluation)
        alternative_gold["cases"][0]["findings"].pop(0)
        validate_corpus(runtime, alternative_gold)
        changed_report = evaluate_prepared_payloads(runtime, alternative_gold, cache, **modules)
        self.assertEqual(changed_report["rows"][0]["complete_masked_spans"], 2)

        def normalized_payload(payload):
            if payload is None:
                return None
            def normalize(text):
                return re.sub(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]", "[OPAQUE]", text)
            return {"query": normalize(payload["query"]),
                    "memory_texts": [normalize(m["text"]) for m in payload["memories"]]}

        for case_id in ("ready", "review"):
            self.assertEqual(len(captured[case_id]), 2)
            first, second = captured[case_id]
            self.assertEqual(first["status"], second["status"])
            self.assertEqual(normalized_payload(first["payload"]), normalized_payload(second["payload"]))

    def test_deliberately_incomplete_preparation_scores_partial_even_if_fake_egress_allows_it(self):
        case = self.make_case("partial", "Project: Bramble-R2.", categories=("PROJECT",))
        runtime = {"schema_version": 1, "cases": [case]}
        evaluation = {"runtime_sha256": _digest(runtime), "cases": [
            {"case_id": "partial", "findings": self.spans_for(case, "Bramble-R2", "PROJECT")}]}
        cache = self.rules_cache([case])
        token = "[PVT_" + "B" * 24 + "_PROJECT_1]"
        faulty_preparation = {"status": "ok", "error": None,
            "payload": {"query": "", "memories": [{"source_id": "opaque", "text": "Project: " + token + "-R2."}]},
            "mapping": SimpleNamespace(_entries={token: SimpleNamespace(value="Bramble")})}
        # This bypass is confined to an instrumentation test. It makes no claim
        # that production preparation or outbound validation permits this text.
        fake_privacy = SimpleNamespace(prepare_private_payload=lambda *args, **kwargs: faulty_preparation)
        fake_egress = SimpleNamespace(validate_outbound=lambda *args: {"status": "ok", "code": None})
        report = evaluate_prepared_payloads(runtime, evaluation, cache, privacy_module=fake_privacy, egress_module=fake_egress)
        row = report["rows"][0]
        self.assertEqual(row["status"], "ready")
        self.assertEqual((row["complete_masked_spans"], row["partial_masked_spans"], row["unmasked_spans"]), (0, 1, 0))
        self.assertFalse(row["all_sensitive_spans_masked"])
        summary = next(s for s in report["summaries"] if s["split"] == "all")
        self.assertEqual(summary["ready_cases_with_incomplete_masking"], 1)
        self.assertEqual(summary["partial_masked_spans"], 1)
        self.assertEqual(summary["complete_masked_spans"], 0)
        self.assertIsNone(faulty_preparation["mapping"])


if __name__ == "__main__":
    unittest.main()
