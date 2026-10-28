"""Restricted request serialization contracts; synthetic inputs, zero models."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import candidate_context_batch as legacy
from memory_migration_study import candidate_context_batch_v2 as module
from memory_migration_study import relation_occurrence as occurrence


def make_pool(text, spans):
    candidates = [{"cid": f"C{i}", "text": quote, "start": start, "end": start + len(quote)}
                  for i, (quote, start) in enumerate(spans)]
    raw = [{"text": c["text"], "start": c["start"], "end": c["end"], "confidence": .8}
           for c in candidates]
    over = len(candidates) > occurrence.MAX_CANDIDATES
    return occurrence._seal({"version": occurrence.VERSION,
        "status": "needs_review" if over else "ok", "error_kind": "coverage" if over else None,
        "errors": ["candidate_limit_exceeded"] if over else [],
        "text_sha256": occurrence._text_hash(text), "generator_identity": {"fixture": "synthetic-ner"},
        "candidate_count": len(candidates), "candidates": candidates,
        "inference_counts": occurrence._counts(proposal_infer_invocations=1),
        "raw_result": {"entities": {"organization": raw}}}, "pool_sha256")


def reorder_objects(value):
    if type(value) is dict:
        return {key: reorder_objects(value[key]) for key in reversed(tuple(value))}
    if type(value) is list:
        return [reorder_objects(item) for item in value]
    return value


class CandidateContextV2Tests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            mock = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mock.assert_not_called)
        self.text = "Moss is a word. Moss buys from us."
        self.pool = make_pool(self.text, [("Moss", self.text.rindex("Moss")), ("Moss", 0)])

    def raw(self, labels=("current_customer", "not_specific_name")):
        return {"candidates": [{"cid": c["cid"], "label": label}
                               for c, label in zip(self.pool["candidates"], labels)]}

    def test_sorted_file_roundtrip_has_identical_actual_messages_and_request_hash(self):
        roundtrip = json.loads(json.dumps(self.pool, ensure_ascii=False, sort_keys=True))
        self.assertEqual(self.pool, roundtrip)
        for mode in module.MODES:
            before = module.build_request(self.text, self.pool, mode=mode)
            after = module.build_request(self.text, roundtrip, mode=mode)
            self.assertEqual(before, after)

    def test_recursive_reversed_object_insertion_order_is_irrelevant(self):
        reversed_pool = reorder_objects(self.pool)
        for mode in module.MODES:
            self.assertEqual(module.build_request(self.text, self.pool, mode=mode),
                             module.build_request(self.text, reversed_pool, mode=mode))

    def test_candidate_list_ids_and_non_source_order_are_retained(self):
        request = module.build_request(self.text, self.pool)
        content = json.loads(request["messages"][1]["content"])
        self.assertEqual(content["candidates"], self.pool["candidates"])
        self.assertGreater(content["candidates"][0]["start"], content["candidates"][1]["start"])

    def test_exact_unicode_whitespace_quotes_and_symbols_are_not_normalized(self):
        text = '😀苔藓\n苔藓\t"ｅ\u0301≠e\u0301"。'
        pool = make_pool(text, [("苔藓", text.rindex("苔藓")), ("苔藓", 1)])
        for mode in module.MODES:
            request = module.build_request(text, pool, mode=mode)
            content = json.loads(request["messages"][1]["content"])
            self.assertEqual(content["candidates"], pool["candidates"])
            actual = content["text"]
            self.assertEqual(actual if mode == "plain" else legacy.strip_markers(actual, text, pool), text)

    def test_legacy_builder_and_spec_stay_legacy_and_show_original_order_dependence(self):
        roundtrip = json.loads(json.dumps(self.pool, sort_keys=True))
        first, second = (legacy.build_request(self.text, p) for p in (self.pool, roundtrip))
        self.assertNotEqual(first["messages"], second["messages"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        self.assertEqual(first["version"], "candidate_context_batch_v1")
        self.assertEqual(legacy.compiled_spec()["version"], "candidate_context_batch_v1")
        self.assertNotIn("serialization_version", first)

    def test_v2_has_separate_version_spec_and_digest_without_modifying_source_pool(self):
        before = deepcopy(self.pool)
        old, new = legacy.build_request(self.text, self.pool), module.build_request(self.text, self.pool)
        self.assertEqual(self.pool, before)
        self.assertEqual(new["version"], module.VERSION)
        self.assertEqual(new["serialization_version"], module.SERIALIZATION_VERSION)
        self.assertNotEqual(new["spec_sha256"], old["spec_sha256"])
        self.assertNotEqual(new["request_sha256"], old["request_sha256"])
        self.assertEqual(new["spec_sha256"], legacy._digest(module.compiled_spec()))
        self.assertEqual(new["request_sha256"], legacy._digest(
            {k: v for k, v in new.items() if k != "request_sha256"}))

    def test_preflight_system_policy_schema_and_exact_budget_are_unchanged(self):
        for mode in module.MODES:
            old, new = legacy.build_request(self.text, self.pool, mode=mode), module.build_request(self.text, self.pool, mode=mode)
            self.assertEqual(new["preflight"], old["preflight"])
            self.assertEqual(new["qualification"], old["qualification"])
            self.assertEqual(new["schema"], old["schema"])
            self.assertEqual(new["messages"][0], old["messages"][0])
            self.assertEqual(json.loads(new["messages"][1]["content"]), json.loads(old["messages"][1]["content"]))

    def test_decode_binds_v2_request_but_preserves_actual_decisions_and_offsets(self):
        for mode in module.MODES:
            old = legacy.decode_response(self.text, self.pool, self.raw(), mode=mode)
            new = module.decode_response(self.text, self.pool, self.raw(), mode=mode,
                                         request=module.build_request(self.text, self.pool, mode=mode))
            self.assertEqual(new["findings"], old["findings"])
            self.assertEqual(new["candidate_decisions"], old["candidate_decisions"])
            self.assertEqual(new["findings"][0]["start"], self.text.rindex("Moss"))
            self.assertEqual(new["request_sha256"], module.build_request(self.text, self.pool, mode=mode)["request_sha256"])
            self.assertNotEqual(new["request_sha256"], old["request_sha256"])
            self.assertEqual(new["request_version"], module.VERSION)

    def test_unknown_remains_review_and_error_denominators_are_not_repaired(self):
        result = module.decode_response(self.text, self.pool, self.raw(("organization_unknown_relation", "not_specific_name")),
                                        request=module.build_request(self.text, self.pool))
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["errors"], ["semantic_uncertainty"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["local_calls"], 0)

    def test_candidate_tamper_and_list_reordering_are_not_hidden_by_serialization(self):
        for action in ("tamper", "reorder"):
            changed = deepcopy(self.pool)
            if action == "tamper":
                changed["candidates"][0]["start"] = 0
            else:
                changed["candidates"].reverse()
            with self.subTest(action=action), self.assertRaises(module.CandidateContextError):
                module.build_request(self.text, changed)

    def test_over_budget_request_stays_unfit_and_cannot_be_decoded(self):
        text = "Moss " + "x" * 2900
        pool = make_pool(text, [("Moss", 0)])
        self.assertFalse(module.build_request(text, pool)["preflight"]["fits"])
        raw = {"candidates": [{"cid": "C0", "label": "current_customer"}]}
        with self.assertRaisesRegex(module.CandidateContextError, "request_context_budget_exceeded"):
            module.decode_response(text, pool, raw, request=module.build_request(text, pool))

    def test_decode_rejects_v1_and_changed_v2_request_spec_or_hash(self):
        with self.assertRaisesRegex(module.CandidateContextError, "request_version_mismatch"):
            module.decode_response(self.text, self.pool, self.raw(),
                                   request=legacy.build_request(self.text, self.pool))
        request = module.build_request(self.text, self.pool)
        for field in ("spec_sha256", "request_sha256", "mode", "serialization_version"):
            changed = deepcopy(request)
            changed[field] = "CHANGED"
            with self.subTest(field=field), self.assertRaisesRegex(module.CandidateContextError, "request_contract_mismatch"):
                module.decode_response(self.text, self.pool, self.raw(), request=changed)

    def test_nonfinite_values_rejected_and_source_changes_affect_digest(self):
        for nonfinite in (float("nan"), float("inf"), float("-inf")):
            changed = deepcopy(self.pool)
            changed["generator_identity"]["value"] = nonfinite
            with self.subTest(nonfinite=nonfinite), self.assertRaises(ValueError):
                module.build_request(self.text, changed)
        changed_text = self.text + " Never normalize this."
        changed_pool = make_pool(changed_text, [("Moss", changed_text.rindex("Moss")), ("Moss", 0)])
        self.assertNotEqual(module.build_request(self.text, self.pool)["request_sha256"],
                            module.build_request(changed_text, changed_pool)["request_sha256"])

    def test_decode_rejects_loose_numeric_equality_with_unchanged_recorded_hash(self):
        expected = module.build_request(self.text, self.pool)
        for container, key, value in (("preflight", "num_ctx", 4096.0),
                                      ("preflight", "fits", 1),
                                      ("qualification", "candidate_count", 2.0)):
            changed = deepcopy(expected)
            changed[container][key] = value
            self.assertEqual(changed, expected)
            with self.subTest(container=container, key=key), self.assertRaisesRegex(
                    module.CandidateContextError, "request_contract_mismatch"):
                module.decode_response(self.text, self.pool, self.raw(), request=changed)

    def test_decode_rejects_nonfinite_or_unserializable_retained_request(self):
        for value in (float("nan"), float("inf"), float("-inf"), object()):
            changed = module.build_request(self.text, self.pool)
            changed["preflight"]["num_ctx"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                    module.CandidateContextError, "request_contract_mismatch"):
                module.decode_response(self.text, self.pool, self.raw(), request=changed)

    def test_overlapping_or_marker_collision_inputs_keep_v1_eligibility(self):
        for text, spans in (("Moss Cooperative", [("Moss", 0), ("Moss Cooperative", 0)]),
                            ("Moss [[CANDIDATE:C0]]", [("Moss", 0)])):
            pool = make_pool(text, spans)
            for mode in module.MODES:
                with self.subTest(text=text, mode=mode), self.assertRaises(module.CandidateContextError):
                    module.build_request(text, pool, mode=mode)


if __name__ == "__main__":
    unittest.main()
