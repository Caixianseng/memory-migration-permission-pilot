"""Complete-pool and position-marking contracts; synthetic data, zero models."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import candidate_context_batch as batch
from memory_migration_study import relation_occurrence as occurrence


def pool(text, spans):
    candidates = [{"cid": f"C{i}", "text": quote, "start": start, "end": start+len(quote)}
                  for i, (quote, start) in enumerate(spans)]
    over = len(candidates) > occurrence.MAX_CANDIDATES
    raw = [{"text": c["text"], "start": c["start"], "end": c["end"], "confidence": .8} for c in candidates]
    result = {"version": occurrence.VERSION, "status": "needs_review" if over else "ok",
        "error_kind": "coverage" if over else None, "errors": ["candidate_limit_exceeded"] if over else [],
        "text_sha256": occurrence._text_hash(text), "generator_identity": {"fixture": "automatic-ner"},
        "candidate_count": len(candidates), "candidates": candidates,
        "inference_counts": occurrence._counts(proposal_infer_invocations=1),
        "raw_result": {"entities": {"organization": raw}}}
    return reseal(result)


def reseal(value):
    return occurrence._seal(value, "pool_sha256")


def labels(candidate_pool, value="current_customer"):
    return {"candidates": [{"cid": c["cid"], "label": value} for c in candidate_pool["candidates"]]}


class CandidateContextBatchTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            self.guards.append(guard.start()); self.addCleanup(guard.stop)
        self.text = "Larch buys from us. Loom only supplies goods."
        self.pool = pool(self.text, [("Loom", self.text.index("Loom")), ("Larch", 0)])

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def test_plain_and_marked_differ_only_in_user_text_with_full_candidates(self):
        before = deepcopy(self.pool)
        plain = batch.build_request(self.text, self.pool, mode="plain")
        marked = batch.build_request(self.text, self.pool, mode="marked")
        self.assertEqual(plain["messages"][0], marked["messages"][0])
        self.assertEqual(plain["schema"], marked["schema"])
        p, m = (json.loads(r["messages"][1]["content"]) for r in (plain, marked))
        self.assertEqual(p, {"text": self.text, "candidates": self.pool["candidates"]})
        self.assertEqual(m["candidates"], p["candidates"])
        self.assertEqual(batch.strip_markers(m["text"], self.text, self.pool), self.text)
        self.assertEqual(self.pool, before)

    def test_complete_three_candidate_original_coverage_can_enter_both_modes(self):
        text = "A B C our company"; original = pool(text, [("A", 0), ("B", 2), ("C", 4)])
        before = deepcopy(original)
        for mode in batch.MODES:
            request = batch.build_request(text, original, mode=mode)
            self.assertTrue(request["qualification"]["recovered_old_candidate_limit"])
            self.assertEqual(len(json.loads(request["messages"][1]["content"])["candidates"]), 3)
            self.assertEqual(len(batch.decode_response(text, original, labels(original), mode=mode)["findings"]), 3)
        self.assertEqual(original, before)
        self.assertEqual(original["status"], "needs_review")

    def test_new_limit_is_twelve_without_implicitly_accepting_thirteen(self):
        for count in (12, 13):
            words = [f"X{i}" for i in range(count)]; text = " ".join(words)
            original = pool(text, [(word, text.index(word)) for word in words])
            if count == 12:
                self.assertEqual(batch.validate_pool(text, original)["candidate_count"], 12)
                self.assertEqual(batch.build_request(text, original)["schema"]["properties"]["candidates"]["maxItems"], 12)
            else:
                with self.assertRaisesRegex(batch.CandidateContextError, "new_candidate_limit_exceeded"):
                    batch.build_request(text, original)
                self.assertEqual(len(original["candidates"]), 13)

    def test_other_old_failures_or_multiple_errors_are_not_recoverable(self):
        text = "A B C"; original = pool(text, [("A", 0), ("B", 2), ("C", 4)])
        for error, kind in ((["proposal_failed"], "engineering"), (["proposal_full_token_budget_exceeded"], "coverage"),
                            (["candidate_limit_exceeded", "proposal_failed"], "coverage")):
            changed = deepcopy(original); changed.update(errors=error, error_kind=kind); reseal(changed)
            with self.assertRaisesRegex(batch.CandidateContextError, "unsupported_original_pool_failure"):
                batch.validate_pool(text, changed)
        changed = deepcopy(self.pool); changed.update(status="needs_review", errors=["candidate_limit_exceeded"], error_kind="coverage"); reseal(changed)
        with self.assertRaisesRegex(batch.CandidateContextError, "spurious_old_candidate_limit"):
            batch.validate_pool(self.text, changed)

    def test_omitted_raw_candidate_and_wrong_count_are_rejected_even_with_new_hash(self):
        text = "A B C"; original = pool(text, [("A", 0), ("B", 2), ("C", 4)])
        for change in ("drop", "count", "raw_drop"):
            changed = deepcopy(original)
            if change == "drop": changed["candidates"].pop()
            if change == "count": changed["candidate_count"] = 2
            if change == "raw_drop": changed["raw_result"]["entities"]["organization"].pop()
            reseal(changed)
            with self.subTest(change=change), self.assertRaisesRegex(batch.CandidateContextError, "incomplete_candidate_inventory"):
                batch.validate_pool(text, changed)

    def test_raw_reordering_invalid_confidence_duplicate_and_partial_inventory_rejected(self):
        for change in ("order", "confidence", "boolean", "duplicate", "text"):
            changed = deepcopy(self.pool); raw = changed["raw_result"]["entities"]["organization"]
            if change == "order": raw.reverse()
            if change == "confidence": raw[0]["confidence"] = .49
            if change == "boolean": raw[0]["confidence"] = True
            if change == "duplicate": raw[1] = deepcopy(raw[0])
            if change == "text": raw[0]["text"] = "Loo"
            reseal(changed)
            with self.subTest(change=change), self.assertRaises(batch.CandidateContextError):
                batch.validate_pool(self.text, changed)

    def test_original_hash_text_identity_and_proposal_counts_are_checked(self):
        for change in ("hash", "identity", "counts", "bool_count"):
            changed = deepcopy(self.pool)
            if change == "hash": changed["pool_sha256"] = "0"*64
            if change == "identity": changed["generator_identity"] = {}; reseal(changed)
            if change == "counts": changed["inference_counts"]["proposal_infer_invocations"] = 0; reseal(changed)
            if change == "bool_count": changed["inference_counts"]["proposal_infer_invocations"] = True; reseal(changed)
            with self.subTest(change=change), self.assertRaises(batch.CandidateContextError):
                batch.validate_pool(self.text, changed)
        with self.assertRaises(batch.CandidateContextError):
            batch.validate_pool(self.text + "!", self.pool)

    def test_overlapping_spans_block_both_modes_without_dropping_anything(self):
        text = "Larch Cooperative"; original = pool(text, [(text, 0), ("Larch", 0)])
        for mode in batch.MODES:
            with self.assertRaisesRegex(batch.CandidateContextError, "overlapping_candidate_positions"):
                batch.build_request(text, original, mode=mode)
        self.assertEqual(len(original["candidates"]), 2)

    def test_source_reserved_markers_and_case_variants_block_both_modes(self):
        for marker in ("[[CANDIDATE:C0]]", "[[/CANDIDATE:C42]]", "[[candidate:incomplete"):
            text = "Larch " + marker; original = pool(text, [("Larch", 0)])
            for mode in batch.MODES:
                with self.assertRaisesRegex(batch.CandidateContextError, "source_marker_collision"):
                    batch.build_request(text, original, mode=mode)

    def test_strip_rejects_forged_deleted_reordered_and_duplicate_markers(self):
        marked = json.loads(batch.build_request(self.text, self.pool, mode="marked")["messages"][1]["content"])["text"]
        for changed in (marked.replace("C0", "C9"), marked.replace("[[CANDIDATE:C0]]", ""),
                        marked + "[[CANDIDATE:C0]]", marked.replace("Larch", "LARCH")):
            with self.assertRaisesRegex(batch.CandidateContextError, "marker_layout_changed"):
                batch.strip_markers(changed, self.text, self.pool)

    def test_identical_names_and_unsorted_pool_map_to_original_occurrences(self):
        text = "Splice is a word. Splice is our customer."
        original = pool(text, [("Splice", text.rindex("Splice")), ("Splice", 0)])
        raw = {"candidates": [{"cid": "C1", "label": "not_specific_name"}, {"cid": "C0", "label": "current_customer"}]}
        for mode in batch.MODES:
            result = batch.decode_response(text, original, raw, mode=mode)
            self.assertEqual([f["start"] for f in result["findings"]], [text.rindex("Splice")])
        marked = json.loads(batch.build_request(text, original, mode="marked")["messages"][1]["content"])["text"]
        self.assertLess(marked.index("[[CANDIDATE:C1]]"), marked.index("[[CANDIDATE:C0]]"))

    def test_adjacent_unicode_spans_and_newlines_roundtrip_exactly(self):
        text = '甲乙🙂\n客户说"原文"。'; original = pool(text, [("甲", 0), ("乙", 1)])
        request = batch.build_request(text, original, mode="marked")
        marked = json.loads(request["messages"][1]["content"])["text"]
        self.assertEqual(batch.strip_markers(marked, text, original), text)
        self.assertIn("🙂\n", marked)

    def test_five_label_mapping_and_unknown_remains_whole_record_review(self):
        for label in batch.LABELS:
            result = batch.decode_response(self.text, self.pool, labels(self.pool, label))
            self.assertEqual(result["status"], "needs_review" if label == "organization_unknown_relation" else "ok")
            self.assertEqual(len(result["findings"]), 2 if label in {"current_customer", "former_customer"} else 0)
            self.assertEqual(result["local_calls"], 0)
        mixed = labels(self.pool); mixed["candidates"][1]["label"] = "organization_unknown_relation"
        self.assertEqual(batch.decode_response(self.text, self.pool, mixed)["errors"], ["semantic_uncertainty"])

    def test_response_inventory_extra_keys_unknown_ids_and_score_cannot_override(self):
        raw = labels(self.pool)
        cases = [{"candidates": raw["candidates"][:1]}, {"candidates": raw["candidates"]*2},
                 {"candidates": [raw["candidates"][0], raw["candidates"][0]]},
                 {"candidates": [{"cid": "C9", "label": "current_customer"}, raw["candidates"][1]]},
                 {"candidates": [{**raw["candidates"][0], "confidence": 1}, raw["candidates"][1]]},
                 {**raw, "permissions": ["public"]},
                 {"candidates": [{"cid": "C0", "label": "PUBLIC"}, raw["candidates"][1]]}]
        for value in cases:
            with self.assertRaises(batch.CandidateContextError):
                batch.decode_response(self.text, self.pool, value)

    def test_empty_automatic_inventory_is_explicit_without_new_proposals(self):
        text = "No named organization supplied."; original = pool(text, [])
        result = batch.decode_response(text, original, {"candidates": []}, mode="marked")
        self.assertEqual((result["status"], result["findings"], result["candidate_decisions"]), ("ok", [], []))

    def test_exact_byte_boundary_is_inclusive_and_oversize_is_never_truncated(self):
        text = "A."; original = pool(text, [("A", 0)])
        base = batch.build_request(text, original)["preflight"]["context_byte_bound"]
        for excess in (0, 1):
            expanded = text + "x"*(batch.NUM_CTX-base+excess); inventory = pool(expanded, [("A", 0)])
            request = batch.build_request(expanded, inventory)
            self.assertEqual(request["preflight"]["context_byte_bound"], batch.NUM_CTX+excess)
            self.assertEqual(request["preflight"]["fits"], excess == 0)
            self.assertEqual(json.loads(request["messages"][1]["content"])["text"], expanded)
            if excess:
                with self.assertRaisesRegex(batch.CandidateContextError, "request_context_budget_exceeded"):
                    batch.decode_response(expanded, inventory, labels(inventory))

    def test_marked_length_is_measured_separately_without_inheriting_plain_fit(self):
        text = "A."; original = pool(text, [("A", 0)])
        base = batch.build_request(text, original)["preflight"]["context_byte_bound"]
        expanded = text + "x"*(batch.NUM_CTX-base-1); inventory = pool(expanded, [("A", 0)])
        self.assertTrue(batch.build_request(expanded, inventory, mode="plain")["preflight"]["fits"])
        self.assertFalse(batch.build_request(expanded, inventory, mode="marked")["preflight"]["fits"])
        with self.assertRaisesRegex(batch.CandidateContextError, "request_context_budget_exceeded"):
            batch.decode_response(expanded, inventory, labels(inventory), mode="marked")

    def test_spec_schema_and_requests_are_deterministic_and_not_aliased(self):
        first = batch.build_request(self.text, self.pool, mode="marked")
        self.assertEqual(first, batch.build_request(self.text, self.pool, mode="marked"))
        self.assertEqual(first, json.loads(json.dumps(first)))
        self.assertEqual(first["request_sha256"], batch._digest({k: v for k, v in first.items() if k != "request_sha256"}))
        first["schema"]["properties"]["candidates"]["maxItems"] = 0
        self.assertEqual(batch.build_request(self.text, self.pool)["schema"]["properties"]["candidates"]["maxItems"], 12)
        with self.assertRaisesRegex(batch.CandidateContextError, "unsupported_input_mode"):
            batch.build_request(self.text, self.pool, mode="random")


if __name__ == "__main__":
    unittest.main()
