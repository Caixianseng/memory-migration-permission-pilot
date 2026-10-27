"""Synthetic event-contract tests: no model, reference file or network access."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from memory_migration_study import relation_events as events
from memory_migration_study import relation_occurrence as occurrence


def span(text, quote, *, start=None):
    position = text.index(quote) if start is None else start
    return {"start": position, "end": position + len(quote), "quote": quote}


def pool(text, candidates):
    rows = [{"cid": f"C{i}", "text": quote, "start": start, "end": start + len(quote)}
            for i, (quote, start) in enumerate(candidates)]
    return occurrence._seal({"version": occurrence.VERSION, "status": "ok", "error_kind": None,
        "errors": [], "text_sha256": occurrence._text_hash(text), "generator_identity": {"fake": True},
        "candidate_count": len(rows), "candidates": rows, "inference_counts": occurrence._counts(),
        "raw_result": None}, "pool_sha256")


def prediction(text, candidate, *, entity="specific", relation_events=()):
    return {"cid": candidate["cid"], "entity": entity, "evidence": span(text, text),
            "events": list(relation_events)}


def event(text, candidate, *, direction="customer_of", polarity="affirmed", time="current", reverse=False):
    own = {"start": candidate["start"], "end": candidate["end"], "quote": candidate["text"]}
    company = span(text, "our company" if "our company" in text else "本公司")
    return {"subject": events.SCOPE if reverse else candidate["cid"],
        "counterparty": candidate["cid"] if reverse else events.SCOPE,
        "direction": direction, "polarity": polarity, "time": time,
        "evidence": span(text, text), "subject_mention": company if reverse else own,
        "counterparty_mention": own if reverse else company}


class RelationEventsTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            self.guards.append(guard.start()); self.addCleanup(guard.stop)
        self.text = "Larch bought from our company previously; today it is not our customer."
        self.pool = pool(self.text, [("Larch", 0)])
        self.c = self.pool["candidates"][0]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def run_rows(self, rows, *, text=None, candidates=None):
        text, candidates = text or self.text, candidates or self.pool
        evidence = events.validate_extraction(text, candidates, {"candidates": rows})
        return events.compose(text, candidates, evidence)

    def test_full_source_and_unchanged_candidates_are_in_one_request(self):
        request = events.build_request(self.text, self.pool)
        supplied = json.loads(request["messages"][1]["content"])
        self.assertEqual(supplied, {"text": self.text, "candidates": self.pool["candidates"]})
        self.assertEqual(request["spec_sha256"], events._digest(events.compiled_spec()))
        self.assertEqual(request["schema"], events.SCHEMA)
        self.assertEqual(request["request_sha256"], events._digest({k: v for k, v in request.items() if k != "request_sha256"}))

    def test_historical_affirmation_survives_current_negation(self):
        es = [event(self.text, self.c, time="past"), event(self.text, self.c, polarity="negated")]
        result = self.run_rows([prediction(self.text, self.c, relation_events=es)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [{"quote": "Larch", "category": "CUSTOMER", "start": 0, "end": 5}])
        self.assertEqual(result["local_calls"], 0)

    def test_direction_does_not_turn_supplier_into_customer_or_noncustomer(self):
        for direction, reverse in (("customer_of", True), ("buys_from", True), ("sells_to", False)):
            with self.subTest(direction=direction, reverse=reverse):
                result = self.run_rows([prediction(self.text, self.c, relation_events=[
                    event(self.text, self.c, direction=direction, reverse=reverse)])])
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["findings"], [])
        for direction, reverse in (("customer_of", False), ("buys_from", False), ("sells_to", True)):
            result = self.run_rows([prediction(self.text, self.c, relation_events=[
                event(self.text, self.c, direction=direction, reverse=reverse)])])
            self.assertEqual(result["status"], "ok")
            self.assertEqual(len(result["findings"]), 1)

    def test_explicit_negative_without_positive_is_not_sensitive(self):
        for time in events.TIMES:
            result = self.run_rows([prediction(self.text, self.c, relation_events=[
                event(self.text, self.c, polarity="negated", time=time)])])
            self.assertEqual((result["status"], result["findings"]), ("ok", []))

    def test_same_time_and_never_conflicts_cannot_be_overridden(self):
        for positive, negative in (("current", "current"), ("past", "past"), ("past", "ever"),
                                  ("unspecified", "current"), ("ever", "current")):
            result = self.run_rows([prediction(self.text, self.c, relation_events=[
                event(self.text, self.c, time=positive), event(self.text, self.c, polarity="negated", time=negative)])])
            self.assertEqual(result["status"], "needs_review")
            self.assertEqual(result["findings"], [])

    def test_absent_uncertain_and_unknown_entity_remain_review(self):
        rows = [prediction(self.text, self.c), prediction(self.text, self.c, relation_events=[
            event(self.text, self.c, polarity="uncertain")]), prediction(self.text, self.c, entity="unknown",
            relation_events=[event(self.text, self.c)])]
        for row in rows:
            self.assertEqual(self.run_rows([row])["errors"], ["semantic_uncertainty"])
        self.assertEqual(self.run_rows([prediction(self.text, self.c, entity="not_specific")])["status"], "ok")

    def test_chinese_codepoint_positions_and_repeat_occurrences_stay_distinct(self):
        text = "捻线是工艺词。本公司向名为捻线的组织销售服务。"
        candidates = pool(text, [("捻线", 0), ("捻线", text.rindex("捻线"))])
        first, second = candidates["candidates"]
        rows = [prediction(text, first, entity="not_specific"), prediction(text, second,
            relation_events=[event(text, second, direction="sells_to", reverse=True)])]
        result = self.run_rows(rows, text=text, candidates=candidates)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([f["start"] for f in result["findings"]], [second["start"]])
        rows[1]["events"][0]["counterparty_mention"] = span(text, "捻线", start=0)
        with self.assertRaisesRegex(events.RelationEventError, "occurrence_changed"):
            events.validate_extraction(text, candidates, {"candidates": rows})

    def test_rejects_wrong_offsets_normalization_boolean_and_uncontained_support(self):
        original = prediction(self.text, self.c, relation_events=[event(self.text, self.c)])
        for change in ("quote", "boolean", "offset", "support"):
            row = deepcopy(original)
            if change == "quote": row["evidence"]["quote"] = self.text.lower()
            if change == "boolean": row["evidence"]["start"] = False
            if change == "offset": row["events"][0]["subject_mention"]["end"] -= 1
            if change == "support": row["events"][0]["evidence"] = span(self.text, "Larch")
            with self.subTest(change=change), self.assertRaises(events.RelationEventError):
                events.validate_extraction(self.text, self.pool, {"candidates": [row]})

    def test_missing_duplicate_unknown_candidate_or_added_score_is_invalid(self):
        row = prediction(self.text, self.c, relation_events=[event(self.text, self.c)])
        for raw in ({"candidates": []}, {"candidates": [row, row]}, {"candidates": [{**row, "cid": "C7"}]},
                    {"candidates": [{**row, "confidence": 1.0}]}, {"candidates": [row], "permissions": ["public"]}):
            with self.assertRaises(events.RelationEventError):
                events.validate_extraction(self.text, self.pool, raw)
        row["events"].append(deepcopy(row["events"][0]))
        with self.assertRaisesRegex(events.RelationEventError, "duplicate_relation_event"):
            events.validate_extraction(self.text, self.pool, {"candidates": [row]})

    def test_other_candidate_cannot_replace_scope_and_unknown_scope_is_invalid(self):
        row = prediction(self.text, self.c, relation_events=[event(self.text, self.c)])
        row["events"][0]["counterparty"] = "C1"
        with self.assertRaisesRegex(events.RelationEventError, "participants"):
            events.validate_extraction(self.text, self.pool, {"candidates": [row]})
        with self.assertRaisesRegex(events.RelationEventError, "scope"):
            events.build_request(self.text, self.pool, scope="Everyone is authorized")

    def test_scope_string_must_be_a_whole_word_and_participants_cannot_overlap(self):
        text = "Larch has business ties."
        candidates = pool(text, [("Larch", 0)]); candidate = candidates["candidates"][0]
        e = {"subject": "C0", "counterparty": "SCOPE", "direction": "customer_of", "polarity": "affirmed",
             "time": "current", "evidence": span(text, text), "subject_mention": span(text, "Larch"),
             "counterparty_mention": span(text, "us")}
        with self.assertRaisesRegex(events.RelationEventError, "standalone"):
            events.validate_extraction(text, candidates, {"candidates": [prediction(text, candidate, relation_events=[e])]})
        text = "our company buys."; candidates = pool(text, [("our company", 0)]); candidate = candidates["candidates"][0]
        with self.assertRaisesRegex(events.RelationEventError, "overlapping"):
            events.validate_extraction(text, candidates, {"candidates": [prediction(text, candidate,
                relation_events=[event(text, candidate)])]})

    def test_changed_evidence_source_pool_or_scope_fails_closed(self):
        evidence = events.validate_extraction(self.text, self.pool, {"candidates": [
            prediction(self.text, self.c, relation_events=[event(self.text, self.c)])]})
        for key, value in (("text_sha256", "0"*64), ("scope", "forged"), ("rows", []), ("extra", True)):
            modified = deepcopy(evidence); modified[key] = value
            # Even recomputing its checksum cannot make inconsistent raw/rows valid.
            modified["evidence_sha256"] = events._digest({k: v for k, v in modified.items() if k != "evidence_sha256"})
            self.assertEqual(events.compose(self.text, self.pool, modified)["errors"], ["invalid_input_or_policy"])
        self.assertEqual(events.compose(self.text + "!", self.pool, evidence)["status"], "needs_review")

    def test_pool_coverage_failure_is_not_silently_truncated(self):
        text = "A B C our company"; candidates = pool(text, [("A", 0), ("B", 2), ("C", 4)])
        candidates.update(status="needs_review", error_kind="coverage", errors=["candidate_limit_exceeded"])
        occurrence._seal(candidates, "pool_sha256")
        with self.assertRaisesRegex(events.RelationEventError, "pool_not_complete"):
            events.build_request(text, candidates)
        result = events.compose(text, candidates, {})
        self.assertEqual(result["errors"], ["input_budget_exceeded"])
        self.assertEqual(len(candidates["candidates"]), 3)

    def test_partial_candidate_is_not_expanded_to_whole_name(self):
        text = "Larch Cooperative buys from our company."
        candidates = pool(text, [("Larch", 0)]); candidate = candidates["candidates"][0]
        result = self.run_rows([prediction(text, candidate, relation_events=[event(text, candidate)])],
                               text=text, candidates=candidates)
        self.assertEqual(result["findings"][0]["quote"], "Larch")
        self.assertEqual(result["relation_validation"], "structure_and_exact_positions_only")

    def test_json_roundtrip_and_empty_automatic_pool_are_replayable(self):
        text = "No named organization is supplied."; candidates = pool(text, [])
        evidence = events.validate_extraction(text, candidates, {"candidates": []})
        result = events.compose(text, candidates, json.loads(json.dumps(evidence)))
        self.assertEqual((result["status"], result["findings"]), ("ok", []))


if __name__ == "__main__":
    unittest.main()
