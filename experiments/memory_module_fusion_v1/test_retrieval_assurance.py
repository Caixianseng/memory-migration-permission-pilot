"""Host/gate boundary tests AND mandatory real pinned TinyBERT CPU inference.

AuditFixtureRanker is only a deterministic gate-control fixture. The separate
RealTinyBERTTests construct the actual ONNX worker and do not substitute scores.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from .retrieval_assurance import AuthorityChanged, METHODS, prepare_retrieval
from .reranker_runtime import TinyBERTReranker, REVISION


def sources(n=10):
    return [{"source_id": f"S{i:02d}", "text": f"Project amber bridge documentation detail {i}.",
             "version": 1, "origin": {"parent_index": i // 2}} for i in range(n)]


class Host:
    def __init__(self, records):
        self.ids, self.epoch, self.events = {s["source_id"] for s in records}, 1, []
        self.hook = None

    def authorize(self, ids, purpose):
        self.events.append((list(ids), purpose))
        if not set(ids) <= self.ids:
            raise PermissionError("host_denied")
        if self.hook:
            self.hook(ids, purpose)
        return True


class AuditFixtureRanker:
    metadata = {"fixture_only": True, "model_revision": "UNIT_TEST_NOT_REAL_MODEL"}
    def __init__(self, scores=None, hook=None, fail=False):
        self.scores, self.hook, self.fail, self.calls = scores or {}, hook, fail, 0

    def score_sources(self, question, records):
        self.calls += 1
        if self.hook:
            self.hook()
        if self.fail:
            raise RuntimeError("fixture_rank_failure")
        windows = []
        for row in records:
            text = row["text"]
            windows.append({"source_id": row["source_id"], "start": 0, "end": len(text),
                            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "pair_tokens": 12, "truncated": False, "source_token_start": 0,
                            "source_token_end": 5, "source_total_tokens": 5,
                            "score": self.scores.get(row["source_id"], .1)})
        return {"status": "ok", "source_scores": {r["source_id"]: self.scores.get(r["source_id"], .1) for r in records},
                "windows": windows, "cpu_ms": 1.25, "wall_ms": 2.0}


class BoundaryTests(unittest.TestCase):
    def run_controller(self, records, *, method="adaptive_rerank", ranker=None, config=None, host=None, questions=None):
        host = host or Host(records)
        result = prepare_retrieval(records, questions or ["What is the amber bridge project?"], ranker,
                                   {"method": method, **(config or {})}, host.authorize, lambda: host.epoch)
        return result, host

    def test_adaptive_failure_widens_2_4_8_then_full_and_keeps_whole_ids(self):
        records = sources()
        ranker = AuditFixtureRanker()
        result, host = self.run_controller(records, ranker=ranker)
        decisions = result["gate_decisions"]
        self.assertEqual([d["requested_k"] for d in decisions if "requested_k" in d], [2, 4, 8])
        self.assertEqual(decisions[-1]["decision"], "full_raw_fallback")
        self.assertEqual(result["selected_source_ids"], [s["source_id"] for s in records])
        self.assertEqual(ranker.calls, 1)  # Same validated feature pool reused.
        self.assertTrue(result["full_raw_fallback_and_prior_stage_costs_must_all_be_charged"])
        self.assertEqual(result["ranker_cpu_ms"], 1.25)
        self.assertTrue(any("full_raw_fallback" in purpose for _, purpose in host.events))
        self.assertTrue(result["source_payload_untouched"])

    def test_fixed_rerank_has_same_feature_pool_but_fixed_two_payload_sources(self):
        records, ranker = sources(), AuditFixtureRanker()
        result, host = self.run_controller(records, method="fixed_rerank", ranker=ranker)
        self.assertEqual(len(result["selected_source_ids"]), 2)
        pool = next(ids for ids, purpose in host.events if purpose.startswith("rank_before"))
        self.assertEqual(len(pool), 10)
        self.assertEqual(result["gate_decisions"][0]["decision"], "fixed_budget")

    def test_distinct_parent_prior_prevents_stopping_on_two_same_parent_sentences(self):
        records = sources(6)
        ranker = AuditFixtureRanker({s["source_id"]: .99 for s in records})
        result, _ = self.run_controller(records, ranker=ranker, config={"require_distinct_parents": 2})
        self.assertEqual([d["requested_k"] for d in result["gate_decisions"]], [2, 4])
        self.assertEqual(result["gate_decisions"][0]["distinct_parent_count"], 1)
        self.assertEqual(result["gate_decisions"][1]["decision"], "accept_quality_signal")

    def test_epoch_change_during_ranker_never_falls_back_or_returns_stale_selection(self):
        records, host = sources(), Host(sources())
        ranker = AuditFixtureRanker(hook=lambda: setattr(host, "epoch", host.epoch + 1))
        with self.assertRaises(AuthorityChanged):
            self.run_controller(records, ranker=ranker, host=host)
        self.assertFalse(any("full_raw" in purpose for _, purpose in host.events))

    def test_epoch_change_during_stage_authorization_is_detected_after_callback(self):
        records, host = sources(), Host(sources())
        host.hook = lambda ids, purpose: setattr(host, "epoch", host.epoch + 1) if purpose.startswith("stage_before") else None
        with self.assertRaises(AuthorityChanged):
            self.run_controller(records, method="adaptive_bm25", host=host)

    def test_initial_denial_happens_before_any_ranker_source_read(self):
        records, host, ranker = sources(), Host(sources()), AuditFixtureRanker()
        host.ids.remove("S00")
        with self.assertRaises(PermissionError):
            self.run_controller(records, ranker=ranker, host=host)
        self.assertEqual(ranker.calls, 0)

    def test_ranker_failure_is_charged_and_reauthorized_full_raw(self):
        ranker, records = AuditFixtureRanker(fail=True), sources()
        result, host = self.run_controller(records, ranker=ranker)
        self.assertEqual(result["ranker_call_count"], 1)
        self.assertFalse(result["ranker_cpu_accounting_complete"])
        self.assertEqual(result["gate_decisions"][0]["decision"], "ranker_error_full_raw")
        self.assertEqual(set(result["selected_source_ids"]), host.ids)

    def test_evaluation_labels_are_rejected_not_available_for_gating(self):
        for question in ({"question": "query", "answer": "secret"},
                         {"question": "query", "support_sets": [["S00"]]}):
            with self.assertRaises(ValueError):
                self.run_controller(sources(), method="bm25", questions=[question])
        with self.assertRaises(ValueError):
            self.run_controller(sources(), method="bm25", config={"evaluation": {}})

    def test_per_question_union_deduplicates_and_never_mutates_original_payload(self):
        records = sources(4)
        original = copy.deepcopy(records)
        result, _ = self.run_controller(records, method="bm25", questions=[
            {"question_id": "Q1", "question": "amber bridge"},
            {"question_id": "Q2", "question": "amber project"}])
        self.assertEqual(len(result["per_question"]), 2)
        self.assertEqual(len(result["selected_source_ids"]), len(set(result["selected_source_ids"])))
        self.assertEqual(records, original)
        self.assertTrue(result["quality_scores_do_not_prove_support_or_authorize_access"])

    def test_empty_view_does_not_start_model_and_requires_callbacks(self):
        ranker = AuditFixtureRanker()
        result, _ = self.run_controller([], ranker=ranker)
        self.assertEqual(result["selected_source_ids"], [])
        self.assertEqual(ranker.calls, 0)
        with self.assertRaises(ValueError):
            prepare_retrieval(sources(), ["query"])


class RealTinyBERTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No skip: this task requires an actual pinned local model to run.
        cls.ranker = TinyBERTReranker()

    @classmethod
    def tearDownClass(cls):
        cls.ranker.close()

    def test_actual_cpu_model_scores_relevant_passage_above_distractors(self):
        result = self.ranker.score_sources("Which planet is called the Red Planet?", [
            {"source_id": "M", "text": "Mars is called the Red Planet because iron minerals on its surface look red."},
            {"source_id": "V", "text": "Venus is sometimes called Earth's twin and has thick clouds."},
            {"source_id": "W", "text": "The workshop makes wooden tables and chairs."}])
        self.assertEqual(self.ranker.metadata["model_revision"], REVISION)
        self.assertEqual(self.ranker.metadata["providers"], ["CPUExecutionProvider"])
        self.assertGreater(result["source_scores"]["M"], result["source_scores"]["V"])
        self.assertGreater(result["source_scores"]["M"], result["source_scores"]["W"])

    def test_long_source_tail_is_scored_in_nontruncated_offset_preserving_windows(self):
        text = "The workshop makes wooden tables and chairs. " * 300 + "Mars is the Red Planet."
        result = self.ranker.score_sources("Which planet is the Red Planet?", [{"source_id": "LONG", "text": text}])
        windows = result["windows"]
        self.assertGreater(len(windows), 2)
        cursor = 0
        for window in windows:
            self.assertLessEqual(window["pair_tokens"], 512)
            self.assertFalse(window["truncated"])
            self.assertEqual(window["source_token_start"], cursor)
            self.assertEqual(window["text_sha256"], hashlib.sha256(text[window["start"]:window["end"]].encode()).hexdigest())
            cursor = window["source_token_end"]
        self.assertEqual(cursor, windows[-1]["source_total_tokens"])
        best = max(windows, key=lambda row: row["score"])
        self.assertGreater(best["start"], len(text) // 2)

    def test_all_four_modes_run_with_real_model_and_deliver_only_complete_ids(self):
        records = [
            {"source_id": "M", "text": "Mars is called the Red Planet.", "origin": {"parent_index": 0}},
            {"source_id": "V", "text": "Venus has thick clouds.", "origin": {"parent_index": 1}},
            {"source_id": "W", "text": "The workshop makes wooden tables.", "origin": {"parent_index": 2}}]
        for method in METHODS:
            with self.subTest(method=method):
                host = Host(records)
                result = prepare_retrieval(records, ["Which planet is the Red Planet?"], self.ranker,
                                           {"method": method}, host.authorize, lambda: host.epoch)
                self.assertTrue(set(result["selected_source_ids"]) <= host.ids)
                self.assertTrue(result["no_generation_model_api_calls"])
                self.assertTrue(result["source_payload_untouched"])
                self.assertEqual(result["ranker_call_count"], int("rerank" in method))


class RuntimeCloseTests(unittest.TestCase):
    def assert_owned_streams_closed(self, ranker):
        self.assertIsNotNone(ranker.process.poll())
        for stream in (ranker.process.stdin, ranker.process.stdout, ranker.process.stderr):
            if stream is not None:
                self.assertTrue(stream.closed)
        self.assertFalse(ranker._reader.is_alive())

    def test_normal_close_is_idempotent_and_closes_owned_pipes(self):
        ranker = TinyBERTReranker()
        ranker.close()
        ranker.close()
        self.assert_owned_streams_closed(ranker)

    def test_already_exited_worker_still_has_all_pipes_closed(self):
        ranker = TinyBERTReranker()
        ranker.process.terminate()
        ranker.process.wait(timeout=3)
        ranker.close()
        ranker.close()
        self.assert_owned_streams_closed(ranker)

    def test_broken_stdin_cleanup_stops_only_the_owned_worker(self):
        ranker = TinyBERTReranker()
        ranker.process.stdin.close()
        ranker.close()
        self.assert_owned_streams_closed(ranker)


if __name__ == "__main__":
    unittest.main()
