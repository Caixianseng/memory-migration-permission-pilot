"""Offline tests for the plain BM25 retrieval baseline; no model or network calls.

Every test asserts a property that a fair baseline must have: the exactly
relevant source wins, exact score ties resolve stably by ``source_id``, only
caller-supplied sources can be returned, ``top_k`` is honoured in both
directions, and retrieved text is the original message byte for byte.
"""
import unittest

try:
    from .retrieval_baseline import score_sources, select, tokenize
except ImportError:  # direct execution from the experiment directory
    from retrieval_baseline import score_sources, select, tokenize

QUESTIONS = ["When is the budget deadline for the project?",
             "Which room hosts the project meeting?",
             "Who attends the project meeting?"]


def sources():
    return [
        {"source_id": "S01", "version": 3, "text": "The project budget deadline is Friday; finance closes the ledger.", "acl_group": "A"},
        {"source_id": "S02", "version": 1, "text": "Room 4B hosts the weekly project meeting on Tuesday morning.", "acl_group": "A"},
        {"source_id": "S03", "version": 1, "text": "Battery inspection and sensor calibration procedure for the field unit.", "acl_group": "B"},
        {"source_id": "S04", "version": 2, "text": "The project meeting is attended by Ana, Bo and Chen from delivery.", "acl_group": "B"},
    ]


class TokenizationTests(unittest.TestCase):
    def test_english_words_and_chinese_bigrams(self):
        self.assertEqual(tokenize("Budget DEADLINE!"), ["w:budget", "w:deadline"])
        self.assertEqual(tokenize("项目预算"), ["c:项目", "c:目预", "c:预算"])
        self.assertEqual(tokenize("会"), ["c:会"])

    def test_repeated_terms_are_kept_for_term_frequency(self):
        self.assertEqual(tokenize("room room"), ["w:room", "w:room"])

    def test_non_string_text_rejected(self):
        with self.assertRaisesRegex(ValueError, "text_must_be_string"):
            tokenize(None)


class SelectionTests(unittest.TestCase):
    def test_exactly_relevant_source_is_returned_first(self):
        cases = {"When is the budget deadline for the project?": "S01",
                 "Which room hosts the project meeting?": "S02",
                 "Who attends the project meeting?": "S04"}
        for question, expected in cases.items():
            with self.subTest(question=question):
                self.assertEqual([item["source_id"] for item in select(sources(), [question], top_k=1)],
                                 [expected])

    def test_three_question_sum_drops_the_unrelated_source(self):
        # Summed scores rank by total evidence over the three questions.  A source
        # matching two questions can therefore outrank the source that answers the
        # first one; this baseline is not answer-aware and that is reported as a
        # limitation rather than tuned away.
        ranked = select(sources(), QUESTIONS, top_k=3)
        self.assertEqual(sorted(item["source_id"] for item in ranked), ["S01", "S02", "S04"])
        scores = [item["score"] for item in score_sources(sources(), QUESTIONS)[:3]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(score_sources(sources(), QUESTIONS)[-1], {"source_id": "S03", "score": 0.0})

    def test_chinese_query_matches_chinese_source(self):
        docs = [{"source_id": "D1", "version": 1, "text": "项目预算在周五截止，财务关闭账本。"},
                {"source_id": "D2", "version": 1, "text": "现场设备的电池检查与传感器校准流程。"}]
        ranked = select(docs, ["项目预算什么时候截止？"], top_k=1)
        self.assertEqual([item["source_id"] for item in ranked], ["D1"])

    def test_multiple_questions_are_aggregated_over_the_three_questions(self):
        docs = [{"source_id": "Q1", "version": 1, "text": "budget deadline friday ledger"},
                {"source_id": "Q2", "version": 1, "text": "budget only"},
                {"source_id": "Q3", "version": 1, "text": "unrelated battery sensor calibration"}]
        questions = ["budget", "deadline", "ledger"]
        ids = [item["source_id"] for item in select(docs, questions, top_k=2)]
        self.assertEqual(ids[0], "Q1")
        # sum aggregation equals the sum of the per-question scores
        total = {item["source_id"]: item["score"] for item in score_sources(docs, questions)}
        parts = 0.0
        for question in questions:
            parts += {item["source_id"]: item["score"] for item in score_sources(docs, [question])}["Q1"]
        self.assertAlmostEqual(total["Q1"], parts, places=12)
        # max aggregation is bounded by sum and never negative
        sums = {item["source_id"]: item["score"] for item in score_sources(docs, questions)}
        maxima = {item["source_id"]: item["score"] for item in score_sources(docs, questions, aggregation="max")}
        for sid in sums:
            self.assertGreaterEqual(maxima[sid], 0.0)
            self.assertLessEqual(maxima[sid], sums[sid] + 1e-12)

    def test_max_aggregation_is_supported_and_still_deterministic(self):
        a = select(sources(), QUESTIONS, top_k=4, aggregation="max")
        b = select(list(reversed(sources())), QUESTIONS, top_k=4, aggregation="max")
        self.assertEqual([item["source_id"] for item in a], [item["source_id"] for item in b])
        with self.assertRaisesRegex(ValueError, "unknown_score_aggregation"):
            select(sources(), QUESTIONS, aggregation="mean")


class TieAndDeterminismTests(unittest.TestCase):
    def test_exact_score_tie_is_broken_by_source_id(self):
        docs = [{"source_id": "S02", "version": 1, "text": "same text for both sources"},
                {"source_id": "S01", "version": 1, "text": "same text for both sources"},
                {"source_id": "S03", "version": 1, "text": "unrelated battery calibration"}]
        ranked = select(docs, ["same text"], top_k=2)
        self.assertEqual([item["source_id"] for item in ranked], ["S01", "S02"])
        scores = score_sources(docs, ["same text"])
        self.assertEqual(scores[0]["score"], scores[1]["score"])
        # reversed input order must not change the tie order
        self.assertEqual([item["source_id"] for item in select(list(reversed(docs)), ["same text"], top_k=2)],
                         ["S01", "S02"])

    def test_repeated_calls_are_byte_identical(self):
        first = select(sources(), QUESTIONS)
        second = select(sources(), QUESTIONS)
        self.assertEqual([item["source_id"] for item in first], [item["source_id"] for item in second])
        self.assertEqual([item["score"] for item in score_sources(sources(), QUESTIONS)],
                         [item["score"] for item in score_sources(sources(), QUESTIONS)])

    def test_input_order_does_not_change_ranking(self):
        forward = [item["source_id"] for item in select(sources(), QUESTIONS, top_k=4)]
        backward = [item["source_id"] for item in select(list(reversed(sources())), QUESTIONS, top_k=4)]
        self.assertEqual(forward, backward)


class BoundaryTests(unittest.TestCase):
    def test_no_sources_returns_empty_list(self):
        for empty in ([], (), None):
            with self.subTest(empty=empty):
                self.assertEqual(select(empty, QUESTIONS), [])

    def test_top_k_larger_than_sources_returns_every_source_without_padding(self):
        ranked = select(sources(), QUESTIONS, top_k=99)
        self.assertEqual(len(ranked), len(sources()))
        self.assertEqual(sorted(item["source_id"] for item in ranked), ["S01", "S02", "S03", "S04"])

    def test_top_k_equal_to_source_count_and_default_top_k(self):
        self.assertEqual(len(select(sources(), QUESTIONS, top_k=4)), 4)
        self.assertEqual(len(select(sources(), QUESTIONS)), 4)
        self.assertEqual(len(select(sources(), QUESTIONS, top_k=2)), 2)

    def test_invalid_top_k_is_rejected(self):
        for bad in (0, -1, 1.5, True, "2", None):
            with self.subTest(top_k=bad):
                with self.assertRaisesRegex(ValueError, "invalid_top_k"):
                    select(sources(), QUESTIONS, top_k=bad)

    def test_no_match_still_returns_exactly_top_k_without_falling_back_to_all(self):
        docs = [{"source_id": "S0%d" % i, "version": 1, "text": "battery sensor calibration"} for i in range(1, 6)]
        ranked = select(docs, ["完全不相关的询问"], top_k=2)
        self.assertEqual([item["source_id"] for item in ranked], ["S01", "S02"])
        self.assertLess(len(ranked), len(docs))

    def test_empty_or_invalid_questions_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "questions_required"):
            select(sources(), [])
        with self.assertRaisesRegex(ValueError, "questions_must_be_string_list"):
            select(sources(), ["ok", 3])


class SourceIntegrityTests(unittest.TestCase):
    def test_only_passed_in_sources_are_returned_as_original_objects(self):
        docs = sources()
        ranked = select(docs, QUESTIONS, top_k=3)
        by_id = {record["source_id"]: record for record in docs}
        for item in ranked:
            self.assertIn(item["source_id"], by_id)
            self.assertIs(item, by_id[item["source_id"]])
        self.assertEqual(sorted(item["source_id"] for item in ranked),
                         sorted({item["source_id"] for item in ranked}))

    def test_metadata_is_carried_untouched(self):
        ranked = select(sources(), ["Which room hosts the project meeting?"], top_k=1)[0]
        self.assertEqual(ranked["version"], 1)
        self.assertEqual(ranked["acl_group"], "A")
        self.assertEqual(set(ranked), {"source_id", "version", "text", "acl_group"})

    def test_long_message_is_not_truncated_rewritten_or_padded(self):
        body = " ".join("line%d budget detail" % i for i in range(200)) + " END_MARKER_9F3"
        docs = [{"source_id": "L1", "version": 7, "text": body},
                {"source_id": "L2", "version": 1, "text": "battery sensor calibration"}]
        ranked = select(docs, ["budget detail"], top_k=1)[0]
        self.assertEqual(ranked["text"], body)
        self.assertEqual(len(ranked["text"]), len(body))
        self.assertTrue(ranked["text"].endswith("END_MARKER_9F3"))
        self.assertEqual(ranked["text"].encode("utf-8"), body.encode("utf-8"))

    def test_forbidden_and_malformed_sources_are_rejected(self):
        forbidden = sources()
        forbidden[0]["allow"] = False
        with self.assertRaisesRegex(ValueError, "forbidden_source"):
            select(forbidden, QUESTIONS)
        denied = sources()
        denied[0]["allowed"] = False
        with self.assertRaisesRegex(ValueError, "forbidden_source"):
            select(denied, QUESTIONS)
        with self.assertRaisesRegex(ValueError, "duplicate_source_id"):
            select(sources() + [sources()[0]], QUESTIONS)
        with self.assertRaisesRegex(ValueError, "source_text_required"):
            select([{"source_id": "X", "text": 5}], QUESTIONS)
        with self.assertRaisesRegex(ValueError, "invalid_source_id"):
            select([{"source_id": "", "text": "budget"}], QUESTIONS)


if __name__ == "__main__":
    unittest.main()
