"""Routing has no reference or model input and cannot alter candidate evidence."""
from copy import deepcopy
import unittest
from unittest.mock import patch
from memory_migration_study.occurrence_routing import select_context_mode
from tests.test_candidate_context_batch import pool


class OccurrenceRoutingTests(unittest.TestCase):
    def test_only_duplicate_returned_surface_activates_markers(self):
        text = "Hem means an edge. Hem is our customer."
        candidates = pool(text, [("Hem", 0), ("Hem", text.rindex("Hem"))])
        before = deepcopy(candidates)
        with patch("socket.socket", side_effect=AssertionError("network_forbidden")):
            result = select_context_mode(text, candidates)
        self.assertEqual(result["mode"], "marked")
        self.assertEqual(result["repeated_surface_count"], 1)
        self.assertEqual(candidates, before)

    def test_repeated_source_word_without_second_candidate_does_not_add_a_candidate(self):
        text = "Hem means an edge. Hem is our customer."
        candidates = pool(text, [("Hem", text.rindex("Hem"))])
        self.assertEqual(select_context_mode(text, candidates)["mode"], "plain")
        self.assertEqual(len(candidates["candidates"]), 1)

    def test_case_and_unicode_are_exact_without_semantic_guessing(self):
        text = "Hem hem 纹 纹"
        candidates = pool(text, [("Hem", 0), ("hem", 4)])
        self.assertEqual(select_context_mode(text, candidates)["mode"], "plain")
        candidates = pool(text, [("纹", 8), ("纹", 10)])
        self.assertEqual(select_context_mode(text, candidates)["mode"], "marked")

    def test_invalid_source_or_modified_pool_cannot_choose_a_route(self):
        text = "Hem Hem"; candidates = pool(text, [("Hem", 0), ("Hem", 4)])
        with self.assertRaises(ValueError):
            select_context_mode(text + "!", candidates)
        candidates["candidates"].pop()
        with self.assertRaises(ValueError):
            select_context_mode(text, candidates)


if __name__ == "__main__": unittest.main()
