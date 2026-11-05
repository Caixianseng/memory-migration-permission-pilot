"""Deterministic support-index contract and independent least-fixed-point tests."""

import hashlib
import random
import tempfile
import unittest
from pathlib import Path

from .support_index import SourceBindingError, SupportIndex, UnsupportedFactError


def sources(*names):
    return [{"id": name, "text": "Title " + name + "\nEvidence " + name + ".", "version": 1}
            for name in names]


def leaf(index, source_id, fact_id=None):
    source = index._sources[source_id]
    return index.register_exact_span(source_id, source.text.index("\n") + 1, len(source.text), fact_id)


def independent_truth(allowed, base, rules):
    """Boolean least-fixed-point oracle, independent of proof enumeration/caches."""
    active = {fact for fact, source_id in base if source_id in allowed}
    while True:
        grown = active | {head for head, body in rules if set(body) <= active}
        if grown == active:
            return active
        active = grown


class SupportIndexTests(unittest.TestCase):
    def test_deny_all_and_exact_unicode_binding(self):
        text = "标题\n雪与🌙。"
        index = SupportIndex([{"ID": "源", "text": text, "version": "v1"}])
        fact = index.register_exact_span("源", 3, len(text), expected_quote="雪与🌙。")
        self.assertEqual(index.active_facts(), set())
        index.set_allowed(["源"], epoch=1, versions={"源": "v1"})
        output = index.render_supported([fact])
        self.assertEqual(output["text"], "雪与🌙。")
        self.assertEqual(output["source_hashes"]["源"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(output["spans"][0]["text_sha256"], hashlib.sha256("雪与🌙。".encode()).hexdigest())
        for begin, end in [(-1, 2), (3, 3), (0, len(text) + 1), (True, 3)]:
            with self.assertRaises(SourceBindingError):
                index.register_exact_span("源", begin, end)
        with self.assertRaises(SourceBindingError):
            index.register_exact_span("源", 3, len(text), expected_quote="snow")
        index.close()

    def test_independent_identical_quote_alternatives(self):
        index = SupportIndex({"A": {"text": "A\nSame exact sentence.", "version": 1},
                              "C": {"text": "C\nSame exact sentence.", "version": 2}})
        for source_id in ("A", "C"):
            index.register_exact_span(source_id, 2, len(index._sources[source_id].text), "same")
        index.set_allowed(["A", "C"])
        self.assertEqual(len(index.witnesses_for("same")), 2)
        index.set_allowed(["C"])
        self.assertEqual(index.render_supported(["same"])["support_ids"], ["C"])
        self.assertEqual(len(index.witnesses_for("same")), 1)
        with self.assertRaises(SourceBindingError):
            index.register_exact_span("C", 0, len(index._sources["C"].text), "same")
        index.set_allowed([])
        self.assertEqual(index.witnesses_for("same"), [])
        index.close()

    def test_and_or_revoke_regrant(self):
        index = SupportIndex(sources("A", "B", "C"))
        for name in "ABC":
            leaf(index, name, name)
        index.add_rule("target", ["A", "B"])
        index.add_rule("target", ["C"])
        index.set_allowed(list("ABC"))
        self.assertEqual(len(index.witnesses_for("target")), 2)
        index.set_allowed(["B", "C"])
        self.assertEqual(index.render_supported(["target"])["source_ids"], ["C"])
        index.set_allowed(["B"])
        self.assertNotIn("target", index.active_facts())
        with self.assertRaises(UnsupportedFactError):
            index.render_supported(["target"])
        index.set_allowed(["A", "B"])
        rendered = index.render_supported(["target"])
        self.assertEqual(rendered["source_ids"], ["A", "B"])
        self.assertNotIn("target", rendered["text"])
        index.close()

    def test_diamond_cycle_never_self_supports(self):
        index = SupportIndex(sources("A", "B"))
        leaf(index, "A", "a")
        leaf(index, "B", "b")
        for head, body in [("x", ["a"]), ("x", ["b"]), ("y", ["x"]), ("x", ["y"])]:
            index.add_rule(head, body)
        index.set_allowed(["A", "B"])
        index.set_allowed(["B"])
        self.assertEqual(index.render_supported(["x", "y"])["source_ids"], ["B"])
        index.set_allowed([])
        self.assertEqual(index.active_facts(), set())
        index.set_allowed(["A"])
        self.assertEqual(index.active_facts(), {"a", "x", "y"})
        with self.assertRaisesRegex(ValueError, "acyclic"):
            index.evaluate_counting_acyclic()
        index.close()

    def test_unseeded_and_self_cycles_and_source_free_rules(self):
        index = SupportIndex([])
        index.add_rule("x", ["y"])
        index.add_rule("y", ["x"])
        index.add_rule("self", ["self"])
        self.assertEqual(index.active_facts(), set())
        with self.assertRaises(ValueError):
            index.add_rule("unconditional", [])
        with self.assertRaises(ValueError):
            index.add_rule("string_body", "x")
        index.close()

    def test_minimal_proofs_remove_redundant_supersets(self):
        index = SupportIndex(sources("A", "B"), initially_allowed=["A", "B"])
        leaf(index, "A", "a")
        leaf(index, "B", "b")
        index.add_rule("x", ["a", "b"])
        index.add_rule("x", ["a"])
        proofs = index.witnesses_for("x")
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0]["source_ids"], ["A"])
        index.close()

    def test_source_version_update_never_rebinds_existing_span(self):
        index = SupportIndex(sources("A"), initially_allowed=["A"])
        leaf(index, "A", "a")
        index.add_rule("target", ["a"])
        with self.assertRaises(SourceBindingError):
            index.update_source("A", "A\nChanged.", 1)
        index.update_source("A", "A\nChanged.", 2)
        self.assertEqual(index.active_facts(), set())
        with self.assertRaises(SourceBindingError):
            index.set_allowed(["A"], versions={"A": 1})
        index.set_allowed(["A"], versions={"A": 2})
        self.assertEqual(index.active_facts(), set())
        index.register_exact_span("A", 2, len("A\nChanged."), "new")
        self.assertEqual(index.active_facts(), {"new"})
        index.close()

    def test_grant_epoch_unknown_version_and_strict_all_or_nothing(self):
        index = SupportIndex(sources("A"))
        leaf(index, "A", "a")
        index.set_allowed(["A"], epoch=4)
        index.set_allowed(["A"], epoch=4)
        for allowed, epoch in [([], 4), (["A"], 3)]:
            with self.assertRaises(ValueError):
                index.set_allowed(allowed, epoch)
        with self.assertRaises(SourceBindingError):
            index.set_allowed(["unknown"])
        with self.assertRaises(SourceBindingError):
            index.set_allowed(["A"], versions={"A": "1"})
        with self.assertRaises(UnsupportedFactError):
            index.render_supported(["a", "unknown"])
        partial = index.render_supported(["a", "unknown"], strict=False)
        self.assertEqual(partial["fact_ids"], ["a"])
        self.assertEqual(partial["missing_fact_ids"], ["unknown"])
        index.close()

    def test_initial_external_epoch_zero_can_bind_once(self):
        index = SupportIndex(sources("A"))
        leaf(index, "A", "a")
        index.set_allowed(["A"], epoch=0)
        self.assertEqual(index.render_supported(["a"])["epoch"], 0)
        with self.assertRaises(ValueError):
            index.set_allowed([], epoch=0)
        stats = index.set_allowed([], epoch=1)
        self.assertGreaterEqual(stats["maintenance_elapsed_ms"], stats["elapsed_ms"])
        self.assertEqual(index.active_facts(), set())
        index.close()

    def test_acyclic_counting_matches_full_proofs(self):
        index = SupportIndex(sources("A", "B", "C"))
        for name in "ABC":
            leaf(index, name, name)
        for head, body in [("x", ["A", "B"]), ("x", ["C"]), ("z", ["x", "B"])]:
            index.add_rule(head, body)
        for allowed in [[], ["A"], ["A", "B"], ["B", "C"], ["C"], []]:
            index.set_allowed(allowed)
            full = index.recompute_full()
            counted = index.evaluate_counting_acyclic()
            self.assertEqual(index.active_facts(), full["active_facts"])
            self.assertEqual(index.active_facts(), counted["active_facts"])
            self.assertGreaterEqual(full["stats"]["elapsed_ms"], 0)
            self.assertGreaterEqual(counted["stats"]["elapsed_ms"], 0)
        index.close()

    def test_dirty_maintenance_skips_unrelated_rule_cones(self):
        index = SupportIndex(sources("A", "B"), initially_allowed=["A", "B"])
        leaf(index, "A", "a")
        leaf(index, "B", "b")
        index.add_rule("target", ["a"])
        previous = "b"
        for number in range(30):
            head = "unrelated" + str(number)
            index.add_rule(head, [previous])
            previous = head
        stats = index.set_allowed(["B"])
        self.assertEqual(stats["dirty_facts"], 2)
        self.assertEqual(stats["relevant_rules"], 1)
        full = index.recompute_full()
        self.assertEqual(index.active_facts(), full["active_facts"])
        self.assertLess(stats["rule_evaluations"], full["stats"]["rule_evaluations"])
        index.close()

    def test_persistent_reload_and_changed_source_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "supports.sqlite"
            with SupportIndex(sources("A"), db_path=db) as index:
                leaf(index, "A", "a")
                index.add_rule("target", ["a"])
                index.set_allowed(["A"], epoch=10)
            with SupportIndex(sources("A"), db_path=db) as index:
                self.assertEqual(index.epoch, 10)
                self.assertIn("target", index.active_facts())
                self.assertEqual(index.render_supported(["target"])["source_ids"], ["A"])
            with self.assertRaises(SourceBindingError):
                SupportIndex([{"id": "A", "text": "Changed", "version": 2}], db_path=db)

    def test_source_hash_input_and_persisted_text_integrity(self):
        with self.assertRaises(SourceBindingError):
            SupportIndex([{"id": "A", "text": "Original", "sha256": "bad"}])
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "supports.sqlite"
            with SupportIndex(sources("A"), db_path=db) as index:
                index.connection.execute("UPDATE support_sources SET text='corrupted'")
                index.connection.commit()
            with self.assertRaises(SourceBindingError):
                SupportIndex([], db_path=db)

    def test_randomized_incremental_matches_independent_truth_and_full_proofs(self):
        rng = random.Random(5041)
        index = SupportIndex(sources("A", "B", "C", "D"))
        base = [(name.lower(), name) for name in "ABCD"]
        for fact, name in base:
            leaf(index, name, fact)
        names = list("abcd") + ["x", "y", "z"]
        rules = []
        for number in range(18):
            head = rng.choice(names[4:])
            body = rng.sample(names, rng.randint(1, 3))
            rules.append((head, body))
            index.add_rule(head, body, rule_id="r" + str(number))
        for _ in range(60):
            allowed = {name for name in "ABCD" if rng.randrange(2)}
            index.set_allowed(allowed)
            self.assertEqual(index.active_facts(), independent_truth(allowed, base, rules))
            full = index.recompute_full()
            self.assertEqual(index.active_facts(), full["active_facts"])
            for fact in index.active_facts():
                actual = sorted(witness["span_ids"] for witness in index.witnesses_for(fact))
                self.assertEqual(actual, full["proofs"][fact])
                self.assertLessEqual(set(index.render_supported([fact])["source_ids"]), allowed)
        index.close()


if __name__ == "__main__":
    unittest.main()
