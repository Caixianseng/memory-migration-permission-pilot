"""Prepared deterministic fake-only definitions; execution awaits root's gate.

No old research material, sealed reference, native client, service or model is used.
"""
import random
import unittest

from experiments.algorithm_ports_20261029.bf_port import (
    BfMaterialization, DeliveryKey, FullRecomputeBaseline, GroundRule,
    PortContractError, delivery_projection,
)


class BfPortPreparedTests(unittest.TestCase):
    def assert_transition(self, engines, *, delete=(), insert=()):
        left, right = engines
        a, b = left.update(delete=delete, insert=insert), right.update(delete=delete, insert=insert)
        self.assertEqual(a.materialized, b.materialized)
        self.assertEqual(a.added, b.added)
        self.assertEqual(a.removed, b.removed)
        self.assertEqual(left.base_facts, right.base_facts)
        return a, b

    def engines(self, base, rules):
        pair = BfMaterialization(base, rules), FullRecomputeBaseline(base, rules)
        self.assertEqual(pair[0].facts, pair[1].facts)
        return pair

    def test_and_and_alternative_complete_support(self):
        rules = [GroundRule("answer", ("a", "b")), GroundRule("answer", ("c",))]
        pair = self.engines({"a", "b", "c"}, rules)
        first, _ = self.assert_transition(pair, delete={"a"})
        self.assertIn("answer", first.materialized)
        last, _ = self.assert_transition(pair, delete={"c"})
        self.assertNotIn("answer", last.materialized)

    def test_recursive_cycle_loses_its_only_root(self):
        rules = [GroundRule("x", ("root",)), GroundRule("y", ("x",)), GroundRule("x", ("y",))]
        pair = self.engines({"root"}, rules)
        result, _ = self.assert_transition(pair, delete={"root"})
        self.assertEqual(result.materialized, frozenset())
        self.assertGreater(result.work["backward_facts_checked"], 0)

    def test_cycle_with_alternative_root_survives(self):
        rules = [GroundRule("x", ("a",)), GroundRule("x", ("b",)),
                 GroundRule("y", ("x",)), GroundRule("x", ("y",))]
        pair = self.engines({"a", "b"}, rules)
        result, _ = self.assert_transition(pair, delete={"a"})
        self.assertEqual(result.materialized, frozenset({"b", "x", "y"}))
        result, _ = self.assert_transition(pair, delete={"b"})
        self.assertFalse(result.materialized)

    def test_proved_deleted_fact_must_remain_available_in_other_and_body(self):
        # 'a' is explicitly removed but remains derivable. 'b' is truly removed.
        # Putting the proved a in O would incorrectly hide the rule using a AND b.
        rules = [GroundRule("a", ("root",)), GroundRule("joined", ("a", "b"))]
        pair = self.engines({"root", "a", "b"}, rules)
        result, _ = self.assert_transition(pair, delete={"a", "b"})
        self.assertIn("a", result.materialized)
        self.assertNotIn("joined", result.materialized)

    def test_copy_keeps_common_upstream_dependency(self):
        rules = [GroundRule("copy-1", ("source-1",)), GroundRule("copy-2", ("source-1",)),
                 GroundRule("fact", ("copy-1",)), GroundRule("fact", ("copy-2",))]
        pair = self.engines({"source-1"}, rules)
        result, _ = self.assert_transition(pair, delete={"source-1"})
        self.assertNotIn("fact", result.materialized)

    def test_two_trusted_grants_one_revoked(self):
        rules = [GroundRule("permitted", ("source", "grant-1")),
                 GroundRule("permitted", ("source", "grant-2"))]
        pair = self.engines({"source", "grant-1", "grant-2"}, rules)
        result, _ = self.assert_transition(pair, delete={"grant-1"})
        self.assertIn("permitted", result.materialized)
        result, _ = self.assert_transition(pair, delete={"source"})
        self.assertNotIn("permitted", result.materialized)

    def test_set_duplicates_replays_and_insert_wins(self):
        rule = GroundRule("head", ("a", "a"))
        pair = self.engines(["a", "a"], [rule, rule])
        self.assert_transition(pair, insert=["a", "a"])
        self.assert_transition(pair, delete=["a", "a"], insert=["a"])
        self.assertEqual(pair[0].facts, frozenset({"a", "head"}))
        self.assert_transition(pair, delete=["a"])
        self.assert_transition(pair, delete=["a"])
        self.assert_transition(pair, insert=["a"])

    def test_delete_means_explicit_membership_not_forced_derived_deletion(self):
        pair = self.engines({"a"}, [GroundRule("derived", ("a",))])
        result, _ = self.assert_transition(pair, delete={"derived"})
        self.assertIn("derived", result.materialized)
        self.assertEqual(result.effective_deletions, 0)

    def test_deep_chain_uses_no_python_recursion(self):
        rules = [GroundRule(f"n{i+1}", (f"n{i}",)) for i in range(1500)]
        pair = self.engines({"n0"}, rules)
        result, _ = self.assert_transition(pair, delete={"n0"})
        self.assertFalse(result.materialized)

    def test_update_and_insert_rebuild_after_root_loss(self):
        rules = [GroundRule("x", ("a",)), GroundRule("y", ("x", "b")), GroundRule("x", ("y",))]
        pair = self.engines({"a", "b"}, rules)
        self.assert_transition(pair, delete={"a"}, insert={"c"})
        self.assert_transition(pair, insert={"a"})
        self.assertEqual(pair[0].facts, frozenset({"a", "b", "c", "x", "y"}))

    def test_deterministic_generated_small_graphs_compare_independent_oracle(self):
        # Self-authored mechanical graphs; this is not a natural-language benchmark.
        rng = random.Random(20261029)
        atoms = tuple(f"g{i}" for i in range(9))
        for _ in range(24):
            rules = [GroundRule(rng.choice(atoms), tuple(rng.choice(atoms) for _ in range(rng.randint(1, 3))))
                     for _ in range(18)]
            pair = self.engines(set(rng.sample(atoms, 4)), rules)
            for _ in range(12):
                self.assert_transition(pair, delete={rng.choice(atoms)}, insert={rng.choice(atoms)})

    def test_total_operation_timer_and_work_fields_are_real_measurements(self):
        engine = BfMaterialization({"a"}, [GroundRule("x", ("a",))])
        self.assertIs(type(engine.last_result.elapsed_ns), int)
        self.assertGreaterEqual(engine.last_result.elapsed_ns, 0)
        self.assertGreater(engine.last_result.work["index_entries"], 0)
        result = engine.delete({"a"})
        self.assertEqual(result.work["baseline_rule_scans"], 0)
        self.assertGreater(result.work["deletion_rule_derivations"], 0)

    def test_common_gate_preserves_exact_principal_operation_and_global_deny(self):
        alice = DeliveryKey("alice", "agent-a", "read", "fact", "local")
        bob = DeliveryKey("bob", "agent-a", "read", "fact", "local")
        export = DeliveryKey("alice", "agent-a", "export", "fact", "cloud")
        targets = {alice: {"fact", "alice-read"}, bob: {"fact", "bob-read"},
                   export: {"fact", "alice-export"}}
        facts = {"fact", "alice-read", "alice-export"}
        self.assertEqual(delivery_projection(facts, targets, globally_forbidden={export}), frozenset({alice}))
        self.assertEqual(delivery_projection(facts, targets, globally_forbidden={alice, export}), frozenset())
        with self.assertRaises(PortContractError):
            delivery_projection(facts, {alice: set()}, globally_forbidden=set())

    def test_rejects_unstated_or_ambiguous_contract(self):
        with self.assertRaises(PortContractError):
            GroundRule("x", ())
        with self.assertRaises(PortContractError):
            GroundRule("x", ["a"])
        with self.assertRaises(PortContractError):
            BfMaterialization("text is not a set of facts", [])
        with self.assertRaises(PortContractError):
            BfMaterialization({"a"}, [{"head": "x", "body": ["a"]}])


if __name__ == "__main__":
    unittest.main()
