import copy
import itertools
import unittest

from memory_migration_study.policy import make_plan
from memory_migration_study.plan_verifier import verify_plan


def case_for(groups, *, copy_allowed=True):
    actors = sorted(set().union(*groups)) or ["a"]
    return {"case_id": "role-cover-example",
            "actors": [{"actor_id": a, "user_id": "user-" + a, "agent_id": "agent-" + a} for a in actors],
            "actor_mapping": {a: "target-" + a for a in actors},
            "records": [{"source_id": f"m{i}", "text": f"Synthetic independent fact number {i}.",
                         "source_readers": sorted(g), "recipient_readers": sorted(g), "target_readers": sorted(g),
                         "export_allowed": True, "copy_allowed": copy_allowed} for i, g in enumerate(groups)]}


def brute_force_cost(groups, container_cost, object_cost):
    """Independent tiny-domain oracle: enumerate role families then per-column covers."""
    actors = sorted(set().union(*groups))
    roles = [frozenset(g) for size in range(1, len(actors) + 1) for g in itertools.combinations(actors, size)]
    best = float("inf")
    for bits in range(1 << len(roles)):
        selected = [g for i, g in enumerate(roles) if bits & (1 << i)]
        cost = container_cost * len(selected)
        for column in groups:
            if not column:
                continue
            options = [g for g in selected if g <= column]
            minimum = None
            for size in range(1, len(options) + 1):
                if any(set().union(*combo) == set(column) for combo in itertools.combinations(options, size)):
                    minimum = size
                    break
            if minimum is None:
                cost = float("inf")
                break
            cost += minimum * object_cost
        best = min(best, cost)
    return best


class RoleCoverTests(unittest.TestCase):
    def test_overlap_reduces_containers_while_counting_more_copies(self):
        case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}])
        exact = make_plan(case, "exact_groups", "old")
        plan = make_plan(case, "role_cover", "new")
        self.assertEqual((len(exact["containers"]), len(exact["objects"])), (3, 3))
        self.assertEqual((len(plan["containers"]), len(plan["objects"])), (2, 4))
        self.assertEqual(plan["planner"]["weighted_cost"], 12)
        self.assertTrue(verify_plan(case, plan)["equivalent"])

    def test_high_replica_cost_selects_exact_groups(self):
        case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}])
        plan = make_plan(case, "role_cover", "cost", planner_options={"container_cost": 1, "object_cost": 8})
        self.assertEqual((len(plan["containers"]), len(plan["objects"])), (3, 3))
        self.assertTrue(verify_plan(case, plan)["equivalent"])

    def test_all_512_three_by_three_matrices_match_independent_optimum(self):
        for bits in range(512):
            groups = [{a for j, a in enumerate("abc") if bits & (1 << (3 * i + j))} for i in range(3)]
            case = case_for(groups)
            plan = make_plan(case, "role_cover", "exhaustive")
            with self.subTest(bits=bits):
                self.assertEqual(plan["planner"]["weighted_cost"], brute_force_cost(groups, 4, 1))
                self.assertTrue(verify_plan(case, plan)["equivalent"])
                self.assertEqual(plan["planner"]["optimality"], "proven_in_declared_finite_model")

    def test_copy_false_and_unknown_keep_one_full_reader_placement(self):
        for permission in (False, None):
            case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}], copy_allowed=permission)
            plan = make_plan(case, "role_cover", "single")
            self.assertEqual(len(plan["objects"]), 3)
            self.assertTrue(all(len(v) == 1 for v in plan["object_mapping"].values()))
            self.assertTrue(verify_plan(case, plan)["equivalent"])

    def test_unknown_and_export_denial_never_become_allow(self):
        case = case_for([{"a", "b"}, {"a"}])
        case["records"][0]["target_readers"] = None
        case["records"][1]["export_allowed"] = False
        plan = make_plan(case, "role_cover", "denied")
        self.assertFalse(plan["objects"])
        report = verify_plan(case, plan)
        self.assertFalse(report["safe"])
        self.assertEqual(len(report["unknown_reference"]), 2)
        self.assertFalse(report["added"])
        self.assertEqual(len(report["missing"]), 1)

    def test_implicit_owner_cannot_be_added_to_private_record(self):
        case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}])
        options = {"implicit_readers": ["a"]}
        plan = make_plan(case, "role_cover", "owner", planner_options=options)
        self.assertEqual(plan["object_mapping"]["m1"], [])
        self.assertEqual(plan["excluded"][0]["reason"], "implicit_reader_not_authorized")
        report = verify_plan(case, plan, implicit_readers=["a"])
        self.assertTrue(report["safe"])
        self.assertFalse(report["equivalent"])
        self.assertEqual(len(report["missing"]), 2)
        # Check the old naive plan against the SAME trusted target semantics.
        naive = make_plan(case, "exact_groups", "naive")
        self.assertEqual(verify_plan(case, naive, implicit_readers=["a"])["added"],
                         [{"actor_id": "a", "source_id": "m1", "operation": "read"}])

    def test_unrepresentable_reader_groups_and_noncopyable_record(self):
        case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}])
        options = {"allowed_reader_sets": [["a", "b"], ["b", "c"]]}
        plan = make_plan(case, "role_cover", "target", planner_options=options)
        self.assertTrue(verify_plan(case, plan, **options)["equivalent"])
        case["records"][2]["copy_allowed"] = False
        plan = make_plan(case, "role_cover", "target", planner_options=options)
        self.assertEqual(plan["object_mapping"]["m2"], [])
        self.assertEqual(plan["excluded"][0]["reason"], "target_has_no_safe_cover")

    def test_budget_exhaustion_keeps_safe_complete_incumbent(self):
        case = case_for([{"a", "b"}, {"b", "c"}, {"a", "b", "c"}])
        plan = make_plan(case, "role_cover", "bounded", planner_options={"max_search_states": 1})
        self.assertTrue(verify_plan(case, plan)["equivalent"])
        self.assertEqual(plan["planner"]["optimality"], "not_proven")
        self.assertTrue(plan["planner"]["search_limit_reached"])

    def test_large_domain_fallback_is_bounded_and_marked(self):
        case = case_for([set("abcdefghi"), set("abcd"), set("defgh")])
        plan = make_plan(case, "role_cover", "large")
        self.assertTrue(verify_plan(case, plan)["equivalent"])
        self.assertFalse(plan["planner"]["candidate_domain_complete"])
        self.assertEqual(plan["planner"]["optimality"], "not_proven")

    def test_ids_are_run_namespaced_and_model_verifier_detects_corruption(self):
        case = case_for([{"a", "b"}, {"b"}])
        plan = make_plan(case, "role_cover", "verify")
        for mutation, code in (
            (lambda p: p["objects"][0].update(text="corrupt"), "content_changed"),
            (lambda p: p["object_mapping"]["m0"].clear(), "object_mapping_incomplete_or_incorrect"),
            (lambda p: p["objects"].append(copy.deepcopy(p["objects"][0])), "duplicate_target_id"),
            (lambda p: p["containers"][0]["target_ids"].clear(), "container_inventory_incorrect"),
        ):
            changed = copy.deepcopy(plan)
            mutation(changed)
            self.assertIn(code, verify_plan(case, changed)["structural_errors"])
        other = make_plan(case, "role_cover", "other")
        self.assertFalse({o["target_id"] for o in plan["objects"]} & {o["target_id"] for o in other["objects"]})

    def test_bad_options_are_errors_not_silent_fallbacks(self):
        case = case_for([{"a"}])
        for options in ({"object_cost": 0}, {"max_search_states": -1}, {"implicit_readers": ["stranger"]},
                        {"unknown": 1}, {"allowed_reader_sets": [[]]}):
            with self.assertRaises(ValueError):
                make_plan(case, "role_cover", "bad", planner_options=options)
        with self.assertRaises(ValueError):
            make_plan(case, "exact_groups", "bad", planner_options={})

    def test_plan_cannot_choose_a_weaker_authorization_reference(self):
        case = case_for([{"a", "b"}])
        case["records"][0]["target_readers"] = ["a"]
        plan = make_plan(case, "exact_groups", "source", source_only=True)
        report = verify_plan(case, plan)
        self.assertIn("reference_scope_mismatch", report["structural_errors"])
        self.assertEqual(report["added"], [{"actor_id": "b", "source_id": "m0", "operation": "read"}])
        self.assertFalse(report["safe"])
        # Source-only controls require an explicit trusted verifier argument.
        self.assertTrue(verify_plan(case, plan, source_only=True)["equivalent"])

    def test_checker_detects_identity_collapse(self):
        case = case_for([{"a", "b"}, {"a"}])
        plan = make_plan(case, "role_cover", "mapping")
        case["actor_mapping"]["b"] = case["actor_mapping"]["a"]
        self.assertIn("identity_mapping_invalid", verify_plan(case, plan)["structural_errors"])


if __name__ == "__main__":
    unittest.main()
