"""Contract tests for the isolated synthetic task-budget reference.

No product, model, native service, credentials, or external data are used.
The tiny matrix oracle enumerates physical permission rectangles independently
of the production solver's candidate/placement construction.
"""
import copy
import itertools
import socket
import unittest
from unittest.mock import patch

from memory_migration_study.task_budget_reference import (
    evaluate_plan,
    solve_reference,
)


def record(source_id, readers, *, export=True, copies=2, preserve=False):
    return {
        "source_id": source_id,
        "readers": readers,
        "export_allowed": export,
        "max_target_copies": copies,
        "preserve_all_readers": preserve,
    }


def task(task_id, actor_id, requirements, weight=1):
    return {
        "task_id": task_id,
        "actor_id": actor_id,
        "required_sets": requirements,
        "weight": weight,
        "requirement_origin": "synthetic_predeclared",
    }


def problem(actors, records, tasks=(), *, k=1, allowed=None, implicit=()):
    return {
        "schema_version": 1,
        "case_id": "synthetic-contract-check",
        "data_origin": "synthetic_development",
        "actors": list(actors),
        "records": list(records),
        "target": {
            "max_groups": k,
            "implicit_readers": list(implicit),
            "allowed_reader_sets": allowed,
            "constraint_origin": "synthetic",
        },
        "tasks": list(tasks),
    }


def plan(case, *groups):
    return {
        "case_id": case["case_id"],
        "groups": [
            {"readers": list(readers), "source_ids": list(sources)}
            for readers, sources in groups
        ],
    }


def pressure_case(k=1):
    return problem(
        list("abcd"),
        [record("m0", list("abcd")), record("m1", ["a"])],
        [task("complete-a", "a", [["m0", "m1"]])],
        k=k,
    )


def physical_rectangle_oracle(permissions, k):
    """Exhaust all <=2 actual containers over two users and two memories."""
    candidates = []
    for readers in range(1, 4):
        for sources in range(1, 4):
            rectangle = 0
            for actor in range(2):
                for source in range(2):
                    if readers & (1 << actor) and sources & (1 << source):
                        rectangle |= 1 << (actor * 2 + source)
            if not rectangle & ~permissions:
                candidates.append((readers, sources, rectangle))
    best_edges = best_tasks = best_weighted = 0
    legal_task_edges = 0
    for actor in range(2):
        row = 3 << (2 * actor)
        if permissions & row == row:
            legal_task_edges |= row
    for count in range(k + 1):
        for chosen in itertools.combinations(candidates, count):
            # Identical reader groups are merged in this no-capacity model.
            if len({entry[0] for entry in chosen}) != len(chosen):
                continue
            actual = 0
            for _, _, rectangle in chosen:
                actual |= rectangle
            completed = sum(
                (actual & (3 << (2 * actor))) == (3 << (2 * actor))
                for actor in range(2)
            )
            best_edges = max(best_edges, actual.bit_count())
            best_tasks = max(best_tasks, completed)
            best_weighted = max(best_weighted, (actual & legal_task_edges).bit_count())
    return {"edges": best_edges, "task_weighted_edges": best_weighted, "tasks": best_tasks}


class TaskBudgetReferenceTests(unittest.TestCase):
    def test_single_actor_can_merge_all_memories_into_one_group(self):
        case = problem(
            ["a"],
            [record("m" + str(i), ["a"]) for i in range(4)],
            [task("all-four", "a", [["m0", "m1", "m2", "m3"]])],
        )
        for objective in ("tasks", "edges", "task_weighted_edges"):
            result = solve_reference(case, objective=objective)
            self.assertEqual(result["status"], "optimal_in_declared_finite_model")
            self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 1)
            self.assertEqual(result["evaluation"]["group_count"], 1)
            self.assertEqual(len(result["evaluation"]["actual"]), 4)
            self.assertEqual(result["evaluation"]["missing_migratable"], [])

    def test_task_and_edge_objectives_can_differ_without_removed_safe_groups(self):
        case = pressure_case()
        edge = solve_reference(case, objective="edges")
        tasks = solve_reference(case, objective="tasks")
        self.assertEqual(len(edge["evaluation"]["actual"]), 4)
        self.assertEqual(edge["evaluation"]["tasks"]["completed_count"], 0)
        self.assertEqual(len(tasks["evaluation"]["actual"]), 2)
        self.assertEqual(tasks["evaluation"]["tasks"]["completed_count"], 1)
        self.assertEqual(edge["evaluation"]["E_migrate"], tasks["evaluation"]["E_migrate"])
        for result in (edge, tasks):
            self.assertTrue(result["evaluation"]["valid"])
            self.assertFalse(result["evaluation"]["native_enforcement_verified"])
            self.assertEqual(result["evaluation"]["added"], [])

    def test_task_weighted_edge_baseline_closes_the_simple_example(self):
        result = solve_reference(pressure_case(), objective="task_weighted_edges")
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 1)

    def test_unusable_demands_cannot_pollute_task_weighted_edge_ranking(self):
        base = pressure_case()
        base["records"].extend([
            record("unknown", None),
            record("no-export", ["b"], export=False),
        ])
        distractors = [
            task("denied-demand", "b", [["m0", "m1"]], weight=100),
            task("unknown-demand", "b", [["m0", "unknown"]], weight=100),
            task("export-forbidden-demand", "b", [["m0", "no-export"]], weight=100),
        ]
        baseline = solve_reference(base, objective="task_weighted_edges")
        for added in ([distractor] for distractor in distractors):
            changed = copy.deepcopy(base)
            changed["tasks"].extend(added)
            with self.subTest(tasks=added):
                result = solve_reference(changed, objective="task_weighted_edges")
                self.assertEqual(result["plan"], baseline["plan"])
                self.assertEqual(result["objective_value"], 2)
                self.assertEqual(result["evaluation"]["tasks"]["completed_ids"], ["complete-a"])
                partial = evaluate_plan(changed, plan(changed, (["b"], ["m0"])))
                self.assertTrue(partial["valid"])
                self.assertEqual(partial["weighted_relation_coverage"], 0)
        combined = copy.deepcopy(base)
        combined["tasks"].extend(distractors)
        result = solve_reference(combined, objective="task_weighted_edges")
        self.assertEqual(result["plan"], baseline["plan"])
        self.assertEqual(result["objective_value"], 2)

    def test_budget_infeasibility_does_not_remove_migratable_demand_weights(self):
        case = problem(
            ["a", "b", "c"],
            [
                record("left", ["a", "b"], copies=1, preserve=True),
                record("right", ["a", "c"], copies=1, preserve=True),
            ],
            [task("need-both", "a", [["left", "right"]])],
            k=1,
            allowed=[["a", "b"], ["a", "c"]],
        )
        result = solve_reference(case, objective="task_weighted_edges")
        self.assertEqual(result["evaluation"]["tasks"]["eligible_count"], 1)
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 0)
        self.assertEqual(result["objective_value"], 1)
        self.assertEqual(result["evaluation"]["weighted_relation_coverage"], 1)

    def test_more_budget_allows_both_objectives_to_preserve_all_relations(self):
        case = pressure_case(k=2)
        for objective in ("tasks", "edges"):
            result = solve_reference(case, objective=objective)
            self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 1)
        edge = solve_reference(case, objective="edges")
        self.assertEqual(len(edge["evaluation"]["actual"]), 5)
        self.assertEqual(edge["evaluation"]["missing_migratable"], [])
        # Task-only optimization need not retain irrelevant relations on a tie.

    def test_one_copy_can_serve_a_legal_subset_when_full_audience_is_not_required(self):
        case = problem(
            ["a", "b"],
            [record("m", ["a", "b"], copies=1)],
            [task("a-only", "a", [["m"]])],
            allowed=[["a"], ["b"]],
        )
        result = solve_reference(case)
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 1)
        self.assertEqual(result["evaluation"]["copy_counts"], {"m": 1})
        self.assertEqual(result["evaluation"]["actual"], [["a", "m"]])
        self.assertEqual(result["evaluation"]["missing_migratable"], [["b", "m"]])

    def test_preserve_all_readers_applies_to_union_of_copies(self):
        case = problem(
            ["a", "b"],
            [record("m", ["a", "b"], copies=2, preserve=True)],
            [task("a-only", "a", [["m"]])],
            k=2,
            allowed=[["a"], ["b"]],
        )
        good = evaluate_plan(case, plan(case, (["a"], ["m"]), (["b"], ["m"])))
        self.assertTrue(good["valid"])
        self.assertEqual(good["copy_counts"], {"m": 2})
        bad = evaluate_plan(case, plan(case, (["a"], ["m"])))
        self.assertFalse(bad["valid"])
        self.assertIsNone(bad["tasks"]["completed_count"])

    def test_full_audience_plus_single_copy_can_make_object_undeployable(self):
        case = problem(
            ["a", "b"],
            [record("m", ["a", "b"], copies=1, preserve=True)],
            [task("a-only", "a", [["m"]])],
            allowed=[["a"], ["b"]],
        )
        result = solve_reference(case)
        self.assertEqual(result["plan"]["groups"], [])
        self.assertEqual(len(result["evaluation"]["E_migrate"]), 2)
        self.assertEqual(len(result["evaluation"]["missing_migratable"]), 2)
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 0)

    def test_export_and_unknown_denominators_are_separate(self):
        case = problem(
            ["a"],
            [
                record("yes", ["a"]),
                record("no", ["a"], export=False),
                record("unknown-export", ["a"], export=None),
                record("unknown-read", None),
            ],
            [
                task("yes-task", "a", [["yes"]]),
                task("no-task", "a", [["no"]]),
                task("unknown-export-task", "a", [["unknown-export"]]),
                task("unknown-read-task", "a", [["unknown-read"]]),
            ],
        )
        result = solve_reference(case)
        evaluated = result["evaluation"]
        self.assertEqual(len(evaluated["E_read"]), 3)
        self.assertEqual(evaluated["E_migrate"], [["a", "yes"]])
        self.assertEqual(evaluated["tasks"]["declared_count"], 4)
        self.assertEqual(evaluated["tasks"]["eligible_count"], 1)
        self.assertEqual(evaluated["tasks"]["known_read_legal_count"], 3)
        self.assertEqual(evaluated["tasks"]["completed_count"], 1)
        self.assertIn("unknown-read-task", evaluated["tasks"]["unknown_read_task_ids"])
        self.assertIn("no-task", evaluated["tasks"]["non_migratable_task_ids"])
        self.assertEqual(evaluated["missing_migratable"], [])
        for source_id in ("no", "unknown-export", "unknown-read"):
            bad = evaluate_plan(case, plan(case, (["a"], [source_id])))
            self.assertFalse(bad["valid"])
            self.assertIsNone(bad["tasks"]["completed_count"])

    def test_implicit_reader_cannot_disappear_from_safety_or_denominator(self):
        case = problem(
            ["a", "admin"],
            [record("private", ["a"])],
            [task("read", "a", [["private"]])],
            implicit=["admin"],
        )
        result = solve_reference(case)
        self.assertEqual(result["plan"]["groups"], [])
        self.assertEqual(result["evaluation"]["E_migrate"], [["a", "private"]])
        self.assertEqual(result["evaluation"]["missing_migratable"], [["a", "private"]])
        injected = evaluate_plan(case, plan(case, (["a"], ["private"])))
        self.assertFalse(injected["valid"])
        self.assertIn(["admin", "private"], injected["added"])

    def test_independent_sufficient_sets_use_or_of_and_and_count_once(self):
        case = problem(
            ["a"],
            [record("m" + str(i), ["a"]) for i in range(3)],
            [task("alternatives", "a", [["m0", "m1"], ["m2"]], weight=3)],
        )
        one_partial = evaluate_plan(case, plan(case, (["a"], ["m0"])))
        alternative = evaluate_plan(case, plan(case, (["a"], ["m2"])))
        all_sources = evaluate_plan(case, plan(case, (["a"], ["m0", "m1", "m2"])))
        self.assertEqual(one_partial["tasks"]["completed_count"], 0)
        self.assertEqual(alternative["tasks"]["completed_count"], 1)
        self.assertEqual(alternative["tasks"]["completed_weight"], 3)
        self.assertEqual(all_sources["tasks"]["completed_count"], 1)
        self.assertEqual(all_sources["tasks"]["completed_weight"], 3)

    def test_known_unauthorized_task_cannot_earn_utility(self):
        case = problem(
            ["a", "b"],
            [record("private", ["b"])],
            [task("a-illegal", "a", [["private"]])],
        )
        result = solve_reference(case)
        self.assertEqual(result["evaluation"]["tasks"]["known_read_legal_count"], 0)
        self.assertEqual(result["evaluation"]["tasks"]["eligible_count"], 0)
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 0)

    def test_independent_checker_rejects_unsafe_and_malformed_placements(self):
        case = problem(
            ["a", "b"],
            [record("m", ["a"], copies=1)],
            [task("read", "a", [["m"]])],
        )
        bad_plans = [
            plan(case, (["b"], ["m"])),
            plan(case, (["stranger"], ["m"])),
            plan(case, (["a"], ["invented"])),
            plan(case, (["a"], [])),
            plan(case, ([], ["m"])),
            plan(case, (["a"], ["m"]), (["a"], ["m"])),
        ]
        wrong_case = plan(case, (["a"], ["m"]))
        wrong_case["case_id"] = "other-case"
        bad_plans.append(wrong_case)
        for forged in bad_plans:
            with self.subTest(plan=forged):
                evaluated = evaluate_plan(case, forged)
                self.assertFalse(evaluated["valid"])
                self.assertTrue(evaluated["errors"])
                self.assertIsNone(evaluated["tasks"]["completed_count"])

    def test_repeated_plan_identifiers_are_input_errors(self):
        case = problem(["a"], [record("m", ["a"])])
        for malformed in (
            plan(case, (["a", "a"], ["m"])),
            plan(case, (["a"], ["m", "m"])),
        ):
            with self.subTest(plan=malformed):
                with self.assertRaises(ValueError):
                    evaluate_plan(case, malformed)

    def test_checker_counts_groups_and_copies_independently(self):
        case = problem(
            ["a", "b"],
            [record("m", ["a", "b"], copies=1)],
            [task("read", "a", [["m"]])],
            k=1,
        )
        forged = plan(case, (["a"], ["m"]), (["b"], ["m"]))
        evaluated = evaluate_plan(case, forged)
        self.assertFalse(evaluated["valid"])
        self.assertEqual(evaluated["group_count"], 2)
        self.assertEqual(evaluated["copy_counts"], {"m": 2})
        self.assertIsNone(evaluated["tasks"]["completed_count"])

    def test_empty_plan_is_valid_but_does_not_score_as_full_retention(self):
        case = pressure_case(k=0)
        result = solve_reference(case)
        self.assertTrue(result["evaluation"]["valid"])
        self.assertEqual(result["plan"]["groups"], [])
        self.assertEqual(result["evaluation"]["tasks"]["completed_count"], 0)
        self.assertEqual(len(result["evaluation"]["missing_migratable"]), 5)

    def test_search_cutoff_never_claims_optimality(self):
        result = solve_reference(pressure_case(), max_states=1)
        self.assertTrue(result["search_limit_reached"])
        self.assertEqual(result["status"], "feasible_not_proven")
        self.assertTrue(result["evaluation"]["valid"])

    def test_inputs_are_not_mutated(self):
        case = pressure_case()
        frozen = copy.deepcopy(case)
        result = solve_reference(case)
        self.assertEqual(case, frozen)
        frozen_plan = copy.deepcopy(result["plan"])
        evaluate_plan(case, result["plan"])
        self.assertEqual(result["plan"], frozen_plan)
        self.assertEqual(case, frozen)

    def test_reference_and_checker_cannot_connect_to_network(self):
        with patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")) as create:
            with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")) as connect:
                result = solve_reference(pressure_case())
                self.assertTrue(evaluate_plan(pressure_case(), result["plan"])["valid"])
        create.assert_not_called()
        connect.assert_not_called()

    def test_untrusted_or_unknown_contract_fields_are_rejected(self):
        mutations = [
            lambda p: p.update(data_origin="production"),
            lambda p: p["tasks"][0].update(requirement_origin="evaluation_gold"),
            lambda p: p["tasks"][0].update(expected_answer="secret"),
            lambda p: p["target"].update(constraint_origin="product_claim"),
            lambda p: p["target"].update(max_groups=True),
            lambda p: p["records"][0].update(max_target_copies=True),
            lambda p: p["records"][0].update(export_allowed="true"),
            lambda p: p["records"][0].update(preserve_all_readers="false"),
            lambda p: p["tasks"][0].update(weight=True),
            lambda p: p["tasks"][0].update(actor_id="unknown"),
            lambda p: p["tasks"][0].update(required_sets=[["missing"]]),
            lambda p: p["tasks"][0].update(required_sets=[[]]),
            lambda p: p["actors"].append("a"),
        ]
        for mutation in mutations:
            case = pressure_case()
            mutation(case)
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    solve_reference(case)

    def test_solver_rejects_unknown_objective_and_invalid_budget(self):
        for objective in ("new_magic", "", None):
            with self.subTest(objective=objective):
                with self.assertRaises(ValueError):
                    solve_reference(pressure_case(), objective=objective)
        for budget in (0, -1, True):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    solve_reference(pressure_case(), max_states=budget)

    def test_all_two_by_two_matrices_match_independent_physical_oracle(self):
        for matrix in range(16):
            records = [
                record(
                    "m" + str(source),
                    ["ab"[actor] for actor in range(2) if matrix & (1 << (actor * 2 + source))],
                )
                for source in range(2)
            ]
            tasks = [task("t-" + actor, actor, [["m0", "m1"]]) for actor in "ab"]
            for k in range(3):
                expected = physical_rectangle_oracle(matrix, k)
                case = problem(["a", "b"], records, tasks, k=k)
                for objective in ("edges", "tasks", "task_weighted_edges"):
                    with self.subTest(matrix=matrix, k=k, objective=objective):
                        result = solve_reference(case, objective=objective)
                        evaluated = result["evaluation"]
                        self.assertEqual(result["status"], "optimal_in_declared_finite_model")
                        self.assertTrue(evaluated["valid"])
                        actual_score = (
                            evaluated["tasks"]["completed_weight"]
                            if objective == "tasks"
                            else evaluated["weighted_relation_coverage"]
                            if objective == "task_weighted_edges"
                            else len(evaluated["actual"])
                        )
                        self.assertEqual(actual_score, expected[objective])


if __name__ == "__main__":
    unittest.main()
