import copy
import json
import unittest
from pathlib import Path

from memory_migration_study.backend import ReferenceAPI
from memory_migration_study.policy import make_plan
from memory_migration_study.tasks import DeterministicAnswerer, retrieve, run_tasks, score_runs
from test_study_policy import fixture


def evaluation():
    return json.loads((Path(__file__).resolve().parents[1] / "examples/study_demo/evaluation.json").read_text(encoding="utf-8"))["cases"]["delivery_story"]


class TaskTests(unittest.TestCase):
    def run_fixture(self, method="exact_groups", modifier=None, answerer=None):
        case = fixture()
        plan = make_plan(case, method, "tasks")
        if modifier:
            modifier(plan)
        with ReferenceAPI(case, plan) as backend:
            run = run_tasks(case, plan, backend.adapter, answerer=answerer)
        return run, score_runs(run, evaluation())

    def test_three_groups_same_pipeline_fresh_sessions_offline_metrics(self):
        run, scores = self.run_fixture()
        self.assertEqual(len(run["runs"]), 9)
        self.assertEqual(len({r["session_id"] for r in run["runs"]}), 9)
        self.assertEqual(scores["instrumentation_metrics"]["complete_mean_loss"], 0)
        self.assertIsNone(scores["real_llm_metrics"])
        self.assertEqual(scores["instrumentation_metrics"]["groups"]["no_memory"]["correct"], 1)

    def test_seeded_order_repeats_without_reusing_sessions(self):
        one, _ = self.run_fixture()
        two, _ = self.run_fixture()
        self.assertEqual(one["orders"], two["orders"])
        self.assertFalse({r["session_id"] for r in one["runs"]}.intersection(r["session_id"] for r in two["runs"]))

    def test_replicas_reverse_insertion_and_id_remapping_preserve_task_context(self):
        normal, scores = self.run_fixture("reader_copies")
        def reorder(plan):
            plan["objects"].reverse()
            mapping = {}
            for index, obj in enumerate(plan["objects"]):
                old = obj["target_id"]
                obj["target_id"] = "remapped/" + str(index)
                mapping[old] = obj["target_id"]
            for sid, values in plan["object_mapping"].items():
                plan["object_mapping"][sid] = [mapping[v] for v in values]
        reordered, other = self.run_fixture("reader_copies", reorder)
        lookup = lambda run: {(r["task_id"], r["group"]): (r["context_sha256"], r["answer"]) for r in run["runs"]}
        self.assertEqual(lookup(normal), lookup(reordered))
        self.assertEqual(scores["instrumentation_metrics"], other["instrumentation_metrics"])

    def test_retrieval_deduplicates_before_topk_and_stable_ties(self):
        memories = [{"source_id": "b", "text": "fact: two"}, {"source_id": "a", "text": "fact: one"}, {"source_id": "a", "text": "fact: one"}]
        self.assertEqual(retrieve("fact", memories), retrieve("fact", list(reversed(memories))))
        self.assertEqual([m["source_id"] for m in retrieve("fact", memories)], ["a", "b"])

    def test_runtime_labels_rejected_before_answerer(self):
        case = fixture()
        case["tasks"][0]["expected_answer"] = "hidden"
        with self.assertRaises(ValueError):
            run_tasks(case, {}, None)

    def test_answerer_receives_no_evaluation_or_host_paths(self):
        class Guard:
            kind = "deterministic_instrumentation"
            def __call__(self, **kwargs):
                self.assertions.append(set(kwargs))
                text = json.dumps(kwargs)
                if any(key in text for key in ("expected_answer", "forbidden_markers", "judge_spec")):
                    raise AssertionError("hidden label entered answerer")
                return DeterministicAnswerer()(**kwargs)
            assertions = []
        guard = Guard()
        self.run_fixture(answerer=guard)
        self.assertTrue(all(keys == {"query", "memories", "session_id"} for keys in guard.assertions))

    def test_reject_all_retains_preregistered_denom_and_shows_loss(self):
        _, scores = self.run_fixture("reject_all")
        metric = scores["instrumentation_metrics"]
        self.assertEqual(metric["groups"]["migrated"]["preregistered_tasks"], 3)
        self.assertAlmostEqual(metric["complete_mean_loss"], 2 / 3)
        self.assertEqual(metric["authorized_fact_complete_mean_loss"], 1)
        self.assertEqual(metric["groups"]["migrated"]["by_task_type"]["authorized_fact"]["strict_success_rate"], 0)
        self.assertEqual(metric["groups"]["migrated"]["by_task_type"]["denied_request"]["strict_success_rate"], 1)

    def test_failure_is_not_removed_from_pairing_denominator(self):
        class Failing:
            kind = "deterministic_instrumentation"
            def __call__(self, **kwargs):
                raise RuntimeError("failure")
        _, scores = self.run_fixture(answerer=Failing())
        metric = scores["instrumentation_metrics"]
        self.assertIsNone(metric["complete_mean_loss"])
        self.assertEqual(metric["groups"]["migrated"]["failed_or_unknown"], 3)
        self.assertEqual(metric["groups"]["migrated"]["strict_success_rate"], 0)

    def test_loss_can_be_negative(self):
        run, _ = self.run_fixture()
        for result in run["runs"]:
            if result["task_id"] == "delivery_A" and result["group"] == "authorized_reference":
                result["answer"] = "WRONG"
        scores = score_runs(run, evaluation())
        self.assertEqual(next(p for p in scores["instrumentation_metrics"]["paired_tasks"] if p["task_id"] == "delivery_A")["loss"], -1)


if __name__ == "__main__":
    unittest.main()
