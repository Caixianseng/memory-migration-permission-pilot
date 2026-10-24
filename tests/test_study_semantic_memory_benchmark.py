"""Whole-pipeline tests with tiny authored inputs, never the study heldout set."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import semantic_memory_benchmark as benchmark
from memory_migration_study.coverage_memory import verify_coverage_certificate
from memory_migration_study.memory_labels import MemoryLabelAuthority
from memory_migration_study.query_intent import INTENT_VERSION, query_sha256


CANARY = "SCORING_ONLY_NEVER_SEND_TO_MODELS_8841"
OUTSIDER_QUERY = "OUTSIDER_ONLY_621: name the customer."


def fixture():
    text = "Customer: Cedar Foundry; Status: approved; Contact: relay@sample.test."
    source = {"source_id": "authored-fixture-source", "text": text}
    tasks = [{"task_id": "name", "actor_id": "owner", "query": "Who is the customer?"},
             {"task_id": "status", "actor_id": "owner", "query": "What is the status?"},
             {"task_id": "repeat", "actor_id": "owner", "query": "For Cedar Foundry, what is the status?"},
             {"task_id": "mail", "actor_id": "owner", "query": "What is the contact email?"},
             {"task_id": "outsider", "actor_id": "outsider", "query": OUTSIDER_QUERY}]
    runtime = [{"story_id": "authored-fixture", "language": "en", "template_family": "integration-only",
                "source": source, "tasks": tasks,
                "policy": {"version": "typed-fixture", "protected_categories": ["CUSTOMER", "EMAIL"],
                           "instructions": "Customer names and contact emails are sensitive."}}]
    evaluation = {"authored-fixture": {"answers": {"name": "Cedar Foundry", "status": "approved",
                   "repeat": "approved", "mail": "relay@sample.test"},
                   "sensitive_spans": [{"start": text.index(v), "end": text.index(v)+len(v)}
                                       for v in ("Cedar Foundry", "relay@sample.test")],
                   "scoring_only_canary": CANARY}}
    return runtime, evaluation


def candidate_spans(text):
    result = []
    for value, category in (("Cedar Foundry", "CUSTOMER"), ("relay@sample.test", "EMAIL")):
        for match in re.finditer(re.escape(value), text):
            result.append({"start": match.start(), "end": match.end(), "category": category})
    return result


class FakeNerRuntime:
    identity = {"model_id": "injected-test-instrument", "weights_sha256": "0"*64}
    initialization_seconds = 0.0

    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def infer(self, text, labels, **options):
        self.calls.append({"text": text, "labels": copy.deepcopy(labels), "options": options})
        if self.fail:
            raise RuntimeError("injected local failure")
        names = {"CUSTOMER": "organization", "EMAIL": "email"}
        entities = {label: [] for label in labels}
        for span in candidate_spans(text):
            label = names[span["category"]]
            if label in entities:
                entities[label].append({"text": text[span["start"]:span["end"]],
                    "start": span["start"], "end": span["end"], "confidence": .99})
        return {"entities": entities}


class FakeModelBuilder:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        text = kwargs["text"]
        return {"status": "needs_review" if self.fail else "ok", "builder_version": "injected_builder_v1",
                "local_calls": 1, "elapsed_seconds": 0.0, "errors": ["semantic_uncertainty"] if self.fail else [],
                # Deliberately retain candidates on failure, ensuring the runner
                # must consult the build status before creating signed records.
                "facts": [{"text": text, "source_start": 0, "source_end": len(text), "findings": candidate_spans(text)}]}


class FakeAnswerer:
    def __init__(self):
        self.calls = []

    def __call__(self, payload):
        self.calls.append(copy.deepcopy(payload))
        query = payload["query"].casefold()
        text = "\n".join(m["text"] for m in payload["memories"])
        if "email" in query:
            match = re.search(r"Contact: (.+?)\.$", text)
        elif "status" in query:
            match = re.search(r"Status: (.+?); Contact:", text)
        else:
            match = re.search(r"Customer: (.+?); Status:", text)
        return {"status": "ok", "answer": match.group(1) if match else "UNKNOWN",
                "local_calls": 1, "elapsed_seconds": 0.0, "error": None}


class FakeClassifier:
    def __init__(self):
        self.calls = []

    def __call__(self, *, query, request_id):
        self.calls.append({"query": query, "request_id": request_id})
        intent = "EMAIL" if "email" in query.casefold() else "STATUS" if "status" in query.casefold() else "CUSTOMER"
        return {"status": "ok", "intent": intent, "query_sha256": query_sha256(query),
                "request_id": request_id, "version": INTENT_VERSION, "source": "local_classifier",
                "local_calls": 1, "elapsed_seconds": 0.0, "error": None}


class SemanticMemoryBenchmarkTests(unittest.TestCase):
    def run_fixture(self, *, model_failure=False, ner_failure=False, poisoned_answers=False):
        runtime, evaluation = fixture()
        if poisoned_answers:
            for key in evaluation["authored-fixture"]["answers"]:
                evaluation["authored-fixture"]["answers"][key] = CANARY
        model, ner = FakeModelBuilder(model_failure), FakeNerRuntime(ner_failure)
        answerer, classifier, access, progress = FakeAnswerer(), FakeClassifier(), [], []
        original_access = MemoryLabelAuthority.validate_access

        def real_access(authority, record, **kwargs):
            result = original_access(authority, record, **kwargs)
            access.append({"actor_id": kwargs["actor_id"], "result": result})
            return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            split = root / "corpus/development"
            split.mkdir(parents=True)
            (split / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            (split / "evaluation.json").write_text(json.dumps(evaluation), encoding="utf-8")
            with patch.object(benchmark, "LocalNerRuntime", return_value=ner), \
                 patch.object(benchmark, "LocalMemoryBuilder", return_value=model), \
                 patch.object(benchmark, "LocalFactAnswerer", return_value=answerer), \
                 patch.object(benchmark, "LocalQueryIntentClassifier", return_value=classifier), \
                 patch.object(benchmark.LocalSensitivityAgent, "health", return_value=None) as health, \
                 patch.object(MemoryLabelAuthority, "validate_access", new=real_access):
                report = benchmark.run(root / "corpus", root / "output", "no-model-assets", {}, progress=progress.append)
                health.assert_called_once_with()
            output = root / "output"
            rows = json.loads((output / "rows.json").read_text(encoding="utf-8"))
            builds = json.loads((output / "builds.json").read_text(encoding="utf-8"))
            stores = json.loads((output / "record_store.json").read_text(encoding="utf-8"))
            self.assertTrue((output / "index.html").is_file())
            self.assertEqual(benchmark.aggregate(rows, builds), report["arms"])
            self.assertEqual(report["model_builder_generations"], sum(b["local_calls"] for b in builds if b["builder"] == "model"))
            self.assertEqual(report["coverage_builder_encoder_calls"], sum(b["local_calls"] for b in builds if b["builder"] == "coverage"))
            self.assertEqual(report["query_intent_generations"], len(classifier.calls))
            self.assertEqual(report["migration_encoder_calls"], sum(r["detector_calls"] for r in rows))
            self.assertEqual(report["answer_generations"], len(answerer.calls))
            for row in rows:
                expected = evaluation[row["story_id"]]["answers"].get(row["task_id"])
                correct = row["actor_id"] == "owner" and isinstance(row["final_answer"], str) and row["final_answer"].strip().casefold() == expected.casefold()
                self.assertEqual(row["score"]["correct"], correct)
                self.assertEqual(row["score"], benchmark.score(row, evaluation[row["story_id"]]))
            captured = {"builder": model.calls, "detector": ner.calls, "answerer": answerer.calls, "classifier": classifier.calls}
            self.assertNotIn(CANARY, json.dumps(captured))
            self.assertNotIn('"sensitive_spans"', json.dumps(captured))
            self.assertNotIn('"answers"', json.dumps(captured))
            return report, rows, builds, stores, captured, access, progress

    def test_one_story_five_tasks_six_arms_and_real_authority_denial(self):
        report, rows, builds, stores, captured, access, progress = self.run_fixture()
        self.assertEqual(len(rows), 30)
        self.assertEqual({(r["task_id"], r["arm"]) for r in rows},
                         {(task, arm) for task in ("name", "status", "repeat", "mail", "outsider") for arm in benchmark.ARMS})
        self.assertEqual(len(builds), 2)
        self.assertEqual(len(captured["classifier"]), 4)
        self.assertEqual(len(captured["answerer"]), 24)
        self.assertEqual(report["model_builder_generations"], 1)
        self.assertEqual(report["coverage_builder_encoder_calls"], 1)
        self.assertEqual(report["query_intent_generations"], 4)
        self.assertEqual(report["migration_encoder_calls"], 36)
        for arm, metrics in report["arms"].items():
            self.assertEqual(metrics["registered_tasks"], 5)
            self.assertEqual(metrics["legal_tasks"], 4)
            self.assertEqual(metrics["ready"], 4)
            self.assertEqual(metrics["correct"], 4)
            self.assertEqual(metrics["restoration_failure"], 0)
            self.assertEqual(metrics["true_model_unknown"], 0)
            self.assertEqual(metrics["outsider_blocked"], 1)
            self.assertEqual(metrics["unauthorized_output"], 0)
            outsider = next(r for r in rows if r["arm"] == arm and r["actor_id"] == "outsider")
            self.assertEqual(outsider["module_authorization_error"], "principal_not_authorized")
            self.assertEqual(outsider["detector_calls"], 0)
            self.assertEqual(outsider["answer_calls"], 0)
        self.assertEqual(len([event for event in access if event["actor_id"] == "outsider"]), 6)
        self.assertTrue(all(event["result"] == "principal_not_authorized" for event in access if event["actor_id"] == "outsider"))
        self.assertNotIn(OUTSIDER_QUERY, json.dumps(captured))
        self.assertEqual(progress[-1]["completed"], 30)
        self.assertEqual(progress[-1]["expected"], 30)
        self.assertEqual(report["cloud_calls"], 0)

    def test_model_build_failure_keeps_all_rows_and_does_not_deploy_candidates(self):
        report, rows, builds, stores, captured, access, _ = self.run_fixture(model_failure=True)
        self.assertEqual(len(rows), 30)
        model_rows = [r for r in rows if r["arm"] == "model_build_migration"]
        self.assertEqual(len(model_rows), 5)
        self.assertEqual(report["arms"]["model_build_migration"]["build_block"], 4)
        self.assertEqual(report["arms"]["model_build_migration"]["ready"], 0)
        self.assertEqual(report["arms"]["model_build_migration"]["build_successes"], 0)
        self.assertEqual(report["arms"]["model_build_migration"]["stored_characters"], 0)
        self.assertEqual(next(s for s in stores if s["builder"] == "model")["records"], [])
        self.assertEqual(len(captured["answerer"]), 20)
        self.assertEqual(len(captured["classifier"]), 4)
        # No record exists for that failed builder; do not call a host precheck
        # an observed authority rejection. The other five arms really deny it.
        self.assertFalse(next(r for r in model_rows if r["actor_id"] == "outsider")["score"]["outsider_blocked"])
        self.assertEqual(len([e for e in access if e["actor_id"] == "outsider"]), 5)

    def test_failed_coverage_is_not_stored_or_reported_as_success(self):
        report, rows, builds, stores, captured, _, _ = self.run_fixture(model_failure=True, ner_failure=True)
        self.assertEqual(len(rows), 30)
        self.assertEqual(captured["classifier"], [])
        self.assertEqual(captured["answerer"], [])
        coverage = next(b for b in builds if b["builder"] == "coverage")
        self.assertEqual(coverage["status"], "needs_review")
        self.assertGreater(coverage["coverage"]["retained_characters"], 0)
        self.assertTrue(coverage["coverage"]["all_non_whitespace_covered"])
        self.assertTrue(verify_coverage_certificate(fixture()[0][0]["source"]["text"], coverage["coverage"]))
        self.assertEqual(coverage["stored_characters"], 0)
        self.assertTrue(all(s["records"] == [] for s in stores))
        for metrics in report["arms"].values():
            self.assertEqual(metrics["legal_tasks"], 4)
            self.assertEqual(metrics["build_block"], 4)
            self.assertEqual(metrics["correct"], 0)
            self.assertEqual(metrics["supported_legal_tasks"], 0)
            self.assertEqual(metrics["build_successes"], 0)

    def test_poisoned_scoring_answers_change_scores_without_entering_models(self):
        report, rows, _, _, captured, _, _ = self.run_fixture(poisoned_answers=True)
        self.assertEqual(len(rows), 30)
        self.assertEqual(len(captured["answerer"]), 24)
        self.assertEqual(len(captured["classifier"]), 4)
        for metrics in report["arms"].values():
            self.assertEqual(metrics["correct"], 0)
            self.assertEqual(metrics["supported_legal_tasks"], 0)
            self.assertEqual(metrics["ready"], 4)


if __name__ == "__main__":
    unittest.main()
