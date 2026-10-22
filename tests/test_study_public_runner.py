import copy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from memory_migration_study.cli import main
from memory_migration_study.public_runner import run_public_pilot
from memory_migration_study.runner import run_demo
from memory_migration_study.tasks import DeterministicAnswerer


EXAMPLES = Path(__file__).resolve().parents[1] / "examples/study_demo"


def inputs():
    runtime = json.loads((EXAMPLES / "runtime.json").read_text(encoding="utf-8"))
    evaluation = json.loads((EXAMPLES / "evaluation.json").read_text(encoding="utf-8"))
    case = runtime["cases"][0]
    return {"cases": [copy.deepcopy(case)]}, {"cases": {case["case_id"]: copy.deepcopy(evaluation["cases"][case["case_id"]])}}


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class PublicRunnerTests(unittest.TestCase):
    def test_explicit_instrumentation_answerer_is_never_reported_as_real_llm(self):
        runtime, evaluation = inputs()
        with TemporaryDirectory() as folder:
            root = Path(folder)
            save(root / "runtime.json", runtime)
            save(root / "evaluation.json", evaluation)
            report = run_demo(root / "run", runtime_path=root / "runtime.json",
                              evaluation_path=root / "evaluation.json", answerer=DeterministicAnswerer())
            manifest = report["manifest"]
            self.assertEqual(manifest["answerer_kind"], "deterministic_instrumentation")
            self.assertEqual(manifest["remote_model_calls"], 0)
            self.assertEqual(manifest["paid_model_status"], "not_run")
            self.assertIsNone(manifest["real_llm_metrics"])
            self.assertIn("paid_model_calls", manifest["not_run"])
            targets = [r for r in report["results"] if r["tasks"]]
            self.assertTrue(targets)
            self.assertTrue(all(r["tasks"]["instrumentation_metrics"] is not None and
                                r["tasks"]["real_llm_metrics"] is None for r in targets))

    def test_public_pilot_writes_counts_and_explicit_reference_scope(self):
        runtime, evaluation = inputs()
        prepared = []
        def prepare(project, output):
            prepared.append((project, output))
            output.mkdir()
            save(output / "runtime.json", runtime)
            save(output / "evaluation.json", evaluation)
            save(output / "provenance.json", {"episode_id": "public-example", "natural_acl_qualified": 0})
        with TemporaryDirectory() as folder:
            root = Path(folder)
            legacy = root / "legacy"
            legacy.mkdir()
            with patch("memory_migration_study.public_fixture.prepare_controlled_fixture", side_effect=prepare), \
                 patch("memory_migration_study.public_fixture.SpanInstrumentationAnswerer", return_value=DeterministicAnswerer()):
                summary = run_public_pilot(legacy, root / "pilot", seed=17)
            self.assertEqual(prepared, [(legacy.resolve(), (root / "pilot/fixture").resolve())])
            self.assertEqual(summary["counts"], {"public_episodes": 1, "independent_stories": 1,
                                               "controlled_memories": 3, "tasks": 3,
                                               "authorized_fact_tasks": 2, "denied_request_tasks": 1})
            self.assertEqual(summary["seed"], 17)
            self.assertEqual(summary["remote_model_calls"], 0)
            self.assertFalse(summary["native_execution_performed"])
            self.assertIsNone(summary["real_llm_metrics"])
            self.assertEqual(summary["natural_authorization_qualification"], 0)
            self.assertEqual(len(summary["conditions"]), 6)
            saved = json.loads((root / "pilot/summary.json").read_text(encoding="utf-8"))
            self.assertEqual(saved, summary)
            index = (root / "pilot/index.html").read_text(encoding="utf-8")
            self.assertIn("未调用真实大模型", index)
            self.assertIn("公开 episode：1", index)
            self.assertIn("fixture/provenance.json", index)
            self.assertIn("reference_run/report.json", index)
            self.assertEqual(summary["reference_manifest"]["qualification"], summary["qualification"])
            sentinel = root / "pilot/keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                run_public_pilot(legacy, root / "pilot")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_cli_forwards_public_paths_seed_without_a_model_connector(self):
        counts = {"public_episodes": 1, "tasks": 7}
        with patch("memory_migration_study.cli.run_public_pilot", return_value={"counts": counts}) as run, \
             patch("memory_migration_study.cli.ChatCompletionsConnector") as connector, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["public-pilot", "--legacy-project", "legacy", "--output", "new", "--seed", "23"]), 0)
        run.assert_called_once_with(Path("legacy"), Path("new"), seed=23)
        connector.assert_not_called()
        stdout = json.loads(output.getvalue())
        self.assertEqual(stdout["counts"], counts)
        self.assertFalse(stdout["real_llm_run"])
        self.assertFalse(stdout["native_execution_performed"])


if __name__ == "__main__":
    unittest.main()
