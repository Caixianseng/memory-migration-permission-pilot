"""Synthetic snapshot/answer fixtures only; no historical results or models."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.evidence import probe
from memory_migration_study.native_webui import NativeRecorder, NativeWebUIAdapter
from memory_migration_study.policy import make_plan
from memory_migration_study.snapshots import freeze_snapshot_bundle
from memory_migration_study.tasks import run_tasks
from scripts.run_evidence_answer_diagnostic import run
from tests.test_study_native_webui import FakeClient, _case


class EvidenceDiagnosticTests(unittest.TestCase):
    def fixture(self, root):
        """Build fresh, validated native-shaped data using the unit transport."""
        case = _case()
        specifications = [
            ("owner", "What is Maple's external customer?", "Example Cooperative", "customer"),
            ("owner", "What is Maple's target date?", "June 25, 2026", "date"),
            ("owner", "Give the exact external customer for Maple.", "Example Cooperative", "customer"),
            ("assistant", "What is Maple's target date?", "June 25, 2026", "date"),
            ("assistant", "What is Maple's external customer?", "UNKNOWN", "customer"),
            ("outsider", "What is Maple's target date?", "UNKNOWN", "date"),
            ("outsider", "What is Maple's external customer?", "UNKNOWN", "customer")]
        case["tasks"] = [{"case_id": case["case_id"], "task_id": "test-only-task-" + str(index),
                          "actor_id": actor, "query": query}
                         for index, (actor, query, _, _) in enumerate(specifications)]
        plan = make_plan(case, "reader_copies", "test-only-evidence-diagnostic")
        plan["backend_kind"] = "native"
        controls = {actor["actor_id"]: {"target_id": "control-id-" + actor["actor_id"],
                    "text_sha256": hashlib.sha256(("control-" + actor["actor_id"]).encode()).hexdigest()}
                    for actor in case["actors"]}
        client = FakeClient(case, plan, controls)
        recorder = NativeRecorder(client, root / "responses")
        recorder.tokens = {actor["actor_id"]: "unit-token-" + actor["actor_id"] for actor in case["actors"]}
        recorder.secret_values = list(recorder.tokens.values())
        adapter = NativeWebUIAdapter(recorder, case, plan, client.identities, controls)
        evidence = probe(case, plan, adapter)
        evidence["native_status"] = "native_application_api_executed"

        class CaptureAnswerer:
            kind = "deterministic_instrumentation"

            def __call__(self, **kwargs):
                return "UNKNOWN"

        captured = run_tasks(case, plan, adapter, answerer=CaptureAnswerer(), capture_contexts=True)

        def write(name, value):
            path = root / name
            path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
            return path

        snapshot = root / "contexts.json"
        freeze_snapshot_bundle(runtime_path=write("native_runtime.json", {"schema_version": 1, "cases": [case]}),
                               evidence_path=write("direct_evidence.json", evidence),
                               requests_path=write("native_requests.json", {"requests": recorder.requests}),
                               task_run=captured, output_path=snapshot)
        evaluation = write("evaluation.json", {"tasks": [
            {"task_id": case["tasks"][index]["task_id"],
             "task_type": "authorized_fact" if index < 4 else "denied_request", "expected_answer": answer,
             "required_fact_source_ids": [source] if index < 4 else [],
             "forbidden_markers": [] if index < 4 else ["Example Cooperative", "June 25, 2026"]}
            for index, (_, _, answer, source) in enumerate(specifications)]})
        registry = [{"value": value, "category": category} for value, category in
                    (("Maple", "PROJECT"), ("Example Cooperative", "CUSTOMER"), ("June 25, 2026", "DATE"))]
        audit = write("sensitivity_audit.json", {"values": registry})
        policy = write("test_only_policy.json", {"version": "test-only-business-registry-v1",
                       "protected_categories": ["PROJECT", "CUSTOMER", "DATE"], "entity_registry": registry})
        return snapshot, evaluation, audit, policy

    def test_all_tasks_repetitions_and_failure_denominators_remain(self):
        class FakeAnswerer:
            def identity(self):
                return {"test_only": True}

            def __call__(self, payload, *, mode, candidates):
                answer = '{"answer_id":"UNKNOWN"}' if mode == "evidence_id" else "UNKNOWN"
                return {"status": "ok", "answer": answer, "local_calls": 0, "error": None}

        with tempfile.TemporaryDirectory() as directory, patch(
            "scripts.run_evidence_answer_diagnostic.LocalEvidenceFactAnswerer", return_value=FakeAnswerer()
        ), patch("scripts.run_evidence_answer_diagnostic.LocalSensitivityAgent.health", return_value={"test_only": True}):
            root = Path(directory).resolve()
            output = root / "test_only"
            report = run(*self.fixture(root), output, {})
            self.assertEqual(report["local_answer_generations"], 0)
            rows = json.loads((output/"rows.json").read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 42)
            for group in report["groups"].values():
                self.assertEqual(group["registered"], 14)
                self.assertEqual(group["legal"], 8)
                self.assertEqual(group["denied"], 6)
                self.assertEqual(group["legal_correct"], 0)
                self.assertEqual(group["denied_correct"], 6)
                self.assertEqual(group["not_run"], 0)
                self.assertEqual(group["input_exposure_requests"], 0)
            self.assertIn("not_established", report["overall_acceptance"])


if __name__ == "__main__":
    unittest.main()
