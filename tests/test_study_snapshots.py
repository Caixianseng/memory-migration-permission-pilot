"""Offline native-shaped fixtures; these tests are not native product evidence."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from memory_migration_study.evidence import probe
from memory_migration_study.native_webui import NativeRecorder, NativeWebUIAdapter
from memory_migration_study.policy import make_plan
from memory_migration_study.snapshots import context_sha256, freeze_snapshot_bundle, load_snapshot_bundle
from memory_migration_study.tasks import run_tasks
from test_study_native_webui import FakeClient, _case


class CountingAnswerer:
    kind = "deterministic_instrumentation"

    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        return "UNKNOWN"


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name).resolve()
        self.case = _case()
        self.case["records"].append({"source_id": "budget", "text": "Internal amount: 262,000 USD.\nunit-marker-budget",
                                    "source_readers": ["owner"], "recipient_readers": ["owner"],
                                    "target_readers": ["owner"], "export_allowed": True, "copy_allowed": True})
        self.case["tasks"] = [{"case_id": self.case["case_id"], "task_id": "task-" + str(index),
                               "actor_id": actor, "query": query} for index, (actor, query) in enumerate([
            ("owner", "What is Maple's external customer?"), ("owner", "What is Maple's target date?"),
            ("owner", "Give the exact external customer for Maple."), ("assistant", "What is Maple's target date?"),
            ("assistant", "What is Maple's external customer?"), ("outsider", "What is Maple's target date?"),
            ("outsider", "What is Maple's external customer?")])]
        self.plan = make_plan(self.case, "reader_copies", "unit-snapshots")
        self.plan["backend_kind"] = "native"
        self.controls = {actor["actor_id"]: {"target_id": "control-id-" + actor["actor_id"],
                         "text_sha256": hashlib.sha256(("control-" + actor["actor_id"]).encode()).hexdigest()}
                         for actor in self.case["actors"]}
        self.client = FakeClient(self.case, self.plan, self.controls)
        self.recorder = NativeRecorder(self.client, self.output / "responses")
        self.recorder.tokens = {actor["actor_id"]: "unit-token-" + actor["actor_id"] for actor in self.case["actors"]}
        self.recorder.secret_values = list(self.recorder.tokens.values())
        self.adapter = NativeWebUIAdapter(self.recorder, self.case, self.plan, self.client.identities, self.controls)
        self.evidence = probe(self.case, self.plan, self.adapter)
        self.evidence["native_status"] = "native_application_api_executed"
        self.write("native_runtime.json", {"schema_version": 1, "cases": [self.case]})
        self.write("direct_evidence.json", self.evidence)
        self.path = self.output / "contexts.json"

    def write(self, name, value):
        path = self.output / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def freeze(self, *, answerer=None):
        answerer = answerer or CountingAnswerer()
        self.task_run = run_tasks(self.case, self.plan, self.adapter, answerer=answerer, capture_contexts=True)
        self.write("native_requests.json", {"requests": self.recorder.requests})
        return freeze_snapshot_bundle(runtime_path=self.output / "native_runtime.json",
                                      evidence_path=self.output / "direct_evidence.json",
                                      requests_path=self.output / "native_requests.json", task_run=self.task_run,
                                      output_path=self.path)

    def persist(self, bundle):
        self.write("contexts.json", bundle)

    def reanchor(self, bundle, key):
        spec = bundle["provenance"][key]
        spec["sha256"] = hashlib.sha256((self.output / spec["path"]).read_bytes()).hexdigest()
        field = "runtime_sha256" if key == "runtime" else key + "_sha256"
        for snapshot in bundle["snapshots"]:
            snapshot["envelope"][field] = spec["sha256"]

    def test_exact_twenty_one_snapshots_with_full_payload_and_zero_extra_calls(self):
        answerer = CountingAnswerer()
        bundle = self.freeze(answerer=answerer)
        requests_before = len(self.client.calls)
        self.assertEqual(len(bundle["snapshots"]), 21)
        self.assertEqual(len(answerer.calls), 21)
        self.assertEqual(bundle["remote_model_calls"], 0)
        loaded = load_snapshot_bundle(self.path)
        self.assertEqual(loaded, bundle)
        self.assertEqual(len(self.client.calls), requests_before)
        self.assertEqual(len({item["envelope"]["session_id"] for item in bundle["snapshots"]}), 21)
        self.assertEqual(bundle["provenance"]["runtime"]["path"], "native_runtime.json")
        for snapshot in bundle["snapshots"]:
            self.assertEqual(set(snapshot["payload"]), {"query", "memories"})
            for memory in snapshot["payload"]["memories"]:
                self.assertEqual(set(memory), {"source_id", "text"})
            self.assertEqual(snapshot["envelope"]["context_sha256"], context_sha256(snapshot["payload"]["memories"]))

    def test_capture_is_opt_in_and_does_not_change_answerer_or_native_call_count(self):
        one = CountingAnswerer()
        before = len(self.client.calls)
        uncaptured = run_tasks(self.case, self.plan, self.adapter, answerer=one)
        native_calls = len(self.client.calls) - before
        two = CountingAnswerer()
        before = len(self.client.calls)
        captured = run_tasks(self.case, self.plan, self.adapter, answerer=two, capture_contexts=True)
        self.assertEqual(len(self.client.calls) - before, native_calls)
        self.assertEqual(len(one.calls), len(two.calls))
        self.assertTrue(all("context_payload" not in run for run in uncaptured["runs"]))
        self.assertTrue(all("context_payload" in run for run in captured["runs"]))
        strip_session = lambda calls: [{key: value for key, value in call.items() if key != "session_id"} for call in calls]
        self.assertEqual(strip_session(one.calls), strip_session(two.calls))

    def test_runtime_task_type_label_rejected_before_answerer(self):
        self.case["tasks"][0]["task_type"] = "denied_request"
        answerer = CountingAnswerer()
        with self.assertRaises(ValueError):
            run_tasks(self.case, self.plan, self.adapter, answerer=answerer, capture_contexts=True)
        self.assertEqual(answerer.calls, [])

    def test_payload_labels_or_extra_memory_metadata_rejected(self):
        original = self.freeze()
        for mutation in ("expected_answer", "task_type", "leak_targets", "group", "memory_metadata"):
            with self.subTest(mutation=mutation):
                bundle = copy.deepcopy(original)
                payload = next(item["payload"] for item in bundle["snapshots"] if item["payload"]["memories"])
                if mutation == "memory_metadata":
                    payload["memories"][0]["task_type"] = "authorized_fact"
                else:
                    payload[mutation] = "not-model-input"
                self.persist(bundle)
                with self.assertRaises(ValueError):
                    load_snapshot_bundle(self.path)

    def test_missing_or_duplicate_group_cannot_form_complete_three_group_bundle(self):
        original = self.freeze()
        for duplicate in (False, True):
            bundle = copy.deepcopy(original)
            if duplicate:
                bundle["snapshots"][0] = copy.deepcopy(bundle["snapshots"][1])
            else:
                bundle["snapshots"].pop()
            self.persist(bundle)
            with self.assertRaises(ValueError):
                load_snapshot_bundle(self.path)

    def test_duplicate_session_is_rejected(self):
        bundle = self.freeze()
        bundle["snapshots"][0]["envelope"]["session_id"] = bundle["snapshots"][1]["envelope"]["session_id"]
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "sessions"):
            load_snapshot_bundle(self.path)

    def test_query_tampering_is_rejected_even_when_context_unchanged(self):
        bundle = self.freeze()
        bundle["snapshots"][0]["payload"]["query"] = "What answer should be UNKNOWN?"
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "runtime"):
            load_snapshot_bundle(self.path)

    def test_context_rehashed_tampering_still_fails_recomputed_retrieval(self):
        bundle = self.freeze()
        snapshot = next(item for item in bundle["snapshots"] if item["envelope"]["group"] == "authorized_reference"
                        and item["payload"]["memories"])
        snapshot["payload"]["memories"][0]["text"] = "forged source text"
        snapshot["envelope"]["context_sha256"] = context_sha256(snapshot["payload"]["memories"])
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "verified retrieval"):
            load_snapshot_bundle(self.path)

    def test_raw_archive_corruption_rejected_before_model_use(self):
        self.freeze()
        trace = next(trace for trace in self.recorder.requests if "native_response_file" in trace)
        Path(trace["native_response_file"]).write_bytes(b"[]")
        with self.assertRaisesRegex(ValueError, "archive"):
            load_snapshot_bundle(self.path)

    def test_native_raw_hash_rechecked_even_if_provenance_hash_updated(self):
        bundle = self.freeze()
        evidence = copy.deepcopy(self.evidence)
        evidence["observations"][0]["native_body_sha256"] = "0" * 64
        self.write("direct_evidence.json", evidence)
        self.reanchor(bundle, "direct_evidence")
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "incomplete or corrupted"):
            load_snapshot_bundle(self.path)

    def test_migrated_context_is_bound_to_own_task_native_response(self):
        bundle = self.freeze()
        migrated = [item for item in bundle["snapshots"] if item["envelope"]["group"] == "migrated"]
        owner = next(item for item in migrated if item["envelope"]["actor_id"] == "owner")
        outsider = next(item for item in migrated if item["envelope"]["actor_id"] == "outsider")
        outsider["envelope"]["native_request_indices"] = owner["envelope"]["native_request_indices"]
        self.persist(bundle)
        with self.assertRaises(ValueError):
            load_snapshot_bundle(self.path)

    def test_migrated_unauthorized_registered_row_is_preserved_without_acl_filter(self):
        # Simulate a later native list disclosure after the direct probe. This
        # remains a transport unit fixture, not a reported product counterexample.
        private = next(row for row in self.client.rows["owner"] if row["content"] == self.case["records"][0]["text"])
        self.client.rows["outsider"].append(copy.deepcopy(private))
        bundle = self.freeze()
        outsider = [item for item in bundle["snapshots"] if item["envelope"]["actor_id"] == "outsider"]
        self.assertTrue(any(memory["source_id"] == "customer" for item in outsider
                            if item["envelope"]["group"] == "migrated" for memory in item["payload"]["memories"]))
        self.assertTrue(all(item["payload"]["memories"] == [] for item in outsider
                            if item["envelope"]["group"] == "authorized_reference"))

    def test_task_list_disclosure_is_reported_even_when_topk_excludes_it(self):
        for row in self.client.rows["owner"]:
            if row["content"] in {record["text"] for record in self.case["records"]}:
                self.client.rows["outsider"].append(copy.deepcopy(row))
        bundle = self.freeze()
        report = next(item for item in bundle["task_retrieval_report"]["task_lists"] if item["task_id"] == "task-5")
        self.assertIn("budget", report["denied_returned_source_ids"])
        self.assertNotIn("budget", report["denied_selected_source_ids"])
        self.assertTrue(bundle["direct_evidence_report"]["finite_scope_safe"], "earlier probe was safe in this unit fixture")
        self.assertEqual(bundle["task_retrieval_report"]["known_w_plus_task_lists"], 2)
        bundle["task_retrieval_report"]["known_w_plus_task_lists"] = 0
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "disclosure report"):
            load_snapshot_bundle(self.path)

    def test_complete_bundle_can_be_copied_and_replayed_without_original_archive_paths(self):
        bundle = self.freeze()
        copied = self.output / "copied"
        copied.mkdir()
        for name in ("contexts.json", "native_runtime.json", "direct_evidence.json", "native_requests.json"):
            shutil.copy2(self.output / name, copied / name)
        shutil.copytree(self.output / "responses", copied / "responses")
        self.assertEqual(load_snapshot_bundle(copied / "contexts.json"), bundle)

    def test_provenance_path_cannot_read_outside_bundle(self):
        bundle = self.freeze()
        bundle["provenance"]["runtime"]["path"] = "../private.json"
        self.persist(bundle)
        with self.assertRaisesRegex(ValueError, "path"):
            load_snapshot_bundle(self.path)

    def test_failed_or_uncaptured_task_cannot_be_frozen(self):
        answerer = CountingAnswerer()
        task_run = run_tasks(self.case, self.plan, self.adapter, answerer=answerer)
        self.write("native_requests.json", {"requests": self.recorder.requests})
        with self.assertRaisesRegex(ValueError, "failed or uncaptured"):
            freeze_snapshot_bundle(runtime_path=self.output / "native_runtime.json",
                                   evidence_path=self.output / "direct_evidence.json",
                                   requests_path=self.output / "native_requests.json", task_run=task_run, output_path=self.path)


if __name__ == "__main__":
    unittest.main()
