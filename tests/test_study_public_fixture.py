import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from memory_migration_study.policy import decision, make_plan
from memory_migration_study.public_fixture import CASE_ID, EPISODE, SpanInstrumentationAnswerer, prepare_controlled_fixture
from memory_migration_study.tasks import retrieve, validate_runtime


_ROOT = Path(__file__).resolve().parents[1]
_PROJECT = _ROOT / "memory_migration_permission_149tests_20261021/memory_migration_permission_pilot"
_SOURCE = Path("results/public_acl_feasibility_2026-10-18/source_run_01")
_EPISODES = Path("datasets/benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data/office/episodes.jsonl")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


@unittest.skipUnless((_PROJECT / _SOURCE / "source_result.json").is_file() and (_PROJECT / _EPISODES).is_file(),
                     "optional user-supplied public source execution is absent")
class PublicFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.project = self.base / "relocated-project"
        self.source = self.project / _SOURCE
        self.source.mkdir(parents=True)
        sr = _read(_PROJECT / _SOURCE / "source_result.json")
        for name in ["source_result.json", *sr["files"]]:
            shutil.copyfile(_PROJECT / _SOURCE / name, self.source / name)
        (self.project / _EPISODES).parent.mkdir(parents=True)
        shutil.copyfile(_PROJECT / _EPISODES, self.project / _EPISODES)
        self.output = self.base / "prepared"

    def prepare(self):
        manifest = prepare_controlled_fixture(self.project, self.output)
        return manifest, _read(self.output / "runtime.json"), _read(self.output / "evaluation.json"), _read(self.output / "provenance.json")

    def refresh_policy_hash(self, policy):
        _write(self.source / "controlled_policy.json", policy)
        sr = _read(self.source / "source_result.json")
        sr["files"]["controlled_policy.json"] = hashlib.sha256((self.source / "controlled_policy.json").read_bytes()).hexdigest()
        _write(self.source / "source_result.json", sr)

    def test_exact_episode_source_content_actors_and_seven_tasks(self):
        manifest, runtime, evaluation, provenance = self.prepare()
        self.assertEqual(manifest["qualification"], "controlled_machine_checked_fact_spans")
        self.assertEqual(manifest["independent_stories"], 1)
        self.assertEqual(manifest["natural_acl_qualified"], 0)
        self.assertIsNone(manifest["human_review"])
        self.assertIsNone(manifest["real_llm"])
        self.assertEqual(len(runtime["cases"]), 1)
        case = runtime["cases"][0]
        self.assertEqual(case["case_id"], CASE_ID)
        self.assertEqual(len(case["records"]), 3)
        self.assertEqual(len(case["tasks"]), 7)
        self.assertEqual({actor["agent_id"] for actor in case["actors"]}, {"memory_worker"})
        self.assertEqual([actor["user_id"] for actor in case["actors"]],
                         ["pm_ava_lin", "assistant_erin_blake", "employee_nina_torres"])
        policy = _read(self.source / "controlled_policy.json")
        self.assertEqual({record["source_id"]: record["text"] for record in case["records"]},
                         {record["source_id"]: record["content"] for record in policy["records"]})
        for record in case["records"]:
            self.assertEqual(record["source_readers"], record["recipient_readers"])
            self.assertEqual(record["source_readers"], record["target_readers"])
        labels = evaluation["cases"][CASE_ID]["tasks"]
        self.assertEqual(sum(label["task_type"] == "authorized_fact" for label in labels), 4)
        self.assertEqual(sum(label["task_type"] == "denied_request" for label in labels), 3)
        self.assertEqual(provenance["episode_id"], EPISODE)
        self.assertEqual(provenance["source_observations"]["read_pairs_checked_from_bodies"], 9)
        self.assertFalse(provenance["new_experiment_grants"]["upstream_original_grant_claimed"])
        self.assertEqual(provenance["identity_binding"]["agent_binding"], "application_level_only")
        self.assertIn(str(self.project), provenance["public_episode_file"])
        self.assertEqual(make_plan(case, "reader_copies", "traceable")["method"], "reader_copies")

    def test_fact_offsets_hashes_and_output_manifest_are_mechanically_reproducible(self):
        manifest, _, evaluation, _ = self.prepare()
        policy = _read(self.source / "controlled_policy.json")
        by_key = {record["key"]: record for record in policy["records"]}
        facts = evaluation["cases"][CASE_ID]["fact_anchors"]
        for key, anchor in facts.items():
            text = by_key[key]["original_text"]
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), anchor["original_text_sha256"])
            self.assertEqual(text[anchor["span"]["start"]:anchor["span"]["end"]], anchor["fact"])
        for name, entry in manifest["files"].items():
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), entry["sha256"])

    def test_all_source_artifact_hashes_are_checked(self):
        path = self.source / "per_reader_copy_1.json"
        path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact hash mismatch"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_changed_original_rejected_even_with_updated_artifact_and_text_hash(self):
        policy = _read(self.source / "controlled_policy.json")
        record = policy["records"][0]
        record["original_text"] = record["original_text"].replace("Granite Mutual", "Invented Customer")
        record["original_text_sha256"] = hashlib.sha256(record["original_text"].encode()).hexdigest()
        record["content"] = record["original_text"] + "\n" + record["marker"]
        self.refresh_policy_hash(policy)
        with self.assertRaisesRegex(ValueError, "natural text differs"):
            self.prepare()

    def test_changed_text_hash_and_marker_are_rejected(self):
        original = _read(self.source / "controlled_policy.json")
        for mutation in ("hash", "marker"):
            with self.subTest(mutation=mutation):
                policy = copy.deepcopy(original)
                if mutation == "hash":
                    policy["records"][0]["original_text_sha256"] = "0" * 64
                else:
                    policy["records"][0]["content"] += "rewritten"
                self.refresh_policy_hash(policy)
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_future_turns_and_hidden_labels_do_not_enter_runtime(self):
        policy = _read(self.source / "controlled_policy.json")
        policy["expected_answer"] = "HIDDEN-LABEL-CANARY"
        policy["records"][0]["judge_spec"] = {"hidden": "HIDDEN-JUDGE-CANARY"}
        self.refresh_policy_hash(policy)
        (self.project / _EPISODES).parent.joinpath("checkpoints.jsonl").write_text(
            '{"expected_answer":"BENCHMARK-CANARY"}', encoding="utf-8")
        _, runtime, evaluation, provenance = self.prepare()
        text = json.dumps(runtime)
        validate_runtime(runtime)
        for marker in ("expected_answer", "judge_spec", "forbidden_markers", "HIDDEN-LABEL-CANARY",
                       "HIDDEN-JUDGE-CANARY", "BENCHMARK-CANARY", "fact_anchors", "episode_file"):
            self.assertNotIn(marker, text)
        episodes = [json.loads(line) for line in (self.project / _EPISODES).read_text(encoding="utf-8").splitlines() if line.strip()]
        episode = next(episode for episode in episodes if episode["episode_id"] == EPISODE)
        future = next(turn for turn in episode["turns"] if turn["turn_id"] == "t010")
        self.assertNotIn(future["text"], text)
        self.assertFalse(provenance["future_turns_used"])
        for task in runtime["cases"][0]["tasks"]:
            self.assertEqual(set(task), {"case_id", "task_id", "actor_id", "query"})
            for anchor in evaluation["cases"][CASE_ID]["fact_anchors"].values():
                self.assertNotIn(anchor["fact"], task["query"])

    def test_source_response_body_mismatch_rejected_despite_pass_flags(self):
        sr = _read(self.source / "source_result.json")
        owner_read = next(q for q in sr["requests"] if q["viewer"] == "owner" and q["path"].startswith("/source/records/"))
        owner_read["body"]["memory"] = "wrong content"
        _write(self.source / "source_result.json", sr)
        with self.assertRaisesRegex(ValueError, "authorized read"):
            self.prepare()

    def test_denied_source_response_content_is_rejected(self):
        sr = _read(self.source / "source_result.json")
        policy = _read(self.source / "controlled_policy.json")
        denied = next(q for q in sr["requests"] if q["viewer"] == "assistant" and q["http"] == 403)
        denied["body"]["unexpected"] = policy["records"][0]["content"]
        _write(self.source / "source_result.json", sr)
        with self.assertRaisesRegex(ValueError, "unauthorized content"):
            self.prepare()

    def test_denied_source_response_json_key_content_is_rejected(self):
        sr = _read(self.source / "source_result.json")
        policy = _read(self.source / "controlled_policy.json")
        denied = next(q for q in sr["requests"] if q["viewer"] == "assistant" and q["http"] == 403)
        denied["body"][policy["records"][0]["content"]] = "key-only disclosure"
        _write(self.source / "source_result.json", sr)
        with self.assertRaisesRegex(ValueError, "unauthorized content"):
            self.prepare()

    def test_output_must_be_new_and_source_archive_stays_unchanged(self):
        paths = list(self.source.glob("*.json")) + [self.project / _EPISODES]
        before = {path: path.read_bytes() for path in paths}
        self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_span_answerer_uses_only_supplied_context_and_returns_unknown_without_fact(self):
        _, runtime, evaluation, _ = self.prepare()
        case = runtime["cases"][0]
        answerer = SpanInstrumentationAnswerer()
        self.assertEqual(answerer.kind, "deterministic_instrumentation")
        labels = {label["task_id"]: label for label in evaluation["cases"][CASE_ID]["tasks"]}
        for task in case["tasks"]:
            permitted = [{"source_id": record["source_id"], "text": record["text"]}
                         for record in case["records"] if decision(record, task["actor_id"]) == "allow"]
            context = retrieve(task["query"], permitted)
            self.assertEqual(answerer(query=task["query"], memories=context, session_id="fresh"),
                             labels[task["task_id"]]["expected_answer"])
            self.assertEqual(answerer(query=task["query"], memories=[], session_id="fresh"), "UNKNOWN")
        with self.assertRaises(TypeError):
            answerer(query="customer", memories=[], session_id="fresh", evaluation=evaluation)
        # New values are extracted from context; the expected public answers are not embedded in the answerer.
        self.assertEqual(answerer(query="What is Maple's exact customer?", memories=[
            {"source_id": "only-context", "text": "For Maple, the exact external customer is Example Cooperative, but that mapping stays inside."}],
            session_id="fresh"), "Example Cooperative")


if __name__ == "__main__":
    unittest.main()
