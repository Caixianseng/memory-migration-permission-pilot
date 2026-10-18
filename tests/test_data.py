import json
import tempfile
import unittest
from pathlib import Path

from memory_migration_pilot.data import discover_data_root, load_bundle


class DataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.root = self.workspace / "datasets/datasets"
        self.synthetic = self.root / "synthetic/synthetic_corpus.json"
        self.synthetic.parent.mkdir(parents=True)
        self.groups = self.workspace / "groups.json"
        self.groups.write_text(json.dumps({"groups": {"project_a": ["alice", "bob"]}}), encoding="utf-8")

    def write_synthetic(self, entries):
        self.synthetic.write_text(json.dumps({"meta": {"subjects": ["alice", "bob", "eve"]}, "entries": entries}), encoding="utf-8")

    @staticmethod
    def entry(source_id, acl=None, state="active"):
        return {"entry_id": source_id, "R": ["alice"] if acl is None else acl, "state": state, "text": f"text:{source_id}"}

    def load_synthetic(self, **kwargs):
        return load_bundle(self.root, "synthetic", group_config=self.groups, **kwargs)

    @staticmethod
    def subject(episode_id, principal_id):
        return json.dumps(["office", episode_id, principal_id], separators=(",", ":"), ensure_ascii=False)

    def test_discover_nested_dataset_root(self):
        self.write_synthetic([])
        self.assertEqual(discover_data_root(self.workspace), self.root)
        self.assertEqual(discover_data_root(self.synthetic), self.root)

    def test_group_expansion_and_unknown_acl_are_fail_closed(self):
        self.write_synthetic([
            self.entry("group", ["project_a", "eve"]),
            self.entry("unknown-user", ["alice", "mallory"]),
            self.entry("unknown-group", ["project_missing"]),
        ])
        bundle = self.load_synthetic(limit=0)
        self.assertEqual([record["id"] for record in bundle["records"]], ["group"])
        self.assertEqual(bundle["records"][0]["allowed_users"], ["alice", "bob", "eve"])
        self.assertEqual(bundle["audit"]["excluded_by_reason"]["unknown_acl_principal_or_group"], 2)

    def test_group_config_is_required_and_unknown_group_members_reject_record(self):
        self.write_synthetic([self.entry("group", ["project_a"]), self.entry("user")])
        with self.assertRaises(ValueError):
            load_bundle(self.root, "synthetic")
        self.groups.write_text(json.dumps({"groups": {"project_a": ["alice", "mallory"]}}), encoding="utf-8")
        bundle = self.load_synthetic(limit=0)
        self.assertEqual([record["id"] for record in bundle["records"]], ["user"])
        self.assertEqual(bundle["audit"]["excluded_by_reason"]["invalid_group_member"], 1)

    def test_state_filtering(self):
        self.write_synthetic([self.entry(state, state=state) for state in ["active", "updated", "deleted", "expired", "mystery"]])
        bundle = self.load_synthetic(limit=0)
        self.assertEqual({x["id"] for x in bundle["records"]}, {"active", "updated"})
        self.assertEqual(bundle["audit"]["excluded_by_reason"], {"state_deleted": 1, "state_expired": 1, "unknown_state": 1})

    def test_limit_is_deterministic_and_independent_of_file_order(self):
        entries = [self.entry(str(i)) for i in range(30)]
        self.write_synthetic(entries)
        first = self.load_synthetic(limit=7, seed=5)["records"]
        self.write_synthetic(entries[::-1])
        second = self.load_synthetic(limit=7, seed=5)["records"]
        self.assertEqual(first, second)
        self.assertNotEqual(first, self.load_synthetic(limit=7, seed=6)["records"])
        self.assertEqual(len(self.load_synthetic(limit=0)["records"]), 30)

    def write_gatemem(self, expected_action="refuse", include_invalid=False):
        base = self.root / "benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data/office"
        base.mkdir(parents=True, exist_ok=True)
        turns = [
            {"turn_id": "t2", "turn_kind": "dialogue", "speaker": {"principal_id": "alice", "role": "employee"}, "text": "earlier turn"},
            {"turn_id": "t10", "turn_kind": "dialogue", "speaker": {"principal_id": "bob", "role": "manager"}, "text": "boundary turn"},
            {"turn_id": "t1", "turn_kind": "dialogue", "speaker": {"principal_id": "alice", "role": "employee"}, "text": "FUTURE MUST NOT APPEAR"},
        ]
        if include_invalid:
            turns = [
                {"turn_id": "bad1", "turn_kind": "dialogue", "text": "missing speaker"},
                {"turn_id": "bad2", "turn_kind": "dialogue", "speaker": {"principal_id": "agent", "role": "agent"}, "text": "agent text"},
                {"turn_id": "bad3", "turn_kind": "dialogue", "speaker": {"principal_id": "alice", "role": "manager"}, "text": "inconsistent identity"},
            ] + turns
        episode = {"episode_id": "episode1", "entities": {"principals": [
            {"principal_id": "alice", "role": "employee"}, {"principal_id": "bob", "role": "manager"}, {"principal_id": "agent", "role": "agent"}
        ]}, "turns": turns}
        checkpoint = {"checkpoint_id": "checkpoint1", "episode_id": "episode1", "as_of_turn_id": "t10", "asker": {"principal_id": "bob", "role": "manager"}, "expected_action": expected_action, "judge_spec": {"secret": "ANSWER MUST NOT APPEAR"}, "leak_targets": ["LEAK TARGET MUST NOT APPEAR"], "query_text": "QUERY MUST NOT APPEAR"}
        later_checkpoint = dict(checkpoint, checkpoint_id="checkpoint2", as_of_turn_id="t1")
        (base / "episodes.jsonl").write_text(json.dumps(episode) + "\n", encoding="utf-8")
        (base / "checkpoints.jsonl").write_text(json.dumps(checkpoint) + "\n" + json.dumps(later_checkpoint) + "\n", encoding="utf-8")

    def test_gatemem_prefix_uses_position_and_excludes_reference_answers(self):
        self.write_gatemem()
        bundle = load_bundle(self.root, "gatemem", limit=0, domains=("office",))
        self.assertEqual({x["id"] for x in bundle["records"]}, {"episode1:t2", "episode1:t10"})
        self.assertEqual(bundle["subjects"], [self.subject("episode1", "alice"), self.subject("episode1", "bob")])
        for record in bundle["records"]:
            self.assertEqual(record["allowed_users"], [self.subject("episode1", record["source_ref"]["raw_speaker_id"])])
        serialized = json.dumps(bundle["records"])
        for marker in ["FUTURE MUST NOT APPEAR", "ANSWER MUST NOT APPEAR", "LEAK TARGET MUST NOT APPEAR", "QUERY MUST NOT APPEAR", "expected_action", "judge_spec"]:
            self.assertNotIn(marker, serialized)
        self.assertIn("controlled", bundle["policy_origin"])

    def test_gatemem_expected_action_cannot_change_policy(self):
        self.write_gatemem(expected_action="refuse")
        first = load_bundle(self.root, "gatemem", limit=0, domains=("office",))
        self.write_gatemem(expected_action="answer")
        second = load_bundle(self.root, "gatemem", limit=0, domains=("office",))
        self.assertEqual(first["records"], second["records"])
        self.assertEqual(first["policy_origin"], second["policy_origin"])

    def test_gatemem_uncertain_speakers_are_excluded(self):
        self.write_gatemem(include_invalid=True)
        bundle = load_bundle(self.root, "gatemem", limit=0, domains=("office",))
        self.assertEqual(len(bundle["records"]), 2)
        self.assertEqual(bundle["audit"]["excluded_by_reason"], {
            "missing_speaker": 1, "unknown_or_nonhuman_speaker": 1, "speaker_role_mismatch": 1,
        })
        self.assertEqual(len(bundle["input_files"]), 2)
        self.assertTrue(all(len(x["sha256"]) == 64 for x in bundle["input_files"]))

    def test_gatemem_episode_limit_does_not_add_other_episode_subjects(self):
        self.write_gatemem()
        base = self.root / "benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data/office"
        episode = {"episode_id": "episode2", "entities": {"principals": [
            {"principal_id": "other_episode_user", "role": "employee"}
        ]}, "turns": [{
            "turn_id": "second_t1", "turn_kind": "dialogue",
            "speaker": {"principal_id": "other_episode_user", "role": "employee"},
            "text": "other episode",
        }]}
        checkpoint = {"checkpoint_id": "second_checkpoint", "episode_id": "episode2", "as_of_turn_id": "second_t1", "asker": {"principal_id": "other_episode_user", "role": "employee"}}
        with (base / "episodes.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(episode) + "\n")
        with (base / "checkpoints.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(checkpoint) + "\n")
        first = load_bundle(self.root, "gatemem", limit=0, domains=("office",))
        self.assertEqual(first["subjects"], [self.subject("episode1", "alice"), self.subject("episode1", "bob")])
        self.assertEqual(first["audit"]["available_episodes"], 2)
        self.assertEqual(first["audit"]["selected_episodes"], 1)
        self.assertEqual(first["audit"]["selected_prefix_raw_turns"], 2)
        self.assertEqual(first["audit"]["episodes_not_selected"], 1)
        self.assertEqual(first["audit"]["excluded_by_reason"], {})
        for selection in (0, None):
            all_episodes = load_bundle(self.root, "gatemem", limit=0, domains=("office",), episodes_per_domain=selection)
            self.assertEqual(all_episodes["subjects"], [
                self.subject("episode1", "alice"), self.subject("episode1", "bob"),
                self.subject("episode2", "other_episode_user"),
            ])
            self.assertEqual(all_episodes["audit"]["selected_episodes"], 2)
            self.assertEqual(all_episodes["audit"]["selected_prefix_raw_turns"], 3)

    def test_gatemem_matching_raw_ids_are_scoped_to_episode(self):
        self.write_gatemem()
        base = self.root / "benchmarks/migration_public_2026-10-18/gatemem/raw/bench/data/office"
        episode = {"episode_id": "episode2", "entities": {"principals": [
            {"principal_id": "alice", "role": "employee"}
        ]}, "turns": [{
            "turn_id": "t1", "turn_kind": "dialogue",
            "speaker": {"principal_id": "alice", "role": "employee"}, "text": "different Alice",
        }]}
        checkpoint = {"checkpoint_id": "second_checkpoint", "episode_id": "episode2", "as_of_turn_id": "t1", "asker": {"principal_id": "alice", "role": "employee"}}
        with (base / "episodes.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(episode) + "\n")
        with (base / "checkpoints.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(checkpoint) + "\n")
        bundle = load_bundle(self.root, "gatemem", limit=0, domains=("office",), episodes_per_domain=0)
        self.assertEqual(len(bundle["subjects"]), 3)
        alice_records = [record for record in bundle["records"] if record["source_ref"]["raw_speaker_id"] == "alice"]
        self.assertEqual(len(alice_records), 2)
        self.assertEqual({record["allowed_users"][0] for record in alice_records}, {
            self.subject("episode1", "alice"), self.subject("episode2", "alice"),
        })


if __name__ == "__main__":
    unittest.main()
