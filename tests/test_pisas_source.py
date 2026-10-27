"""Synthetic source-only importer tests: no dataset, scoring file or network."""
from copy import deepcopy
import inspect
import json
import pickle
import unittest
from unittest.mock import patch

from memory_migration_study import pisas_source as source


def scenario():
    return {"scenario_id": "source-secret-id", "task": {"description": "Summarize the task.", "type": "oracle-task"},
        "cast": {"c1": {"name": "Maya Chen", "role": "Manager", "team": "Platform", "task_slot": "executor"},
                 "c2": {"name": "Val", "role": "Engineer", "team": "Platform", "participant": True}},
        "org": {"internal": "oracle-org"}, "timeline": [
            {"id": "secret-artifact-A", "timestamp": "2026-01-01", "type": "chat", "author": "people_ops_system",
             "visible_to": ["Maya Chen"], "attributes": {"answer": "oracle-attribute"}, "reveals": ["oracle-reveals"],
             "content": "Original secret: Alice / 12345.\nKeep attributes and reveals in this sentence."},
            {"id": "secret-artifact-B", "visible_to": ["Val", "Maya Chen"], "content": "Public task status: open."}]}


class PiSAsSourceTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        for target in ("socket.socket", "socket.create_connection", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("network_forbidden"))
            self.guards.append(guard.start())
            self.addCleanup(guard.stop)

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def test_only_one_source_argument_and_no_oracle_metadata_in_model_view(self):
        self.assertEqual(list(inspect.signature(source.project_source).parameters), ["scenario"])
        raw = scenario()
        raw["utility"] = {"decision_rule": "oracle-answer"}
        raw["cast"]["c1"]["visibility"] = "oracle-cast"
        raw["timeline"][0]["appropriateness"] = "oracle-judgement"
        view = source.project_source(raw)["model_view"]
        serialized = json.dumps(view)
        for excluded in ("oracle-", "source-secret-id", "secret-artifact", "task_slot", "visible_to", "people_ops_system"):
            self.assertNotIn(excluded, serialized)
        self.assertEqual(set(view), {"task", "cast", "memories"})
        self.assertEqual(view["memories"][0]["content"], raw["timeline"][0]["content"])
        self.assertEqual([m["source_id"] for m in view["memories"]], ["m_0001", "m_0002"])

    def test_actor_filters_whole_objects_by_source_acl_not_author_or_cast_key(self):
        projected = source.project_source(scenario())
        view = source.build_actor_view(projected, "Val")
        self.assertEqual([m["source_id"] for m in view["model_view"]["memories"]], ["m_0002"])
        self.assertEqual(view["qualification"]["excluded_object_count"], 1)
        self.assertEqual(len(source.build_actor_view(projected, "Maya Chen")["model_view"]["memories"]), 2)
        for invalid in ("c1", "people_ops_system", "maya chen", "Unknown", "*"):
            with self.subTest(actor=invalid), self.assertRaisesRegex(source.SourceError, "unknown_actor"):
                source.build_actor_view(projected, invalid)

    def test_empty_task_is_pending_and_never_completed_from_extra_answer(self):
        raw = scenario(); raw["task"] = {"description": "", "decision_rule": "ANSWER"}
        projected = source.project_source(raw)
        self.assertEqual(projected["model_view"]["task"]["description"], "")
        self.assertEqual(projected["qualification"]["status"], "needs_task_description")
        self.assertFalse(projected["qualification"]["evaluation_used"])
        self.assertEqual(source.build_actor_view(projected, "Val")["qualification"]["status"], "needs_task_description")

    def test_list_cast_is_supported_without_changing_content_or_input(self):
        raw = scenario(); raw["cast"] = list(raw["cast"].values()); before = deepcopy(raw)
        projected = source.project_source(raw)
        source.build_actor_view(projected, "Val")
        self.assertEqual(raw, before)
        self.assertEqual(projected["model_view"]["memories"][0]["content"], before["timeline"][0]["content"])

    def test_duplicate_ids_names_and_acl_members_fail_closed(self):
        for kind in ("artifact", "name", "acl"):
            raw = scenario()
            if kind == "artifact": raw["timeline"][1]["id"] = raw["timeline"][0]["id"]
            if kind == "name": raw["cast"]["c2"]["name"] = raw["cast"]["c1"]["name"]
            if kind == "acl": raw["timeline"][0]["visible_to"] *= 2
            with self.subTest(kind=kind), self.assertRaisesRegex(source.SourceError, "duplicate_"):
                source.project_source(raw)

    def test_unknown_or_malformed_acl_never_becomes_public(self):
        for acl in (["c1"], ["*"], ["Nobody"], "Maya Chen", None):
            raw = scenario(); raw["timeline"][0]["visible_to"] = acl
            with self.subTest(acl=acl), self.assertRaises(source.SourceError):
                source.project_source(raw)
        raw = scenario()
        for item in raw["timeline"]: item["visible_to"] = []
        view = source.build_actor_view(source.project_source(raw), "Maya Chen")
        self.assertEqual(view["model_view"]["memories"], [])
        self.assertEqual(view["qualification"]["visible_object_count"], 0)

    def test_tampered_hash_content_acl_and_additional_keys_rejected(self):
        for kind in ("hash", "content", "acl", "extra"):
            projected = source.project_source(scenario())
            if kind == "hash": projected["source_sha256"] = "0"*64
            if kind == "content": projected["model_view"]["memories"][0]["content"] = "changed"
            if kind == "acl": projected["host_objects"][0]["visible_to"].append("Val")
            if kind == "extra": projected["utility"] = {"answer": "oracle"}
            with self.subTest(kind=kind), self.assertRaisesRegex(source.SourceError, "projection_integrity_mismatch"):
                source.build_actor_view(projected, "Val")

    def test_same_model_ids_cannot_mix_across_sources_or_reuse_capability(self):
        first = source.project_source(scenario())
        raw = scenario(); raw["scenario_id"] = "different-source"; raw["timeline"][0]["content"] = "different content"
        second = source.project_source(raw)
        self.assertNotEqual(first["source_sha256"], second["source_sha256"])
        self.assertEqual(first["model_view"]["memories"][0]["source_id"], second["model_view"]["memories"][0]["source_id"])
        second["host_objects"] = deepcopy(first["host_objects"])
        with self.assertRaisesRegex(source.SourceError, "projection_integrity_mismatch"):
            source.build_actor_view(second, "Maya Chen")
        forged = {key: deepcopy(value) for key, value in first.items() if key != "_capability"}
        with self.assertRaisesRegex(source.SourceError, "invalid_projection_capability"):
            source.build_actor_view(forged, "Maya Chen")

    def test_actor_views_cannot_be_reused_to_expand_access_and_do_not_alias_source(self):
        projected = source.project_source(scenario())
        actor_view = source.build_actor_view(projected, "Val")
        with self.assertRaisesRegex(source.SourceError, "complete_source_projection_required"):
            source.build_actor_view(actor_view, "Maya Chen")
        actor_view["model_view"]["cast"][0]["name"] = "changed"
        self.assertEqual(projected["model_view"]["cast"][0]["name"], "Maya Chen")
        self.assertEqual(len(source.build_actor_view(projected, "Val")["model_view"]["memories"]), 1)

    def test_capability_is_not_serializable_and_source_hash_covers_ignored_metadata(self):
        raw = scenario(); first = source.project_source(raw)
        raw["timeline"][0]["reveals"] = ["different-oracle"]
        second = source.project_source(raw)
        self.assertEqual(first["model_view"], second["model_view"])
        self.assertNotEqual(first["source_sha256"], second["source_sha256"])
        with self.assertRaises(TypeError): json.dumps(first)
        with self.assertRaises(TypeError): pickle.dumps(first["_capability"])


if __name__ == "__main__":
    unittest.main()
