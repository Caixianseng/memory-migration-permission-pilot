import copy
import json
import unittest
from pathlib import Path

from memory_migration_study.policy import decision, make_plan, validate_case


def fixture():
    return copy.deepcopy(json.loads((Path(__file__).resolve().parents[1] / "examples/study_demo/runtime.json").read_text(encoding="utf-8"))["cases"][0])


class PolicyTests(unittest.TestCase):
    def test_conjunction_local_rule_restricts_source_allow(self):
        record = fixture()["records"][2]
        self.assertEqual(decision(record, "C", source_only=True), "allow")
        self.assertEqual(decision(record, "C"), "deny")

    def test_missing_rule_unknown_but_explicit_deny_dominates(self):
        record = fixture()["records"][0]
        record.pop("recipient_readers")
        self.assertEqual(decision(record, "B"), "unknown")
        self.assertEqual(decision(record, "C"), "deny")

    def test_shared_user_does_not_inherit_private_agent_right(self):
        case = fixture()
        self.assertEqual(case["actors"][0]["user_id"], case["actors"][1]["user_id"])
        self.assertEqual(decision(case["records"][1], "B"), "deny")

    def test_collision_and_missing_identity_mapping_rejected(self):
        case = fixture()
        case["actor_mapping"]["B"] = case["actor_mapping"]["A"]
        with self.assertRaises(ValueError):
            validate_case(case)
        case = fixture()
        del case["actor_mapping"]["C"]
        with self.assertRaises(ValueError):
            validate_case(case)

    def test_duplicate_user_agent_binding_rejected(self):
        case = fixture()
        case["actors"][1]["agent_id"] = case["actors"][0]["agent_id"]
        with self.assertRaises(ValueError):
            validate_case(case)

    def test_export_and_copy_qualification_are_independent(self):
        case = fixture()
        case["records"][0]["export_allowed"] = False
        case["records"][1]["copy_allowed"] = False
        exact = make_plan(case, "exact_groups", "one")
        copies = make_plan(case, "reader_copies", "two")
        self.assertEqual(exact["object_mapping"]["delivery_date"], [])
        self.assertTrue(exact["object_mapping"]["private_code"])
        self.assertEqual(copies["object_mapping"]["private_code"], [])
        self.assertEqual(decision(case["records"][0], "B"), "allow")

    def test_copy_names_are_unique_across_runs_and_readers(self):
        case = fixture()
        first = make_plan(case, "reader_copies", "one")
        second = make_plan(case, "reader_copies", "two")
        self.assertEqual(len(first["object_mapping"]["delivery_date"]), 2)
        self.assertFalse(set(o["target_id"] for o in first["objects"]).intersection(o["target_id"] for o in second["objects"]))

    def test_reject_all_does_not_shrink_reference(self):
        case = fixture()
        plan = make_plan(case, "reject_all", "rejected")
        self.assertFalse(plan["objects"])
        self.assertEqual(set(plan["object_mapping"]), {r["source_id"] for r in case["records"]})
        self.assertEqual(decision(case["records"][0], "B"), "allow")


if __name__ == "__main__":
    unittest.main()
