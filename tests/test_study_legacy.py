import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.legacy import check_with_legacy
from memory_migration_study.policy import make_plan


_FIXTURE = '''def check_plan_relation(records, containers, subjects, identity_mapping):
    # A sentinel result proves that evaluation delegates to the configured code.
    return {"status": "partial", "fixture_checker_called": True,
            "received": {"records": records, "containers": containers,
                         "subjects": subjects, "identity_mapping": identity_mapping}}
'''


def _case():
    return {"case_id": "legacy-bridge", "actors": [
        {"actor_id": actor, "user_id": "user-" + actor, "agent_id": "agent-" + actor}
        for actor in ("alice", "bob", "eve")],
        "actor_mapping": {actor: "native-" + actor for actor in ("alice", "bob", "eve")},
        "records": [
            {"source_id": "shared", "text": "shared content", "source_readers": ["alice", "bob", "eve"],
             "recipient_readers": ["alice", "bob"], "target_readers": ["alice", "bob"],
             "export_allowed": True, "copy_allowed": True},
            {"source_id": "denied", "text": "denied content", "source_readers": [],
             "recipient_readers": [], "target_readers": [], "export_allowed": True, "copy_allowed": True}]}


class LegacyBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        self.module = self.project / "scripts" / "migration_policy.py"
        self.module.parent.mkdir()
        self.module.write_text(_FIXTURE, encoding="utf-8")
        self.case = _case()
        self.plan = make_plan(self.case, "reader_copies", "legacy-test")

    def check(self, case=None, plan=None):
        return check_with_legacy(self.case if case is None else case,
                                 self.plan if plan is None else plan, self.project)

    def test_not_configured_is_distinct_from_failed_load(self):
        absent = check_with_legacy(self.case, self.plan)
        self.assertEqual(absent["status"], "not_configured")
        self.assertFalse(absent["legacy_loaded"])
        missing = check_with_legacy(self.case, self.plan, self.project / "missing")
        self.assertEqual(missing["status"], "unknown")
        self.assertFalse(missing["legacy_loaded"])
        self.assertIn("FileNotFoundError", missing["issues"][0])

    def test_delegates_multicopy_and_common_deny_with_exact_provenance(self):
        original = self.module.read_bytes()
        result = self.check()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["legacy_checker_called"])
        self.assertTrue(result["legacy_report"]["fixture_checker_called"])
        self.assertEqual(result["module_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(Path(result["module_path"]), self.module.resolve())
        received = result["legacy_report"]["received"]
        self.assertEqual(received["records"], [{"key": "shared", "readers": ["alice", "bob"]},
                                               {"key": "denied", "readers": []}])
        self.assertEqual(len(received["containers"]), 2)
        self.assertEqual(received["identity_mapping"], self.case["actor_mapping"])
        for container in received["containers"]:
            self.assertIn(container["owner"], container["readers"])
            self.assertEqual(container["record_keys"], ["shared"])
        self.assertTrue(result["model_only"])
        self.assertFalse(result["backend_execution_verified_by_this_check"])
        self.assertFalse(result["native_owner_verified"])
        self.assertFalse(result["http_evidence"])
        self.assertEqual(self.module.read_bytes(), original)
        self.assertFalse((self.module.parent / "__pycache__").exists())

    def test_reject_all_delegates_empty_target_inventory(self):
        result = self.check(plan=make_plan(self.case, "reject_all", "reject"))
        self.assertTrue(result["legacy_checker_called"])
        self.assertEqual(result["legacy_inputs"]["containers"], [])
        self.assertEqual(len(result["legacy_inputs"]["records"]), 2)

    def test_unknown_reference_never_becomes_deny(self):
        case = copy.deepcopy(self.case)
        case["records"][0]["recipient_readers"] = None
        plan = make_plan(case, "exact_groups", "unknown")
        result = self.check(case, plan)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["legacy_loaded"])
        self.assertFalse(result["legacy_checker_called"])
        self.assertIsNone(result["legacy_inputs"])
        self.assertEqual({item["subject"] for item in result["unresolved"]}, {"alice", "bob"})

    def test_explicit_deny_can_resolve_missing_other_rule(self):
        case = copy.deepcopy(self.case)
        case["records"][1]["recipient_readers"] = None
        result = self.check(case, make_plan(case, "exact_groups", "deny"))
        self.assertTrue(result["legacy_checker_called"])
        self.assertEqual(result["legacy_inputs"]["records"][1]["readers"], [])

    def test_source_only_ablation_does_not_weaken_common_reference(self):
        plan = make_plan(self.case, "exact_groups", "ablation", source_only=True)
        result = self.check(plan=plan)
        self.assertEqual(result["legacy_inputs"]["records"][0]["readers"], ["alice", "bob"])
        self.assertIn("eve", result["legacy_inputs"]["containers"][0]["readers"])

    def test_identity_collisions_and_missing_fields_are_unknown(self):
        for mutation in ("collision", "mapping_missing", "actor_field_missing"):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.case)
                if mutation == "collision":
                    case["actor_mapping"]["bob"] = case["actor_mapping"]["alice"]
                elif mutation == "mapping_missing":
                    del case["actor_mapping"]["bob"]
                else:
                    del case["actors"][0]["agent_id"]
                result = self.check(case)
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(result["legacy_checker_called"])

    def test_missing_and_colliding_object_mappings_are_unknown(self):
        for mutation in ("missing", "collision", "inventory", "container_mismatch"):
            with self.subTest(mutation=mutation):
                plan = copy.deepcopy(self.plan)
                if mutation == "missing":
                    del plan["object_mapping"]["denied"]
                elif mutation == "collision":
                    plan["object_mapping"]["denied"] = plan["object_mapping"]["shared"][:1]
                elif mutation == "inventory":
                    plan["inventory_complete"] = False
                else:
                    plan["objects"][0]["readers"] = []
                result = self.check(plan=plan)
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(result["legacy_checker_called"])

    def test_nonempty_deny_all_container_is_unsupported(self):
        plan = make_plan(self.case, "exact_groups", "empty-acl")
        plan["containers"][0]["readers"] = []
        plan["objects"][0]["readers"] = []
        result = self.check(plan=plan)
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(result["legacy_checker_called"])
        self.assertIn("implicit_owner", result["issues"][0])

    def test_two_physical_copies_in_same_container_collapse_to_one_relation(self):
        plan = make_plan(self.case, "exact_groups", "same-container")
        replica = dict(plan["objects"][0], target_id="second-copy")
        plan["objects"].append(replica)
        plan["object_mapping"]["shared"].append(replica["target_id"])
        plan["containers"][0]["target_ids"].append(replica["target_id"])
        result = self.check(plan=plan)
        self.assertEqual(result["legacy_inputs"]["containers"][0]["record_keys"], ["shared"])

    def test_configured_checker_failure_does_not_become_safe(self):
        self.module.write_text("def check_plan_relation(**kwargs):\n    raise RuntimeError('fixture')\n", encoding="utf-8")
        result = self.check()
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["legacy_checker_called"])
        self.assertIsNone(result["legacy_report"])

    def test_malformed_object_source_and_checker_report_remain_unknown(self):
        plan = copy.deepcopy(self.plan)
        plan["objects"][0]["source_id"] = []
        self.assertEqual(self.check(plan=plan)["status"], "unknown")
        self.module.write_text("def check_plan_relation(**kwargs):\n    return {'status': []}\n", encoding="utf-8")
        result = self.check()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["issues"], ["malformed_legacy_checker_report"])


_REAL_PROJECT = (Path(__file__).resolve().parents[1]
                 / "memory_migration_permission_149tests_20261021" / "memory_migration_permission_pilot")


@unittest.skipUnless((_REAL_PROJECT / "scripts" / "migration_policy.py").is_file(),
                     "optional user-supplied 149-test project is absent")
class SuppliedLegacyModuleTests(unittest.TestCase):
    def test_real_module_multicopy_deny_and_reject_all(self):
        case = _case()
        exact = check_with_legacy(case, make_plan(case, "reader_copies", "real-exact"), _REAL_PROJECT)
        self.assertEqual(exact["status"], "exact")
        self.assertEqual(exact["legacy_report"]["legal_relations_total"], 2)
        self.assertEqual(exact["legacy_report"]["domain_size"], 6)
        self.assertEqual(exact["legacy_report"]["new_grants"], [])
        blocked = check_with_legacy(case, make_plan(case, "reject_all", "real-reject"), _REAL_PROJECT)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["legacy_report"]["legal_relations_preserved"], 0)
        self.assertEqual(len(blocked["legacy_report"]["lost_grants"]), 2)
        self.assertTrue(blocked["legacy_report"]["no_expansion"])

    def test_real_module_detects_ablation_extra_grant(self):
        case = _case()
        result = check_with_legacy(case, make_plan(case, "exact_groups", "real-ablation", source_only=True), _REAL_PROJECT)
        self.assertEqual(result["status"], "unsafe")
        self.assertEqual(result["legacy_report"]["new_grants"][0]["subject"], "eve")


if __name__ == "__main__":
    unittest.main()
