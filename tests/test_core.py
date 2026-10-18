"""Independent security checks of the local reference experiment.

These tests exercise only the in-repository SQLite/HTTP backend.  They do not
constitute vendor-product tests or independent real-world security scenarios.
"""

import copy
import tempfile
import unittest
from pathlib import Path

from memory_migration_pilot.core import (
    LocalAPI,
    ReferenceStore,
    candidate_probes,
    collect_source_truth,
    default_mapping,
    make_plan,
    run_budget_audit,
    run_full_audit,
)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.counter = 0
        self.subjects = ["alice", "bob", "outsider"]
        self.records = [
            {"id": "alice-note", "text": "ALICE-私有内容", "allowed_users": ["alice"]},
            {"id": "bob-note", "text": "BOB-private", "allowed_users": ["bob"]},
            {"id": "shared-note", "text": "SHARED-project", "allowed_users": ["alice", "bob"]},
        ]

    def store(self, role="target", fault="none"):
        self.counter += 1
        store = ReferenceStore(
            Path(self.temp.name) / f"store-{self.counter}.sqlite",
            role,
            f"deployment-{self.counter}",
            fault=fault,
        )
        self.addCleanup(store.close)
        return store

    def api(self, store, subjects):
        api = LocalAPI(store, subjects)
        self.addCleanup(api.close)
        return api

    def source(self, records=None):
        records = self.records if records is None else records
        store = self.store("source")
        store.seed_source(records)
        api = self.api(store, self.subjects)
        truth, evidence = collect_source_truth(api, self.subjects, records)
        return store, api, truth, evidence

    def target(self, plan=None, records=None, publish=True, fault="none"):
        records = self.records if records is None else records
        plan = make_plan(records, self.subjects, "acl_grouping") if plan is None else plan
        store = self.store(fault=fault)
        manifest = store.stage_target(records, plan)
        if publish:
            store.publish(manifest)
        api = self.api(store, list(plan["mapping"].values()))
        return store, api, plan, manifest

    def test_unlimited_correct_baselines_preserve_full_matrix(self):
        _, _, truth, _ = self.source()
        for method in ["acl_grouping", "per_item_reject", "selective_groups"]:
            with self.subTest(method=method):
                plan = make_plan(self.records, self.subjects, method)
                self.assertEqual(plan["state"], "exact")
                self.assertEqual(plan["retained_ids"], sorted(r["id"] for r in self.records))
                self.assertFalse(plan["is_new_algorithm"])
                _, api, _, _ = self.target(plan)
                report = run_full_audit(api, self.subjects, self.records, plan["mapping"], truth)
                self.assertEqual(report["unauthorized_disclosures"], 0)
                self.assertEqual(report["content_errors"], 0)
                self.assertEqual(report["legal_access_retention"], 1.0)
                self.assertEqual(report["indeterminate_requests"], 0)

    def test_same_acl_reuses_one_dataset(self):
        records = self.records + [{"id": "alice-second", "text": "another", "allowed_users": ["alice"]}]
        plan = make_plan(records, self.subjects, "acl_grouping")
        self.assertEqual(len(plan["containers"]), 3)
        group = next(g for g in plan["containers"] if g["source_acl"] == ["alice"])
        self.assertEqual(set(group["record_ids"]), {"alice-note", "alice-second"})

    def test_zero_quota_loses_legal_access_instead_of_omitting_denominator(self):
        _, _, truth, _ = self.source()
        plan = make_plan(self.records, self.subjects, "selective_groups", max_datasets=0)
        self.assertEqual(plan["state"], "blocked")
        self.assertEqual(plan["retained_legal_reads"], 0)
        self.assertEqual(plan["total_legal_reads"], 4)
        _, api, _, _ = self.target(plan)
        report = run_full_audit(api, self.subjects, self.records, plan["mapping"], truth)
        self.assertEqual(report["known_legal_cells"], 8)  # read and list each evaluated
        self.assertEqual(report["legal_access_retention"], 0.0)
        self.assertEqual(report["unauthorized_disclosures"], 0)

    def test_simulated_capacity_and_simple_value_sorting_are_explicit(self):
        records = [
            {"id": "a", "text": "a", "allowed_users": ["alice"]},
            *[{"id": f"b{i}", "text": f"b{i}", "allowed_users": ["bob"]} for i in range(3)],
            {"id": "s", "text": "s", "allowed_users": ["alice", "bob"]},
        ]
        batch = make_plan(records, self.subjects, "acl_grouping", 1)
        sequential = make_plan(records, self.subjects, "per_item_reject", 1)
        selected = make_plan(records, self.subjects, "selective_groups", 1)
        self.assertEqual(batch["state"], "blocked")
        self.assertEqual(sequential["retained_ids"], ["a"])
        self.assertEqual(selected["retained_ids"], ["b0", "b1", "b2"])
        self.assertEqual(selected["retained_legal_reads"], 3)
        self.assertEqual(selected["resource_constraint_origin"], "synthetic_stress_only")
        self.assertFalse(selected["is_new_algorithm"])

    def test_missing_collision_and_foreign_identity_mappings_rejected(self):
        good = default_mapping(self.subjects)
        bad_cases = [
            {k: v for k, v in good.items() if k != "bob"},
            {**good, "bob": good["alice"]},
            {**good, "bob": "foreign_tenant|bob"},
            {**good, "bob": "target_lab|"},
        ]
        for mapping in bad_cases:
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                make_plan(self.records, self.subjects, "acl_grouping", mapping=mapping)

    def test_bad_record_acl_or_duplicate_id_is_not_a_safe_empty_policy(self):
        cases = [
            [{"id": "x", "text": "x"}],
            [{"id": "x", "text": "x", "allowed_users": ["mallory"]}],
            self.records + [copy.deepcopy(self.records[0])],
        ]
        for records in cases:
            with self.subTest(records=records), self.assertRaises(ValueError):
                make_plan(records, self.subjects, "acl_grouping")

    def test_duplicate_acl_members_do_not_inflate_legal_read_value(self):
        records = [{"id": "x", "text": "x", "allowed_users": ["alice", "alice"]}]
        with self.assertRaises(ValueError):
            make_plan(records, self.subjects, "selective_groups")

    def test_http_credentials_and_identity_override_are_enforced(self):
        store = self.store("source")
        store.seed_source(self.records)
        api = self.api(store, self.subjects)
        for token in [None, "not-a-registered-token"]:
            status, body = api.raw_request("/memories", token)
            self.assertEqual(status, 401)
            self.assertNotIn("items", body)
        for key in ["user", "user_id", "actor", "tenant"]:
            status, body = api.raw_request(f"/memories/bob-note?{key}=bob", api.tokens["alice"])
            self.assertEqual(status, 400)
            self.assertNotIn("text", body)
        self.assertEqual(api.request("alice", "read", "bob-note")[0], 404)
        self.assertEqual(api.request("bob", "read", "bob-note")[0], 200)

    def test_outsider_and_unknown_object_never_disclose(self):
        _, api, plan, _ = self.target()
        outsider = plan["mapping"]["outsider"]
        self.assertEqual(api.request(outsider, "list"), (200, {"items": []}))
        for memory_id in [r["id"] for r in self.records] + ["' OR '1'='1", "../bob-note"]:
            status, body = api.request(outsider, "read", memory_id)
            self.assertEqual(status, 404)
            self.assertNotIn("text", body)

    def test_unsupported_operation_is_not_silently_read(self):
        _, api, plan, _ = self.target()
        with self.assertRaises(ValueError):
            api.request(plan["mapping"]["alice"], "search", "alice-note")

    def test_staged_objects_invisible_even_with_list_fault(self):
        for fault in ["none", "list_acl_bypass"]:
            with self.subTest(fault=fault):
                store, api, plan, manifest = self.target(publish=False, fault=fault)
                for user in plan["mapping"].values():
                    self.assertEqual(api.request(user, "list"), (200, {"items": []}))
                    for record in self.records:
                        self.assertEqual(api.request(user, "read", record["id"])[0], 404)
                store.publish(manifest)
                self.assertEqual(api.request(plan["mapping"]["alice"], "read", "alice-note")[0], 200)

    def test_manifest_changes_cannot_reuse_admission(self):
        store, api, plan, manifest = self.target(publish=False)
        for field, value in [
            ("deployment_id", "other-deployment"),
            ("policy_version", "static-v2"),
            ("mapping", {**manifest["mapping"], "alice": "target_lab|outsider"}),
            ("tenant", "another_tenant"),
            ("contents", {**manifest["contents"], "alice-note": "changed-hash"}),
        ]:
            altered = copy.deepcopy(manifest)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                store.publish(altered)
            self.assertEqual(api.request(plan["mapping"]["alice"], "read", "alice-note")[0], 404)
        store.publish(manifest)

    def test_staged_content_or_acl_tampering_prevents_publish(self):
        for kind in ["content", "acl"]:
            with self.subTest(kind=kind):
                store, api, plan, manifest = self.target(publish=False)
                with store.lock, store.conn:
                    if kind == "content":
                        store.conn.execute("UPDATE records SET body=? WHERE id=?", ("changed", "alice-note"))
                    else:
                        group = next(g for g in plan["containers"] if g["source_acl"] == ["alice"])
                        store.conn.execute("INSERT INTO dataset_acl VALUES(?,?)", (group["id"], plan["mapping"]["bob"]))
                with self.assertRaises(ValueError):
                    store.publish(manifest)
                self.assertEqual(api.request(plan["mapping"]["alice"], "list"), (200, {"items": []}))

    def test_list_fault_is_a_labeled_negative_control_and_read_only_misses_it(self):
        _, _, truth, _ = self.source()
        _, api, plan, _ = self.target(fault="list_acl_bypass")
        read_only = run_budget_audit(api, self.subjects, self.records, plan["mapping"], truth,
                                     "read_only", budget=100)
        self.assertEqual(read_only["counterexamples"], [])
        self.assertEqual(read_only["status"], "unknown")
        self.assertEqual(read_only["untested_requests"], len(self.subjects))
        full = run_full_audit(api, self.subjects, self.records, plan["mapping"], truth)
        self.assertGreater(full["unauthorized_disclosures"], 0)
        self.assertEqual(full["status"], "counterexample_found")
        self.assertTrue(all(x["operation"] == "list" for x in full["counterexamples"]))

    def test_budget_zero_and_partial_budget_remain_unknown(self):
        _, _, truth, _ = self.source()
        _, api, plan, _ = self.target()
        total = len(candidate_probes(self.subjects, self.records))
        for budget in [0, 1, 3]:
            before = api.calls
            report = run_budget_audit(api, self.subjects, self.records, plan["mapping"], truth,
                                      "fixed", budget=budget)
            self.assertEqual(report["status"], "unknown")
            self.assertEqual(report["actual_api_calls"], budget)
            self.assertEqual(api.calls - before, budget)
            self.assertEqual(report["untested_requests"], total - budget)
            self.assertGreater(report["unknown_cell_fraction"], 0)

    def test_one_list_call_covers_many_cells_but_costs_one_request(self):
        _, _, truth, _ = self.source()
        _, api, plan, _ = self.target()
        # Fixed order: three alice reads followed by one alice list.
        before = api.calls
        report = run_budget_audit(api, self.subjects, self.records, plan["mapping"], truth,
                                  "fixed", budget=4)
        self.assertEqual(api.calls - before, 4)
        self.assertEqual(report["actual_api_calls"], 4)
        self.assertEqual(report["covered_cells"], 6)
        self.assertEqual(report["history"][-1]["operation"], "list")
        self.assertEqual(len(report["history"][-1]["checked_ids"]), len(self.records))
        self.assertEqual(report["status"], "unknown")

    def test_full_budget_can_only_clear_the_declared_finite_domain(self):
        _, _, truth, _ = self.source()
        _, api, plan, _ = self.target()
        total = len(candidate_probes(self.subjects, self.records))
        for strategy in ["fixed", "random", "rule_coverage", "migration_relation", "enumerate"]:
            with self.subTest(strategy=strategy):
                before = api.calls
                report = run_budget_audit(api, self.subjects, self.records, plan["mapping"], truth,
                                          strategy, budget=total + 10)
                self.assertEqual(api.calls - before, total)
                self.assertEqual(report["actual_api_calls"], total)
                self.assertEqual(report["untested_requests"], 0)
                self.assertEqual(report["unknown_cell_fraction"], 0.0)
                self.assertEqual(report["status"], "no_counterexample_in_finite_domain")
                probes = [(x["user"], x["operation"], x["memory_id"]) for x in report["history"]]
                self.assertEqual(len(probes), len(set(probes)))

    def test_transport_failure_is_unknown_not_authorization_denial(self):
        class FailedAPI:
            def request(self, *_args):
                return 599, {"error": "simulated_transport_failure"}

        truth = {(u, r["id"]): u in r["allowed_users"] for u in self.subjects for r in self.records}
        report = run_budget_audit(FailedAPI(), self.subjects, self.records,
                                  default_mapping(self.subjects), truth, "fixed", 2)
        self.assertEqual(report["indeterminate_requests"], 2)
        self.assertEqual(report["covered_cells"], 0)
        self.assertEqual(report["unknown_cell_fraction"], 1.0)
        self.assertEqual(report["status"], "unknown")
        self.assertEqual(report["counterexamples"], [])

    def test_random_strategy_is_reproducible_without_hidden_fault_inputs(self):
        _, _, truth, _ = self.source()
        _, api, plan, _ = self.target()
        args = (api, self.subjects, self.records, plan["mapping"], truth, "random", 5)
        first = run_budget_audit(*args, seed=73)
        second = run_budget_audit(*args, seed=73)
        for key in ["history", "covered_cells", "counterexamples"]:
            self.assertEqual(first[key], second[key])


if __name__ == "__main__":
    unittest.main()
