import copy
import json
import unittest

from memory_migration_study.backend import ReferenceAPI
from memory_migration_study.evidence import evaluate, probe
from memory_migration_study.policy import make_plan
from test_study_policy import fixture


class EvidenceTests(unittest.TestCase):
    def capture(self, method="exact_groups", fault="none", modifier=None):
        case = fixture()
        plan = make_plan(case, method, "test-run")
        if modifier:
            modifier(case, plan)
        with ReferenceAPI(case, plan, fault=fault, page_size=1) as backend:
            return probe(case, plan, backend.adapter)

    def test_exact_groups_and_reader_copies_preserve_all_relations(self):
        for method in ("exact_groups", "reader_copies"):
            result = evaluate(self.capture(method))
            self.assertEqual((result["known_w_plus"], result["known_w_minus"], result["unknown_count"]), (0, 0, 0))
            self.assertIs(result["finite_scope_safe"], True)
            self.assertEqual(result["declared_relationships"], 18)

    def test_reject_all_exposes_legal_loss(self):
        result = evaluate(self.capture("reject_all"))
        self.assertEqual(result["known_w_plus"], 0)
        self.assertEqual(result["known_w_minus"], 8)
        self.assertEqual(result["legal_access_retention"], 0)
        self.assertIs(result["finite_scope_safe"], True)

    def test_500_body_leak_is_definite_wplus_despite_other_unknowns(self):
        result = evaluate(self.capture(fault="error_body_leak"))
        self.assertGreater(result["known_w_plus"], 0)
        self.assertGreater(result["execution_errors"], 0)
        self.assertIs(result["finite_scope_safe"], False)

    def test_registered_extra_copy_cannot_hide_unauthorized_access(self):
        def extra(case, plan):
            record = case["records"][1]
            target = "test-run/extra-copy"
            plan["objects"].append({"target_id": target, "source_id": record["source_id"], "text": record["text"], "readers": ["C"], "container_id": "extra"})
            plan["object_mapping"][record["source_id"]].append(target)
        result = evaluate(self.capture("reader_copies", modifier=extra))
        self.assertGreater(result["known_w_plus"], 0)

    def test_one_accessible_copy_prevents_false_loss(self):
        def restrict(case, plan):
            plan["objects"][0]["readers"] = []
            obj = copy.deepcopy(plan["objects"][0])
            obj.update(target_id="test-run/second", readers=["A", "B"])
            plan["objects"].append(obj)
            plan["object_mapping"][obj["source_id"]].append(obj["target_id"])
        result = evaluate(self.capture(modifier=restrict))
        self.assertEqual(result["known_w_minus"], 0)

    def test_missing_replica_probe_is_unknown_even_when_other_replica_works(self):
        bundle = self.capture("reader_copies")
        bundle["observations"] = [o for o in bundle["observations"] if not (o["actor_id"] == "A" and o["endpoint"] == "read" and o["requested_source_id"] == "delivery_date")]
        result = evaluate(bundle)
        self.assertGreater(result["unknown_count"], 0)
        self.assertIsNone(result["finite_scope_safe"])

    def test_identity_failure_cannot_be_authorization_denial(self):
        bundle = self.capture()
        bundle["actor_controls"]["A"]["identity_valid"] = False
        result = evaluate(bundle)
        self.assertGreater(result["credential_failures"], 0)
        self.assertIsNone(result["finite_scope_safe"])

    def test_401_body_leak_still_counts(self):
        bundle = self.capture()
        obs = next(o for o in bundle["observations"] if o["actor_id"] == "C" and o["endpoint"] == "read")
        obs.update(status=401, raw_body=json.dumps({"text": bundle["case"]["records"][0]["text"]}))
        bundle["actor_controls"]["C"]["identity_valid"] = False
        result = evaluate(bundle)
        self.assertGreater(result["known_w_plus"], 0)
        self.assertIs(result["finite_scope_safe"], False)

    def test_missing_or_ambiguous_mapping_is_unknown(self):
        bundle = self.capture()
        del bundle["plan"]["object_mapping"]["private_code"]
        result = evaluate(bundle)
        self.assertIsNone(result["finite_scope_safe"])
        self.assertIn("incomplete_source_object_mapping", result["structural_errors"])

    def test_incomplete_pagination_is_unknown(self):
        bundle = self.capture()
        bundle["actor_controls"]["A"]["list_complete"] = False
        result = evaluate(bundle)
        self.assertIsNone(result["finite_scope_safe"])
        self.assertTrue(any(r["state"] == "unknown" and r["operation"] == "list" for r in result["relationships"]))

    def test_removed_page_is_unknown_even_if_cached_complete_flag_is_true(self):
        bundle = self.capture()
        bundle["observations"] = [o for o in bundle["observations"] if not (o["actor_id"] == "A" and o["endpoint"] == "list" and o["page"] == 0)]
        self.assertIsNone(evaluate(bundle)["finite_scope_safe"])

    def test_read_loss_not_erased_by_list_content(self):
        bundle = self.capture()
        for obs in bundle["observations"]:
            if obs["actor_id"] == "B" and obs["endpoint"] == "read" and obs["requested_source_id"] == "delivery_date":
                obs.update(status=403, raw_body='{"error":"forbidden"}')
        result = evaluate(bundle)
        self.assertEqual(result["known_w_minus"], 1)
        self.assertTrue(next(r for r in result["logical_content_reachability"] if r["actor_id"] == "B" and r["source_id"] == "delivery_date")["any_read_or_list_content"])

    def test_wrong_request_id_still_attributes_actual_source_disclosure(self):
        bundle = self.capture()
        private = bundle["case"]["records"][1]
        obs = next(o for o in bundle["observations"] if o["actor_id"] == "B" and o["endpoint"] == "read" and o["requested_source_id"] == "delivery_date")
        obs["raw_body"] = json.dumps({"item": {"target_id": obs["target_id"], "source_id": "delivery_date", "text": private["text"]}})
        result = evaluate(bundle)
        self.assertGreater(result["content_integrity_errors"], 0)
        self.assertTrue(any(r["state"] == "known_w_plus" and r["source_id"] == "private_code" and r["actor_id"] == "B" for r in result["relationships"]))

    def test_metadata_only_is_separate_and_not_content(self):
        bundle = self.capture()
        private_id = bundle["plan"]["object_mapping"]["private_code"][0]
        obs = next(o for o in bundle["observations"] if o["actor_id"] == "C" and o["target_id"] == private_id)
        obs["raw_body"] = json.dumps({"target_id": private_id})
        result = evaluate(bundle)
        self.assertEqual(result["known_w_plus"], 0)
        self.assertGreater(result["metadata_disclosures"], 0)

    def test_credentials_never_enter_evidence_and_target_mapping_is_executed(self):
        case = fixture()
        plan = make_plan(case, "exact_groups", "mapping")
        with ReferenceAPI(case, plan) as backend:
            self.assertEqual(backend.adapter.parse(backend.adapter._request("A", "/whoami"))["actor_id"], case["actor_mapping"]["A"])
            self.assertEqual(backend.adapter.parse(backend.adapter._request("B", "/whoami?actor_id=A"))["actor_id"], case["actor_mapping"]["B"])
            captured = probe(case, plan, backend.adapter)
            serialized = json.dumps(captured)
            for secret in backend.credentials.values():
                self.assertNotIn(secret, serialized)
            backend.adapter.expected_target_actor_ids["A"] = "wrong-principal"
            self.assertFalse(backend.adapter.identity("A")[0])

    def test_control_content_must_match_registered_hash(self):
        case = fixture()
        plan = make_plan(case, "exact_groups", "controls")
        with ReferenceAPI(case, plan) as backend:
            backend.adapter.controls["A"]["text_sha256"] = "wrong"
            result = evaluate(probe(case, plan, backend.adapter))
            self.assertIsNone(result["finite_scope_safe"])

    def test_json_key_and_unicode_escaped_key_disclosures_are_checked(self):
        for ensure_ascii in (True, False):
            bundle = self.capture()
            text = bundle["case"]["records"][1]["text"]
            obs = next(o for o in bundle["observations"] if o["actor_id"] == "C" and o["endpoint"] == "read")
            obs.update(status=403, raw_body=json.dumps({text: "concealed in key"}, ensure_ascii=ensure_ascii))
            result = evaluate(bundle)
            self.assertGreater(result["known_w_plus"], 0)
        bundle = self.capture()
        text = bundle["case"]["records"][1]["text"]
        escaped = "".join("\\u%04x" % ord(char) for char in text)
        obs = next(o for o in bundle["observations"] if o["actor_id"] == "C" and o["endpoint"] == "read")
        obs["raw_body"] = '{"' + escaped + '": 1}'
        self.assertGreater(evaluate(bundle)["known_w_plus"], 0)

    def test_plan_source_only_cannot_change_common_oracle(self):
        case = fixture()
        plan = make_plan(case, "exact_groups", "source-only-diagnostic", source_only=True)
        with ReferenceAPI(case, plan) as backend:
            result = evaluate(probe(case, plan, backend.adapter))
        self.assertGreater(result["known_w_plus"], 0)


if __name__ == "__main__":
    unittest.main()
