"""Opt-in semantic classification cannot bypass signed transfer authorization.

All inference is a zero-network stub; the authority, privacy preparation,
egress, opaque map and restoration paths are the actual implementations.
"""
from copy import deepcopy
import json
import unittest

from memory_migration_study.detection_cache import DetectionCache
from memory_migration_study.memory_labels import (MemoryLabelAuthority, prepare_labeled_transfer,
    restore_labeled_answer)
from memory_migration_study.privacy import _digest, _TOKEN


KINDS = ("local_encoder", "local_generation", "unknown")


class TypedDetector:
    max_local_calls = 1

    def __init__(self, *, calls=0, failure=False, unknown=False, action=None):
        self.calls, self.failure, self.unknown, self.action = calls, failure, unknown, action
        self.inputs = []

    def cache_identity(self):
        return {"self_authored_fixture": "typed_detector_v1", "calls": self.calls}

    def __call__(self, *, text, source_id, policy, rule_findings):
        self.inputs.append((text, source_id, deepcopy(policy), deepcopy(rule_findings)))
        if self.action:
            self.action()
        response = {"status": "needs_review" if self.failure else "ok", "findings": [], "errors": [],
            "local_calls": self.calls, "elapsed_seconds": 0.01}
        if not self.unknown:
            response["inference_counts"] = {"local_encoder": self.calls, "local_generation": 0, "unknown": 0}
        return response


class ReceiptHook:
    """Trusted callback fixture, with tampering applied only to its returned data."""
    def __init__(self, *, additional=1, edit=None, drop=False, action=None, cached=False):
        self.additional, self.edit, self.drop, self.action, self.cached = additional, edit, drop, action, cached
        self.inputs, self.keys, self.physical_generations = [], set(), 0

    def __call__(self, payload, policy, baseline_detection, *, actor_id, agent_id, mode, cache_scope):
        baseline = deepcopy(baseline_detection)
        self.inputs.append(deepcopy({"payload": payload, "policy": policy, "baseline": baseline,
            "actor_id": actor_id, "agent_id": agent_id, "mode": mode, "cache_scope": cache_scope}))
        key = _digest({"payload": payload, "policy": policy, "scope": cache_scope, "actor": actor_id, "agent": agent_id})
        added = 0 if self.cached and key in self.keys else self.additional
        self.keys.add(key)
        self.physical_generations += added
        new = {"local_encoder": 0, "local_generation": added, "unknown": 0}
        total = {k: baseline["inference_counts"][k]+new[k] for k in KINDS}
        result = deepcopy(baseline)
        result.update(status="ok", errors=[], semantic_mode=mode, baseline_local_calls=baseline["local_calls"],
            semantic_local_counts=new, inference_counts=total, local_counts=dict(total),
            local_calls=baseline["local_calls"]+added, local_calls_complete=True, local_counts_complete=True,
            full_policy_sha256=_digest(policy), baseline_detection_sha256=_digest(baseline),
            cache_scope_sha256=_digest(cache_scope), agent_elapsed_seconds=baseline["agent_elapsed_seconds"]+added*0.01)
        if added:
            result["agent_observations"].append({"stage": "local_policy_semantics_v1", "local_calls": added,
                "elapsed_seconds": added*0.01, "inference_counts": dict(new), "receipt_sha256": "a"*64})
        if self.drop:
            result["findings"] = []
        if self.action:
            self.action(payload, policy, baseline_detection, cache_scope)
        if self.edit:
            self.edit(result)
        return result


class PolicySemanticTransferTests(unittest.TestCase):
    def setUp(self):
        self.authority = MemoryLabelAuthority(b"self-authored-policy-semantic-authority-key-32")
        self.policy = {"version": "semantic_test_v1", "protected_categories": ["CUSTOMER"]}
        self.record = self.make_record()

    def make_record(self, *, text="Customer: Invented Cedar Guild", findings=None, source_prefix=""):
        source = {"source_id": "self_source_A", "text": source_prefix+text}
        if findings is None:
            value = "Invented Cedar Guild"
            start = text.index(value)
            findings = [{"start": start, "end": start+len(value), "category": "CUSTOMER"}]
        fact = {"text": text, "source_start": len(source_prefix), "source_end": len(source["text"]), "findings": findings}
        return json.loads(json.dumps(self.authority.build_record(source, fact, self.policy, owner_id="owner", readers=["owner"],
            agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="self_builder_v1")))

    def transfer(self, *, records=None, policy=None, hook=None, detector=None, **changes):
        arguments = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1",
            "mode": "migration", "privacy_pipeline": "semantic", "semantic_mode": "joint"}
        arguments.update(changes)
        return prepare_labeled_transfer([self.record] if records is None else records, arguments.pop("query", "Who is the client?"),
            policy or self.policy, semantic_refiner=hook if hook is not None else ReceiptHook(),
            agent=detector if detector is not None else TypedDetector(), **arguments)

    def restore(self, answer, prepared, *, records=None, policy=None, **changes):
        arguments = {"authority": self.authority, "actor_id": "owner", "agent_id": "agent-B", "request_id": "request-1"}
        arguments.update(changes)
        return restore_labeled_answer(answer, prepared, [self.record] if records is None else records, policy or self.policy, **arguments)

    def token(self, prepared):
        return _TOKEN.search(prepared["payload"]["memories"][0]["text"]).group()

    def test_real_signed_handoff_egress_and_restore(self):
        hook = ReceiptHook()
        prepared = self.transfer(hook=hook)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(prepared["egress"]["status"], "ok")
        self.assertEqual(prepared["local_calls"], 1)
        self.assertEqual(prepared["inference_counts"], {"local_encoder": 0, "local_generation": 1, "unknown": 0})
        self.assertEqual(self.restore(self.token(prepared), prepared)["answer"], "Invented Cedar Guild")
        with self.assertRaises(TypeError):
            json.dumps(prepared["mapping"])
        self.assertTrue(prepared["metadata"]["semantic_classification_is_not_authorization"])

    def test_default_legacy_and_boundary_do_not_call_semantic_hook(self):
        for pipeline in ("legacy", "boundary"):
            hook = ReceiptHook()
            prepared = self.transfer(hook=hook, privacy_pipeline=pipeline, semantic_mode="invalid-but-unused")
            self.assertEqual(prepared["status"], "ok")
            self.assertEqual(hook.inputs, [])
            self.assertNotIn("inference_counts", prepared)

    def test_missing_hook_and_invalid_mode_fail_closed(self):
        for mode, hook, error in (("joint", None, "semantic_refiner_required"), ("all", ReceiptHook(), "invalid_semantic_mode"),
                                   ([], ReceiptHook(), "invalid_semantic_mode")):
            result = prepare_labeled_transfer([self.record], "", self.policy, authority=self.authority, actor_id="owner",
                agent_id="agent-B", request_id="request-1", privacy_pipeline="semantic", semantic_mode=mode, semantic_refiner=hook)
            self.assertEqual(result["error"], error)
            self.assertIsNone(result["payload"])

    def test_foreign_actor_agent_and_current_acl_are_checked_before_hook(self):
        for changes, error in (({"actor_id": "outsider"}, "principal_not_authorized"),
            ({"agent_id": "agent-C"}, "principal_not_authorized"),
            ({"authorizer": lambda *_: False}, "current_authorization_failed")):
            hook, detector = ReceiptHook(), TypedDetector(calls=1)
            result = self.transfer(hook=hook, detector=detector, **changes)
            self.assertEqual(result["error"], error)
            self.assertEqual(hook.inputs, [])
            self.assertEqual(detector.inputs, [])

    def test_source_signature_acl_and_fact_substitution_are_rejected(self):
        edits = (lambda r: r["access"]["readers"].append("outsider"),
            lambda r: r["source"].update(text="tampered full source"),
            lambda r: r.update(source_start=1, text=r["text"][1:]),
            lambda r: r.update(access_signature="0"*64))
        for edit in edits:
            record, hook, detector = deepcopy(self.record), ReceiptHook(), TypedDetector()
            edit(record)
            result = self.transfer(records=[record], hook=hook, detector=detector)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(hook.inputs, [])
            self.assertEqual(detector.inputs, [])

    def test_recheck_after_baseline_revocation_before_semantic_hook(self):
        hook = ReceiptHook()
        detector = TypedDetector(calls=1, action=lambda: self.authority.revoke(self.record["record_id"]))
        result = self.transfer(hook=hook, detector=detector)
        self.assertEqual(result["error"], "grant_revoked")
        self.assertEqual(hook.inputs, [])
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(result["inference_counts"]["local_encoder"], 2)

    def test_revoke_blocks_old_map_and_request_replay(self):
        hook = ReceiptHook(cached=True)
        prepared = self.transfer(hook=hook)
        value = self.token(prepared)
        self.authority.revoke(self.record["record_id"])
        self.assertEqual(self.restore(value, prepared)["error"], "grant_revoked")
        before = len(hook.inputs)
        self.assertEqual(self.transfer(hook=hook)["error"], "grant_revoked")
        self.assertEqual(len(hook.inputs), before)

    def test_epoch_and_source_revoke_reject_before_hook(self):
        for source_revoke in (True, False):
            self.setUp()
            hook = ReceiptHook()
            if source_revoke:
                self.authority.revoke_source("self_source_A")
            else:
                self.authority.bump_epoch()
            result = self.transfer(hook=hook)
            self.assertEqual(result["error"], "grant_revoked" if source_revoke else "lifecycle_epoch_changed")
            self.assertEqual(hook.inputs, [])

    def test_policy_edit_invalidates_old_prepared_restore(self):
        prepared = self.transfer()
        policy = dict(self.policy, instructions="A new same-version independent policy.")
        self.assertEqual(self.restore(self.token(prepared), prepared, policy=policy)["error"], "restoration_policy_mismatch")

    def test_hook_cannot_change_any_payload_policy_or_domain_binding(self):
        edits = [lambda r, field=field: r.update({field: "f"*64}) for field in
            ("payload_sha256", "policy_sha256", "full_policy_sha256", "baseline_detection_sha256", "cache_scope_sha256")]
        edits += [lambda r: r.update(policy_version="wrong"), lambda r: r.update(policy_id="wrong"),
            lambda r: r.update(protected_categories=[]), lambda r: r.update(semantic_mode="roles")]
        for edit in edits:
            result = self.transfer(hook=ReceiptHook(edit=edit))
            self.assertEqual(result["status"], "needs_review")
            self.assertIsNone(result["payload"])
            self.assertIn("semantic_refiner_result_invalid", result["detection"]["errors"])
            # Complete physical work survives a rejected content binding.
            self.assertEqual(result["local_calls"], 1)
            self.assertTrue(result["local_calls_complete"])

    def test_bad_finding_offsets_sources_categories_and_authority_fail_closed(self):
        edits = (lambda f: f.update(source_id="nonexistent"), lambda f: f.update(start=True),
            lambda f: f.update(end=9999), lambda f: f.update(category="PROJECT"),
            lambda f: f.update(quote="not the original substring"), lambda f: f.update(authorized=True),
            lambda f: f.update(provenance=[{"owner_id": "outsider"}]))
        for edit in edits:
            def mutate(result):
                edit(result["findings"][0])
            result = self.transfer(hook=ReceiptHook(edit=mutate))
            self.assertNotEqual(result["status"], "ok")
            self.assertIsNone(result["payload"])

    def test_fake_callback_authority_is_not_a_grant(self):
        result = self.transfer(hook=ReceiptHook(edit=lambda r: r.update(authorized=True, readers=["outsider"])))
        self.assertNotEqual(result["status"], "ok")
        self.assertIsNone(result["mapping"])
        self.assertEqual(result["local_calls"], 1)

    def test_hook_gets_only_selected_fact_and_deep_copies(self):
        record = self.make_record(source_prefix="Unselected confidential source paragraph.\n")
        before = deepcopy(record)
        def change_arguments(payload, policy, baseline, scope):
            payload["memories"][0]["text"] = "model tampering"
            policy["protected_categories"].clear()
            baseline["findings"].clear()
            scope["authority_domain"] = "tampered"
        hook = ReceiptHook(action=change_arguments)
        prepared = self.transfer(records=[record], hook=hook)
        self.assertEqual(prepared["status"], "ok")
        self.assertEqual(record, before)
        self.assertEqual(hook.inputs[0]["payload"]["memories"], [{"source_id": record["record_id"], "text": record["text"]}])
        self.assertNotIn("Unselected confidential", json.dumps(hook.inputs))
        self.assertNotIn("access", hook.inputs[0])
        self.assertEqual(set(hook.inputs[0]["cache_scope"]), {"authority_domain", "lifecycle_sha256", "grants_sha256"})

    def test_rule_and_registry_constraints_cannot_be_dropped(self):
        policy = dict(self.policy, entity_registry=[{"value": "Invented Cedar Guild", "category": "CUSTOMER"}])
        result = self.transfer(policy=policy, hook=ReceiptHook(drop=True))
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("Invented Cedar Guild", json.dumps(result["payload"]))
        self.assertEqual(self.restore(self.token(result), result, policy=policy)["answer"], "Invented Cedar Guild")

    def test_signed_generation_labels_remain_in_generation_and_two_stage(self):
        record = self.make_record(text="OpaqueOrganization", findings=[{"start": 0, "end": 18, "category": "CUSTOMER"}])
        for mode in ("generation", "two_stage"):
            result = self.transfer(records=[record], query="", mode=mode, hook=ReceiptHook(drop=True))
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["checks"][0]["label_valid"])
            self.assertNotIn("OpaqueOrganization", result["payload"]["memories"][0]["text"])
            self.assertEqual(self.restore(self.token(result), result, records=[record])["answer"], "OpaqueOrganization")

    def test_invalid_label_falls_back_without_reauthorizing_content(self):
        changed = deepcopy(self.record)
        changed["label_signature"] = "0"*64
        detector = TypedDetector(calls=1)
        result = self.transfer(records=[changed], query="", mode="generation", detector=detector)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checks"][0]["fallback_reason"], "label_signature_invalid")
        self.assertEqual(result["local_calls"], 2)

    def test_failed_baseline_is_never_upgraded_or_sent_to_hook(self):
        hook = ReceiptHook()
        result = self.transfer(detector=TypedDetector(calls=1, failure=True), hook=hook)
        self.assertNotEqual(result["status"], "ok")
        self.assertEqual(hook.inputs, [])
        self.assertEqual(result["local_calls"], 2)

    def test_unknown_positive_baseline_cost_is_not_misclassified(self):
        hook = ReceiptHook()
        result = self.transfer(detector=TypedDetector(calls=1, unknown=True), hook=hook)
        self.assertNotEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 2)
        self.assertEqual(result["inference_counts"]["unknown"], 2)
        self.assertFalse(result["metadata"]["local_counts_complete"])
        self.assertEqual(hook.inputs, [])

    def test_baseline_encoder_and_new_generation_counts_are_both_retained(self):
        result = self.transfer(detector=TypedDetector(calls=1), hook=ReceiptHook(additional=2))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["local_calls"], 4)
        self.assertEqual(result["inference_counts"], {"local_encoder": 2, "local_generation": 2, "unknown": 0})
        self.assertEqual(sum(o["local_calls"] for o in result["detection"]["agent_observations"]), 4)

    def test_cached_baseline_and_hook_do_not_recharge_or_reuse_tokens(self):
        cache, hook, detector = DetectionCache(), ReceiptHook(cached=True), TypedDetector(calls=1)
        first = self.transfer(detector=detector, hook=hook, detection_cache=cache)
        second = self.transfer(detector=detector, hook=hook, detection_cache=cache, request_id="request-2")
        self.assertEqual(first["local_calls"], 3)
        self.assertEqual(second["local_calls"], 0)
        self.assertEqual(second["inference_counts"], dict.fromkeys(KINDS, 0))
        self.assertEqual(hook.physical_generations, 1)
        self.assertEqual(len(detector.inputs), 2)
        self.assertNotEqual(self.token(first), self.token(second))
        self.assertEqual(second["metadata"]["detection_cache"]["hits"], 2)

    def test_same_version_policy_change_does_not_hit_old_semantic_scope(self):
        hook = ReceiptHook(cached=True)
        self.transfer(hook=hook)
        policy = dict(self.policy, instructions="An independent policy revision with the same version string.")
        second = self.transfer(hook=hook, policy=policy)
        self.assertEqual(second["status"], "ok")
        self.assertEqual(hook.physical_generations, 2)
        self.assertNotEqual(hook.inputs[0]["baseline"]["policy_sha256"], hook.inputs[1]["baseline"]["policy_sha256"])

    def test_cost_tampering_blocks_without_recounting_unknown_work_as_success(self):
        edits = (lambda r: r.update(local_calls=0), lambda r: r.update(local_calls_complete=False),
            lambda r: r["semantic_local_counts"].update(unknown=1),
            lambda r: r["inference_counts"].update(local_encoder=True),
            lambda r: r["agent_observations"].pop(0),
            lambda r: r.update(agent_elapsed_seconds=float("nan")))
        for edit in edits:
            result = self.transfer(detector=TypedDetector(calls=1), hook=ReceiptHook(edit=edit))
            self.assertNotEqual(result["status"], "ok")
            self.assertFalse(result["local_calls_complete"])
            self.assertIsNone(result["payload"])
            self.assertEqual(result["local_calls"], 2)  # known baseline lower bound

    def test_query_sensitive_value_is_not_memory_evidence(self):
        policy = {"version": "self_query_v1", "protected_categories": ["PROJECT"]}
        original = self.policy
        self.policy = policy
        record = self.make_record(text="Status: shipped", findings=[])
        self.policy = original
        result = self.transfer(records=[record], policy=policy, query="Project InventedNightLake", hook=ReceiptHook())
        self.assertEqual(result["status"], "ok")
        query_token = _TOKEN.search(result["payload"]["query"]).group()
        self.assertEqual(self.restore(query_token, result, records=[record], policy=policy)["error"], "query_only_value_has_no_evidence")

    def test_revoke_inside_hook_is_rechecked_by_original_preparation(self):
        hook = ReceiptHook(action=lambda *_: self.authority.revoke(self.record["record_id"]))
        result = self.transfer(hook=hook)
        self.assertNotEqual(result["status"], "ok")
        self.assertIsNone(result["payload"])
        self.assertEqual(result["local_calls"], 1)

    def test_actual_refiner_and_pinned_encoder_adapter_integrate_without_models(self):
        from memory_migration_study.ner_detector import GlinerEntityAgent
        from memory_migration_study.policy_semantics import LocalPolicySemanticAgent, PolicySemanticRefiner
        from tests.test_candidate_adjudicator import FakeTransport, envelope

        class FakeEncoderRuntime:
            identity = {"weights_sha256": "a"*64}
            calls = 0

            def infer(self, text, labels, **options):
                self.calls += 1
                return {"entities": {}}

        runtime = FakeEncoderRuntime()
        detector = GlinerEntityAgent(runtime, approved_policies=[self.policy])
        transport = FakeTransport([envelope({"verdicts": [{"cid": "C0001", "role": "value", "quote": "Invented Cedar Guild"}]})])
        hook = PolicySemanticRefiner(LocalPolicySemanticAgent(transport=transport))
        cache = DetectionCache()
        results = [self.transfer(detector=detector, hook=hook, detection_cache=cache, semantic_mode=mode,
            request_id="request-"+mode) for mode in ("roles", "completion", "joint")]
        self.assertTrue(all(r["status"] == "ok" for r in results), results)
        self.assertEqual([r["local_calls"] for r in results], [3, 0, 0])
        self.assertEqual(results[0]["inference_counts"], {"local_encoder": 2, "local_generation": 1, "unknown": 0})
        self.assertEqual(runtime.calls, 2)
        self.assertEqual(len(transport.posts), 1)
        self.assertNotEqual(self.token(results[0]), self.token(results[1]))


if __name__ == "__main__":
    unittest.main()
