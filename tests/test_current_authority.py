"""Current delivery, real HMAC and external-witness rollback controls, no LLM."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from memory_migration_study.authority_freshness import (
    FreshnessConflict, SQLiteStateWitness, SignedSnapshotStore, SnapshotIntegrityError,
    WitnessUnavailable,
)
from memory_migration_study.current_authority import (
    CurrentMemoryAuthority, CurrentReadDecision, CurrentReadRequest, classify_access,
    prepare_current_transfer, restore_current_answer,
)
from memory_migration_study.memory_labels import MemoryLabelAuthority


class CurrentAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.key = b"test-only-current-authority-key-000000"
        self.witness = SQLiteStateWitness(self.root / "independent_service.sqlite", create=True)
        self.store = SignedSnapshotStore(self.root / "rollbackable_snapshots")
        self.callback_calls = []
        self.denied = set()
        self.policy = {"version": "review-policy-v1", "protected_categories": ["CUSTOMER"],
                       "entity_registry": [{"value": "Granite Mutual", "category": "CUSTOMER"}]}
        self.authority = CurrentMemoryAuthority.provision(self.key, namespace="review-only",
            witness=self.witness, snapshot_store=self.store, live_authorizer=self.live)
        self.record = self.make_record("one")

    def live(self, request):
        self.assertIsInstance(request, CurrentReadRequest)
        self.assertEqual(request.operation, "read")
        self.callback_calls.append(request)
        deny = (request.principal.user_id, request.principal.agent_id, request.source_id) in self.denied
        return CurrentReadDecision.for_request(request, "deny" if deny else "allow")

    def make_record(self, source_id):
        text = "Customer: Granite Mutual."
        fact = {"text": text, "source_start": 0, "source_end": len(text),
                "findings": [{"start": 10, "end": 24, "category": "CUSTOMER"}]}
        return self.authority.build_record({"source_id": source_id, "text": text}, fact, self.policy,
            owner_id="owner", agent_id="builder", builder_version="test-only-v1",
            allowed_principals=[{"user_id": "alice", "agent_id": "A"},
                                {"user_id": "bob", "agent_id": "B"}])

    def decision(self, record=None, authority=None, user="alice", agent="A"):
        return (authority or self.authority).access_decision(record or self.record,
            actor_id=user, agent_id=agent, policy_version=self.policy["version"])

    def reload(self, state=None, witness=None):
        kwargs = dict(namespace="review-only", witness=witness or self.witness,
                      snapshot_store=self.store, live_authorizer=self.live)
        if state is None:
            return CurrentMemoryAuthority.recover_current(self.key, **kwargs)
        return CurrentMemoryAuthority(self.key, state=state, **kwargs)

    def test_exact_live_principal_matrix_and_bound_callback(self):
        for user, agent, expected in [("alice", "A", "allow"), ("bob", "B", "allow"),
                                      ("alice", "B", "deny"), ("bob", "A", "deny")]:
            with self.subTest(user=user, agent=agent):
                self.assertEqual(self.decision(user=user, agent=agent)["decision"], expected)
        self.assertEqual([(r.principal.user_id, r.principal.agent_id) for r in self.callback_calls],
                         [("alice", "A"), ("bob", "B")])

    def test_latest_restart_preserves_revocation_and_independent_legal_record(self):
        independent = self.make_record("two")
        self.authority.revoke(self.record["record_id"], event_id="revoke-first")
        restarted = self.reload()
        self.assertEqual(self.decision(authority=restarted)["code"], "grant_revoked")
        self.assertEqual(self.decision(independent, restarted)["decision"], "allow")

    def test_old_valid_signed_backup_is_stale_in_current_mode(self):
        old = deepcopy(self.authority.export_state())
        self.authority.revoke(self.record["record_id"], event_id="revoke-first")
        restored = self.reload(old)
        result = self.decision(authority=restored)
        self.assertEqual(result["decision"], "unknown")
        self.assertEqual(result["code"], "authority_state_stale")
        # This control documents the precise offline profile and its limit.
        offline = MemoryLabelAuthority(self.key, state=old)
        self.assertIsNone(offline.validate_access(self.record, actor_id="alice", agent_id="A"))

    def test_unprovisioned_namespace_is_not_auto_registered(self):
        unknown = CurrentMemoryAuthority(self.key, state=self.authority.export_state(), namespace="absent",
            witness=self.witness, snapshot_store=self.store, live_authorizer=self.live)
        self.assertEqual(self.decision(authority=unknown)["decision"], "unknown")
        self.assertIsNone(self.witness.head("absent"))
        with self.assertRaises(FreshnessConflict):
            CurrentMemoryAuthority.provision(self.key, namespace="review-only", witness=self.witness,
                                            snapshot_store=self.store, live_authorizer=self.live)

    def test_unavailable_witness_is_not_counted_as_policy_denial(self):
        class Unavailable:
            def head(self, namespace):
                raise WitnessUnavailable("test-only-unavailable")
            def check(self, *args):
                raise WitnessUnavailable("test-only-unavailable")
        restored = self.reload(self.authority.export_state(), Unavailable())
        result = self.decision(authority=restored)
        self.assertEqual(result, {"decision": "unknown", "code": "authority_state_unavailable",
                                 "contract": restored.contract_version,
                                 "enforcement": "trusted_host_current_read_guard"})

    def test_live_unknown_exception_or_bool_response_is_never_allow(self):
        callbacks = [lambda req: CurrentReadDecision.for_request(req, "unknown"),
                     lambda req: True,
                     lambda req: (_ for _ in ()).throw(RuntimeError("test-only-service-failure"))]
        for callback in callbacks:
            with self.subTest(callback=callback):
                self.authority.live_authorizer = callback
                self.assertEqual(self.decision()["decision"], "unknown")

    def test_old_callback_cannot_replace_exact_current_callback(self):
        result = self.authority.validate_access(self.record, actor_id="alice", agent_id="A",
                                               authorizer=lambda *args: True)
        self.assertEqual(classify_access(result)["decision"], "unknown")

    def test_callback_result_cannot_be_replayed_for_a_new_request(self):
        captured = []
        def live(req):
            if not captured:
                captured.append(CurrentReadDecision.for_request(req, "allow"))
            return captured[0]
        self.authority.live_authorizer = live
        self.assertEqual(self.decision()["decision"], "allow")
        self.assertEqual(self.decision()["code"], "current_authorization_response_invalid")

    def test_explicit_live_denial_and_policy_version_are_preserved(self):
        self.denied.add(("alice", "A", "one"))
        self.assertEqual(self.decision()["code"], "current_authorization_denied")
        self.assertEqual(self.callback_calls[-1].policy_version, "review-policy-v1")

    def test_current_mode_cannot_mint_a_flattened_legacy_grant(self):
        text = "plain"
        with self.assertRaisesRegex(ValueError, "requires_exact_principals"):
            self.authority.build_record({"source_id": "plain", "text": text},
                {"text": text, "source_start": 0, "source_end": len(text), "findings": []}, self.policy,
                owner_id="owner", readers=["alice", "bob"], agent_id="builder",
                allowed_agent_ids=["A", "B"], builder_version="test-only")

    def test_durable_commit_failure_does_not_acknowledge_or_modify_local_state(self):
        before = self.authority.export_state()
        original = self.witness.commit
        try:
            self.witness.commit = lambda *args, **kwargs: (_ for _ in ()).throw(WitnessUnavailable("test-only"))
            with self.assertRaises(WitnessUnavailable):
                self.authority.revoke(self.record["record_id"], event_id="test-only-failed")
            self.assertEqual(self.authority.export_state(), before)
        finally:
            self.witness.commit = original
        self.assertEqual(self.decision()["decision"], "unknown")
        self.assertEqual(self.decision()["code"], "authority_commit_indeterminate")
        self.assertEqual(self.decision(authority=self.reload())["decision"], "allow")

    def test_corrupt_committed_snapshot_is_not_recovered(self):
        head = self.witness.head("review-only")
        path = self.store.root / (head.state_sha256 + ".json")
        path.write_text("{}", encoding="utf-8")
        with self.assertRaises(SnapshotIntegrityError):
            self.reload()

    def test_prepare_and_restore_recheck_current_state_and_exact_principal(self):
        prepared = prepare_current_transfer([self.record], "Who is the customer?", self.policy,
            authority=self.authority, actor_id="alice", agent_id="A", request_id="test-only-r1", mode="generation",
            agent=lambda **kwargs: {"status": "ok", "findings": [], "local_calls": 0})
        self.assertEqual(prepared["status"], "ok", prepared.get("error"))
        answer = prepared["payload"]["memories"][0]["text"].split("Customer: ", 1)[1].rstrip(".")
        restored = restore_current_answer(answer, prepared, [self.record], self.policy,
            authority=self.authority, actor_id="alice", agent_id="A", request_id="test-only-r1")
        self.assertEqual(restored["answer"], "Granite Mutual")
        self.authority.revoke_source("one", event_id="revoke-before-restore")
        blocked = restore_current_answer(answer, prepared, [self.record], self.policy,
            authority=self.authority, actor_id="alice", agent_id="A", request_id="test-only-r1")
        self.assertEqual(blocked["answer"], None)
        self.assertEqual(blocked["authorization"]["decision"], "deny")

    def test_authority_failure_inside_preparation_callback_stays_unknown(self):
        calls = []
        def becomes_unavailable(request):
            calls.append(request)
            if len(calls) == 1:
                return CurrentReadDecision.for_request(request, "allow")
            raise RuntimeError("test-only-unavailable")
        self.authority.live_authorizer = becomes_unavailable
        prepared = prepare_current_transfer([self.record], "Who?", self.policy, authority=self.authority,
            actor_id="alice", agent_id="A", request_id="mid-prepare", mode="generation",
            agent=lambda **kwargs: {"status": "ok", "findings": [], "local_calls": 0})
        self.assertNotEqual(prepared["status"], "ok")
        self.assertEqual(prepared["authorization"]["decision"], "unknown")
        self.assertEqual(prepared["processing_outcome"], "authorization_unknown")
        self.assertEqual(prepared["error"], "current_authorizer_unavailable")

    def test_authority_failure_inside_restoration_callback_stays_unknown(self):
        prepared = prepare_current_transfer([self.record], "Who?", self.policy, authority=self.authority,
            actor_id="alice", agent_id="A", request_id="mid-restore", mode="generation",
            agent=lambda **kwargs: {"status": "ok", "findings": [], "local_calls": 0})
        answer = prepared["payload"]["memories"][0]["text"].split("Customer: ", 1)[1].rstrip(".")
        calls = []
        def becomes_unavailable(request):
            calls.append(request)
            if len(calls) == 1:
                return CurrentReadDecision.for_request(request, "allow")
            raise RuntimeError("test-only-unavailable")
        self.authority.live_authorizer = becomes_unavailable
        restored = restore_current_answer(answer, prepared, [self.record], self.policy, authority=self.authority,
            actor_id="alice", agent_id="A", request_id="mid-restore")
        self.assertEqual(restored["status"], "blocked")
        self.assertEqual(restored["authorization"]["decision"], "unknown")
        self.assertEqual(restored["error"], "current_authorizer_unavailable")

    def test_signed_current_record_cannot_cross_authority_namespaces_even_with_same_key(self):
        other = CurrentMemoryAuthority.provision(self.key, namespace="another-independent-service",
            witness=self.witness, snapshot_store=self.store, live_authorizer=self.live)
        self.assertEqual(self.decision(authority=other)["code"], "authority_namespace_mismatch")
        changed = deepcopy(self.record)
        changed["access"]["authority_namespace"] = other.namespace
        self.assertEqual(self.decision(changed, other)["code"], "access_signature_invalid")
        self.assertIsNone(self.authority.validate_label(self.record, self.policy))

    def test_prepare_malformed_record_collections_are_invalid_without_callback(self):
        for records in (None, 7, {}, (self.record,)):
            with self.subTest(records_type=type(records).__name__):
                result = prepare_current_transfer(records, "Who?", self.policy,
                    authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
                self.assertEqual(result["processing_outcome"], "authorization_invalid")
                self.assertIsNone(result["payload"])
                self.assertIsNone(result["mapping"])
        self.assertEqual(self.callback_calls, [])

    def test_restore_malformed_record_collections_are_invalid_without_callback(self):
        for records in (None, 7, {}, (self.record,)):
            with self.subTest(records_type=type(records).__name__):
                result = restore_current_answer("UNKNOWN", {"status": "ok"}, records, self.policy,
                    authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
                self.assertIsNone(result["answer"])
        self.assertEqual(self.callback_calls, [])

    def test_prepare_unhashable_record_ids_are_invalid_without_callback(self):
        for record_id in ([], {}, ["nested"]):
            with self.subTest(record_id=record_id):
                result = prepare_current_transfer([{"record_id": record_id}], "Who?", self.policy,
                    authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
                self.assertIsNone(result["payload"])
        self.assertEqual(self.callback_calls, [])

    def test_restore_unhashable_record_ids_are_invalid_without_callback(self):
        for record_id in ([], {}, ["nested"]):
            with self.subTest(record_id=record_id):
                result = restore_current_answer("UNKNOWN", {"status": "ok"},
                    [{"record_id": record_id}], self.policy, authority=self.authority,
                    actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
                self.assertIsNone(result["answer"])
        self.assertEqual(self.callback_calls, [])

    def test_prepare_mixed_record_entries_are_invalid_before_first_read(self):
        for records in ([None], [7], ["record"], [{}], [self.record, None],
                        [self.record, {"record_id": []}]):
            with self.subTest(records=records):
                result = prepare_current_transfer(records, "Who?", self.policy,
                    authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
        self.assertEqual(self.callback_calls, [])

    def test_restore_mixed_record_entries_are_invalid_before_first_read(self):
        for records in ([None], [7], ["record"], [{}], [self.record, None],
                        [self.record, {"record_id": []}]):
            with self.subTest(records=records):
                result = restore_current_answer("UNKNOWN", {"status": "ok"}, records, self.policy,
                    authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
        self.assertEqual(self.callback_calls, [])

    def test_keyword_records_and_malformed_principal_metadata_do_not_call_authorizer(self):
        common = dict(authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
        for name in ("actor_id", "agent_id", "request_id"):
            for value in (None, 7, [], {}, "", "x" * 257):
                with self.subTest(name=name, value=value):
                    kwargs = {**common, name: value}
                    prepared = prepare_current_transfer(records=[self.record], query="Who?",
                        policy=self.policy, **kwargs)
                    restored = restore_current_answer(answer="UNKNOWN", prepared={"status": "ok"},
                        records=[self.record], policy=self.policy, **kwargs)
                    for result in (prepared, restored):
                        self.assertEqual(result["status"], "blocked")
                        self.assertEqual(result["authorization"]["decision"], "invalid")
        self.assertEqual(self.callback_calls, [])

    def test_empty_invalid_requests_are_not_reported_as_authorized(self):
        common = dict(authority=self.authority, actor_id="alice", agent_id="A", request_id="invalid")
        for kwargs in ({"mode": "not-a-mode"}, {"privacy_pipeline": "not-a-pipeline"},
                       {"label_requirements": []}):
            with self.subTest(kwargs=kwargs):
                result = prepare_current_transfer([], "Who?", self.policy, **common, **kwargs)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["authorization"]["decision"], "invalid")
                self.assertEqual(result["processing_outcome"], "authorization_invalid")
        self.assertEqual(self.callback_calls, [])


if __name__ == "__main__":
    unittest.main()
