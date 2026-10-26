"""Real HMAC/SQLite/durable-blob recovery contracts; no models or network."""
from copy import deepcopy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study.authority_freshness import (
    Checkpoint, FreshnessConflict, SignedSnapshotStore, SnapshotIntegrityError,
    SQLiteStateWitness, WitnessUnavailable, assert_monotonic_lifecycle,
    commit_snapshot, provision_snapshot, state_sha256)
from memory_migration_study.memory_labels import MemoryLabelAuthority


KEY = b"test-only-state-witness-key-32-bytes"
NAMESPACE = "test-only-authority"


def valid_signature(envelope):
    try:
        MemoryLabelAuthority(KEY, state=envelope)
        return True
    except (TypeError, ValueError):
        return False


class FreshnessContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="authority-state-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store = SignedSnapshotStore(self.root / "rollbackable-snapshots")
        self.witness = SQLiteStateWitness(self.root / "independent-test-witness/ledger.sqlite", create=True)
        self.authority = MemoryLabelAuthority(KEY)
        self.initial = self.authority.export_state()

    def provision(self):
        return provision_snapshot(self.store, self.witness, NAMESPACE, self.initial,
                                  validator=valid_signature)

    def publish(self, previous, *, event_id="revoke-one"):
        return commit_snapshot(self.store, self.witness, NAMESPACE, previous,
                               self.authority.export_state(), validator=valid_signature,
                               event_id=event_id)

    def record(self, source_id="source-one", text="Synthetic nonpublic fact."):
        source = {"source_id": source_id, "text": text}
        fact = {"text": text, "source_start": 0, "source_end": len(text), "findings": []}
        policy = {"version": "test-only-v1", "protected_categories": ["CUSTOMER"]}
        return self.authority.build_record(source, fact, policy, owner_id="alice",
                                           readers=["alice"], agent_id="builder",
                                           allowed_agent_ids=["reader"], builder_version="test-only")

    def current_read_fixture(self, envelope, record):
        """Component composition, not the parent's full serving integration."""
        freshness = self.witness.check(NAMESPACE, state_sha256(envelope))
        if freshness.status != "current":
            return freshness.status
        restored = MemoryLabelAuthority(KEY, state=envelope)
        return restored.validate_access(record, actor_id="alice", agent_id="reader")

    def test_reading_and_storing_old_snapshot_cannot_auto_provision(self):
        digest = self.store.put(self.initial, validator=valid_signature)
        result = self.witness.check(NAMESPACE, digest)
        self.assertEqual((result.status, result.code), ("unknown", "witness_unprovisioned"))
        self.assertIsNone(result.checkpoint)
        self.assertIsNone(self.witness.head(NAMESPACE))
        checkpoint = self.provision()
        self.assertEqual(checkpoint, Checkpoint(NAMESPACE, 0, digest))
        self.assertEqual(self.witness.check(NAMESPACE, digest).status, "current")
        with self.assertRaisesRegex(FreshnessConflict, "already_provisioned"):
            self.provision()

    def test_revoke_then_restart_loads_latest_and_rejects_old_backup(self):
        record = self.record()
        first = self.provision()
        self.assertIsNone(self.current_read_fixture(self.initial, record))
        self.authority.revoke(record["record_id"])
        latest = self.publish(first)
        # Reopening the witness is a genuine new SQLite adapter, not a cache.
        self.witness = SQLiteStateWitness(self.witness.path)
        self.assertEqual(self.witness.head(NAMESPACE), latest)
        restored_state = self.store.load(latest.state_sha256, validator=valid_signature)
        self.assertEqual(self.current_read_fixture(restored_state, record), "grant_revoked")
        restored_old = self.store.load(first.state_sha256, validator=valid_signature)
        self.assertTrue(valid_signature(restored_old))
        self.assertEqual(self.current_read_fixture(restored_old, record), "stale")

    def test_source_revocation_remains_after_restart(self):
        record = self.record()
        first = self.provision()
        self.authority.revoke_source("source-one")
        latest = self.publish(first, event_id="revoke-source")
        self.witness = SQLiteStateWitness(self.witness.path)
        state = self.store.load(latest.state_sha256, validator=valid_signature)
        self.assertEqual(self.current_read_fixture(state, record), "grant_revoked")

    def test_namespace_and_wrong_head_cannot_be_substituted(self):
        checkpoint = self.provision()
        other = self.witness.check("other-authority", checkpoint.state_sha256)
        self.assertEqual(other.status, "unknown")
        self.assertEqual(other.code, "witness_unprovisioned")
        self.assertEqual(self.witness.check(NAMESPACE, "0" * 64).status, "stale")
        with self.assertRaisesRegex(ValueError, "namespace_mismatch"):
            self.witness.commit("other-authority", checkpoint, "1" * 64, event_id="wrong-namespace")
        self.assertEqual(self.witness.head(NAMESPACE), checkpoint)

    def test_current_cas_rejects_out_of_order_event_without_replacing_head(self):
        first = self.provision()
        self.authority.revoke("record-one")
        second = self.publish(first, event_id="one")
        self.authority.revoke("record-two")
        with self.assertRaisesRegex(FreshnessConflict, "compare_and_swap"):
            self.publish(first, event_id="late-event")
        self.assertEqual(self.witness.head(NAMESPACE), second)
        third = self.publish(second, event_id="correct-order")
        self.assertEqual(third.revision, second.revision + 1)

    def test_event_retries_are_idempotent_and_changed_body_is_rejected(self):
        first = self.provision()
        self.authority.revoke("record-one")
        second = self.publish(first, event_id="event-one")
        repeated = self.witness.commit(NAMESPACE, first, second.state_sha256, event_id="event-one")
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.checkpoint, second)
        self.assertEqual(repeated.event_checkpoint, second)
        with self.assertRaisesRegex(FreshnessConflict, "event_body_changed"):
            self.witness.commit(NAMESPACE, first, "0" * 64, event_id="event-one")
        self.assertEqual(self.witness.head(NAMESPACE), second)

    def test_replaying_a_superseded_event_never_rewinds_current_head(self):
        first = self.provision()
        self.authority.revoke("record-one")
        old_event_state = self.authority.export_state()
        second = self.publish(first, event_id="event-one")
        self.authority.revoke("record-two")
        third = self.publish(second, event_id="event-two")
        retry = self.witness.commit(NAMESPACE, first, second.state_sha256, event_id="event-one")
        self.assertEqual(retry.checkpoint, third)
        self.assertEqual(retry.event_checkpoint, second)
        self.assertTrue(retry.replayed)
        with self.assertRaisesRegex(FreshnessConflict, "already_superseded"):
            commit_snapshot(self.store, self.witness, NAMESPACE, first, old_event_state,
                            validator=valid_signature, event_id="event-one")
        self.assertEqual(self.witness.head(NAMESPACE), third)

    def test_validly_signed_rollback_cannot_be_published_as_a_new_event(self):
        first = self.provision()
        self.authority.revoke("record-one")
        self.authority.revoke_source("source-one")
        second = self.publish(first)
        self.assertTrue(valid_signature(self.initial))
        with self.assertRaisesRegex(FreshnessConflict, "rollback_forbidden"):
            commit_snapshot(self.store, self.witness, NAMESPACE, second, self.initial,
                            validator=valid_signature, event_id="new-event-with-old-state")
        self.assertEqual(self.witness.head(NAMESPACE), second)
        self.assertEqual(self.witness.check(NAMESPACE, first.state_sha256).status, "stale")

    def test_epoch_is_monotonic_and_cannot_erase_revoked_ids(self):
        previous = self.initial
        self.authority.bump_epoch()
        self.authority.revoke("record-one")
        following = self.authority.export_state()
        assert_monotonic_lifecycle(previous, following)
        for field in ("epoch", "revoked_records"):
            changed = deepcopy(following)
            changed["state"][field] = previous["state"][field]
            if field == "epoch":
                old = deepcopy(following)
            else:
                old = following
            with self.subTest(field=field), self.assertRaisesRegex(FreshnessConflict, "rollback"):
                assert_monotonic_lifecycle(old, changed)

    def test_unavailable_witness_is_unknown_and_does_not_register_new_head(self):
        checkpoint = self.provision()
        with patch.object(self.witness, "_connect", side_effect=sqlite3.OperationalError("test-only unavailable")):
            result = self.witness.check(NAMESPACE, checkpoint.state_sha256)
            self.assertEqual((result.status, result.code), ("unknown", "witness_unavailable"))
            self.assertIsNone(result.checkpoint)
            self.authority.revoke("record-one")
            with self.assertRaises(WitnessUnavailable):
                self.publish(checkpoint)
        self.assertEqual(self.witness.head(NAMESPACE), checkpoint)

    def test_missing_witness_is_not_silently_created_on_read(self):
        path = self.root / "missing-witness.sqlite"
        witness = SQLiteStateWitness(path)
        self.assertEqual(witness.check(NAMESPACE, state_sha256(self.initial)).status, "unknown")
        self.assertFalse(path.exists())

    def test_blob_is_valid_and_present_before_any_witness_update(self):
        first = self.provision()
        self.authority.revoke("record-one")
        expected_state = self.authority.export_state()
        real_commit = self.witness.commit
        seen = []

        def committed(namespace, expected, digest, *, event_id):
            self.assertEqual(self.store.load(digest, validator=valid_signature), expected_state)
            self.assertEqual(self.witness.head(namespace), first)
            seen.append(digest)
            return real_commit(namespace, expected, digest, event_id=event_id)

        with patch.object(self.witness, "commit", side_effect=committed):
            latest = self.publish(first)
        self.assertEqual(seen, [latest.state_sha256])

    def test_failed_witness_commit_leaves_only_unacknowledged_blob(self):
        first = self.provision()
        self.authority.revoke("record-one")
        pending = self.authority.export_state()
        with patch.object(self.witness, "commit", side_effect=WitnessUnavailable("witness_unavailable")):
            with self.assertRaises(WitnessUnavailable):
                self.publish(first)
        pending_digest = state_sha256(pending)
        self.assertEqual(self.store.load(pending_digest, validator=valid_signature), pending)
        self.assertEqual(self.witness.head(NAMESPACE), first)
        self.assertEqual(self.witness.check(NAMESPACE, pending_digest).status, "stale")
        self.assertEqual(list(self.store.root.glob(".publish-*")), [])

    def test_tampering_bytes_or_signature_is_not_a_valid_recovery(self):
        first = self.provision()
        path = self.store.root / (first.state_sha256 + ".json")
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"epoch":0', b'"epoch":1'))
        with self.assertRaisesRegex(SnapshotIntegrityError, "sha256_mismatch"):
            self.store.load(first.state_sha256, validator=valid_signature)
        invalid = deepcopy(self.initial)
        invalid["state"]["epoch"] += 1
        with self.assertRaisesRegex(SnapshotIntegrityError, "signature_invalid"):
            self.store.put(invalid, validator=valid_signature)
        self.assertEqual(self.witness.head(NAMESPACE), first)

    def test_signature_validator_is_mandatory_and_not_truthiness_based(self):
        for validator in (None, lambda envelope: 1, lambda envelope: {"allow": True}):
            with self.subTest(validator=repr(validator)), self.assertRaises((ValueError, SnapshotIntegrityError)):
                self.store.put(self.initial, validator=validator)
        self.assertEqual(list(self.store.root.iterdir()), [])

    def test_unrelated_revocation_preserves_a_new_legal_read_without_global_epoch_change(self):
        first_record = self.record("source-one", "Synthetic first fact.")
        independent = self.record("source-two", "Synthetic independently authorized fact.")
        first = self.provision()
        self.authority.revoke(first_record["record_id"])
        latest = self.publish(first)
        current = self.store.load(latest.state_sha256, validator=valid_signature)
        self.assertEqual(self.current_read_fixture(current, first_record), "grant_revoked")
        self.assertIsNone(self.current_read_fixture(current, independent))
        self.assertEqual(self.current_read_fixture(self.initial, independent), "stale")

    def test_two_writer_instances_cannot_both_win_the_same_expected_revision(self):
        first = self.provision()
        other = SQLiteStateWitness(self.witness.path)
        first_result = self.witness.commit(NAMESPACE, first, "1" * 64, event_id="writer-one")
        with self.assertRaisesRegex(FreshnessConflict, "compare_and_swap"):
            other.commit(NAMESPACE, first, "2" * 64, event_id="writer-two")
        self.assertEqual(other.head(NAMESPACE), first_result.checkpoint)

    def test_existing_immutable_blob_is_verified_instead_of_overwritten(self):
        digest = self.store.put(self.initial, validator=valid_signature)
        path = self.store.root / (digest + ".json")
        initial = path.read_bytes()
        self.assertEqual(self.store.put(self.initial, validator=valid_signature), digest)
        self.assertEqual(path.read_bytes(), initial)
        path.write_bytes(b"test-only damaged existing blob")
        with self.assertRaises(SnapshotIntegrityError):
            self.store.put(self.initial, validator=valid_signature)
        self.assertEqual(path.read_bytes(), b"test-only damaged existing blob")


if __name__ == "__main__":
    unittest.main()
