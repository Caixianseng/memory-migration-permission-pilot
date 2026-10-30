"""Independent current-state witnesses and durable, content-addressed snapshots.

An HMAC authenticates a snapshot; it cannot establish that the snapshot is the
latest one. ``offline_snapshot`` therefore makes no current-state claim. A
``current`` caller must consult a separately trusted witness before delivery.

The SQLite implementation is a local, transaction-tested witness adapter. Its
database and write authority MUST be protected outside the rollback/failure
domain of the snapshot store in a deployment claiming rollback resistance.
Putting two files in different local directories is only a controlled example;
it cannot protect against an administrator rolling both stores back together.
No signing key, source text, model input or answer is stored by the witness.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable


OFFLINE_SNAPSHOT = "offline_snapshot"
CURRENT = "current"
_STATE_VERSION = "local_memory_labels_v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class WitnessUnavailable(RuntimeError):
    """Current state is unknown; this is not an authorization denial."""


class FreshnessConflict(ValueError):
    """A stale update or a changed event cannot replace the current head."""


class SnapshotIntegrityError(ValueError):
    """The snapshot's bytes, signature or lifecycle structure are invalid."""


def _identifier(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and "\x00" not in value


def _digest(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _require(value, code):
    if not value:
        raise ValueError(code)


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        raise SnapshotIntegrityError("snapshot_not_canonical_json") from None


def _state(envelope):
    if (not isinstance(envelope, dict) or set(envelope) != {"state", "signature"}
            or not _digest(envelope.get("signature"))):
        raise SnapshotIntegrityError("signed_snapshot_envelope_invalid")
    data = envelope["state"]
    if (not isinstance(data, dict)
            or set(data) != {"version", "epoch", "revoked_records", "revoked_sources"}
            or data["version"] != _STATE_VERSION or type(data["epoch"]) is not int
            or data["epoch"] < 0):
        raise SnapshotIntegrityError("lifecycle_state_invalid")
    for key in ("revoked_records", "revoked_sources"):
        values = data[key]
        if (not isinstance(values, list) or any(not _identifier(v) for v in values)
                or values != sorted(set(values))):
            raise SnapshotIntegrityError("lifecycle_revocations_not_canonical")
    return data


def state_sha256(envelope: dict) -> str:
    """Digest the complete signed envelope, without asserting HMAC validity."""
    _state(envelope)
    return hashlib.sha256(_canonical(envelope)).hexdigest()


def assert_monotonic_lifecycle(previous: dict, following: dict) -> None:
    """The trusted publishing path cannot erase acknowledged revocations."""
    old, new = _state(previous), _state(following)
    if (new["epoch"] < old["epoch"]
            or not set(old["revoked_records"]) <= set(new["revoked_records"])
            or not set(old["revoked_sources"]) <= set(new["revoked_sources"])):
        raise FreshnessConflict("lifecycle_rollback_forbidden")


@dataclass(frozen=True)
class Checkpoint:
    namespace: str
    revision: int
    state_sha256: str

    def __post_init__(self):
        _require(_identifier(self.namespace), "invalid_witness_namespace")
        _require(type(self.revision) is int and 0 <= self.revision < 2**63,
                 "invalid_witness_revision")
        _require(_digest(self.state_sha256), "invalid_state_sha256")


@dataclass(frozen=True)
class FreshnessResult:
    status: str  # current / stale / unknown, never an allow/deny decision
    code: str
    checkpoint: Checkpoint | None


@dataclass(frozen=True)
class CommitReceipt:
    checkpoint: Checkpoint  # actual latest head, including for old duplicates
    event_checkpoint: Checkpoint
    replayed: bool


class SQLiteStateWitness:
    """Trusted-host adapter; reads never create or provision a missing state.

    ``create=True`` creates only an empty ledger. Registering a namespace needs
    a separate explicit ``provision`` call. A rollbackable snapshot must never
    be used to auto-register an unknown namespace during recovery.

    ``commit`` is the low-level digest CAS primitive. Authority code should use
    ``commit_snapshot`` so signature validation and monotonic lifecycle checks
    precede an update. Access to this write API is a trusted-host capability.
    """

    def __init__(self, path: Path | str, *, create: bool = False):
        supplied = Path(path).absolute()
        _require(not supplied.is_symlink(), "witness_path_is_linked")
        self.path = supplied.resolve()
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                # sqlite3.Connection's own context manager commits/rolls back,
                # but does not close its file handle (visible on Windows).
                with closing(sqlite3.connect(self.path, timeout=2.0)) as connection:
                    connection.executescript("""
                        PRAGMA synchronous=FULL;
                        CREATE TABLE IF NOT EXISTS witness_heads (
                            namespace TEXT PRIMARY KEY,
                            revision INTEGER NOT NULL CHECK(revision >= 0),
                            state_sha256 TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS witness_events (
                            namespace TEXT NOT NULL,
                            event_id TEXT NOT NULL,
                            expected_revision INTEGER NOT NULL,
                            expected_sha256 TEXT NOT NULL,
                            state_sha256 TEXT NOT NULL,
                            applied_revision INTEGER NOT NULL,
                            PRIMARY KEY(namespace, event_id)
                        );
                    """)
            except (sqlite3.Error, OSError):
                raise WitnessUnavailable("witness_unavailable") from None

    def __repr__(self):
        return "<SQLiteStateWitness: separately trusted current-state ledger>"

    def _connect(self):
        if self.path.is_symlink() or self.path.resolve() != self.path:
            raise WitnessUnavailable("witness_unavailable")
        # mode=rw refuses to manufacture a fresh empty database after loss.
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2.0)
        try:
            connection.execute("PRAGMA synchronous=FULL")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def _transaction(self):
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except (sqlite3.Error, OSError):
            if connection is not None:
                connection.rollback()
            raise WitnessUnavailable("witness_unavailable") from None
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _head(connection, namespace):
        row = connection.execute(
            "SELECT revision, state_sha256 FROM witness_heads WHERE namespace=?",
            (namespace,)).fetchone()
        if row is None:
            return None
        try:
            return Checkpoint(namespace, row[0], row[1])
        except ValueError:
            raise WitnessUnavailable("witness_head_invalid") from None

    def head(self, namespace: str) -> Checkpoint | None:
        _require(_identifier(namespace), "invalid_witness_namespace")
        connection = None
        try:
            connection = self._connect()
            return self._head(connection, namespace)
        except (sqlite3.Error, OSError):
            raise WitnessUnavailable("witness_unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    def check(self, namespace: str, envelope_sha256: str) -> FreshnessResult:
        _require(_identifier(namespace), "invalid_witness_namespace")
        _require(_digest(envelope_sha256), "invalid_state_sha256")
        try:
            checkpoint = self.head(namespace)
        except WitnessUnavailable:
            return FreshnessResult("unknown", "witness_unavailable", None)
        if checkpoint is None:
            return FreshnessResult("unknown", "witness_unprovisioned", None)
        if checkpoint.state_sha256 != envelope_sha256:
            return FreshnessResult("stale", "snapshot_not_current", checkpoint)
        return FreshnessResult("current", "current_checkpoint_matches", checkpoint)

    def provision(self, namespace: str, envelope_sha256: str, *,
                  event_id: str = "provision") -> Checkpoint:
        checkpoint = Checkpoint(namespace, 0, envelope_sha256)
        _require(_identifier(event_id), "invalid_witness_event_id")
        with self._transaction() as connection:
            if self._head(connection, namespace) is not None:
                raise FreshnessConflict("witness_already_provisioned")
            connection.execute("INSERT INTO witness_heads VALUES (?,?,?)",
                               (namespace, 0, envelope_sha256))
            connection.execute("INSERT INTO witness_events VALUES (?,?,?,?,?,?)",
                               (namespace, event_id, -1, "", envelope_sha256, 0))
        return checkpoint

    def commit(self, namespace: str, expected: Checkpoint, envelope_sha256: str,
               *, event_id: str) -> CommitReceipt:
        _require(isinstance(expected, Checkpoint) and expected.namespace == namespace,
                 "expected_checkpoint_namespace_mismatch")
        _require(_digest(envelope_sha256), "invalid_state_sha256")
        _require(_identifier(event_id), "invalid_witness_event_id")
        with self._transaction() as connection:
            current = self._head(connection, namespace)
            if current is None:
                raise FreshnessConflict("witness_not_provisioned")
            event = connection.execute(
                "SELECT expected_revision,expected_sha256,state_sha256,applied_revision "
                "FROM witness_events WHERE namespace=? AND event_id=?",
                (namespace, event_id)).fetchone()
            if event is not None:
                if event[:3] != (expected.revision, expected.state_sha256, envelope_sha256):
                    raise FreshnessConflict("witness_event_body_changed")
                committed = Checkpoint(namespace, event[3], envelope_sha256)
                return CommitReceipt(current, committed, True)
            if current != expected:
                raise FreshnessConflict("witness_compare_and_swap_failed")
            following = Checkpoint(namespace, current.revision + 1, envelope_sha256)
            connection.execute(
                "UPDATE witness_heads SET revision=?, state_sha256=? WHERE namespace=?",
                (following.revision, following.state_sha256, namespace))
            connection.execute("INSERT INTO witness_events VALUES (?,?,?,?,?,?)",
                               (namespace, event_id, expected.revision, expected.state_sha256,
                                following.state_sha256, following.revision))
            return CommitReceipt(following, following, False)


class SignedSnapshotStore:
    """Append-only API for signed lifecycle blobs; it holds no signing key.

    A blob is file-fsynced and atomically published without overwriting an
    existing blob. POSIX also fsyncs the directory. Windows uses file fsync;
    this local helper is not a hardware power-loss or distributed transaction
    guarantee. Hash and caller-provided HMAC validation are repeated on reads.
    """

    def __init__(self, root: Path | str, *, max_bytes: int = 4 * 1024 * 1024):
        supplied = Path(root).absolute()
        _require(not supplied.is_symlink(), "snapshot_root_is_linked")
        self.root = supplied.resolve()
        _require(type(max_bytes) is int and max_bytes > 0, "invalid_snapshot_byte_limit")
        self.max_bytes = max_bytes
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _path(self, digest):
        _require(_digest(digest), "invalid_state_sha256")
        if self.root.is_symlink() or self.root.resolve() != self.root:
            raise SnapshotIntegrityError("snapshot_root_changed")
        path = self.root / (digest + ".json")
        if path.is_symlink():
            raise SnapshotIntegrityError("snapshot_blob_is_linked")
        return path

    @staticmethod
    def _validate(envelope, validator):
        _state(envelope)
        if not callable(validator):
            raise ValueError("snapshot_signature_validator_required")
        try:
            valid = validator(json.loads(_canonical(envelope))) is True
        except Exception:
            valid = False
        if not valid:
            raise SnapshotIntegrityError("snapshot_signature_invalid")

    def _directory_fsync(self):
        if os.name != "nt":
            descriptor = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def put(self, envelope: dict, *, validator: Callable[[dict], bool]) -> str:
        raw = _canonical(envelope)
        if len(raw) > self.max_bytes:
            raise SnapshotIntegrityError("snapshot_byte_limit_exceeded")
        isolated = json.loads(raw)
        self._validate(isolated, validator)
        digest = state_sha256(isolated)
        destination = self._path(digest)
        if destination.exists():
            self.load(digest, validator=validator)
            return digest
        descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=self.root)
        temporary = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                # Atomic publication, no overwrite even with competing writers.
                os.link(temporary, destination)
            except FileExistsError:
                self.load(digest, validator=validator)
            self._directory_fsync()
        finally:
            temporary.unlink(missing_ok=True)
        return digest

    def load(self, digest: str, *, validator: Callable[[dict], bool]) -> dict:
        path = self._path(digest)
        if not path.is_file() or path.stat().st_size > self.max_bytes:
            raise SnapshotIntegrityError("snapshot_blob_missing_or_oversize")
        with path.open("rb") as stream:
            raw = stream.read(self.max_bytes + 1)
        if len(raw) > self.max_bytes or hashlib.sha256(raw).hexdigest() != digest:
            raise SnapshotIntegrityError("snapshot_blob_sha256_mismatch")
        try:
            envelope = json.loads(raw)
        except (ValueError, UnicodeError):
            raise SnapshotIntegrityError("snapshot_blob_json_invalid") from None
        if _canonical(envelope) != raw or state_sha256(envelope) != digest:
            raise SnapshotIntegrityError("snapshot_blob_not_canonical")
        self._validate(envelope, validator)
        return envelope


def provision_snapshot(store: SignedSnapshotStore, witness, namespace: str,
                       envelope: dict, *, validator: Callable[[dict], bool],
                       event_id: str = "provision") -> Checkpoint:
    """Trusted explicit provisioning: durable validated blob, then witness CAS."""
    digest = store.put(envelope, validator=validator)
    return witness.provision(namespace, digest, event_id=event_id)


def commit_snapshot(store: SignedSnapshotStore, witness, namespace: str,
                    expected: Checkpoint, envelope: dict, *,
                    validator: Callable[[dict], bool], event_id: str) -> Checkpoint:
    """Publish before acknowledging; never erase revocations on this path.

    A crash before the witness commit leaves an unacknowledged immutable blob.
    It cannot make that blob current. A crash after the witness commit leaves
    the already-published blob recoverable by its witnessed digest. Callers
    must not acknowledge a revocation or update local state on an exception.
    """
    _require(isinstance(expected, Checkpoint) and expected.namespace == namespace,
             "expected_checkpoint_namespace_mismatch")
    previous = store.load(expected.state_sha256, validator=validator)
    store._validate(envelope, validator)
    assert_monotonic_lifecycle(previous, envelope)
    digest = store.put(envelope, validator=validator)
    receipt = witness.commit(namespace, expected, digest, event_id=event_id)
    if receipt.checkpoint != receipt.event_checkpoint:
        raise FreshnessConflict("witness_event_already_superseded")
    if receipt.checkpoint.state_sha256 != digest:
        raise FreshnessConflict("witness_committed_digest_mismatch")
    return receipt.checkpoint
