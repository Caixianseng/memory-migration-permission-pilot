"""Filesystem-backed service layer for the local Agent Memory Gateway.

This is a single-host trusted gateway. It deliberately does not claim
distributed atomicity, model-input provenance completeness, or erasure of
plaintext that a recipient has already received.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from experiments.persistent_exchange_v1 import store

from .delivery import committed_receipt, deliver


_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRANSFER_ID = re.compile(r"^[a-f0-9]{32}$")


def _agent_id(value: str) -> str:
    if not isinstance(value, str) or not _AGENT_ID.fullmatch(value):
        raise ValueError("invalid_agent_id")
    return value


def _transfer_id(value: str) -> str:
    if not isinstance(value, str) or not _TRANSFER_ID.fullmatch(value):
        raise ValueError("invalid_transfer_id")
    return value


class GatewayService:
    """Owns agent databases, one trusted policy database and a private spool."""

    def __init__(self, data_dir: str | Path):
        supplied = Path(data_dir).expanduser()
        if supplied.is_symlink():
            raise ValueError("data_directory_symlink_forbidden")
        supplied.mkdir(parents=True, exist_ok=True)
        self.root = supplied.resolve()
        self.agent_dir = self.root / "agents"
        self.spool_dir = self.root / "spool"
        self.policy_path = self.root / "policy.sqlite"

        for directory in (self.agent_dir, self.spool_dir):
            if directory.is_symlink():
                raise ValueError("gateway_storage_symlink_forbidden")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.policy_path.is_symlink():
            raise ValueError("policy_database_symlink_forbidden")
        try:
            os.chmod(self.spool_dir, 0o700)
        except OSError:
            # Windows ACLs are managed by the account and parent directory.
            pass

    def _agent_path(self, agent_id: str) -> Path:
        agent_id = _agent_id(agent_id)
        path = self.agent_dir / (agent_id + ".sqlite")
        if path.is_symlink():
            raise ValueError("agent_database_symlink_forbidden")
        return path

    def _open_agent(self, agent_id: str):
        return store.AgentStore(self._agent_path(agent_id), agent_id)

    def _open_policy(self):
        return store.TrustedPolicy(self.policy_path)

    def register_source(
        self,
        agent_id: str,
        source_id: str,
        text: str,
        version: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        agent = self._open_agent(agent_id)
        try:
            source = agent.add_original(
                source_id, text, version=version, metadata=metadata or {}
            )
        finally:
            agent.close()

        policy = self._open_policy()
        try:
            reference = {
                key: source[key]
                for key in ("source_id", "version", "sha256", "owner_id")
            }
            current = policy.db.execute(
                "SELECT source_id,version,sha256,owner_id FROM sources WHERE source_id=?",
                (source_id,),
            ).fetchone()
            if current is None or dict(current) != reference:
                policy.register_sources([source])
            epoch = policy.epoch
        finally:
            policy.close()

        return {"agent_id": agent_id, **reference, "policy_epoch": epoch}

    def create_memory(
        self,
        agent_id: str,
        memory_id: str,
        content: str,
        source_ids: list[str] | None = None,
        parent_memory_ids: list[str] | None = None,
        version: int = 1,
        provenance: dict[str, Any] | None = None,
        kind: str = "derived",
    ) -> dict[str, Any]:
        agent = self._open_agent(agent_id)
        try:
            artifact = agent.add_memory(
                memory_id,
                content,
                source_ids=source_ids or [],
                parent_memory_ids=parent_memory_ids or [],
                version=version,
                provenance=provenance or {},
                kind=kind,
            )
        finally:
            agent.close()

        # Do not return the memory body or arbitrary provenance to API callers.
        return {
            "agent_id": agent_id,
            "memory_key": artifact["memory_key"],
            "memory_id": artifact["memory_id"],
            "version": artifact["version"],
            "kind": artifact["kind"],
            "content_sha256": artifact["content_sha256"],
            "artifact_sha256": artifact["artifact_sha256"],
            "direct_sources": artifact["direct_sources"],
            "dependencies": artifact["dependencies"],
            "parents": artifact["parents"],
        }

    def set_permissions(
        self, recipient_id: str, allowed_source_ids: list[str]
    ) -> dict[str, Any]:
        recipient_id = _agent_id(recipient_id)
        allowed = sorted(set(allowed_source_ids))
        policy = self._open_policy()
        try:
            current = [
                row[0]
                for row in policy.db.execute(
                    "SELECT source_id FROM grants WHERE recipient_id=? ORDER BY source_id",
                    (recipient_id,),
                )
            ]
            if current != allowed:
                epoch = policy.set_permissions(recipient_id, allowed)
            else:
                epoch = policy.epoch
        finally:
            policy.close()
        return {
            "recipient_id": recipient_id,
            "allowed_source_ids": allowed,
            "policy_epoch": epoch,
        }

    def get_permissions(self, recipient_id: str) -> dict[str, Any]:
        recipient_id = _agent_id(recipient_id)
        policy = self._open_policy()
        try:
            allowed = [
                row[0]
                for row in policy.db.execute(
                    "SELECT source_id FROM grants WHERE recipient_id=? ORDER BY source_id",
                    (recipient_id,),
                )
            ]
            return {
                "recipient_id": recipient_id,
                "allowed_source_ids": allowed,
                "policy_epoch": policy.epoch,
            }
        finally:
            policy.close()

    def _transfer_path(self, transfer_id: str) -> Path:
        transfer_id = _transfer_id(transfer_id)
        path = self.spool_dir / (transfer_id + ".json")
        if path.is_symlink():
            raise ValueError("transfer_spool_symlink_forbidden")
        return path

    def _read_packet(self, transfer_id: str) -> dict[str, Any]:
        path = self._transfer_path(transfer_id)
        if not path.is_file():
            raise FileNotFoundError("transfer_not_found")
        raw = path.read_bytes()
        packet = json.loads(raw)
        if store.canonical(packet) + b"\n" != raw:
            raise store.StoreError("transfer_spool_canonical_encoding_invalid")
        if packet.get("import_id") != transfer_id:
            raise store.StoreError("transfer_spool_identity_mismatch")
        return packet

    def prepare_transfer(
        self,
        sender_id: str,
        recipient_id: str,
        memory_refs: list[str],
        batch_id: str | None = None,
    ) -> dict[str, Any]:
        sender_id = _agent_id(sender_id)
        recipient_id = _agent_id(recipient_id)
        if sender_id == recipient_id:
            raise store.StoreError("separate_agent_recipient_required")

        sender = self._open_agent(sender_id)
        policy = self._open_policy()
        try:
            packet = store.export_package(
                sender, policy, recipient_id, memory_refs, batch_id=batch_id
            )
        finally:
            sender.close()
            policy.close()

        transfer_id = _transfer_id(packet["import_id"])
        path = self._transfer_path(transfer_id)
        raw = store.canonical(packet) + b"\n"
        descriptor = os.open(
            str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                path.unlink()
            except OSError:
                pass
            raise

        return {
            "transfer_id": transfer_id,
            "batch_id": packet["batch_id"],
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "policy_epoch": packet["epoch"],
            "packet_sha256": packet["content_sha256"],
            "memory_count": len(packet["memories"]),
            "source_count": len(packet["sources"]),
            "status": "prepared",
        }

    def commit_transfer(self, transfer_id: str) -> dict[str, Any]:
        packet = self._read_packet(transfer_id)
        receiver = self._open_agent(packet["recipient_id"])
        policy = self._open_policy()
        try:
            return deliver(receiver, policy, packet)
        finally:
            receiver.close()
            policy.close()

    def get_transfer(self, transfer_id: str) -> dict[str, Any]:
        packet = self._read_packet(transfer_id)
        receiver = self._open_agent(packet["recipient_id"])
        policy = self._open_policy()
        try:
            receipt = committed_receipt(receiver, packet)
            if receipt is not None:
                status = "committed"
                reason = None
            else:
                try:
                    policy.check_dependencies(
                        packet["recipient_id"], packet["sources"], packet["epoch"]
                    )
                    status = "ready"
                    reason = None
                except store.StoreError as exc:
                    status = "blocked"
                    reason = str(exc)
            return {
                "transfer_id": transfer_id,
                "batch_id": packet["batch_id"],
                "sender_id": packet["sender_id"],
                "recipient_id": packet["recipient_id"],
                "policy_epoch": packet["epoch"],
                "packet_sha256": packet["content_sha256"],
                "status": status,
                "block_reason": reason,
                "receipt": receipt,
            }
        finally:
            receiver.close()
            policy.close()

    def discard_transfer(self, transfer_id: str) -> dict[str, Any]:
        path = self._transfer_path(transfer_id)
        if not path.is_file():
            raise FileNotFoundError("transfer_not_found")
        path.unlink()
        # The one-use seal remains unconsumed in the policy DB. Deleting the
        # local packet cannot authorize or complete a transfer.
        return {
            "transfer_id": transfer_id,
            "status": "discarded",
            "seal_remains_unconsumed": True,
        }

    def retrieve_batch(self, agent_id: str, batch_id: str) -> dict[str, Any]:
        receiver = self._open_agent(agent_id)
        try:
            exists = receiver.db.execute(
                "SELECT 1 FROM batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if exists is None:
                raise FileNotFoundError("batch_not_found")
            result = receiver.retrieve(batch_id)
            return {
                "agent_id": agent_id,
                "batch_id": batch_id,
                "memory": result["memory"],
                "memories": [
                    {
                        key: item[key]
                        for key in (
                            "memory_key",
                            "memory_id",
                            "version",
                            "origin_agent",
                            "content_sha256",
                            "kind",
                            "artifact_sha256",
                        )
                    }
                    for item in result["memories"]
                ],
                "source_ids": result["source_ids"],
                "query_receipt": result["query_receipt"],
            }
        finally:
            receiver.close()

    def audit(self, agent_id: str, limit: int = 100) -> dict[str, Any]:
        agent = self._open_agent(agent_id)
        try:
            chain = store.verify_events(agent.db)
            rows = agent.db.execute(
                "SELECT seq,kind,previous,payload_json,event_hash "
                "FROM events ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
            events = [
                {
                    "seq": row["seq"],
                    "kind": row["kind"],
                    "previous": row["previous"],
                    "payload": json.loads(row["payload_json"]),
                    "event_hash": row["event_hash"],
                }
                for row in reversed(rows)
            ]
            return {"agent_id": agent_id, "chain": chain, "events": events}
        finally:
            agent.close()
