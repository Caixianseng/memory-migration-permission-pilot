"""Isolated bridge of existing signed/current reads and native transfer policy.

The fixture is trusted research policy, not product IAM. No model/network I/O.
Read scope never supplies missing transfer rights.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import secrets

from memory_migration_study.authority_freshness import SQLiteStateWitness, SignedSnapshotStore
from memory_migration_study.current_authority import (
    CurrentMemoryAuthority, CurrentReadDecision, prepare_current_transfer, restore_current_answer,
)
from memory_migration_study.native_agent_protocol import NativeAgentBroker

SENDER = ("sender_user", "agentA")
RECEIVER = ("receiver_user", "agentB")
VERSION = "isolated_signed_current_native_transfer_bridge_v1"


class HandoffSession:
    def __init__(self, case: dict, state_dir: Path):
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=False)
        self.case = case
        self.policy = {"version": "ports-v1", "protected_categories": ["CUSTOMER"],
                       "entity_registry": [{"value": row["protected_value"], "category": "CUSTOMER"}
                                           for row in case["records"]]}
        self.rows = {row["source_id"]: row for row in case["records"]}
        self.live_denied = set()
        self.live_calls = 0
        self.authority = CurrentMemoryAuthority.provision(secrets.token_bytes(32),
            namespace="ports-" + case["story_id"],
            witness=SQLiteStateWitness(state_dir / "current_witness.sqlite", create=True),
            snapshot_store=SignedSnapshotStore(state_dir / "signed_snapshots"),
            live_authorizer=self._live)
        self.records = []
        native_records = []
        for row in case["records"]:
            text = row["text"]
            value = row["protected_value"]
            start = text.index(value)
            principals = [{"user_id": SENDER[0], "agent_id": SENDER[1]}]
            if row["recipient_read"] is True:
                principals.append({"user_id": RECEIVER[0], "agent_id": RECEIVER[1]})
            record = self.authority.build_record(
                {"source_id": row["source_id"], "text": text},
                {"text": text, "source_start": 0, "source_end": len(text),
                 "findings": [{"start": start, "end": start + len(value), "category": "CUSTOMER"}]},
                self.policy, owner_id="fixture_owner", agent_id="fixture_builder",
                builder_version="deterministic-port-fixture-v1", allowed_principals=principals)
            # Reuse the original validators before constructing another schema.
            if self.authority.access_decision(record, actor_id=SENDER[0], agent_id=SENDER[1],
                                              policy_version=self.policy["version"])["decision"] != "allow":
                raise ValueError("source_read_not_authorized")
            self.records.append(record)
            readers = ["sender"] + (["receiver"] if row["recipient_read"] is True else [])
            native_records.append({"record_id": record["record_id"], "source_id": record["record_id"],
                "text": record["text"], "source": record["source"],
                "source_start": record["source_start"], "source_end": record["source_end"],
                "source_readers": readers, "recipient_readers": readers, "target_readers": readers,
                # Explicit trusted fixture values: never infer these from read.
                "export_allowed": row.get("export_allowed"), "copy_allowed": row.get("copy_allowed")})
        self.by_record = {r["record_id"]: r for r in self.records}
        self.by_source = {r["source"]["source_id"]: r for r in self.records}
        self.broker = NativeAgentBroker({"case_id": case["story_id"], "actors": [
            {"actor_id": "sender", "user_id": SENDER[0], "agent_id": SENDER[1], "workspace_id": "source"},
            {"actor_id": "receiver", "user_id": RECEIVER[0], "agent_id": RECEIVER[1], "workspace_id": "target"}],
            "records": native_records, "actor_mapping": {"sender": "sender", "receiver": "receiver"}},
            key=secrets.token_bytes(32), policy_version=self.policy["version"])

    def _live(self, request):
        self.live_calls += 1
        pair = (request.principal.user_id, request.principal.agent_id)
        row = self.rows.get(request.source_id)
        allowed = (row is not None and request.source_id not in self.live_denied and
                   (pair == SENDER or (pair == RECEIVER and row["recipient_read"] is True)))
        return CurrentReadDecision.for_request(request, "allow" if allowed else "deny")

    def eligible(self):
        result, excluded = [], []
        for record in self.records:
            sid = record["source"]["source_id"]
            row = self.rows[sid]
            decision = self.authority.access_decision(record, actor_id=RECEIVER[0], agent_id=RECEIVER[1],
                                                       policy_version=self.policy["version"])
            if decision["decision"] != "allow":
                excluded.append({"source_id": sid, "reason": "current_read_" + decision["decision"]})
            elif row.get("export_allowed") is not True or row.get("copy_allowed") is not True:
                excluded.append({"source_id": sid, "reason": "explicit_transfer_not_allowed"})
            else:
                result.append(record)
        return result, excluded

    def prepare(self, records, request_id):
        if not records:
            raise ValueError("empty_selection")
        packet = self.broker.export([r["record_id"] for r in records], sender_actor_id="sender",
            recipient_actor_id="receiver", transfer_id=request_id, ttl_seconds=3600)
        self.broker.validate(packet, sender_actor_id="sender", actor_id="receiver")
        self._check_binding(records, packet, request_id)
        prepared = prepare_current_transfer(records, self.case["query"], self.policy,
            authority=self.authority, actor_id=RECEIVER[0], agent_id=RECEIVER[1],
            request_id=request_id, mode="generation",
            agent=lambda **_: {"status": "ok", "findings": [], "local_calls": 0})
        if prepared["status"] != "ok":
            raise ValueError("prepare_" + str(prepared.get("error")))
        return {"prepared": prepared, "records": records, "packet": packet, "request_id": request_id}

    @staticmethod
    def _check_binding(records, packet, request_id):
        # Separate valid signatures must not authorize splicing different objects.
        if packet["transfer_id"] != request_id or len(records) != len(packet["items"]):
            raise ValueError("bridge_binding_mismatch")
        for record, item in zip(records, packet["items"]):
            origin = item["origin"]
            if (item["record_id"] != record["record_id"] or item["text"] != record["text"]
                    or item["content_sha256"] != hashlib.sha256(record["text"].encode()).hexdigest()
                    or origin != {"source_id": record["source"]["source_id"],
                                  "source_sha256": record["source"]["sha256"],
                                  "source_start": record["source_start"], "source_end": record["source_end"]}):
                raise ValueError("bridge_binding_mismatch")

    def restore(self, answer, request, *, user=RECEIVER[0], agent=RECEIVER[1]):
        self.broker.validate(request["packet"], sender_actor_id="sender", actor_id="receiver")
        self._check_binding(request["records"], request["packet"], request["request_id"])
        return restore_current_answer(answer, request["prepared"], request["records"], self.policy,
            authority=self.authority, actor_id=user, agent_id=agent, request_id=request["request_id"])

    def revoke(self, source_id):
        record = self.by_source[source_id]
        self.live_denied.add(source_id)
        self.authority.revoke_source(source_id, event_id="revoke-" + source_id)
        self.broker.revoke(record["record_id"])
