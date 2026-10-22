"""Explicit conjunctive, three-valued authorization and simple baselines."""
from __future__ import annotations

import hashlib
import json

METHODS = ("exact_groups", "reader_copies", "reject_all", "partial")
RULES = ("source_readers", "recipient_readers", "target_readers")


def stable_id(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]


def validate_case(case: dict) -> None:
    if not isinstance(case.get("case_id"), str) or not case["case_id"]:
        raise ValueError("case_id is required")
    actors = case.get("actors")
    if not isinstance(actors, list) or not actors:
        raise ValueError("explicit actors are required")
    ids, bindings = [], []
    for actor in actors:
        for key in ("actor_id", "user_id", "agent_id"):
            if not isinstance(actor.get(key), str) or not actor[key]:
                raise ValueError("actors require actor_id, user_id and agent_id")
        ids.append(actor["actor_id"])
        bindings.append((actor["user_id"], actor["agent_id"]))
    if len(set(ids)) != len(ids) or len(set(bindings)) != len(bindings):
        raise ValueError("actor identifiers and user/agent bindings must be unique")
    mapping = case.get("actor_mapping")
    if not isinstance(mapping, dict) or set(mapping) != set(ids):
        raise ValueError("identity mapping must cover exactly all actors")
    if any(not isinstance(v, str) or not v for v in mapping.values()) or len(set(mapping.values())) != len(ids):
        raise ValueError("identity mapping must be complete and injective")
    records = case.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("records must be nonempty")
    seen = set()
    for record in records:
        source_id = record.get("source_id")
        if not isinstance(source_id, str) or not source_id or source_id in seen:
            raise ValueError("source_id must be nonempty and unique")
        seen.add(source_id)
        if not isinstance(record.get("text"), str) or not record["text"].strip():
            raise ValueError("nonempty source text is required")
        for field in RULES:
            values = record.get(field)
            if values is not None and (not isinstance(values, list) or len(values) != len(set(values)) or any(v not in ids for v in values)):
                raise ValueError(f"{field} must explicitly list registered actors or be unknown")
        for field in ("export_allowed", "copy_allowed"):
            if record.get(field) is not None and type(record[field]) is not bool:
                raise ValueError(f"{field} must be boolean or unknown")


def decision(record: dict, actor_id: str, *, source_only: bool = False) -> str:
    """An explicit denial dominates missing rules; missing rules never allow."""
    rules = ("source_readers",) if source_only else RULES
    values = [record.get(key) for key in rules]
    if any(value is not None and actor_id not in value for value in values):
        return "deny"
    return "unknown" if any(value is None for value in values) else "allow"


def make_plan(case: dict, method: str, run_id: str, *, source_only: bool = False,
              keep_source: bool = False, partial_limit: int = 1) -> dict:
    validate_case(case)
    if method not in METHODS:
        raise ValueError("unknown method")
    if not run_id or not isinstance(run_id, str):
        raise ValueError("run_id is required")
    if partial_limit < 0:
        raise ValueError("partial_limit must be nonnegative")
    actors = [a["actor_id"] for a in case["actors"]]
    mapping = {r["source_id"]: [] for r in case["records"]}
    objects, groups, excluded = [], {}, []
    for record in case["records"]:
        source_id = record["source_id"]
        readers = sorted(a for a in actors if decision(record, a, source_only=source_only) == "allow")
        reason = None
        if not keep_source and record.get("export_allowed") is not True:
            reason = "export_forbidden" if record.get("export_allowed") is False else "export_unknown"
        elif method == "reject_all":
            reason = "reject_all_diagnostic"
        elif any(decision(record, a, source_only=source_only) == "unknown" for a in actors):
            reason = "authorization_unknown"
        elif method == "reader_copies" and record.get("copy_allowed") is not True:
            reason = "copy_forbidden" if record.get("copy_allowed") is False else "copy_unknown"
        elif not readers:
            reason = "no_common_readers"
        elif method == "partial" and len(objects) >= partial_limit:
            reason = "artificial_partial_stress"
        if reason:
            excluded.append({"source_id": source_id, "reason": reason})
            continue
        partitions = [[a] for a in readers] if method == "reader_copies" else [readers]
        for partition in partitions:
            # Include both run and actor namespace; no reuse of source IDs as target IDs.
            container = f"{run_id}/group/{stable_id(partition)}"
            target_id = f"{run_id}/{stable_id(partition)}/{stable_id(source_id)}"
            groups.setdefault(container, {"container_id": container, "readers": partition, "target_ids": []})["target_ids"].append(target_id)
            objects.append({"target_id": target_id, "source_id": source_id,
                            "text": record["text"], "readers": partition, "container_id": container})
            mapping[source_id].append(target_id)
    return {"schema_version": 1, "case_id": case["case_id"], "method": method, "run_id": run_id,
            "objects": objects, "containers": list(groups.values()), "object_mapping": mapping,
            "mapping_complete": True, "inventory_complete": True, "excluded": excluded,
            "backend_kind": "reference_backend", "source_only": source_only,
            "artificial_stress": method == "partial", "resource_constraint_origin": "artificial_diagnostic" if method == "partial" else "none"}
