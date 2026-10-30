"""Independent finite-request-domain checker; no planner/decision imports.

This checks the configuration model, NOT product enforcement and NOT Cedar.
Trusted target constraints must be supplied independently of the plan.
"""
from __future__ import annotations

from collections import Counter


def verify_plan(case, plan, *, implicit_readers=(), allowed_reader_sets=None,
                source_only=False, keep_source=False):
    actors = {a["actor_id"] for a in case["actors"]}
    records = {r["source_id"]: r for r in case["records"]}
    implicit = set(implicit_readers)
    if not implicit <= actors:
        raise ValueError("unregistered_implicit_reader")
    allowed_sets = None if allowed_reader_sets is None else {frozenset(g) for g in allowed_reader_sets}
    errors, expected, unknown, actual = [], set(), set(), set()
    if plan.get("case_id") != case["case_id"]:
        errors.append("case_identity_mismatch")
    if plan.get("source_only") is not source_only:
        errors.append("reference_scope_mismatch")
    binding_map = case.get("actor_mapping", {})
    if set(binding_map) != actors or len(set(binding_map.values())) != len(actors):
        errors.append("identity_mapping_invalid")
    for sid, record in records.items():
        # Reference scope is chosen by the verifier caller, never by the plan
        # being evaluated. A plan cannot weaken the oracle by changing a flag.
        fields = ("source_readers",) if source_only else ("source_readers", "recipient_readers", "target_readers")
        for actor in actors:
            rules = [record.get(f) for f in fields]
            if any(rule is not None and actor not in rule for rule in rules):
                continue
            if any(rule is None for rule in rules):
                unknown.add((actor, sid))
            else:
                expected.add((actor, sid))
    objects = plan.get("objects", [])
    containers = plan.get("containers", [])
    tids = [o["target_id"] for o in objects]
    cids = [g["container_id"] for g in containers]
    if len(tids) != len(set(tids)):
        errors.append("duplicate_target_id")
    if len(cids) != len(set(cids)):
        errors.append("duplicate_container_id")
    groups = {g["container_id"]: g for g in containers}
    calculated_mapping = {sid: [] for sid in records}
    actual_members = {cid: [] for cid in groups}
    for obj in objects:
        sid, tid, cid = obj["source_id"], obj["target_id"], obj["container_id"]
        if sid not in records or cid not in groups:
            errors.append("unregistered_source_or_container")
            continue
        group_readers = set(groups[cid]["readers"])
        effective = group_readers | implicit
        if not effective <= actors:
            errors.append("unregistered_target_reader")
        if allowed_sets is not None and frozenset(effective) not in allowed_sets:
            errors.append("target_reader_set_not_representable")
        if set(obj["readers"]) != group_readers:
            errors.append("object_container_readers_disagree")
        if obj["text"] != records[sid]["text"]:
            errors.append("content_changed")
        if not tid.startswith(plan["run_id"] + "/") or not cid.startswith(plan["run_id"] + "/"):
            errors.append("target_namespace_mismatch")
        if not keep_source and records[sid].get("export_allowed") is not True:
            errors.append("export_not_allowed")
        calculated_mapping[sid].append(tid)
        actual_members[cid].append(tid)
        actual |= {(a, sid) for a in effective}
    for sid, copies in calculated_mapping.items():
        if len(copies) > 1 and records[sid].get("copy_allowed") is not True:
            errors.append("replication_not_allowed")
    if {k: sorted(v) for k, v in plan.get("object_mapping", {}).items()} != {k: sorted(v) for k, v in calculated_mapping.items()}:
        errors.append("object_mapping_incomplete_or_incorrect")
    for cid, group in groups.items():
        if sorted(group["target_ids"]) != sorted(actual_members[cid]):
            errors.append("container_inventory_incorrect")
        if not group["target_ids"]:
            errors.append("empty_container")
    if plan.get("mapping_complete") is not True or plan.get("inventory_complete") is not True:
        errors.append("inventory_not_declared_complete")
    added, missing = actual - expected, expected - actual
    def requests(edges):
        return [{"actor_id": a, "source_id": sid, "operation": "read"} for a, sid in sorted(edges)]
    return {"kind": "finite_configuration_model_only", "registered_requests": len(actors) * len(records),
            "added": requests(added), "missing": requests(missing), "unknown_reference": requests(unknown),
            "structural_errors": sorted(set(errors)), "safe": not added and not errors and not unknown,
            "equivalent": not added and not missing and not errors and not unknown,
            "container_count": len(containers), "object_count": len(objects),
            "copy_counts": dict(Counter(o["source_id"] for o in objects)), "native_enforcement_verified": False}
