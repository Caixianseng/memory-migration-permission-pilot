"""Bounded GateMem candidates; no automatic ACL or task qualification."""
from __future__ import annotations

from pathlib import Path

from memory_migration_pilot.data import load_bundle


def prepare_gatemem(data_root: Path, *, episodes_per_domain=1, limit=20, seed=42) -> dict:
    bundle = load_bundle(data_root, "gatemem", domains=("office", "household"),
                         episodes_per_domain=episodes_per_domain, limit=limit, seed=seed)
    candidates = []
    for record in bundle["records"]:
        candidates.append({"source_id": record["id"], "text": record["text"],
                           "source_ref": record["source_ref"], "status": "needs_review",
                           "suggested_controlled_source_readers": record["allowed_users"],
                           "policy_origin": "researcher_controlled_candidate_not_upstream_acl",
                           "source_readers": None, "recipient_readers": None, "target_readers": None,
                           "export_allowed": None, "copy_allowed": None,
                           "qualification_reasons": ["controller_approval_missing", "task_fact_and_reference_unreviewed"]})
    return {"schema_version": 1, "dataset": "gatemem", "status": "needs_review",
            "candidates": candidates, "input_files": bundle["input_files"], "audit": bundle["audit"],
            "natural_authorization_eligible_cases": 0, "qualified_controlled_cases": 0,
            "candidate_records": len(candidates), "runtime_tasks": [], "real_llm_metrics": None,
            "hidden_labels_loaded_into_output": False,
            "note": "Only pre-first-checkpoint visible dialogue is reused. Candidates cannot enter main scoring before explicit controller and task review."}
