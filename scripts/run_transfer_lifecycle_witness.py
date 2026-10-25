"""Zero-model local A->B lifecycle witnesses with two PREEXISTING grants.

Both standard-authorized arms share the same signed exact-fact records. The
sources' independence is an explicit self-authored fixture premise, not inferred
from equal text. Old prepared contexts are conservatively checked as a whole;
only a fresh context can select the still-valid original G2 after G1 revocation.
No key, capability map, token, or model response is written to the report.
Records include full original source text for trusted-host verification; this
JSON envelope must not be equated with a payload exposed to an untrusted Agent.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_migration_study.memory_labels import (ACCESS_SCOPE_VERSION, MemoryLabelAuthority,
    prepare_labeled_transfer, restore_labeled_answer)
from memory_migration_study.privacy import _digest, _policy


VERSION = "preexisting_independent_grants_local_lifecycle_v1"
FACT_VALUE = "Cedar Collective"
POLICY = {"version": "two-existing-grants-v1", "protected_categories": ["CUSTOMER"]}
RECEIPT_FILES = ("memory_labels.py", "privacy.py", "privacy_egress.py", "boundary_detector.py",
                 "boundary_reconciliation.py", "boundary_preparation.py", "structured_candidates.py", "amount_candidates.py")


class ZeroModelDetector:
    """A local test instrument, never a learned model or external transport."""
    max_local_calls = 1

    def __init__(self):
        self.invocations = 0

    def __call__(self, **kwargs):
        self.invocations += 1
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 0, "elapsed_seconds": 0.0}


def _build_records(authority):
    records, receipts = [], []
    for index, alias in enumerate(("G1", "G2"), 1):
        fact_text = "Customer: "+FACT_VALUE
        source = {"source_id": "pretrusted-source-"+alias,
                  "text": fact_text+"\nEvidence document: independently provided document "+str(index)}
        fact = {"text": fact_text, "source_start": 0, "source_end": len(fact_text),
                "findings": [{"start": len("Customer: "), "end": len(fact_text), "category": "CUSTOMER"}]}
        record = authority.build_record(source, fact, POLICY, owner_id="owner", readers=["owner"],
            agent_id="agent-A", allowed_agent_ids=["agent-B"], builder_version="zero_model_exact_fact_fixture_v1",
            detector_version="manual_fixture_labels_v1")
        # Exercise actual serialization without exporting the authority key/map.
        record = json.loads(json.dumps(record, ensure_ascii=False))
        records.append(record)
        receipts.append({"alias": alias, "issued_at_step": index, "source_id": source["source_id"],
            "source_sha256": record["source"]["sha256"], "fact_sha256": record["access"]["content_sha256"],
            "record_sha256": _digest(record), "grant_sha256": _digest(record["access"]),
            "scope_version": record["access"]["scope_version"]})
    return records, receipts


def _safe_transfer(prepared):
    return {"status": prepared.get("status"), "error": prepared.get("error"),
            "egress_status": prepared.get("egress", {}).get("status"),
            "local_calls": prepared.get("local_calls"),
            "access_check_count": len(prepared.get("checks", []))}


def _prepare(authority, records, pipeline, request_id, detector):
    return prepare_labeled_transfer(records, "", POLICY, authority=authority,
        actor_id="owner", agent_id="agent-B", request_id=request_id, mode="generation",
        privacy_pipeline=pipeline, agent=detector)


def _probe(authority, records, prepared, request_id, policy=None):
    if prepared.get("status") != "ok":
        return {"status": "blocked", "error": "transfer_not_ready", "fact_matches": False, "answer_sha256": None}
    mapping = prepared["mapping"]
    # Instrument-only: choose an existing token with actual authorized memory
    # sources, not a query-provided answer or a generated/model answer.
    token = next((token for token, entry in mapping._entries.items() if entry.sources), None)
    if token is None:
        return {"status": "blocked", "error": "no_memory_token_for_probe", "fact_matches": False, "answer_sha256": None}
    result = restore_labeled_answer(token, prepared, records, policy or POLICY, authority=authority,
        actor_id="owner", agent_id="agent-B", request_id=request_id)
    answer = result.get("answer")
    return {"status": result["status"], "error": result.get("error"),
            "fact_matches": result["status"] == "ok" and answer == FACT_VALUE,
            "answer_sha256": hashlib.sha256(answer.encode("utf-8")).hexdigest() if isinstance(answer, str) else None}


def _select_current(authority, records):
    selected, checks = [], []
    for alias, record in zip(("G1", "G2"), records):
        reason = authority.validate_access(record, actor_id="owner", agent_id="agent-B", policy_version=POLICY["version"])
        checks.append({"alias": alias, "allowed": reason is None, "reason": reason,
                       "original_grant_sha256": _digest(record["access"])})
        if reason is None:
            selected.append(record)
    return selected, checks


def run_witness():
    started = time.perf_counter()
    key = secrets.token_bytes(32)  # Ephemeral; never returned, serialized or saved.
    initial_authority = MemoryLabelAuthority(key)
    records, receipts = _build_records(initial_authority)
    initial_state = initial_authority.export_state()
    records_hash = _digest(records)
    report = {"version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy_sha256": _digest(_policy(POLICY)), "full_policy_sha256": _digest(POLICY),
        "input_records_sha256": records_hash, "grant_receipts": receipts,
        "grant_issuance_events": [{"step": row["issued_at_step"], "event": "grant_issued", "alias": row["alias"]}
                                  for row in receipts],
        "fixture_independence": "host_declared_distinct_pretrusted_sources_not_inferred_from_text",
        "scope": "local_simulated_authority_json_handoff_and_programmatic_restore_probe",
        "limitations": ["not_native_backend_or_online_distributed_revocation", "not_LLM_task_utility",
                        "not_new_algorithm_advantage", "latest_authority_state_assumed_no_rollback_guarantee",
                        "old_prepared_context_checks_all_records_not_selective_restoration",
                        "full_source_record_envelope_is_trusted_host_internal_only"],
        "new_inference_counts": {"local_encoder": 0, "local_generation": 0, "unknown": 0},
        "source_receipts": {"scripts/run_transfer_lifecycle_witness.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            **{"memory_migration_study/"+name: hashlib.sha256((ROOT/"memory_migration_study"/name).read_bytes()).hexdigest()
               for name in RECEIPT_FILES}},
        "runtime": {"python": platform.python_version(), "model_loaded": False, "remote_calls": 0}, "arms": []}

    def fresh_authority():
        return MemoryLabelAuthority(key, state=deepcopy(initial_state))

    for pipeline in ("legacy", "boundary"):
        detector = ZeroModelDetector()
        authority = fresh_authority()
        request = pipeline+"-original-context"
        prepared = _prepare(authority, records, pipeline, request, detector)
        cell = {"privacy_pipeline": pipeline, "input_records_sha256": records_hash,
                "grant_sha256": [row["grant_sha256"] for row in receipts],
                "pre_revocation": {"transfer": _safe_transfer(prepared),
                                   "restore": _probe(authority, records, prepared, request)},
                "first_revocation_step": 4,
                "both_grants_preexist_revocation": all(row["issued_at_step"] < 4 for row in receipts)}
        authority.revoke(records[0]["record_id"])
        cell["record_G1_revocation"] = {
            "event": {"step": 4, "event": "record_revoked", "alias": "G1"},
            "old_prepared_restore": _probe(authority, records, prepared, request),
            "old_request_replay": _safe_transfer(_prepare(authority, records, pipeline, request, detector))}
        selected, checks = _select_current(authority, records)
        fresh_request = pipeline+"-fresh-existing-G2-context"
        fresh_prepared = _prepare(authority, selected, pipeline, fresh_request, detector)
        cell["record_G1_revocation"].update(current_access_checks=checks,
            selected_existing_grants=[row["alias"] for row in checks if row["allowed"]],
            fresh_context_transfer=_safe_transfer(fresh_prepared),
            fresh_context_restore=_probe(authority, selected, fresh_prepared, fresh_request))

        # Independent branches avoid a prior record revocation hiding a source,
        # epoch or policy failure behind the same earlier error.
        source_authority = fresh_authority()
        source_request = pipeline+"-source-context"
        source_prepared = _prepare(source_authority, records, pipeline, source_request, detector)
        source_authority.revoke_source(records[0]["source"]["source_id"])
        selected, checks = _select_current(source_authority, records)
        source_fresh_request = pipeline+"-source-fresh-existing-G2"
        source_fresh = _prepare(source_authority, selected, pipeline, source_fresh_request, detector)
        cell["source_G1_revocation"] = {"current_access_checks": checks,
            "old_prepared_restore": _probe(source_authority, records, source_prepared, source_request),
            "selected_existing_grants": [row["alias"] for row in checks if row["allowed"]],
            "fresh_context_transfer": _safe_transfer(source_fresh),
            "fresh_context_restore": _probe(source_authority, selected, source_fresh, source_fresh_request)}

        epoch_authority = fresh_authority()
        epoch_request = pipeline+"-epoch-context"
        epoch_prepared = _prepare(epoch_authority, records, pipeline, epoch_request, detector)
        epoch_authority.bump_epoch()
        cell["epoch_change"] = {"old_prepared_restore": _probe(epoch_authority, records, epoch_prepared, epoch_request),
            "old_request_replay": _safe_transfer(_prepare(epoch_authority, records, pipeline, epoch_request, detector))}
        policy_authority = fresh_authority()
        policy_request = pipeline+"-policy-context"
        policy_prepared = _prepare(policy_authority, records, pipeline, policy_request, detector)
        changed_policy = {**POLICY, "instructions": "Changed current sensitivity constraint."}
        cell["same_version_policy_change"] = {"policy_sha256_before": _digest(_policy(POLICY)),
            "policy_sha256_after": _digest(_policy(changed_policy)),
            "old_prepared_restore": _probe(policy_authority, records, policy_prepared, policy_request, changed_policy)}
        cell["zero_model_detector_invocations"] = detector.invocations
        report["arms"].append(cell)

    checks = {}
    for cell in report["arms"]:
        prefix = cell["privacy_pipeline"]+":"
        checks[prefix+"both_grants_preexist"] = cell["both_grants_preexist_revocation"]
        checks[prefix+"original_fact_available"] = cell["pre_revocation"]["restore"]["fact_matches"]
        revoked = cell["record_G1_revocation"]
        checks[prefix+"old_prepared_blocked"] = revoked["old_prepared_restore"]["error"] == "grant_revoked"
        checks[prefix+"old_request_replay_blocked"] = revoked["old_request_replay"]["error"] == "grant_revoked"
        checks[prefix+"existing_G2_restores"] = revoked["selected_existing_grants"] == ["G2"] and revoked["fresh_context_restore"]["fact_matches"]
        source = cell["source_G1_revocation"]
        checks[prefix+"source_G1_only_revoked"] = source["selected_existing_grants"] == ["G2"] and source["fresh_context_restore"]["fact_matches"]
        checks[prefix+"epoch_fail_closed"] = all(row["error"] == "lifecycle_epoch_changed" for row in cell["epoch_change"].values())
        checks[prefix+"policy_fail_closed"] = cell["same_version_policy_change"]["old_prepared_restore"]["error"] == "restoration_policy_mismatch"
        checks[prefix+"no_detector_or_model_execution"] = cell["zero_model_detector_invocations"] == 0
    checks["exact_same_grants_both_arms"] = report["arms"][0]["grant_sha256"] == report["arms"][1]["grant_sha256"]
    checks["signed_inputs_unchanged"] = _digest(records) == records_hash
    checks["new_exact_fact_grant_scope"] = all(row["scope_version"] == ACCESS_SCOPE_VERSION for row in receipts)
    report.update(checks=checks, all_checks_passed=all(checks.values()), wall_seconds=time.perf_counter()-started)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    target = args.output_dir/"report.json"
    if target.exists():
        parser.error("report.json already exists; choose a fresh output directory")
    report = run_witness()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"all_checks_passed": report["all_checks_passed"], "checks": len(report["checks"]),
                      "new_inference_counts": report["new_inference_counts"], "report": str(target)}, ensure_ascii=False))
    return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
