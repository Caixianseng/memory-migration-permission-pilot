"""Two bounded native-client calls through the existing single-value privacy gate.

Only synthetic registry-labelled facts. No detector effectiveness or native ACL
claim. Plan-only does not launch a native client or read its credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study.native_agent_protocol import NativeAgentBroker
from memory_migration_study.native_privacy_gateway import (
    QUESTION, prepare_native_private_memory, restore_native_private_answer)

VERSION = "native-private-handoff-integration-v1"
PROBE = ROOT / "results/native_agent_probe_20261026"
SELF = "scripts/run_native_private_handoff.py"
SOURCES = (SELF, *("memory_migration_study/" + n + ".py" for n in (
    "native_agent_protocol", "native_privacy_gateway", "privacy", "privacy_egress", "policy",
    "qoder_native", "deepseek_native", "deepseek_sdk")),
    "results/native_agent_probe_20261026/qoder_capabilities.json",
    "results/native_agent_probe_20261026/dsh_single_request_guard.mjs",
    "results/native_agent_probe_20261026/sdk_guard_metadata.patch.yml")


def require(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def scope(path):
    p = Path(path).absolute()
    require(p == p.resolve() and p.is_relative_to(ROOT / "results") and p != ROOT / "results",
            "result_scope_or_link_invalid")
    return p


def manifest():
    return {name: sha((ROOT / name).read_bytes()) for name in SOURCES}


def plan_only(output):
    output = scope(output)
    require(not output.exists(), "fresh_output_required")
    frozen = manifest()
    plan = {"schema": VERSION, "output": output.relative_to(ROOT).as_posix(),
            "implementation_sha256": frozen, "question": QUESTION,
            "max_native_client_attempts": 2, "max_output_tokens_each": 64,
            "raw_deepseek_api_calls": 0, "detector_mode": "rules_with_explicit_synthetic_registry",
            "cases": [{"client": client, "sender": sender, "recipient": client,
                       "workspace": client + "_private_target", "record_id": "customer",
                       "value": "SYNTHETIC-CUSTOMER-" + secrets.token_hex(6).upper(),
                       "source_only": "SYNTHETIC-SOURCE-ONLY-" + secrets.token_hex(6).upper()}
                      for client, sender in (("qoder", "harness"), ("harness", "qoder"))],
            "scope": "One exact-value fixture per direction, external pre/post authorization; not native ACL, automatic memory, semantic detection, fresh64, or innovation acceptance.",
            "cost": {"account_cost": None, "physical_http_requests": None,
                     "note": "Native-account charges remain unverified; no raw API or automatic retry."}}
    output.mkdir(parents=True)
    for name in SOURCES:
        target = output / "frozen_source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write((ROOT / name).read_bytes())
    save(output / "plan.json", plan)
    return plan


def approved(path):
    path = scope(path)
    plan = json.loads(path.read_bytes())
    require(plan["schema"] == VERSION and path == ROOT / plan["output"] / "plan.json", "plan_binding_invalid")
    require(path.read_bytes() == encoded(plan), "plan_encoding_changed")
    require(manifest() == plan["implementation_sha256"], "implementation_changed")
    require(plan["question"] == QUESTION and plan["max_native_client_attempts"] == 2
            and plan["max_output_tokens_each"] == 64 and len(plan["cases"]) == 2
            and [c["client"] for c in plan["cases"]] == ["qoder", "harness"], "plan_budget_invalid")
    for case, client, sender in zip(plan["cases"], ("qoder", "harness"), ("harness", "qoder")):
        require(set(case) == {"client", "sender", "recipient", "workspace", "record_id", "value", "source_only"}
                and case["recipient"] == client and case["sender"] == sender
                and case["workspace"] == client + "_private_target" and case["record_id"] == "customer"
                and re.fullmatch(r"SYNTHETIC-CUSTOMER-[A-F0-9]{12}", case["value"])
                and re.fullmatch(r"SYNTHETIC-SOURCE-ONLY-[A-F0-9]{12}", case["source_only"]), "fixture_contract_changed")
    for name, digest in plan["implementation_sha256"].items():
        require(sha((path.parent / "frozen_source" / name).read_bytes()) == digest, "snapshot_changed")
    return plan


def build_fixture(spec, workspace):
    sender, recipient, rid = spec["sender"], spec["recipient"], spec["record_id"]
    text = "Customer = " + spec["value"] + "\nSource only = " + spec["source_only"]
    start = text.index(spec["value"])
    case = {"case_id": recipient + "-private", "actors": [
        {"actor_id": sender, "user_id": "alice", "agent_id": sender, "workspace_id": "source-" + sender},
        {"actor_id": recipient, "user_id": "alice", "agent_id": recipient, "workspace_id": workspace.name},
        {"actor_id": "other", "user_id": "bob", "agent_id": recipient, "workspace_id": "other-workspace"}],
        "records": [{"record_id": rid, "text": spec["value"],
                     "source": {"source_id": "source-" + sender, "text": text},
                     "source_start": start, "source_end": start + len(spec["value"]),
                     "source_readers": [sender, recipient], "recipient_readers": [sender, recipient],
                     "target_readers": [sender, recipient], "export_allowed": True, "copy_allowed": True}]}
    broker = NativeAgentBroker(case, key=secrets.token_bytes(32))
    packet = broker.export([rid], sender_actor_id=sender, recipient_actor_id=recipient,
                           transfer_id=recipient + "-private", ttl_seconds=3600)
    policy = {"version": "native-private-integration-v1", "protected_categories": ["CUSTOMER"],
              "instructions": "Protect the host-declared synthetic customer identifier.",
              "entity_registry": [{"value": spec["value"], "category": "CUSTOMER"}]}
    query = "Return the authorized customer " + spec["value"] + "."
    options = {"broker": broker, "sender_actor_id": sender, "actor_id": recipient,
               "agent_id": recipient, "workspace": workspace, "request_id": recipient + "-request",
               "authorizer": lambda r, a, v: r == rid and a == recipient and v == policy["version"]}
    return packet, query, policy, options, case


def invoke(client, workspace, question, runtime_home):
    if client == "qoder":
        from memory_migration_study.qoder_native import run_qoder_question
        return run_qoder_question(workspace, question, capabilities_path=PROBE / "qoder_capabilities.json")
    from memory_migration_study.deepseek_native import run_deepseek_question
    return run_deepseek_question(workspace, question, runtime_home=runtime_home,
                                patch_template=PROBE / "sdk_guard_metadata.patch.yml",
                                guard_path=PROBE / "dsh_single_request_guard.mjs")


def one_case(spec, workspace, runtime_home, native_call=invoke):
    packet, query, policy, options, case = build_fixture(spec, workspace)
    wrong = prepare_native_private_memory(packet, query, policy, **{**options, "actor_id": "other"})
    negative = [{"name": "wrong_recipient_before_client", "status": wrong["status"],
                 "error": wrong.get("error"), "passed": wrong["status"] == "blocked"}]
    revoked = NativeAgentBroker(case, key=secrets.token_bytes(32))
    old = revoked.export([spec["record_id"]], sender_actor_id=spec["sender"],
                         recipient_actor_id=spec["recipient"], transfer_id="revoked-before-import")
    revoked.revoke(spec["record_id"])
    denied = prepare_native_private_memory(old, query, policy, **{**options, "broker": revoked})
    negative.append({"name": "revoked_before_client", "status": denied["status"],
                     "error": denied.get("error"), "passed": denied["status"] == "blocked"})
    require(all(r["passed"] for r in negative), "preflight_negative_control_failed")
    prepared = prepare_native_private_memory(packet, query, policy, **options)
    if prepared["status"] != "ok":
        return {"client": spec["client"], "status": "preparation_failed", "error": prepared.get("error"),
                "client_attempts": 0, "negative_controls": negative, "joint_success": False}
    native_input = prepared["question"] + prepared["agents_md"]
    require(spec["value"] not in native_input and spec["source_only"] not in native_input,
            "registered_raw_native_input")
    with (workspace / "AGENTS.md").open("xb") as stream:
        stream.write(prepared["agents_md"].encode("utf-8"))
    started = time.monotonic()
    receipt = native_call(spec["client"], workspace, prepared["question"], runtime_home)
    answer = receipt.get("answer") if receipt.get("status") == "ok" else None
    restored = restore_native_private_answer(answer, prepared["request"], policy, **options)
    replay = restore_native_private_answer(answer, prepared["request"], policy, **options)
    negative.append({"name": "consumed_response_replay", "status": replay["status"],
                     "error": replay.get("error"), "passed": replay.get("error") == "native_request_unknown_or_replayed"})
    observed = receipt.get("raw_response") or answer
    output_check = None if not isinstance(observed, str) else {
        "registered_value_present": spec["value"] in observed,
        "source_only_present": spec["source_only"] in observed}
    correct = restored.get("status") == "ok" and restored.get("answer") == spec["value"]
    return {"client": spec["client"], "status": "completed", "client_attempts": 1,
            "elapsed_seconds": time.monotonic() - started, "receipt": receipt,
            "privacy_metadata": prepared["metadata"], "native_input_sha256": sha(native_input.encode()),
            "registered_raw_absent_from_constructed_native_input": True,
            "full_cloud_request_content_inspected": False, "native_response_registration_check": output_check,
            "restoration_status": restored["status"], "restoration_error": restored.get("error"),
            "restored_answer_sha256": sha(restored["answer"].encode()) if isinstance(restored.get("answer"), str) else None,
            "restored_correct": correct, "negative_controls": negative,
            "joint_success": bool(correct and output_check is not None and not any(output_check.values())
                                  and all(r["passed"] for r in negative))}


def execute(path):
    plan = approved(path)
    out = ROOT / plan["output"]
    with (out / "execution_started.json").open("xb") as stream:
        stream.write(encoded({"plan_sha256": sha(Path(path).read_bytes()), "client_attempt_cap": 2}))
    rows = []
    for spec in plan["cases"]:
        require(manifest() == plan["implementation_sha256"], "implementation_changed_between_clients")
        workspace = scope(out / spec["workspace"])
        require(not workspace.exists(), "workspace_not_fresh")
        workspace.mkdir()
        subprocess.run(["git", "init", "-q", str(workspace)], check=True, capture_output=True, timeout=15)
        row = one_case(spec, workspace, out / (spec["client"] + "_private_runtime"))
        rows.append(row)
        save(out / (spec["client"] + "_result.json"), row)
        print(json.dumps({"client": row["client"], "status": row["status"],
                          "restored_correct": row.get("restored_correct"), "joint_success": row["joint_success"]}), flush=True)
    summary = {"schema": VERSION + "_summary", "status": "completed", "planned_cells": 2,
               "client_attempts": sum(r["client_attempts"] for r in rows),
               "client_responses_ok": sum(r.get("receipt", {}).get("status") == "ok" for r in rows),
               "restored_correct": sum(r.get("restored_correct") is True for r in rows),
               "joint_success": sum(r["joint_success"] for r in rows),
               "controls_passed": sum(c["passed"] for r in rows for c in r["negative_controls"]),
               "controls_total": sum(len(r["negative_controls"]) for r in rows),
               "mapping_object_persisted": False, "inference_payloads_are_synthetic": True,
               "new_raw_api_calls": 0, "native_acl_or_online_revocation": False,
               "full_cloud_request_content_inspected": False, "cost": plan["cost"],
               "effect_acceptance_or_novelty_established": False,
               "implementation_unchanged": manifest() == plan["implementation_sha256"]}
    save(out / "summary.json", summary)
    return summary


def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan-only", action="store_true")
    group.add_argument("--execute", action="store_true")
    p.add_argument("--output", type=Path)
    p.add_argument("--approved-plan", type=Path)
    a = p.parse_args()
    if a.plan_only:
        require(a.output is not None, "output_required")
        result = plan_only(a.output)
        print(json.dumps({"status": "plan_only", "native_calls": 0, "output": result["output"]}))
    else:
        require(a.approved_plan is not None, "approved_plan_required")
        print(json.dumps(execute(a.approved_plan)))


if __name__ == "__main__":
    main()
