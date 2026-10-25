"""Zero-model, hand-authored native privacy gate demonstration.

Only Git init is executed. No Qoder/Node/Harness process, model, credentials,
network or serialized restoration capability is used by this example.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.native_agent_protocol import NativeAgentBroker, safe_packet_metadata
from memory_migration_study.native_privacy_gateway import (
    prepare_native_private_memory, restore_native_private_answer,
)

VALUE = "SYNTHETIC-HARBOR-7319"
SOURCE_ONLY = "SYNTHETIC-SOURCE-ONLY-8294"
RECORD_ID = "demo-single-value"
POLICY_VERSION = "demo-privacy-v1"


class DemoError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def new_workspace(path):
    path.mkdir()
    permitted = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in permitted}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "-c", "init.templateDir=", "init", "-q", str(path)],
        env=environment, capture_output=True, timeout=20, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0:
        raise DemoError("git_init_failed")


def fixture(workspace, scenario):
    source = "Hand-authored customer value: " + VALUE + "\nUnselected source fact: " + SOURCE_ONLY
    start = source.index(VALUE)
    case = {"case_id": "gateway-demo-" + scenario, "actors": [
        {"actor_id": "sender", "user_id": "synthetic-user", "agent_id": "AgentA", "workspace_id": "source"},
        {"actor_id": "recipient", "user_id": "synthetic-user", "agent_id": "AgentB", "workspace_id": workspace.name}],
        "records": [{"record_id": RECORD_ID, "text": VALUE,
            "source": {"source_id": "hand-authored-source", "text": source},
            "source_start": start, "source_end": start + len(VALUE),
            "source_readers": ["sender", "recipient"], "recipient_readers": ["sender", "recipient"],
            "target_readers": ["sender", "recipient"], "export_allowed": True, "copy_allowed": True}]}
    broker = NativeAgentBroker(case, key=secrets.token_bytes(32))
    packet = broker.export([RECORD_ID], sender_actor_id="sender", recipient_actor_id="recipient",
                           transfer_id="demo-" + scenario)
    policy = {"version": POLICY_VERSION, "protected_categories": ["CUSTOMER"],
              "instructions": "Protect the explicitly hand-authored synthetic business identifier.",
              "entity_registry": [{"value": VALUE, "category": "CUSTOMER"}]}

    def authorizer(record_id, actor_id, version):
        return record_id == RECORD_ID and actor_id == "recipient" and version == POLICY_VERSION

    scope = {"broker": broker, "sender_actor_id": "sender", "actor_id": "recipient", "agent_id": "AgentB",
             "workspace": workspace, "request_id": "request-" + scenario, "authorizer": authorizer}
    return packet, policy, scope


def scenario(workspace, name, *, revoke_before_restore):
    new_workspace(workspace)
    packet, policy, scope = fixture(workspace, name)
    prepared = prepare_native_private_memory(packet, "Return the value associated with " + VALUE + ".",
                                              policy, **scope)
    if prepared["status"] != "ok":
        raise DemoError("gateway_prepare_failed")
    # This is the explicit simulation point. It is NOT an agent/model response.
    simulated_answer = prepared["agents_md"]
    (workspace / "AGENTS.md").write_bytes(prepared["agents_md"].encode("utf-8"))
    if revoke_before_restore:
        scope["broker"].revoke(RECORD_ID)
    restored = restore_native_private_answer(simulated_answer, prepared["request"], policy, **scope)
    replayed = restore_native_private_answer(simulated_answer, prepared["request"], policy, **scope)
    actual_native_memory = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    # Project only public metadata and synthetic answers. Never dump prepared:
    # its request is an intentionally non-serializable in-process capability.
    return {"scenario": name, "model_calls": 0, "client_calls": 0, "simulated_answer": True,
            "prepare_status": prepared["status"], "sensitivity_source": "hand_authored_entity_registry",
            "memory_source": "hand_authored_exact_value_not_agent_generated",
            "authorization_source": "controlled_fixture_not_native_product_identity",
            "packet_metadata": safe_packet_metadata(packet), "prepare_metadata": prepared["metadata"],
            "native_file": {"content": actual_native_memory, "contains_original_value": VALUE in actual_native_memory,
                            "contains_unselected_source_fact": SOURCE_ONLY in actual_native_memory},
            "fixed_question_contains_original_value": VALUE in prepared["question"],
            "revoked_after_prepare_before_restore": revoke_before_restore,
            "restoration": restored, "replay": replayed}


def run(output=None):
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "_" + secrets.token_hex(3)
    output = Path(output or results / ("native_privacy_gateway_demo_" + suffix)).absolute()
    if (output.resolve() != output or output == results or not output.is_relative_to(results)
            or output.exists() or output.is_symlink()):
        raise DemoError("output_must_be_new_results_subdirectory")
    output.mkdir(parents=True, exist_ok=False)
    legal = scenario(output / "legal_recipient", "legal", revoke_before_restore=False)
    revoked = scenario(output / "revoked_recipient", "revoked", revoke_before_restore=True)
    checks = {
        "legal_value_restored": legal["restoration"]["status"] == "ok" and legal["restoration"]["answer"] == VALUE,
        "revocation_before_restore_blocks": revoked["restoration"]["status"] == "blocked"
            and revoked["restoration"]["error"] == "broker_record_revoked",
        "both_request_replays_block": all(row["replay"]["error"] == "native_request_unknown_or_replayed" for row in (legal, revoked)),
        "target_files_have_no_registered_raw_values": all(not row["native_file"]["contains_original_value"]
            and not row["native_file"]["contains_unselected_source_fact"] for row in (legal, revoked)),
        "fixed_question_has_no_registered_raw_value": all(not row["fixed_question_contains_original_value"] for row in (legal, revoked)),
    }
    report = {"schema": "native-privacy-gateway-engineering-demo-v1", "status": "engineering_path_checked",
              "all_checks_passed": all(checks.values()), "checks": checks,
              "model_calls": 0, "client_calls": 0, "git_init_processes": 2, "simulated_answer": True,
              "credentials_read": False, "network_calls": 0, "enforcement_scope": "external_gated",
              "native_acl": False, "data": "hand_authored_synthetic_only",
              "source_labels": "hand_authored_sensitivity_registry_not_model_generated",
              "source_policy": "hand_authored_controlled_authorization_fixture",
              "implementation_sha256": sha((ROOT / "memory_migration_study/native_privacy_gateway.py").read_bytes()),
              "example_sha256": sha(Path(__file__).read_bytes()), "scenarios": [legal, revoked],
              "limitations": ["No actual Qoder, Harness, model or native client interoperability was tested.",
                  "No sensitivity detection quality, signed generation-label quality or unseen-data effect is measured.",
                  "Current broker state is in-process; this is not native read ACL, persistent online revocation or plaintext forgetting.",
                  "Explicitly simulated single-value answers are instrumentation, not task-performance evidence."]}
    with (output / "report.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return output, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        output, report = run(arguments.output)
    except (DemoError, OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError):
        raise SystemExit("Demo failed; no model/client was called and no existing path was deleted. Inspect the new output, if any.") from None
    print(json.dumps({"status": report["status"], "output": str(output), "checks": report["checks"],
                      "model_calls": 0, "client_calls": 0, "simulated_answer": True}, ensure_ascii=False))
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
