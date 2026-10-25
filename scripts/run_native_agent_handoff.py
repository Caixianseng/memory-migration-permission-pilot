"""Small, explicit native-client interoperability experiment; synthetic data only.

No inference happens without --execute. Four bounded questions, no retries.
The broker controls import, not the clients' subsequent file reads or revocation.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.native_agent_protocol import (
    NativeAgentBroker, NativeProtocolError, render_agents_md, safe_packet_metadata,
)
from memory_migration_study.qoder_native import run_qoder_question

QUESTION = (
    "Use only the task facts already present in this workspace's native AGENTS.md. "
    "Do not use tools. Return exactly one JSON object with the three string keys "
    '"receipt_code", "status", "source_canary". Use "UNKNOWN" for every absent field. '
    "No explanation or code fence."
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def make_workspace(path, text):
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    (path / "AGENTS.md").write_text(text, encoding="utf-8", newline="\n")


def build_direction(out, direction, sender, receiver):
    tag = "FWD" if direction == "forward" else "REV"
    facts = {"receipt_code": tag + "-" + secrets.token_hex(4), "status": "ready",
             "source_canary": "PRIVATE-" + tag + "-" + secrets.token_hex(4)}
    source = "# Controlled synthetic task memory\n\n" + "\n".join(k + " = " + v for k, v in facts.items()) + "\n"
    source_path, target_path = out / (sender + "_source_" + direction), out / (receiver + "_target_" + direction)
    make_workspace(source_path, source)
    actors = [{"actor_id": a, "user_id": "alice" if a != "other" else "bob",
               "agent_id": a if a != "other" else receiver,
               "workspace_id": (source_path.name if a == sender else target_path.name if a == receiver else "other-" + direction)}
              for a in (sender, receiver, "other")]
    records = []
    for field, value in facts.items():
        text = field + " = " + value
        pos = source.index(text)
        readers = [sender] if field == "source_canary" else [sender, receiver]
        records.append({"record_id": field, "text": text,
                        "source": {"source_id": sender + "-memory", "text": source},
                        "source_start": pos, "source_end": pos + len(text),
                        "source_readers": readers, "recipient_readers": readers, "target_readers": readers,
                        "export_allowed": field != "source_canary", "copy_allowed": field != "source_canary"})
    case = {"case_id": direction, "actors": actors, "records": records}
    broker = NativeAgentBroker(case, key=secrets.token_bytes(32))
    packet = broker.export(["receipt_code", "status"], sender_actor_id=sender,
                           recipient_actor_id=receiver, transfer_id=direction, ttl_seconds=3600)
    receipt = broker.validate(packet, sender_actor_id=sender, actor_id=receiver)
    target = render_agents_md(packet)
    assert facts["source_canary"] not in target and facts["source_canary"] not in json.dumps(packet)
    make_workspace(target_path, target)
    write_json(out / (direction + "_packet.json"), packet)
    write_json(out / (direction + "_case.json"), case)
    checks = []

    def denied(name, action, expected):
        try:
            action()
            code = "UNEXPECTED_ALLOW"
        except NativeProtocolError as exc:
            code = exc.code
        checks.append({"check": name, "expected": expected, "observed": code, "passed": code == expected})

    denied("wrong_recipient", lambda: broker.validate(packet, sender_actor_id=sender, actor_id="other"), "packet_audience_mismatch")
    for field in ("text", "audience"):
        changed = deepcopy(packet)
        if field == "text":
            changed["items"][0]["text"] = "receipt_code = FORGED"
        else:
            changed["audience"]["user_id"] = "bob"
        denied("tampered_" + field, lambda p=changed: broker.validate(p, sender_actor_id=sender, actor_id=receiver), "packet_integrity_invalid")
    changed = deepcopy(packet)
    del changed["integrity"]
    denied("missing_integrity", lambda: broker.validate(changed, sender_actor_id=sender, actor_id=receiver), "packet_schema_fields")
    denied("private_selection", lambda: broker.export(["source_canary"], sender_actor_id=sender,
           recipient_actor_id=receiver, transfer_id=direction + "-private"), "recipient_read_not_allowed")
    for capability in ("export_allowed", "copy_allowed"):
        isolated_case = deepcopy(case)
        isolated_case["records"][0][capability] = False
        isolated = NativeAgentBroker(isolated_case, key=secrets.token_bytes(32))
        # All three readership lists still allow both principals: this isolates the operation boundary.
        denied("forbidden_" + capability, lambda b=isolated: b.export(["receipt_code"], sender_actor_id=sender,
               recipient_actor_id=receiver, transfer_id=direction + "-" + capability),
               "export_not_allowed" if capability == "export_allowed" else "copy_not_allowed")
    denied("strict_native_permissions", lambda: broker.export(["receipt_code"], sender_actor_id=sender,
           recipient_actor_id=receiver, transfer_id=direction + "-strict", mode="strict"), "unsupported_constraints")
    future = NativeAgentBroker(case, key=b"expiry-check-key-32-bytes-long!!!!!", clock=lambda: 1000)
    expired = future.export(["status"], sender_actor_id=sender, recipient_actor_id=receiver,
                            transfer_id=direction + "-expiry", ttl_seconds=1)
    future_now = NativeAgentBroker(case, key=b"expiry-check-key-32-bytes-long!!!!!", clock=lambda: 1001)
    denied("expired_packet", lambda: future_now.validate(expired, sender_actor_id=sender, actor_id=receiver), "packet_expired_or_not_yet_valid")
    revocation_broker = NativeAgentBroker(case, key=secrets.token_bytes(32))
    replay = revocation_broker.export(["receipt_code"], sender_actor_id=sender, recipient_actor_id=receiver,
                                      transfer_id=direction + "-revoke")
    revocation_broker.revoke("receipt_code")
    denied("revoked_packet_replay", lambda: revocation_broker.validate(replay, sender_actor_id=sender, actor_id=receiver), "record_revoked")
    still = revocation_broker.export(["status"], sender_actor_id=sender, recipient_actor_id=receiver,
                          transfer_id=direction + "-still-legal")
    checks.append({"check": "independent_record_retained", "passed": revocation_broker.validate(still, sender_actor_id=sender, actor_id=receiver)["status"] == "ok"})
    return {"direction": direction, "sender": sender, "receiver": receiver,
            "source_workspace": str(source_path), "target_workspace": str(target_path),
            "expected_source": facts, "expected_target": {**facts, "source_canary": "UNKNOWN"},
            "source_sha256": digest(source.encode()), "target_sha256": digest(target.encode()),
            "packet_metadata": safe_packet_metadata(packet), "initial_import_receipt": receipt,
            "host_checks": checks}


def score(receipt, expected):
    answer = receipt.get("answer")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate answer key")
            value[key] = item
        return value
    try:
        parsed = json.loads(answer, object_pairs_hook=unique) if isinstance(answer, str) else None
    except (ValueError, TypeError):
        parsed = None
    valid = isinstance(parsed, dict) and set(parsed) == set(expected) and all(isinstance(x, str) for x in parsed.values())
    return {"valid_json_shape": valid,
            "all_fields_correct": receipt.get("status") == "ok" and valid and parsed == expected,
            "per_field_correct": {k: bool(valid and parsed.get(k) == v) for k, v in expected.items()},
            "parsed_answer": parsed}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "results/native_agent_handoff_20261026_v1")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to((ROOT / "results").resolve()) or out.exists():
        raise SystemExit("Output must be a new directory under results; no overwriting or automatic retries.")
    out.mkdir(parents=True)
    directions = [build_direction(out, "forward", "qoder", "harness"), build_direction(out, "reverse", "harness", "qoder")]
    plan = {"schema": "native-agent-handoff-study-v1", "native_memory_kind": "native_workspace_instructions",
            "host_authored_synthetic_memory": True, "prompt": QUESTION,
            "prompt_sha256": digest(QUESTION.encode()), "max_questions": 4, "max_output_tokens_each": 64,
            "new_raw_api_calls": 0, "directions": directions,
            "limitations": ["Static AGENTS.md is context, not native ACL enforcement or live revocation.",
                            "One synthetic story per direction, no statistical generalization.",
                            "Same OS account; host principals are controlled fixture identities.",
                            "Native-account charges are unverified; zero CLI USD is not proof of zero cost."]}
    write_json(out / "plan.json", plan)
    if not all(c["passed"] for d in directions for c in d["host_checks"]):
        raise SystemExit("Host preflight failed; no native inference allowed.")
    if not args.execute:
        print(json.dumps({"status": "plan_only", "path": str(out), "model_calls": 0}))
        return
    from memory_migration_study.deepseek_native import run_deepseek_question
    probe = ROOT / "results/native_agent_probe_20261026"
    rows = []
    # Account SDK source first: an auth failure remains visible, never replaced by raw API.
    specs = [(directions[1], "source", "harness"), (directions[0], "source", "qoder"),
             (directions[0], "target", "harness"), (directions[1], "target", "qoder")]
    for index, (direction, stage, client) in enumerate(specs):
        started = time.monotonic()
        workspace = Path(direction[stage + "_workspace"])
        if workspace.resolve() != workspace or not workspace.is_relative_to(out):
            raise SystemExit("Registered workspace binding changed; no client launch.")
        if digest((workspace / "AGENTS.md").read_bytes()) != direction[stage + "_sha256"]:
            raise SystemExit("Registered native memory hash changed; no client launch.")
        if stage == "target" and direction["packet_metadata"]["audience"]["workspace_id"] != workspace.name:
            raise SystemExit("Registered packet recipient binding changed; no client launch.")
        if client == "qoder":
            receipt = run_qoder_question(workspace, QUESTION, capabilities_path=probe / "qoder_capabilities.json")
        else:
            receipt = run_deepseek_question(workspace, QUESTION,
                runtime_home=probe / (out.name + "_" + str(index)),
                patch_template=probe / "sdk_guard_metadata.patch.yml",
                guard_path=probe / "dsh_single_request_guard.mjs",
                credentials_source=Path("C:/Users/CAI/.dsh/.credentials.yaml"))
        row = {"index": index, "direction": direction["direction"], "stage": stage, "client": client,
               "elapsed_seconds": time.monotonic() - started, "receipt": receipt,
               "score": score(receipt, direction["expected_" + stage])}
        row["registered_canary_disclosure"] = (
            direction["expected_source"]["source_canary"] in str(receipt.get("raw_response") or receipt.get("answer") or "")
            if stage == "target" and isinstance(receipt.get("raw_response") or receipt.get("answer"), str) else None)
        rows.append(row)
        write_json(out / "native_results.json", rows)
        print(json.dumps({"index": index, "client": client, "stage": stage, "status": receipt.get("status"),
                          "error": receipt.get("error"), "correct": row["score"]["all_fields_correct"]}), flush=True)
    summary = {"status": "completed", "question_attempts": len(rows),
               "client_invocations_started": sum(r["receipt"].get("invocation_started") is True for r in rows),
               "directly_observed_physical_http_requests": None,
               "client_successes": sum(r["receipt"].get("status") == "ok" for r in rows),
               "all_fields_correct": sum(r["score"]["all_fields_correct"] for r in rows),
               "host_checks_passed": sum(c["passed"] for d in directions for c in d["host_checks"]),
               "host_checks_total": sum(len(d["host_checks"]) for d in directions),
               "target_registered_canary_disclosures": sum(r["registered_canary_disclosure"] is True for r in rows),
               "target_canary_observed_responses": sum(r["registered_canary_disclosure"] is not None for r in rows),
               "native_read_acl_and_live_revocation": "unsupported",
               "new_raw_api_calls": 0, "account_cost": None}
    write_json(out / "summary.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
