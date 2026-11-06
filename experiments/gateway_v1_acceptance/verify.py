"""Independent verification of completed Gateway acceptance artifacts.

The verifier never imports the Gateway or Store and never reruns a scenario.
SQLite inputs are opened read-only after rejecting live journal sidecars. Only
the new verification JSON is written. ACL outcomes are descriptive; the strong
transaction and gateway methods determine the behavioral acceptance gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]
METHODS = ("acl", "transaction", "gateway")
STRONG = ("transaction", "gateway")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key:" + key)
        result[key] = value
    return result


def loads(raw: str | bytes):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("nonfinite_json:" + value)))


def load(path: Path):
    return loads(path.read_text(encoding="utf-8-sig"))


def jsonl(path: Path) -> list[dict[str, Any]]:
    return [loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()]


def inside(root: Path, relative: str) -> Path:
    supplied = Path(relative)
    if supplied.is_absolute():
        raise ValueError("relative_artifact_path_required:" + relative)
    target = (root / supplied).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("artifact_path_escapes_root:" + relative)
    return target


def check(out: list[dict], name: str, condition: bool, **detail):
    out.append({"name": name, "passed": bool(condition), **detail})


def table_exists(db, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      (name,)).fetchone() is not None


def event_chain(db) -> dict[str, Any]:
    previous, count = "0" * 64, 0
    for row in db.execute(
            "SELECT seq,kind,previous,payload_json,event_hash FROM events ORDER BY seq"):
        count += 1
        payload = loads(row["payload_json"])
        actual = digest({"seq": row["seq"], "kind": row["kind"],
                         "previous": row["previous"], "payload": payload})
        if row["seq"] != count or row["previous"] != previous or actual != row["event_hash"]:
            raise ValueError("event_chain_invalid_at:" + str(row["seq"]))
        previous = row["event_hash"]
    return {"events": count, "head": previous}


def open_readonly(path: Path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("regular_database_required:" + str(path))
    raw_header = path.read_bytes()[:100]
    if raw_header[:16] != b"SQLite format 3\x00":
        raise ValueError("sqlite_header_invalid:" + str(path))
    # immutable prevents reader-created SHM or hot-journal recovery. Rejecting
    # WAL/rollback sidecars first avoids silently ignoring uncheckpointed data.
    sidecars = [str(p) for p in path.parent.iterdir()
                if p.name.startswith(path.name + "-")]
    if sidecars or raw_header[18:20] != b"\x01\x01":
        raise ValueError("closed_delete_journal_database_required:" + str(path))
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def durable_bindings(receiver, policy, checks: list[dict]) -> list[dict]:
    batches = [dict(row) for row in receiver.execute("SELECT * FROM batches ORDER BY batch_id")]
    seals = {row["import_id"]: dict(row) for row in policy.execute("SELECT * FROM seals")}
    owner = receiver.execute("SELECT value FROM metadata WHERE key='agent_id'").fetchone()[0]
    check(checks, "receiver_owner", owner == "B", actual=owner)
    for batch in batches:
        prefix = batch["batch_id"] + ":"
        seal = seals.get(batch["import_id"])
        check(checks, prefix + "seal_exists", seal is not None)
        if seal is not None:
            matching = all(seal[key] == batch[key] for key in
                           ("batch_id", "import_id", "sender_id", "recipient_id", "epoch"))
            check(checks, prefix + "seal_identity_and_consumption",
                  matching and seal["packet_sha256"] == batch["packet_sha256"]
                  and seal["consumed_by"] == owner)
        event = receiver.execute("SELECT * FROM events WHERE event_hash=?",
                                 (batch["import_event_hash"],)).fetchone()
        check(checks, prefix + "import_event_exists",
              event is not None and event["kind"] == "import_committed")
        if event is None or event["kind"] != "import_committed":
            continue
        payload = loads(event["payload_json"])
        check(checks, prefix + "event_identity",
              all(payload.get(key) == batch[key] for key in
                  ("batch_id", "import_id", "sender_id", "recipient_id", "epoch", "packet_sha256")))
        memories = [dict(row) for row in receiver.execute(
            "SELECT bm.position,m.* FROM batch_memories bm JOIN memories m USING(memory_key) "
            "WHERE bm.batch_id=? ORDER BY bm.position", (batch["batch_id"],))]
        check(checks, prefix + "memory_order_and_count",
              [row["position"] for row in memories] == list(range(len(memories)))
              and payload.get("memory_keys") == [row["memory_key"] for row in memories]
              and bool(memories))
        for memory in memories:
            key = memory["memory_key"]
            binding = payload.get("artifact_bindings", {}).get(key, {})
            dependencies = [dict(row) for row in receiver.execute(
                "SELECT source_id,source_version AS version,source_sha256 AS sha256,owner_id "
                "FROM memory_dependencies WHERE memory_key=? ORDER BY source_id", (key,))]
            body_digest = hashlib.sha256(memory["content"].encode("utf-8")).hexdigest()
            check(checks, prefix + key + ":body_digest", body_digest == memory["content_sha256"])
            check(checks, prefix + key + ":durable_import_binding",
                  binding.get("content_sha256") == memory["content_sha256"]
                  and binding.get("dependencies_sha256") == digest(dependencies)
                  and binding.get("artifact_sha256") == memory["artifact_sha256"]
                  and all(binding.get(field) == memory[field] for field in
                          ("origin_agent", "memory_id", "version", "kind")))
            for dependency in dependencies:
                historical = policy.execute(
                    "SELECT source_id,version,sha256,owner_id FROM source_versions "
                    "WHERE source_id=? AND version=?",
                    (dependency["source_id"], dependency["version"])).fetchone()
                check(checks, prefix + key + ":historical_source_binding:" + dependency["source_id"],
                      historical is not None and dict(historical) == dependency)
    expected_consumed = {row["import_id"] for row in batches}
    actual_consumed = {key for key, value in seals.items() if value["consumed_by"] == owner}
    check(checks, "consumed_seals_have_exact_receiver_batches", actual_consumed == expected_consumed,
          consumed_count=len(actual_consumed), batch_count=len(expected_consumed))
    return batches


def inspect_directory(directory: Path, method: str) -> dict[str, Any]:
    receiver_path = directory / "agents/B.sqlite"
    policy_path = directory / "policy.sqlite"
    paths = [receiver_path, policy_path]
    hashes_before = {str(path.relative_to(directory)): sha(path) for path in paths}
    names_before = sorted(str(path.relative_to(directory)) for path in directory.rglob("*")
                          if path.is_file())
    receiver = policy = None
    infrastructure, invariants = [], []
    try:
        receiver, policy = open_readonly(receiver_path), open_readonly(policy_path)
        chains = {}
        for label, db in (("receiver", receiver), ("policy", policy)):
            check(infrastructure, label + ":journal_delete",
                  db.execute("PRAGMA journal_mode").fetchone()[0] == "delete")
            quick = [row[0] for row in db.execute("PRAGMA quick_check")]
            check(infrastructure, label + ":quick_check", quick == ["ok"], actual=quick)
            foreign = [list(row) for row in db.execute("PRAGMA foreign_key_check")]
            check(infrastructure, label + ":foreign_key_check", not foreign, actual=foreign)
            chain = event_chain(db)
            chains[label] = chain
            check(infrastructure, label + ":event_chain", True, **chain)
        if method == "acl":
            effects = ([dict(row) for row in receiver.execute(
                "SELECT seq,import_id,batch_id,packet_sha256,packet_json FROM acl_effects ORDER BY seq")]
                if table_exists(receiver, "acl_effects") else [])
            for row in effects:
                packet = loads(row.pop("packet_json"))
                check(invariants, "acl_effect_packet_binding:" + str(row["seq"]),
                      packet.get("import_id") == row["import_id"]
                      and packet.get("batch_id") == row["batch_id"]
                      and packet.get("content_sha256") == row["packet_sha256"]
                      and digest({key: value for key, value in packet.items()
                                  if key != "content_sha256"}) == row["packet_sha256"])
                seal = policy.execute("SELECT * FROM seals WHERE import_id=?",
                                      (row["import_id"],)).fetchone()
                check(invariants, "acl_effect_seal_binding:" + str(row["seq"]),
                      seal is not None and seal["batch_id"] == row["batch_id"]
                      and seal["packet_sha256"] == row["packet_sha256"]
                      and seal["consumed_by"] == "B")
        else:
            effects = durable_bindings(receiver, policy, invariants)
        ids = Counter(row["import_id"] for row in effects)
        batches = Counter(row["batch_id"] for row in effects)
        duplicates = {"import_ids": {key: value for key, value in ids.items() if value > 1},
                      "batch_ids": {key: value for key, value in batches.items() if value > 1}}
        check(invariants, "no_duplicate_persistent_operations",
              not duplicates["import_ids"] and not duplicates["batch_ids"], actual=duplicates)
        effect_projection = sorted(
            [{key: row[key] for key in ("batch_id", "import_id", "packet_sha256")}
             for row in effects], key=lambda row: (row["batch_id"], row["import_id"]))
        seals = [dict(row) for row in policy.execute(
            "SELECT import_id,batch_id,packet_sha256,consumed_by FROM seals ORDER BY import_id")]
        snapshot = {
            "effect_count": len(effects), "effects": effect_projection, "seals": seals,
            "consumed_seal_count": sum(row["consumed_by"] is not None for row in seals),
            "receiver_events": [dict(row) for row in receiver.execute(
                "SELECT seq,kind,event_hash FROM events ORDER BY seq")],
            "policy_events": [dict(row) for row in policy.execute(
                "SELECT seq,kind,event_hash FROM events ORDER BY seq")],
            "receiver_event_chain": chains["receiver"], "policy_event_chain": chains["policy"],
            "receiver_quick_check": "ok", "policy_quick_check": "ok",
            "epoch": int(policy.execute(
                "SELECT value FROM policy_metadata WHERE key='epoch'").fetchone()[0]),
            "source_versions": [dict(row) for row in policy.execute(
                "SELECT source_id,version FROM sources ORDER BY source_id")],
        }
        for effect in effects:
            packet_path = directory / "spool" / (effect["import_id"] + ".json")
            check(invariants, "effect_spool_exists:" + effect["import_id"], packet_path.is_file())
            if packet_path.is_file():
                raw = packet_path.read_bytes()
                packet = loads(raw)
                check(invariants, "effect_spool_binding:" + effect["import_id"],
                      raw == canonical(packet) + b"\n"
                      and packet.get("import_id") == effect["import_id"]
                      and packet.get("batch_id") == effect["batch_id"]
                      and packet.get("content_sha256") == effect["packet_sha256"]
                      and digest({key: value for key, value in packet.items()
                                  if key != "content_sha256"}) == effect["packet_sha256"])
        return {"data_directory": str(directory), "method": method,
                "effect_count": len(effects), "effects": effects,
                "snapshot": snapshot,
                "currently_allowed_sources": [row[0] for row in policy.execute(
                    "SELECT source_id FROM grants WHERE recipient_id='B' ORDER BY source_id")],
                "infrastructure_checks": infrastructure, "durable_checks": invariants,
                "hashes_before": hashes_before, "input_files_unchanged": True}
    finally:
        if receiver is not None:
            receiver.close()
        if policy is not None:
            policy.close()
        hashes_after = {str(path.relative_to(directory)): sha(path) for path in paths}
        names_after = sorted(str(path.relative_to(directory)) for path in directory.rglob("*")
                             if path.is_file())
        if hashes_before != hashes_after or names_before != names_after:
            raise ValueError("verifier_input_changed_during_read:" + str(directory))


def safe_worker(run: Path, value: str) -> Path:
    path = Path(value)
    target = path.resolve() if path.is_absolute() else inside(run, value)
    if not target.is_relative_to(run):
        raise ValueError("worker_path_escapes_run:" + value)
    return target


def no_plaintext(receipt) -> bool:
    if isinstance(receipt, dict):
        return (not {"content", "memory", "memories"}.intersection(receipt)
                and all(no_plaintext(value) for value in receipt.values()))
    if isinstance(receipt, list):
        return all(no_plaintext(value) for value in receipt)
    return True


def confirmed(result) -> bool:
    receipt = result.get("receipt") or {}
    return (result.get("accepted") is True and receipt.get("status") == "already_committed"
            and receipt.get("new_persistent_acceptance") is False
            and receipt.get("metadata_only") is True and no_plaintext(receipt))


def verify_worker(run: Path, operation: dict, infrastructure: list[dict]) -> Path:
    path = safe_worker(run, operation["worker_directory"])
    process = load(path / "process_exit.json")
    check(infrastructure, str(path.relative_to(run)) + ":process_exit_record",
          all(operation.get(key) == process.get(key) for key in
              ("exit_code", "stdout", "stderr", "worker_directory")))
    for name, key in (("result.json", "result"), ("rows.json", "rows"),
                      ("failpoint.json", "failpoint")):
        artifact = path / name
        check(infrastructure, str(path.relative_to(run)) + ":" + key + ":presence",
              artifact.is_file() == (key in operation))
        if artifact.is_file():
            check(infrastructure, str(path.relative_to(run)) + ":" + key + ":copy_matches",
                  canonical(load(artifact)) == canonical(operation.get(key)))
    if "result" in operation:
        result = operation["result"]
        ack = path / "ack.json"
        check(infrastructure, str(path.relative_to(run)) + ":actual_ack_sink_presence",
              ack.is_file() == (result.get("accepted") is True))
        if ack.is_file():
            check(infrastructure, str(path.relative_to(run)) + ":actual_ack_sink_binding",
                  canonical(load(ack)) == canonical(result.get("receipt")))
    return path


def snapshot_matches(actual: dict, recorded: dict) -> bool:
    return all(key in recorded and canonical(value) == canonical(recorded[key])
               for key, value in actual.items())


def verify_regression(row: dict, run: Path, config: dict, inspect,
                      infrastructure: list[dict]) -> dict:
    scenario, method = row["scenario_id"], row["method"]
    oracle = config["scenario_oracle"][scenario]
    check(infrastructure, scenario + ":" + method + ":frozen_oracle",
          canonical(row.get("expected")) == canonical(oracle))
    if row.get("harness_error"):
        check(infrastructure, scenario + ":" + method + ":no_harness_error", False,
              actual=row["harness_error"])
        return {"scenario_id": scenario, "method": method, "passed": False,
                "unverifiable": "harness_error", "checks": {}}
    operations = row["operations"]
    worker_paths = [verify_worker(run, operation, infrastructure) for operation in operations]
    computed, extra = {}, {}
    observations = []
    if scenario == "R8":
        paths = row.get("probe_directories", [])
        check(infrastructure, scenario + ":" + method + ":two_probe_directories",
              len(paths) == 2 and {Path(value).name for value in paths} == set(oracle["probes"]))
        observations = [inspect(value, method) for value in paths]
        count = sum(value["effect_count"] for value in observations)
        check(infrastructure, scenario + ":" + method + ":probe_snapshots_match_actual_disk",
              len(row["after_snapshot"].get("probe_snapshots", [])) == len(observations)
              and all(snapshot_matches(value["snapshot"], saved) for value, saved in
                      zip(observations, row["after_snapshot"].get("probe_snapshots", []))))
        computed["both_probes_rejected"] = (len(operations) == 2 and all(
            value.get("result", {}).get("accepted") is False for value in operations))
    else:
        observation = inspect(row["data_directory"], method)
        observations = [observation]
        count = observation["effect_count"]
        check(infrastructure, scenario + ":" + method + ":after_snapshot_matches_actual_disk",
              snapshot_matches(observation["snapshot"], row["after_snapshot"]))
        if scenario in ("R1", "R2", "R3"):
            if len(operations) != 2:
                raise ValueError("fault_and_retry_operations_required:" + scenario)
            fault, retry = operations
            marker = fault.get("failpoint", {})
            fault_name = {"R1": "before_dml", "R2": "before_commit",
                          "R3": "after_commit_before_ack"}[scenario]
            computed["fault_point_reached"] = (fault.get("exit_code") == oracle["fault_exit_code"]
                and marker.get("reached") is True and marker.get("fault") == fault_name)
            computed["effects_at_fault"] = (retry.get("result", {}).get(
                "before_snapshot", {}).get("effect_count") == oracle["effects_at_fault"])
            computed["ACK_absent_at_fault"] = not (worker_paths[0] / "ack.json").exists()
            if scenario == "R2":
                computed["transaction_had_writes"] = (marker.get("writer_in_transaction") is True
                                                       and marker.get("writer_total_changes", 0) > 0)
            result = retry.get("result", {})
            computed["legal_retry_or_confirmation"] = (confirmed(result) if scenario == "R3"
                                                        else result.get("accepted") is True)
        elif scenario == "R4":
            first, again = operations
            computed["initial_ACK_received"] = ((worker_paths[0] / "ack.json").is_file()
                                                  and first.get("result", {}).get("accepted") is True)
            computed["duplicate_confirmed"] = confirmed(again.get("result", {}))
        elif scenario == "R5":
            result = operations[0].get("result", {})
            evidence = result.get("precheck_evidence") or {}
            mutation_path = worker_paths[0] / "revoker/mutation.json"
            check(infrastructure, scenario + ":" + method + ":revoker_record_matches",
                  mutation_path.is_file() and canonical(load(mutation_path)) == canonical(
                      evidence.get("revoker_result")))
            computed["revocation_committed_after_allowed_precheck"] = (
                evidence.get("passed") is True
                and evidence.get("revoker_result", {}).get("status") == "committed")
            computed["old_packet_rejected"] = result.get("accepted") is False
            extra["actual_policy_has_no_B_grants_after_later_epoch"] = (
                not observation["currently_allowed_sources"]
                and observation["snapshot"]["epoch"] > evidence.get("epoch", -1))
        elif scenario == "R6":
            initial = operations[0]
            first_recovery = operations[1].get("rows", [])
            computed["initial_worker_committed_then_exited"] = (
                initial.get("exit_code") == 73 and len(first_recovery) == 2
                and first_recovery[0].get("before_snapshot", {}).get("effect_count") == 1)
            for index in (1, 2):
                recovered = operations[index].get("rows", [])
                computed[f"recovery_scan_{index}_classifies_both_tasks"] = (
                    len(recovered) == 2 and confirmed(recovered[0])
                    and recovered[1].get("accepted") is False)
                if len(recovered) == 2:
                    for item_index, result in enumerate(recovered):
                        step = worker_paths[index] / ("item-%02d" % item_index)
                        check(infrastructure, scenario + ":" + method + f":sweep{index}:{item_index}",
                              canonical(load(step / "result.json")) == canonical(
                                  {key: value for key, value in result.items()
                                   if key not in {"batch_id", "packet_sha256"}})
                              and (step / "ack.json").is_file() == (result.get("accepted") is True))
                        if (step / "ack.json").is_file():
                            check(infrastructure, scenario + ":" + method + f":sweep{index}:{item_index}:ACK_binding",
                                  canonical(load(step / "ack.json")) == canonical(result.get("receipt")))
            extra["source_advanced_and_B_revoked"] = (
                not observation["currently_allowed_sources"]
                and any(value["version"] == 2 for value in observation["snapshot"]["source_versions"]))
        elif scenario == "R7":
            ready = [load(path / "ready.json") for path in worker_paths]
            go = load(worker_paths[0].parent / "barrier/go.json")
            extra["both_processes_passed_equal_precheck_barrier"] = (
                len(ready) == 2 and all(value.get("precheck_passed") is True for value in ready)
                and go.get("both_prechecks_completed") is True)
            computed["both_requests_receive_valid_ACK"] = all(
                value.get("result", {}).get("accepted") is True for value in operations)
            computed["one_new_one_existing_receipt"] = sum(
                confirmed(value.get("result", {})) for value in operations) == 1
    computed["final_effect_count"] = count == oracle["final_effect_count"]
    acknowledgements = [value.get("result", {}).get("receipt") for value in operations]
    acknowledgements.extend(result.get("receipt") for value in operations for result in value.get("rows", []))
    computed["no_plaintext_ACK"] = all(no_plaintext(value) for value in acknowledgements)
    check(infrastructure, scenario + ":" + method + ":row_after_count_matches_actual_disk",
          row["after_snapshot"]["effect_count"] == count)
    check(infrastructure, scenario + ":" + method + ":runner_checks_recomputed",
          row.get("checks") == computed, recomputed=computed, recorded=row.get("checks"))
    check(infrastructure, scenario + ":" + method + ":runner_pass_matches_recomputed",
          row.get("passed") is all(computed.values()))
    durable_ok = all(value["passed"] for observation in observations for value in observation["durable_checks"])
    return {"scenario_id": scenario, "method": method,
            "passed": all(computed.values()) and all(extra.values()) and durable_ok,
            "shared_oracle_checks": computed, "independent_additional_checks": extra,
            "durable_invariants_pass": durable_ok, "actual_effect_count": count,
            "expected_effect_count": oracle["final_effect_count"],
            "baseline_failure_is_not_artifact_error": method == "acl"}


def verify_performance(rows: list[dict], run: Path, inspect,
                       infrastructure: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[(row["project_id"], row["method"], row["data_directory"])].append(row)
    results = []
    for (project, method, relative), group in sorted(groups.items()):
        group.sort(key=lambda value: value["repeat_index"])
        prefix = project + ":" + method
        observation = inspect(relative, method)
        worker = inside(run, relative).parent / "worker"
        process = load(worker / "process_exit.json")
        saved_rows = load(worker / "rows.json")
        check(infrastructure, prefix + ":performance_worker_completed", process["exit_code"] == 0)
        check(infrastructure, prefix + ":six_saved_worker_rows", len(saved_rows) == 6)
        trials = []
        previous = None
        for index, row in enumerate(group):
            raw_trial = {key: value for key, value in row.items()
                         if key not in {"kind", "project_id", "method", "repeat_index", "data_directory"}}
            check(infrastructure, prefix + f":{index}:raw_worker_row_matches",
                  index < len(saved_rows) and canonical(raw_trial) == canonical(saved_rows[index]))
            step = worker / ("item-%02d" % index)
            step_result = load(step / "result.json")
            check(infrastructure, prefix + f":{index}:step_result_matches",
                  canonical(step_result) == canonical({key: value for key, value in raw_trial.items()
                                                      if key not in {"batch_id", "packet_sha256"}}))
            ack_path = step / "ack.json"
            check(infrastructure, prefix + f":{index}:ack_presence_matches",
                  ack_path.is_file() == (row.get("accepted") is True))
            if ack_path.is_file():
                check(infrastructure, prefix + f":{index}:ack_matches_returned_receipt",
                      canonical(load(ack_path)) == canonical(row.get("receipt")))
            receipt = row.get("receipt") or {}
            checks = {
                "accepted": row.get("accepted") is True,
                "new_persistent_acceptance": receipt.get("new_persistent_acceptance") is True,
                "metadata_only_ACK": receipt.get("metadata_only") is True and no_plaintext(receipt),
                "one_additional_effect": row["before_snapshot"]["effect_count"] == index
                    and row["after_snapshot"]["effect_count"] == index + 1,
                "nonnegative_observed_measurements": all(type(row.get(key)) is int and row[key] >= 0
                    for key in ("wall_ns", "cpu_ns", "sql_logical_statements")),
                "logical_SQL_count_consistent": row.get("sql_logical_statements") == sum(
                    row.get("sql_logical_counts", {}).values())
                    and row.get("SQL_is_physical_IO") is False
                    and row.get("physical_IO_operations") is None,
            }
            if previous is not None:
                checks["serial_snapshot_continuity"] = canonical(previous) == canonical(row["before_snapshot"])
            trials.append({"repeat_index": row["repeat_index"], "checks": checks,
                           "passed": all(checks.values())})
            previous = row["after_snapshot"]
        check(infrastructure, prefix + ":final_performance_snapshot_matches_actual_disk",
              bool(group) and snapshot_matches(observation["snapshot"], group[-1]["after_snapshot"]))
        expected_effects = {(row["transfer_id"], row["batch_id"], row["packet_sha256"]) for row in group}
        actual_effects = {(row["import_id"], row["batch_id"], row["packet_sha256"])
                          for row in observation["effects"]}
        checks = {
            "six_distinct_completed_operations": len(group) == 6 and len(expected_effects) == 6
                and observation["effect_count"] == 6 and expected_effects == actual_effects,
            "all_trials_pass": all(value["passed"] for value in trials),
            "durable_invariants": all(value["passed"] for value in observation["durable_checks"]),
        }
        results.append({"project_id": project, "method": method,
                        "passed": all(checks.values()), "checks": checks, "trials": trials})
    return results


def verify_run(run: Path) -> dict[str, Any]:
    infrastructure, directory_results, directory_cache = [], [], {}
    config = load(run / "config.json")
    lock = load(run / "config_lock.json")
    completion = load(run / "completion.json")
    versions = load(run / "code_version.json")
    freeze = load(Path(__file__).parent / "freeze_manifest.json")
    check(infrastructure, "completed_before_verification",
          completion.get("status") == "completed" and lock.get("locked_before_execution") is True)
    check(infrastructure, "config_matches_frozen_contract",
          canonical(config) == canonical(load(Path(__file__).parent / "contract.json"))
          and sha(Path(__file__).parent / "contract.json") == lock.get("contract_sha256"))
    check(infrastructure, "runner_hash_matches_lock",
          sha(Path(__file__).parent / "runner.py") == lock.get("runner_sha256"))
    check(infrastructure, "freeze_manifest_matches_lock",
          sha(Path(__file__).parent / "freeze_manifest.json") == lock.get("freeze_manifest_sha256"))
    for relative, expected in freeze["code_sha256"].items():
        path = inside(Path(__file__).parent, relative)
        check(infrastructure, "frozen_acceptance_code:" + relative, path.is_file() and sha(path) == expected)
    for item in versions["files"]:
        path = inside(REPO, item["path"])
        check(infrastructure, "production_code_hash:" + item["path"],
              path.is_file() and sha(path) == item["sha256"])
    for relative, expected in completion["artifact_sha256"].items():
        path = inside(run, relative)
        check(infrastructure, "completed_artifact_hash:" + relative,
              path.is_file() and sha(path) == expected)
    check(infrastructure, "same_security_core_not_a_superiority_requirement",
          config.get("same_B_C_security_core") is True and versions.get("same_B_C_core") is True
          and completion.get("B_C_same_core") is True and completion.get("code_hashes_unchanged") is True)
    check(infrastructure, "no_model_calls_or_old_experiment_reruns",
          config.get("new_model_calls") == 0 and completion.get("new_model_calls") == 0
          and completion.get("old_experiments_reexecuted") == 0)
    regression = jsonl(run / "raw_regression.jsonl")
    performance = jsonl(run / "raw_performance.jsonl")
    wanted_regression = {(f"R{i}", method) for i in range(1, 9) for method in METHODS}
    actual_regression = [(row.get("scenario_id"), row.get("method")) for row in regression]
    wanted_performance = {(f"P{i:02d}", method, repeat) for i in range(1, 11)
                          for method in METHODS for repeat in range(6)}
    actual_performance = [(row.get("project_id"), row.get("method"), row.get("repeat_index"))
                          for row in performance]
    check(infrastructure, "fixed_24_unique_regression_rows",
          len(regression) == len(set(actual_regression)) == config.get("regression_rows") == 24
          and set(actual_regression) == wanted_regression
          and completion.get("regression_rows") == 24)
    check(infrastructure, "fixed_180_unique_performance_rows",
          len(performance) == len(set(actual_performance)) == config.get("performance_rows") == 180
          and set(actual_performance) == wanted_performance
          and completion.get("performance_rows") == 180)

    def inspect(relative, method):
        directory = inside(run, relative)
        key = (directory, method)
        if key not in directory_cache:
            result = inspect_directory(directory, method)
            directory_cache[key] = result
            directory_results.append(result)
            infrastructure.extend({**value, "directory": str(directory.relative_to(run))}
                                  for value in result["infrastructure_checks"])
        return directory_cache[key]

    regression_results = []
    for row in regression:
        try:
            regression_results.append(verify_regression(row, run, config, inspect, infrastructure))
        except Exception as exc:
            check(infrastructure, "regression_verification_completed:" + str(row.get("scenario_id"))
                  + ":" + str(row.get("method")), False, error=type(exc).__name__ + ":" + str(exc))
            regression_results.append({"scenario_id": row.get("scenario_id"),
                                       "method": row.get("method"), "passed": False,
                                       "unverifiable": type(exc).__name__ + ":" + str(exc)})
    try:
        performance_results = verify_performance(performance, run, inspect, infrastructure)
    except Exception as exc:
        check(infrastructure, "performance_verification_completed", False,
              error=type(exc).__name__ + ":" + str(exc))
        performance_results = []
    # Include every completed template receiver/policy pair as well as the
    # outcome databases. Never open the sender's SQLite through a write API.
    known = {directory for directory, _method in directory_cache}
    for policy in sorted(run.rglob("policy.sqlite")):
        directory = policy.parent.resolve()
        if directory not in known:
            relative = directory.relative_to(run)
            is_template = (str(relative).replace("\\", "/") == "regression_template"
                           or str(relative).replace("\\", "/").startswith("performance_templates/"))
            check(infrastructure, "additional_database_is_closed_template:" + str(relative), is_template)
            if is_template:
                result = inspect(str(relative), "template")
                check(infrastructure, "template_has_no_receiver_effects:" + str(relative),
                      result["effect_count"] == 0)
    discovered = {path.resolve() for path in run.rglob("B.sqlite") if path.parent.name == "agents"}
    observed = {directory / "agents/B.sqlite" for directory, _method in directory_cache}
    check(infrastructure, "every_receiver_database_independently_inspected", discovered == observed,
          discovered=len(discovered), inspected=len(observed))
    check(infrastructure, "every_policy_database_independently_inspected",
          {path.resolve() for path in run.rglob("policy.sqlite")}
          == {directory / "policy.sqlite" for directory, _method in directory_cache})
    method_summaries = {}
    for method in METHODS:
        selected = [row for row in regression_results if row["method"] == method]
        perf = [row for row in performance_results if row["method"] == method]
        method_summaries[method] = {
            "regression_rows": len(selected), "shared_oracle_passes": sum(row["passed"] for row in selected),
            "shared_oracle_failures": [row["scenario_id"] for row in selected if not row["passed"]],
            "performance_projects": len(perf), "performance_passes": sum(row["passed"] for row in perf),
            "required_for_behavioral_gate": method in STRONG,
        }
    artifacts_ok = all(value["passed"] for value in infrastructure)
    strong_ok = all(method_summaries[method]["regression_rows"] == 8
                    and method_summaries[method]["shared_oracle_passes"] == 8
                    and method_summaries[method]["performance_projects"] == 10
                    and method_summaries[method]["performance_passes"] == 10 for method in STRONG)
    return {
        "schema": "gateway-v1-independent-readonly-verification-v1",
        "verified_utc": datetime.now(timezone.utc).isoformat(), "run_directory": str(run),
        "verification_passed": artifacts_ok and strong_ok,
        "artifact_integrity_and_record_consistency_pass": artifacts_ok,
        "strong_transaction_and_gateway_gate_pass": strong_ok,
        "ACL_result_is_descriptive_no_forced_failure": True,
        "B_C_equivalent_results_are_acceptable": True,
        "method_summaries": method_summaries, "infrastructure_checks": infrastructure,
        "regression_results": regression_results, "performance_results": performance_results,
        "database_inspections": directory_results,
        "database_count": 2 * len(directory_results), "scenario_reexecutions": 0,
        "model_calls": 0, "database_writes": 0,
        "independence": "stdlib JSON/hashlib/sqlite3 implementation; no imports of the tested runner, Gateway or Store",
        "evidence_scope": "Final databases are independently observed. Earlier fault ordering uses saved process, marker and snapshot records; this verifier does not recreate past SQL execution.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    destination = (args.output or run / "verify.json").resolve()
    if not destination.is_relative_to(run):
        parser.error("verification output must be a new file inside the run directory")
    if destination.exists():
        parser.error("preserve the existing verification output; select a new output filename")
    try:
        report = verify_run(run)
    except Exception as exc:
        report = {"schema": "gateway-v1-independent-readonly-verification-v1",
                  "verified_utc": datetime.now(timezone.utc).isoformat(),
                  "run_directory": str(run), "verification_passed": False,
                  "verification_incomplete": True, "error": type(exc).__name__ + ":" + str(exc),
                  "scenario_reexecutions": 0, "model_calls": 0, "database_writes": 0}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"output": str(destination),
                      "verification_passed": report["verification_passed"]}, ensure_ascii=False))
    raise SystemExit(0 if report["verification_passed"] else 2)


if __name__ == "__main__":
    main()
