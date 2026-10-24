"""Actual 1/3/10 local transfers, cache controls and controlled revocation probes.

Only a selected development story is read. Restoration probes programmatically
select a token from authorized memory; they are instrumentation, not model task
answers. Neither authority keys nor recovery maps/values are saved.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
from pathlib import Path
import random
import re
import secrets
import shutil
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.coverage_memory import CoverageMemoryBuilder
from memory_migration_study.detection_cache import DetectionCache, detector_revision
from memory_migration_study.memory_labels import MemoryLabelAuthority, prepare_labeled_transfer, restore_labeled_answer
from memory_migration_study.ner_detector import GlinerEntityAgent, LocalNerRuntime
from memory_migration_study.privacy import _digest
from memory_migration_study.reuse_benchmark import save

VERSION = "actual_transfer_lifecycle_v2_timed"
ARMS = ("migration", "migration_cached", "generation", "generation_cached")
_TOKENS = re.compile(r"\[PVT_[A-F0-9]{24}_[A-Z]+_\d+\]")


class EmptySetupCandidates:
    """Zero-model setup for migration-only controls; rules are still applied.

    This is not a sensitivity oracle. Migration-only arms ignore its labels and
    execute the full real detector on each uncached transfer.
    """
    def __call__(self, **kwargs):
        return {"status": "ok", "findings": [], "errors": [], "local_calls": 0,
                "elapsed_seconds": 0.0, "model": "zero_model_setup_instrument"}


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _source_hashes():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / "memory_migration_study").glob("*.py")}


def _setup(story, detector, authority, *, generation):
    started = perf_counter()
    builder = CoverageMemoryBuilder(detector=detector if generation else EmptySetupCandidates())
    source, policy = story["source"], story["policy"]
    built = builder(text=source["text"], source_id=source["source_id"], policy=policy)
    records = []
    if built["status"] == "ok":
        for fact in built["facts"]:
            records.append(authority.build_record(source, fact, policy, owner_id="owner", readers=["owner"],
                agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"],
                detector_version=detector_revision(detector) if generation else "zero_model_setup_instrument"))
    # Persistence boundary without serializing authority or restoration maps.
    records = json.loads(json.dumps(records, ensure_ascii=False))
    return built, records, perf_counter()-started


def _prepare(records, query, policy, authority, detector, request_id, *, generation, cache=None):
    started = perf_counter()
    prepared = prepare_labeled_transfer(records, query, policy, authority=authority, actor_id="owner",
        agent_id="target-agent", request_id=request_id, mode="generation" if generation else "migration",
        agent=detector, detection_cache=cache)
    prepared["_benchmark_prepare_wall_seconds"] = perf_counter()-started
    return prepared


def _tokens(prepared):
    if not prepared or prepared.get("status") != "ok":
        return set(), None
    payload = prepared["payload"]
    all_tokens = set(_TOKENS.findall(json.dumps(payload, ensure_ascii=False)))
    memory = [token for record in payload["memories"] for token in _TOKENS.findall(record["text"])]
    return all_tokens, memory[0] if memory else None


def _probe(prepared, records, policy, authority, request_id, token):
    if token is None:
        return {"status": "not_applicable", "error": "no_authorized_memory_token", "model_calls": 0,
                "restore_executed": False, "restore_wall_seconds": 0.0}
    started = perf_counter()
    restored = restore_labeled_answer(token, prepared, records, policy, authority=authority,
        actor_id="owner", agent_id="target-agent", request_id=request_id)
    elapsed = perf_counter()-started
    answer = restored.get("answer")
    # The actual answer remains local transient data; save only probe outcomes.
    return {"status": restored["status"], "error": restored.get("error"), "model_calls": 0,
            "restore_executed": True, "restore_wall_seconds": elapsed,
            "restored_from_memory": restored["status"] == "ok" and isinstance(answer, str)
                 and any(answer in record["text"] for record in records)}


def _observation(prepared, request_id):
    detection = prepared.get("detection") or {}
    return {"request_sha256": _hash(request_id), "status": prepared.get("status"), "error": prepared.get("error"),
            "encoder_calls": prepared.get("local_calls", 0),
            "prepare_wall_seconds": prepared["_benchmark_prepare_wall_seconds"],
            "call_accounting_complete": detection.get("local_calls_complete", True),
            "cache": prepared.get("metadata", {}).get("detection_cache", {}),
            "label_checks": prepared.get("checks", []),
            "masked_payload_sha256": _digest(prepared["payload"]) if prepared.get("status") == "ok" else None}


def _cell(story, query, detector, arm, repetitions):
    started = perf_counter()
    authority = MemoryLabelAuthority(secrets.token_bytes(32))
    generation, cached = arm.startswith("generation"), arm.endswith("_cached")
    cache = DetectionCache(max_entries=256, ttl_seconds=300) if cached else None
    built, records, setup_seconds = _setup(story, detector, authority, generation=generation)
    rows, seen = [], set()
    for index in range(repetitions):
        iteration_started = perf_counter()
        request_id = secrets.token_hex(16)
        if not records:
            rows.append({"iteration": index+1, "status": "not_executed", "error": "memory_build_unavailable",
                         "prepare_executed": False, "encoder_calls": 0, "cache": {}, "token_freshness_checked": False,
                         "prepare_wall_seconds": 0.0, "reused_tokens": 0, "token_sha256": [],
                         "restore_probe": {"status": "not_executed", "model_calls": 0,
                                           "restore_executed": False, "restore_wall_seconds": 0.0}})
            rows[-1]["iteration_wall_seconds"] = perf_counter()-iteration_started
            rows[-1]["instrumentation_wall_seconds"] = rows[-1]["iteration_wall_seconds"]
            continue
        prepared = _prepare(records, query, story["policy"], authority, detector, request_id,
                            generation=generation, cache=cache)
        tokens, memory_token = _tokens(prepared)
        observation = _observation(prepared, request_id)
        rows.append(dict(observation, iteration=index+1, prepare_executed=True,
                         token_freshness_checked=bool(tokens), reused_tokens=len(tokens & seen),
                         token_sha256=sorted(_hash(token) for token in tokens),
                         restore_probe=_probe(prepared, records, story["policy"], authority, request_id, memory_token)))
        seen.update(tokens)
        prepared["mapping"] = None
        row = rows[-1]
        row["iteration_wall_seconds"] = perf_counter()-iteration_started
        row["instrumentation_wall_seconds"] = (row["iteration_wall_seconds"]-row["prepare_wall_seconds"]
                                                -row["restore_probe"]["restore_wall_seconds"])
    migration_calls = sum(row["encoder_calls"] for row in rows)
    prepare_seconds = sum(row["prepare_wall_seconds"] for row in rows)
    restore_seconds = sum(row["restore_probe"]["restore_wall_seconds"] for row in rows)
    iteration_overhead = sum(row["instrumentation_wall_seconds"] for row in rows)
    result = {"arm": arm, "requested_repetitions": repetitions, "independent_local_domain": True,
            "setup_status": built["status"], "setup_errors": built.get("errors", []),
            "setup_encoder_calls": built["local_calls"], "setup_builder_model_calls": 0,
            "coverage": built["coverage"], "stored_records": len(records),
            "stored_text_characters": sum(len(r["text"]) for r in records),
            "serialized_store_bytes": len(json.dumps(records, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
            "prepare_calls_executed": sum(row["prepare_executed"] for row in rows),
            "ready_transfers": sum(row["status"] == "ok" for row in rows),
            "migration_encoder_calls": migration_calls,
            "total_physical_encoder_calls": built["local_calls"]+migration_calls,
            "cache_hits": sum(row["cache"].get("hits", 0) for row in rows),
            "reused_tokens": sum(row["reused_tokens"] for row in rows), "rows": rows,
            "setup_wall_seconds": setup_seconds, "prepare_wall_seconds": prepare_seconds,
            "restore_instrument_wall_seconds": restore_seconds,
            "iteration_instrumentation_wall_seconds": iteration_overhead,
            "timing_scope": "Setup includes chunking/detection, signing and JSON roundtrip. Prepare measures the transfer API. Restore instrumentation is separate. Cell wall includes these plus domain/cache initialization and host overhead; shared model loading/asset validation is excluded."}
    cell_seconds = perf_counter()-started
    result.update(cell_wall_seconds=cell_seconds,
                  cell_framework_wall_seconds=cell_seconds-setup_seconds-prepare_seconds-restore_seconds-iteration_overhead)
    return result


def _finish_witness_timing(row, started, *, restore_seconds=0.0, revoke_seconds=0.0):
    elapsed = perf_counter()-started
    row.update(witness_wall_seconds=elapsed, restore_instrument_wall_seconds=restore_seconds,
               revoke_wall_seconds=revoke_seconds,
               witness_framework_wall_seconds=elapsed-row["prepare_wall_seconds"]-restore_seconds-revoke_seconds)
    return row


def _dynamic(story, query, detector, changed_policy):
    started = perf_counter()
    authority = MemoryLabelAuthority(secrets.token_bytes(32))
    built, records, setup_seconds = _setup(story, detector, authority, generation=True)
    result = {"setup_status": built["status"], "setup_encoder_calls": built["local_calls"],
              "setup_wall_seconds": setup_seconds, "witnesses": []}
    if not records:
        result.update(status="incomplete", error="memory_build_unavailable", total_physical_encoder_calls=built["local_calls"])
        elapsed = perf_counter()-started
        result.update(dynamic_wall_seconds=elapsed, witnesses_wall_seconds=0.0,
                      dynamic_framework_wall_seconds=elapsed-setup_seconds)
        return result
    policy = story["policy"]
    for name, current_records, current_policy, fallback in (
        ("same_version_policy_change", records, changed_policy, "label_policy_changed"),
        ("removed_label", [{k: v for k, v in r.items() if k not in {"label", "label_signature"}} for r in records], policy, "label_missing")):
        witness_started = perf_counter()
        request_id = secrets.token_hex(16)
        prepared = _prepare(current_records, query, current_policy, authority, detector, request_id, generation=True)
        row = dict(_observation(prepared, request_id), witness=name)
        row["passed"] = prepared["status"] == "ok" and prepared["local_calls"] > 0 and all(
            check.get("fallback_reason") == fallback for check in prepared.get("checks", [])) and bool(prepared.get("checks"))
        prepared["mapping"] = None
        result["witnesses"].append(_finish_witness_timing(row, witness_started))

    # Warm a proper cache and retain the old map only in memory for the revoke
    # race witness. Authorization is checked before every reuse/restoration.
    cache = DetectionCache()
    witness_started = perf_counter()
    old_request = secrets.token_hex(16)
    prepared = _prepare(records, query, policy, authority, detector, old_request, generation=True, cache=cache)
    _, memory_token = _tokens(prepared)
    before = _probe(prepared, records, policy, authority, old_request, memory_token)
    revoke_started = perf_counter()
    for record in records:
        authority.revoke(record["record_id"])
    revoke_seconds = perf_counter()-revoke_started
    after = _probe(prepared, records, policy, authority, old_request, memory_token)
    row = dict(_observation(prepared, old_request), witness="revoke_before_restore",
        before_probe=before, after_probe=after,
        passed=before["status"] == "ok" and after["status"] == "blocked" and after["error"] == "grant_revoked")
    prepared["mapping"] = None
    result["witnesses"].append(_finish_witness_timing(row, witness_started,
        restore_seconds=before["restore_wall_seconds"]+after["restore_wall_seconds"], revoke_seconds=revoke_seconds))
    witness_started = perf_counter()
    replay = _prepare(records, query, policy, authority, detector, old_request, generation=True, cache=cache)
    row = dict(_observation(replay, old_request), witness="old_request_replay_after_revoke",
        passed=replay["status"] == "blocked" and replay.get("error") == "grant_revoked" and replay["local_calls"] == 0)
    replay["mapping"] = None
    result["witnesses"].append(_finish_witness_timing(row, witness_started))

    # A new host-issued grant is independent of revoked record IDs. This does
    # not revive an old grant or erase information already received by anyone.
    witness_started = perf_counter()
    fresh_records = [authority.build_record(story["source"], fact, policy, owner_id="owner", readers=["owner"],
        agent_id="source-agent", allowed_agent_ids=["target-agent"], builder_version=built["builder_version"],
        detector_version=detector_revision(detector)) for fact in built["facts"]]
    fresh_request = secrets.token_hex(16)
    fresh = _prepare(fresh_records, query, policy, authority, detector, fresh_request, generation=True, cache=cache)
    _, memory_token = _tokens(fresh)
    probe = _probe(fresh, fresh_records, policy, authority, fresh_request, memory_token)
    row = dict(_observation(fresh, fresh_request), witness="new_independent_grant",
        restore_probe=probe, passed=fresh["status"] == "ok" and probe["status"] == "ok")
    fresh["mapping"] = None
    result["witnesses"].append(_finish_witness_timing(row, witness_started, restore_seconds=probe["restore_wall_seconds"]))
    result["total_physical_encoder_calls"] = built["local_calls"] + sum(row["encoder_calls"] for row in result["witnesses"])
    result["status"] = "passed" if all(row["passed"] for row in result["witnesses"]) else "incomplete"
    elapsed = perf_counter()-started
    witness_seconds = sum(row["witness_wall_seconds"] for row in result["witnesses"])
    result.update(dynamic_wall_seconds=elapsed, witnesses_wall_seconds=witness_seconds,
                  dynamic_framework_wall_seconds=elapsed-setup_seconds-witness_seconds)
    return result


def run(corpus, output, model_root, *, story_id=None, task_id=None, repetitions=(1, 3, 10), progress=None):
    run_started = perf_counter()
    corpus, output = Path(corpus), Path(output)
    if (not isinstance(repetitions, (tuple, list)) or not repetitions
            or any(type(n) is not int or not 1 <= n <= 10 for n in repetitions) or len(set(repetitions)) != len(repetitions)):
        raise ValueError("invalid_actual_repetition_counts")
    raw = (corpus / "development/runtime.json").read_bytes()
    runtime = json.loads(raw)
    candidates = [s for s in runtime if story_id is None or s["story_id"] == story_id]
    if not candidates:
        raise ValueError("development_story_not_found")
    story = copy.deepcopy(min(candidates, key=lambda s: (len(s["source"]["text"]), s["story_id"])))
    tasks = [t for t in story["tasks"] if t["actor_id"] == "owner" and (task_id is None or t["task_id"] == task_id)]
    if not tasks:
        raise ValueError("authorized_development_task_not_found")
    task = tasks[0]
    policy = story["policy"]
    changed_policy = dict(policy, instructions=policy.get("instructions", "")+" Host revision: refresh entity labels before transfer.")
    output.mkdir(parents=True, exist_ok=False)
    hashes = _source_hashes()
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    archive = output / "implementation"
    archive.mkdir()
    for p in (ROOT / "memory_migration_study").glob("*.py"):
        shutil.copy2(p, archive / p.name)
    shutil.copy2(__file__, output / "executed_lifecycle_script.py")
    order = [(arm, n) for n in repetitions for arm in ARMS]
    random.Random(2026102503).shuffle(order)
    save(output / "plan.json", {"version": VERSION, "split": "development", "story_id": story["story_id"],
        "task_id": task["task_id"], "arms": ARMS, "actual_repetitions": repetitions, "execution_order": order,
        "development_runtime_sha256": hashlib.sha256(raw).hexdigest(), "selected_input_sha256": _digest(story),
        "implementation_sha256": hashes, "script_sha256": script_hash, "threshold": .5,
        "clock": "time.perf_counter", "timing_protocol": "Setup, each transfer API, restoration instrumentation and host overhead are measured independently. Shared model loading/asset validation is separate. Final report serialization/rendering is outside run_measured_wall_seconds.",
        "scope": "One source story, actual local repeated preparations; no heldout/evaluation reads or arithmetic projections. Independent authority/cache per cell; model weights shared. No answer model, native online or cross-process claim."})
    save(output / "runtime.json", {"story": story, "task": task, "changed_policy": changed_policy})
    loading_started = perf_counter()
    runtime_model = LocalNerRuntime(model_root)
    loading_seconds = perf_counter()-loading_started
    detector = GlinerEntityAgent(runtime_model, approved_policies=[policy, changed_policy])
    save(output / "runtime_identity.json", {"ner": runtime_model.identity,
        "initialization_seconds": runtime_model.initialization_seconds,
        "model_loading_and_asset_validation_wall_seconds": loading_seconds, "detector": detector.cache_identity()})
    cells = []
    for arm, n in order:
        cells.append(_cell(story, task["query"], detector, arm, n))
        save(output / "cells.json", cells)
        if progress:
            progress({"completed_cells": len(cells), "total_cells": len(order), "arm": arm, "actual_repetitions": n,
                      "ready": cells[-1]["ready_transfers"], "encoder_calls": cells[-1]["total_physical_encoder_calls"]})
    dynamic = _dynamic(story, task["query"], detector, changed_policy)
    save(output / "dynamic.json", dynamic)
    if _source_hashes() != hashes or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != script_hash:
        raise ValueError("implementation_changed_during_lifecycle_study")
    measured_seconds = perf_counter()-run_started
    cells_seconds = sum(c["cell_wall_seconds"] for c in cells)
    report = {"version": VERSION, "story_id": story["story_id"], "independent_source_stories": 1,
        "actual_repetition_counts": list(repetitions), "cells": cells, "dynamic": dynamic,
        "registered_preparations": sum(n for _, n in order),
        "executed_preparations": sum(c["prepare_calls_executed"] for c in cells),
        "setup_encoder_calls": sum(c["setup_encoder_calls"] for c in cells),
        "migration_encoder_calls": sum(c["migration_encoder_calls"] for c in cells),
        "total_physical_encoder_calls": sum(c["total_physical_encoder_calls"] for c in cells)+dynamic["total_physical_encoder_calls"],
        "model_loading_and_asset_validation_wall_seconds": loading_seconds,
        "cells_wall_seconds": cells_seconds, "dynamic_wall_seconds": dynamic["dynamic_wall_seconds"],
        "run_framework_and_intermediate_io_wall_seconds": measured_seconds-loading_seconds-cells_seconds-dynamic["dynamic_wall_seconds"],
        "run_measured_wall_seconds": measured_seconds,
        "timing_scope": "Monotonic measured intervals, not arithmetic time projections. Cell cumulative wall includes setup and restoration instrumentation; transfer API and restore times are also separate. Loading/validation is reported independently. Run wall includes intermediate evidence IO but excludes final report/HTML/network-audit serialization.",
        "model_answer_calls": 0, "cloud_calls": 0, "new_api_cost_cny": 0, "implementation_unchanged": True,
        "status": "passed" if all(c["ready_transfers"] == c["requested_repetitions"] and c["reused_tokens"] == 0 for c in cells)
                                and dynamic["status"] == "passed" else "completed_with_failures",
        "probe_scope": "Programmatic authorized-memory token restoration, never model task correctness or a privacy completeness score."}
    save(output / "report.json", report)
    render(output, report)
    return report


def render(output, report):
    keys = ("arm", "requested_repetitions", "prepare_calls_executed", "ready_transfers", "setup_encoder_calls",
            "migration_encoder_calls", "total_physical_encoder_calls", "cache_hits", "reused_tokens",
            "setup_wall_seconds", "prepare_wall_seconds", "restore_instrument_wall_seconds", "cell_wall_seconds")
    esc = lambda x: html.escape(str(x))
    body = '<!doctype html><meta charset="utf-8"><title>真实重复迁移与生命周期</title><style>body{font:16px/1.7 system-ui;margin:32px}table{border-collapse:collapse}th,td{border:1px solid #bbc;padding:8px}</style><h1>真实重复迁移与生命周期</h1>'
    body += '<p>仅一个开发故事；每个1/3/10次条件均独立建立权限域与缓存，实际调用迁移接口。A构建不做语义推理，迁移仍检测；B计入实际生成标签成本。不是算术投影。恢复探针由程序选择已授权记忆代号，不是模型答题。</p><table><tr>'+''.join('<th>'+esc(k)+'</th>' for k in keys)+'</tr>'
    for cell in report["cells"]:
        body += '<tr>'+''.join('<td>'+esc(cell[k])+'</td>' for k in keys)+'</tr>'
    body += '</table><p>每格累计实测时间含构建、迁移、程序恢复探针及主机开销；prepare与恢复探针耗时分别列出。共享模型加载与文件验证单列为 '+esc(report["model_loading_and_asset_validation_wall_seconds"])+' 秒，不藏入某个条件。时间为单次本机观察，不设性能达标阈值。</p><p>动态见证：'+esc(report["dynamic"]["status"])+ '；总体执行状态：'+esc(report["status"])+ '。不代表原生在线撤权、跨进程缓存或通用隐私保护。</p><p><a href="report.json">全部结果</a> · <a href="dynamic.json">动态见证</a> · <a href="plan.json">输入与源码冻结</a></p>'
    (Path(output)/"index.html").write_text(body, encoding="utf-8")


def network_audit():
    counts = {"loopback_connections": 0, "external_attempts_blocked": 0}
    def audit(event, values):
        if event == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                counts["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            counts["loopback_connections"] += 1
    return counts, audit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("examples/privacy_semantics_v1"))
    parser.add_argument("--story-id")
    parser.add_argument("--task-id")
    parser.add_argument("--model-root", type=Path, default=Path(".runtime/github_ner"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    network, audit = network_audit()
    sys.addaudithook(audit)
    report = run(args.corpus, args.output, args.model_root, story_id=args.story_id, task_id=args.task_id,
                 progress=lambda row: print(json.dumps(row), flush=True))
    save(args.output / "network_audit.json", network)
    print(json.dumps({"output": str(args.output), "status": report["status"], "encoder_calls": report["total_physical_encoder_calls"],
                      "run_measured_wall_seconds": report["run_measured_wall_seconds"],
                      "model_answer_calls": 0, "new_api_cost_cny": 0, "network": network}, ensure_ascii=False))
