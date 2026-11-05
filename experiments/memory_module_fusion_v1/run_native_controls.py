"""Bounded native followup of two development-locked strong BM25 controls.

First 1..4 reserved cases, all three current permission states, two fixed arms.
No proof index, learned local reranker, automatic retry, resume or gold lookup.
Importing this module or using --help makes no SDK/model call.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import secrets
import time

from .strong_controls import select_control, ARMS as CONTROL_DEFINITIONS, DEV_SELECTION_RULE
from .context_adapter import prepare_sources, deliver
from experiments.revocation_grouping_v1.lifecycle_host import LifecycleHost, save
from experiments.revocation_grouping_v1.lifecycle_runner import target_messages
from experiments.revocation_grouping_v1.sdk_adapter import FlashSDKClient, usage_costs
from experiments.revocation_prefix_v1.cache_qualification import native_isolation


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_OUTPUT = REPO / "results/memory_module_fusion_v1/hotpot-native-strong-20261105-v1"
LOCK = REPO / "results/memory_module_fusion_v1/strong-controls-20261105-v1/dev_based_followup_lock.json"
EXPECTED_ARMS = ("authorized_parent_bm25_top4", "authorized_parent_bm25_top3")
ORDER_SEED = 2026110561
MAX_OUTPUT_TOKENS = 384
CASE_BUDGET_CNY = "3"
MAX_JOBS_PER_CASE = 6


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashes():
    # This followup owns its manifest. Main-run CODE_FILES/frozen engine and
    # existing results are neither edited nor imported for mutation.
    paths = [Path(__file__), HERE / "strong_controls.py", HERE / "context_adapter.py",
        REPO / "experiments/revocation_grouping_v1/lifecycle_host.py",
        REPO / "experiments/revocation_grouping_v1/lifecycle_runner.py",
        REPO / "experiments/revocation_grouping_v1/retrieval_baseline.py",
        REPO / "experiments/revocation_grouping_v1/sdk_adapter.py",
        REPO / "experiments/revocation_grouping_v1/dsh_group_guard.mjs",
        REPO / "experiments/permission_context_v1/authorized_expansion.py",
        REPO / "experiments/revocation_prefix_v1/cache_qualification.py", LOCK]
    return {str(path.resolve().relative_to(REPO)): sha(path) for path in paths}


def build_plan(case_count):
    """Read public inputs and the prior development arm lock; no client created."""
    if type(case_count) is not int or case_count not in (1, 2, 3, 4):
        raise ValueError("fixed_case_count_must_be_1_to_4")
    lock = json.loads(LOCK.read_bytes())
    arms = tuple(lock.get("selected_arms", ()))
    if (arms != EXPECTED_ARMS or lock.get("selection_split") != "development"
            or lock.get("selection_rule") != DEV_SELECTION_RULE
            or lock.get("reserved_results_used") is not False):
        raise ValueError("prior_development_strong_control_lock_changed")
    if lock.get("fixed_arm_definitions") != CONTROL_DEFINITIONS:
        raise ValueError("locked_strong_control_definitions_changed")
    data = HERE / "data_hotpot"
    public = [json.loads(line) for line in (data / "cases.public.jsonl").read_bytes().splitlines() if line.strip()]
    reserved = [case for case in public if case["split"] == "reserved"]
    if len(reserved) != 16 or [case["case_id"] for case in reserved] != sorted(case["case_id"] for case in reserved):
        raise ValueError("fixed_lexicographic_reserved_partition_changed")
    cases = reserved[:case_count]
    schedules = json.loads((data / "schedules.json").read_bytes())
    target_prompt = json.loads((REPO / "experiments/revocation_grouping_v1/workload_contract_long.json").read_bytes())["target_prompt"]
    rng = random.Random(ORDER_SEED)
    plans, seen_nonces = [], set()
    for case in cases:
        events = schedules[case["case_id"]]
        if len(events) != 3 or [event["time"] for event in events] != [0, 1, 2]:
            raise ValueError("fixed_three_policy_states_required")
        source_ids = {source["source_id"] for source in case["sources"]}
        orders = []
        for event in events:
            if len(set(event["allowed"])) != len(event["allowed"]) or set(event["allowed"]) - source_ids:
                raise ValueError("invalid_current_policy_view")
            order = list(arms)
            rng.shuffle(order)
            orders.append({"event": event, "arm_order": order})
        nonces = {arm: secrets.token_hex(32) for arm in arms}
        if any(len(nonce) != 64 or nonce in seen_nonces for nonce in nonces.values()) or len(set(nonces.values())) != 2:
            raise ValueError("qualification_nonce_collision_or_length_mismatch")
        seen_nonces.update(nonces.values())
        plans.append({"case_id": case["case_id"], "events": orders, "nonces": nonces})
    return cases, plans, arms, target_prompt, lock


def prepare_control(case, arm, host, nonce, target_prompt):
    """Current view -> fixed BM25 IDs -> whole-source adapter; entirely local."""
    started = time.perf_counter()
    current = host.allowed_sources()
    epoch = host.revision
    selected, retrieval = select_control(case["question"], current, case["hierarchy"], arm)
    prepared = prepare_sources(host, selected, current_sources=current, strategy="child_only",
                               expected_epoch=epoch, max_source_bytes=None)
    if set(prepared.source_ids) != set(selected):
        raise AssertionError("safe_adapter_changed_control_selection")
    trace = {"arm": arm, "features": {"parent_ranking": True, "proof": False,
        "rerank": False, "expansion": False}, "initialization_ms": 0.0,
        "maintenance": None, "cache_reuse": None, "seed_source_ids": selected,
        "retrieval": retrieval, "total_prepare_ms": (time.perf_counter() - started) * 1000,
        "prepared": asdict(prepared), "no_hard_byte_cap": True}
    messages = target_messages(prepared.context,
        [{"question_id": case["case_id"], "question": case["question"]}], {"target_prompt": target_prompt})
    messages[0]["content"] = f"Qualification tag: {nonce}\n" + messages[0]["content"]
    return prepared, trace, messages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--case-count", type=int, default=4, choices=[1, 2, 3, 4])
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("fresh_output_required_no_resume_or_retry")
    cases, plans, arms, target_prompt, lock = build_plan(args.case_count)
    frozen = hashes()
    data = HERE / "data_hotpot"
    data_hashes = {name: sha(data / name) for name in ("cases.public.jsonl", "evaluation_only.json", "schedules.json")}
    output.mkdir(parents=True, exist_ok=False)
    save(output / "manifest.json", {"stage": "development_locked_strong_simple_control_native_followup",
        "case_selection": "first four lexicographic reserved IDs; optional fixed prefix of 1..4",
        "cases": cases, "plans": plans, "arms": arms, "config": {arm: CONTROL_DEFINITIONS[arm] for arm in arms},
        "seed": ORDER_SEED, "code_hashes": frozen, "data_hashes": data_hashes,
        "development_lock": lock, "development_lock_path": str(LOCK), "reserved_outcomes_used_for_arm_selection": False,
        "max_calls": len(cases) * 3 * len(arms), "max_output_tokens": MAX_OUTPUT_TOKENS,
        "budget_cap_cny_per_case": CASE_BUDGET_CNY, "max_jobs_per_case": MAX_JOBS_PER_CASE,
        "nonce_chars": 64, "nonce_scope": "independent per case and arm; fixed across all three states",
        "target_prompt": target_prompt, "all_initial_and_priming_calls_counted": True,
        "automatic_retry": False, "cost_is_supplier_bill": False, "human_review": None,
        "local_learned_ranker": False, "proof_index": False, "byte_cap": None,
        "independent_units": "Hotpot questions; three policy states are repeated observations"})
    (output / "run_native_controls_snapshot.py").write_bytes(Path(__file__).read_bytes())
    status = {"status": "running", "registered": 0, "attempted": 0, "completed": 0,
        "max_calls": len(cases) * 3 * len(arms), "automatic_retry": False, "cost_is_supplier_bill": False}
    counter = 0
    try:
        safe = FlashSDKClient(output / "metadata.private", budget_cap_cny=".5", max_jobs=1).preflight()
        save(output / "metadata_safe.json", safe)
        for case, plan in zip(cases, plans):
            case_root = output / case["case_id"]
            client = FlashSDKClient(case_root / "sdk.private", budget_cap_cny=CASE_BUDGET_CNY,
                                    max_jobs=MAX_JOBS_PER_CASE)
            hosts = {arm: LifecycleHost(case["sources"], case_root / "hosts" / arm) for arm in arms}
            for step, entry in enumerate(plan["events"]):
                event = entry["event"]
                for arm in entry["arm_order"]:
                    counter += 1
                    status["registered"] = counter
                    host = hosts[arm]
                    row = {"call_index": counter, "case_id": case["case_id"], "question_id": case["case_id"],
                        "arm": arm, "time": event["time"], "step": step, "allowed": event["allowed"],
                        "selected": [], "context": None, "context_sha256": None, "source_bytes": None,
                        "messages": None, "trace": {}, "host_root": str(host.root),
                        "receipt": None, "output": None, "status": "pending"}
                    try:
                        if hashes() != frozen or data_hashes != {name: sha(data / name) for name in data_hashes}:
                            raise ValueError("frozen_followup_code_lock_or_data_changed")
                        host.set_permissions(event["allowed"])
                        prepared, trace, messages = prepare_control(case, arm, host, plan["nonces"][arm], target_prompt)
                        row.update(selected=list(prepared.source_ids), context=prepared.context,
                            context_sha256=prepared.context_sha256, source_bytes=prepared.source_bytes,
                            context_bytes=len(prepared.context.encode("utf-8")), messages=messages, trace=trace)
                        save(output / "inputs" / f"{counter:04d}.json", row)
                        def send():
                            status["attempted"] += 1
                            return client.generate(messages, f"strong-control-{counter:04d}", MAX_OUTPUT_TOKENS, "target")
                        started = time.perf_counter()
                        answer = deliver(prepared, host, messages, send)
                        row.update(output=answer["output"], receipt=answer["receipt"],
                                   target_wall_ms=(time.perf_counter() - started) * 1000)
                        tokens, peak, cache = usage_costs(answer["receipt"]["usage"])
                        row.update(tokens=tokens, estimated_peak_cost_cny=str(peak),
                            estimated_cache_aware_peak_cost_cny=str(cache) if cache is not None else None,
                            cost_is_supplier_bill=False)
                        if step == 0:
                            row["initial_cache_isolation"] = native_isolation(answer["receipt"], messages, plan["nonces"][arm])
                        row["status"] = "completed"
                        status["completed"] += 1
                    except BaseException as error:
                        row.update(status="failed_no_retry", failure_class=type(error).__name__)
                        raise
                    finally:
                        save(output / "rows" / f"{counter:04d}.json", row)
                        save(output / "progress" / f"{counter:04d}.json", status)
                    print(json.dumps({"completed": status["completed"], "max_calls": status["max_calls"],
                        "case_id": case["case_id"], "arm": arm, "time": event["time"]}), flush=True)
        status["status"] = "completed"
    except BaseException as error:
        status.update(status="failed_no_retry", failure_class=type(error).__name__)
        raise
    finally:
        # This immutable name is written exactly once, including preflight or
        # preparation failures. Earlier checkpoints always use distinct names.
        save(output / "status.json", status)
    print(json.dumps(status))


if __name__ == "__main__":
    main()
