"""One bounded, deterministic, model-free B/F mechanical comparison.

Run as a module; never imports production data, invokes models or reads old runs.
The scan baseline is an independent oracle, not a strongest performance claim.
An independently implemented indexed queue recomputation reuses static indexes.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
import traceback
import tracemalloc

from .bf_port import (BfMaterialization, DeliveryKey, FullRecomputeBaseline,
                      GroundRule, UpdateResult, delivery_projection)


VERSION = "bounded_bf_mechanical_comparison_v1"
REPO = Path(__file__).resolve().parents[2]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class IndexedRecomputeBaseline:
    """Independent from-scratch queue closure, reusing only static body indexes.

    Unique body atoms have one pending counter each. A fresh closure/counter
    vector is built for every effective base update. No B/F proof or previous
    derived fact seeds recomputation. Identical base sets reuse the valid result.
    """
    def __init__(self, base_facts, rules):
        started = time.perf_counter_ns()
        self._base = set(base_facts)
        self._rules = tuple(sorted(set(rules), key=lambda r: (r.head, r.body)))
        self._heads = tuple(rule.head for rule in self._rules)
        self._lengths = tuple(len(set(rule.body)) for rule in self._rules)
        self._index = defaultdict(list)
        for index, rule in enumerate(self._rules):
            for atom in sorted(set(rule.body)):
                self._index[atom].append(index)
        self._materialized, work = self._recompute()
        work["static_index_entries_built"] = sum(map(len, self._index.values()))
        self._last_result = self._result("init", set(), started, work, 0, len(self._base), 0, len(self._base))

    @property
    def facts(self):
        return frozenset(self._materialized)

    @property
    def base_facts(self):
        return frozenset(self._base)

    @property
    def last_result(self):
        return self._last_result

    def _recompute(self):
        pending = list(self._lengths)
        closure = set(self._base)
        queue = deque(sorted(self._base))
        work = {"counter_resets": len(pending), "queue_facts": 0,
                "body_index_edges": 0, "forward_derivations": 0,
                "static_index_entries_built": 0}
        while queue:
            atom = queue.popleft()
            work["queue_facts"] += 1
            for index in self._index.get(atom, ()):
                work["body_index_edges"] += 1
                pending[index] -= 1
                if pending[index] == 0:
                    work["forward_derivations"] += 1
                    head = self._heads[index]
                    if head not in closure:
                        closure.add(head)
                        queue.append(head)
        return closure, work

    def _result(self, op, before, started, work, nd, ni, ed, ei):
        snapshot = frozenset(self._materialized)
        added, removed = frozenset(self._materialized - before), frozenset(before - self._materialized)
        return UpdateResult(op, snapshot, added, removed, len(self._base), nd, ni, ed, ei,
                            time.perf_counter_ns() - started, dict(work))

    def update(self, *, delete=(), insert=()):
        started = time.perf_counter_ns()
        # Same accepted finite ground program, independent explicit-set update.
        if type(delete) not in {list, tuple, set, frozenset} or type(insert) not in {list, tuple, set, frozenset}:
            raise ValueError("invalid_finite_update")
        removed, added = set(delete), set(insert)
        before = set(self._materialized)
        new_base = (self._base - removed) | added
        ed, ei = (removed & self._base) - added, added - self._base
        if new_base != self._base:
            self._base = new_base
            self._materialized, work = self._recompute()
        else:
            work = {"counter_resets": 0, "queue_facts": 0, "body_index_edges": 0,
                    "forward_derivations": 0, "static_index_entries_built": 0}
        self._last_result = self._result("update", before, started, work, len(removed), len(added), len(ed), len(ei))
        return self._last_result


@dataclass(frozen=True)
class Event:
    name: str
    delete: tuple[str, ...] = ()
    insert: tuple[str, ...] = ()
    global_deny_all: bool = False
    expected_visible: tuple[str, ...] | None = None
    must_present: tuple[str, ...] = ()
    must_absent: tuple[str, ...] = ()


@dataclass(frozen=True)
class Scenario:
    name: str
    base: frozenset[str]
    rules: tuple[GroundRule, ...]
    targets: dict
    key_names: dict
    always_blocked: frozenset
    events: tuple[Event, ...]


def boundary_scenario():
    r = lambda h, *b: GroundRule(h, b)
    rules = (r("copy-1", "source-A"), r("copy-2", "copy-1"),
             r("copied-fact", "copy-1"), r("copied-fact", "copy-2"),
             r("alternative", "source-A"), r("alternative", "source-B"),
             r("joint", "source-A", "source-B"), r("cycle-u", "source-A"),
             r("cycle-v", "cycle-u"), r("cycle-u", "cycle-v"),
             r("alice-allowed", "alice-grant-old"), r("alice-allowed", "alice-grant-new"))
    keys = {
        "alice_alt": DeliveryKey("alice", "agent-a", "read", "alternative", "local"),
        "bob_alt": DeliveryKey("bob", "agent-b", "read", "alternative", "local"),
        "alice_joint": DeliveryKey("alice", "agent-a", "read", "joint", "local"),
        "alice_copy": DeliveryKey("alice", "agent-a", "read", "copied-fact", "local"),
        "wrong_agent": DeliveryKey("alice", "agent-other", "read", "alternative", "local"),
        "export": DeliveryKey("alice", "agent-a", "export", "alternative", "cloud"),
    }
    targets = {
        keys["alice_alt"]: {"alternative", "alice-allowed"},
        keys["bob_alt"]: {"alternative", "bob-grant"},
        keys["alice_joint"]: {"joint", "alice-allowed"},
        keys["alice_copy"]: {"copied-fact", "alice-allowed"},
        keys["wrong_agent"]: {"alternative", "wrong-agent-grant"},
        keys["export"]: {"alternative", "export-grant"},
    }
    return Scenario("boundary_contract", frozenset({"source-A", "source-B", "alice-grant-old", "bob-grant", "export-grant"}),
        rules, targets, {key: name for name, key in keys.items()}, frozenset({keys["export"]}), (
        Event("initial", expected_visible=("alice_alt", "bob_alt", "alice_joint", "alice_copy")),
        Event("revoke_source_A_independent_B_retained", delete=("source-A",), expected_visible=("alice_alt", "bob_alt"),
              must_present=("alternative",), must_absent=("copied-fact", "joint", "cycle-u", "cycle-v")),
        Event("revoke_alice_grant", delete=("alice-grant-old",), expected_visible=("bob_alt",)),
        Event("new_alice_grant_restores_fresh_access", insert=("alice-grant-new",), expected_visible=("alice_alt", "bob_alt")),
        Event("revoke_B_all_content_unsupported", delete=("source-B",), expected_visible=(), must_absent=("alternative",)),
        Event("new_source_A_support", insert=("source-A",), expected_visible=("alice_alt", "bob_alt", "alice_copy")),
        Event("global_obligation_overrides_all_OR", global_deny_all=True, expected_visible=()),
        Event("clear_global_obligation", expected_visible=("alice_alt", "bob_alt", "alice_copy")),
        Event("revoke_A_again_removes_unrooted_cycle", delete=("source-A",), expected_visible=(), must_absent=("cycle-u", "cycle-v")),
        Event("insert_B_only", insert=("source-B",), expected_visible=("alice_alt", "bob_alt"), must_absent=("cycle-u", "cycle-v")),
        Event("revoke_last_B", delete=("source-B",), expected_visible=()),
    ))


def sized_scenario(groups):
    base, rules = {"reader-grant"}, []
    targets, names = {}, {}
    for i in range(groups):
        p = f"g{i:04d}:"
        a, b = p + "source-A", p + "source-B"
        base.update((a, b))
        rules.extend((GroundRule(p + "copy-1", (a,)), GroundRule(p + "copy-2", (p + "copy-1",)),
                      GroundRule(p + "alt", (a,)), GroundRule(p + "alt", (b,)),
                      GroundRule(p + "joint", (a, b)), GroundRule(p + "cycle-u", (a,)),
                      GroundRule(p + "cycle-v", (p + "cycle-u",)), GroundRule(p + "cycle-u", (p + "cycle-v",))))
        previous = p + "alt"
        for j in range(6):
            head = p + f"tail-{j}"
            rules.append(GroundRule(head, (previous,)))
            previous = head
        key = DeliveryKey("reader", "agent-r", "read", p + "tail-5", "local")
        targets[key], names[key] = {previous, "reader-grant"}, p + "answer"
    all_a = tuple(f"g{i:04d}:source-A" for i in range(groups))
    all_b = tuple(f"g{i:04d}:source-B" for i in range(groups))
    events = (Event("initial"), Event("single_A_delete", delete=(all_a[0],)),
              Event("single_B_delete", delete=(all_b[0],)), Event("single_A_insert", insert=(all_a[0],)),
              Event("all_A_delete", delete=all_a), Event("all_A_insert", insert=all_a),
              Event("all_roots_delete", delete=all_a + all_b), Event("all_B_insert", insert=all_b),
              Event("all_A_restore", insert=all_a))
    return Scenario(f"sized_{groups}_groups", frozenset(base), tuple(rules), targets, names, frozenset(), events)


def retained_bytes(value, seen=None):
    """Python getsizeof graph estimate; excludes allocator/native/RSS overhead."""
    if seen is None:
        seen = set()
    marker = id(value)
    if marker in seen:
        return 0
    seen.add(marker)
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(retained_bytes(k, seen) + retained_bytes(v, seen) for k, v in value.items())
    elif isinstance(value, (list, tuple, set, frozenset, deque)):
        size += sum(retained_bytes(item, seen) for item in value)
    elif hasattr(value, "__dict__"):
        size += retained_bytes(vars(value), seen)
    return size


def measure(engine_type, engine, scenario, event, revision):
    entire_start = time.perf_counter_ns()
    tracemalloc.start()
    workload_start = time.perf_counter_ns()
    if engine is None:
        engine = engine_type(scenario.base, scenario.rules)
        result = engine.last_result
        kernel_elapsed = result.elapsed_ns
        work = result.work
    elif event.delete or event.insert:
        result = engine.update(delete=event.delete, insert=event.insert)
        kernel_elapsed, work = result.elapsed_ns, result.work
    else:
        result, kernel_elapsed, work = None, 0, {"gate_only_event": 1}
    materialized = engine.facts
    blocked = set(scenario.targets) if event.global_deny_all else scenario.always_blocked
    visible = delivery_projection(materialized, scenario.targets, globally_forbidden=blocked)
    # Actual shared integrity/fresh-preparation work on synthetic IDs, not a native
    # authorization/signature benchmark or a production RestorationMap.
    state_sha = digest(sorted(engine.base_facts))
    fresh_packet = canonical({"revision": revision, "source_state_sha256": state_sha,
                              "selected": [asdict(key) for key in sorted(visible)]})
    packet_sha = hashlib.sha256(fresh_packet).hexdigest()
    materialized_sha = digest(sorted(materialized))
    workload_elapsed = time.perf_counter_ns() - workload_start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    retained = retained_bytes(engine)
    observed_elapsed = time.perf_counter_ns() - entire_start
    return engine, materialized, visible, {
        "kernel_elapsed_ns": kernel_elapsed, "workload_total_ns": workload_elapsed,
        "predeclared_repetitions": 1,
        "workload_min_ns": workload_elapsed, "workload_median_ns": workload_elapsed,
        "instrumented_total_including_memory_measurement_ns": observed_elapsed,
        "tracemalloc_peak_allocated_bytes_this_operation": peak,
        "retained_python_getsizeof_graph_estimate_bytes": retained,
        "materialized_count": len(materialized), "materialized_sha256": materialized_sha,
        "explicit_count": len(engine.base_facts), "visible_count": len(visible),
        "fresh_mechanical_packet_bytes": len(fresh_packet), "fresh_packet_sha256": packet_sha,
        "work": work,
        "net_added_count": len(result.added) if result else 0,
        "net_removed_count": len(result.removed) if result else 0,
    }


def scenario_manifest(scenario):
    return {"name": scenario.name, "base_count": len(scenario.base), "rules": len(scenario.rules),
            "ground_body_atoms": sum(len(rule.body) for rule in scenario.rules),
            "targets": len(scenario.targets), "events": [asdict(e) for e in scenario.events],
            "base_sha256": digest(sorted(scenario.base)),
            "rule_sha256": digest([asdict(r) for r in scenario.rules])}


def run(output):
    output.mkdir(parents=True, exist_ok=False)
    scenarios = (boundary_scenario(), sized_scenario(16), sized_scenario(128))
    sources = {str(p.relative_to(REPO)).replace("\\", "/"): file_sha(p) for p in (
        Path(__file__), REPO / "experiments/algorithm_ports_20261029/bf_port.py",
        REPO / "tests/test_algorithm_ports_bf.py")}
    plan = {"version": VERSION, "created_utc": datetime.now(timezone.utc).isoformat(),
            "sources": sources, "scenarios": [scenario_manifest(s) for s in scenarios],
            "repetitions": 1, "random_benchmark_graphs": 0,
            "model_calls": 0, "old_material_reads": 0,
            "engines": ["bf", "scan_full_recompute_oracle", "indexed_queue_full_recompute"],
            "timing": "Single instrumented paired pass; totals include init/indexes, validation, closure snapshots, shared final gate, state hashing and fresh mechanical packet. Native I/O/authentication/signing/production reprepare are not measured.",
            "memory": "Per-operation tracemalloc peak and recursive Python getsizeof estimate, not RSS.",
            "claim_limit": "Finite declared ground-logic correctness; no native ACL, semantic independence, QA or general performance claim."}
    write_json(output / "plan.json", plan)
    rows, summaries = [], []
    constructors = {"bf": BfMaterialization, "scan_full_recompute_oracle": FullRecomputeBaseline,
                    "indexed_queue_full_recompute": IndexedRecomputeBaseline}
    names = tuple(constructors)
    for scenario in scenarios:
        engines = dict.fromkeys(names)
        totals = {name: {"workload_total_ns": 0, "instrumented_total_ns": 0,
                         "kernel_elapsed_ns": 0, "max_traced_peak_bytes": 0,
                         "max_retained_estimate_bytes": 0, "work": {}} for name in names}
        for revision, event in enumerate(scenario.events):
            observed, visible, measurements = {}, {}, {}
            order = names[revision % 3:] + names[:revision % 3]
            for name in order:
                engines[name], observed[name], visible[name], measurements[name] = measure(
                    constructors[name], engines[name], scenario, event, revision)
                item, total = measurements[name], totals[name]
                total["workload_total_ns"] += item["workload_total_ns"]
                total["instrumented_total_ns"] += item["instrumented_total_including_memory_measurement_ns"]
                total["kernel_elapsed_ns"] += item["kernel_elapsed_ns"]
                total["max_traced_peak_bytes"] = max(total["max_traced_peak_bytes"], item["tracemalloc_peak_allocated_bytes_this_operation"])
                total["max_retained_estimate_bytes"] = max(total["max_retained_estimate_bytes"], item["retained_python_getsizeof_graph_estimate_bytes"])
                for counter, value in item["work"].items():
                    total["work"][counter] = total["work"].get(counter, 0) + value
            oracle = observed["scan_full_recompute_oracle"]
            oracle_visible = visible["scan_full_recompute_oracle"]
            correct = all(observed[n] == oracle and visible[n] == oracle_visible for n in names)
            boundary_names = {scenario.key_names[k] for k in oracle_visible}
            declared = (event.expected_visible is None or boundary_names == set(event.expected_visible))
            declared = declared and set(event.must_present) <= oracle and not (set(event.must_absent) & oracle)
            row = {"scenario": scenario.name, "event": event.name, "revision": revision,
                   "engine_order": order, "all_materialized_equal": correct,
                   "declared_boundary_invariants_pass": declared, "measurements": measurements}
            rows.append(row)
            # Preserve progress even if this first fixed pass encounters a failure.
            write_json(output / "progress.json", {"closed": False, "rows": rows})
            if not correct or not declared:
                write_json(output / "first_failure.json", {"row": row,
                    "synthetic_materialized": {n: sorted(observed[n]) for n in names},
                    "synthetic_visible_names": {n: sorted(scenario.key_names[k] for k in visible[n]) for n in names}})
                raise AssertionError("first_mechanical_mismatch_preserved")
        summaries.append({"scenario": scenario_manifest(scenario), "states": len(scenario.events),
                          "all_states_equal": True, "engine_totals": totals,
                          "repeat_statistics": {n: {"n": 1, "minimum_total_workload_ns": t["workload_total_ns"],
                              "median_total_workload_ns": t["workload_total_ns"]} for n, t in totals.items()}})
    report = {"version": VERSION, "status": "completed", "all_comparisons_equal": True,
              "declared_boundary_invariants_pass": True, "scenarios": summaries, "rows": rows,
              "states_compared": len(rows), "engine_state_observations": 3 * len(rows),
              "model_calls": 0, "old_sealed_data_reads": 0, "first_failures": 0,
              "repetitions": 1, "sources": sources, "plan_sha256": file_sha(output / "plan.json"),
              "limits": ["mechanical host-declared ground rules only", "single instrumented pass; timings are not robust speed estimates",
                         "scan oracle is not strongest performance baseline", "indexed queue baseline reuses static dependencies",
                         "native authentication, online ACL/revocation and production reprepare not benchmarked",
                         "independent provenance and global obligation are declared by the shared trusted fixture, not inferred"]}
    write_json(output / "results.json", report)
    lines = ["# B/F 有界机械更新对照", "", "三个自编确定性图，单次带测量开销的配对执行；无模型、旧数据或客户端。", "",
             f"正确性：{len(rows)}/{len(rows)}状态与独立全量最小不动点及索引队列重算一致；声明的边界约束全部通过。", "",
             "| 场景 | 状态 | B/F总工作时(ms) | 队列全重算(ms) | 全扫oracle(ms) |", "|---|---:|---:|---:|---:|"]
    for entry in summaries:
        totals = entry["engine_totals"]
        lines.append(f"| {entry['scenario']['name']} | {entry['states']} | {totals['bf']['workload_total_ns']/1e6:.3f} | {totals['indexed_queue_full_recompute']['workload_total_ns']/1e6:.3f} | {totals['scan_full_recompute_oracle']['workload_total_ns']/1e6:.3f} |")
    lines += ["", "总工作时包括初始化／索引、输入校验、维护与快照、共同最终门、状态哈希及新的机械ID包准备；同时另存包含内存测量开销的总时长。工作量和内存字段见JSON。", "",
              "全扫实现用于独立正确性oracle。复用静态依赖索引的队列从头闭包是额外性能基线；本次单遍计时不能证明B/F普遍更快。", "",
              "边界图检查独立B支持保留、A副本共同祖先、AND／OR、用户与Agent／操作／目的地隔离、撤权后新grant恢复、全局禁止优先和无根循环删除。小／中图均含替代、合取、副本、循环与链，含单点及全根删除／插入。", "",
              "这是给定受信ground合同的机械效果，不是自然语言来源独立性、真实问答成功、原生ACL或论文创新证明。主线程独立的handoff试验未在此重复。", ""]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    write_json(output / "progress.json", {"closed": True, "rows": rows})
    return {"status": "completed", "states": len(rows), "all_equal": True,
            "results_sha256": file_sha(output / "results.json"),
            "summary_totals": {s["scenario"]["name"]: {n: t["workload_total_ns"] for n, t in s["engine_totals"].items()} for s in summaries}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    allowed = (REPO / "results/algorithm_ports_20261029").resolve()
    if output == allowed or allowed not in output.parents:
        raise ValueError("output_must_be_new_algorithm_result_subdirectory")
    if output.exists():
        raise FileExistsError("preserve_previous_attempt_use_new_output_directory")
    started = datetime.now(timezone.utc).isoformat()
    wall_started = time.perf_counter_ns()
    try:
        summary = run(output)
        write_json(output / "execution_receipt.json", {"started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(), "status": "completed",
            "python_version": platform.python_version(), "model_calls": 0,
            "runner_elapsed_ns": time.perf_counter_ns() - wall_started, "summary": summary})
        print(json.dumps(summary, sort_keys=True))
    except Exception as error:
        if output.is_dir() and not (output / "execution_receipt.json").exists():
            write_json(output / "execution_receipt.json", {"started_utc": started,
                "finished_utc": datetime.now(timezone.utc).isoformat(), "status": "failed",
                "exception_type": type(error).__name__, "traceback": traceback.format_exc(), "model_calls": 0})
        raise


if __name__ == "__main__":
    main()
