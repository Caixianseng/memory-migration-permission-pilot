"""Bounded offline support-index feasibility benchmark; no model/network calls.

Fixtures are explicitly synthetic complexity cases, including declared independent
copies of complete identical source text. They are not evidence of natural corpus
duplication. No future update is passed to any evaluated controller.

The independent full oracle uses integer-bitset proofs and synchronous fixed-point
rounds, unlike SupportIndex's frozenset/in-place implementation. The independent
acyclic counter has the weaker truth-only contract and cannot render witnesses.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import platform
import sqlite3
import statistics
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from .support_index import SupportIndex


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def text_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fixture(n, cyclic):
    sources, leaves, rules = [], [], []
    sid = lambda number: f"s{number:05d}"
    for number in range(n):
        block, local = divmod(number, 32)
        # Exactly one declared independent copy per 32-source block, including
        # the title/context. All other complete source texts are distinct.
        origin = block * 32 if local == 31 else number
        text = (f"Title: synthetic document {origin:05d}\n"
                f"Verified literal evidence for object {origin:05d}: code V{origin:05d}. "
                "This source is a synthetic complexity fixture.")
        source = {"id": sid(number), "text": text, "version": 1}
        fact = "exact:" + text_hash(text)
        span = {"fact_id": fact, "source_id": sid(number), "start": 0, "end": len(text),
                "source_version": "1", "source_sha256": text_hash(text),
                "quote": text, "quote_sha256": text_hash(text)}
        identity = [sid(number), "1", span["source_sha256"], 0, len(text)]
        span["span_id"] = "witness:" + digest([fact] + identity)
        span["slot"] = number
        sources.append(source)
        leaves.append(span)
    for block in range(n // 32):
        unique = [leaves[block * 32 + offset]["fact_id"] for offset in range(31)]
        levels = [unique]
        for depth in range(1, 4):
            level = []
            for offset in range(0, len(levels[-1]), 2):
                head = f"b{block}:layer{depth}:{offset // 2}"
                rules.append({"head": head, "body": levels[-1][offset:offset + 2]})
                level.append(head)
            levels.append(level)
        alternative = f"b{block}:alternative"
        rules.extend([{"head": alternative, "body": [levels[1][0]]},
                      {"head": alternative, "body": [levels[1][1]]},
                      {"head": f"b{block}:shared0", "body": [alternative, levels[2][1]]},
                      {"head": f"b{block}:shared1", "body": [alternative, levels[2][2]]},
                      {"head": f"b{block}:shared2", "body": [f"b{block}:shared0", levels[3][1]]}])
        if cyclic:
            rules.extend([{"head": f"b{block}:cycle_x", "body": [alternative]},
                          {"head": f"b{block}:cycle_y", "body": [f"b{block}:cycle_x"]},
                          {"head": f"b{block}:cycle_x", "body": [f"b{block}:cycle_y"]},
                          {"head": f"b{block}:unseeded", "body": [f"b{block}:unseeded"]}])
    across = lambda offset: [sid(block * 32 + offset) for block in range(n // 32)]
    transitions = [
        ("revoke_original_copy_available", [sid(0)], []),
        ("revoke_last_alternative", [sid(31)], []),
        ("regrant_original", [], [sid(0)]),
        ("regrant_independent_copy", [], [sid(31)]),
        ("revoke_two_and_inputs", [sid(2), sid(3)], []),
        ("revoke_shared_input_across_blocks", across(8), []),
        ("partial_and_regrant", [], [sid(2)]),
        ("restore_shared_and_inputs", [], [sid(3)] + across(8)),
        ("revoke_contiguous_four", [sid(number) for number in range(16, 20)], []),
        ("revoke_originals_keep_copies", across(0), []),
        ("restore_contiguous_four", [], [sid(number) for number in range(16, 20)]),
        ("revoke_copies_remove_grounding", across(31), []),
        ("restore_original_grounding", [], across(0)),
        ("restore_all_copies", [], across(31)),
        ("revoke_two_inputs_each_block", across(4) + across(12), []),
        ("restore_all_sources", [], across(4) + across(12)),
    ]
    return {"case_id": f"synthetic-{n}-{'cyclic' if cyclic else 'acyclic'}",
            "n_sources": n, "cyclic": cyclic, "declared_exact_copies": n // 32,
            "sources": sources, "leaves": leaves, "rules": rules,
            "updates": [{"epoch": epoch, "label": label, "revoke": revoke, "grant": grant}
                        for epoch, (label, revoke, grant) in enumerate(transitions, 1)]}


class OracleInputs:
    """Build independently validated immutable inputs without using index caches."""

    def __init__(self, data):
        self.sources = {source["id"]: dict(source) for source in data["sources"]}
        self.leaves = [dict(leaf) for leaf in data["leaves"]]
        self.rules = [(rule["head"], tuple(rule["body"])) for rule in data["rules"]]
        self.facts = {leaf["fact_id"] for leaf in self.leaves}
        self.facts.update(head for head, _ in self.rules)
        self.facts.update(fact for _, body in self.rules for fact in body)
        for leaf in self.leaves:
            source = self.sources[leaf["source_id"]]
            quote = source["text"][leaf["start"]:leaf["end"]]
            if (not quote or quote != leaf["quote"] or text_hash(source["text"]) != leaf["source_sha256"]
                    or text_hash(quote) != leaf["quote_sha256"] or canonical(source["version"]) != leaf["source_version"]):
                raise AssertionError("Invalid independent oracle input binding")

    def live_leaves(self, allowed, ops):
        for leaf in self.leaves:
            ops["span_checks"] += 1
            if leaf["source_id"] in allowed:
                # Current immutable source snapshots are validated at init;
                # quote checking matches the module full-recompute contract.
                ops["quote_hash_checks"] += 1
                if text_hash(leaf["quote"]) != leaf["quote_sha256"]:
                    raise AssertionError("Corrupt quote")
                yield leaf


class FullProofOracle(OracleInputs):
    def run(self, allowed):
        ops = defaultdict(int)
        proofs = {fact: set() for fact in self.facts}
        for leaf in self.live_leaves(allowed, ops):
            proofs[leaf["fact_id"]].add(1 << leaf["slot"])
        while True:
            ops["rounds"] += 1
            candidates = {fact: set(value) for fact, value in proofs.items()}
            for head, body in self.rules:
                ops["rule_evaluations"] += 1
                ops["premise_checks"] += len(body)
                for combination in itertools.product(*(proofs[fact] for fact in body)):
                    union = 0
                    for proof in combination:
                        union |= proof
                    ops["proof_unions"] += 1
                    candidates[head].add(union)
            normalized = {}
            for fact, masks in candidates.items():
                kept = []
                for mask in sorted(masks, key=lambda value: (value.bit_count(), value)):
                    ops["proof_candidates"] += 1
                    if not any(previous & mask == previous for previous in kept):
                        kept.append(mask)
                normalized[fact] = set(kept)
            if normalized == proofs:
                return proofs, dict(ops)
            proofs = normalized


class AcyclicCounter(OracleInputs):
    def __init__(self, data):
        super().__init__(data)
        parents, children = defaultdict(set), defaultdict(set)
        self.by_head = defaultdict(list)
        for head, body in self.rules:
            self.by_head[head].append(body)
            parents[head].update(body)
            for fact in body:
                children[fact].add(head)
        degree = {fact: len(parents[fact]) for fact in self.facts}
        queue = deque(sorted(fact for fact, number in degree.items() if number == 0))
        self.order = []
        while queue:
            fact = queue.popleft()
            self.order.append(fact)
            for head in sorted(children[fact]):
                degree[head] -= 1
                if degree[head] == 0:
                    queue.append(head)
        if len(self.order) != len(self.facts):
            raise ValueError("truth-only counting baseline requires an acyclic graph")

    def run(self, allowed):
        ops = defaultdict(int)
        counts = dict.fromkeys(self.facts, 0)
        for leaf in self.live_leaves(allowed, ops):
            counts[leaf["fact_id"]] += 1
        for head in self.order:
            for body in self.by_head[head]:
                ops["rule_evaluations"] += 1
                ops["premise_checks"] += len(body)
                counts[head] += int(all(counts[fact] > 0 for fact in body))
        return {fact for fact, count in counts.items() if count}, dict(ops)


def timed(function, *args, **kwargs):
    started = time.perf_counter_ns()
    value = function(*args, **kwargs)
    return value, (time.perf_counter_ns() - started) / 1_000_000


def build_index(data, db_path):
    index = SupportIndex(data["sources"], db_path=db_path)
    for leaf in data["leaves"]:
        index.register_exact_span(leaf["source_id"], leaf["start"], leaf["end"], leaf["fact_id"],
                                  expected_quote=leaf["quote"])
    for rule in data["rules"]:
        index.add_rule(rule["head"], rule["body"])
    index.set_allowed([source["id"] for source in data["sources"]], epoch=0)
    return index


def masks_from_module(proofs, span_slots):
    result = {}
    for fact, witnesses in proofs.items():
        values = set()
        for witness in witnesses:
            mask = 0
            for span_id in witness:
                mask |= 1 << span_slots[span_id]
            values.add(mask)
        result[fact] = values
    return result


def module_incremental_proofs(index, span_slots):
    # Read the persisted cache without invoking/re-rendering/re-solving it. This
    # audit is outside every measured controller time.
    proofs = dict.fromkeys(index._facts, None)
    proofs = {fact: [] for fact in proofs}
    for row in index.connection.execute("SELECT fact_id,span_ids FROM support_proofs"):
        proofs[row["fact_id"]].append(json.loads(row["span_ids"]))
    return masks_from_module(proofs, span_slots)


def proof_record(proofs):
    return {fact: [hex(mask) for mask in sorted(masks)] for fact, masks in sorted(proofs.items())}


def measure_state(data, index, oracle, counter, allowed, epoch, label, incremental_ms, incremental_stats):
    (independent_proofs, independent_ops), independent_ms = timed(oracle.run, allowed)
    module_full, module_full_ms = timed(index.recompute_full)
    slots = {leaf["span_id"]: leaf["slot"] for leaf in data["leaves"]}
    audit_start = time.perf_counter_ns()
    cached_proofs = module_incremental_proofs(index, slots)
    module_full_proofs = masks_from_module(module_full["proofs"], slots)
    active = {fact for fact, proofs in independent_proofs.items() if proofs}
    checks = {"incremental_active_equals_independent": index.active_facts() == active,
              "incremental_minimal_proofs_equal_independent": cached_proofs == independent_proofs,
              "module_full_minimal_proofs_equal_independent": module_full_proofs == independent_proofs,
              "module_full_active_equals_independent": module_full["active_facts"] == active}
    audit_ms = (time.perf_counter_ns() - audit_start) / 1_000_000
    count_result = {"status": "not_applicable", "reason": "cyclic graph", "contract": "truth_only_no_witnesses"}
    if counter is not None:
        (count_active, count_ops), count_ms = timed(counter.run, allowed)
        checks["independent_count_active_equals_full_proofs"] = count_active == active
        count_result = {"status": "ok", "wall_ms": count_ms, "ops": count_ops,
                        "contract": "truth_only_no_witnesses"}
    if not all(checks.values()):
        raise AssertionError((data["case_id"], epoch, checks))
    return {"case_id": data["case_id"], "epoch": epoch, "label": label,
            "allowed_source_ids": sorted(allowed), "active_fact_count": len(active),
            "active_minimal_proof_count": sum(len(proofs) for proofs in independent_proofs.values()),
            "checks": checks, "incremental": {"wall_ms": incremental_ms, "ops": incremental_stats,
                "contract": "all_minimal_grounded_proofs_sqlite_persisted"},
            "module_full_recompute": {"wall_ms": module_full_ms, "ops": module_full["stats"],
                "contract": "all_minimal_grounded_proofs_read_only_shared_index"},
            "independent_full_recompute": {"wall_ms": independent_ms, "ops": independent_ops,
                "contract": "all_minimal_grounded_proofs_python_bitsets_no_sqlite"},
            "acyclic_counting": count_result, "proof_comparison_audit_ms": audit_ms,
            "minimal_proof_masks": proof_record(independent_proofs),
            "proof_state_sha256": digest(proof_record(independent_proofs))}


def case_summary(data, initializations, records):
    updates = records[1:]
    totals = {}
    for arm in ("incremental", "module_full_recompute", "independent_full_recompute", "acyclic_counting"):
        selected = [record[arm] for record in updates if "wall_ms" in record[arm]]
        if not selected:
            totals[arm] = {"status": "not_applicable", "contract": "truth_only_no_witnesses"}
            continue
        values = [record["wall_ms"] for record in selected]
        init_key = {"incremental": "sqlite_index_with_initial_state",
                    "independent_full_recompute": "independent_proof_inputs_and_initial_state",
                    "acyclic_counting": "independent_count_inputs_and_initial_state"}.get(arm)
        totals[arm] = {"updates_wall_ms": sum(values), "update_median_ms": statistics.median(values),
                       "update_max_ms": max(values), "initialization_key": init_key,
                       "initialization_plus_updates_ms":
                           initializations[init_key]["wall_ms"] + sum(values) if init_key else None}
    ratios = {}
    for baseline in ("module_full_recompute", "independent_full_recompute", "acyclic_counting"):
        paired = [record for record in updates if "wall_ms" in record[baseline]]
        if paired:
            ratios[baseline] = {
                "baseline_updates_ms_over_incremental_updates_ms":
                    sum(record[baseline]["wall_ms"] for record in paired) /
                    sum(record["incremental"]["wall_ms"] for record in paired),
                "incremental_faster_steps": sum(record["incremental"]["wall_ms"] < record[baseline]["wall_ms"]
                                                for record in paired), "paired_steps": len(paired),
                "same_contract": baseline != "acyclic_counting",
                "different_storage_or_representation": True}
    return {"case_id": data["case_id"], "n_sources": data["n_sources"],
            "n_rules": len(data["rules"]), "cyclic": data["cyclic"],
            "declared_synthetic_exact_copies": data["declared_exact_copies"],
            "update_count": len(updates), "all_checks_passed": all(all(record["checks"].values()) for record in records),
            "initializations": initializations, "totals": totals, "paired_update_comparisons": ratios}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New output directory; never overwritten")
    parser.add_argument("--storage", choices=("file", "memory"), default="file",
                        help="Explicitly separate durable SQLite commits from in-memory maintenance")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    start = time.perf_counter_ns()
    cases = [fixture(n, cyclic) for n in (32, 128, 512) for cyclic in (False, True)]
    own_path = Path(__file__).resolve()
    manifest = {"schema": "support-index-bounded-feasibility-v1", "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "platform": platform.platform(), "sqlite": sqlite3.sqlite_version,
        "script_sha256": text_hash(own_path.read_text(encoding="utf-8")),
        "frozen_core_sha256": text_hash(own_path.with_name("support_index.py").read_text(encoding="utf-8")),
        "fixture_sha256": digest(cases), "network_or_model_calls": 0,
        "sqlite_storage_mode": args.storage,
        "causal_contract": "Each method receives only the current allowed set and current epoch; no future transitions.",
        "measurement_contract": {
            "incremental": "End-to-end public set_allowed call including SQLite grant and proof writes.",
            "module_full": "Read-only full proof recompute using the already built shared SQLite index metadata.",
            "independent_full": "Fresh proof fixed point per state; independent integer-bitset algorithm; no SQLite persistence.",
            "counting": "Independently compiled DAG and support counts; truth only, no minimal proof enumeration or rendering.",
            "initialization": "Separate complete public index construction and independent baseline input compilation plus initial evaluation.",
            "scope": "One bounded local run, no statistical replication or natural-corpus-duplication claim."}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "fixtures.json").write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summaries = []
    with (output / "records.jsonl").open("x", encoding="utf-8") as records_file:
        for data in cases:
            (oracle, oracle_build_ms) = timed(FullProofOracle, data)
            allowed = {source["id"] for source in data["sources"]}
            (_, oracle_initial_ms) = timed(oracle.run, allowed)
            counter = None
            initializations = {"independent_proof_inputs_and_initial_state": {
                "wall_ms": oracle_build_ms + oracle_initial_ms, "input_build_ms": oracle_build_ms,
                "initial_evaluate_ms": oracle_initial_ms, "storage": "python_memory"}}
            if not data["cyclic"]:
                counter, count_build_ms = timed(AcyclicCounter, data)
                _, count_initial_ms = timed(counter.run, allowed)
                initializations["independent_count_inputs_and_initial_state"] = {
                    "wall_ms": count_build_ms + count_initial_ms, "input_build_ms": count_build_ms,
                    "initial_evaluate_ms": count_initial_ms, "storage": "python_memory", "contract": "truth_only_no_witnesses"}
            db_path = ":memory:" if args.storage == "memory" else output / (data["case_id"] + ".sqlite")
            index, index_build_ms = timed(build_index, data, db_path)
            initializations["sqlite_index_with_initial_state"] = {
                "wall_ms": index_build_ms, "initial_permission_update": index.last_stats,
                "storage": "sqlite_" + args.storage}
            records = [measure_state(data, index, oracle, counter, allowed, 0, "initial_all_allowed",
                                     index_build_ms, index.last_stats)]
            records[0]["kind"] = "initialization"
            records_file.write(canonical(records[0]) + "\n")
            records_file.flush()
            for update in data["updates"]:
                allowed.difference_update(update["revoke"])
                allowed.update(update["grant"])
                stats, elapsed = timed(index.set_allowed, allowed, epoch=update["epoch"])
                record = measure_state(data, index, oracle, counter, allowed, update["epoch"],
                                       update["label"], elapsed, stats)
                record["kind"] = "permission_update"
                record["current_delta"] = update
                records.append(record)
                records_file.write(canonical(record) + "\n")
                records_file.flush()
            index.close()
            summary = case_summary(data, initializations, records)
            summaries.append(summary)
            print(canonical({"case_id": data["case_id"], "all_checks_passed": summary["all_checks_passed"],
                             "initial_index_ms": index_build_ms, "totals": summary["totals"]}), flush=True)
    result = {"schema": manifest["schema"], "sqlite_storage_mode": args.storage,
              "all_checks_passed": all(case["all_checks_passed"] for case in summaries),
              "cases": summaries, "records": len(cases) * 17,
              "total_wall_ms": (time.perf_counter_ns() - start) / 1_000_000,
              "interpretation": "Ratios retain negative results; counting has a weaker contract and storage differs. Initialization costs are included separately and in lifecycle totals."}
    (output / "summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(canonical({"output": str(output), "all_checks_passed": result["all_checks_passed"], "records": result["records"]}))


if __name__ == "__main__":
    main()
