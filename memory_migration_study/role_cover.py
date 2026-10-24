"""Bounded weighted role cover, independently implemented from a standard model.

Readers are authenticated user/Agent bindings. A role is a safe reader subset;
placing a source in a role covers only explicitly allowed edges. We enumerate
ALL reader subsets in small domains, not just maximal bicliques: copy costs and
non-copyable objects invalidate the usual maximal-only simplification.
This is an existing optimization baseline, not a novel role-mining algorithm.
"""
from __future__ import annotations

from itertools import combinations
import time

from .policy import decision, stable_id, validate_case


def normalize_options(options, actors):
    options = dict(options or {})
    allowed = {"container_cost", "object_cost", "max_exact_actors", "max_search_states",
               "implicit_readers", "allowed_reader_sets"}
    if set(options) - allowed:
        raise ValueError("unknown_role_cover_option")
    result = {"container_cost": 4, "object_cost": 1, "max_exact_actors": 8,
              "max_search_states": 30000, "implicit_readers": [], "allowed_reader_sets": None}
    result.update(options)
    for key, lo, hi in (("container_cost", 0, 1000000), ("object_cost", 1, 1000000),
                        ("max_exact_actors", 1, 10), ("max_search_states", 1, 200000)):
        if type(result[key]) is not int or not lo <= result[key] <= hi:
            raise ValueError("invalid_role_cover_cost_or_limit")
    def group(values):
        if (not isinstance(values, (list, tuple)) or any(not isinstance(v, str) or v not in actors for v in values)
                or len(set(values)) != len(values)):
            raise ValueError("invalid_target_reader_set")
        return tuple(sorted(values))
    result["implicit_readers"] = list(group(result["implicit_readers"]))
    if result["allowed_reader_sets"] is not None:
        if not isinstance(result["allowed_reader_sets"], list) or len(result["allowed_reader_sets"]) > 4096:
            raise ValueError("invalid_target_reader_sets")
        result["allowed_reader_sets"] = sorted(set(group(g) for g in result["allowed_reader_sets"]))
        if any(not g for g in result["allowed_reader_sets"]):
            raise ValueError("empty_target_reader_set")
    return result


def make_role_plan(case, run_id, *, source_only=False, keep_source=False, options=None):
    validate_case(case)
    started = time.monotonic()
    actors = sorted(a["actor_id"] for a in case["actors"])
    opts = normalize_options(options, actors)
    implicit = set(opts["implicit_readers"])
    eligible, excluded = [], []
    for record in case["records"]:
        states = {a: decision(record, a, source_only=source_only) for a in actors}
        readers = frozenset(a for a, state in states.items() if state == "allow")
        reason = None
        if not keep_source and record.get("export_allowed") is not True:
            reason = "export_forbidden" if record.get("export_allowed") is False else "export_unknown"
        elif "unknown" in states.values():
            reason = "authorization_unknown"
        elif not readers:
            reason = "no_common_readers"
        elif not implicit <= readers:
            reason = "implicit_reader_not_authorized"
        if reason:
            excluded.append({"source_id": record["source_id"], "reason": reason})
        else:
            eligible.append((record, readers))

    # Large domains have explicit, deterministic candidate-limited fallback.
    # The status does not claim global optimality for that path.
    if opts["allowed_reader_sets"] is not None:
        candidate_groups = {frozenset(g) for g in opts["allowed_reader_sets"]}
        complete = True
    elif len(actors) <= opts["max_exact_actors"]:
        candidate_groups = {frozenset(g) for n in range(1, len(actors) + 1)
                            for g in combinations(actors, n)}
        complete = True
    else:
        candidate_groups = {rs for _, rs in eligible} | {frozenset([a]) | implicit for a in actors}
        # One bounded intersection pass adds useful overlap roles without an
        # exponential closure, while retaining the exact-groups fallback.
        seed = sorted(candidate_groups, key=lambda g: tuple(sorted(g)))[:64]
        candidate_groups |= {a & b for a, b in combinations(seed, 2) if a & b}
        complete = False
    candidate_groups = {g for g in candidate_groups if implicit <= g and g}
    usable = []
    for record, readers in eligible:
        groups = [g for g in candidate_groups if g <= readers
                  and (record.get("copy_allowed") is True or g == readers)]
        if not groups or set().union(*groups) != readers:
            excluded.append({"source_id": record["source_id"], "reason": "target_has_no_safe_cover"})
        else:
            usable.append((record, readers))
    candidate_groups = sorted({g for _, readers in usable for g in candidate_groups if g <= readers},
                              key=lambda g: tuple(sorted(g)))
    edges = [(r["source_id"], a) for r, readers in usable for a in sorted(readers)]
    edge_index = {edge: i for i, edge in enumerate(edges)}
    full = (1 << len(edges)) - 1
    actions, by_edge = [], [[] for _ in edges]
    for record, readers in usable:
        for gi, group in enumerate(candidate_groups):
            if not group <= readers or (record.get("copy_allowed") is not True and group != readers):
                continue
            mask = sum(1 << edge_index[(record["source_id"], a)] for a in group)
            ai = len(actions)
            actions.append((record["source_id"], gi, mask))
            for a in group:
                by_edge[edge_index[(record["source_id"], a)]].append(ai)
    cc, oc = opts["container_cost"], opts["object_cost"]

    def cost(selected):
        return cc * len({actions[i][1] for i in selected}) + oc * len(selected)

    # Feasible incumbent, including every explicitly allowed edge of each
    # deployable object. No truncation of access to satisfy a search budget.
    covered = opened = 0
    selected = []
    while covered != full:
        candidates = [i for i, (_, _, mask) in enumerate(actions) if mask & ~covered]
        def rank(i):
            _, gi, mask = actions[i]
            increment = oc + (0 if opened & (1 << gi) else cc)
            return (increment / (mask & ~covered).bit_count(), increment, -mask.bit_count(), i)
        best = min(candidates, key=rank)
        selected.append(best)
        covered |= actions[best][2]
        opened |= 1 << actions[best][1]
    # Also compare the unmodified exact-readers configuration when representable.
    exact = []
    for record, readers in usable:
        choices = [i for i, (sid, gi, _) in enumerate(actions)
                   if sid == record["source_id"] and candidate_groups[gi] == readers]
        if not choices:
            break
        exact.append(choices[0])
    if len(exact) == len(usable) and cost(exact) <= cost(selected):
        selected = exact
    best_selected, best_cost = list(selected), cost(selected)
    visited, states, cutoff = {}, 0, False

    def search(covered, opened, total, chosen):
        nonlocal states, cutoff, best_selected, best_cost
        if covered == full:
            if total < best_cost:
                best_cost, best_selected = total, list(chosen)
            return
        if states >= opts["max_search_states"]:
            cutoff = True
            return
        states += 1
        if total >= best_cost or visited.get((covered, opened), best_cost) <= total:
            return
        visited[(covered, opened)] = total
        # Each still-uncovered record needs at least one further placement.
        missing_records = {sid for (sid, _), i in edge_index.items() if not covered & (1 << i)}
        if total + oc * len(missing_records) >= best_cost:
            return
        uncovered = [i for i in range(len(edges)) if not covered & (1 << i)]
        edge = min(uncovered, key=lambda i: (len(by_edge[i]), i))
        choices = sorted(by_edge[edge], key=lambda i: (
            (oc + (0 if opened & (1 << actions[i][1]) else cc)) / (actions[i][2] & ~covered).bit_count(), i))
        for i in choices:
            _, gi, mask = actions[i]
            increment = oc + (0 if opened & (1 << gi) else cc)
            search(covered | mask, opened | (1 << gi), total + increment, chosen + [i])
            if cutoff:
                break
    # Recursion depth is bounded by edge count; larger cases keep the incumbent.
    if complete and len(edges) <= 120:
        search(0, 0, 0, [])
    elif edges:
        cutoff = True
    groups, objects = {}, []
    mapping = {r["source_id"]: [] for r in case["records"]}
    records_by_id = {r["source_id"]: r for r in case["records"]}
    for i in sorted(best_selected):
        sid, gi, _ = actions[i]
        readers = sorted(candidate_groups[gi])
        container = f"{run_id}/group/{stable_id(readers)}"
        tid = f"{run_id}/{stable_id(readers)}/{stable_id(sid)}"
        groups.setdefault(container, {"container_id": container, "readers": readers, "target_ids": []})["target_ids"].append(tid)
        objects.append({"target_id": tid, "source_id": sid, "text": records_by_id[sid]["text"],
                        "readers": readers, "container_id": container})
        mapping[sid].append(tid)
    return {"schema_version": 1, "case_id": case["case_id"], "method": "role_cover", "run_id": run_id,
            "objects": objects, "containers": list(groups.values()), "object_mapping": mapping,
            "mapping_complete": True, "inventory_complete": True, "excluded": excluded,
            "backend_kind": "reference_backend", "source_only": source_only,
            "artificial_stress": False, "resource_constraint_origin": "explicit_target_contract",
            "planner": {"version": "weighted_role_cover_v1", "options": opts,
                        "weighted_cost": best_cost, "container_count": len(groups), "object_count": len(objects),
                        "candidate_groups": len(candidate_groups), "placement_candidates": len(actions),
                        "search_states": states, "search_limit_reached": cutoff,
                        "optimality": "proven_in_declared_finite_model" if complete and not cutoff else "not_proven",
                        "candidate_domain_complete": complete,
                        "elapsed_seconds": round(time.monotonic() - started, 6)}}
