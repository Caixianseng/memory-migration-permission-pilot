"""Bounded synthetic reference for task-aware authorization placement.

No models, native services, policy extraction, or novel heuristic. Readers are
trusted pre-intersected principals, not model-generated authorization. This
finite model supports one principal per task and no per-container capacity.
"""
from itertools import combinations, product


def _keys(value, required):
    if not isinstance(value, dict) or set(value) != set(required):
        raise ValueError("invalid_schema_fields")


def _ids(values, domain=None, *, empty=True):
    if (not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values)
            or len(values) != len(set(values)) or (not empty and not values)
            or (domain is not None and not set(values) <= domain)):
        raise ValueError("invalid_identifiers")


def validate_problem(problem):
    _keys(problem, ("schema_version", "case_id", "data_origin", "actors", "records", "target", "tasks"))
    if type(problem["schema_version"]) is not int or problem["schema_version"] != 1:
        raise ValueError("unsupported_schema_version")
    if not isinstance(problem["case_id"], str) or not problem["case_id"]:
        raise ValueError("invalid_case_id")
    if problem["data_origin"] != "synthetic_development":
        raise ValueError("only_synthetic_development_supported")
    _ids(problem["actors"], empty=False)
    if len(problem["actors"]) > 4:
        raise ValueError("reference_actor_limit")
    actors = set(problem["actors"])
    records = problem["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 4:
        raise ValueError("reference_record_limit")
    for record in records:
        _keys(record, ("source_id", "readers", "export_allowed", "max_target_copies", "preserve_all_readers"))
        if record["readers"] is not None:
            _ids(record["readers"], actors)
        if record["export_allowed"] is not None and type(record["export_allowed"]) is not bool:
            raise ValueError("invalid_export_permission")
        if type(record["max_target_copies"]) is not int or not 1 <= record["max_target_copies"] <= 3:
            raise ValueError("invalid_copy_limit")
        if type(record["preserve_all_readers"]) is not bool:
            raise ValueError("invalid_recipient_preservation")
    _ids([r["source_id"] for r in records], empty=False)
    sources = {r["source_id"] for r in records}
    target = problem["target"]
    _keys(target, ("max_groups", "implicit_readers", "allowed_reader_sets", "constraint_origin"))
    if type(target["max_groups"]) is not int or not 0 <= target["max_groups"] <= 3:
        raise ValueError("reference_group_limit")
    if target["constraint_origin"] != "synthetic":
        raise ValueError("unverified_real_constraint_not_supported")
    _ids(target["implicit_readers"], actors)
    allowed = target["allowed_reader_sets"]
    if allowed is not None:
        if not isinstance(allowed, list) or len(allowed) > 15:
            raise ValueError("invalid_reader_sets")
        for group in allowed:
            _ids(group, actors, empty=False)
            if not set(target["implicit_readers"]) <= set(group):
                raise ValueError("allowed_sets_are_effective_readers")
        if len({tuple(sorted(g)) for g in allowed}) != len(allowed):
            raise ValueError("duplicate_allowed_reader_set")
    tasks = problem["tasks"]
    if not isinstance(tasks, list) or len(tasks) > 8:
        raise ValueError("reference_task_limit")
    for task in tasks:
        _keys(task, ("task_id", "actor_id", "required_sets", "weight", "requirement_origin"))
        if not isinstance(task["actor_id"], str) or task["actor_id"] not in actors:
            raise ValueError("unknown_task_actor")
        if task["requirement_origin"] != "synthetic_predeclared":
            raise ValueError("scoring_labels_are_not_planner_inputs")
        if type(task["weight"]) is not int or not 1 <= task["weight"] <= 1000:
            raise ValueError("invalid_task_weight")
        if not isinstance(task["required_sets"], list) or not 1 <= len(task["required_sets"]) <= 8:
            raise ValueError("invalid_sufficient_sets")
        for need in task["required_sets"]:
            _ids(need, sources, empty=False)
        if len({tuple(sorted(s)) for s in task["required_sets"]}) != len(task["required_sets"]):
            raise ValueError("duplicate_sufficient_set")
    _ids([t["task_id"] for t in tasks])


def evaluate_plan(problem, plan):
    """Rebuild relations from the plan; independent of candidate generation/search."""
    validate_problem(problem)
    _keys(plan, ("case_id", "groups"))
    if not isinstance(plan["groups"], list):
        raise ValueError("invalid_plan_groups")
    actors = set(problem["actors"])
    records = {r["source_id"]: r for r in problem["records"]}
    target = problem["target"]
    implicit = set(target["implicit_readers"])
    allowed = None if target["allowed_reader_sets"] is None else {frozenset(g) for g in target["allowed_reader_sets"]}
    read, eligible, excluded = set(), set(), []
    for sid, record in records.items():
        reasons = []
        if record["readers"] is None:
            reasons.append("read_authorization_unknown")
        else:
            read.update((a, sid) for a in record["readers"])
        if record["export_allowed"] is not True:
            reasons.append("export_forbidden" if record["export_allowed"] is False else "export_unknown")
        if reasons:
            excluded.append({"source_id": sid, "reasons": reasons})
        else:
            eligible.update((a, sid) for a in record["readers"])
    errors, actual, seen_groups = [], set(), set()
    copies = {sid: 0 for sid in records}
    if plan["case_id"] != problem["case_id"]:
        errors.append("case_identity_mismatch")
    if len(plan["groups"]) > target["max_groups"]:
        errors.append("group_budget_exceeded")
    for group in plan["groups"]:
        _keys(group, ("readers", "source_ids"))
        _ids(group["readers"])
        _ids(group["source_ids"])
        effective = frozenset(group["readers"]) | implicit
        if not effective or not group["source_ids"]:
            errors.append("empty_group")
        if effective in seen_groups:
            errors.append("duplicate_effective_reader_group")
        seen_groups.add(effective)
        if not effective <= actors:
            errors.append("unknown_reader")
        if allowed is not None and effective not in allowed:
            errors.append("reader_group_not_representable")
        for sid in group["source_ids"]:
            if sid not in records:
                errors.append("unknown_source")
                continue
            copies[sid] += 1
            actual.update((a, sid) for a in effective)
            if records[sid]["readers"] is None:
                errors.append("unknown_authorization_placed")
            if records[sid]["export_allowed"] is not True:
                errors.append("export_not_allowed")
    for sid, record in records.items():
        if copies[sid] > record["max_target_copies"]:
            errors.append("copy_budget_exceeded")
        if (copies[sid] and record["preserve_all_readers"]
                and {a for a, source in actual if source == sid} != set(record["readers"] or [])):
            errors.append("required_recipient_set_not_preserved")
    if actual - eligible:
        errors.append("unauthorized_relation")
    completed, legal, migratable, unknown, denied = [], [], [], [], []
    weight, edge_weights = 0, {}
    for task in problem["tasks"]:
        aid, tid = task["actor_id"], task["task_id"]
        needs = [{(aid, sid) for sid in sufficient} for sufficient in task["required_sets"]]
        legal_here = any(need <= read for need in needs)
        if legal_here:
            legal.append(tid)
        elif any(all(records[sid]["readers"] is None or aid in records[sid]["readers"]
                     for sid in sufficient) for sufficient in task["required_sets"]):
            unknown.append(tid)
        else:
            denied.append(tid)
        migratable_needs = [need for need in needs if need <= eligible]
        if migratable_needs:
            migratable.append(tid)
        if any(need <= actual for need in needs):
            completed.append(tid)
            weight += task["weight"]
        # Ineligible/unknown tasks and impossible alternative paths must not
        # consume the weighted baseline's budget through their partial edges.
        for edge in set().union(*migratable_needs):
            edge_weights[edge] = edge_weights.get(edge, 0) + task["weight"]
    valid = not errors
    pairs = lambda edges: [list(e) for e in sorted(edges)]
    return {"valid": valid, "errors": sorted(set(errors)),
            "E_read": pairs(read), "E_migrate": pairs(eligible), "actual": pairs(actual),
            "added": pairs(actual - eligible), "missing_migratable": pairs(eligible - actual),
            "excluded_records": excluded,
            "weighted_relation_coverage": sum(edge_weights.get(e, 0) for e in actual) if valid else None,
            "tasks": {"declared_count": len(problem["tasks"]),
                      "completed_count": len(completed) if valid else None,
                      "completed_weight": weight if valid else None,
                      "completed_ids": sorted(completed) if valid else None,
                      "known_read_legal_count": len(legal), "eligible_count": len(migratable),
                      "unknown_read_task_ids": sorted(unknown), "read_denied_task_ids": sorted(denied),
                      "non_migratable_task_ids": sorted(set(legal) - set(migratable))},
            "group_count": len(plan["groups"]), "object_count": sum(copies.values()), "copy_counts": copies,
            "reference_authorization_complete": not any(r["readers"] is None or r["export_allowed"] is None
                                                        for r in records.values()),
            "native_enforcement_verified": False}


def solve_reference(problem, *, objective="tasks", max_states=250000):
    """Enumerate complete finite configurations; no optimality claim on cutoff."""
    validate_problem(problem)
    if objective not in {"tasks", "edges", "task_weighted_edges"}:
        raise ValueError("invalid_objective")
    if type(max_states) is not int or not 1 <= max_states <= 250000:
        raise ValueError("invalid_search_limit")
    target = problem["target"]
    actors = sorted(problem["actors"])
    implicit = set(target["implicit_readers"])
    declared = target["allowed_reader_sets"]
    if declared is None:
        groups = [frozenset(g) for n in range(1, len(actors) + 1) for g in combinations(actors, n)
                  if implicit <= set(g)]
    else:
        groups = [frozenset(g) for g in declared]
    groups.sort(key=lambda g: tuple(sorted(g)))
    records = sorted(problem["records"], key=lambda r: r["source_id"])
    best_plan = {"case_id": problem["case_id"], "groups": []}
    best_eval = evaluate_plan(problem, best_plan)

    def rank(ev):
        value = (ev["tasks"]["completed_weight"] if objective == "tasks" else
                 len(ev["actual"]) if objective == "edges" else ev["weighted_relation_coverage"])
        return value, -ev["object_count"], -ev["group_count"]

    best_rank, states = rank(best_eval), 0
    for n in range(min(target["max_groups"], len(groups)) + 1):
        for family in combinations(groups, n):
            choices = []
            for record in records:
                placements = [()]
                if record["readers"] is not None and record["export_allowed"] is True:
                    readers = set(record["readers"])
                    possible = [i for i, group in enumerate(family) if group <= readers]
                    for count in range(1, min(record["max_target_copies"], len(possible)) + 1):
                        for chosen in combinations(possible, count):
                            if (not record["preserve_all_readers"]
                                    or set().union(*(family[i] for i in chosen)) == readers):
                                placements.append(chosen)
                choices.append(placements)
            for assignment in product(*choices):
                if states >= max_states:
                    return {"plan": best_plan, "evaluation": best_eval, "objective": objective,
                            "objective_value": best_rank[0], "status": "feasible_not_proven", "states": states,
                            "search_limit_reached": True, "candidate_groups": len(groups),
                            "proof_scope": "controlled_synthetic_configuration"}
                states += 1
                used = set().union(*(set(indices) for indices in assignment))
                if used != set(range(n)):
                    continue  # Empty groups are equivalent to a smaller family already considered.
                plan = {"case_id": problem["case_id"], "groups": [
                    {"readers": sorted(group), "source_ids": [record["source_id"]
                     for record, indices in zip(records, assignment) if gi in indices]}
                    for gi, group in enumerate(family)]}
                ev = evaluate_plan(problem, plan)
                if not ev["valid"]:
                    raise AssertionError("reference_generated_invalid_plan:" + ",".join(ev["errors"]))
                score = rank(ev)
                if score > best_rank:
                    best_plan, best_eval, best_rank = plan, ev, score
    return {"plan": best_plan, "evaluation": best_eval, "objective": objective,
            "objective_value": best_rank[0], "status": "optimal_in_declared_finite_model", "states": states,
            "search_limit_reached": False, "candidate_groups": len(groups),
            "proof_scope": "controlled_synthetic_configuration"}
