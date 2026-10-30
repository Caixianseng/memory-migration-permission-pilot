"""Reuse a configured legacy checker for a finite static read relation only.

The legacy implicit-owner model is projected from the declared reference ACLs;
this adapter neither observes an owner nor verifies any backend or HTTP behavior.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import ModuleType

from .policy import decision, validate_case


_SCOPE = "registered_subjects_objects_static_read_membership_only"
_STATUSES = {"unknown", "exact", "partial", "blocked", "unsafe"}


class _ProjectionError(ValueError):
    def __init__(self, issue, *, status="unknown", unresolved=None):
        super().__init__(issue)
        self.status = status
        self.unresolved = unresolved or []


def _names(values, registered):
    return (isinstance(values, list)
            and all(isinstance(value, str) and value in registered for value in values)
            and len(values) == len(set(values)))


def _project(case, plan):
    """Produce equivalent legacy inputs, or explicitly decline projection."""
    try:
        validate_case(case)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise _ProjectionError("invalid_case: " + str(exc)) from exc
    if not isinstance(plan, dict) or plan.get("case_id") != case["case_id"]:
        raise _ProjectionError("missing_plan_or_case_id_mismatch")
    if plan.get("mapping_complete") is not True or plan.get("inventory_complete") is not True:
        raise _ProjectionError("complete_object_mapping_and_inventory_required")

    subjects = [actor["actor_id"] for actor in case["actors"]]
    registered = set(subjects)
    source_ids = {record["source_id"] for record in case["records"]}
    source_rows, unresolved = [], []
    for record in case["records"]:
        # The common reference remains fixed even for a source-only ablation plan.
        states = {subject: decision(record, subject) for subject in subjects}
        unresolved.extend({"subject": subject, "object_key": record["source_id"],
                           "reference_decision": "unknown"}
                          for subject, state in states.items() if state == "unknown")
        source_rows.append({"key": record["source_id"],
                            "readers": [subject for subject in subjects if states[subject] == "allow"]})
    if unresolved:
        raise _ProjectionError("three_valued_reference_not_expressible_as_legacy_acl",
                               unresolved=unresolved)

    mapping, objects, containers = (plan.get(field) for field in ("object_mapping", "objects", "containers"))
    if not isinstance(mapping, dict) or set(mapping) != source_ids:
        raise _ProjectionError("incomplete_source_object_mapping")
    all_targets = []
    for targets in mapping.values():
        if (not isinstance(targets, list)
                or any(not isinstance(target, str) or not target for target in targets)):
            raise _ProjectionError("malformed_target_mapping")
        all_targets.extend(targets)
    if len(all_targets) != len(set(all_targets)):
        raise _ProjectionError("target_identity_collision")
    if not isinstance(objects, list) or not isinstance(containers, list):
        raise _ProjectionError("explicit_objects_and_containers_required")

    by_target = {}
    for obj in objects:
        if not isinstance(obj, dict):
            raise _ProjectionError("malformed_target_object")
        target = obj.get("target_id")
        if not isinstance(target, str) or not target or target in by_target:
            raise _ProjectionError("missing_or_duplicate_target_identity")
        if (not isinstance(obj.get("source_id"), str) or obj["source_id"] not in source_ids
                or not _names(obj.get("readers"), registered)):
            raise _ProjectionError("unknown_object_source_or_readers")
        by_target[target] = obj
    if set(by_target) != set(all_targets):
        raise _ProjectionError("target_inventory_does_not_match_mapping")
    for source_id, targets in mapping.items():
        if any(by_target[target]["source_id"] != source_id for target in targets):
            raise _ProjectionError("target_source_mapping_mismatch")

    projected, owner_choices, seen_groups, grouped_targets = [], [], set(), []
    for group in containers:
        if not isinstance(group, dict):
            raise _ProjectionError("malformed_target_container")
        group_id, readers, targets = (group.get(field) for field in ("container_id", "readers", "target_ids"))
        if not isinstance(group_id, str) or not group_id or group_id in seen_groups:
            raise _ProjectionError("missing_or_duplicate_container_identity")
        seen_groups.add(group_id)
        if not _names(readers, registered):
            raise _ProjectionError("unknown_or_malformed_container_readers")
        if (not isinstance(targets, list)
                or any(not isinstance(target, str) or target not in by_target for target in targets)
                or len(targets) != len(set(targets))):
            raise _ProjectionError("unknown_or_duplicate_container_target")
        grouped_targets.extend(targets)
        for target in targets:
            obj = by_target[target]
            if obj.get("container_id") != group_id or set(obj["readers"]) != set(readers):
                raise _ProjectionError("object_and_container_policy_mismatch")
        if not targets:
            continue  # An empty container contributes no object-read relation.
        if not readers:
            raise _ProjectionError("implicit_owner_cannot_represent_nonempty_deny_all_container",
                                   status="unsupported")
        # owner ∈ readers makes (owner OR readers) exactly equal to readers.
        owner = sorted(readers)[0]
        keys = sorted({by_target[target]["source_id"] for target in targets})
        projected.append({"owner": owner, "readers": list(readers), "record_keys": keys})
        owner_choices.append({"container_id": group_id, "synthetic_owner": owner,
                              "basis": "existing_declared_reader_preserves_relation"})
    if len(grouped_targets) != len(set(grouped_targets)) or set(grouped_targets) != set(all_targets):
        raise _ProjectionError("container_inventory_does_not_match_mapping")
    return {"records": source_rows, "containers": projected, "subjects": subjects,
            "identity_mapping": dict(case["actor_mapping"])}, owner_choices


def check_with_legacy(case: dict, plan: dict, legacy_project=None) -> dict:
    """Load ``scripts/migration_policy.py`` and call its existing pure checker.

    ``status`` is a legacy model result when ``legacy_report`` is populated.
    Missing configuration returns ``not_configured``. Invalid/incomplete inputs
    remain ``unknown``; a relation the owner model cannot express is
    ``unsupported``. Neither status nor a successful projection certifies HTTP
    behavior, native ownership, list behavior, or export/copy permissions.
    No import cache is written into the configured legacy project.
    """
    result = {
        "schema_version": "legacy-policy-bridge/1", "status": "not_configured",
        "legacy_loaded": False, "legacy_checker_called": False,
        "project_path": None, "module_path": None, "module_sha256": None,
        "function": "check_plan_relation", "scope": _SCOPE,
        "model_only": True, "backend_execution_verified_by_this_check": False,
        "native_owner_verified": False, "http_evidence": False,
        "reference": "conjunction_of_source_recipient_target_readers",
        "excluded_scope": ["native_owner_semantics", "http_execution", "list", "export", "copy"],
        "projection": {"kind": "static_read_relation_projection",
                       "owner_evidence": "synthetic_existing_reader_not_native_owner_evidence"},
        "legacy_inputs": None, "legacy_report": None, "issues": [], "unresolved": [],
    }
    if legacy_project is None or str(legacy_project) == "":
        return result
    result["status"] = "unknown"
    try:
        project = Path(legacy_project).expanduser().resolve()
        module_path = project / "scripts" / "migration_policy.py"
        result.update(project_path=str(project), module_path=str(module_path))
        source = module_path.read_bytes()
        result["module_sha256"] = hashlib.sha256(source).hexdigest()
        module = ModuleType("memory_migration_study._configured_legacy_policy")
        module.__file__ = str(module_path)
        # Execute the exact hashed bytes, avoiding importlib's .pyc side effects.
        exec(compile(source, str(module_path), "exec"), module.__dict__)
        checker = getattr(module, "check_plan_relation", None)
        if not callable(checker):
            result["issues"].append("legacy_check_plan_relation_not_callable")
            return result
        result["legacy_loaded"] = True
    except (OSError, TypeError, ValueError, SyntaxError, ImportError) as exc:
        result["issues"].append("legacy_load_error: " + type(exc).__name__)
        return result
    except Exception as exc:
        result["issues"].append("legacy_module_execution_error: " + type(exc).__name__)
        return result
    try:
        inputs, owner_choices = _project(case, plan)
    except _ProjectionError as exc:
        result.update(status=exc.status, unresolved=exc.unresolved)
        result["issues"].append(str(exc))
        return result
    result["legacy_inputs"] = inputs
    result["projection"]["synthetic_owner_containers"] = owner_choices
    result["projection"]["identity_mapping_scope"] = "total_injective_declaration_only_not_native_identity_verification"
    result["legacy_checker_called"] = True
    try:
        report = checker(**inputs)
    except Exception as exc:
        result["issues"].append("legacy_checker_error: " + type(exc).__name__)
        return result
    if (not isinstance(report, dict) or not isinstance(report.get("status"), str)
            or report["status"] not in _STATUSES):
        result["issues"].append("malformed_legacy_checker_report")
        return result
    result.update(status=report["status"], legacy_report=report)
    return result
