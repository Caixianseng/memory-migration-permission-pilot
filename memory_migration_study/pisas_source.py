"""Source-only PiSAs projection; document ACLs are not privacy annotations.

Only source scenario JSON is accepted. No evaluator, annotation or answer file
is consulted. The process-local seal prevents mixing or editing projections;
it authenticates this importer output, not the dataset's authority or accuracy.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import secrets


VERSION = "pisas_source_projection_v1"
_KEY = secrets.token_bytes(32)


class SourceError(ValueError):
    """Fixed validation reason; never includes source content."""


def _require(condition, code):
    if not condition:
        raise SourceError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value):
    return type(value) is str and bool(value.strip())


class _Capability:
    __slots__ = ("_seal",)

    def __init__(self, material):
        self._seal = hmac.new(_KEY, _canonical(material), hashlib.sha256).digest()

    def valid(self, material):
        return hmac.compare_digest(self._seal,
            hmac.new(_KEY, _canonical(material), hashlib.sha256).digest())

    def __getstate__(self):
        raise TypeError("source projection capabilities must remain local")

    def __repr__(self):
        return "<PiSAs source capability: contents withheld>"


def _sealed(material):
    return {**material, "_capability": _Capability(material)}


def _checked(projected):
    _require(type(projected) is dict and type(projected.get("_capability")) is _Capability,
             "invalid_projection_capability")
    material = {key: value for key, value in projected.items() if key != "_capability"}
    try:
        valid = projected["_capability"].valid(material)
    except (TypeError, ValueError, AttributeError, RecursionError, OverflowError):
        valid = False
    _require(valid, "projection_integrity_mismatch")
    _require(material.get("version") == VERSION and material.get("view_kind") == "source",
             "complete_source_projection_required")
    return material


def project_source(scenario):
    """Import one scenario, retaining exact content and name-based initial ACLs.

    Missing/empty task descriptions are qualified as pending, never inferred.
    Unknown ACL names fail closed. Cast keys and timeline author are not grants.
    Extras are hashed for provenance but never copied into the model view.
    """
    _require(type(scenario) is dict, "invalid_scenario")
    try:
        source_hash = _sha(scenario)
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise SourceError("invalid_source_json") from None
    _require(_identifier(scenario.get("scenario_id")), "invalid_scenario_id")
    task = scenario.get("task")
    _require(type(task) is dict, "invalid_task")
    description = task.get("description", "")
    _require(type(description) is str, "invalid_task_description")
    raw_cast = scenario.get("cast")
    _require(type(raw_cast) in (dict, list), "invalid_cast")
    items = list(raw_cast.values()) if type(raw_cast) is dict else raw_cast
    _require(bool(items), "empty_cast")
    cast, names = [], set()
    for person in items:
        _require(type(person) is dict and _identifier(person.get("name")), "invalid_cast_member")
        name = person["name"]
        _require(name not in names, "duplicate_cast_name")
        names.add(name)
        _require(all(type(person.get(field, "")) is str for field in ("role", "team")),
                 "invalid_cast_member")
        cast.append({field: person.get(field, "") for field in ("name", "role", "team")})
    timeline = scenario.get("timeline")
    _require(type(timeline) is list, "invalid_timeline")
    memories, host_objects, artifact_ids = [], [], set()
    for ordinal, artifact in enumerate(timeline, 1):
        _require(type(artifact) is dict and _identifier(artifact.get("id")), "invalid_artifact_id")
        artifact_id = artifact["id"]
        _require(artifact_id not in artifact_ids, "duplicate_artifact_id")
        artifact_ids.add(artifact_id)
        content, acl = artifact.get("content"), artifact.get("visible_to")
        _require(type(content) is str, "invalid_artifact_content")
        _require(type(acl) is list and all(_identifier(name) for name in acl), "invalid_source_acl")
        _require(len(acl) == len(set(acl)), "duplicate_acl_member")
        _require(set(acl) <= names, "unknown_source_acl_member")
        model_id = f"m_{ordinal:04d}"
        memories.append({"source_id": model_id, "content": content})
        host_objects.append({"model_id": model_id, "artifact_id": artifact_id,
            "source_sha256": source_hash, "visible_to": list(acl)})
    qualification = {"status": "qualified" if description.strip() else "needs_task_description",
        "task_description_present": bool(description.strip()), "source_object_count": len(memories),
        "source_acl_scope": "initial_document_visibility_declared_in_scenario",
        "attribute_visibility_inferred": False, "sensitivity_assessed": False,
        "native_current_authorization_verified": False, "evaluation_used": False}
    material = {"version": VERSION, "view_kind": "source", "source_sha256": source_hash,
        "scenario_id": scenario["scenario_id"], "qualification": qualification,
        "model_view": {"task": {"description": description}, "cast": cast, "memories": memories},
        "host_objects": host_objects}
    return _sealed(deepcopy(material))


def build_actor_view(projected, actor):
    """Filter whole source objects by their initial exact-name ACL, nothing else.

    The supplied actor must be bound by the caller; this is not authentication,
    field-level privacy selection, delegation, or proof of export permission.
    """
    material = _checked(projected)
    _require(_identifier(actor) and actor in {p["name"] for p in material["model_view"]["cast"]},
             "unknown_actor")
    result = deepcopy(material)
    result.update(view_kind="actor", actor=actor)
    objects = [item for item in result["host_objects"] if actor in item["visible_to"]]
    allowed_ids = {item["model_id"] for item in objects}
    result["host_objects"] = objects
    result["model_view"]["memories"] = [item for item in result["model_view"]["memories"]
                                        if item["source_id"] in allowed_ids]
    result["qualification"].update(visible_object_count=len(objects),
        excluded_object_count=len(material["host_objects"])-len(objects))
    return _sealed(result)
