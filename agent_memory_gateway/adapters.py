"""Explicit local JSON exchange; no model calls or native-memory access.

The caller is the trusted local writer. These functions are not HTTP file-read
endpoints. Platform/model labels and declared dependencies are supplied export
metadata, not authenticated supplier identity or complete causal provenance.
Import registers sources/memories only: it never grants access or commits a
transfer. Registration is per object, not an atomic multi-object import.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .service import GatewayService

EXPORT_SCHEMA = "agent-memory-gateway-export-v1"
CONTEXT_SCHEMA = "agent-memory-gateway-context-v1"
PLATFORMS = frozenset({"workbuddy", "deepseek_harness"})
MAX_EXPORT_BYTES = 1_048_576
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_PRIVATE_DIRS = frozenset({"sdk.private", "home.private", ".workbuddy", ".deepseek"})


class AdapterError(ValueError):
    """Stable validation code; never echoes imported text or native errors."""


def _need(condition, code):
    if not condition:
        raise AdapterError(code)


def _shape(value, required, optional=()):
    _need(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional),
          "export_object_schema_invalid")


def _identifier(value):
    _need(isinstance(value, str) and _ID.fullmatch(value) is not None, "export_identifier_invalid")
    return value


def _text(value):
    _need(isinstance(value, str) and bool(value.strip()) and len(value) <= 100_000,
          "export_text_invalid")
    return value


def _version(value):
    _need(type(value) is int and value > 0, "export_version_invalid")
    return value


def _direction(source, target):
    _need(isinstance(source, str) and isinstance(target, str) and
          source in PLATFORMS and target in PLATFORMS and source != target,
          "export_platform_direction_invalid")


def _path(value, *, existing):
    supplied = Path(value).absolute()
    _need(not supplied.is_symlink(), "adapter_file_symlink_forbidden")
    resolved = supplied.resolve(strict=existing)
    _need(not any(part.lower() in _PRIVATE_DIRS for part in supplied.parts + resolved.parts),
          "adapter_private_directory_forbidden")
    _need(resolved.suffix.lower() == ".json", "explicit_json_file_required")
    if existing:
        _need(resolved.is_file(), "export_file_required")
    else:
        _need(resolved.parent.is_dir(), "existing_export_parent_required")
    return resolved


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, "duplicate_export_json_key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise AdapterError("nonfinite_export_json_number")


def load_memory_export(path, *, expected_source_platform=None, expected_target_platform=None):
    """Validate one explicitly exported JSON file without writing gateway state.

    Required top-level fields: schema, source_platform, target_platform,
    sources, memories. Sources require source_id/text/source_type; memories
    require memory_id/content/source_ids. Only the optional fields validated
    below are accepted. Input order must place parent memories before children.
    """
    source_path = _path(path, existing=True)
    with source_path.open("rb") as stream:
        raw = stream.read(MAX_EXPORT_BYTES + 1)
    _need(len(raw) <= MAX_EXPORT_BYTES, "export_file_too_large")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs,
                          parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise AdapterError("export_json_invalid") from None
    _shape(data, {"schema", "source_platform", "target_platform", "sources", "memories"}, {"model"})
    _need(data["schema"] == EXPORT_SCHEMA, "export_schema_version_invalid")
    _direction(data["source_platform"], data["target_platform"])
    for key, expected in (("source_platform", expected_source_platform),
                          ("target_platform", expected_target_platform)):
        _need(expected is None or data[key] == expected, "export_expected_platform_mismatch")
    if "model" in data:
        _need(isinstance(data["model"], str) and 0 < len(data["model"]) <= 128,
              "export_model_label_invalid")
    _need(type(data["sources"]) is list and 0 < len(data["sources"]) <= 256,
          "export_sources_invalid")
    _need(type(data["memories"]) is list and 0 < len(data["memories"]) <= 256,
          "export_memories_invalid")
    sources = {}
    for item in data["sources"]:
        _shape(item, {"source_id", "text", "source_type"}, {"version"})
        sid = _identifier(item["source_id"])
        _need(sid not in sources, "duplicate_export_source_id")
        _text(item["text"])
        _version(item.get("version", 1))
        _need(isinstance(item["source_type"], str) and _TYPE.fullmatch(item["source_type"]) is not None,
              "export_source_type_invalid")
        sources[sid] = item
    seen = set()
    for item in data["memories"]:
        _shape(item, {"memory_id", "content", "source_ids"}, {"parent_memory_ids", "version", "kind"})
        mid = _identifier(item["memory_id"])
        _need(mid not in seen, "duplicate_export_memory_id")
        _text(item["content"])
        _version(item.get("version", 1))
        direct = item["source_ids"]
        parents = item.get("parent_memory_ids", [])
        for refs in (direct, parents):
            _need(type(refs) is list and len(refs) <= 256, "export_dependency_list_invalid")
            for ref in refs:
                _identifier(ref)
            _need(len(refs) == len(set(refs)), "duplicate_export_dependency")
        _need(set(direct) <= set(sources), "export_source_outside_manifest")
        _need(set(parents) <= seen, "export_parent_not_previously_declared")
        _need(bool(direct or parents), "export_memory_dependencies_required")
        kind = item.get("kind", "derived")
        _need(kind in ("raw", "derived"), "export_memory_kind_invalid")
        if kind == "raw":
            _need(len(direct) == 1 and not parents and item["content"] == sources[direct[0]]["text"],
                  "raw_export_must_equal_original")
        seen.add(mid)
    return {"document": data, "export_sha256": hashlib.sha256(raw).hexdigest(),
            "execution_mode": "exported_record_import", "new_model_calls": 0,
            "supplier_metadata_verified": False}


def import_memory_export(service: "GatewayService", path, *, sender_id,
                         expected_source_platform=None, expected_target_platform=None):
    """Import declared sources/memories; do not authorize or deliver anything.

    All file validation precedes service calls. A later storage conflict can
    leave earlier registrations intact; the receipt never claims batch atomicity.
    """
    loaded = load_memory_export(path, expected_source_platform=expected_source_platform,
                                expected_target_platform=expected_target_platform)
    data = loaded["document"]
    route = {"source_platform": data["source_platform"], "target_platform": data["target_platform"],
             "claimed_model": data.get("model"), "supplier_metadata_verified": False,
             "execution_mode": "exported_record_import", "export_sha256": loaded["export_sha256"]}
    registered = []
    for item in data["sources"]:
        # Original records are immutable at a given source/version. A later
        # export may derive a new memory from exactly the same original while
        # changing its file digest, route or claimed model. Those per-export
        # fields belong to the memory provenance/receipt, never the original.
        registered.append(service.register_source(sender_id, item["source_id"], item["text"],
                          version=item.get("version", 1),
                          metadata={"source_type": item["source_type"],
                                    "registered_by": "explicit-json-export-adapter-v1"}))
    memories = []
    for item in data["memories"]:
        memories.append(service.create_memory(sender_id, item["memory_id"], item["content"],
                        source_ids=item["source_ids"], parent_memory_ids=item.get("parent_memory_ids", []),
                        version=item.get("version", 1), kind=item.get("kind", "derived"),
                        provenance={"generator": "exported-record-import-v1", "evidence_hash": loaded["export_sha256"],
                                    "declared_export_route": route, "causal_provenance_verified": False}))
    return {"status": "records_imported", **route, "sender_id": sender_id,
            "source_count": len(registered), "memory_count": len(memories),
            "memory_keys": [m["memory_key"] for m in memories], "new_model_calls": 0,
            "grants_changed": False, "authority_sources_registered": True,
            "transfer_prepared": False, "persistent_delivery_performed": False,
            "import_transaction_scope": "per-source/per-memory registration"}


def export_receiver_context(service: "GatewayService", *, recipient_id, batch_id, output,
                            source_platform, target_platform):
    """Export already committed Host memory for an explicitly labelled recipient.

    No native application is contacted. This writes one new JSON context file,
    not a WorkBuddy/Harness internal-memory import. Host DB paths, receipt data
    and ancestor source texts are omitted from the recipient context.
    """
    _direction(source_platform, target_platform)
    target = _path(output, existing=False)
    result = service.retrieve_batch(recipient_id, batch_id)
    content_sha = hashlib.sha256(result["memory"].encode("utf-8")).hexdigest()
    payload = {"schema": CONTEXT_SCHEMA, "source_platform": source_platform,
               "target_platform": target_platform, "recipient_id": recipient_id,
               "batch_id": batch_id, "memory": result["memory"], "content_sha256": content_sha,
               "execution_mode": "file_export_only", "native_memory_imported": False,
               "supplier_metadata_verified": False, "new_model_calls": 0}
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)+"\n").encode("utf-8")
    # Exclusive creation preserves any existing export, database or spool file.
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "context_exported", "output": str(target), "content_sha256": content_sha,
            "file_sha256": hashlib.sha256(raw).hexdigest(), "source_platform": source_platform,
            "target_platform": target_platform, "execution_mode": "file_export_only",
            "new_model_calls": 0, "native_memory_imported": False}
