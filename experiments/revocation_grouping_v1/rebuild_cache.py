"""Immutable content/version/config-bound artifacts for shared lazy rebuilding.

The caller supplies ONLY currently allowed original sources. The cache is not
an authority: the shared host must recheck current grants before every delivery.
It never derives a smaller dependency list from an existing model output.
Integrity hashes detect inconsistent/corrupt storage, not a malicious local
administrator able to rewrite both body and metadata.

Default reuse binds the grant epoch. Explicit transform configuration
``permission_reuse='recheck_current_dependencies'`` allows an artifact to be
reused after reauthorization when all source bodies/versions and transformation
settings match. Its key records the literal marker ``revalidate-at-use`` rather
than a fictitious grant version. The host MUST revalidate ALL dependencies at
actual delivery; a cache hit never authorizes disclosure. Original generation
grant versions remain in checksummed, immutable provenance, outside the key.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


class CacheIntegrityError(ValueError):
    pass


class CacheConflictError(CacheIntegrityError):
    pass


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _reuse_mode(transform_config):
    mode = transform_config.get("permission_reuse", "strict_epoch")
    if mode not in ("strict_epoch", "recheck_current_dependencies"):
        raise ValueError("unknown_permission_reuse_mode")
    return mode


def _permission_versions(source_records):
    # _input_binding validates every source and epoch before this helper is used.
    return {source["source_id"]: source.get("permission_version", source.get("grant_version", 1))
            for source in sorted(source_records, key=lambda source: source["source_id"])}


def _input_binding(source_records, transform_config):
    if not isinstance(source_records, (list, tuple)) or not source_records:
        raise ValueError("nonempty_source_records_required")
    if not isinstance(transform_config, dict):
        raise ValueError("transform_config_object_required")
    reuse_mode = _reuse_mode(transform_config)
    dependencies, seen = [], set()
    for source in source_records:
        if not isinstance(source, dict):
            raise ValueError("source_object_required")
        sid, text, version = source.get("source_id"), source.get("text"), source.get("version", 1)
        if not isinstance(sid, str) or not sid or sid in seen:
            raise ValueError("invalid_or_duplicate_source_id")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("source_text_required")
        if not isinstance(version, (int, str)) or isinstance(version, bool) or version == "":
            raise ValueError("source_version_required")
        if source.get("allow", True) is not True or source.get("allowed", True) is not True:
            raise ValueError("cache_received_forbidden_source")
        permission_version = source.get("permission_version", source.get("grant_version", 1))
        if not isinstance(permission_version, (str, int)) or isinstance(permission_version, bool):
            raise ValueError("permission_version_required")
        seen.add(sid)
        dependencies.append({"source_id": sid, "version": version, "text_sha256": _hash(text.encode("utf-8")),
                             "permission_allowed": True,
                             "permission_version": ("revalidate-at-use" if reuse_mode == "recheck_current_dependencies"
                                                    else permission_version)})
    binding = {"schema": "revocation-group-cache-v1", "dependencies": sorted(dependencies, key=lambda item: item["source_id"]),
               "transform_config": transform_config}
    # JSON round-trip makes the stored binding independent of caller mutation.
    return json.loads(_canonical(binding))


class RebuildCache:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise CacheIntegrityError("cache_root_not_regular_directory")
        self.root = self.root.resolve()

    @staticmethod
    def key(source_records, transform_config):
        return _hash(_canonical(_input_binding(source_records, transform_config)))

    def lookup(self, source_records, transform_config):
        binding = _input_binding(source_records, transform_config)
        cache_key = _hash(_canonical(binding))
        path = self.root / (cache_key + ".json")
        if path.is_symlink():
            raise CacheIntegrityError("cache_entry_symlink")
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            artifact = json.loads(raw)
            if not isinstance(artifact, dict):
                raise ValueError("artifact_not_object")
            checksum = artifact.pop("record_sha256")
            if checksum != _hash(_canonical(artifact)):
                raise ValueError("record_checksum_mismatch")
            artifact["record_sha256"] = checksum
            if artifact["binding"] != binding or artifact["cache_key"] != cache_key:
                raise ValueError("artifact_binding_mismatch")
            if artifact["artifact_id"] != "group-" + cache_key:
                raise ValueError("artifact_id_mismatch")
            if artifact["text_sha256"] != _hash(artifact["text"].encode("utf-8")):
                raise ValueError("artifact_body_mismatch")
            if artifact["dependencies"] != binding["dependencies"] or artifact["source_ids"] != [item["source_id"] for item in binding["dependencies"]]:
                raise ValueError("artifact_dependencies_mismatch")
            generation_epochs = artifact.get("generated_at_permission_versions")
            if generation_epochs is None:
                # Existing strict-epoch v1 artifacts already bind the generation
                # epochs in dependencies; do not invalidate those historical
                # entries or silently rewrite their checksummed provenance.
                if _reuse_mode(transform_config) != "strict_epoch":
                    raise ValueError("generation_permission_provenance_missing")
            else:
                if not isinstance(generation_epochs, dict) or set(generation_epochs) != set(artifact["source_ids"]):
                    raise ValueError("generation_permission_provenance_invalid")
                if any(not isinstance(value, (str, int)) or isinstance(value, bool) for value in generation_epochs.values()):
                    raise ValueError("generation_permission_provenance_invalid")
                if _reuse_mode(transform_config) == "strict_epoch" and generation_epochs != _permission_versions(source_records):
                    raise ValueError("generation_permission_epoch_mismatch")
            return artifact
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise CacheIntegrityError("cache_integrity_failure") from error

    def store(self, source_records, transform_config, text, receipt):
        if not isinstance(text, str) or not text.strip() or not isinstance(receipt, dict):
            raise ValueError("nonempty_output_and_receipt_required")
        binding = _input_binding(source_records, transform_config)
        cache_key = _hash(_canonical(binding))
        artifact = {"artifact_id": "group-" + cache_key, "cache_key": cache_key,
                    "binding": binding, "dependencies": binding["dependencies"],
                    "source_ids": [item["source_id"] for item in binding["dependencies"]],
                    "generated_at_permission_versions": _permission_versions(source_records),
                    "text": text, "text_sha256": _hash(text.encode("utf-8")), "receipt": receipt}
        artifact["record_sha256"] = _hash(_canonical(artifact))
        raw = _canonical(artifact)
        path = self.root / (cache_key + ".json")
        try:
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            previous = self.lookup(source_records, transform_config)
            if previous != json.loads(raw):
                raise CacheConflictError("immutable_cache_entry_conflict")
        result = self.lookup(source_records, transform_config)
        if result is None:
            raise CacheIntegrityError("cache_entry_missing_after_store")
        return result
