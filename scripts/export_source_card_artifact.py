"""Export one audited, hand-authored synthetic development run; never arbitrary logs.

Standard library only. No client, model, credential, or network access. Frozen
original byte hashes deliberately make this a single-batch exporter, not a way
to publish other memories. The resulting material is linkable synthetic data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "source_card_synthetic_artifact_export_v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
VERIFIER_SHA256 = "d92892dd656df0d9f2a33bbbce19ec546bff7507ef12bd7496a5c165f153b9b2"
RAW_HASHES = {
    "annotations.json": "d0ecb19a96125da6c5d4cff41b893678674937e151cdec1c228b912a8d044f1b",
    "auth_events.json": "90d4fdc04e2e387b5037a9be6992852514582dc4e772928ce13dbbd5cb09bfca",
    "builds.json": "a426c3eb6bf7ded314dbb5c97d6199a06e3b9b217dc62cbdce3ca46fece7804a",
    "config.json": "590c204ab3960569aead29d308557085d9a13973f2bdc13965d6cba68a61fd21",
    "evaluation.json": "ac82c3d995e44401b336c25861f44222a4ff09c0a2394dbef6823a8ee974978e",
    "network_audit.json": "342e5a55f41e557dceadb48b464d429b4359187b636578cac75474bc6263b2ef",
    "plan.json": "1fa38089b5fc7d0542aee51e8d1839e98565f583207074a2ab4d71e6358a18b8",
    "pools.json": "af574d7d5942893072da8dbf67a0c5c62e65c05617a0a901eb32c677ea925757",
    "query_encoder_events.json": "d75a1541c709cfeab9f7b6b22a8e66d8cf82df41764a09c0a00e8985b5747814",
    "record_store.json": "006bf8496fda8bf6d9f4c7bb9b147ff1e6018149b904eb9f601150f1a07d43a4",
    "report.json": "0562977c9d2c249c798c86294f99def94054eff54dd5b7a2b1006118871590f5",
    "request_transport.jsonl": "59a9cbcdd8b476ef7ca4393e47da9cbf6713dc611c8028413de1d9b3843c9be1",
    "rows.json": "7aa979683031bd87c0d24136c3b6d276a2f4f526111d81cb3676ddc8e4382198",
    "runtime.json": "f95e8f462fbf4e0256163d672665256b6983c69c5780e21e3262b74a42d253db",
    "runtime_identity.json": "64a78281448039aa70dab2ff446a887b5928f91ee36bbcf7a52e865a02614629",
    "shared_contexts.json": "6d4630ffc9b7e1022326dfad691b607243285fd021bd91383071f6f738e43dcc",
    "source_card_sets.json": "16f543a809cd9bda83c70734c8733c28c283672486330c4e380f23aa4d79be5e",
    "transport_audit.json": "40fd47489911373bb6a8975170a2015e1a6996276fc76e920d8016cded9a73b5",
    "independent_source_card_verification_v1.json": "aec000a09f51965ed6c1a060580be0f6dbee7ee857c3266ad594db4e2d533534",
    "independent_source_card_verification_v2.json": "5cdd99f5d536f029171ad4693b3a0f2219c15a184a6b59f18f335a33c1e05fed",
    "independent_source_card_verification_v3.json": "34bd1db6debd2e2ca81474fc1df9a6b3f6c9876d19cceeb39d3c96f8c0e5dd03",
}
PUBLIC_HASHES = {
    "examples/privacy_semantics_v1/README.md": "03adc28434b5449a7466629705a5bb153ab5068b6aa8162b8b567e48c9326b97",
    "examples/privacy_semantics_v1/development/runtime.json": "22647d2e6e813ee094fe94609d6eb0804308d887059fb64e2331c9195e6e15f4",
    "examples/privacy_semantics_v1/development/evaluation.json": "acb8b84664876f14cd6b788bfb32ad7600060cda3377d0681d6c305f4b23a98c",
    "configs/local_privacy_detector.json": "840715dc542f7acde4f0afca87b20df6b55aef78dccc0efc613cf1a969bd27a1",
}
FORBIDDEN_KEYS = frozenset({"mapping", "restoration_map", "_entries", "hmac_key", "secret", "api_key",
    "authorization", "credentials", "auth_env", "password", "access_token", "refresh_token"})
SECRET = re.compile(r"\bsk-[A-Za-z0-9]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
HOST_PATH = re.compile(r"(?:^|[\s\"'])(?:[A-Za-z]:[\\/]|/(?:home|Users)/)|\\\\Users\\", re.MULTILINE)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse(data: bytes):
    return json.loads(data, object_pairs_hook=no_duplicates,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def relative_name(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(p in {".", ".."} for p in path.parts) or "\\" in value or ":" in value:
        raise ValueError("unsafe_archive_member")
    return path.as_posix()


def read_bound(base: Path, name: str, expected: str | None = None) -> bytes:
    relative_name(name)
    if base.is_symlink() or getattr(base, "is_junction", lambda: False)():
        raise ValueError("linked_input_forbidden")
    base = base.resolve(strict=True)
    candidate = base / name
    for part in (candidate, *candidate.parents):
        if part == base.parent:
            break
        if part.is_symlink() or (getattr(part, "is_junction", lambda: False)()):
            raise ValueError("linked_input_forbidden")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("bounded_regular_input_required")
    value = resolved.read_bytes()
    if expected is not None and sha(value) != expected:
        raise ValueError("frozen_input_sha256_mismatch:" + name)
    return value


def inspect_json(value):
    """Reject publication of secret-bearing objects or concrete host paths."""
    if isinstance(value, dict):
        if FORBIDDEN_KEYS.intersection(str(k).lower() for k in value):
            raise ValueError("private_object_key_forbidden")
        for item in value.values():
            inspect_json(item)
    elif isinstance(value, list):
        for item in value:
            inspect_json(item)
    elif isinstance(value, str):
        if SECRET.search(value) or HOST_PATH.search(value):
            raise ValueError("secret_or_host_path_forbidden")


def validate_synthetic_binding(objects: dict, public: dict):
    runtime = parse(public["examples/privacy_semantics_v1/development/runtime.json"])
    evaluation = parse(public["examples/privacy_semantics_v1/development/evaluation.json"])
    if runtime != objects["runtime.json"] or evaluation != objects["evaluation.json"] or len(runtime) != 8:
        raise ValueError("public_corpus_binding_failed")
    stories = {s["story_id"]: s for s in runtime}
    store = objects["record_store.json"]
    if {s["story_id"] for s in store} != set(stories):
        raise ValueError("record_story_binding_failed")
    for group in store:
        original = stories[group["story_id"]]["source"]
        for record in group["records"]:
            source = record["source"]
            if source["source_id"] != original["source_id"] or source["text"] != original["text"] or source["sha256"] != sha(original["text"].encode()):
                raise ValueError("nonpublic_record_source")
            start, end = record["source_start"], record["source_end"]
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(original["text"]) or original["text"][start:end] != record["text"]:
                raise ValueError("nonexact_synthetic_fact")
    # The additional control is frozen in the approved, byte-pinned plan.
    missing = objects["plan.json"]["missing_control"]["queries"]
    for context in objects["shared_contexts.json"]:
        story = stories[context["story_id"]]
        expected = {t["task_id"]: t["query"] for t in story["tasks"]}
        expected["missing_contact_email_control"] = missing[story["language"]]
        if context["original_query"] != expected[context["task_id"]]:
            raise ValueError("nonpublic_query")
    receipt = objects["independent_source_card_verification_v3.json"]
    if receipt["status"] != "passed" or receipt["verification_model_calls"] != 0 or not receipt["checks"] or not all(c["passed"] is True for c in receipt["checks"]):
        raise ValueError("independent_offline_receipt_required")


def qualify_export(repo: Path, run: Path):
    """Return a complete explicit byte manifest in memory; do not create files."""
    repo = repo.resolve(strict=True)
    run = run.resolve(strict=True)
    if not run.is_relative_to(repo / "results") or run == repo / "results":
        raise ValueError("run_must_be_project_results_child")
    files, provenance, objects = {}, {}, {}
    for name, expected in RAW_HASHES.items():
        original = read_bound(run, name, expected)
        value = [parse(line) for line in original.splitlines()] if name.endswith(".jsonl") else parse(original)
        if name == "transport_audit.json":
            # Explicit derived copy: omit only these two unused host metadata fields.
            if set(value).intersection({"python_executable", "python_version"}) != {"python_executable", "python_version"}:
                raise ValueError("host_metadata_schema_changed")
            value = {k: v for k, v in value.items() if k not in {"python_executable", "python_version"}}
            exported = json_bytes(value)
        else:
            exported = original
        inspect_json(value)
        objects[name] = value
        target = "run/" + name
        files[target] = exported
        provenance[target] = {"source": "registered_run/" + name, "original_sha256": sha(original),
            "exported_sha256": sha(exported), "transformation": "remove_python_executable_and_python_version" if exported != original else "byte_exact"}
    public = {name: read_bound(repo, name, expected) for name, expected in PUBLIC_HASHES.items()}
    for name, value in public.items():
        if name.endswith(".json"):
            inspect_json(parse(value))
        files["source/" + name] = value
        provenance["source/" + name] = {"source": "public_repository/" + name, "original_sha256": sha(value), "exported_sha256": sha(value), "transformation": "byte_exact"}
    validate_synthetic_binding(objects, public)
    plan = objects["plan.json"]
    if len(plan["implementation_sha256"]) != 50:
        raise ValueError("registered_dependency_count_changed")
    for name, expected in plan["implementation_sha256"].items():
        name = relative_name(name)
        if not name.endswith(".py") or not name.startswith(("memory_migration_study/", "scripts/")):
            raise ValueError("unexpected_implementation_member")
        data = read_bound(run / "implementation", name, expected)
        target = "run/implementation/" + name
        files[target] = data
        provenance[target] = {"source": "executed_archive/" + name, "original_sha256": expected, "exported_sha256": expected, "transformation": "byte_exact"}
    files["approved-plan.json"] = files["run/plan.json"]
    verifier = read_bound(repo, "scripts/verify_source_card_reader.py", VERIFIER_SHA256)
    files["verification/verifier.py"] = verifier
    files["verification/exporter.py"] = read_bound(repo, "scripts/export_source_card_artifact.py")
    files["README.md"] = README.encode("utf-8")
    manifest = {"version": VERSION, "scope": "One exposed eight-story hand-authored synthetic development run; linkable, not anonymized.",
        "model_calls_during_export": 0, "credentials_read": False, "raw_restore_map_exported": False, "HMAC_secret_exported": False,
        "original_HMAC_signatures_offline_reverifiable": False, "original_map_object_identity_offline_reverifiable": False,
        "qualification": "Exact public corpus bytes, pinned run hashes, exact source spans, frozen 50 source bytes, successful zero-model saved-evidence verifier receipt. Not protection against coordinated artifact forgery.",
        "omitted": ["arbitrary results tree", "index.html", "service logs", "private maps/tables/keys", "credentials", "runtime downloads", "transport audit host executable/version"],
        "provenance": provenance, "files": {n: {"sha256": sha(v), "bytes": len(v)} for n, v in sorted(files.items())}}
    files["manifest.json"] = json_bytes(manifest)
    return files, manifest


README = """# Source fact card reader: public synthetic development artifact

This package is one hand-authored synthetic development run, not anonymized
private memory. It contains original synthetic sources, PVT-bearing requests,
raw local model responses and final synthetic answers; these are linkable.

Legal joint results: F 28/32 (strict raw 24/32), Flat-ID 31/32, Source-ID 32/32.
Source-ID gains only one task in one story over the strong Flat-ID baseline.
All arms: 8/8 genuine missing-information UNKNOWN; 8/8 outsiders blocked before
models. One execution, exposed development stories; no generalization, stable
advantage, statistical significance, algorithm novelty or semantic privacy claim.
146 local generation posts (8 build + 18 labels + 120 answers), 76 encoder calls.
Fresh64 was not opened. Export and offline replay make no model calls.

Run from any directory with standard Python:

    python verification/verifier.py --input-root . --output offline_receipt.json

Use a new output filename. The verifier disables network/model execution, loads
the exact archived pure modules, reconstructs source ranges and equivalent
masked projections under a temporary authority, and recomputes saved metrics.
Original HMAC keys, map objects and Python object identity were intentionally
not preserved: this cannot independently verify the original process HMAC
signatures or provide tamperproof execution attestation. Journal/hash consistency
cannot defeat coordinated forgery. Original failed v1 and successful v2/v3
verification receipts are retained; the v1 metadata interpretation was corrected
without changing experimental artifacts. The current verifier adds import-origin
checking and supports this package layout.

manifest.json lists exact bytes and explicit provenance. Only transport_audit.json
is derived: its host executable and Python build metadata are omitted; original
and exported SHA256 values remain in the manifest. No key, RestorationMap, Entry,
user directory, credential or arbitrary result directory is exported.
"""


def export_artifact(repo: Path, run: Path, output: Path):
    files, manifest = qualify_export(repo, run)
    repo = repo.resolve(strict=True)
    output = output.resolve()
    archive = output.with_suffix(".zip")
    allowed = any(output.is_relative_to(repo / parent) and output != repo / parent for parent in ("results", "artifacts"))
    if not allowed or output.suffix or output.exists() or archive.exists():
        raise ValueError("new_extensionless_results_or_artifacts_child_required")
    parent = output.parent
    if parent.exists() and (parent.is_symlink() or getattr(parent, "is_junction", lambda: False)()):
        raise ValueError("linked_output_forbidden")
    output.mkdir(parents=True, exist_ok=False)
    for name, value in sorted(files.items()):
        path = output / relative_name(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(value)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, value in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 26, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, value, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return {"status": "exported", "directory": output.relative_to(repo).as_posix(), "archive": archive.relative_to(repo).as_posix(),
        "archive_sha256": sha(archive.read_bytes()), "files": len(files), "model_calls": 0,
        "manifest_sha256": sha(files["manifest.json"]), "source_stories": 8}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if args.check_only:
        files, _ = qualify_export(ROOT, args.run)
        result = {"status": "qualified", "files": len(files), "bytes": sum(map(len, files.values())), "model_calls": 0}
    elif args.output is None:
        parser.error("--output is required unless --check-only")
    else:
        result = export_artifact(ROOT, args.run, args.output)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
