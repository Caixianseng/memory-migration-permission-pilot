"""Explicit synthetic flat/GLiClass research export; never traverses results.

No models, credentials, restoration maps, session files or archived code are
executed. Every entry comes from a named allowlist or a predeclared source-path
set, with original bytes/hashes preserved. The earlier public source archive
remains an external repository dependency rather than a nested duplicate ZIP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = "330d31c9e70980631dd3b67dc8a059512af77693e39870c2b8570b696effce43"
COMMON = ("plan.json", "identities.json", "materials.json", "reference_materials.json", "unscored_rows.json", "rows.json",
          "report.json", "model_phase_closed.json", "score_phase_started.json", "network_audit.json",
          "development/runtime.json", "development/evaluation.json", "heldout/runtime.json", "heldout/evaluation.json")
FLAT_FILES = (*COMMON, "model_calls.json", "independent_decision_verification_v1.json")
GLIC_FILES = (*COMMON, "qualification.json", "encoder_calls.json", "independent_gliclass_verification_v1.json",
              "independent_gliclass_verification_v2.json")
FLAT_MODULES = ("privacy", "local_detector", "ner_detector", "candidate_proposals", "candidate_adjudicator", "context_candidate_typing",
    "context_typed_detection", "boundary_detector", "boundary_reconciliation", "structured_candidates", "amount_candidates",
    "candidate_decision", "candidate_decision_detection")
GLIC_MODULES = ("gliclass_candidate", "candidate_decision", "candidate_proposals", "candidate_adjudicator", "privacy", "local_detector",
                "boundary_detector", "boundary_reconciliation", "structured_candidates", "amount_candidates")
COMMON_RUNNERS = ("run_candidate_decision_diagnostic", "run_context_candidate_diagnostic", "run_semantic_detection_benchmark")
SOURCE_PATHS = {
    "flat": {*("memory_migration_study/" + name + ".py" for name in FLAT_MODULES), *("scripts/" + name + ".py" for name in COMMON_RUNNERS)},
    "gliclass": {*("memory_migration_study/" + name + ".py" for name in GLIC_MODULES),
                 *("scripts/" + name + ".py" for name in (*COMMON_RUNNERS, "run_gliclass_candidate_diagnostic"))},
}
AUDIT = {"flat": ("verify_candidate_decision_diagnostic", "verify_context_candidate_diagnostic"),
         "gliclass": ("verify_gliclass_candidate_diagnostic", "verify_candidate_decision_diagnostic", "verify_context_candidate_diagnostic")}
FORBIDDEN_FIELDS = frozenset({"api_key", "access_token", "refresh_token", "authorization", "private_key", "signing_key",
                               "restoration_map", "restoration_mapping", "mapping"})


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path and path.is_relative_to(ROOT), "linked_or_external_source")
    return path.read_bytes()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def scan(raw, suffix):
    require(suffix in {".json", ".py", ".md"}, "unapproved_export_extension")
    text = raw.decode("utf-8")
    require(not re.search(r"\bsk-[A-Za-z0-9_-]{20,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", text),
            "credential_shape_detected")
    if suffix == ".json":
        stack = [strict_json(raw)]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                require(not {str(key).lower() for key in item} & FORBIDDEN_FIELDS, "credential_or_restoration_field_detected")
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)


def collect(flat, gliclass, preflight):
    entries, source_refs, verification = {}, {}, {}
    for group, directory, names in (("flat", flat, FLAT_FILES), ("gliclass", gliclass, GLIC_FILES)):
        directory = Path(directory).resolve(strict=True)
        require(directory.is_relative_to(ROOT / "results"), "result_source_scope")
        blobs = {name: regular(directory / name) for name in names}
        plan, closure = strict_json(blobs["plan.json"]), strict_json(blobs["model_phase_closed.json"])
        require(closure.get("model_phase_closed") is True, "model_phase_not_closed")
        require(plan["reference"]["archive_sha256"] == SOURCE_SHA256, "source_archive_registration_mismatch")
        archive_path = ROOT / plan["reference"]["archive"].replace("\\", "/")
        require(sha(regular(archive_path)) == SOURCE_SHA256, "source_archive_changed")
        for name, expected in closure["artifact_sha256"].items():
            require(name in blobs and sha(blobs[name]) == expected, "closed_artifact_changed:" + name)
        for name in ("development/runtime.json", "development/evaluation.json", "heldout/runtime.json", "heldout/evaluation.json"):
            require(sha(blobs[name]) == plan["reference"]["corpus_sha256"][name], "corpus_changed:" + name)
        source_hashes = {name.replace("\\", "/"): value for name, value in plan["implementation_sha256"].items()}
        require(set(source_hashes) == SOURCE_PATHS[group], "source_path_allowlist_changed")
        for name in sorted(SOURCE_PATHS[group]):
            raw = regular(directory / "frozen_source" / name)
            require(sha(raw) == source_hashes[name], "frozen_source_changed:" + name)
            blobs["frozen_source/" + name] = raw
        for name in AUDIT[group]:
            blobs["audit_source/scripts/" + name + ".py"] = regular(ROOT / "scripts" / (name + ".py"))
        for name, raw in blobs.items():
            scan(raw, PurePosixPath(name).suffix)
            entries[group + "/" + name] = raw
        receipt_name = "independent_decision_verification_v1.json" if group == "flat" else "independent_gliclass_verification_v2.json"
        receipt = strict_json(blobs[receipt_name])
        require(receipt.get("status") == "passed" and receipt.get("verification_model_calls") == 0, "independent_receipt_not_passed")
        if group == "flat":
            count = len(receipt["checks"])
            require(count == 2557 and all(item["passed"] for item in receipt["checks"]), "flat_check_count_or_failure")
        else:
            count = receipt["check_count"]
            require(count == 1117 and receipt.get("verification_network_attempts") == 0, "gliclass_check_count_or_network")
        verification[group] = {"receipt": group + "/" + receipt_name, "status": "passed", "checks": count,
                               "sha256": sha(blobs[receipt_name]), "scope": "saved-observation consistency, not method acceptance"}
        source_refs[group] = {"source_result_dir": str(directory.relative_to(ROOT)), "source_archive": str(archive_path.relative_to(ROOT)),
                              "source_archive_sha256": SOURCE_SHA256}
    prior = regular(Path(preflight).resolve(strict=True) / "plan.json")
    prior_plan, execution = strict_json(prior), strict_json(entries["gliclass/plan.json"])
    for field in ("schedule", "reference", "reference_flat", "implementation_sha256", "max_encoder_forwards", "max_root_forwards"):
        require(prior_plan[field] == execution[field], "preflight_binding_changed:" + field)
    scan(prior, ".json");entries["gliclass/preflight_plan.json"] = prior
    return entries, source_refs, verification


README = """# Candidate classifier diagnostic artifact

`flat/` preserves the four-condition flat classifier experiment (840 rows,
324 local generations). `gliclass/` preserves the three-arm comparison (360
rows, 111 new CPU encoder forwards). Both reuse the same 80 exposed development
and 40 exposed regression materials. They are negative development results;
default methods were not changed and no speed or novel privacy claim follows.

Models, credentials, restoration maps and recursive results snapshots are not
included. All entries are explicit allowlisted original bytes. Frozen source
comes from each pre-execution plan; audit_source is the current independent
verifier source and is not retroactively preregistered experiment code.

Use these artifacts in the matching project checkout. The existing public
`benchmarks/artifacts/context_candidate_detection_20261026_v2.zip` remains a
required external source dependency, SHA256:
`330d31c9e70980631dd3b67dc8a059512af77693e39870c2b8570b696effce43`.
It is not duplicated inside this ZIP. The included runtime/evaluation files are
synthetic originals from that already public artifact, not newly independent data.

After unpacking into a NEW directory below project/results, run the repository
verifiers (not automatically executing archived code). For UNPACK=that directory:

```powershell
python scripts/verify_candidate_decision_diagnostic.py --run UNPACK/flat --output UNPACK/flat/recheck_flat.json
python scripts/verify_gliclass_candidate_diagnostic.py UNPACK/gliclass --flat-reference UNPACK/flat --preflight-plan UNPACK/gliclass/preflight_plan.json --output UNPACK/gliclass/recheck_gliclass.json
```

These are zero-model saved-response/token/logit checks. Token replay does not
independently rerun tokenization or weights; process hook counts are not hardware
attestation. The original passed receipts report 2557 and 1117 checks.
"""


def export(flat, gliclass, preflight, output):
    output = Path(output).absolute()
    allowed = (ROOT / "benchmarks/artifacts").resolve()
    require(output.parent.resolve() == allowed and output.suffix == ".zip" and not output.exists()
            and not output.with_suffix(".manifest.json").exists() and output.resolve(strict=False) == output, "new_artifact_path_required")
    entries, source_refs, verification = collect(flat, gliclass, preflight)
    entries["README.md"] = README.encode("utf-8")
    manifest = {"schema": "synthetic-candidate-classifier-artifact-v1", "source_refs": source_refs, "verification": verification,
        "contains_synthetic_originals_and_gold": True, "contains_models_or_credentials_or_restoration_maps": False,
        "cloud_calls_during_export": 0, "method_acceptance": False, "default_changed": False,
        "exporter_sha256": sha(Path(__file__).read_bytes()),
        "files": {name: {"sha256": sha(raw), "bytes": len(raw)} for name, raw in sorted(entries.items())}}
    entries["PUBLIC_ARTIFACT_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(entries.items()):
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and ".." not in relative.parts and not any(part in {".runtime", ".git", "models", "credentials"} for part in relative.parts),
                    "forbidden_archive_path")
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 26, 0, 0, 0));info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3;info.external_attr = 0o100644 << 16
            archive.writestr(info, raw, compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        require(set(archive.namelist()) == set(entries), "archive_entry_set_changed")
        for name, raw in entries.items():
            require(sha(archive.read(name)) == sha(raw), "archive_bytes_changed:" + name)
    receipt = {"schema": manifest["schema"], "path": str(output.relative_to(ROOT)), "bytes": output.stat().st_size,
        "sha256": sha(regular(output)), "entries": len(entries), "manifest_sha256": sha(entries["PUBLIC_ARTIFACT_MANIFEST.json"]),
        "source_archive_sha256": SOURCE_SHA256, "verification": verification, "explicit_allowlist": True,
        "model_calls": 0, "models_or_credentials_or_restoration_maps": False}
    output.with_suffix(".manifest.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return receipt


def unpack_checked(archive, destination):
    destination = Path(destination).absolute()
    require(not destination.exists() and destination.resolve(strict=False) == destination
            and destination.is_relative_to(ROOT / "results"), "new_unpack_directory_required")
    with zipfile.ZipFile(archive) as source:
        manifest = strict_json(source.read("PUBLIC_ARTIFACT_MANIFEST.json"))
        require(set(source.namelist()) == set(manifest["files"]) | {"PUBLIC_ARTIFACT_MANIFEST.json"}, "unexpected_archive_member")
        destination.mkdir(parents=True)
        for name in source.namelist():
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and ".." not in relative.parts, "unsafe_unpack_path")
            target = destination.joinpath(*relative.parts)
            require(target.resolve(strict=False).is_relative_to(destination), "unsafe_unpack_target")
            raw = source.read(name)
            if name != "PUBLIC_ARTIFACT_MANIFEST.json":
                expected = manifest["files"][name]
                require(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"], "unpack_hash_mismatch")
            target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(raw)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flat", type=Path, default=ROOT / "results/flat_candidate_detection_20261026_v1")
    parser.add_argument("--gliclass", type=Path, default=ROOT / "results/gliclass_candidate_detection_20261026_v1")
    parser.add_argument("--preflight", type=Path, default=ROOT / "results/gliclass_candidate_plan_20261026_v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--unpack", type=Path)
    args = parser.parse_args()
    receipt = export(args.flat, args.gliclass, args.preflight, args.output)
    if args.unpack:
        receipt["unpacked"] = str(unpack_checked(args.output, args.unpack))
    print(json.dumps(receipt, ensure_ascii=False))
