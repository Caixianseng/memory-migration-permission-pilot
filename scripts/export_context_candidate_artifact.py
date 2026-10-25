"""Export one verified, synthetic-only detection run; no models or credentials.

An explicit allowlist excludes runtime homes, private mappings, native-account
receipts, console logs and vendor/model assets. Reproducing the verifier needs
the matching repository revision, not execution of archived source code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "plan.json", "identities.json", "materials.json", "model_calls.json", "encoding_invocations.json",
    "unscored_rows.json", "rows.json", "report.json", "model_phase_closed.json", "score_phase_started.json",
    "network_audit.json", "independent_verification_v2.json", "verification_pre_fix_failure_v1.json",
    "role_false_positive_analysis_v1.json", "role_false_positive_analysis_v1.md",
    "development/runtime.json", "development/evaluation.json", "heldout/runtime.json", "heldout/evaluation.json",
)
SOURCES = {
    "scripts/run_context_candidate_diagnostic.py", "scripts/run_semantic_detection_benchmark.py",
    *("memory_migration_study/" + name + ".py" for name in (
        "privacy", "local_detector", "ner_detector", "candidate_proposals", "candidate_adjudicator",
        "context_candidate_typing", "context_typed_detection")),
}
SECRET = re.compile(rb"\bsk-[A-Za-z0-9_-]{24,}\b|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def export(run, output):
    run, output = Path(run).resolve(), Path(output).resolve()
    if (not run.is_relative_to((ROOT / "results").resolve())
            or not output.is_relative_to((ROOT / "benchmarks/artifacts").resolve())
            or output.suffix != ".zip" or output.exists() or output.with_suffix(".manifest.json").exists()):
        raise ValueError("new_artifact_path_required")
    verification = load(run / "independent_verification_v2.json")
    report = load(run / "report.json")
    if verification.get("status") != "passed" or report.get("version") != "context_candidate_development_v1":
        raise ValueError("matching_verified_synthetic_run_required")
    plan = load(run / "plan.json")
    source_hashes = {key.replace("\\", "/"): value for key, value in plan["implementation_sha256"].items()}
    if set(source_hashes) != SOURCES:
        raise ValueError("unexpected_frozen_sources")
    closure = load(run / "model_phase_closed.json")
    for rel, expected in closure["artifact_sha256"].items():
        if rel not in FILES or digest((run / rel).read_bytes()) != expected:
            raise ValueError("closed_artifact_changed")
    paths = [*FILES, *("frozen_source/" + rel for rel in sorted(SOURCES))]
    contents = {}
    for rel in paths:
        path = run / rel
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(run) or not path.is_file():
            raise ValueError("artifact_source_path_invalid")
        data = path.read_bytes()
        if SECRET.search(data):
            raise ValueError("possible_credential_in_export")
        contents[rel] = data
    for rel, expected in source_hashes.items():
        if digest(contents["frozen_source/" + rel]) != expected:
            raise ValueError("frozen_source_hash_mismatch")
    manifest = {"schema": "synthetic-context-candidate-artifact-v1",
        "scope": "80 exposed development + 40 exposed regression materials; negative result, not fresh acceptance",
        "contains_synthetic_originals_and_gold": True, "contains_models_or_credentials": False,
        "cloud_calls_during_experiment": 0, "method_acceptance": False,
        "verification_script_sha256": digest((ROOT / "scripts/verify_context_candidate_diagnostic.py").read_bytes()),
        "files": {rel: digest(data) for rel, data in contents.items()}}
    contents["PUBLIC_ARTIFACT_MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    contents["README.txt"] = (
        "Controlled synthetic detection experiment, 2026-10-26. Method failed its precision/recall gate.\n"
        "Original failures, raw local responses, exact scores, and frozen implementation bytes are retained.\n"
        "Extract only into a NEW results subdirectory in the matching repository revision.\n"
        "Run: python scripts/verify_context_candidate_diagnostic.py --run <new extracted directory> --output <new extracted directory>/verification_replay.json\n"
        "Verification replays recorded responses; it does not run models, use credentials, or execute archived source.\n"
        "Old heldout materials are exposed regression data, not independent acceptance. No inference-privacy proof.\n"
    ).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for rel in sorted(contents):
            archive.writestr(rel, contents[rel])
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(contents):
            raise ValueError("artifact_zip_validation_failed")
        if any(digest(archive.read(rel)) != digest(data) for rel, data in contents.items()):
            raise ValueError("artifact_roundtrip_mismatch")
    receipt = {"file": output.name, "sha256": digest(output.read_bytes()), "bytes": output.stat().st_size,
               "entry_count": len(contents), "verification_script_sha256": manifest["verification_script_sha256"],
               "method_acceptance": False, "synthetic_only": True}
    output.with_suffix(".manifest.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.run, args.output), ensure_ascii=False))
