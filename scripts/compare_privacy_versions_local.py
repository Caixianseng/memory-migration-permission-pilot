"""Compare a frozen v1 archive with the current code; loopback inference only."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_migration_study.privacy_corpus import evaluate_corpus
from memory_migration_study.runner import save_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--v1-archive", type=Path, required=True)
    parser.add_argument("--detector-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--current-label", default="current", help="Explicit revision label; do not label new code as a historical revision")
    args = parser.parse_args()
    corpus, output, archive = args.corpus.resolve(), args.output.resolve(), args.v1_archive.resolve()
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"].values():
        if hashlib.sha256((corpus / entry["path"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("frozen_corpus_changed")
    archive_hashes = json.loads((archive.parent / "implementation_archive_sha256.json").read_text(encoding="utf-8"))
    for name, sha in archive_hashes.items():
        if hashlib.sha256((archive / name).read_bytes()).hexdigest() != sha:
            raise ValueError("frozen_v1_implementation_changed")
    output.mkdir(parents=True, exist_ok=False)
    new_archive = output / (args.current_label + "_implementation_at_run")
    new_archive.mkdir()
    package = Path(__file__).resolve().parents[1] / "memory_migration_study"
    for source in package.glob("*.py"):
        shutil.copy2(source, new_archive / source.name)
    frozen = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    save_json(output / "comparison_plan.json", {"schema_version": 2, "remote_model_calls": 0,
        "corpus_manifest": manifest, "v1_archive_sha256": archive_hashes, "v2_package_sha256": frozen,
        "expected_heldout_cases": manifest["expected_heldout_cases"],
        "protocol": "Both implementations frozen before either sees new results; no retuning after heldout.",
        "execution_order": ["v1", args.current_label], "semantic_authorization": "not_evaluated"})
    spec = importlib.util.spec_from_file_location("privacy_frozen_v1", archive / "__init__.py",
                                                 submodule_search_locations=[str(archive)])
    old = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = old
    spec.loader.exec_module(old)
    versions = [("v1", importlib.import_module("privacy_frozen_v1.privacy"), importlib.import_module("privacy_frozen_v1.local_detector")),
                (args.current_label, importlib.import_module("memory_migration_study.privacy"), importlib.import_module("memory_migration_study.local_detector"))]
    config = json.loads(args.detector_config.read_text(encoding="utf-8"))
    for name, core, local in versions:
        agent = local.LocalSensitivityAgent(config)
        health = agent.health()
        provenance = dict(health, model_digest=local.DIGEST, prompt_version=local.PROMPT_VERSION,
                          prompt_sha256=hashlib.sha256(local.SYSTEM_PROMPT.encode()).hexdigest(), version=name)
        report = evaluate_corpus(corpus / "runtime.json", corpus / "evaluation.json", agent=agent,
                                 detector=core.detect_sensitive, detector_provenance=provenance,
                                 expected_heldout_cases=manifest["expected_heldout_cases"],
                                 cache_path=output / f"{name}_cache.json", output_path=output / f"{name}_detection.json",
                                 progress=lambda row: print(json.dumps(dict(row, version=name)), flush=True))
        print(json.dumps({"version": name, "gate": report["heldout_gate"]}), flush=True)
    if any(hashlib.sha256((package / name).read_bytes()).hexdigest() != sha for name, sha in frozen.items()):
        raise ValueError("implementation_changed_during_evaluation")
    print(json.dumps({"completed": True, "remote_model_calls": 0}), flush=True)


if __name__ == "__main__":
    main()
