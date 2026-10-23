"""Frozen baseline/current detection and actual payload coverage; no cloud calls."""
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
from memory_migration_study.privacy_payload_eval import evaluate_prepared_payloads
from memory_migration_study.runner import save_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--baseline-archive", type=Path, required=True)
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--detector-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    read = lambda p: json.loads(p.read_text(encoding="utf-8"))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    corpus, baseline, output = args.corpus.resolve(), args.baseline_archive.resolve(), args.output.resolve()
    manifest = read(corpus / "manifest.json")
    for item in manifest["files"].values():
        if sha(corpus / item["path"]) != item["sha256"]:
            raise ValueError("corpus_changed")
    old = read(args.baseline_manifest)
    hashes = old.get("deployment_sha256", old)
    if any(sha(baseline / name) != digest for name, digest in hashes.items()):
        raise ValueError("baseline_changed")
    output.mkdir(parents=True, exist_ok=False)
    package = Path(__file__).resolve().parents[1] / "memory_migration_study"
    archive = output / "current_implementation_at_run"
    archive.mkdir()
    current = {p.name: sha(p) for p in package.glob("*.py")}
    for p in package.glob("*.py"):
        shutil.copy2(p, archive / p.name)
    save_json(output / "plan.json", {"schema_version": 3, "corpus_manifest": manifest,
        "baseline_package_sha256": hashes, "current_package_sha256": current,
        "execution_order": ["baseline", "current"], "remote_model_calls": 0,
        "protocol": "Both code versions and data frozen before scoring; no heldout retuning; payload gold enters scoring only."})
    spec = importlib.util.spec_from_file_location("privacy_revision_baseline", baseline / "__init__.py", submodule_search_locations=[str(baseline)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    runtime, gold = read(corpus / "runtime.json"), read(corpus / "evaluation.json")
    for label, prefix in (("baseline", spec.name), ("current", "memory_migration_study")):
        core = importlib.import_module(prefix + ".privacy")
        local = importlib.import_module(prefix + ".local_detector")
        egress = importlib.import_module(prefix + ".privacy_egress")
        agent = local.LocalSensitivityAgent(read(args.detector_config))
        provenance = dict(agent.health(), model_digest=local.DIGEST, prompt_version=local.PROMPT_VERSION,
                          prompt_sha256=hashlib.sha256(local.SYSTEM_PROMPT.encode()).hexdigest(), revision=label)
        result = evaluate_corpus(corpus / "runtime.json", corpus / "evaluation.json", agent=agent,
            detector=core.detect_sensitive, detector_provenance=provenance,
            expected_heldout_cases=manifest["expected_heldout_cases"],
            cache_path=output / f"{label}_cache.json", output_path=output / f"{label}_detection.json",
            progress=lambda row: print(json.dumps(dict(row, revision=label)), flush=True))
        payloads = evaluate_prepared_payloads(runtime, gold, read(output / f"{label}_cache.json"),
                                             privacy_module=core, egress_module=egress)
        save_json(output / f"{label}_payloads.json", payloads)
        print(json.dumps({"revision": label, "gate": result["heldout_gate"], "payloads": payloads["summaries"]}), flush=True)
    if any(sha(package / name) != digest for name, digest in current.items()):
        raise ValueError("implementation_changed_during_run")
    print(json.dumps({"completed": True, "remote_model_calls": 0}), flush=True)


if __name__ == "__main__":
    main()
