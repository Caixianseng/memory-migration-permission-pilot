"""Freeze and run one bounded native span-attribute baseline, entirely offline."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_migration_study import native_span_attributes as native
from memory_migration_study.ner_detector import LocalNerRuntime, MODEL_ID, MODEL_REVISION, CODE_REVISION, file_sha
from scripts import relation_probe_scoring as original
from scripts import native_span_attribute_scoring as scoring

OLD_RUN = ROOT / "results/relation_occurrence_probe_20261027_run_01"
OLD_PLAN_SHA = "849ab4ca2cf2e4e21692b5532252f6f13c79ae0f92e320675bb2ea7286f4b8e2"
LIMITS = {"extract_calls": 12, "max_texts": 12, "max_tokens": 512, "max_candidates": 2,
          "wall_seconds": 600, "cloud_calls": 0, "native_product_calls": 0}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def sources():
    paths = list((ROOT / "memory_migration_study").glob("*.py")) + [Path(__file__),
        ROOT / "scripts/native_span_attribute_scoring.py", ROOT / "scripts/relation_probe_scoring.py",
        ROOT / "tests/test_native_span_attributes.py", ROOT / "tests/test_native_span_attribute_scoring.py"]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def plan(output):
    if not output.is_relative_to(ROOT / "results"):
        raise ValueError("output_outside_results")
    output.mkdir(parents=True, exist_ok=False)
    if sha(OLD_RUN / "plan.json") != OLD_PLAN_SHA:
        raise ValueError("previous_frozen_plan_changed")
    old = json.loads((OLD_RUN / "plan.json").read_text(encoding="utf-8"))
    fixture = ROOT / "examples/relation_occurrence_probe_20261027"
    runtime = fixture / "runtime.json"
    reference = fixture / "evaluation.json"
    if sha(runtime) != old["runtime_sha256"]:
        raise ValueError("runtime_changed")
    if sha(reference) != old["reference_opaque_sha256"]:
        raise ValueError("previous_reference_changed")
    # Reference is copied/hashed only; never parsed in this phase.
    shutil.copyfile(runtime, output / "runtime.json")
    shutil.copyfile(reference, output / "evaluation.opaque.json")
    manifest = sources()
    for name in manifest:
        dest = output / "implementation" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    value = {"schema": "native_span_attribute_probe_v1", "limits": LIMITS, "spec": native.compiled_spec(),
             "policies": old["policies"], "sources": manifest, "runtime_sha256": sha(runtime),
             "reference_sha256": sha(reference), "assets_root": str(ROOT / ".runtime/github_ner"),
             "asset_receipt_sha256": sha(ROOT / ".runtime/github_ner/receipt.json"),
             "model_id": MODEL_ID, "model_revision": MODEL_REVISION, "code_revision": CODE_REVISION,
             "prereg_sha256": sha(ROOT / "docs/原生片段属性强基线_预注册_2026-10-27.md"),
             "prior_plan_sha256": OLD_PLAN_SHA, "sample_scope": "Already-exposed 12-text development set; not holdout.",
             "reference_parsed": False, "default_changed": False}
    save(output / "plan.json", value)
    return {"status": "planned", "plan_sha256": sha(output / "plan.json"), "new_model_calls": 0}


def verify(output, expected):
    if sha(output / "plan.json") != expected:
        raise ValueError("plan_changed")
    p = json.loads((output / "plan.json").read_text(encoding="utf-8"))
    if p["limits"] != LIMITS or p["spec"] != native.compiled_spec() or p["sources"] != sources():
        raise ValueError("implementation_changed")
    for name, digest in p["sources"].items():
        if sha(output / "implementation" / name) != digest:
            raise ValueError("archive_changed")
    for name, key in (("runtime.json", "runtime_sha256"), ("evaluation.opaque.json", "reference_sha256")):
        if sha(output / name) != p[key]:
            raise ValueError("frozen_material_changed")
    if sha(Path(p["assets_root"]) / "receipt.json") != p["asset_receipt_sha256"]:
        raise ValueError("assets_receipt_changed")
    if sha(ROOT / "docs/原生片段属性强基线_预注册_2026-10-27.md") != p["prereg_sha256"]:
        raise ValueError("preregistration_changed")
    return p


def verify_assets(p):
    root = Path(p["assets_root"]).resolve()
    receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
    if (receipt.get("code_revision"), receipt.get("model_revision"), receipt.get("model_id")) != (
            CODE_REVISION, MODEL_REVISION, MODEL_ID):
        raise ValueError("asset_revision_changed")
    for name, digest in receipt["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file() or file_sha(path) != digest:
            raise ValueError("asset_content_changed")
    return len(receipt["files"])


def verify_counts(counts, *, completed, nonempty=None):
    if set(counts) != set(native.COUNTERS) or any(type(v) is not int or v < 0 for v in counts.values()):
        raise ValueError("invalid_native_counts")
    if counts["extract_invocations"] != completed or counts["encoder_forward_entries"] != completed:
        raise ValueError("native_extract_encoder_count_mismatch")
    if counts["attribute_attach_entries"] != completed:
        raise ValueError("native_attribute_count_mismatch")
    if nonempty is not None and counts["explicit_span_score_entries"] != nonempty:
        raise ValueError("native_span_score_count_mismatch")
    if any(v > completed for v in counts.values()):
        raise ValueError("native_nested_call_budget_exceeded")


def execute(output, expected):
    p = verify(output, expected)
    save(output / "execution_started.json", {"plan_sha256": expected, "reference_parsed": False})
    started = time.monotonic()
    rows, events, evidence = [], [], []
    runtime = None
    state = {"status": "started", "reference_parsed": False}

    def budget():
        if time.monotonic() - started > LIMITS["wall_seconds"]:
            raise TimeoutError("native_attribute_wall_budget")

    def capture(event):
        events.append(copy.deepcopy(event))
        save(output / ("capture_%03d.json" % len(events)), event)
        budget()

    with patch("socket.create_connection", side_effect=RuntimeError("network_forbidden")) as connect, \
         patch("socket.socket.connect", side_effect=RuntimeError("network_forbidden")) as sock, \
         patch("urllib.request.urlopen", side_effect=RuntimeError("network_forbidden")) as url:
        try:
            import torch
            torch.set_num_threads(2)
            if torch.get_num_interop_threads() != 2:
                torch.set_num_interop_threads(2)
            torch.manual_seed(42)
            ner = LocalNerRuntime(p["assets_root"], threads=2)
            runtime = native.NativeSpanAttributeRuntime(ner, max_extracts=12, on_capture=capture)
            data = json.loads((output / "runtime.json").read_text(encoding="utf-8"))
            texts = data["texts"]
            if data["schema_version"] != "relation_occurrence_probe_runtime_v1" or len(texts) != 12:
                raise ValueError("runtime_schema_changed")
            preflight = [runtime.preflight(text) for text in texts]
            save(output / "preflight.json", preflight)
            save(output / "identity.json", ner.identity)
            verify_counts(runtime.snapshot_counts(), completed=0, nonempty=0)
            budget()
            if not all(item["fits"] for item in preflight):
                state.update(status="preflight_blocked", new_model_calls=0)
                return state
            for index, text in enumerate(texts):
                verify(output, expected)
                budget()
                item = runtime.infer(text)
                evidence.append(item)
                verify_counts(runtime.snapshot_counts(), completed=index+1,
                              nonempty=sum(bool(e["entities"]) for e in evidence))
                save(output / ("evidence_%02d.json" % index), item)
                for profile in original.PROFILES:
                    response = native.decide(text, p["policies"][profile], item)
                    status = native.observation_status(response, item)
                    if status == "engineering_error":
                        raise RuntimeError("native_attribute_engineering_error")
                    row = {"cell": {"text_index": index, "profile": profile, "arm": scoring.ARM},
                           "response": response, "status": status,
                           "preparation": original.prepare_observation(text, p["policies"][profile], response)}
                    rows.append(row)
                    save(output / ("row_%02d.json" % (len(rows)-1)), row)
                print(json.dumps({"texts_completed": index+1, "rows": len(rows), "counts": runtime.snapshot_counts()}), flush=True)
            save(output / "predictions.json", rows)
            save(output / "shared_evidence.json", evidence)
            verify(output, expected)
            counts = runtime.snapshot_counts()
            verify_counts(counts, completed=12, nonempty=sum(bool(e["entities"]) for e in evidence))
            verified_assets = verify_assets(p)
            budget()
            closure = {"plan_sha256": expected, "predictions_sha256": sha(output / "predictions.json"),
                       "evidence_sha256": sha(output / "shared_evidence.json"), "counts": counts,
                       "capture_count": len(events), "reference_parsed": False, "verified_asset_files": verified_assets,
                       "capture_sha256": {path.name: sha(path) for path in sorted(output.glob("capture_*.json"))},
                       "network_attempts": connect.call_count + sock.call_count + url.call_count}
            if closure["network_attempts"]:
                raise RuntimeError("unexpected_network_attempt")
            save(output / "prediction_phase_closed.json", closure)
            # FIRST parse of evaluation reference, after predictions and preparations are sealed.
            reference = json.loads((output / "evaluation.opaque.json").read_text(encoding="utf-8"))
            state["reference_parsed"] = True
            scored = scoring.score_rows(rows, reference, texts)
            save(output / "scored_rows.json", scored["scored_rows"])
            verify(output, expected)
            if (sha(output / "predictions.json") != closure["predictions_sha256"]
                    or sha(output / "shared_evidence.json") != closure["evidence_sha256"]
                    or any(sha(output / name) != digest for name, digest in closure["capture_sha256"].items())):
                raise RuntimeError("closed_predictions_changed")
            report = {"schema": "native_span_attribute_result_v1", "status": "complete", "texts": 12,
                      "opportunities": 24, "counts": counts, "by_profile_arm": scored["by_profile_arm"],
                      "plan_sha256": expected, "predictions_sha256": closure["predictions_sha256"],
                      "closure_sha256": sha(output / "prediction_phase_closed.json"), "network_attempts": 0,
                      "cloud_calls": 0, "qwen_calls": 0, "nli_calls": 0, "native_product_calls": 0,
                      "default_changed": False, "wall_seconds": time.monotonic() - started,
                      "scope": "Existing API strong baseline on exposed development data; no innovation or holdout claim."}
            save(output / "report.json", report)
            state.update(status="complete", counts=counts)
            return report
        except Exception as error:
            state.update(status="stopped", error_type=type(error).__name__, error=str(error))
            raise
        finally:
            state.update(rows=len(rows), counts=runtime.snapshot_counts() if runtime is not None else None,
                         network_attempts=connect.call_count+sock.call_count+url.call_count,
                         wall_seconds=time.monotonic()-started)
            save(output / "execution_final.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan-only", action="store_true")
    modes.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-plan-sha")
    args = parser.parse_args()
    result = plan(args.output.resolve()) if args.plan_only else execute(args.output.resolve(), args.expected_plan_sha)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") in {"stopped", "preflight_blocked"}:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
