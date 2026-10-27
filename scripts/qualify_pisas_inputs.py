"""Fetch pinned public DATA and qualify source/evaluation separation offline.

Independent implementation; does not import the upstream evaluation code, run
models, or use reference visibility as runtime authorization.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REVISION = "8a1ba30ba210d4a430bbd25cf4a3500d0e22c5b9"
BASE = "https://huggingface.co/datasets/ServiceNow/PiSAs/resolve/" + REVISION + "/"
TASKS = ("JIRA_allocation", "meeting_allocation", "severity_classification", "inpatient_discharge",
         "thesis_readiness", "manuscript_submission", "uas_flight_readiness", "outgoing_museum_loan", "special_event_permit_readiness")
NAMES = ("scenario.json", "utility.json", "appropriateness.json", "visibility.json")
DATA = ROOT / ".runtime/pisas_qualification_20261027"


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    return sha_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(524289)
    if len(raw) > 524288:
        raise ValueError("download_file_budget_exceeded")
    return raw


def download(*, resume=False):
    DATA.mkdir(parents=True, exist_ok=resume)
    if (DATA / "receipt.json").exists():
        raise ValueError("completed_download_must_not_be_restarted")
    raw = fetch("https://huggingface.co/api/datasets/ServiceNow/PiSAs/revision/" + REVISION + "?blobs=true")
    meta = json.loads(raw)
    if meta.get("sha") != REVISION or meta.get("cardData", {}).get("license") != "apache-2.0":
        raise ValueError("dataset_revision_or_license_changed")
    with (DATA / "pinned_blob_metadata.json").open("xb") as stream:
        stream.write(raw)
    selected = [f"{task}/scenario_01/{name}" for task in TASKS for name in NAMES] + ["README.md"]
    remote = {entry["rfilename"]: entry for entry in meta["siblings"]}
    if not set(selected) <= set(remote):
        raise ValueError("documented_sample_missing")
    receipt = {"dataset": "ServiceNow/PiSAs", "revision": REVISION, "license": "apache-2.0",
               "selection": "scenario_01 of each of the nine documented tasks, fixed before annotation parsing",
               "files": {}, "new_model_calls": 0, "metadata_sha256": sha_bytes(raw), "resumed_partial_download": resume,
               "prior_attempt_requests": None if resume else 0,
               "prior_attempt_note": "Previous process terminated at download_path_escape; original partial files preserved and independently checked against pinned Git blob IDs." if resume else None}
    # Materialize directories before concurrent resolves. Every final path is
    # still checked against one resolved root; containment is never bypassed.
    (DATA / "data").mkdir(exist_ok=True)
    target_root = (DATA / "data").resolve()
    for relative in selected:
        path = DATA / "data" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.resolve().is_relative_to(target_root):
            raise ValueError("download_path_escape")
    fetched, reused = [], []
    def one(relative):
        path = DATA / "data" / relative
        if not path.resolve().is_relative_to(target_root):
            raise ValueError("download_path_escape")
        if path.exists():
            if not resume:
                raise ValueError("unexpected_existing_download")
            content = path.read_bytes()
            reused.append(relative)
        else:
            fetched.append(relative)
            content = fetch(BASE + relative)
        expected = remote[relative]
        blob = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
        if expected.get("lfs") or expected.get("size") != len(content) or expected.get("blobId") != blob:
            raise ValueError("download_remote_blob_mismatch")
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(content)
        return relative, {"sha256": sha_bytes(content), "git_blob_sha1": blob, "bytes": len(content), "url": BASE + relative}
    with ThreadPoolExecutor(max_workers=4) as executor:
        for relative, info in executor.map(one, selected):
            receipt["files"][relative] = info
    receipt["download_requests_this_attempt"] = 1 + len(fetched)
    receipt["reused_files_verified_against_remote_blob"] = len(reused)
    receipt["download_bytes"] = sum(x["bytes"] for x in receipt["files"].values()) + len(raw)
    if receipt["download_bytes"] > 8_000_000:
        raise ValueError("download_total_budget_exceeded")
    save(DATA / "receipt.json", receipt)
    return {"status": "downloaded", "revision": REVISION, "files": len(selected), "bytes": receipt["download_bytes"],
            "receipt_sha256": sha_bytes((DATA / "receipt.json").read_bytes()), "new_model_calls": 0}


def load_inputs():
    receipt = json.loads((DATA / "receipt.json").read_text(encoding="utf-8"))
    if receipt["revision"] != REVISION:
        raise ValueError("receipt_revision_changed")
    for relative, info in receipt["files"].items():
        path = (DATA / "data" / relative).resolve()
        if not path.is_relative_to((DATA / "data").resolve()) or sha_bytes(path.read_bytes()) != info["sha256"]:
            raise ValueError("dataset_bytes_changed")
    return receipt


def audit_annotations(source, utility, appropriateness, visibility):
    """Reference-only audit. Never supplies runtime inputs or authorization."""
    attrs, app, vis = utility["attribute_values"], appropriateness["attributes"], visibility["attributes"]
    if not all(isinstance(x, dict) for x in (attrs, app, vis)):
        raise ValueError("invalid_reference_shape")
    raw_cast = source["cast"]
    cast = list(raw_cast.values()) if isinstance(raw_cast, dict) else raw_cast
    names = {x["name"] for x in cast}
    timeline = {x["id"]: x for x in source["timeline"]}
    problems, declared, literal = [], set(), set()
    declared_assessed, literal_assessed, missing_carriers = [], [], []
    unmapped_principals = {}
    attribute_ids_agree = set(attrs) == set(app) == set(vis)
    if not attribute_ids_agree:
        problems.append("attribute_ids_differ")
    if any(x.get("scenario_id") != source.get("scenario_id") for x in (utility, appropriateness, visibility)):
        problems.append("scenario_id_mismatch")
    if utility.get("oracle_answer") not in utility.get("allowed_answers", []):
        problems.append("oracle_not_in_answer_space")
    counts = {"appropriate": 0, "inappropriate": 0, "other_label": 0, "nonliteral_reference_values": 0}
    for aid in sorted(set(attrs) & set(app) & set(vis)):
        item, rule = attrs[aid], vis[aid]
        counts[app[aid] if app[aid] in {"appropriate", "inappropriate"} else "other_label"] += 1
        allowed, hidden = set(rule["visible_to"]), set(rule["hidden_from"])
        if allowed & hidden or rule["holder"] not in allowed:
            problems.append("invalid_attribute_visibility:" + aid)
        unknown = (allowed | hidden | {rule["holder"]}) - names
        if unknown:
            # Some references include task_system, which is not a cast actor.
            # Record the unsupported mapping without inventing runtime grants.
            unmapped_principals[aid] = sorted(unknown)
        sid = item.get("source")
        if not isinstance(sid, str) or sid not in timeline:
            problems.append("invalid_reference_source:" + aid)
        carried = [art for art in timeline.values() if aid in art.get("attributes", [])]
        if isinstance(sid, str) and sid in timeline and aid not in timeline[sid].get("attributes", []):
            problems.append("reference_not_carried_by_source:" + aid)
        if not carried:
            missing_carriers.append(aid)
            continue
        # Audit the source's own occurrence declarations even if a reference
        # source ID is stale. This does not repair or authorize that reference.
        declared_assessed.append(aid)
        for art in carried:
            declared.update((aid, person) for person in set(art["visible_to"]) & hidden & names)
        value = item.get("value")
        if not isinstance(value, str) or not value:
            problems.append("unsupported_reference_value:" + aid)
            continue
        literal_assessed.append(aid)
        if not any(value in art["content"] for art in carried):
            counts["nonliteral_reference_values"] += 1
        for art in carried:
            for person in set(art["visible_to"]) & hidden & names:
                if value in art["content"]:
                    literal.add((aid, person))
    return {"attribute_ids_agree": attribute_ids_agree, "attributes": len(attrs), "label_counts": counts,
            "reference_problems": problems, "unmapped_reference_principals": unmapped_principals,
            "carrier_basis": "timeline.attributes; utility.source consistency is audited separately",
            "declared_assessed_attributes": len(declared_assessed), "literal_assessed_attributes": len(literal_assessed),
            "attributes_without_declared_carriers": missing_carriers,
            "declared_initial_visibility_conflict_edges": len(declared) if declared_assessed else None,
            "literal_initial_visibility_conflict_edges": len(literal) if literal_assessed else None,
            "literal_conflict_attribute_ids": sorted({aid for aid, _ in literal}),
            "interpretation": "Bounded to cast actors and declared carriers. Source-artifact access and scoring visibility disagree for these incidences; no migration/model has run. Zero literal matches does not establish absence of semantic exposure. Missing carriers are unassessed, not safe."}


def qualify(output):
    from memory_migration_study.pisas_source import project_source, build_actor_view
    from unittest.mock import patch
    receipt = load_inputs()
    output.mkdir(parents=True, exist_ok=False)
    plan = {"schema": "pisas_source_qualification_v1", "revision": REVISION,
            "receipt_sha256": sha_bytes((DATA / "receipt.json").read_bytes()), "tasks": list(TASKS),
            "samples": 9, "new_model_calls": 0, "reference_used_for_runtime": False,
            "sources": {p: sha_bytes((ROOT / p).read_bytes()) for p in (
                "scripts/qualify_pisas_inputs.py", "memory_migration_study/pisas_source.py", "tests/test_pisas_source.py",
                "tests/test_pisas_qualification.py")}}
    save(output / "plan.json", plan)
    rows, source_objects = [], {}
    with patch("socket.socket.connect", side_effect=RuntimeError("network_forbidden")), \
         patch("urllib.request.urlopen", side_effect=RuntimeError("network_forbidden")):
        for task in TASKS:
            source = json.loads((DATA / "data" / task / "scenario_01/scenario.json").read_text(encoding="utf-8"))
            source_objects[task] = source
            try:
                projected = project_source(source)
            except (ValueError, TypeError, KeyError) as exc:
                rows.append({"task": task, "status": "source_unsupported", "error_type": type(exc).__name__})
                continue
            # A source-only adapter; no reference file is parsed in this phase.
            view = projected["model_view"]
            actor_views = {c["name"]: build_actor_view(projected, c["name"])["model_view"] for c in view["cast"]}
            saved = {"source_sha256": projected["source_sha256"], "qualification": projected["qualification"],
                     "model_view": view, "actor_views": actor_views}
            save(output / "runtime" / (task + ".json"), saved)
            sizes = {name: len(json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) for name, v in actor_views.items()}
            rows.append({"task": task, "status": "source_projected", "source_sha256": saved["source_sha256"], "qualification": saved["qualification"],
                         "runtime_file_sha256": sha_bytes((output / "runtime" / (task + ".json")).read_bytes()),
                         "actors": len(actor_views), "object_count": len(view["memories"]),
                         "all_view_utf8_bytes": len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
                         "actor_view_utf8_bytes_min": min(sizes.values()), "actor_view_utf8_bytes_max": max(sizes.values()),
                         "actor_views_under_existing_3072_input_byte_bound": sum(size+320 <= 3072 for size in sizes.values()),
                         "size_note": "Conservative payload byte bound plus 320 chat overhead; not measured tokenizer usage or a finalized prompt."})
        save(output / "runtime_phase_closed.json", {"rows": rows, "reference_parsed": False,
            "new_model_calls": 0, "receipt_sha256": plan["receipt_sha256"]})
        # Only now read evaluation labels to measure qualification, not performance.
        for row in rows:
            base = DATA / "data" / row["task"] / "scenario_01"
            refs = [json.loads((base / name).read_text(encoding="utf-8")) for name in NAMES[1:]]
            try:
                row["reference_audit"] = audit_annotations(source_objects[row["task"]], *refs)
            except (ValueError, TypeError, KeyError) as exc:
                row["reference_audit"] = {"status": "reference_unsupported", "error_type": type(exc).__name__}
        if load_inputs() != receipt:
            raise ValueError("input_receipt_changed")
        for p, value in plan["sources"].items():
            if sha_bytes((ROOT / p).read_bytes()) != value:
                raise ValueError("qualification_code_changed")
    report = {"schema": "pisas_source_qualification_v1", "status": "complete", "revision": REVISION, "scenarios": rows,
              "samples": len(rows), "new_model_calls": 0, "migration_runs": 0, "privacy_performance": None,
              "runtime_closure_sha256": sha_bytes((output / "runtime_phase_closed.json").read_bytes()),
              "plan_sha256": sha_bytes((output / "plan.json").read_bytes()),
              "scope": "Nine first scenarios only; external development qualification, not a full benchmark or independent final acceptance."}
    save(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--download", action="store_true")
    group.add_argument("--qualify", action="store_true")
    parser.add_argument("--resume-download", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.qualify and (args.output is None or not args.output.resolve().is_relative_to(ROOT / "results")):
        raise ValueError("qualification_output_must_be_in_results")
    result = download(resume=args.resume_download) if args.download else qualify(args.output.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
