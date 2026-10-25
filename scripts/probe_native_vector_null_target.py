"""One bounded target-only WebUI/Chroma observation run, never a repair retry."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts.run_native_exact_fact_bridge import WorkerRPC, archive_code, verify_sha_table, file_sha256, check_semantic_row
from scripts.probe_native_vector_null import save, exception_record

VERSION = "native_target_only_vector_null_diagnostic_v1"
ACTORS = ("owner", "assistant", "outsider")


def load_fixture(path):
    original = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    main_path = "/exact-fact/"+original["sidecar"]["main"]["record_id"]
    valid_path = "/exact-fact/"+original["sidecar"]["valid_control"]["record_id"]
    for item in original["target_rpc_receipts"]:
        if item["command"] != "add":
            continue
        data = item["input"]
        if data["path"] == main_path and data["actor"] in {"owner", "assistant"}:
            logical_id = "main-"+data["actor"]
        elif data["path"] == valid_path and data["actor"] == "assistant":
            logical_id = "valid-assistant"
        else:
            raise ValueError("unexpected_source_fixture_write")
        rows.append({"logical_id": logical_id, **deepcopy(data)})
    for item in original["resident_controls"]:
        rows.append({"logical_id": "resident-"+item["actor"], "actor": item["actor"], "text": item["content"], "path": item["path"]})
    expected = {"main-owner", "main-assistant", "valid-assistant", "resident-owner", "resident-assistant", "resident-outsider"}
    if (len(rows) != 6 or {row["logical_id"] for row in rows} != expected
            or any(not isinstance(row["text"], str) or not row["text"].strip() for row in rows)
            or original["trusted_fixture"]["source_only_canary"] in json.dumps(rows, ensure_ascii=False)):
        raise ValueError("fixture_projection_invalid")
    return rows


def matrix_schedule():
    return [{"phase": phase, "round": round_index, "actor": actor}
        for phase in ("before_delete", "after_delete") for round_index in (1, 2) for actor in ACTORS]


def score_observation(row, expected, by_id):
    listed = row.get("native_list", {})
    try:
        items = json.loads(listed.get("native_raw_body", ""))
    except (ValueError, TypeError):
        items = None
    valid_list = (listed.get("status") == 200 and listed.get("response_checked") is True
        and listed.get("execution_error") is None and isinstance(items, list)
        and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in items))
    if valid_list:
        valid_list = len(items) == len({item["id"] for item in items}) and {item["id"] for item in items} == expected
        valid_list = valid_list and all(item["content"] == by_id[item["id"]]["text"]
            and item["path"] == by_id[item["id"]]["path"].strip("/") for item in items)
    semantic_ok = valid_list and check_semantic_row(row["semantic_row"], expected_ids=expected,
        listed_rows={item["id"]: item for item in items}, source_canary="NEVER-SENT-SOURCE-CANARY")
    observations = row.get("adapter_observations", [])
    observed = len(observations) == 1
    if observed:
        current = observations[0]
        vectors = current.get("input", {}).get("query_vectors", {})
        observed = (current.get("original_calls") == 1 and current.get("trace_restored") is True
            and current.get("stage") == {key: row[key] for key in ("actor", "phase", "round")}
            and current.get("input", {}).get("actor_from_verified_native_identity") == row["actor"]
            and current.get("input", {}).get("limit") == 100 and current.get("input", {}).get("filter") is None
            and vectors.get("shape") == [1, 384] and vectors.get("finite") is True
            and current.get("count_get", {}).get("count") == len(expected)
            and set(current.get("count_get", {}).get("get", {}).get("ids", [])) == expected
            and not current.get("observation_error") and not current.get("output_observation_error"))
    return {"native_sql_control_passed": bool(valid_list), "native_semantic_complete_passed": bool(semantic_ok),
        "instrumentation_passed": bool(observed), "passed": bool(valid_list and semantic_ok and observed),
        "null_response": row.get("semantic_row", {}).get("status") == 200 and row.get("semantic_row", {}).get("native_raw_body") == "null"}


def run(output, *, python, legacy_project, fixture_report, timeout=300):
    output, legacy_project = Path(output).resolve(), Path(legacy_project).resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture_rows = load_fixture(fixture_report)
    paths = sorted((PROJECT/"memory_migration_study").glob("*.py"))
    paths += [PROJECT/"scripts"/name for name in ("run_native_exact_fact_bridge.py", "native_exact_fact_source.py",
        "native_exact_fact_target.py", "native_exact_fact_common.py", "probe_native_vector_null.py",
        "probe_native_vector_null_target.py", "native_vector_null_target_worker.py")]
    paths += [legacy_project/"scripts"/name for name in ("qualify_migration.py", "openwebui_migration_probe.py")]
    code_hashes = {str(path.resolve()): file_sha256(path) for path in paths}
    archived = archive_code(paths, code_hashes, output)
    assets = legacy_project/"runtime_assets"
    origin_plan = json.loads(Path(fixture_report).with_name("plan.json").read_text(encoding="utf-8"))
    asset_paths = {Path(path) for path in origin_plan["asset_sha256"] if not path.endswith("installed_file_hashes.json") and not path.endswith("pip_report.json")}
    site = Path(python).resolve().parent.parent/"Lib/site-packages"
    asset_paths.update(site/path for path in ("open_webui/retrieval/vector/async_client.py", "chromadb/api/client.py",
        "chromadb/api/models/Collection.py", "chromadb/api/models/CollectionCommon.py", "chromadb/api/rust.py", "chromadb/config.py"))
    asset_paths.update((site/"chromadb_rust_bindings").glob("*.pyd"))
    asset_hashes = {str(path.resolve()): file_sha256(path) for path in sorted(asset_paths)}
    origin_assets_match = all(asset_hashes[str(Path(path).resolve())] == expected
        for path, expected in origin_plan["asset_sha256"].items()
        if Path(path) in asset_paths)
    plan = {"version": VERSION, "python": str(python), "code_sha256": code_hashes, "code_archive": archived,
        "asset_sha256": asset_hashes, "origin_native_assets_match": origin_assets_match,
        "fixture_origin_report_sha256": file_sha256(fixture_report), "fixture": fixture_rows,
        "protocol": {"queries": 12, "writes": 6, "deletes": 2, "max_embedding_invocations": 18, "generation_budget": 0,
            "query": "Customer service and delivery status.", "k": 100, "schedule": matrix_schedule(),
            "relevance_threshold_changed": False, "retry": False, "fallback": False, "reembedding": False,
            "external_network_allowed": False, "source_backend_started": False},
        "observability_difference": "actual Chroma.search thread calls native count/get before original once and scopes sys.settrace to original.__code__; extra reads/timing differ from v3",
        "scope": "target-only fresh diagnosis using prior synthetic target input projection; no source authorization or full migration acceptance claim"}
    save(output/"plan.json", plan)
    worker, rows, writes, deletions = None, [], [], []
    report = {"version": VERSION, "status": "failed"}
    try:
        if not origin_assets_match:
            raise ValueError("native_vendor_or_model_asset_differs_from_v3")
        worker = WorkerRPC(python, PROJECT/"scripts/native_vector_null_target_worker.py", ["--state", output/"target_state",
            "--assets", assets, "--legacy-project", legacy_project], timeout=timeout)
        runtime = worker.call("init", {})
        for row in fixture_rows:
            result = worker.call("diagnostic_add", row)
            if any(result.get(key) != row[key] for key in row) or not isinstance(result.get("target_id"), str):
                raise ValueError("native_fixture_write_not_verified")
            writes.append(result)
        by_id = {row["target_id"]: row for row in writes}
        if len(by_id) != 6:
            raise ValueError("native_fixture_ids_not_unique")
        expected = {actor: {row["target_id"] for row in writes if row["actor"] == actor} for actor in ACTORS}
        deleted = False
        for entry in matrix_schedule():
            if entry["phase"] == "after_delete" and not deleted:
                for logical_id in ("main-owner", "main-assistant"):
                    result = worker.call("diagnostic_delete", {"logical_id": logical_id})
                    item = next(row for row in writes if row["logical_id"] == logical_id)
                    deletions.append({"logical_id": logical_id, **result})
                    expected[item["actor"]].remove(item["target_id"])
                deleted = True
            result = worker.call("diagnostic_query", entry)
            result["expected_ids"] = sorted(expected[entry["actor"]])
            result["score"] = score_observation(result, expected[entry["actor"]], by_id)
            rows.append(result)
            save(output/"queries.json", rows)
            save(output/"rpc_receipts.json", worker.calls)
        report.update(status="completed", runtime=runtime, writes=writes, deletions=deletions)
    except Exception as error:
        report["fatal_error"] = exception_record(error)
    finally:
        if worker is not None:
            try:
                report["target_final"] = worker.call("close", {})
            except Exception as error:
                report["close_error"] = exception_record(error)
            report["rpc_receipts"] = worker.calls
            worker.terminate()
    report.update(queries=rows, recorded_queries=len(rows), queries_passed=sum(row["score"]["passed"] for row in rows),
        null_queries=sum(row["score"]["null_response"] for row in rows), generation_calls=0, paid_api_calls=0)
    report["code_postflight"] = verify_sha_table(code_hashes)
    report["asset_postflight"] = verify_sha_table(asset_hashes)
    report["archive_postflight"] = verify_sha_table({str(output/item["archive_path"]): item["sha256"] for item in archived.values()})
    final = report.get("target_final", {})
    diagnostic = final.get("diagnostic", {})
    report["embedding_invocations"] = final.get("native_embedding_function_invocations")
    report["observed_search_exception_events"] = sum(len(item.get("exception_events", [])) for item in diagnostic.get("adapter_observations", []))
    report["protocol_passed"] = (report["status"] == "completed" and len(rows) == 12 and len(writes) == 6 and len(deletions) == 2
        and all(row.get("status") == 200 and row.get("deleted") is True for row in deletions)
        and all(row["score"]["instrumentation_passed"] for row in rows)
        and diagnostic.get("query_attempts") == 12 and diagnostic.get("original_search_calls") == 12
        and type(report["embedding_invocations"]) is int and report["embedding_invocations"] <= 18
        and diagnostic.get("embedding_budget_respected") is True and not diagnostic.get("observer_failures")
        and final.get("generation_attempts") == 0 and not any(event.get("allowed") is not True for event in final.get("network_events", []))
        and all(report[name]["status"] == "passed" for name in ("code_postflight", "asset_postflight", "archive_postflight")))
    report["functional_observations_passed"] = report["queries_passed"] == 12
    report["interpretation"] = "native_failure_observed" if report["queries_passed"] < 12 else "native_failure_not_reproduced_in_fixed_12_queries"
    save(output/"report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=PROJECT/".venv-native-webui/Scripts/python.exe")
    parser.add_argument("--legacy-project", type=Path, default=PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    parser.add_argument("--fixture-report", type=Path, default=PROJECT/"results/native_exact_fact_bridge_20261025_v3/report.json")
    args = parser.parse_args()
    report = run(args.output, python=args.python, legacy_project=args.legacy_project, fixture_report=args.fixture_report)
    print(json.dumps({key: report[key] for key in ("status", "protocol_passed", "recorded_queries", "queries_passed",
        "null_queries", "observed_search_exception_events", "embedding_invocations", "interpretation")}, ensure_ascii=False))
    raise SystemExit(0 if report["protocol_passed"] else 1)


if __name__ == "__main__":
    main()
