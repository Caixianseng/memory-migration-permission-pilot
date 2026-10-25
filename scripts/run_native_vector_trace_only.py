"""Pre-register and inject only a target trace subclass into unchanged bridge.run."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from scripts import run_native_exact_fact_bridge as bridge

VERSION = "same_sequence_native_bridge_trace_only_diagnostic_v1"


def run(output, *, python, sdk_root, legacy_project, timeout=300):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    extra_paths = [Path(__file__).resolve(), PROJECT/"scripts/native_vector_trace_only_worker.py"]
    extra_hashes = {str(path.resolve()): bridge.file_sha256(path) for path in extra_paths}
    extra_root = output/"trace_implementation"
    extra_root.mkdir()
    extra_archive = bridge.archive_code(extra_paths, extra_hashes, extra_root)
    expected_old_target = (PROJECT/"scripts/native_exact_fact_target.py").resolve()
    replacement = (PROJECT/"scripts/native_vector_trace_only_worker.py").resolve()
    standard_output = output/"standard_run"
    standard_source_files = sorted((PROJECT/"memory_migration_study").glob("*.py"))
    standard_source_files += [PROJECT/"scripts"/name for name in ("run_native_exact_fact_bridge.py", "native_exact_fact_source.py",
        "native_exact_fact_target.py", "native_exact_fact_common.py")]
    standard_source_files += [Path(legacy_project)/"scripts"/name for name in ("qualify_migration.py", "openwebui_migration_probe.py")]
    standard_hashes = {str(path.resolve()): bridge.file_sha256(path) for path in standard_source_files}
    plan = {"version": VERSION, "standard_output": "standard_run", "original_bridge_version": bridge.VERSION,
        "extra_code_sha256": extra_hashes, "extra_archive_root": "trace_implementation", "extra_code_archive": extra_archive,
        "expected_standard_source_sha256": standard_hashes,
        "factory_injection": {"requested_target_script": str(expected_old_target), "actual_target_script": str(replacement),
            "source_script_unchanged": True, "rpc_arguments_unchanged": True,
            "scoped_patch": "only bridge.WorkerRPC factory inside call to original bridge.run"},
        "protocol": {"standard_checks": 29, "source_embedding_budget": 2, "target_embedding_budget": 21,
            "generation_budget": 0, "paid_api_budget": 0, "retry": False, "extra_native_reads": 0,
            "semantic_query": "Customer service and delivery status.", "k": 100, "relevance_threshold_changed": False,
            "same_standard_source_and_target_rpc_sequence": True},
        "scope": "one predeclared complete same-sequence trace-only diagnostic; its success cannot replace v3 failure",
        "archive_scope": "original bridge archive covers standard control flow; these two injected files are separate pre-child archive"}
    bridge.save(output/"trace_plan.json", plan)
    original_factory = bridge.WorkerRPC
    spawns = []
    def factory(python_arg, script, args, *, timeout=300):
        requested = Path(script).resolve()
        actual = replacement if requested == expected_old_target else requested
        spawns.append({"requested_script": str(requested), "actual_script": str(actual),
            "arguments": list(map(str, args)), "timeout": timeout,
            "only_target_replaced": requested != actual and requested == expected_old_target})
        return original_factory(python_arg, actual, args, timeout=timeout)
    report = None
    failure = None
    try:
        with patch.object(bridge, "WorkerRPC", side_effect=factory):
            report = bridge.run(standard_output, python=python, sdk_root=sdk_root, legacy_project=legacy_project, timeout=timeout)
    except Exception as error:
        failure = {"class": type(error).__name__}  # No credentials or environment dump.
    finally:
        bridge.save(output/"factory_spawns.json", spawns)
    standard = report or {}
    source, target = standard.get("source_final", {}), standard.get("target_final", {})
    trace = target.get("trace_only", {})
    observations = trace.get("observations", [])
    checks = standard.get("checks", [])
    null_events = [row for row in observations if row.get("return_kind") == "none"]
    diagnostic = {"version": VERSION, "standard_report_status": standard.get("status"), "fatal_error": failure,
        "standard_check_count": len(checks), "standard_checks_passed": sum(row.get("passed") is True for row in checks),
        "source_embedding_invocations": source.get("mem0_embedding_method_invocations"),
        "target_embedding_invocations": target.get("native_embedding_function_invocations"),
        "source_generation_attempts": source.get("generation_attempts"), "target_generation_attempts": target.get("generation_attempts"),
        "search_calls": trace.get("original_search_calls"), "snapshot_calls": trace.get("snapshot_calls"),
        "null_search_returns": len(null_events), "exception_events": sum(len(row.get("exception_events", [])) for row in observations),
        "extra_code_postflight": bridge.verify_sha_table(extra_hashes),
        "extra_archive_postflight": bridge.verify_sha_table({str(extra_root/item["archive_path"]): item["sha256"] for item in extra_archive.values()}),
        "standard_source_postflight": bridge.verify_sha_table(standard_hashes),
        "factory_restored": bridge.WorkerRPC is original_factory, "injection_spawns": spawns,
        "scope": plan["scope"]}
    # Empty accounts before writes produce 404 without entering search: 5 nonempty snapshots × 3 subjects = 15.
    diagnostic["instrumentation_protocol_passed"] = (failure is None and len(checks) == 29
        and source.get("mem0_embedding_method_invocations") == 2 and target.get("native_embedding_function_invocations") == 21
        and source.get("generation_attempts") == 0 and target.get("generation_attempts") == 0
        and trace.get("snapshot_calls") == 6 and trace.get("original_search_calls") == 15 and len(observations) == 15
        and not trace.get("observer_errors") and all(row.get("original_calls") == 1 and row.get("trace_restored") is True for row in observations)
        and len(spawns) == 2 and sum(row["only_target_replaced"] for row in spawns) == 1
        and diagnostic["factory_restored"] and all(diagnostic[key]["status"] == "passed" for key in
            ("extra_code_postflight", "extra_archive_postflight", "standard_source_postflight"))
        and all(standard.get(key, {}).get("status") == "passed" for key in ("code_postflight", "archive_postflight", "asset_postflight", "sdk_inventory_preflight"))
        and not any(event.get("allowed") is not True for final in (source, target) for event in final.get("network_events", [])))
    bridge.save(output/"trace_diagnostic.json", diagnostic)
    return diagnostic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=PROJECT/".venv-native-webui/Scripts/python.exe")
    parser.add_argument("--sdk-root", type=Path, default=PROJECT/".runtime/native_mem0_sdk_v1")
    parser.add_argument("--legacy-project", type=Path, default=PROJECT/"memory_migration_permission_149tests_20261021/memory_migration_permission_pilot")
    args = parser.parse_args()
    result = run(args.output, python=args.python, sdk_root=args.sdk_root, legacy_project=args.legacy_project)
    print(json.dumps({key: result[key] for key in ("standard_report_status", "standard_check_count", "standard_checks_passed",
        "instrumentation_protocol_passed", "source_embedding_invocations", "target_embedding_invocations", "null_search_returns", "exception_events")}))
    raise SystemExit(0 if result["instrumentation_protocol_passed"] else 1)


if __name__ == "__main__":
    main()
