"""Offline audit of two existing native-client private handoff results.

Standard library only. No producer/scorer imports, credentials, subprocesses,
model/client/network calls, or re-execution of process-local HMAC capabilities.
Read only explicit synthetic results, their AGENTS files and frozen sources.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VERSION = "independent_native_private_handoff_audit_v1"
QUESTION = "Return the single authorized value in AGENTS.md exactly. No tools or explanation. If absent, reply UNKNOWN."
TOKEN = re.compile(r"\[PVT_[A-F0-9]{24}_CUSTOMER_1\]\Z")


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
def jhash(value): return sha(canonical(value))


def json_load(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("json_nonfinite")))


def verify(run):
    run = Path(run).resolve()
    checks, artifacts, counts, failure = [], {}, {}, None
    def check(condition, name): checks.append({"check": name, "passed": bool(condition)})
    def read(name):
        path = run / name
        if path.is_symlink() or not path.resolve().is_relative_to(run) or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("unsafe_evidence_path")
        raw = path.read_bytes(); artifacts[name] = sha(raw)
        return json_load(raw)
    try:
        plan = read("plan.json"); start = read("execution_started.json"); summary = read("summary.json")
        rows = {c: read(c + "_result.json") for c in ("qoder", "harness")}
        check(start == {"client_attempt_cap": 2, "plan_sha256": artifacts["plan.json"]}, "execution_bound_to_original_plan")
        check(plan["schema"] == "native-private-handoff-integration-v1"
            and run == (ROOT / plan["output"]).resolve() and plan["question"] == QUESTION, "plan_output_and_fixed_question")
        check(plan["max_native_client_attempts"] == 2 and plan["max_output_tokens_each"] == 64
            and plan["raw_deepseek_api_calls"] == 0, "two_native_attempts_and_configured_64_output_bound")
        check([c["client"] for c in plan["cases"]] == ["qoder", "harness"]
            and plan["detector_mode"] == "rules_with_explicit_synthetic_registry", "closed_synthetic_two_direction_fixture")
        for name, expected in plan["implementation_sha256"].items():
            rel = Path(name)
            check(not rel.is_absolute() and ".." not in rel.parts, "registered_source_is_relative")
            archived = run / "frozen_source" / rel
            check(sha(archived.read_bytes()) == expected, "frozen_source_exact_hash")
            check(sha((ROOT / rel).read_bytes()) == expected, "current_registered_source_unchanged")
        counts["registered_frozen_sources"] = len(plan["implementation_sha256"])
        frozen_driver = run / "frozen_source/scripts/run_native_private_handoff.py"
        tree = ast.parse(frozen_driver.read_bytes())
        one_case = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "one_case")
        native_lines = [x.lineno for x in ast.walk(one_case) if isinstance(x, ast.Call)
            and isinstance(x.func, ast.Name) and x.func.id == "native_call"]
        prepare_lines = [x.lineno for x in ast.walk(one_case) if isinstance(x, ast.Call)
            and isinstance(x.func, ast.Name) and x.func.id == "prepare_native_private_memory"]
        restore_lines = [x.lineno for x in ast.walk(one_case) if isinstance(x, ast.Call)
            and isinstance(x.func, ast.Name) and x.func.id == "restore_native_private_answer"]
        check(len(native_lines) == 1 and len(prepare_lines) == 3 and max(prepare_lines) < native_lines[0]
            and len(restore_lines) == 2 and min(restore_lines) > native_lines[0], "host_prechecks_then_single_client_then_restore_and_replay_frozen_order")
        token_values, successes, controls = [], 0, 0
        all_registered = [spec[k] for spec in plan["cases"] for k in ("value", "source_only")]
        for spec in plan["cases"]:
            client = spec["client"]; row = rows[client]; receipt = row["receipt"]
            workspace = (run / spec["workspace"]).absolute()
            check(workspace == workspace.resolve() and workspace.parent == run
                and spec["workspace"] == client + "_private_target" and (workspace / ".git").is_dir()
                and not (workspace / ".git").is_symlink(), "host_bound_isolated_git_workspace")
            check(spec["sender"] == {"qoder": "harness", "harness": "qoder"}[client]
                and spec["recipient"] == client and spec["record_id"] == "customer"
                and re.fullmatch(r"SYNTHETIC-CUSTOMER-[A-F0-9]{12}", spec["value"])
                and re.fullmatch(r"SYNTHETIC-SOURCE-ONLY-[A-F0-9]{12}", spec["source_only"]), "host_sender_recipient_record_and_synthetic_values")
            memory = workspace / "AGENTS.md"
            check(not memory.is_symlink() and memory.resolve().parent == workspace, "native_memory_file_not_redirected")
            raw = memory.read_bytes(); token = raw.decode(); token_values.append(token)
            artifacts[spec["workspace"] + "/AGENTS.md"] = sha(raw)
            check(TOKEN.fullmatch(token) is not None and len(raw) == 41, "native_memory_is_single_request_pseudonym_only")
            meta = row["privacy_metadata"]
            check(sha(raw) == meta["agents_md_sha256"] == receipt["agent_memory_file_sha256"], "local_memory_prepost_hash_matches_client_receipt")
            check(sha((QUESTION + token).encode()) == row["native_input_sha256"]
                and sha(QUESTION.encode()) == meta["question_sha256"], "constructed_native_memory_and_question_hashes")
            check(not any(value in QUESTION + token for value in all_registered)
                and row["registered_raw_absent_from_constructed_native_input"] is True, "all_preregistered_values_absent_from_constructed_input")
            check(receipt["answer"] == receipt["raw_response"] == token and receipt["status"] == "ok"
                and receipt["error"] is None and receipt["exit_code"] == 0 and receipt["invocation_started"] is True,
                "actual_native_final_answer_equals_isolated_memory_token")
            check(not any(value in receipt["raw_response"] for value in all_registered)
                and row["native_response_registration_check"] == {"registered_value_present": False, "source_only_present": False},
                "actual_native_final_text_contains_no_registered_original")
            policy = {"version": "native-private-integration-v1", "protected_categories": ["CUSTOMER"],
                "instructions": "Protect the host-declared synthetic customer identifier.",
                "entity_registry": [{"value": spec["value"], "category": "CUSTOMER"}]}
            source_question = "Return the authorized customer " + spec["value"] + "."
            source_payload = {"query": source_question, "memories": [{"source_id": "customer", "text": spec["value"]}]}
            # Frozen privacy.py replaces source identifiers as well as values;
            # infer the opaque ID from the already exported request nonce.
            opaque_id = "m_" + re.fullmatch(r"\[PVT_([A-F0-9]{24})_CUSTOMER_1\]", token).group(1) + "_1"
            prepared_payload = {"query": source_question.replace(spec["value"], token), "memories": [{"source_id": opaque_id, "text": token}]}
            native_payload = {"query": QUESTION, "memories": [{"source_id": opaque_id, "text": token}]}
            check(meta["policy_sha256"] == jhash(policy) and meta["source_payload_sha256"] == jhash(source_payload), "synthetic_policy_and_original_exact_record_hashes")
            check(meta["prepared_payload_sha256"] == jhash(prepared_payload)
                and meta["native_payload_sha256"] == jhash(native_payload), "source_question_and_memory_both_pseudonymized_with_full_payload_binding")
            check(meta["workspace_sha256"] == sha(str(workspace).encode()) and meta["record_count"] == 1
                and meta["local_calls"] == 0, "host_workspace_and_single_value_zero_detector_model_scope")
            check(meta["enforcement_scope"] == "external_gated" and meta["native_acl"] is False
                and meta["native_memory_kind"] == "native_workspace_instructions", "external_gate_not_native_acl_or_auto_memory")
            check(row["restoration_status"] == "ok" and row["restoration_error"] is None
                and row["restored_answer_sha256"] == sha(spec["value"].encode()) and row["restored_correct"] is True,
                "declared_restored_value_hash_matches_registered_exact_value")
            expected_controls = [("wrong_recipient_before_client", "broker_packet_audience_mismatch"),
                ("revoked_before_client", "broker_record_revoked"), ("consumed_response_replay", "native_request_unknown_or_replayed")]
            check(len(row["negative_controls"]) == 3 and [(x["name"], x["error"]) for x in row["negative_controls"]] == expected_controls
                and all(x["status"] == "blocked" and x["passed"] is True for x in row["negative_controls"]), "three_recorded_host_control_receipts_with_exact_failure_codes")
            check(row["full_cloud_request_content_inspected"] is False and row["client_attempts"] == 1
                and row["status"] == "completed" and row["joint_success"] is True, "single_native_attempt_and_cloud_inspection_boundary")
            controls += len(row["negative_controls"]); successes += 1
            if client == "qoder":
                cap = json_load((run / "frozen_source/results/native_agent_probe_20261026/qoder_capabilities.json").read_bytes())
                args = list(cap["inference_argv_template"][:-1]); args[args.index("--cwd") + 1] = str(workspace)
                check(cap["inference_argv_template"][-2:] == ["--print", "<synthetic query only>"]
                    and sha(json.dumps(args, ensure_ascii=False, separators=(",", ":")).encode()) == receipt["argv_sha256"], "qoder_actual_argv_bound_to_query_only_stdin_template")
                check(not any(value in json.dumps(args) for value in all_registered), "qoder_argv_contains_no_registered_originals")
                for flag, value in {"--max-turns": "1", "--max-output-tokens": "64", "--max-model-request-retries": "0", "--tools": "", "--setting-sources": "project"}.items():
                    check(args[args.index(flag) + 1] == value, "qoder_frozen_budget_and_tools_flags")
                settings = json_load(args[args.index("--settings") + 1])
                check(settings["disableAllHooks"] is True and settings["autoMemoryEnabled"] is False
                    and settings["autoMemoryUserScopeEnabled"] is False and settings["context"]["memoryBoundaryMarkers"] == [".git"]
                    and json_load(args[args.index("--mcp-config") + 1]) == {"mcpServers": {}}, "qoder_scoped_context_no_tools_hooks_or_mcp")
                check(cap["package_version_verified"] == receipt["version"] == "1.1.77"
                    and cap["actual_cli_model_id"] == receipt["model"] == "DeepSeek-Flash"
                    and cap["cli_entry_sha256"] == receipt["cli_entry_sha256"], "qoder_frozen_cli_version_and_entry_identity")
                check(cap["managed_plugin_isolation_caveat"]["effective_prompt_isolation_claim"]
                    == "global user native static/auto memories excluded; managed-plugin absence not established", "qoder_managed_plugin_context_limit_retained")
                counts["qoder_cli_reported_usage"] = receipt["usage"]
                counts["qoder_cli_reported_cost"] = receipt["cli_reported_cost"]
            else:
                check(receipt["version"] == "0.2.1-rc.3" and receipt["model"] == "deepseek-flash"
                    and receipt["native_instruction_loaded"] is True and receipt["last_terminal_reason"] == {"kind": "completed"}, "harness_native_instruction_event_and_completed_turn")
                baselines = receipt["native_instruction_baselines"]
                check(len(baselines) == 1 and baselines[0]["content"] == [{"type": "text", "text": token}], "filtered_native_instruction_event_contains_current_pseudonym")
                changes = baselines[0]["source"]["changes"]
                check(baselines[0]["source"]["kind"] == "agent-instructions" and baselines[0]["source"]["baseline"] is True
                    and len(changes) == 1 and changes[0]["digest"] == hashlib.sha1(raw).hexdigest()
                    and changes[0]["path"] == "AGENTS.md" and changes[0]["action"] == "set", "harness_native_instruction_digest_matches_actual_AGENTS")
                guard = receipt["guard_counts"]
                check(all(guard[k] == 1 for k in ("agent_attempt_count", "stream_attempt_count", "allowed_stream_count"))
                    and guard["dry_run"] is False and guard["reject_code"] is None and len(guard["requests"]) == 1
                    and guard["requests"][0]["count"] == 1 and guard["requests"][0]["maxTokens"] == 64, "harness_one_guarded_stream_max64_no_reject")
                shape = guard["shape"]
                check(shape["stage"] == "full_request" and shape["tool_count"] == 0 and shape["unknown_key_count"] == 0
                    and shape["model_matches"] is True and shape["provider_matches"] is True and shape["reasoning_off"] is True,
                    "harness_recorded_request_shape_no_tools_fixed_provider")
                check(receipt["usage"] == {"inputTokens": 282, "outputTokens": 23, "totalTokens": 305}
                    and receipt["usage"]["outputTokens"] <= 64, "harness_recorded_usage_within_output_bound")
                check(receipt["credentials_source_unchanged"] is True and receipt["temporary_credentials_removed"] is True
                    and not (run / "harness_private_runtime/.credentials.yaml").exists(), "credential_cleanup_existence_only_no_content_read")
                check(receipt["guard_bytes_scope"] == "harness_request_json_without_signal"
                    and receipt["physical_model_requests"] is None, "harness_body_hash_is_not_full_network_request_capture")
                counts["harness_reported_usage"] = receipt["usage"]
        check(len(set(token_values)) == 2, "pseudonym_scopes_are_distinct_per_native_client_request")
        check(summary["status"] == "completed" and summary["client_attempts"] == summary["client_responses_ok"]
            == summary["restored_correct"] == summary["joint_success"] == successes == 2
            and summary["controls_passed"] == summary["controls_total"] == controls == 6, "summary_recomputed_from_original_case_records")
        check(summary["mapping_object_persisted"] is False and summary["implementation_unchanged"] is True
            and summary["native_acl_or_online_revocation"] is False and summary["full_cloud_request_content_inspected"] is False
            and summary["effect_acceptance_or_novelty_established"] is False, "research_and_native_security_boundaries_preserved")
        check(summary["cost"] == plan["cost"] and summary["cost"]["account_cost"] is None
            and summary["cost"]["physical_http_requests"] is None and summary["new_raw_api_calls"] == 0,
            "unknown_native_account_cost_never_coerced_to_free")
        counts.update(native_client_attempts=2, exact_native_pseudonym_answers=2, exact_restoration_hash_matches=2,
            recorded_host_controls=6, detector_model_calls=0, new_verification_native_calls=0, new_verification_model_calls=0)
    except (OSError, ValueError, TypeError, KeyError, IndexError, StopIteration, AttributeError, SyntaxError):
        failure = "evidence_missing_or_contract_mismatch"
        check(False, failure)
    return {"version": VERSION, "status": "passed" if all(x["passed"] for x in checks) else "failed",
        "checks": checks, "check_count": len(checks), "passed_count": sum(x["passed"] for x in checks),
        "failed_count": sum(not x["passed"] for x in checks), "failure": failure, "counts": counts,
        "artifact_sha256": artifacts, "verifier_sha256": sha(Path(__file__).read_bytes()),
        "producer_scorer_imported": False, "credential_content_read": False,
        "verification_native_calls": 0, "verification_model_calls": 0,
        "limits": ["Original in-memory HMAC/map/current-authority instances were not persisted; recorded controls and hashes are checked, not original cryptographic signatures replayed.",
            "Qoder provides a wrapper AGENTS hash plus unique-token answer; Harness additionally provides a filtered native instruction event. No provider-side full prompt capture.",
            "Harness combined rendered instruction content is represented only by a hash; Qoder managed-plugin absence is not established.",
            "Original account charges and physical model HTTP counts remain unknown; CLI-reported zero usage/cost is not evidence of no inference or free service.",
            "Two synthetic exact-value integration calls, external gate, not semantic detector quality, native ACL, online revocation, automatic memory or general task acceptance."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); run, output = args.run.resolve(), args.output.resolve(); results = (ROOT / "results").resolve()
    if not run.is_relative_to(results) or not run.is_dir() or not output.is_relative_to(results) or output.exists():
        raise ValueError("existing_run_and_new_results_receipt_required")
    result = verify(run)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream: json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False); stream.write("\n")
    print(json.dumps({k:result[k] for k in ("status", "check_count", "passed_count", "failed_count", "failure")},ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)
