"""One native Qoder Write task, gated by real tool initialization metadata.

Preparation and metadata_init do not submit model prompts. Execution requires
execute=True, is one-use and has no automatic retry. This produces explicitly
requested static AGENTS content, not Auto-Memory or semantic fact extraction.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid

from .guard import no_links, strict_json, guard_decision, SAFE_ID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RESULTS_ROOT = ROOT/"results"/"qoder_source_generation_20261030"
NODE = Path(r"D:\nodejs\node.exe")
ENTRY = Path(r"F:\项目\多agent协同\data\runtime\qoder\node_modules\@qoder-ai\qodercli\bundle\qodercli.js")
ENTRY_SHA256 = "9a8fb19bb7f2dfe8d9d9933cb356fd21e789544316bacadc4f6c9b760bd41315"
VERSION = "qoder-native-static-source-v1"
MAX_PIPE_BYTES = 256*1024
ENV_KEYS = frozenset("PATH PATHEXT SYSTEMROOT WINDIR TEMP TMP USERPROFILE APPDATA LOCALAPPDATA HOMEDRIVE HOMEPATH PROGRAMFILES PROGRAMFILES(X86) COMMONPROGRAMFILES OS PROCESSOR_ARCHITECTURE".split())


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _save(path, value, *, exclusive=True):
    no_links(path)
    with Path(path).open("x" if exclusive else "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _read(path):
    no_links(path)
    return strict_json(Path(path).read_text(encoding="utf-8"))


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def safe_environment():
    value = {k: v for k, v in os.environ.items() if k.upper() in ENV_KEYS}
    for prefix in ("QODER_", "QODERCN_"):
        for key in ("MEMORY_HEADLESS", "MEMORY_PROJECT", "MEMORY_USER", "DREAM"):
            value[prefix+key] = "false"
    value["NO_BROWSER"] = "1"
    return value


def _run_root(run_dir, *, new=False):
    path = Path(run_dir).absolute()
    no_links(path)
    resolved, allowed = path.resolve(), RESULTS_ROOT.resolve()
    _require(resolved != allowed and resolved.is_relative_to(allowed), "run_outside_dedicated_results")
    _require(path == resolved, "run_path_not_canonical")
    if new:
        _require(not path.exists(), "run_must_be_new")
    else:
        _require(path.is_dir(), "run_missing")
    return path


def _runtime_metadata():
    _require(NODE.is_file() and ENTRY.is_file(), "native_runtime_missing")
    _require(_sha(ENTRY) == ENTRY_SHA256, "native_cli_hash_mismatch")
    package = _read(ENTRY.parent.parent/"package.json")
    _require(package.get("name") == "@qoder-ai/qodercli" and package.get("version") == "1.1.77", "native_cli_version_mismatch")
    return {"node_executable": str(NODE.resolve()), "node_sha256": _sha(NODE),
            "cli_entry": str(ENTRY.resolve()), "cli_sha256": ENTRY_SHA256, "version": "1.1.77"}


def _expected_argv(runtime, workspace):
    return [runtime["node_executable"], runtime["cli_entry"], "--cwd", str(workspace),
        "--setting-sources", "project", "--tools", "Write", "--permission-mode", "dont_ask",
        "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--disable-builtin-skills",
        "--no-session-persistence", "--max-turns", "2", "--max-output-tokens", "128",
        "--max-model-request-retries", "0", "--model", "DeepSeek-Flash",
        "--input-format", "stream-json", "--output-format", "stream-json", "--print"]


def prepare_run(run_dir, facts: list[str]):
    run = _run_root(run_dir, new=True)
    _require(isinstance(facts, list) and len(facts) == 4
        and all(isinstance(f, str) and f and f == f.strip() and "\n" not in f and "\r" not in f and "\x00" not in f for f in facts), "four_exact_synthetic_facts_required")
    content = "\n".join(facts)+"\n"
    _require(len(content.encode("utf-8")) <= 320, "source_fact_budget_exceeded")
    _require(not __import__("re").search(r"(?<!\S)@\S+|\[PVT_", content, __import__("re").I), "source_import_or_reserved_token")
    runtime = _runtime_metadata()
    run.mkdir(parents=True)
    workspace = run/"workspace"; workspace.mkdir()
    subprocess.run(["git", "init", "-q", str(workspace)], capture_output=True, check=True, timeout=15)
    _require((workspace/".git").is_dir(), "source_git_boundary_missing")
    target = workspace/"AGENTS.md"
    state_path = run/"guard_state.json"
    python = str(Path(sys.executable).resolve())
    hook = {"type": "command", "command": python,
        "args": ["-B", "-X", "utf8", str(HERE/"guard.py"), "--state", str(state_path)], "timeout": 10}
    settings = {"disableAllHooks": False, "autoMemoryEnabled": False, "autoMemoryUserScopeEnabled": False,
        "skills": {"enabled": False, "loadFromAgentsDirectory": False}, "experimental": {"enableAgents": False},
        "context": {"fileName": "AGENTS.md", "memoryBoundaryMarkers": [".git"], "loadMemoryFromIncludeDirectories": False},
        "plugins": {"autoUpdate": False}, "enabledPlugins": {},
        "permissions": {"allow": ["Edit(/AGENTS.md)"],
            "deny": ["Bash", "PowerShell", "WebFetch", "WebSearch", "Agent"]},
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [hook]}]}}
    # No broad Edit/Read denial: Edit(path) covers native Write and its internal
    # same-path read. The model's visible tool set independently omits both.
    (workspace/".qoder").mkdir()
    _save(workspace/".qoder"/"settings.json", settings)
    state = {"schema": VERSION, "armed": False, "session_id": None,
        "workspace": str(workspace), "target": str(target),
        "allowed_spellings": ["AGENTS.md", "./AGENTS.md", str(target), target.as_posix()],
        "expected_content_sha256": _digest(content), "claim_path": str(run/"write_claim.json")}
    state["allowed_spellings"] = list(dict.fromkeys(state["allowed_spellings"]))
    _save(state_path, state)
    prompt = ("This is an entirely synthetic research fixture. Use the native Write tool exactly once to create AGENTS.md in the current project. "
        "Write exactly the following four lines in this order, with a final newline. Do not add a heading, explanation, or code fence to the file. "
        "Do not change the facts or use any other tool. Actually call Write; printing the content is insufficient.\n\n"+content)
    _save(run/"input.json", {"synthetic": True, "facts": facts, "expected_content_sha256": _digest(content), "prompt": prompt})
    argv = _expected_argv(runtime, workspace)
    frozen = [run/"input.json", workspace/".qoder"/"settings.json"] + sorted(HERE.glob("*.py"))
    plan = {"schema": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": runtime, "workspace": str(workspace), "target": str(target), "argv": argv,
        "expected_content_sha256": _digest(content), "frozen_files": {str(p): _sha(p) for p in frozen},
        "guard_state_initial_sha256": _sha(state_path), "model_prompts_sent": 0,
        "budget": {"generation_jobs_max": 1, "automatic_retries": 0, "max_turns": 2,
            "max_output_tokens_per_model_turn": 128, "declared_total_output_tokens_max": 256,
            "supplied_prompt_count_max": 1, "supplier_atomic_money_cap": False},
        "scope": "Explicit exact four-line static-memory Write. Not Auto-Memory, learned fact extraction, native ACL, or OS sandbox.",
        "host_wrote_AGENTS": False, "credential_files_read_or_copied_by_adapter": False,
        "settings_sources": ["project"], "expected_visible_tools": ["Write"]}
    _save(run/"plan.json", plan)
    return plan


def _validate_prepared(run):
    plan = _read(run/"plan.json")
    _require(plan.get("schema") == VERSION, "invalid_plan")
    _require(plan.get("workspace") == str(run/"workspace") and plan.get("target") == str(run/"workspace"/"AGENTS.md"), "plan_path_mismatch")
    for name, expected in plan["frozen_files"].items():
        _require(_sha(no_links(name)) == expected, "frozen_file_changed")
    current = _runtime_metadata()
    _require(current == plan["runtime"], "native_runtime_changed")
    _require(plan.get("argv") == _expected_argv(current, run/"workspace"), "native_argv_changed")
    _require(_sha(run/"guard_state.json") == plan["guard_state_initial_sha256"], "guard_state_changed_before_execution")
    _require(not (run/"workspace"/"AGENTS.md").exists(), "target_exists_before_execution")
    _require(not (run/"write_claim.json").exists(), "write_claim_already_consumed")
    _require(not (run/"guard_events.jsonl").exists(), "guard_audit_already_present")
    no_links(run/"workspace"/".git")
    return plan


def validate_init(event, plan):
    _require(isinstance(event, dict) and event.get("type") == "system" and event.get("subtype") == "init", "native_init_missing")
    _require(event.get("tools") == ["Write"], "native_tool_set_not_exact_write")
    _require(event.get("permissionMode") in {"dont_ask", "dontAsk"}, "native_permission_mode_mismatch")
    _require(str(no_links(event.get("cwd", "")).resolve()) == plan["workspace"], "native_workspace_mismatch")
    _require(event.get("qodercli_version") == "1.1.77", "native_init_version_mismatch")
    _require(event.get("model") == "DeepSeek-Flash", "native_model_selector_mismatch")
    _require(event.get("mcp_servers") == [] and event.get("skills") == [] and event.get("plugins") == [], "native_extensions_not_empty")
    session = event.get("session_id")
    _require(isinstance(session, str) and SAFE_ID.fullmatch(session), "native_session_id_invalid")
    return {"type": "init", "tools": ["Write"], "permission_mode": event["permissionMode"],
        "cwd": plan["workspace"], "model": event["model"], "version": "1.1.77", "session_id": session,
        "mcp_servers": [], "skills": [], "plugins": [], "qualification": "native_metadata_observed"}


def sanitize_event(event, plan):
    """Retain only native evidence fields, never full stdout/credentials/text."""
    result = []
    if not isinstance(event, dict):
        raise ValueError("native_event_not_object")
    if event.get("type") == "system" and event.get("subtype") == "init":
        return [validate_init(event, plan)]
    kind = event.get("type")
    if kind in {"assistant", "user"}:
        message = event.get("message", {})
        blocks = message.get("content", []) if isinstance(message, dict) else []
        if isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    values = block.get("input")
                    call_id = block.get("id")
                    _require(isinstance(call_id, str) and SAFE_ID.fullmatch(call_id), "native_tool_id_invalid")
                    _require(block.get("name") == "Write" and isinstance(values, dict)
                        and set(values) == {"file_path", "content"} and isinstance(values.get("content"), str), "unexpected_native_tool_or_fields")
                    allowed = ["AGENTS.md", "./AGENTS.md", plan["target"], Path(plan["target"]).as_posix()]
                    _require(values.get("file_path") in allowed, "native_tool_target_mismatch")
                    digest = _digest(values["content"])
                    _require(digest == plan["expected_content_sha256"], "native_tool_content_mismatch")
                    result.append({"type": "tool_use", "tool_use_id": call_id, "name": "Write",
                        "target_matches": True, "content_sha256": digest})
                elif block.get("type") == "tool_result":
                    call_id = block.get("tool_use_id")
                    _require(isinstance(call_id, str) and SAFE_ID.fullmatch(call_id), "native_result_id_invalid")
                    _require("is_error" not in block or type(block["is_error"]) is bool, "invalid_native_result_error_flag")
                    result.append({"type": "tool_result", "tool_use_id": call_id,
                                   "is_error": block.get("is_error", False)})
    elif kind == "result":
        result.append({"type": "result", "subtype": event.get("subtype"),
            "is_error": event.get("is_error") is not False, "num_turns": event.get("num_turns"),
            "output_tokens": event.get("usage", {}).get("output_tokens") if isinstance(event.get("usage"), dict) else None})
    return result


def _drive(plan, *, prompt=None, timeout_seconds=45, on_init=None):
    """Initialize over stdio, verify tools, then at most one user prompt."""
    process = subprocess.Popen(plan["argv"], cwd=plan["workspace"], env=safe_environment(), shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    output = queue.Queue(); sizes = {"stdout": 0, "stderr": 0}; lock = threading.Lock()
    def drain(name, stream):
        try:
            while True:
                line = stream.readline(MAX_PIPE_BYTES+1) if name == "stdout" else stream.read(4096)
                if not line:
                    break
                with lock:
                    sizes[name] += len(line)
                    too_large = sizes[name] > MAX_PIPE_BYTES
                if too_large:
                    output.put(("error", "native_pipe_limit")); process.kill(); break
                if name == "stdout":
                    output.put(("stdout", line))
        finally:
            output.put((name+"_eof", None)); stream.close()
    threads = [threading.Thread(target=drain, args=(name, getattr(process, name)), daemon=True) for name in sizes]
    for thread in threads:
        thread.start()
    events, initialized, sent, error = [], False, False, None
    deadline = time.monotonic()+timeout_seconds
    initialize_id = "init-"+uuid.uuid4().hex
    def send(value):
        process.stdin.write((json.dumps(value, ensure_ascii=False)+"\n").encode("utf-8")); process.stdin.flush()
    try:
        send({"type": "control_request", "request_id": initialize_id, "request": {"subtype": "initialize"}})
        while time.monotonic() < deadline:
            try:
                kind, value = output.get(timeout=min(0.2, max(0.01, deadline-time.monotonic())))
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            if kind == "error":
                raise ValueError(value)
            if kind != "stdout":
                continue
            raw = strict_json(value.decode("utf-8"))
            clean = sanitize_event(raw, plan)
            for event in clean:
                if event["type"] == "init":
                    _require(not initialized, "duplicate_native_init")
                    initialized = True
                    if on_init is not None:
                        on_init(event)
                    if prompt is not None:
                        send({"type": "user", "message": {"role": "user", "content": prompt},
                              "session_id": event["session_id"], "parent_tool_use_id": None})
                        sent = True
                    else:
                        events.append(event)
                        return {"events": events, "error": None, "prompt_sent": False,
                                "metadata_only": True, "exit_code": None, "pipe_bytes": dict(sizes)}
                elif event["type"] in {"tool_use", "tool_result", "result"}:
                    _require(initialized and sent, "native_model_evidence_before_prompt")
                events.append(event)
                if event["type"] == "result" and sent:
                    process.stdin.close()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        raise ValueError("native_exit_timeout")
                    return {"events": events, "error": None, "prompt_sent": sent,
                            "metadata_only": False, "exit_code": process.returncode, "pipe_bytes": dict(sizes)}
        error = "native_init_missing" if not initialized else "native_generation_timeout_or_early_exit"
    except Exception as exc:
        error = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    finally:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass
        for thread in threads:
            thread.join(timeout=2)
    return {"events": events, "error": error, "prompt_sent": sent,
            "metadata_only": prompt is None, "exit_code": process.returncode, "pipe_bytes": dict(sizes)}


def metadata_init(run_dir, *, timeout_seconds=45):
    run = _run_root(run_dir)
    plan = _validate_prepared(run)
    _require(not (run/"generation_attempt.json").exists(), "generation_already_attempted")
    try:
        result = _drive(plan, timeout_seconds=timeout_seconds)
    except OSError as exc:
        result = {"events": [], "error": type(exc).__name__, "prompt_sent": False,
                  "metadata_only": True, "exit_code": None, "pipe_bytes": {}}
    _require(result["prompt_sent"] is False, "metadata_probe_sent_prompt")
    receipt = {"schema": VERSION, "status": "qualified" if not result["error"] and result["events"] else "failed",
               **result, "model_prompts_sent": 0, "generation_attempts": 0}
    _save(run/"metadata_qualification.json", receipt)
    return receipt


def verify_generation(run_dir):
    run = _run_root(run_dir)
    try:
        plan = _read(run/"plan.json")
        execution = _read(run/"execution_evidence.json")
        _require(execution.get("prompt_sent") is True and execution.get("error") is None
            and execution.get("exit_code") == 0, "native_execution_not_complete")
        events = execution["events"]
        inits = [e for e in events if e.get("type") == "init"]
        calls = [e for e in events if e.get("type") == "tool_use"]
        results = [e for e in events if e.get("type") == "tool_result"]
        finals = [e for e in events if e.get("type") == "result"]
        _require(len(inits) == len(calls) == len(results) == len(finals) == 1, "native_evidence_count_mismatch")
        call, answer = calls[0], results[0]
        _require(call.get("name") == "Write" and call.get("target_matches") is True
            and call.get("content_sha256") == plan["expected_content_sha256"], "native_write_binding_mismatch")
        _require(answer.get("tool_use_id") == call["tool_use_id"] and answer.get("is_error") is False, "native_write_result_not_success")
        _require(finals[0].get("is_error") is False and finals[0].get("subtype") == "success", "native_final_result_not_success")
        turns, tokens = finals[0].get("num_turns"), finals[0].get("output_tokens")
        _require(type(turns) is int and 0 < turns <= 2, "native_turn_budget_unverified")
        _require(type(tokens) is int and 0 <= tokens <= 256, "native_total_output_budget_unverified")
        guard_events = [strict_json(line) for line in (run/"guard_events.jsonl").read_text(encoding="utf-8").splitlines()]
        _require(len(guard_events) == 1 and guard_events[0].get("decision") == "continue_native_permission"
            and guard_events[0].get("tool_use_id") == call["tool_use_id"], "native_guard_not_observed_exactly_once")
        claim = _read(run/"write_claim.json")
        _require(claim.get("tool_use_id") == call["tool_use_id"]
            and claim.get("content_sha256") == plan["expected_content_sha256"], "one_use_claim_mismatch")
        state = _read(run/"guard_state.json")
        _require(state.get("armed") is True and state.get("session_id") == inits[0]["session_id"], "guard_session_binding_mismatch")
        for filename, expected in plan["frozen_files"].items():
            _require(_sha(no_links(filename)) == expected, "frozen_file_changed_during_generation")
        target = no_links(plan["target"])
        _require(target.is_file() and target.parent == run/"workspace", "native_source_file_missing")
        data = target.read_bytes()
        _require(_digest(data.decode("utf-8")) == plan["expected_content_sha256"], "native_source_bytes_mismatch")
        facts = _read(run/"input.json")["facts"]
        _require(data == ("\n".join(facts)+"\n").encode("utf-8"), "native_source_not_exact_four_lines")
        allowed = {"AGENTS.md", ".qoder/settings.json"}
        for path in (run/"workspace").rglob("*"):
            no_links(path)
            rel = path.relative_to(run/"workspace").as_posix()
            if path.is_file() and not rel.startswith(".git/"):
                _require(rel in allowed, "unexpected_source_workspace_file")
        return {"schema": VERSION, "status": "ok", "error": None, "source_path": str(target),
            "native_file_sha256": _sha(target), "tool_use_id": call["tool_use_id"],
            "tool_result_success": True, "model_prompts_sent": 1, "auto_memory_claim": False,
            "scope": "One exact native Write task observed through CLI events and local guard; trusted-host controlled synthetic evidence, not Auto-Memory."}
    except Exception as exc:
        return {"schema": VERSION, "status": "failed", "error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__,
                "auto_memory_claim": False, "tool_result_success": False}


def execute_generation(run_dir, execute=False, *, timeout_seconds=90):
    run = _run_root(run_dir)
    if execute is not True:
        return {"schema": VERSION, "status": "prepared_only", "model_prompts_sent": 0, "auto_memory_claim": False}
    plan = _validate_prepared(run)
    # This atomic marker prevents re-running after a transport/model failure.
    _save(run/"generation_attempt.json", {"schema": VERSION, "attempt": 1, "automatic_retries": 0})
    def arm(event):
        state = _read(run/"guard_state.json")
        state.update(armed=True, session_id=event["session_id"])
        _save(run/"guard_state.json", state, exclusive=False)
    input_data = _read(run/"input.json")
    try:
        evidence = _drive(plan, prompt=input_data["prompt"], timeout_seconds=timeout_seconds, on_init=arm)
    except OSError as exc:
        evidence = {"events": [], "error": type(exc).__name__, "prompt_sent": False,
                    "metadata_only": False, "exit_code": None, "pipe_bytes": {}}
    _save(run/"execution_evidence.json", evidence)
    receipt = verify_generation(run)
    receipt["execution_evidence_sha256"] = _sha(run/"execution_evidence.json")
    _save(run/"generation_receipt.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--metadata-init", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    value = metadata_init(args.run_dir) if args.metadata_init else execute_generation(args.run_dir, execute=args.execute)
    print(json.dumps(value, ensure_ascii=False, indent=2))
