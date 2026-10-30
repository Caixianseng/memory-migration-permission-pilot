"""Bounded Qoder static-workspace memory probe, never a memory authorization layer.

Only the caller's question goes through stdin. Synthetic AGENTS.md is discovered
by the native harness. No user memory, credentials, complete CLI envelope, stderr
or environment is returned or written to disk by this module.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import threading

ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = ROOT / "results"
MAX_OUTPUT_BYTES = 256 * 1024
MAX_PROMPT_BYTES = 4096
MAX_MEMORY_BYTES = 32768
VERSION = "qoder-native-question-v1"
_ENV_KEYS = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "OS", "PROCESSOR_ARCHITECTURE",
})
_MEMORY_ENV = {p + "MEMORY_" + scope: "false"
               for p in ("QODER_", "QODERCN_")
               for scope in ("HEADLESS", "PROJECT", "USER")}
_TOKEN_FIELDS = ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens",
                 "total_tokens", "cached_input_tokens", "cache_read_input_tokens",
                 "cache_creation_input_tokens")
_VALUES = {
    "--setting-sources": "project", "--tools": "", "--permission-mode": "dont_ask",
    "--max-turns": "1", "--max-output-tokens": "64", "--max-model-request-retries": "0",
    "--output-format": "json",
}
_SWITCHES = frozenset({"--strict-mcp-config", "--disable-builtin-skills",
                       "--no-session-persistence", "--print"})
_ARG_KEYS = frozenset(_VALUES) | {"--settings", "--mcp-config", "--model", "--cwd"}


class _Failure(ValueError):
    pass


def _json(text):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise _Failure("json_duplicate_key")
            value[key] = item
        return value
    try:
        return json.loads(text, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(_Failure("json_nonfinite")))
    except _Failure:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise _Failure("json_invalid") from None


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _under(path, root):
    return path != root and path.is_relative_to(root)


def _file_bytes(path, limit=None):
    if path.is_symlink() or not path.is_file():
        raise _Failure("file_missing_or_linked")
    if limit is not None and path.stat().st_size > limit:
        raise _Failure("file_too_large")
    return path.read_bytes()


def _workspace(workspace):
    candidate = Path(workspace).absolute()
    resolved = candidate.resolve(strict=True)
    root = RESULTS_ROOT.resolve(strict=True)
    if not _under(resolved, root) or candidate != resolved:
        raise _Failure("workspace_outside_results_or_linked")
    git = resolved / ".git"
    if (not resolved.is_dir() or not git.is_dir() or git.is_symlink()
            or git.resolve() != git):
        raise _Failure("workspace_git_root_missing")
    if (resolved / "AGENTS.local.md").exists() or (resolved / ".qoder").exists():
        raise _Failure("unexpected_project_context")
    memory_path = resolved / "AGENTS.md"
    if memory_path.resolve() != memory_path:
        raise _Failure("memory_linked")
    memory = _file_bytes(memory_path, MAX_MEMORY_BYTES)
    try:
        text = memory.decode("utf-8")
    except UnicodeError:
        raise _Failure("memory_utf8_invalid") from None
    if not text.strip() or re.search(r"(?<!\S)@\S+", text):
        raise _Failure("memory_empty_or_external_import")
    return resolved, _sha(memory)


def _safe_environment():
    environment = {key: value for key, value in os.environ.items() if key.upper() in _ENV_KEYS}
    environment.update(_MEMORY_ENV)
    environment["NO_BROWSER"] = "1"
    return environment


def _arguments(capabilities, workspace):
    args = capabilities.get("inference_argv_template")
    if not isinstance(args, list) or not all(isinstance(v, str) and "\0" not in v for v in args):
        raise _Failure("argv_template_invalid")
    if len(args) < 4 or args[-2:] != ["--print", "<synthetic query only>"]:
        raise _Failure("argv_prompt_template_invalid")
    args = list(args[:-1])  # --print is boolean; the question is written to stdin.
    if args[0] != capabilities.get("node_executable") or args[1] != capabilities.get("cli_entry"):
        raise _Failure("argv_entry_mismatch")
    options, index = {}, 2
    while index < len(args):
        flag = args[index]
        if flag in options or flag not in _ARG_KEYS | _SWITCHES:
            raise _Failure("argv_unsafe_or_duplicate")
        if flag in _SWITCHES:
            options[flag] = True
            index += 1
        else:
            if index + 1 >= len(args):
                raise _Failure("argv_value_missing")
            options[flag] = args[index + 1]
            index += 2
    if set(options) != _ARG_KEYS | _SWITCHES:
        raise _Failure("argv_constraints_missing")
    if any(options.get(k) != v for k, v in _VALUES.items()):
        raise _Failure("argv_constraints_changed")
    if options["--model"] != capabilities.get("actual_cli_model_id") or options["--model"] != "DeepSeek-Flash":
        raise _Failure("model_selector_mismatch")
    if _json(options["--mcp-config"]) != {"mcpServers": {}}:
        raise _Failure("mcp_not_empty")
    settings = _json(options["--settings"])
    required = {
        "disableAllHooks": True, "autoMemoryEnabled": False, "autoMemoryUserScopeEnabled": False,
        "skills": {"enabled": False, "loadFromAgentsDirectory": False},
        "experimental": {"enableAgents": False},
        "context": {"fileName": "AGENTS.md", "memoryBoundaryMarkers": [".git"],
                    "loadMemoryFromIncludeDirectories": False},
        "plugins": {"autoUpdate": False}, "enabledPlugins": {},
    }
    # Python True == 1; a numeric lookalike would NOT disable JS hooks safely.
    if json.dumps(settings, sort_keys=True) != json.dumps(required, sort_keys=True):
        raise _Failure("settings_constraints_changed")
    args[args.index("--cwd") + 1] = str(workspace)
    return args


def _run_pipes(argv, prompt_bytes, *, workspace, environment, timeout_seconds):
    """Read bounded stdout AND stderr concurrently; never use unbounded communicate."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(argv, cwd=str(workspace), env=environment, shell=False,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=flags)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    failures = []
    lock = threading.Lock()

    def kill():
        try:
            process.kill()
        except OSError:
            pass

    def drain(name, stream):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                with lock:
                    remaining = MAX_OUTPUT_BYTES - len(buffers[name])
                    buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        failures.append("process_output_limit")
                        kill()
                        break
        except (OSError, ValueError):
            with lock:
                failures.append("process_pipe_failure")
        finally:
            stream.close()

    def write():
        try:
            process.stdin.write(prompt_bytes)
            process.stdin.flush()
        except (OSError, ValueError):
            with lock:
                failures.append("process_stdin_failure")
        finally:
            process.stdin.close()

    threads = [threading.Thread(target=drain, args=(name, getattr(process, name)), daemon=True)
               for name in buffers]
    threads.append(threading.Thread(target=write, daemon=True))
    for thread in threads:
        thread.start()
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        failures.append("process_timeout")
        kill()
        try:
            exit_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            exit_code = None
    for thread in threads:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        failures.append("process_pipe_incomplete")
        kill()
    return {"exit_code": exit_code, "stdout": bytes(buffers["stdout"]),
            "stderr_sha256": _sha(bytes(buffers["stderr"])),
            "stderr_bytes": len(buffers["stderr"]), "error": failures[0] if failures else None}


def _parse_response(data):
    try:
        envelope = _json(data.decode("utf-8-sig"))
    except UnicodeError:
        raise _Failure("response_utf8_invalid") from None
    if not isinstance(envelope, dict) or envelope.get("type") != "result":
        raise _Failure("response_not_result")
    usage = envelope.get("usage")
    if usage is not None and not isinstance(usage, dict):
        raise _Failure("usage_invalid")
    public_usage = {}
    for key in _TOKEN_FIELDS:
        if usage is not None and key in usage:
            count = usage[key]
            if type(count) is not int or count < 0:
                raise _Failure("usage_invalid")
            public_usage[key] = count
    costs = {}
    for key in ("total_credits", "total_cost_usd"):
        if key in envelope:
            number = envelope[key]
            if (type(number) not in (int, float) or number < 0 or number > 10**12
                    or not math.isfinite(number)):
                raise _Failure("usage_invalid")
            costs[key] = number
    model_ids = []
    model_usage = envelope.get("modelUsage", {})
    if isinstance(model_usage, dict):
        model_ids = sorted(k for k in model_usage if isinstance(k, str) and
                           re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}", k))
    result = {"usage": public_usage or None, "cli_reported_cost": costs or None,
              "reported_model_ids": model_ids}
    if any(public_usage.get(key, 0) > 64 for key in ("output_tokens", "completion_tokens")):
        return {**result, "error": "output_token_limit_exceeded"}
    # Qoder can report subtype success AND is_error true for authentication errors.
    if envelope.get("is_error") is not False or envelope.get("subtype") != "success":
        return {**result, "error": "qoder_result_error"}
    turns = envelope.get("num_turns")
    if type(turns) is not int or turns != 1:
        return {**result, "error": "turn_limit_exceeded"}
    answer = envelope.get("result")
    if not isinstance(answer, str) or not answer.strip() or len(answer.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return {**result, "error": "result_text_missing"}
    if envelope.get("permission_denials") not in (None, []):
        return {**result, "error": "unexpected_tool_attempt"}
    return {**result, "answer": answer.strip(), "raw_response": answer, "error": None}


def run_qoder_question(workspace: Path, prompt: str, *, capabilities_path,
                       timeout_seconds=120):
    """One explicitly invoked, bounded question; caller owns the four-call budget.

    Raw response means only the final synthetic result text, never the entire
    account/session envelope. Native static memory is context, not authorization.
    """
    receipt = {"status": "error", "answer": None, "raw_response": None, "usage": None,
               "exit_code": None, "model": None, "version": None,
               "agent_memory_file_sha256": None, "argv_sha256": None,
               "error": None, "invocation_started": False, "wrapper_version": VERSION}
    try:
        if not isinstance(prompt, str) or not prompt.strip() or "\0" in prompt:
            raise _Failure("prompt_invalid")
        prompt_bytes = prompt.encode("utf-8")
        if len(prompt_bytes) > MAX_PROMPT_BYTES:
            raise _Failure("prompt_too_large")
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
            raise _Failure("timeout_invalid")
        workspace, memory_sha = _workspace(workspace)
        receipt["agent_memory_file_sha256"] = memory_sha
        capabilities = _json(_file_bytes(Path(capabilities_path), 128 * 1024).decode("utf-8"))
        if not isinstance(capabilities, dict) or capabilities.get("schema_version") != "qoder-capabilities-v1":
            raise _Failure("capabilities_invalid")
        entry = Path(capabilities["cli_entry"])
        node = Path(capabilities["node_executable"])
        if not entry.is_absolute() or not node.is_absolute() or not node.is_file():
            raise _Failure("executable_invalid")
        source_sha = _sha(_file_bytes(entry))
        if source_sha != capabilities.get("cli_entry_sha256"):
            raise _Failure("cli_source_changed")
        if capabilities.get("package_version_verified") != "1.1.77":
            raise _Failure("cli_version_unverified")
        argv = _arguments(capabilities, workspace)
        receipt.update(model=capabilities["actual_cli_model_id"], version="1.1.77",
                       argv_sha256=_sha(json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
                       cli_entry_sha256=source_sha, invocation_started=True)
        response = _run_pipes(argv, prompt_bytes, workspace=workspace,
                              environment=_safe_environment(), timeout_seconds=timeout_seconds)
        receipt.update(exit_code=response["exit_code"], stderr_sha256=response["stderr_sha256"],
                       stderr_bytes=response["stderr_bytes"])
        # Check evidence before exposing ANY model answer, including UNKNOWN.
        if _workspace(workspace)[1] != memory_sha:
            raise _Failure("memory_changed_during_call")
        if _sha(_file_bytes(entry)) != source_sha:
            raise _Failure("cli_source_changed_during_call")
        if response.get("error"):
            raise _Failure(response["error"])
        if len(response["stdout"]) > MAX_OUTPUT_BYTES:
            raise _Failure("process_output_limit")
        parsed = _parse_response(response["stdout"])
        receipt.update({k: v for k, v in parsed.items() if k != "error"})
        if response["exit_code"] != 0:
            raise _Failure("process_exit_nonzero")
        if parsed.get("error"):
            raise _Failure(parsed["error"])
        receipt.update(status="ok", error=None)
    except _Failure as exc:
        receipt.update(error=str(exc), answer=None, raw_response=None)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        receipt.update(error="qoder_preflight_or_process_failure", answer=None, raw_response=None)
    return receipt
