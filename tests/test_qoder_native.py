"""Zero-inference tests for the native Qoder question runner."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import qoder_native as qn

TOKEN = "[PVT_" + "A" * 24 + "_CUSTOMER_1]"


def envelope(**changes):
    value = {"type": "result", "subtype": "success", "is_error": False,
             "num_turns": 1, "result": TOKEN, "usage": {"input_tokens": 731, "output_tokens": 21},
             "modelUsage": {"DeepSeek-Flash": {"inputTokens": 731}},
             "total_cost_usd": 0, "total_credits": 0.01, "permission_denials": [],
             "session_id": "SESSION_METADATA_MUST_NOT_BE_RETURNED"}
    value.update(changes)
    return value


class NativeQuestionTests(unittest.TestCase):
    def setUp(self):
        qn.RESULTS_ROOT.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="qoder_fake_test_", dir=qn.RESULTS_ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "fixture"
        self.workspace.mkdir()
        (self.workspace / ".git").mkdir()
        self.memory = self.workspace / "AGENTS.md"
        self.memory.write_text("Synthetic customer memory: " + TOKEN, encoding="utf-8")
        self.entry = self.base / "qodercli.js"
        self.entry.write_bytes(b"// fake CLI source; never executable")
        self.node = self.base / "node.exe"
        self.node.write_bytes(b"fake node; never executable")
        settings = {"disableAllHooks": True, "autoMemoryEnabled": False,
                    "autoMemoryUserScopeEnabled": False,
                    "skills": {"enabled": False, "loadFromAgentsDirectory": False},
                    "experimental": {"enableAgents": False},
                    "context": {"fileName": "AGENTS.md", "memoryBoundaryMarkers": [".git"],
                                "loadMemoryFromIncludeDirectories": False},
                    "plugins": {"autoUpdate": False}, "enabledPlugins": {}}
        argv = [str(self.node), str(self.entry), "--setting-sources", "project", "--settings",
                json.dumps(settings), "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                "--disable-builtin-skills", "--tools", "", "--permission-mode", "dont_ask",
                "--max-turns", "1", "--max-output-tokens", "64", "--max-model-request-retries", "0",
                "--model", "DeepSeek-Flash", "--cwd", "<new isolated fixture git-root>",
                "--no-session-persistence", "--output-format", "json", "--print", "<synthetic query only>"]
        self.cap = {"schema_version": "qoder-capabilities-v1", "node_executable": str(self.node),
                    "cli_entry": str(self.entry), "cli_entry_sha256": hashlib.sha256(self.entry.read_bytes()).hexdigest(),
                    "package_version_verified": "1.1.77", "actual_cli_model_id": "DeepSeek-Flash",
                    "inference_argv_template": argv}
        self.cap_path = self.base / "capabilities.json"
        self.save_cap()
        self.calls = []

    def save_cap(self):
        self.cap_path.write_text(json.dumps(self.cap), encoding="utf-8")

    def run_fake(self, response=None, effect=None, prompt="Who is the customer?", **options):
        response = envelope() if response is None else response
        def fake(argv, prompt_bytes, **kwargs):
            self.calls.append((list(argv), prompt_bytes, deepcopy(kwargs)))
            if effect:
                effect()
            stdout = response if isinstance(response, bytes) else json.dumps(response).encode()
            return {"exit_code": options.get("exit_code", 0), "stdout": stdout,
                    "stderr_sha256": "a" * 64, "stderr_bytes": 19,
                    "error": options.get("process_error")}
        with patch.object(qn, "_run_pipes", side_effect=fake):
            return qn.run_qoder_question(self.workspace, prompt, capabilities_path=self.cap_path)

    def test_exact_query_stdin_and_no_facts_in_argv(self):
        result = self.run_fake()
        self.assertEqual(result["status"], "ok", result)
        argv, stdin, kwargs = self.calls[0]
        self.assertEqual(stdin, b"Who is the customer?")
        self.assertNotIn("Who is the customer?", argv)
        self.assertNotIn(TOKEN, json.dumps(argv))
        self.assertEqual(argv[-1], "--print")
        self.assertEqual(argv[argv.index("--cwd") + 1], str(self.workspace))
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        for flag, value in (("--max-turns", "1"), ("--max-output-tokens", "64"),
                            ("--max-model-request-retries", "0"), ("--setting-sources", "project")):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--no-session-persistence", argv)
        self.assertEqual(result["answer"], TOKEN)
        self.assertEqual(result["usage"]["input_tokens"], 731)
        self.assertEqual(result["reported_model_ids"], ["DeepSeek-Flash"])
        self.assertNotIn("SESSION_METADATA_MUST_NOT_BE_RETURNED", json.dumps(result))

    def test_environment_ignores_tokens_config_redirect_and_memory_injection(self):
        injected = {"QODER_PERSONAL_ACCESS_TOKEN": "PRIVATE_AUTH", "NODE_OPTIONS": "PRIVATE_NODE",
                    "QODER_CONFIG_DIR": "PRIVATE_AUTH_DIR", "PVT_SCORING_CANARY": TOKEN,
                    "QODER_MEMORY_HEADLESS": "true", "QODERCN_MEMORY_USER": "true"}
        with patch.dict(qn.os.environ, injected):
            result = self.run_fake(prompt="Which customer " + TOKEN + "?")
        env = self.calls[0][2]["environment"]
        self.assertEqual(result["status"], "ok")
        for key in ("QODER_PERSONAL_ACCESS_TOKEN", "NODE_OPTIONS", "QODER_CONFIG_DIR", "PVT_SCORING_CANARY"):
            self.assertNotIn(key, env)
        self.assertNotIn(TOKEN, json.dumps(env))
        self.assertNotIn("PRIVATE_AUTH", json.dumps(result))
        for prefix in ("QODER_", "QODERCN_"):
            for scope in ("HEADLESS", "PROJECT", "USER"):
                self.assertEqual(env[prefix + "MEMORY_" + scope], "false")

    def test_cli_source_change_before_call_blocks_spawn(self):
        self.entry.write_text("changed", encoding="utf-8")
        result = self.run_fake()
        self.assertEqual(result["error"], "cli_source_changed")
        self.assertEqual(self.calls, [])

    def test_cli_source_change_during_call_hides_result(self):
        result = self.run_fake(effect=lambda: self.entry.write_text("changed", encoding="utf-8"))
        self.assertEqual(result["error"], "cli_source_changed_during_call")
        self.assertIsNone(result["raw_response"])

    def test_memory_change_during_call_hides_even_unknown(self):
        result = self.run_fake(envelope(result="UNKNOWN"), effect=lambda: self.memory.write_text("changed", encoding="utf-8"))
        self.assertEqual(result["error"], "memory_changed_during_call")
        self.assertIsNone(result["answer"])

    def test_workspace_outside_results_is_rejected(self):
        with patch.object(qn, "_run_pipes") as process:
            result = qn.run_qoder_question(qn.ROOT, "Who?", capabilities_path=self.cap_path)
        self.assertEqual(result["error"], "workspace_outside_results_or_linked")
        process.assert_not_called()

    def test_missing_git_and_agents_are_preflight_failures(self):
        (self.workspace / ".git").rmdir()
        self.assertEqual(self.run_fake()["error"], "workspace_git_root_missing")
        (self.workspace / ".git").mkdir()
        self.memory.unlink()
        self.assertEqual(self.run_fake()["error"], "file_missing_or_linked")
        self.assertEqual(self.calls, [])

    def test_extra_rules_and_external_imports_rejected(self):
        (self.workspace / ".qoder").mkdir()
        self.assertEqual(self.run_fake()["error"], "unexpected_project_context")
        (self.workspace / ".qoder").rmdir()
        self.memory.write_text("@C:/outside/private.md", encoding="utf-8")
        self.assertEqual(self.run_fake()["error"], "memory_empty_or_external_import")
        self.assertEqual(self.calls, [])

    def test_argv_extra_prompt_or_system_override_is_rejected(self):
        self.cap["inference_argv_template"][2:2] = ["--append-system-prompt", TOKEN]
        self.save_cap()
        self.assertEqual(self.run_fake()["error"], "argv_unsafe_or_duplicate")
        self.assertEqual(self.calls, [])

    def test_constraints_cannot_be_raised_or_user_memory_enabled(self):
        for flag, bad in (("--max-turns", "2"), ("--tools", "*"), ("--max-output-tokens", "65"),
                          ("--setting-sources", "user,project")):
            with self.subTest(flag=flag):
                old = self.cap["inference_argv_template"][:]
                self.cap["inference_argv_template"][old.index(flag) + 1] = bad
                self.save_cap()
                self.assertEqual(self.run_fake()["error"], "argv_constraints_changed")
                self.cap["inference_argv_template"] = old
        self.assertEqual(self.calls, [])

    def test_active_mcp_and_hooks_are_rejected(self):
        args = self.cap["inference_argv_template"]
        pos = args.index("--mcp-config") + 1
        args[pos] = '{"mcpServers":{"injected":{"command":"anything"}}}'
        self.save_cap()
        self.assertEqual(self.run_fake()["error"], "mcp_not_empty")
        args[pos] = '{"mcpServers":{}}'
        pos = args.index("--settings") + 1
        settings = json.loads(args[pos]);settings["disableAllHooks"] = False
        args[pos] = json.dumps(settings)
        self.save_cap()
        self.assertEqual(self.run_fake()["error"], "settings_constraints_changed")
        self.assertEqual(self.calls, [])

    def test_numeric_true_cannot_impersonate_javascript_disable_hook_flag(self):
        args = self.cap["inference_argv_template"]
        index = args.index("--settings") + 1
        settings = json.loads(args[index]); settings["disableAllHooks"] = 1
        args[index] = json.dumps(settings)
        self.save_cap()
        self.assertEqual(self.run_fake()["error"], "settings_constraints_changed")
        self.assertEqual(self.calls, [])

    def test_no_parser_brace_extraction_or_duplicate_keys(self):
        for response in (b'warning PRIVATE\n{"type":"result"}', b'[]', b'{"type":"result","type":"result"}', b'{broken'):
            with self.subTest(response=response):
                result = self.run_fake(response)
                self.assertEqual(result["status"], "error")
                self.assertIsNone(result["raw_response"])
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_error_result_and_success_with_is_error_true_are_errors(self):
        for response in (envelope(subtype="error_max_turns", errors=["AUTH_PRIVATE"]),
                         envelope(is_error=True, result="AUTH_PRIVATE")):
            result = self.run_fake(response)
            self.assertEqual(result["error"], "qoder_result_error")
            self.assertNotIn("AUTH_PRIVATE", json.dumps(result))
            self.assertEqual(result["usage"]["output_tokens"], 21)

    def test_nonzero_exit_cannot_publish_even_valid_result(self):
        result = self.run_fake(exit_code=1)
        self.assertEqual(result["error"], "process_exit_nonzero")
        self.assertIsNone(result["answer"])

    def test_usage_invalid_is_not_fabricated_as_zero(self):
        for usage in ({"input_tokens": -1}, {"output_tokens": True}, {"output_tokens": 1.2}, "PRIVATE"):
            result = self.run_fake(envelope(usage=usage))
            self.assertEqual(result["error"], "usage_invalid")
            self.assertIsNone(result["usage"])
        result = self.run_fake(envelope(usage=None))
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["usage"])

    def test_unexpected_tool_or_extra_turns_rejected(self):
        self.assertEqual(self.run_fake(envelope(num_turns=2))["error"], "turn_limit_exceeded")
        self.assertEqual(self.run_fake(envelope(num_turns=0))["error"], "turn_limit_exceeded")
        self.assertEqual(self.run_fake(envelope(permission_denials=[{"tool": "read"}]))["error"], "unexpected_tool_attempt")

    def test_reported_output_over_cap_is_retained_and_blocks_answer(self):
        result = self.run_fake(envelope(usage={"input_tokens": 700, "output_tokens": 65}))
        self.assertEqual(result["error"], "output_token_limit_exceeded")
        self.assertEqual(result["usage"]["output_tokens"], 65)
        self.assertIsNone(result["answer"])

    def test_timeout_and_output_overflow_are_structured(self):
        result = self.run_fake(process_error="process_timeout", exit_code=-9)
        self.assertEqual(result["error"], "process_timeout")
        result = self.run_fake(b"x" * (qn.MAX_OUTPUT_BYTES + 1))
        self.assertEqual(result["error"], "process_output_limit")

    def test_empty_oversized_prompt_and_timeout_do_not_spawn(self):
        for prompt in ("", "x" * (qn.MAX_PROMPT_BYTES + 1), "bad\0prompt"):
            self.assertEqual(self.run_fake(prompt=prompt)["status"], "error")
        with patch.object(qn, "_run_pipes") as process:
            for timeout in (0, 121, True, float("nan")):
                result = qn.run_qoder_question(self.workspace, "Who?", capabilities_path=self.cap_path,
                                               timeout_seconds=timeout)
                self.assertEqual(result["error"], "timeout_invalid")
            process.assert_not_called()

    def test_receipt_contains_hashes_but_no_log_or_auth_envelope(self):
        result = self.run_fake()
        self.assertEqual(len(result["argv_sha256"]), 64)
        self.assertEqual(result["agent_memory_file_sha256"], hashlib.sha256(self.memory.read_bytes()).hexdigest())
        self.assertFalse(list(self.base.rglob("*.log")))
        self.assertNotIn("environment", result)
        self.assertNotIn("session_id", result)


class FakeProcess:
    def __init__(self, stdout=b"{}", stderr=b"PRIVATE_ACCOUNT_STDERR", timeout=False):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.timeout, self.killed = timeout, False

    def wait(self, timeout):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("fake", timeout)
        return -9 if self.killed else 0

    def kill(self):
        self.killed = True


class ProcessPipeTests(unittest.TestCase):
    def run_process(self, process):
        with patch.object(qn.subprocess, "Popen", return_value=process) as popen:
            result = qn._run_pipes(["fake-node", "fake-entry"], b"synthetic query only", workspace=qn.ROOT,
                                   environment={"SAFE": "yes"}, timeout_seconds=1)
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(popen.call_args.kwargs["creationflags"], getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertNotIn("PRIVATE_ACCOUNT_STDERR", json.dumps({k: v for k, v in result.items() if k != "stdout"}))
        return result

    def test_bounded_pipe_stdout(self):
        process = FakeProcess(stdout=b"x" * (qn.MAX_OUTPUT_BYTES + 100))
        result = self.run_process(process)
        self.assertEqual(result["error"], "process_output_limit")
        self.assertEqual(len(result["stdout"]), qn.MAX_OUTPUT_BYTES)
        self.assertTrue(process.killed)

    def test_bounded_pipe_stderr_and_no_raw_stderr_return(self):
        result = self.run_process(FakeProcess(stderr=b"x" * (qn.MAX_OUTPUT_BYTES + 1)))
        self.assertEqual(result["error"], "process_output_limit")
        self.assertNotIn("stderr", result)

    def test_timeout_kills_child_without_second_invocation(self):
        process = FakeProcess(timeout=True)
        result = self.run_process(process)
        self.assertEqual(result["error"], "process_timeout")
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
