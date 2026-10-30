"""Safety checks with synthetic protocol fixtures; never invoke a model."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.qoder_source_generation_20261030 import guard, writer


FACTS = ["通知邮箱为native.source@example.invalid。", "验收区为北侧蓝柜。", "内部口令为NS-438。", "包装标记为三角。"]


def put(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class QoderSourceGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fake_runtime = {"node_executable": str(self.root/"node.exe"), "node_sha256": "node-hash",
            "cli_entry": str(self.root/"cli.js"), "cli_sha256": writer.ENTRY_SHA256, "version": "1.1.77"}
        self.root_patch = patch.object(writer, "RESULTS_ROOT", self.root)
        self.runtime_patch = patch.object(writer, "_runtime_metadata", return_value=self.fake_runtime)
        self.root_patch.start(); self.runtime_patch.start()
        self.addCleanup(self.root_patch.stop); self.addCleanup(self.runtime_patch.stop)
        self.run = self.root/"run"
        self.plan = writer.prepare_run(self.run, FACTS)
        self.workspace = self.run/"workspace"
        self.content = "\n".join(FACTS)+"\n"

    def state(self):
        state = writer._read(self.run/"guard_state.json")
        state.update(armed=True, session_id="session-fixture")
        return state

    def event(self):
        return {"hook_event_name": "PreToolUse", "session_id": "session-fixture", "cwd": str(self.workspace),
                "tool_name": "Write", "tool_use_id": "tool_fixture_1", "tool_input": {"file_path": "AGENTS.md", "content": self.content}}

    def init(self):
        return {"type": "system", "subtype": "init", "tools": ["Write"], "permissionMode": "dont_ask",
                "cwd": str(self.workspace), "qodercli_version": "1.1.77", "model": "DeepSeek-Flash",
                "mcp_servers": [], "skills": [], "plugins": [], "session_id": "session-fixture"}

    def simulated_evidence(self):
        # This method deliberately writes protocol fixtures only in a temporary
        # unittest directory. It is not a real native generation result.
        state = self.state(); put(self.run/"guard_state.json", state)
        output, code = guard.hook_main(self.run/"guard_state.json", io.BytesIO(json.dumps(self.event(), ensure_ascii=False).encode()))
        self.assertEqual((output, code), ({}, 0))
        use = {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "tool_fixture_1", "name": "Write",
               "input": {"file_path": "AGENTS.md", "content": self.content}}]}}
        result = {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "tool_fixture_1", "content": "synthetic success"}]}}
        final = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 2, "usage": {"output_tokens": 128}}
        events = []
        for item in (self.init(), use, result, final):
            clean = writer.sanitize_event(item, self.plan)
            if item is not final and item.get("type") == "system":
                clean[0].update(accepted=True)
                clean.append({"type": "prompt_sent", "ordinal": 1})
            events.extend(clean)
        put(self.run/"execution_evidence.json", {"prompt_sent": True, "user_prompts_sent": 1,
                                              "error": None, "exit_code": 0, "events": events})
        (self.workspace/"AGENTS.md").write_bytes(self.content.encode("utf-8"))

    def test_prepare_creates_no_agents_and_has_frozen_exact_permissions(self):
        self.assertFalse((self.workspace/"AGENTS.md").exists())
        self.assertFalse(self.plan["host_wrote_AGENTS"])
        settings = writer._read(self.workspace/".qoder/settings.json")
        self.assertEqual(settings["permissions"]["allow"], ["Edit(/AGENTS.md)"])
        self.assertNotIn("Read", settings["permissions"]["deny"])
        self.assertFalse(settings["autoMemoryEnabled"])
        self.assertFalse(settings["autoMemoryUserScopeEnabled"])
        self.assertFalse(settings["disableAllHooks"])
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"], str(Path(writer.sys.executable).resolve()))
        self.assertEqual(writer._validate_prepared(self.run)["argv"], self.plan["argv"])

    def test_valid_guard_does_not_override_native_permission(self):
        self.assertEqual(guard.guard_decision(self.event(), self.state()), {})

    def test_guard_accepts_actual_native_base_input_layout_without_reading_transcript(self):
        # Mirrors createCoreBaseInput + firePreToolUseEvent in pinned CLI.
        event = dict(self.event(), permission_mode="dont_ask", transcript_path="PRIVATE-PATH-NOT-OPENED", model="DeepSeek-Flash")
        state = self.state()
        with patch.object(Path, "read_text", side_effect=AssertionError("must_not_open_transcript")):
            self.assertEqual(guard.guard_decision(event, state), {})

    def test_unarmed_unknown_session_missing_cwd_or_other_tool_is_denied(self):
        changes = [{"session_id": "other"}, {"tool_name": "Bash"}, {"cwd": ""}, {"hook_event_name": "PostToolUse"}]
        for values in changes:
            with self.subTest(values=values):
                event = {**self.event(), **values}
                self.assertEqual(guard.guard_decision(event, self.state())["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(guard.guard_decision(self.event(), writer._read(self.run/"guard_state.json"))["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_path_spellings_outside_exact_allowlist_are_denied(self):
        for value in ("../AGENTS.md", "sub/AGENTS.md", "AGENTS.md:stream", "NUL", "\\\\host\\share\\AGENTS.md", "AGENTS.md.", "\\\\?\\C:\\AGENTS.md", ".qoder/settings.json"):
            with self.subTest(value=value):
                event = self.event(); event["tool_input"]["file_path"] = value
                self.assertEqual(guard.guard_decision(event, self.state())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_preexisting_target_cannot_be_overwritten(self):
        (self.workspace/"AGENTS.md").write_text("existing", encoding="utf-8")
        self.assertEqual(guard.guard_decision(self.event(), self.state())["hookSpecificOutput"]["permissionDecisionReason"], "target_already_exists")

    def test_content_changes_and_extra_tool_fields_are_denied(self):
        for mutate in (lambda e: e["tool_input"].update(content=self.content+"extra"),
                       lambda e: e["tool_input"].update(path="other"),
                       lambda e: e["tool_input"].update(content="@../secret\n")):
            event = self.event(); mutate(event)
            self.assertEqual(guard.guard_decision(event, self.state())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_hook_capability_is_atomic_one_use_and_logs_no_plain_content(self):
        put(self.run/"guard_state.json", self.state())
        raw = json.dumps(self.event(), ensure_ascii=False).encode()
        self.assertEqual(guard.hook_main(self.run/"guard_state.json", io.BytesIO(raw)), ({}, 0))
        output, code = guard.hook_main(self.run/"guard_state.json", io.BytesIO(raw))
        self.assertEqual(code, 2)
        self.assertEqual(output["hookSpecificOutput"]["permissionDecisionReason"], "write_capability_already_consumed")
        log = (self.run/"guard_events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(FACTS[0], log)
        self.assertNotIn("native.source@example.invalid", log)
        self.assertIn("content_sha256", log)

    def test_duplicate_json_or_oversized_input_fails_closed(self):
        put(self.run/"guard_state.json", self.state())
        for raw in (b'{"tool_name":"Write","tool_name":"Bash"}', b"x"*(guard.MAX_EVENT_BYTES+1)):
            output, code = guard.hook_main(self.run/"guard_state.json", io.BytesIO(raw))
            self.assertEqual(code, 2)
            self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_native_init_requires_exact_write_and_empty_extensions(self):
        self.assertEqual(writer.validate_init(self.init(), self.plan)["tools"], ["Write"])
        for field, value in (("tools", ["Write", "Bash"]), ("skills", ["private"]), ("plugins", [{"name": "unknown"}]),
                             ("permissionMode", "bypass_permissions"), ("model", "auto")):
            event = self.init(); event[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                writer.validate_init(event, self.plan)

    def test_sanitized_events_contain_hashes_and_no_source_or_hidden_text(self):
        event = {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "PRIVATE-DO-NOT-PERSIST"},
            {"type": "text", "text": "PRIVATE-DO-NOT-PERSIST"},
            {"type": "tool_use", "id": "tool_fixture_1", "name": "Write", "input": self.event()["tool_input"]}]}}
        serialized = json.dumps(writer.sanitize_event(event, self.plan))
        self.assertNotIn("PRIVATE", serialized)
        self.assertNotIn("native.source", serialized)
        self.assertIn(self.plan["expected_content_sha256"], serialized)

    def test_successful_fixture_needs_all_three_native_write_evidence_parts(self):
        self.simulated_evidence()
        result = writer.verify_generation(self.run)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["auto_memory_claim"])
        self.assertEqual(result["native_file_sha256"], hashlib.sha256(self.content.encode()).hexdigest())
        evidence = writer._read(self.run/"execution_evidence.json")
        evidence["events"] = [e for e in evidence["events"] if e["type"] != "tool_use"]
        put(self.run/"execution_evidence.json", evidence)
        self.assertEqual(writer.verify_generation(self.run)["status"], "failed")

    def test_model_saying_saved_without_tool_or_host_written_file_is_not_success(self):
        (self.workspace/"AGENTS.md").write_bytes(self.content.encode("utf-8"))
        put(self.run/"execution_evidence.json", {"prompt_sent": True, "error": None, "exit_code": 0,
            "events": [writer.validate_init(self.init(), self.plan), {"type": "result", "subtype": "success", "is_error": False}]})
        self.assertEqual(writer.verify_generation(self.run)["status"], "failed")

    def test_actual_file_mutation_or_unregistered_extra_file_is_rejected(self):
        self.simulated_evidence()
        (self.workspace/"AGENTS.md").write_text("changed", encoding="utf-8")
        self.assertEqual(writer.verify_generation(self.run)["status"], "failed")
        (self.workspace/"AGENTS.md").write_bytes(self.content.encode("utf-8"))
        (self.workspace/"extra.txt").write_text("extra", encoding="utf-8")
        self.assertEqual(writer.verify_generation(self.run)["error"], "unexpected_source_workspace_file")

    def test_execute_default_and_invalidated_plan_never_invoke_runtime(self):
        with patch.object(writer, "_drive") as drive:
            self.assertEqual(writer.execute_generation(self.run)["status"], "prepared_only")
            drive.assert_not_called()
            plan = deepcopy(self.plan); plan["argv"].append("--yolo")
            put(self.run/"plan.json", plan)
            with self.assertRaisesRegex(ValueError, "argv_changed"):
                writer.execute_generation(self.run, execute=True)
            drive.assert_not_called()

    def test_metadata_init_never_supplies_a_user_prompt(self):
        clean = writer.validate_init(self.init(), self.plan)
        with patch.object(writer, "_drive", return_value={"events": [clean], "error": None, "prompt_sent": False}) as drive:
            receipt = writer.metadata_init(self.run)
        self.assertEqual(receipt["status"], "qualified")
        self.assertEqual(receipt["model_prompts_sent"], 0)
        self.assertNotIn("prompt", drive.call_args.kwargs)

    def test_lifecycle_allows_one_valid_reinit_without_resending_prompt(self):
        lifecycle = writer.NativeLifecycle()
        first = writer.validate_init(self.init(), self.plan)
        self.assertTrue(lifecycle.observe_init(first))
        lifecycle.mark_prompt_sent()
        second = writer.validate_init(dict(self.init(), session_id="native-second-session"), self.plan)
        self.assertFalse(lifecycle.observe_init(second))
        self.assertTrue(second["session_changed_from_previous_init"])
        self.assertEqual(lifecycle.prompt_count, 1)
        self.assertEqual(lifecycle.session_id, "native-second-session")
        with self.assertRaisesRegex(ValueError, "only_be_sent_once"):
            lifecycle.mark_prompt_sent()

    def test_lifecycle_rejects_third_or_post_tool_init(self):
        lifecycle = writer.NativeLifecycle()
        clean = writer.validate_init(self.init(), self.plan)
        lifecycle.observe_init(dict(clean)); lifecycle.mark_prompt_sent()
        lifecycle.observe_init(dict(clean))
        with self.assertRaisesRegex(ValueError, "limit_exceeded"):
            lifecycle.observe_init(dict(clean))
        lifecycle = writer.NativeLifecycle()
        lifecycle.observe_init(dict(clean)); lifecycle.mark_prompt_sent(); lifecycle.observe_tool()
        with self.assertRaisesRegex(ValueError, "after_tool"):
            lifecycle.observe_init(dict(clean))

    def test_lifecycle_reinit_requires_same_scope_and_a_sent_prompt(self):
        for field, value in (("tools", ["Write", "Read"]), ("permissionMode", "auto"),
                             ("cwd", str(self.root)), ("model", "auto"), ("qodercli_version", "1.1.78"),
                             ("mcp_servers", [{"name": "unknown"}]), ("skills", ["unknown"]), ("plugins", ["unknown"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                writer.validate_init(dict(self.init(), **{field: value}), self.plan)
        lifecycle = writer.NativeLifecycle()
        clean = writer.validate_init(self.init(), self.plan)
        lifecycle.observe_init(dict(clean))
        with self.assertRaisesRegex(ValueError, "before_first_prompt"):
            lifecycle.observe_init(dict(clean))

    def test_rebind_requires_no_claim_and_no_existing_source(self):
        clean = writer.validate_init(self.init(), self.plan)
        writer._arm_guard(self.run, clean)
        writer._arm_guard(self.run, dict(clean, session_id="native-second-session"))
        self.assertEqual(writer._read(self.run/"guard_state.json")["session_id"], "native-second-session")
        put(self.run/"write_claim.json", {"tool_use_id": "used"})
        with self.assertRaisesRegex(ValueError, "consumed_write_claim"):
            writer._arm_guard(self.run, clean)
        (self.run/"write_claim.json").unlink()
        (self.workspace/"AGENTS.md").write_bytes(self.content.encode())
        with self.assertRaisesRegex(ValueError, "existing_source"):
            writer._arm_guard(self.run, clean)

    def test_rejected_native_metadata_preserves_safe_failure_fields(self):
        event = dict(self.init(), tools=["Write", "Bash"], api_key="DO-NOT-PERSIST")
        record = writer.rejected_init_evidence(event, self.plan, "native_tool_set_not_exact_write")
        self.assertFalse(record["field_matches_frozen"]["tools"])
        self.assertNotIn("DO-NOT-PERSIST", json.dumps(record))

    def test_verifier_accepts_two_valid_pretool_inits_and_uses_last_session(self):
        self.simulated_evidence()
        evidence = writer._read(self.run/"execution_evidence.json")
        second = writer.validate_init(dict(self.init(), session_id="native-second-session"), self.plan)
        second["accepted"] = True
        evidence["events"].insert(2, second)
        put(self.run/"execution_evidence.json", evidence)
        state = writer._read(self.run/"guard_state.json"); state["session_id"] = second["session_id"]
        put(self.run/"guard_state.json", state)
        result = writer.verify_generation(self.run)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["native_init_count"], 2)
        self.assertEqual(result["final_native_session_id"], "native-second-session")

    def test_verifier_does_not_relabel_v1_plan_as_v2(self):
        self.simulated_evidence()
        plan = writer._read(self.run/"plan.json"); plan["schema"] = "qoder-native-static-source-v1"
        put(self.run/"plan.json", plan)
        self.assertEqual(writer.verify_generation(self.run)["error"], "source_spec_version_mismatch")

    def test_run_outside_dedicated_root_and_non_four_fact_input_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            writer.prepare_run(self.root.parent/"outside", FACTS)
        with self.assertRaisesRegex(ValueError, "four_exact"):
            writer.prepare_run(self.root/"bad", FACTS[:3])

    def test_environment_does_not_forward_tokens_and_disables_all_memory_paths(self):
        with patch.dict(os.environ, {"QODER_PERSONAL_ACCESS_TOKEN": "DO-NOT-COPY", "DEEPSEEK_API_KEY": "DO-NOT-COPY"}):
            env = writer.safe_environment()
        self.assertNotIn("QODER_PERSONAL_ACCESS_TOKEN", env)
        self.assertNotIn("DEEPSEEK_API_KEY", env)
        for prefix in ("QODER_", "QODERCN_"):
            for name in ("MEMORY_HEADLESS", "MEMORY_PROJECT", "MEMORY_USER"):
                self.assertEqual(env[prefix+name], "false")

    def test_windows_standard_paths_preserved_without_ambient_environment_copy(self):
        standard = {"SystemDrive": "C:", "ProgramData": r"C:\ProgramData", "ALLUSERSPROFILE": r"C:\ProgramData",
                    "ComSpec": r"C:\Windows\System32\cmd.exe"}
        with patch.dict(os.environ, {**standard, "AWS_SECRET_ACCESS_KEY": "DO-NOT-COPY",
                "PRIVATE_SESSION_SETTING": "DO-NOT-COPY", "QODER_AUTH_TOKEN": "DO-NOT-COPY"}):
            env = writer.safe_environment()
        upper = {key.upper(): value for key, value in env.items()}
        for key, value in standard.items():
            self.assertEqual(upper[key.upper()], value)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", upper)
        self.assertNotIn("PRIVATE_SESSION_SETTING", upper)
        self.assertNotIn("QODER_AUTH_TOKEN", upper)

    def test_reported_zero_tokens_is_not_presented_as_verified_actual_usage(self):
        self.simulated_evidence()
        evidence = writer._read(self.run/"execution_evidence.json")
        evidence["events"][-1]["output_tokens"] = 0
        put(self.run/"execution_evidence.json", evidence)
        result = writer.verify_generation(self.run)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["reported_output_tokens"], 0)
        self.assertIsNone(result["actual_output_tokens"])
        self.assertIs(result["actual_output_tokens_verified"], False)


if __name__ == "__main__":
    unittest.main()
