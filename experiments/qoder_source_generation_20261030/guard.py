"""Exact-output PreToolUse guard. Standalone, no model/network dependencies.

A permitted input returns {}, deliberately leaving the native permission
pipeline in charge. Every invalid input returns an explicit deny, never allow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

MAX_EVENT_BYTES = 32768
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def no_links(path):
    """Check all existing ancestors, including Windows junction/reparse points."""
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
                raise ValueError("linked_path")
    return path


def deny(code):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": code}}


def guard_decision(event, state):
    """Pure check against trusted state, with filesystem observations only.

    The hook wrapper atomically consumes a one-use claim after this check. State
    contains only frozen hashes and paths, not credentials or restoration maps.
    """
    try:
        if not isinstance(event, dict) or not isinstance(state, dict) or state.get("armed") is not True:
            return deny("guard_not_armed")
        if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") != "Write":
            return deny("unexpected_hook_or_tool")
        call_id = event.get("tool_use_id")
        if not isinstance(call_id, str) or not SAFE_ID.fullmatch(call_id):
            return deny("invalid_tool_use_id")
        if event.get("session_id") != state.get("session_id") or not isinstance(state.get("session_id"), str):
            return deny("session_mismatch")
        workspace = no_links(state["workspace"])
        if not isinstance(event.get("cwd"), str) or not event["cwd"] or no_links(event["cwd"]).resolve() != workspace.resolve():
            return deny("workspace_mismatch")
        tool_input = event.get("tool_input")
        if not isinstance(tool_input, dict) or set(tool_input) != {"file_path", "content"}:
            return deny("unexpected_write_fields")
        raw_path, content = tool_input["file_path"], tool_input["content"]
        if not isinstance(raw_path, str) or raw_path not in state["allowed_spellings"]:
            return deny("path_not_registered")
        target = no_links(state["target"])
        actual = no_links(workspace/raw_path if not Path(raw_path).is_absolute() else raw_path)
        if actual.resolve() != target.resolve() or target.parent.resolve() != workspace.resolve() or target.name != "AGENTS.md":
            return deny("target_mismatch")
        if target.exists() or target.is_symlink():
            return deny("target_already_exists")
        if not isinstance(content, str):
            return deny("invalid_content_type")
        encoded = content.encode("utf-8")
        if len(encoded) > 512 or sha_bytes(encoded) != state["expected_content_sha256"]:
            return deny("content_outside_frozen_input")
        if re.search(r"(?<!\S)@\S+|\[PVT_", content, re.I):
            return deny("external_import_or_reserved_token")
        return {}  # No permissionDecision=allow/ask; normal pipeline continues.
    except (OSError, TypeError, KeyError, ValueError, UnicodeError, RuntimeError):
        return deny("guard_validation_failed")


def hook_main(state_path, stdin=None):
    """Return (output, exit_code). Invalid input is explicitly denied and exit 2."""
    output, code = deny("guard_input_invalid"), 2
    state, event = None, None
    try:
        state_path = no_links(Path(state_path).resolve(strict=True))
        state = strict_json(state_path.read_text(encoding="utf-8"))
        source = stdin if stdin is not None else sys.stdin.buffer
        raw = source.read(MAX_EVENT_BYTES+1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError("hook_input_limit")
        event = strict_json(raw.decode("utf-8"))
        output = guard_decision(event, state)
        if not output:
            claim = no_links(state["claim_path"])
            if claim.parent != state_path.parent:
                raise ValueError("invalid_claim_location")
            with claim.open("xb") as stream:
                stream.write(json.dumps({"tool_use_id": event["tool_use_id"],
                    "content_sha256": state["expected_content_sha256"]}, sort_keys=True).encode("utf-8"))
            code = 0
    except FileExistsError:
        output, code = deny("write_capability_already_consumed"), 2
    except Exception:
        output, code = deny("guard_runtime_failed"), 2
    # A fixed filename next to trusted state; no event-controlled paths.
    try:
        if state is not None:
            audit_path = no_links(Path(state_path).parent/"guard_events.jsonl")
            valid_id = event.get("tool_use_id") if isinstance(event, dict) else None
            if not isinstance(valid_id, str) or not SAFE_ID.fullmatch(valid_id):
                valid_id = None
            record = {"decision": "continue_native_permission" if code == 0 else "deny",
                "tool_use_id": valid_id,
                "content_sha256": state.get("expected_content_sha256") if code == 0 else None,
                "error": None if code == 0 else output["hookSpecificOutput"]["permissionDecisionReason"]}
            with audit_path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(record, sort_keys=True)+"\n")
    except Exception:
        return deny("guard_audit_failed"), 2
    return output, code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    result, exit_code = hook_main(args.state)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(exit_code)
