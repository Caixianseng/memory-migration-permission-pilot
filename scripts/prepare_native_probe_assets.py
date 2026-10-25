"""Prepare path-correct local probe assets, without executing any client.

No subprocess/network/authentication calls. Qoder output remains intentionally
UNQUALIFIED until separate explicit CLI metadata checks have been performed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "examples" / "native_agent_probe_assets"
PROBE_RELATIVE = Path("results/native_agent_probe_20261026")
SUPPORTED_QODER_VERSION = "1.1.77"
_FILES = ("dsh_single_request_guard.mjs", "sdk_guard_metadata.patch.template.json",
          "qoder_capabilities.example.json")


class AssetPreparationError(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise AssetPreparationError(code)


def _sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(data):
    def unique(items):
        value = {}
        for key, item in items:
            _require(key not in value, "json_duplicate_key")
            value[key] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(AssetPreparationError("json_nonfinite")))
    except AssetPreparationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AssetPreparationError("json_invalid") from None


def _regular(path, *, name=None, limit=None):
    path = Path(path).absolute()
    _require(not str(path).startswith(("\\\\", "//")), "network_path_not_allowed")
    _require(path.is_file() and not path.is_symlink() and path.resolve() == path,
             "local_regular_file_required")
    _require(name is None or path.name == name, "unexpected_installed_file_name")
    _require(limit is None or path.stat().st_size <= limit, "input_file_too_large")
    return path


def _fill(value, replacements):
    if isinstance(value, str):
        for marker, replacement in replacements.items():
            value = value.replace(marker, replacement)
        return value
    if isinstance(value, list):
        return [_fill(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _fill(item, replacements) for key, item in value.items()}
    return value


def _write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def _qoder_inputs(cli_entry, node_executable, package_json, expected_version):
    _require(expected_version == SUPPORTED_QODER_VERSION, "unsupported_qoder_version")
    _require((cli_entry is None) == (node_executable is None), "qoder_and_node_paths_must_be_paired")
    if cli_entry is None:
        _require(package_json is None, "package_manifest_without_cli")
        return None
    entry = _regular(cli_entry, name="qodercli.js", limit=64 * 1024 * 1024)
    _require(entry.parent.name == "bundle", "qoder_bundle_entry_required")
    node = _regular(node_executable)
    _require(node.name.lower() in {"node", "node.exe"}, "node_executable_name_invalid")
    manifest = _regular(package_json or entry.parent.parent / "package.json", name="package.json", limit=128 * 1024)
    package = _json(manifest.read_bytes())
    _require(isinstance(package, dict) and package.get("name") == "@qoder-ai/qodercli"
             and package.get("version") == expected_version, "qoder_package_version_mismatch")
    _require(manifest.parent == entry.parent.parent, "qoder_manifest_entry_layout_mismatch")
    return {"entry": str(entry), "node": str(node), "entry_sha256": _sha(entry),
            "node_sha256": _sha(node), "package_manifest_sha256": _sha(manifest),
            "package_manifest_version": package["version"], "runtime_version_executed": False}


def prepare_assets(output=None, *, qoder_cli_entry=None, node_executable=None,
                   qoder_package_json=None, expected_qoder_version=SUPPORTED_QODER_VERSION):
    expected_output = (ROOT / PROBE_RELATIVE).absolute()
    output = Path(output or expected_output).absolute()
    _require(output == expected_output and output.resolve() == output, "frozen_runner_probe_root_required")
    _require(not output.exists() and not output.is_symlink(), "output_already_exists_no_overwrite")
    trusted = _qoder_inputs(qoder_cli_entry, node_executable, qoder_package_json, expected_qoder_version)
    public_manifest = _json(_regular(ASSETS / "asset_manifest.json", limit=128 * 1024).read_bytes())
    _require(public_manifest.get("schema") == "native-probe-public-assets-v1"
             and set(public_manifest.get("files", {})) == set(_FILES), "public_asset_manifest_invalid")
    for name in _FILES:
        asset = _regular(ASSETS / name, limit=128 * 1024)
        _require(_sha(asset) == public_manifest["files"][name], "public_asset_hash_changed")
    patch = _json((ASSETS / "sdk_guard_metadata.patch.template.json").read_bytes())
    qoder = _json((ASSETS / "qoder_capabilities.example.json").read_bytes())
    _require(qoder.get("package_version_verified") is None
             and qoder.get("runtime_cli_executed") is False, "example_must_be_unqualified")
    guard = output / "dsh_single_request_guard.mjs"
    replacements = {"__RUNTIME_HOME__": str(output / "sdk_metadata_home"),
                    "__GUARD_FILE_URI__": guard.as_uri(),
                    "__GUARD_RECEIPT_PATH__": str(output / "sdk_guard_zero_model_counts.json")}
    patch = _fill(patch, replacements)
    if trusted:
        qoder = _fill(qoder, {"__NODE_EXECUTABLE__": trusted["node"], "__QODER_CLI_ENTRY__": trusted["entry"]})
        qoder["cli_entry_sha256"] = trusted["entry_sha256"]
        qoder["package_manifest_check"] = trusted
    # Even a matching package manifest is not CLI --version/model-catalog proof.
    qoder["package_version_verified"] = None
    qoder["node_version_verified"] = None
    qoder["metadata_preflight_completed"] = False
    output.mkdir(parents=True, exist_ok=False)
    with guard.open("xb") as stream:
        stream.write((ASSETS / guard.name).read_bytes())
    _write_json(output / "sdk_guard_metadata.patch.yml", patch)
    _write_json(output / "qoder_capabilities.example.json", qoder)
    # This empty marker stops native static memory discovery at the metadata
    # fixture. No git, Node, Qoder or Harness process is launched here.
    metadata_workspace = output / "metadata_workspace"
    (metadata_workspace / ".git").mkdir(parents=True)
    commands = {"schema": "native-probe-manual-metadata-v1", "executed": False,
                "requires_separate_explicit_execution": True,
                "environment_overrides": deepcopy(qoder["subprocess_environment_overrides"]),
                "commands": {}}
    if trusted:
        argv = list(qoder["inference_argv_template"][:-2])
        argv.remove("--no-session-persistence")
        argv[argv.index("--cwd") + 1] = str(metadata_workspace)
        commands["commands"] = {"node_version": [trusted["node"], "--version"],
            "qoder_version": [trusted["node"], trusted["entry"], "--version"],
            "qoder_help": [trusted["node"], trusted["entry"], "--help"],
            "qoder_catalog": [*argv, "--list-models"]}
    _write_json(output / "manual_metadata_commands.json", commands)
    generated = [guard.name, "sdk_guard_metadata.patch.yml", "qoder_capabilities.example.json", "manual_metadata_commands.json"]
    manifest = {"schema": "prepared-native-probe-assets-v1", "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
                "files": {name: _sha(output / name) for name in generated},
                "qoder_qualification": "not_qualified_requires_independent_metadata_preflight",
                "qoder_package_manifest_checked": trusted is not None,
                "qoder_runtime_version_checked": False, "client_processes_started": 0,
                "model_inference_calls": 0, "credentials_read_or_copied": False, "network_calls": 0,
                "harness_installation_checked": False,
                "limitations": ["No qualified qoder_capabilities.json is produced.",
                    "Metadata and inference require separate explicit commands.",
                    "Frozen Harness adapter still has a machine-specific INSTALL constant; main runner has a machine-specific credentials_source.",
                    "Only the exact frozen probe root is supported; no previous evidence is overwritten."]}
    _write_json(output / "prepared_assets_manifest.json", manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--qoder-cli-entry", type=Path)
    parser.add_argument("--node-executable", type=Path)
    parser.add_argument("--qoder-package-json", type=Path)
    parser.add_argument("--expected-qoder-version", default=SUPPORTED_QODER_VERSION, choices=[SUPPORTED_QODER_VERSION])
    options = parser.parse_args(argv)
    try:
        result = prepare_assets(options.output, qoder_cli_entry=options.qoder_cli_entry,
            node_executable=options.node_executable, qoder_package_json=options.qoder_package_json,
            expected_qoder_version=options.expected_qoder_version)
    except (AssetPreparationError, OSError, ValueError, TypeError, KeyError):
        raise SystemExit("Asset preparation failed; check paths, fixed version, manifest hashes and fresh output. No client was run.") from None
    print(json.dumps({"status": "assets_prepared_not_qualified", "client_processes_started": 0,
                      "model_inference_calls": 0, "qoder_qualification": result["qoder_qualification"]}))


if __name__ == "__main__":
    main()
