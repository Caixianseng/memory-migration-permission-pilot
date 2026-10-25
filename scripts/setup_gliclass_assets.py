"""Fetch pinned public GLiClass assets; never installs packages or classifies.

All downloaded content stays below .runtime/gliclass. Downloads use anonymous
HTTPS via the stdlib, not huggingface_hub token discovery. --load-check is an
explicit offline CPU loading/tokenizer check with network and forward guards.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import socket
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / ".runtime/gliclass"
MODEL_ID = "knowledgator/gliclass-multilang-mini"
MODEL_REVISION = "0bd888b6c3ef9fca5f0a9d407bddfbbc7623486b"
CODE_REPO = "Knowledgator/GLiClass"
CODE_REVISION = "6a00f8067648f25aa0f4f477d167c5f391cb4165"
MODEL_FILES = frozenset({"config.json", "model.safetensors", "added_tokens.json", "special_tokens_map.json",
                         "spm.model", "tokenizer.json", "tokenizer_config.json"})
WEIGHT_SIZE = 567503348
WEIGHT_SHA256 = "440d8f17603d3e6f7d13a4fe7ffa7e9ef2c5a2581cceccb2f643334b92c8aea8"
MODEL_DIR = ASSETS / "model" / MODEL_REVISION
VENDOR_DIR = ASSETS / "vendor" / CODE_REVISION
SCHEMA = "pinned-gliclass-assets-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data, algorithm="sha256"):
    return hashlib.new(algorithm, data).hexdigest()


def json_safe(value):
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [json_safe(item) for item in sorted(value, key=str)]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("unexpected_loading_metadata_type")


def scope(path):
    path = Path(path).absolute()
    require(path.is_relative_to(ASSETS.absolute()) and path.resolve(strict=False) == path
            and not path.is_symlink(), "asset_path_outside_root_or_linked")
    return path


def write_json(path, value):
    path = scope(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = scope(path.with_name(path.name + ".tmp"))
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def response(url):
    require(url.startswith(("https://huggingface.co/", "https://raw.githubusercontent.com/", "https://api.github.com/")),
            "nonofficial_download_source")
    # No token files, authentication environment variables or Authorization
    # headers are read or set. Public CDN redirects may carry server signatures.
    request = urllib.request.Request(url, headers={"User-Agent": "agent-memory-research-asset-audit/1.0"})
    return urllib.request.urlopen(request, timeout=60)


def small_json(url):
    with response(url) as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024, "metadata_too_large")
    return json.loads(raw), digest(raw)


def verify_file(path, expected):
    path = scope(path)
    require(path.is_file() and path.stat().st_size == expected["size"], "asset_size_mismatch")
    sha256, blob = hashlib.sha256(), hashlib.sha1()
    blob.update(("blob " + str(expected["size"]) + "\0").encode())
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha256.update(block); blob.update(block)
    if expected.get("sha256"):
        require(sha256.hexdigest() == expected["sha256"], "asset_sha256_mismatch")
    if expected.get("git_blob_sha1"):
        require(blob.hexdigest() == expected["git_blob_sha1"], "asset_git_blob_mismatch")
    return {"path": str(path.relative_to(ASSETS)), "size": expected["size"], "sha256": sha256.hexdigest(),
            "git_blob_sha1": blob.hexdigest()}


def download(path, url, expected):
    path = scope(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return {**verify_file(path, expected), "source": url, "existing_verified": True}
    part = scope(path.with_name(path.name + ".part"))
    copied, last_notice = 0, time.monotonic()
    with response(url) as stream, part.open("wb") as output:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            copied += len(block)
            require(copied <= expected["size"], "download_exceeds_registered_size")
            output.write(block)
            if time.monotonic() - last_notice > 20:
                print(json.dumps({"file": path.name, "bytes": copied, "expected": expected["size"]}), flush=True)
                last_notice = time.monotonic()
    checked = verify_file(part, expected)
    os.replace(part, path)
    checked["path"] = str(path.relative_to(ASSETS))
    print(json.dumps({"verified": path.name, "bytes": copied}), flush=True)
    return {**checked, "source": url, "existing_verified": False}


def code_materials():
    url = "https://api.github.com/repos/" + CODE_REPO + "/git/trees/" + CODE_REVISION + "?recursive=1"
    tree, tree_hash = small_json(url)
    require(not tree.get("truncated"), "code_tree_truncated")
    entries = {row["path"]: row for row in tree["tree"] if row.get("type") == "blob"}
    cache, excluded = {}, []
    def fetch(name):
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and name in entries
                and (name.startswith("gliclass/") and name.endswith(".py") or name == "LICENSE"), "unexpected_code_path")
        if name not in cache:
            endpoint = "https://raw.githubusercontent.com/" + CODE_REPO + "/" + CODE_REVISION + "/" + name
            with response(endpoint) as stream:
                raw = stream.read(512 * 1024 + 1)
            row = entries[name]
            require(len(raw) == row["size"] and len(raw) <= 512 * 1024, "code_size_mismatch")
            require(digest(("blob " + str(len(raw)) + "\0").encode() + raw, "sha1") == row["sha"], "code_blob_mismatch")
            cache[name] = (raw, endpoint, row)
        return cache[name][0]
    pending, chosen = ["gliclass/__init__.py"], set()
    while pending:
        name = pending.pop()
        if name in chosen:
            continue
        chosen.add(name)
        parsed = ast.parse(fetch(name), filename=name)
        parent = {child: node for node in ast.walk(parsed) for child in ast.iter_child_nodes(node)}
        package = name[:-12].replace("/", ".") if name.endswith("/__init__.py") else name.rsplit("/", 1)[0].replace("/", ".")
        for node in ast.walk(parsed):
            if not isinstance(node, ast.ImportFrom) or not node.level:
                continue
            absolute = importlib.util.resolve_name("." * node.level + (node.module or ""), package)
            candidates = [absolute] if node.module else [absolute + "." + alias.name for alias in node.names]
            for candidate in candidates:
                code = candidate.replace(".", "/")
                found = code + ".py" if code + ".py" in entries else code + "/__init__.py"
                if candidate == "gliclass.serve":
                    cursor, optional = node, False
                    while cursor in parent:
                        cursor = parent[cursor]
                        if isinstance(cursor, ast.Try) and any(isinstance(handler.type, ast.Name) and handler.type.id == "ImportError" for handler in cursor.handlers):
                            optional = True
                    require(optional, "serve_import_not_optional")
                    excluded.append({"path": found, "reason": "optional_ImportError_guarded_serve_not_needed"})
                    continue
                require(found in entries and found.startswith("gliclass/"), "unresolved_vendor_import")
                pending.append(found)
    chosen.add("LICENSE")
    for name in chosen:
        fetch(name)
    return {name: cache[name] for name in sorted(chosen)}, tree_hash, excluded


def static_audit(materials, config):
    imports, flagged_calls = {}, []
    for name, (raw, _, _) in materials.items():
        if not name.endswith(".py"):
            continue
        parsed = ast.parse(raw, filename=name)
        imports[name] = []
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                imports[name].extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports[name].append("." * node.level + (node.module or ""))
            elif isinstance(node, ast.Call):
                label = ast.unparse(node.func)
                if label.split(".")[-1] in {"from_pretrained", "load", "load_state_dict", "__import__", "eval", "exec", "get", "post", "request", "urlopen", "Popen", "run", "system"}:
                    flagged_calls.append({"path": name, "line": node.lineno, "call": label})
    require(not config.get("auto_map") and not config.get("custom_pipelines"), "model_requests_remote_code")
    require(config.get("architectures") == ["GLiClassModel"] and config.get("architecture_type") == "uni-encoder"
            and config.get("encoder_model_name") == "microsoft/mdeberta-v3-base"
            and isinstance(config.get("encoder_config"), dict)
            and config["encoder_config"].get("model_type") == "deberta-v2", "model_configuration_changed")
    return {"imports": imports, "flagged_call_sites_for_review": flagged_calls, "python_sources_parsed": len(imports),
            "model_auto_map_present": False, "trust_remote_code_required": False,
            "loading_policy": "local_files_only=True,token=False,use_safetensors=True,trust_remote_code=False",
            "selected_encoder_native_config": "deberta-v2; no AutoConfig remote fallback is needed",
            "constructor_pretrained_encoder_download": False,
            "scope": "static inventory, not a proof that arbitrary source execution is safe"}


def prepare():
    scope(ASSETS).mkdir(parents=True, exist_ok=True)
    endpoint = "https://huggingface.co/api/models/" + MODEL_ID + "/revision/" + MODEL_REVISION + "?blobs=true"
    metadata, metadata_sha = small_json(endpoint)
    require(metadata.get("sha") == MODEL_REVISION and metadata.get("cardData", {}).get("license") == "apache-2.0", "model_revision_or_license_mismatch")
    files = {row["rfilename"]: row for row in metadata["siblings"]}
    require(MODEL_FILES <= set(files), "required_inference_files_missing")
    registrations = []
    for name in sorted(MODEL_FILES):
        row = files[name]
        expected = {"size": row["size"]}
        if row.get("lfs"):
            expected["sha256"] = row["lfs"]["sha256"]
        else:
            expected["git_blob_sha1"] = row["blobId"]
        if name == "model.safetensors":
            require(expected["size"] == WEIGHT_SIZE and expected.get("sha256") == WEIGHT_SHA256, "registered_weights_mismatch")
        registrations.append({"kind": "model", "relative": "model/" + MODEL_REVISION + "/" + name,
            "source": "https://huggingface.co/" + MODEL_ID + "/resolve/" + MODEL_REVISION + "/" + name, "expected": expected})
    materials, tree_sha, exclusions = code_materials()
    for name, (raw, url, row) in materials.items():
        registrations.append({"kind": "source", "relative": "vendor/" + CODE_REVISION + "/" + name,
            "source": url, "expected": {"size": len(raw), "sha256": digest(raw), "git_blob_sha1": row["sha"]}})
    plan = {"schema": SCHEMA, "model_id": MODEL_ID, "model_revision": MODEL_REVISION, "code_repo": CODE_REPO,
        "code_revision": CODE_REVISION, "model_license": "apache-2.0", "code_license": "Apache-2.0",
        "model_metadata_sha256": metadata_sha, "code_tree_metadata_sha256": tree_sha, "files": registrations,
        "excluded_optional_imports": exclusions, "download_bytes": sum(row["expected"]["size"] for row in registrations),
        "credential_files_read": False, "hf_token_used": False, "package_installs": 0, "model_forwards": 0,
        "setup_implementation_sha256": digest(Path(__file__).read_bytes())}
    require(plan["download_bytes"] < 600_000_000, "download_exceeds_approved_bound")
    write_json(ASSETS / "download_plan.json", plan)
    receipts = []
    # Source first, so static inspection is available before loading any model.
    for row in sorted(registrations, key=lambda value: value["kind"] == "model"):
        receipts.append({"kind": row["kind"], **download(ASSETS / row["relative"], row["source"], row["expected"])})
    config = json.loads((MODEL_DIR / "config.json").read_text(encoding="utf-8"))
    audit = static_audit(materials, config)
    receipt = {**plan, "status": "assets_verified", "verified_files": receipts, "static_audit": audit,
               "model_dir": str(MODEL_DIR), "vendor_dir": str(VENDOR_DIR), "model_loaded": False,
               "limitations": ["No encoder forward, classification, task accuracy, GPU memory or speed was measured.",
                    "A static import/call-site inventory is not a general source-security proof."]}
    write_json(ASSETS / "asset_receipt.json", receipt)
    return receipt


def load_check():
    plan = json.loads(scope(ASSETS / "download_plan.json").read_text(encoding="utf-8"))
    for row in plan["files"]:
        verify_file(ASSETS / row["relative"], row["expected"])
    os.environ.update(HF_HOME=str(scope(ASSETS / "hf_home")), HF_HUB_CACHE=str(scope(ASSETS / "hf_home/hub")),
        HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_IMPLICIT_TOKEN="1", HF_TOKEN="",
        HF_HUB_DISABLE_TELEMETRY="1", TOKENIZERS_PARALLELISM="false", PYTHONDONTWRITEBYTECODE="1")
    socket_calls, forward_calls = [], []
    def blocked_network(*args, **kwargs):
        socket_calls.append("blocked")
        raise RuntimeError("offline_load_network_forbidden")
    socket.socket.connect = blocked_network
    socket.create_connection = blocked_network
    def audit(event, args):
        if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            name = Path(os.fsdecode(args[0])).name.lower()
            if name in {"token", "stored_tokens", ".netrc", ".git-credentials", ".credentials.yaml"}:
                raise RuntimeError("credential_file_access_forbidden")
    sys.addaudithook(audit)
    sys.path.insert(0, str(VENDOR_DIR))
    result = {"schema": "gliclass-offline-load-check-v1", "status": "error", "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION, "code_revision": CODE_REVISION, "device": "cpu", "dtype": "float32",
        "package_installs": 0, "model_forwards": 0, "network_connection_attempts": 0, "credential_files_read": False,
        "setup_implementation_sha256": digest(Path(__file__).read_bytes())}
    try:
        import importlib.metadata
        import torch
        from transformers import AutoTokenizer
        from gliclass import GLiClassModel
        def blocked_forward(*args, **kwargs):
            forward_calls.append("blocked")
            raise RuntimeError("encoder_forward_forbidden_during_asset_preparation")
        torch.nn.Module._call_impl = blocked_forward
        GLiClassModel.forward = blocked_forward
        model, loading_info = GLiClassModel.from_pretrained(str(MODEL_DIR), local_files_only=True, token=False,
            trust_remote_code=False, use_safetensors=True, dtype=torch.float32, from_pretrained=False,
            output_loading_info=True)
        model.eval()
        tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR), local_files_only=True, token=False, trust_remote_code=False, use_fast=True)
        english = tokenizer("A short public tokenizer preflight.", truncation=False, add_special_tokens=True)
        chinese = tokenizer("本地分词器预检，不进行模型前向。", truncation=False, add_special_tokens=True)
        result.update(status="loaded_without_forward", model_class=type(model).__name__, tokenizer_class=type(tokenizer).__name__,
            parameters=sum(parameter.numel() for parameter in model.parameters()),
            loading_info=json_safe({key: value for key, value in loading_info.items() if key in
                          {"missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs"}}),
            max_position_embeddings=model.config.encoder_config.max_position_embeddings,
            english_tokens=len(english["input_ids"]), chinese_tokens=len(chinese["input_ids"]),
            versions={name: importlib.metadata.version(name) for name in ("torch", "transformers", "numpy", "scikit-learn", "scipy")},
            model_forwards=len(forward_calls), network_connection_attempts=len(socket_calls))
        require(not forward_calls and not socket_calls, "unexpected_load_activity")
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error)[:300], model_forwards=len(forward_calls),
                      network_connection_attempts=len(socket_calls))
    write_json(ASSETS / "load_check.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--load-check", action="store_true")
    args = parser.parse_args()
    require(args.download or args.load_check, "explicit_download_or_load_check_required")
    if args.download:
        receipt = prepare()
        print(json.dumps({"status": receipt["status"], "files": len(receipt["verified_files"]), "bytes": receipt["download_bytes"]}), flush=True)
    if args.load_check:
        result = load_check()
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0 if result["status"] == "loaded_without_forward" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
