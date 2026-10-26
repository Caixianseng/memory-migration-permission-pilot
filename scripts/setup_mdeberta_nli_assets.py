"""Fetch/check pinned public weights with stdlib HTTPS; never load a model.

No huggingface_hub token lookup, netrc, API key, package installation, Python
source download, classification, or implicit retry. Normal system HTTPS proxy
routing is retained. Public CDN redirect URLs are never recorded or printed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "configs/mdeberta_nli_assets_v1.json"
ASSETS = ROOT / ".runtime/mdeberta_nli"
MODEL_ID = "MoritzLaurer/mDeBERTa-v3-base-mnli-xnli"
REVISION = "8adb042d524ecd5c26d3e3ba0e3fbcf7e2d0864c"
NAMES = {"config.json", "tokenizer_config.json", "special_tokens_map.json", "added_tokens.json",
         "spm.model", "tokenizer.json", "model.safetensors", "README.md"}


def require(value, code):
    if not value: raise ValueError(code)


def scoped(path):
    absolute = Path(path).absolute()
    require(absolute.is_relative_to(ASSETS.absolute()) and absolute.resolve(strict=False) == absolute
            and not absolute.is_symlink(), "asset_scope_or_link_invalid")
    return absolute


def checked(path, expected):
    path = scoped(path)
    require(path.is_file() and path.stat().st_size == expected["size"], "asset_size_mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    require(digest.hexdigest() == expected["sha256"], "asset_sha256_mismatch")
    return {"name": expected["name"], "size": expected["size"], "sha256": digest.hexdigest()}


def load_manifest():
    raw = MANIFEST.read_bytes(); manifest = json.loads(raw)
    require(manifest["model_id"] == MODEL_ID and manifest["revision"] == REVISION, "fixed_model_revision_required")
    require(len(manifest["files"]) == len(NAMES) and {f["name"] for f in manifest["files"]} == NAMES,
            "exact_file_allowlist_required")
    require(sum(f["size"] for f in manifest["files"]) == manifest["total_bytes_including_model_card"], "asset_total_mismatch")
    for row in manifest["files"]:
        require(set(row) == {"name", "size", "sha256"} and type(row["size"]) is int and row["size"] > 0
                and len(row["sha256"]) == 64 and all(c in "0123456789abcdef" for c in row["sha256"]), "asset_entry_invalid")
    return manifest, hashlib.sha256(raw).hexdigest()


def fetch_one(path, entry):
    path = scoped(path); path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists(): return dict(checked(path, entry), existing_verified=True)
    partial = scoped(path.with_name(path.name + ".part"))
    require(not partial.exists(), "previous_partial_requires_explicit_diagnosis")
    url = "https://huggingface.co/" + MODEL_ID + "/resolve/" + REVISION + "/" + entry["name"]
    request = urllib.request.Request(url, headers={"User-Agent": "agent-memory-public-asset-check/1.0"})
    size, notice = 0, time.monotonic()
    with urllib.request.urlopen(request, timeout=60) as source, partial.open("xb") as output:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk: break
            size += len(chunk)
            require(size <= entry["size"], "download_exceeds_registered_bytes")
            output.write(chunk)
            if time.monotonic() - notice >= 20:
                print(json.dumps({"file": entry["name"], "bytes": size, "expected": entry["size"]}), flush=True)
                notice = time.monotonic()
    receipt = checked(partial, entry)
    require(not path.exists(), "asset_destination_appeared")
    os.replace(partial, path)
    print(json.dumps({"verified": entry["name"], "bytes": size}), flush=True)
    return dict(receipt, existing_verified=False, source=url)


def run(*, fetch=False):
    manifest, manifest_sha = load_manifest()
    folder = scoped(ASSETS / REVISION)
    if fetch:
        require(shutil.disk_usage(ROOT).free >= manifest["total_bytes_including_model_card"] * 2,
                "insufficient_free_disk_space")
    rows = []
    for entry in manifest["files"]:
        path = scoped(folder / entry["name"])
        rows.append(fetch_one(path, entry) if fetch else checked(path, entry))
    # This structural check does not instantiate a tokenizer or model.
    config = json.loads((folder / "config.json").read_bytes())
    require(config.get("label2id") == manifest["declared_label2id"] and config.get("max_position_embeddings") == 512,
            "nli_config_contract_mismatch")
    result = {"status": "assets_verified_runtime_unqualified", "model_id": MODEL_ID, "revision": REVISION,
        "manifest_sha256": manifest_sha, "files": rows, "model_loads": 0, "model_forwards": 0,
        "vendor_requests": 0, "cloud_model_calls": 0, "runtime_qualified": False, "method_acceptance": False,
        "source": "Anonymous public HTTPS with pinned byte hashes; no submitted research text."}
    if fetch:
        destination = scoped(folder / "asset_receipt.json")
        require(not destination.exists(), "asset_receipt_already_exists_use_verify_only")
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2); stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fetch", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        result = run(fetch=args.fetch)
    except Exception as error:
        print(json.dumps({"status": "asset_setup_failed", "error_type": type(error).__name__,
            "code": str(error) if isinstance(error, ValueError) else "public_asset_fetch_or_io_failed",
            "model_loads": 0, "model_forwards": 0}), flush=True)
        raise SystemExit(1) from None
    print(json.dumps({"status": result["status"], "files": len(result["files"]), "model_loads": 0, "model_forwards": 0}), flush=True)
