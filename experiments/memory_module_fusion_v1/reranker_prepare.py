"""Prepare only public pinned TinyBERT assets in this experiment; no model API.

The independent CPU adapter follows FlashRank's public ONNX pairwise interface.
Upstream code: Apache-2.0, commit below. Packaged weights/model card: CC-BY-SA-4.0.
The public mirror is transport only; revision and the repository's LFS SHA256
are recorded and verified against the downloaded archive. Existing manifests
are immutable and all later loads verify the recorded file hashes.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
CODE_COMMIT = "11f7a40d625f2de047c371c81c6f477386c18bb1"
MODEL_REPOSITORY = "prithivida/flashrank"
MODEL_REVISION = "858a1ac046a05663a35367eac852d7f76feeefdd"
MODEL_NAME = "ms-marco-TinyBERT-L-2-v2"
ARCHIVE = MODEL_NAME + ".zip"
TRANSPORT = "https://hf-mirror.com"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as stream:
        return stream.read()


def prepare(root=None):
    root = Path(root or HERE / "reranker_assets").resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "manifest.json"
    if manifest.exists():
        record = json.loads(manifest.read_text(encoding="utf-8"))
        for relative, digest in record["file_sha256"].items():
            if sha(root / relative) != digest:
                raise ValueError("pinned_reranker_asset_integrity_failure")
        return record
    tree_url = f"{TRANSPORT}/api/models/{MODEL_REPOSITORY}/tree/{MODEL_REVISION}?recursive=true&expand=true"
    tree = json.loads(fetch(tree_url))
    entry = next(item for item in tree if item.get("path") == ARCHIVE)
    expected = entry.get("lfs", {}).get("oid") or entry.get("lfs", {}).get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("pinned_archive_lfs_sha256_required")
    archive_url = f"{TRANSPORT}/{MODEL_REPOSITORY}/resolve/{MODEL_REVISION}/{ARCHIVE}"
    archive_path = root / ARCHIVE
    if not archive_path.exists() or sha(archive_path) != expected:
        archive_path.write_bytes(fetch(archive_url))
    if sha(archive_path) != expected:
        raise ValueError("downloaded_archive_sha256_mismatch")
    extracted = []
    with zipfile.ZipFile(archive_path) as bundle:
        for member in bundle.infolist():
            relative = PurePosixPath(member.filename)
            target = (root / Path(*relative.parts)).resolve()
            if relative.is_absolute() or ".." in relative.parts or not target.is_relative_to(root):
                raise ValueError("unsafe_archive_member")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))
            extracted.append(target.relative_to(root).as_posix())
    # Text-file mirror routes can forbid downloads while the public repository
    # metadata endpoint works. Preserve its checked revision/license record;
    # do not claim an unavailable README was downloaded.
    repository_metadata = json.loads(fetch(f"{TRANSPORT}/api/models/{MODEL_REPOSITORY}"))
    if repository_metadata.get("sha") != MODEL_REVISION or repository_metadata.get("cardData", {}).get("license") != "cc-by-sa-4.0":
        raise ValueError("model_revision_or_license_metadata_changed")
    readme_path = root / "MODEL_LICENSE_PROVENANCE.json"
    readme_path.write_text(json.dumps({"revision": MODEL_REVISION,
        "license": repository_metadata["cardData"]["license"],
        "metadata_url": f"{TRANSPORT}/api/models/{MODEL_REPOSITORY}",
        "official_model_card": f"https://huggingface.co/{MODEL_REPOSITORY}/blob/{MODEL_REVISION}/README.md",
        "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
        "original_README_downloaded": False}, indent=2), encoding="utf-8")
    attribution = root / "ATTRIBUTION.txt"
    attribution.write_text(
        f"Packaged model: https://huggingface.co/{MODEL_REPOSITORY}\n"
        f"Revision: {MODEL_REVISION}\nLicense: CC-BY-SA-4.0\n"
        "Credit: Prithivi Da / prithivida, FlashRank model exporter and authors of the original TinyBERT model.\n"
        f"Interface reference: https://github.com/PrithivirajDamodaran/FlashRank/tree/{CODE_COMMIT}\n"
        "Upstream code license: Apache-2.0. This experiment's adapter is independently implemented.\n",
        encoding="utf-8")
    all_files = extracted + [ARCHIVE, readme_path.name, attribution.name]
    vendor = HERE / "reranker_vendor"
    dependencies = {dist.metadata["Name"]: dist.version
                    for dist in importlib.metadata.distributions(path=[str(vendor)])}
    record = {
        "schema": "pinned-local-tinybert-reranker-v1", "code_commit": CODE_COMMIT,
        "code_repository": "PrithivirajDamodaran/FlashRank", "code_license": "Apache-2.0",
        "model_repository": MODEL_REPOSITORY, "model_revision": MODEL_REVISION,
        "model_name": MODEL_NAME, "model_license": "CC-BY-SA-4.0",
        "transport_mirror": TRANSPORT, "upstream_archive_lfs_sha256": expected,
        "archive_sha256": sha(archive_path),
        "file_sha256": {relative: sha(root / relative) for relative in sorted(all_files)},
        "isolated_dependency_path": str(vendor), "dependencies": dependencies,
        "no_generation_model_api_calls": True,
    }
    with manifest.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, ensure_ascii=False, sort_keys=True)
    print(json.dumps({"status": "prepared", "model_revision": MODEL_REVISION,
                      "archive_sha256": record["archive_sha256"], "files": extracted,
                      "dependencies": dependencies}), flush=True)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    prepare(parser.parse_args().root)
