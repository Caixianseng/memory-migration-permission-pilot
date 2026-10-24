"""Download pinned public GLiNER2 code and safetensors to an ignored local runtime.

No project text is uploaded. Inference uses the downloaded files offline.
This script does not install or alter the existing Python environment.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

CODE_REVISION = "ca4f68235b50fe4c3ecf3876851d748fe4b15c6c"
MODEL_ID = "fastino/gliner2.5-multi-v1"
MODEL_REVISION = "cf5593a5d45e3bbf204b9df621b13b1c0cf25ee3"
FILES = ("config.json", "encoder_config/config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def setup(root, *, download=False):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    receipt_path = root / "receipt.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for relative, expected in receipt["files"].items():
            path = (root / relative).resolve()
            if not path.is_relative_to(root) or not path.is_file() or sha(path) != expected:
                raise ValueError("local_ner_asset_changed")
        print(json.dumps({"status": "verified_existing", "model_revision": receipt["model_revision"]}), flush=True)
        return
    if not download:
        raise ValueError("runtime_missing_use_explicit_download")
    code_url = f"https://codeload.github.com/fastino-ai/GLiNER2/zip/{CODE_REVISION}"
    with urllib.request.urlopen(code_url, timeout=60) as response:
        code = response.read(20 * 1024 * 1024)
    archive_hash = hashlib.sha256(code).hexdigest()
    archive = zipfile.ZipFile(io.BytesIO(code))
    prefix = f"GLiNER2-{CODE_REVISION}/"
    extracted = []
    for item in archive.infolist():
        if item.is_dir() or not item.filename.startswith(prefix):
            continue
        relative = item.filename[len(prefix):]
        if not (relative.startswith("gliner2/") or relative in {"LICENSE", "pyproject.toml"}):
            continue
        destination = (root / "vendor" / relative).resolve()
        if not destination.is_relative_to(root / "vendor") or (item.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("unsafe_archive_member")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(archive.read(item))
        extracted.append(destination)
    print(json.dumps({"stage": "code_ready", "files": len(extracted), "revision": CODE_REVISION}), flush=True)
    with urllib.request.urlopen(f"https://huggingface.co/api/models/{MODEL_ID}/revision/{MODEL_REVISION}?blobs=true", timeout=60) as response:
        metadata = json.load(response)
    expected_revision = metadata.get("sha")
    if expected_revision != MODEL_REVISION:
        raise ValueError("model_revision_mismatch")
    siblings = {f["rfilename"]: f for f in metadata["siblings"]}
    for relative in FILES:
        target = root / "model" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        expected_hash = siblings[relative].get("lfs", {}).get("sha256")
        if target.exists():
            # Completed downloads may survive interruption; still verify the
            # immutable revision's LFS/blob identity before accepting them.
            raw_hash = sha(target)
            if expected_hash and raw_hash == expected_hash:
                extracted.append(target)
                continue
        part = target.with_name(target.name + ".download")
        url = f"https://huggingface.co/{MODEL_ID}/resolve/{MODEL_REVISION}/{relative}"
        print(json.dumps({"stage": "download", "file": relative, "bytes": siblings[relative].get("size")}), flush=True)
        with urllib.request.urlopen(url, timeout=60) as response, part.open("wb") as out:
            for chunk in iter(lambda: response.read(4 * 1024 * 1024), b""):
                out.write(chunk)
        if expected_hash:
            if sha(part) != expected_hash:
                raise ValueError("model_weight_hash_mismatch")
        else:
            raw = part.read_bytes()
            git_hash = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if git_hash != siblings[relative]["blobId"]:
                raise ValueError("model_config_hash_mismatch")
        part.replace(target)
        extracted.append(target)
    receipt = {"code_repository": "https://github.com/fastino-ai/GLiNER2", "code_revision": CODE_REVISION,
               "archive_sha256": archive_hash, "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
               "model_license": metadata.get("cardData", {}).get("license"),
               "files": {p.relative_to(root).as_posix(): sha(p) for p in extracted},
               "runtime_requires": ["torch", "transformers", "safetensors", "pydantic", "requests", "numpy"],
               "inference_network": "offline_only", "project_data_uploaded": False}
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ready", "files": len(extracted), "model_bytes": (root / "model/model.safetensors").stat().st_size}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    setup(Path(__file__).resolve().parents[1] / ".runtime/github_ner", download=args.download)
