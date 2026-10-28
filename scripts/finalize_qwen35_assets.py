"""Verify pinned blobs and Ollama's local upstream-manifest wrapper, no generation."""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
MODEL = "qwen3.5:4b-q4_K_M"
DIGEST = "d8b0f5e9760cd1682034f292d7ef72ec46f432149be0df7574bf2d6e92e38c04"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def request(method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", 11435, timeout=30)
    try:
        c.request(method, path, json.dumps(body).encode() if body is not None else None,
                  {"Content-Type": "application/json"})
        r = c.getresponse()
        raw = r.read(1048577)
        assert r.status == 200 and len(raw) <= 1048576, "metadata_http_failure"
        return json.loads(raw)
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-root", type=Path, required=True)
    p.add_argument("--model-root", type=Path, required=True)
    p.add_argument("--pid", type=int, required=True)
    a = p.parse_args()
    out, models = a.run_root.resolve(), a.model_root.resolve()
    assert out.is_relative_to(ROOT / "results") and models.is_relative_to(ROOT / ".runtime"), "path_scope"
    assert not (out / "asset_receipt.json").exists(), "receipt_already_exists"
    upstream_path = models / ("blobs/sha256-" + DIGEST)
    assert sha(upstream_path) == DIGEST, "upstream_manifest_hash_mismatch"
    upstream = json.loads(upstream_path.read_bytes())
    manifest_path = models / "manifests/registry.ollama.ai/library/qwen3.5/4b-q4_K_M"
    local = json.loads(manifest_path.read_bytes())
    wrapped = dict(upstream, layers=[*upstream["layers"], {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "digest": "sha256:" + DIGEST, "size": upstream_path.stat().st_size}])
    assert local == upstream or local == wrapped, "unexpected_local_manifest_semantics"
    blobs = []
    for layer in [local["config"], *local["layers"]]:
        d = layer["digest"]
        assert d.startswith("sha256:") and len(d) == 71 and all(x in "0123456789abcdef" for x in d[7:]), "invalid_digest"
        file = models / ("blobs/sha256-" + d[7:])
        assert type(layer["size"]) is int and file.stat().st_size == layer["size"] and sha(file) == d[7:], "blob_integrity_mismatch"
        blobs.append({"digest": d, "bytes": layer["size"], "media_type": layer["mediaType"]})
    old = json.loads((ROOT / ".runtime/privacy_agent/runtime_receipt.json").read_text(encoding="utf-8-sig"))
    executable = ROOT / ".runtime/privacy_agent/ollama/ollama.exe"
    assert sha(executable) == old["executable_sha256"], "executable_changed"
    version, tags = request("GET", "/api/version"), request("GET", "/api/tags")
    entries = [m for m in tags["models"] if m["name"] == MODEL]
    assert version["version"] == "0.40.8" and len(entries) == 1 and entries[0]["digest"] == DIGEST, "runtime_identity_mismatch"
    show = request("POST", "/api/show", {"model": MODEL, "verbose": False})
    save(out / "show.json", show)
    result = {"status": "assets_verified", "model": MODEL, "model_digest": DIGEST,
        "version": "0.40.8", "endpoint": "http://127.0.0.1:11435", "pid": a.pid,
        "executable": str(executable), "executable_sha256": old["executable_sha256"],
        "model_root": str(models), "manifest_path": str(manifest_path),
        "local_manifest_sha256": sha(manifest_path), "registry_manifest_sha256": DIGEST,
        "manifest_relationship": "exact_upstream" if local == upstream else "exact_upstream_plus_authenticated_upstream_blob",
        "blobs": blobs, "capabilities": show.get("capabilities"),
        "generation_calls": 0, "cloud_generation_calls": 0, "inference_qualified": False,
        "verified_utc": datetime.now(timezone.utc).isoformat(), "verifier_sha256": sha(Path(__file__)),
        "previous_failure_preserved": (out / "failure.json").exists()}
    save(out / "asset_receipt.json", result)
    print(json.dumps({k: result[k] for k in ("status", "model_digest", "local_manifest_sha256", "manifest_relationship", "generation_calls")}))


if __name__ == "__main__":
    main()
