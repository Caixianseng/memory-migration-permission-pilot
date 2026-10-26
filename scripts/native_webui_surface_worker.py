"""One read-only route extension over the frozen native WebUI worker.

Only note_search_read adds permission=read to the official Note search URL.
The original seven bypass operations and all native auth/storage guards are
unchanged. No native import or request occurs at module import time.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE = ROOT / "scripts/native_webui_projection_worker.py"
BASE_SHA256 = "222718f0ac5f5d424ce5ff20793fe3a9fca4ea380218ed4d10096f39c5473ed7"
if hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA256:
    raise ValueError("frozen_webui_base_changed")
from scripts.native_webui_projection_worker import WebUIProjectionWorker, ProjectionError, require
from scripts.native_exact_fact_common import serve_commands

VERSION = "native_webui_surface_read_search_extension_v1"
COMMANDS = {"init", "summary", "close", "create_dataset", "add_exact_fact", "grant", "revoke", "read_raw", "bypass"}


class SurfaceWorker(WebUIProjectionWorker):
    def __init__(self, *, expected_worker_sha256, **kwargs):
        require(isinstance(expected_worker_sha256, str) and len(expected_worker_sha256) == 64
            and all(c in "0123456789abcdef" for c in expected_worker_sha256), "surface_worker_hash_required")
        self.expected_worker_sha256 = expected_worker_sha256
        super().__init__(**kwargs)

    def _bindings(self):
        require(hashlib.sha256(BASE.read_bytes()).hexdigest() == BASE_SHA256, "frozen_webui_base_changed")
        require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == self.expected_worker_sha256,
            "surface_worker_source_changed")
        return {"base_worker_sha256": BASE_SHA256, "surface_worker_sha256": self.expected_worker_sha256}

    def __call__(self, command, data):
        self._bindings()
        require(command in COMMANDS, "surface_command_not_allowed")
        if command == "bypass" and isinstance(data, dict) and data.get("operation") == "note_search_read":
            self._scope(data, ("dataset", "fact_key", "actor", "operation"))
            require(data["dataset"] in self.datasets and data["fact_key"] in self.facts
                and self.facts[data["fact_key"]]["dataset"] == data["dataset"], "unknown_controlled_fact")
            response, trace = self.recorder.request("GET", "/api/v1/notes/search", actor=data["actor"],
                params={"query": "controlled_", "page": 1, "permission": "read"})
            result = self._response(response, trace)
        else:
            result = super().__call__(command, data)
        self._bindings()
        if command == "init":
            result = dict(result, surface_worker_version=VERSION, source_bindings=self._bindings(),
                added_route="GET /api/v1/notes/search?permission=read", base_seven_bypass_operations_unchanged=True)
        return result

    def summary(self):
        return dict(super().summary(), surface_worker_version=VERSION, source_bindings=self._bindings(),
            added_route="GET /api/v1/notes/search?permission=read", base_seven_bypass_operations_unchanged=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--expected-worker-sha256", required=True)
    parser.add_argument("--http-cap", type=int, default=200)
    parser.add_argument("--openssl-dll-dir", type=Path)
    args = parser.parse_args()
    serve_commands(SurfaceWorker(state=args.state, expected_worker_sha256=args.expected_worker_sha256,
        http_cap=args.http_cap, openssl_dll_dir=args.openssl_dll_dir))
