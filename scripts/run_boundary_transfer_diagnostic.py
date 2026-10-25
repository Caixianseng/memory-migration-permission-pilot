"""Observed local-only development run of the complete signed transfer pipeline.

Only the repository's synthetic development corpus is accepted. Raw HTTP
requests/responses are research evidence; no authority key or recovery map
enters this transport. This is not a production logging facility.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_migration_study.local_detector import LocalSensitivityAgent, MODEL
from memory_migration_study.reuse_benchmark import save

VERSION = "observed_boundary_transfer_development_v1"
MAX_GENERATIONS = 400


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


class ObservedTransport:
    """Count physical POST attempts before execution, retaining failed attempts."""
    def __init__(self, output, original, *, max_generations=MAX_GENERATIONS):
        if type(max_generations) is not int or not 1 <= max_generations <= MAX_GENERATIONS:
            raise ValueError("invalid_generation_cap")
        self.output, self.original = Path(output), original
        self.maximum, self.attempts, self.results, self.errors = max_generations, 0, 0, 0
        self.token_budget_violations = 0

    def append(self, record):
        with (self.output / "request_transport.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()

    def call(self, client, method, path, body=None):
        if method == "GET" and path in {"/api/version", "/api/tags"} and body is None:
            return self.original(client, method, path, body)
        if method != "POST" or path != "/api/chat" or not isinstance(body, dict):
            raise ValueError("unexpected_local_request")
        options = body.get("options", {})
        if (body.get("model") != MODEL or body.get("stream") is not False
                or options.get("num_ctx") != 4096 or options.get("num_predict") not in (64, 1024)
                or options.get("temperature") != 0 or options.get("seed") != 42):
            raise ValueError("unregistered_model_configuration")
        if self.attempts >= self.maximum:
            raise ValueError("registered_generation_cap_reached")
        self.attempts += 1
        index, started = self.attempts, time.monotonic()
        request_hash = digest(body)
        self.append({"phase": "request", "index": index, "request_sha256": request_hash,
                     "request": body, "scope": "synthetic_development_local_only"})
        try:
            response = self.original(client, method, path, body)
        except Exception:
            self.errors += 1
            self.append({"phase": "failure", "index": index, "request_sha256": request_hash,
                         "error": "physical_transport_failed", "elapsed_seconds": time.monotonic()-started})
            raise
        self.results += 1
        prompt = response.get("prompt_eval_count") if isinstance(response, dict) else None
        generated = response.get("eval_count") if isinstance(response, dict) else None
        within_budget = (type(prompt) is int and type(generated) is int and 0 < prompt <= 3072
                         and 0 < generated <= options["num_predict"]
                         and prompt + options["num_predict"] <= options["num_ctx"])
        self.append({"phase": "response", "index": index, "request_sha256": request_hash,
                     "response": response, "response_sha256": digest(response),
                     "actual_usage_within_budget": within_budget,
                     "elapsed_seconds": time.monotonic()-started})
        if not within_budget:
            self.token_budget_violations += 1
            raise ValueError("audited_token_budget_invalid")
        return response

    @contextmanager
    def installed(self):
        observer = self
        def observed(client, method, path, body=None):
            return observer.call(client, method, path, body)
        with patch.object(LocalSensitivityAgent, "_transport", observed):
            yield self

    def summary(self):
        return {"version": VERSION, "physical_generation_attempts": self.attempts,
                "responses": self.results, "transport_errors": self.errors,
                "actual_token_budget_violations": self.token_budget_violations,
                "registered_generation_cap": self.maximum, "cloud_calls": 0,
                "new_api_cost_cny": 0, "request_body_scope": "synthetic_development_only",
                "recovery_mapping_recorded": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "results") or output.exists():
        raise ValueError("new_project_results_directory_required")
    config_path = ROOT / "configs/local_privacy_detector.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    network = {"loopback_connections": 0, "external_attempts_blocked": 0}
    def audit(event, values):
        if event == "socket.connect":
            address = values[1]
            if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                network["external_attempts_blocked"] += 1
                raise RuntimeError("external_network_disabled")
            network["loopback_connections"] += 1
    sys.addaudithook(audit)
    from memory_migration_study.semantic_memory_benchmark import run
    observer = ObservedTransport(output, LocalSensitivityAgent._transport)
    launcher_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    started = time.monotonic()
    completed = False
    try:
        with observer.installed():
            report = run(ROOT / "examples/privacy_semantics_v1", output,
                ROOT / ".runtime/github_ner", config, split="development", detector_kind="gliner",
                paired_boundary=True, progress=lambda row: print(json.dumps(row), flush=True))
        completed = True
        print(json.dumps({"output": str(output), "arms": report["arms"]}, ensure_ascii=False))
    finally:
        if output.exists():
            (output / "launcher.py").write_bytes(Path(__file__).read_bytes())
            summary = dict(observer.summary(), network=network, completed=completed,
                elapsed_seconds=time.monotonic()-started, launcher_sha256=launcher_hash,
                python_executable=sys.executable, python_version=sys.version,
                launcher_unchanged=hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == launcher_hash,
                config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest())
            save(output / "transport_audit.json", summary)
            save(output / "network_audit.json", network)
            print(json.dumps({"transport_audit": summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
