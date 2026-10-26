"""Synthetic protocol fixtures only; no vendor or model is started."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_webui_projection_surface_probe as probe
from scripts import native_webui_surface_worker as extension
from tests.test_native_webui_projection_worker import worker as fixture_worker, Response


class FakeRPC:
    def __init__(self, python, script, args, *, timeout=240, disclosure=False, null_named=False):
        self.state = args[args.index("--state") + 1]
        self.gateway = "gateway" in self.state
        self.disclosure, self.null_named = disclosure, null_named
        self.calls, self.requests, self.datasets, self.facts, self.acl = [], [], {}, {}, set()
        self.identities = {actor: {"id": self.state + ":" + actor, "role": "user", "credential_kind": "bearer"} for actor in probe.ACTORS}

    def trace(self, value, actor="owner", status=200):
        raw = value if isinstance(value, str) else json.dumps(value)
        trace = {"index": len(self.requests), "status": status, "actor": actor, "native_raw_body": raw,
            "native_body_sha256": probe.digest(raw.encode()), "response_checked": True, "execution_error": None,
            "authorization_present": actor is not None, "api_key_present": False, "cookie_present": False}
        self.requests.append(trace)
        return {"status": status, "trace": deepcopy(trace)}

    def summary(self):
        return {"identities": deepcopy(self.identities), "datasets": deepcopy(self.datasets), "facts": deepcopy(self.facts),
            "native_requests": deepcopy(self.requests), "generation_attempts": 0, "embedding_attempts": 0,
            "inference_events": [], "network_events": [], "client_credential_values_persisted": False}

    def allowed(self, actor, ds): return actor == "owner" or (actor, ds) in self.acl
    def file_row(self, ds):
        return {"id": self.facts[ds]["id"], "user_id": self.identities["owner"]["id"],
            "filename": "controlled_" + ds + ".txt", "data": {}}

    def call(self, command, data):
        if command == "init":
            for _ in range(18): self.trace({"credential_response": "omitted"}, actor=None)
            result = {"identities": deepcopy(self.identities)}
        elif command in {"summary", "close"}: result = self.summary()
        elif command == "create_dataset":
            ds = data["dataset"]; self.datasets[ds] = {"id": self.state + ":note:" + ds, "owner": "owner"}
            result = self.trace(self.datasets[ds])
        elif command == "add_exact_fact":
            ds = data["dataset"]
            self.facts[ds] = {"id": self.state + ":file:" + ds, "text": data["text"], "dataset": ds}
            self.trace({"id": self.facts[ds]["id"]}); self.trace({"files": [self.facts[ds]["id"]]})
            result = self.trace(data["text"])
        elif command in {"grant", "revoke"}:
            pair = (data["recipient"], data["dataset"])
            if command == "grant": self.acl.add(pair)
            else: self.acl.discard(pair)
            result = self.trace({"access_grants": [list(v) for v in sorted(self.acl)]})
        elif command == "read_raw":
            result = self.trace(self.facts[data["dataset"]]["text"], data["actor"]) if self.allowed(data["actor"], data["dataset"]) else self.trace({"detail": "Not found"}, data["actor"], 404)
        elif command == "bypass":
            actor, ds, op = data["actor"], data["dataset"], data["operation"]
            allowed = self.allowed(actor, ds)
            if self.disclosure and self.gateway and actor != "owner":
                result = self.trace({"detail": self.facts["managed"]["text"]}, actor, 404)
            elif op == "file_content_html": result = self.trace({"detail": "Not found"}, actor, 404)
            elif op == "file_metadata": result = self.trace(self.file_row(ds), actor) if allowed else self.trace({"detail": "Not found"}, actor, 404)
            elif op == "file_data_content": result = self.trace({"content": ""}, actor) if allowed else self.trace({"detail": "Not found"}, actor, 404)
            elif op == "file_content_named":
                result = self.trace("null" if self.null_named and actor == "owner" else self.facts[ds]["text"], actor) if allowed else self.trace({"detail": "Not found"}, actor, 404)
            elif op == "file_list":
                items = [self.file_row(k) for k in self.facts] if actor == "owner" else []
                result = self.trace({"items": items, "total": len(items)}, actor)
            elif op == "file_search":
                result = self.trace([self.file_row(k) for k in self.facts], actor) if actor == "owner" else self.trace({"detail": "No matching owned files"}, actor, 404)
            elif op in {"note_search", "note_search_read"}:
                visible = [k for k in self.datasets if actor == "owner" or op == "note_search_read" and self.allowed(actor, k)]
                items = [{"id": self.datasets[k]["id"], "data": {"content": {"md": ""}}} for k in visible]
                result = self.trace({"items": items, "total": len(items)}, actor)
            else: raise AssertionError("unknown fake operation")
        else: raise AssertionError("unknown fake command")
        self.calls.append({"command": command, "input": deepcopy(data), "result": deepcopy(result)})
        return result

    def terminate(self): pass


class SurfaceProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def plan(self):
        worker = str((probe.ROOT / "scripts/native_webui_surface_worker.py").resolve())
        return {"python": "explicit-fake", "worker": worker, "code_sha256": {worker: probe.file_sha(worker)},
            "native_states": {a: "fake-" + a for a in probe.ARMS}, "manifest_per_arm": probe.protocol_manifest()}

    def execute_fake(self, **flags):
        return probe.execute(self.plan(), self.directory, validate_inputs=lambda _: None,
            rpc_factory=lambda *a, **kw: FakeRPC(*a, **kw, **flags))

    def test_complete_fake_protocol_exact_budget_and_g_never_granted(self):
        result = self.execute_fake()
        self.assertEqual(result["status"], "fake_transport_protocol_completed", result["failure"])
        self.assertFalse(result["native_qualification_established"])
        self.assertEqual(result["observation_count"], 290)
        self.assertEqual(result["raw_barrier_relations"], 32)
        self.assertEqual(result["http_instrumentation"]["native_projection"]["http_records"], 192)
        self.assertEqual(result["http_instrumentation"]["gateway_storage"]["http_records"], 187)
        rpc = json.loads((self.directory / "rpc_receipts.json").read_bytes())
        self.assertFalse(any(c["command"] in {"grant", "revoke"} for c in rpc["gateway_storage"]))
        self.assertFalse(result["all_seven_original_surfaces_privacy_proven"])
        self.assertGreater(result["unqualified_or_unsupported_safety_rows"], 0)

    def test_disclosure_stops_and_original_404_body_is_retained(self):
        result = self.execute_fake(disclosure=True)
        self.assertEqual(result["failure"]["code"], "registered_material_disclosure")
        self.assertEqual(result["qualified_safety_false"], 1)
        rows = json.loads((self.directory / "observations.json").read_bytes())
        self.assertIn("SYNTHETIC_VALUE_B92", rows[-1]["native_result"]["trace"]["native_raw_body"])
        self.assertLess(len(rows), 290)
        self.assertTrue((self.directory / "report.json").is_file())

    def test_owner_null_is_qualification_gap_not_good_denial(self):
        result = self.execute_fake(null_named=True)
        self.assertEqual(result["status"], "incomplete_or_unqualified")
        self.assertGreater(result["unexpected_qualification_gaps"], 0)
        rows = json.loads((self.directory / "observations.json").read_bytes())
        nulls = [r for r in rows if r["operation"] == "file_content_named"]
        self.assertTrue(all(r["assessment"]["safety_verdict"] is None for r in nulls))

    def test_global_calls_not_duplicated_per_fact_and_read_search_replaces_write(self):
        manifest = probe.protocol_manifest()
        self.assertEqual(len(manifest), 145)
        for phase in probe.PHASES:
            actors = probe.ACTORS if phase == probe.PHASES[0] else probe.ACTORS[1:]
            for actor in actors:
                rows = [r for r in manifest if r["phase"] == phase and r["actor"] == actor]
                for op in ("file_list", "file_search"):
                    self.assertEqual(sum(r["operation"] == op for r in rows), 1)
                for op in probe.PER_FILE: self.assertEqual(sum(r["operation"] == op for r in rows), 2)
        self.assertEqual(sum(r["operation"] == "note_search" for r in manifest), 6)
        self.assertEqual(sum(r["operation"] == "note_search_read" for r in manifest), 9)

    def test_registered_full_source_chain_matches_declared_native_barriers(self):
        contract = probe.read_json(probe.SOURCE)
        for phase, state in probe.source_states(contract).items():
            self.assertEqual(probe.source_read_relations(contract, state), probe.policy_relations("native_projection", phase))
        revoked = probe.source_states(contract)["alice_read_revoked"]
        self.assertEqual(set(revoked["revoked_grants"]), {"grant.readonly", "grant.root"})
        self.assertNotIn("grant.independent", revoked["revoked_grants"])

    def test_legitimate_shared_read_need_not_appear_in_owned_file_list_or_default_write_search(self):
        self.execute_fake()
        rows = json.loads((self.directory / "observations.json").read_bytes())
        paired = [r for r in rows if r["arm"] == "native_projection" and r["phase"] == "current_read_grants"
            and r["actor"] == "alice_reader" and r["operation"] in {"file_list", "note_search", "note_search_read"}]
        self.assertTrue(all(r["assessment"]["view_matches"] for r in paired))
        default = next(r for r in paired if r["operation"] == "note_search")
        read = next(r for r in paired if r["operation"] == "note_search_read")
        self.assertEqual(default["native_result"]["trace"]["native_raw_body"], '{"items": [], "total": 0}')
        self.assertEqual(len(json.loads(read["native_result"]["trace"]["native_raw_body"])["items"]), 2)

    def test_after_revoking_alice_bob_independent_exact_read_retained(self):
        self.execute_fake()
        barriers = json.loads((self.directory / "barriers.json").read_bytes())
        checks = [r for r in barriers if r["arm"] == "native_projection" and r["phase"] == "alice_read_revoked"]
        self.assertEqual(sum(r["expected_available"] for r in checks), 1)
        bob = next(r for r in checks if r["actor"] == "bob_reader" and r["object_id"] == "fact.managed")
        self.assertEqual(bob["native_result"]["trace"]["native_raw_body"], "SYNTHETIC_VALUE_B92")

    def extension_fixture(self, responses):
        base, client = fixture_worker(self.directory, responses)
        w = extension.SurfaceWorker(state=Path(tempfile.gettempdir()) / ("webui_surface_fake_" + self.directory.name),
            expected_worker_sha256=probe.file_sha(extension.__file__))
        w.__dict__.update(base.__dict__)
        return w, client

    def test_extension_adds_only_official_read_parameter_and_keeps_base_operation(self):
        w, client = self.extension_fixture([Response({"items": [], "total": 0}), Response({"items": [], "total": 0})])
        args = {"dataset": "readonly", "fact_key": "readonly", "actor": "alice_reader"}
        w("bypass", dict(args, operation="note_search_read"))
        w("bypass", dict(args, operation="note_search"))
        self.assertEqual(client.calls[0][1], "/api/v1/notes/search")
        self.assertEqual(client.calls[0][2]["params"], {"query": "controlled_", "page": 1, "permission": "read"})
        self.assertEqual(client.calls[1][2]["params"], {"query": "controlled_", "page": 1})
        self.assertNotIn("fixture-token", json.dumps(w.summary()))

    def test_extension_hash_and_extra_scope_fail_before_http(self):
        w, client = self.extension_fixture([])
        with self.assertRaises(ValueError): w("bypass", {"dataset": "readonly", "fact_key": "readonly",
            "actor": "alice_reader", "operation": "note_search_read", "permission": "admin"})
        w.expected_worker_sha256 = "0" * 64
        with self.assertRaisesRegex(ValueError, "surface_worker_source_changed"): w("summary", {})
        self.assertEqual(client.calls, [])


if __name__ == "__main__": unittest.main()
