"""Independent audit negatives over explicit fake-worker traces, never native runs."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_native_exact_fact_bridge as producer
from scripts import verify_native_exact_fact_bridge as audit
from tests.test_native_exact_fact_bridge import FakeSource, FakeTarget


class Clock:
    value = 100
    def tick(self):
        self.value += 1
        return self.value


class TraceWorker:
    """Adapter emits synthetic raw bytes and RPC observations; no HTTP or SDK."""
    def __init__(self, worker, side, root, clock):
        self.worker, self.side, self.root, self.clock = worker, side, root, clock
        self.calls, self.requests, self.http = [], [], []

    def raw(self, method, path, actor, value, *, status=200, payload=None, auth=False):
        index = len(self.http)
        t = {"native_request_index": index, "native_method": method, "native_path": path,
            "actor_id": actor, "authorization_present": actor is not None, "cookie_present": False,
            "status": status, "response_checked": True, "execution_error": None}
        if payload is not None:
            t["native_request_json"] = deepcopy(payload)
        if auth:
            t["auth_response_omitted"] = True
        else:
            raw = json.dumps(value, ensure_ascii=False).encode()
            file = self.root/"target_state/responses"/f"{index:05d}.bin"
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
            t.update(native_raw_body=raw.decode(), native_body_sha256=hashlib.sha256(raw).hexdigest(),
                native_response_file=str(file.resolve()), byte_count=len(raw))
        self.http.append(t)
        return t

    def summary(self):
        network = [{"event": "socket.bind", "allowed": True, "address": ["127.0.0.1", 0], "kind": "declared_loopback_or_probe"}]
        base = {"generation_attempts": 0, "credential_values_persisted": False, "network_events": network}
        if self.side == "source":
            network.extend({"event": "socket.connect", "allowed": True, "address": ["127.0.0.1", 43210], "kind": "declared_loopback_or_probe"} for _ in self.requests)
            return {**base, "requests": deepcopy(self.requests), "mem0_embedding_method_invocations": 2,
                "embedding_method_events": [{"method": "embed", "text_count": 1}]*2, "embedding_texts": 2}
        return {**base, "native_requests": deepcopy(self.http), "native_embedding_function_invocations": 21}

    def call(self, command, data):
        start = self.clock.tick()
        if command == "close" or self.side == "target" and command == "report":
            result = self.summary()
        else:
            result = self.worker.call(command, data)
            if self.side == "source":
                if command == "init":
                    result["gateway_port"] = 43210
                    result.update(native_mem0_user_authentication=False, research_acl_gateway=True)
                elif command == "read":
                    self.requests.append(deepcopy(result))
            elif command == "init":
                for actor in audit.ACTORS:
                    self.raw("GET", "/api/v1/auths/", actor, None, auth=True)
                self.raw("GET", "/api/v1/memories/", None, {"detail": "Not authenticated"}, status=401)
            elif command in {"add", "add_residents"}:
                rows = result["residents"] if command == "add_residents" else [result]
                for row in rows:
                    rid, actor = row["target_id"], row["actor"]
                    native = deepcopy(self.worker.objects[rid])
                    native["user_id"] = "native-user-"+actor
                    self.raw("POST", "/api/v1/memories/add", actor, native,
                        payload={"content": row["content"], "path": row.get("path", data.get("path")), "type": "context"})
            elif command == "delete":
                self.raw("DELETE", "/api/v1/memories/"+data["target_id"], data["actor"], result["deleted"], status=result["status"])
            elif command == "snapshot":
                for row in result["rows"]:
                    actor, op, rid = row["actor"], row["operation"], row.get("requested_id")
                    if op != "semantic":
                        for item in row["items"]:
                            item["user_id"] = "native-user-"+item["actor"]
                        value = row["items"]
                    else:
                        value = row["vector_result"]
                    method = "GET" if op == "list" else "POST"
                    path = "/api/v1/memories/" if op == "list" else "/api/v1/memories/query" if op == "semantic" else "/api/v1/memories/search"
                    body = None if op == "list" else {"content": audit.QUERY, "k": 100} if op == "semantic" else {"memory_id": rid, "type": "all", "limit": 1} if op == "known_id" else {"query": "Customer", "type": "all", "limit": 100}
                    trace = self.raw(method, path, actor, value, status=row["status"], payload=body)
                    row.update(native_raw_body=trace["native_raw_body"], native_body_sha256=trace["native_body_sha256"])
        self.calls.append({"rpc_id": len(self.calls)+1, "command": command, "input": deepcopy(data),
            "input_sha256": audit.digest(data), "result": deepcopy(result), "response_sha256": audit.digest(result),
            "started_ns": start, "finished_ns": self.clock.tick()})
        return result


def fixture(root, **target_flags):
    clock = Clock()
    source = TraceWorker(FakeSource(), "source", root, clock)
    target = TraceWorker(FakeTarget(**target_flags), "target", root, clock)
    report = producer.run_scenario(source, target)
    for name, worker in (("source", source), ("target", target)):
        report[name+"_final"] = worker.call("close", {})
        report[name+"_rpc_receipts"] = worker.calls
    report["test_transport_only"] = True
    return report


class NativeExactFactVerifierTests(unittest.TestCase):
    def test_acl_order_is_set_semantics_but_duplicates_and_membership_still_fail(self):
        self.assertTrue(audit.same_readers(["assistant", "owner"], ["owner", "assistant"]))
        for value in (["owner"], ["owner", "outsider"], ["owner", "owner"], ["owner", "assistant", "assistant"],
                      ["owner", 1], "owner", None):
            self.assertFalse(audit.same_readers(value, ["owner", "assistant"]))

    def test_source_canonical_acl_order_passes_complete_trace(self):
        original = FakeSource.call
        def canonical(worker, command, data):
            result = original(worker, command, data)
            if command == "read" and result.get("status") == 200:
                result["trusted_migration_control"]["source_readers"].sort()
            return result
        with tempfile.TemporaryDirectory() as temp, patch.object(FakeSource, "call", new=canonical):
            root = Path(temp)
            report = fixture(root)
            self.assertEqual(audit.verify_trace(report, root)["status"], "passed")

    def test_independent_trace_passes_actual_host_scenario_fake_and_ignores_producer_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = fixture(root)
            report["status"] = "failed"
            report["checks"] = [{"name": "not_evidence", "passed": False}]
            with patch.object(producer, "check_snapshot", side_effect=AssertionError("producer checker forbidden")):
                result = audit.verify_trace(report, root)
            self.assertEqual(result["status"], "passed")
            self.assertEqual((result["copies_created"], result["copies_deleted"], result["qualified_nonempty_vector_rows"]), (6, 2, 15))
            self.assertGreater(result["source_embedding_method_invocations"], 0)
            self.assertGreater(result["target_embedding_function_invocations"], 0)
            self.assertEqual(result["generation_calls"], 0)

    def test_vector_residue_fake_delete_missing_positive_and_false_empty_404_are_rejected(self):
        for flags in ({"semantic_residual": True}, {"dishonest_delete": True}, {"semantic_drop_positive": True},
                      {"semantic_empty404": True}, {"semantic_bad_document": True}, {"semantic_bad_metadata": True}, {"leak_outsider": True}):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                report = fixture(root, **flags)
                with self.assertRaises(ValueError):
                    audit.verify_trace(report, root)

    def test_missing_copy_policy_unknown_authorization_and_outsider_allow_are_rejected(self):
        mutations = [lambda r: r["sidecar"]["main"]["copies"].pop(),
            lambda r: r["sidecar"]["main"]["migration_evidence"].pop("export_allowed"),
            lambda r: r["sidecar"]["main"]["migration_evidence"].update(copy_allowed=None),
            lambda r: r["sidecar"]["main"]["migration_evidence"]["decisions"].update(outsider="allow"),
            lambda r: r["public_exact_grants"]["main"].update(source_start=1),
            lambda r: r["public_exact_grants"]["main"].update(allowed_agent_ids=["AgentC"])]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                report = fixture(root)
                mutate(report)
                with self.assertRaises(ValueError):
                    audit.verify_trace(report, root)

    def test_drop_network_event_raw_hash_bad_whoami_and_incomplete_rpc_cannot_hide(self):
        mutations = [lambda r: r["source_final"]["network_events"].pop(),
            lambda r: r["target_final"]["native_requests"][3].update(native_body_sha256="0"*64),
            lambda r: r["target_runtime"]["whoami_public_receipts"][0].update(id="outsider-id"),
            lambda r: r["target_rpc_receipts"].pop(2),
            lambda r: r["source_rpc_receipts"][1].pop("input"),
            lambda r: r["target_final"].update(native_embedding_function_invocations=0)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                report = fixture(root)
                mutate(report)
                with self.assertRaises(ValueError):
                    audit.verify_trace(report, root)

    def test_native_raw_file_bytes_and_rpc_public_hash_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = fixture(root)
            (root/"target_state/responses/00003.bin").write_bytes(b"[]")
            with self.assertRaisesRegex(ValueError, "native_raw_file_mismatch"):
                audit.verify_trace(report, root)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = fixture(root)
            report["source_rpc_receipts"][1]["input_sha256"] = "0"*64
            with self.assertRaisesRegex(ValueError, "rpc_hash_mismatch"):
                audit.verify_trace(report, root)

    def test_earlier_version_is_bounded_not_v3_qualified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/"report.json").write_text(json.dumps({"version": "native_exact_fact_research_gateway_bridge_v2", "status": "passed"}))
            (root/"plan.json").write_text("{}")
            result = audit.verify(root)
            self.assertEqual(result["status"], "not_qualified_for_v3")
            self.assertIn("historical report left unchanged", result["scope"])


if __name__ == "__main__":
    unittest.main()
