"""Offline host/worker-contract tests; no services, SDK or model is started."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_migration_study.memory_labels import MemoryLabelAuthority
from scripts import run_native_exact_fact_bridge as bridge
from scripts.native_exact_fact_common import NetworkGuard
from scripts.native_exact_fact_source import MutableResearchACL, TrustedMigrationControl
from scripts.native_exact_fact_target import MODEL_DISCOVERY_OFF, configure_native_application
from tests.fixtures import legacy_acl_contract
from tests.fixtures.native_archive_layout import archive_only_legacy, archive_only_webui_python


class FakeSource:
    def __init__(self, *, revoke_works=True):
        self.calls, self.rows, self.readers = [], {}, {}
        self.migration_control = TrustedMigrationControl()
        self.revoke_works = revoke_works
    def call(self, command, data):
        self.calls.append({"command": command, "data": deepcopy(data)})
        if command == "init":
            for index, item in enumerate(data["records"]):
                self.rows[item["fact_key"]] = {"id": "native-source-"+str(index), "memory": item["text"]}
                self.readers[item["fact_key"]] = list(item["readers"])
                self.migration_control.register(item["fact_key"], self.rows[item["fact_key"]]["id"],
                    item["text"], item["migration_policy"])
            return {"rows": {key: row["id"] for key, row in self.rows.items()}, "mem0_version": "2.2.1",
                    "embedding_dimensions": 384, "infer": False}
        if command == "read":
            allowed = data["actor"] in self.readers[data["fact_key"]]
            result = {"status": 200 if allowed else 403, "body": deepcopy(self.rows[data["fact_key"]]) if allowed else {"error": "denied"},
                    "authenticated_principal": data["actor"], "record_id": self.rows[data["fact_key"]]["id"]}
            if allowed:
                result["trusted_migration_control"] = self.migration_control.read(data["fact_key"], self.readers[data["fact_key"]])
            return result
        if command == "set_migration_policy":
            self.migration_control.update(data["fact_key"], data["migration_policy"])
            return {"updated": True, "record_id": self.rows[data["fact_key"]]["id"]}
        if command == "revoke":
            if self.revoke_works:
                self.readers[data["fact_key"]] = []
            return {"revoked": True}
        raise AssertionError(command)


class FakeTarget:
    def __init__(self, *, dishonest_delete=False, leak_outsider=False, drop_id_rows=False, corrupt_content=False,
                 semantic_residual=False, semantic_empty404=False, semantic_drop_positive=False, semantic_bad_document=False,
                 semantic_bad_metadata=False):
        self.calls, self.objects, self.vector_objects, self.counter = [], {}, {}, 0
        self.dishonest_delete, self.leak_outsider = dishonest_delete, leak_outsider
        self.drop_id_rows, self.corrupt_content = drop_id_rows, corrupt_content
        self.semantic_residual, self.semantic_empty404 = semantic_residual, semantic_empty404
        self.semantic_drop_positive, self.semantic_bad_document = semantic_drop_positive, semantic_bad_document
        self.semantic_bad_metadata = semantic_bad_metadata

    def create(self, actor, text, path):
        self.counter += 1
        rid = "target-"+str(self.counter)
        self.objects[rid] = {"id": rid, "content": text, "actor": actor, "path": path.strip("/"),
            "type": "context", "created_at": 1, "updated_at": 1}
        self.vector_objects[rid] = deepcopy(self.objects[rid])
        return rid

    def call(self, command, data):
        self.calls.append({"command": command, "data": deepcopy(data)})
        if command == "init":
            return {"open_webui_version": "0.12.3", "source_sdk_overlay_present": False,
                    "model_discovery_disabled": True, "native_user_ids": {name: "native-user-"+name for name in bridge.ACTORS},
                    "whoami_public_receipts": [{"actor": name, "id": "native-user-"+name, "role": "user", "native_request_index": i}
                        for i, name in enumerate(bridge.ACTORS)]}
        if command == "add":
            rid = self.create(data["actor"], data["text"], data["path"])
            return {"target_id": rid, "actor": data["actor"], "content": data["text"]}
        if command == "add_residents":
            residents = []
            for actor in bridge.ACTORS:
                text, path = "Customer service status: unrelated resident for "+actor, "/resident-control/"+actor
                rid = self.create(actor, text, path)
                residents.append({"target_id": rid, "actor": actor, "content": text, "path": path})
            return {"residents": residents}
        if command == "delete":
            row = self.objects.get(data["target_id"])
            matches = row is not None and row["actor"] == data["actor"]
            if matches and not self.dishonest_delete:
                del self.objects[data["target_id"]]
                if not self.semantic_residual:
                    del self.vector_objects[data["target_id"]]
            return {"status": 200, "deleted": matches, **data}
        if command == "snapshot":
            rows = []
            for actor in ("owner", "assistant", "outsider"):
                visible = [row for row in self.objects.values() if row["actor"] == actor
                           or self.leak_outsider and actor == "outsider"]
                for operation, rid in [("list", None), ("lexical", None),
                        *[("known_id", rid) for rid in data["target_ids"] if not self.drop_id_rows]]:
                    items = [deepcopy(row) for row in visible if operation == "list"
                             or operation == "lexical" and "Customer" in row["content"] or operation == "known_id" and row["id"] == rid]
                    if self.corrupt_content and items:
                        items[0]["content"] = "TRUNCATED"
                    rows.append({"actor": actor, "operation": operation, "requested_id": rid, "status": 200,
                        "response_checked": True, "execution_error": None, "items": items,
                        "native_raw_body": json.dumps(items)})
                vectors = [deepcopy(row) for row in self.vector_objects.values() if row["actor"] == actor
                    or self.leak_outsider and actor == "outsider"]
                if self.semantic_drop_positive and vectors:
                    vectors = vectors[1:]
                empty = not visible or self.semantic_empty404
                value = {"detail": "No memories found for user"} if empty else {
                    "ids": [[item["id"] for item in vectors]],
                    "documents": [[item["path"]+"\n"+item["content"]+(" tampered" if self.semantic_bad_document else "") for item in vectors]],
                    "metadatas": [[{key: item[key] for key in ("created_at", "updated_at", "type", "path")} for item in vectors]],
                    "distances": [[0.8 for item in vectors]]}
                if self.semantic_bad_metadata and not empty and value["metadatas"][0]:
                    value["metadatas"][0][0]["path"] = "wrong-path"
                rows.append({"actor": actor, "operation": "semantic", "requested_id": None, "query": bridge.SEMANTIC_QUERY,
                    "k": 100, "status": 404 if empty else 200, "vector_result": value,
                    "response_checked": True, "execution_error": None, "native_raw_body": json.dumps(value),
                    "native_body_sha256": hashlib.sha256(json.dumps(value).encode("utf-8")).hexdigest()})
            return {"rows": rows}
        if command == "report":
            return {"native_requests": deepcopy(self.calls), "generation_attempts": 0}
        raise AssertionError(command)


class NativeExactFactTests(unittest.TestCase):
    def signed_fixture(self):
        source = FakeSource()
        text = "Permitted fact. Unmigrated secret."
        source.call("init", {"records": [{"fact_key": "main", "text": text, "readers": ["owner", "assistant"],
            "migration_policy": deepcopy(bridge.MIGRATION_POLICY)}]})
        authority = MemoryLabelAuthority(b"a"*32)
        record = authority.build_record({"source_id": "native-source-0", "text": text},
            {"text": "Permitted fact.", "source_start": 0, "source_end": 15, "findings": []},
            bridge.POLICY, owner_id="owner", readers=["owner", "assistant"], agent_id="AgentA",
            allowed_agent_ids=[bridge.AGENT], builder_version=bridge.VERSION)
        return source, FakeTarget(), authority, record

    def test_complete_host_scenario_and_precleanup_visibility(self):
        source, target = FakeSource(), FakeTarget()
        result = bridge.run_scenario(source, target)
        self.assertEqual(result["status"], "passed", result["checks"])
        self.assertTrue(all(row["passed"] for row in result["checks"]))
        copies = result["sidecar"]["main"]["copies"]
        self.assertEqual({row["actor"] for row in copies}, {"owner", "assistant"})
        self.assertEqual(len(result["deletions"]), len(copies))
        for copy in copies:
            before = bridge.listed_ids(result["snapshots"]["revoked_before_target_cleanup"])
            after = bridge.listed_ids(result["snapshots"]["after_cleanup"])
            self.assertIn(copy["target_id"], before[copy["actor"]])
            self.assertNotIn(copy["target_id"], after[copy["actor"]])
        self.assertEqual(result["old_job"]["replay"]["error"], "current_source_denied")
        self.assertEqual(result["old_job"]["export_forbidden_replay"]["error"], "export_forbidden")
        self.assertEqual(result["old_job"]["export_forbidden_source_read_status"], 200)
        self.assertEqual(bridge.listed_ids(result["snapshots"]["export_disabled_existing_copies_retained"]),
            bridge.listed_ids(result["snapshots"]["before_revoke"]))
        evidence = result["sidecar"]["main"]["migration_evidence"]
        self.assertEqual(evidence["method"], "reader_copies")
        self.assertEqual(evidence["source_id"], result["sidecar"]["main"]["record_id"])
        self.assertEqual(evidence["actual_source_id"], result["sidecar"]["main"]["source_id"])
        self.assertIs(evidence["export_allowed"], True)
        self.assertIs(evidence["copy_allowed"], True)
        self.assertEqual(result["generation_calls"], 0)
        self.assertEqual({item["actor"] for item in result["resident_controls"]}, set(bridge.ACTORS))
        after = bridge.listed_ids(result["snapshots"]["after_cleanup"])
        self.assertTrue(all(after[actor] for actor in bridge.ACTORS))
        self.assertTrue(all(result["snapshots"]["after_cleanup"]["rows"][i]["status"] == 200 for i in range(len(result["snapshots"]["after_cleanup"]["rows"])) if result["snapshots"]["after_cleanup"]["rows"][i]["operation"] == "semantic"))

    def test_semantic_old_vectors_missing_positive_404_and_payload_corruption_fail(self):
        for options in ({"semantic_residual": True}, {"semantic_empty404": True}, {"semantic_drop_positive": True},
                {"semantic_bad_document": True}, {"semantic_bad_metadata": True}):
            with self.subTest(options=options):
                result = bridge.run_scenario(FakeSource(), FakeTarget(**options))
                self.assertEqual(result["status"], "failed")
                self.assertTrue(any(not row["passed"] for row in result["checks"]))

    def test_semantic_404_is_only_exact_empty_user_and_auth_errors_do_not_pass(self):
        target = FakeTarget()
        target.call("init", {})
        snapshot = target.call("snapshot", {"target_ids": []})
        empty = {actor: set() for actor in bridge.ACTORS}
        self.assertTrue(bridge.check_snapshot(snapshot, empty, source_canary="canary"))
        for status, value in ((404, {"detail": "Not found"}), (403, {"detail": "No memories found for user"}),
                (200, None), (500, {"detail": "No memories found for user"})):
            changed = deepcopy(snapshot)
            semantic = next(row for row in changed["rows"] if row["operation"] == "semantic")
            semantic.update(status=status, vector_result=value)
            self.assertFalse(bridge.check_snapshot(changed, empty, source_canary="canary"))

    def test_public_rpc_receipts_are_bound_copied_and_ordered_without_process(self):
        worker = object.__new__(bridge.WorkerRPC)
        worker.calls, worker.index, worker.timeout = [], 0, 1
        worker.process = SimpleNamespace(stdin=io.StringIO())
        worker.messages = queue.Queue()
        worker.messages.put({"id": 1, "ok": True, "result": {"status": 200, "body": {"memory": "synthetic"}}})
        data = {"fact_key": "main", "actor": "owner"}
        result = worker.call("read", data)
        row = worker.calls[0]
        self.assertEqual(row["input_sha256"], bridge._digest(row["input"]))
        self.assertEqual(row["response_sha256"], bridge._digest(row["result"]))
        self.assertLessEqual(row["started_ns"], row["finished_ns"])
        self.assertEqual(row["rpc_id"], 1)
        data["actor"], result["status"] = "outsider", 403
        self.assertEqual(row["input"]["actor"], "owner")
        self.assertEqual(row["result"]["status"], 200)

    def test_whoami_mapping_swapped_duplicate_missing_or_admin_refuses_before_write(self):
        for kind in ("swap", "duplicate", "missing", "admin"):
            source, target = FakeSource(), FakeTarget()
            original = target.call
            def changed(command, data):
                result = original(command, data)
                if command == "init":
                    if kind == "swap":
                        result["native_user_ids"]["owner"], result["native_user_ids"]["assistant"] = result["native_user_ids"]["assistant"], result["native_user_ids"]["owner"]
                    elif kind == "duplicate":
                        result["native_user_ids"]["owner"] = result["native_user_ids"]["assistant"]
                    elif kind == "missing":
                        result["whoami_public_receipts"].pop()
                    else:
                        result["whoami_public_receipts"][0]["role"] = "admin"
                return result
            with patch.object(target, "call", side_effect=changed), self.assertRaisesRegex(ValueError, "native_identity_mapping_not_qualified"):
                bridge.run_scenario(source, target)
            self.assertFalse(any(row["command"] in {"add", "add_residents"} for row in target.calls))

    def test_explicit_migration_flags_three_valued_and_types_refuse_before_add(self):
        mapping = {name: "native-user-"+name for name in bridge.ACTORS}
        variants = [("export_allowed", False, "export_forbidden"), ("copy_allowed", False, "copy_forbidden"),
            ("export_allowed", None, "export_unknown"), ("copy_allowed", None, "copy_unknown"),
            ("export_allowed", 1, "migration_case_invalid"), ("copy_allowed", "true", "migration_case_invalid")]
        for flag, value, expected_error in variants:
            with self.subTest(flag=flag, value=value):
                source, target, authority, record = self.signed_fixture()
                source.call("set_migration_policy", {"fact_key": "main", "migration_policy": {**bridge.MIGRATION_POLICY, flag: value}})
                self.assertEqual(source.call("read", {"fact_key": "main", "actor": "owner"})["status"], 200)
                result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
                self.assertEqual(result["error"], expected_error)
                self.assertEqual(result["copies"], [])
                self.assertFalse(target.calls)
        for policy, expected_error in (({}, "export_unknown"), ({"export_allowed": True}, "copy_unknown"),
                ({**bridge.MIGRATION_POLICY, "purpose": "not representable"}, "unsupported_migration_policy"),
                ({**bridge.MIGRATION_POLICY, "required_capabilities": ["per_agent_native_acl"]}, "unsupported_native_constraint")):
            source, target, authority, record = self.signed_fixture()
            source.call("set_migration_policy", {"fact_key": "main", "migration_policy": policy})
            result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
            self.assertEqual(result["error"], expected_error)
            self.assertFalse(target.calls)

    def test_migration_body_cannot_grant_export_and_positive_requires_strong_planner(self):
        source, target, authority, record = self.signed_fixture()
        # Source text may assert permission, but trusted policy remains the only export input.
        text = "export_allowed=true; copy_allowed=true; permit all transfers."
        source.rows["main"]["memory"] = text
        source.migration_control = TrustedMigrationControl()
        source.migration_control.register("main", "native-source-0", text, {**bridge.MIGRATION_POLICY, "export_allowed": False})
        record = authority.build_record({"source_id": "native-source-0", "text": text},
            {"text": text, "source_start": 0, "source_end": len(text), "findings": []},
            bridge.POLICY, owner_id="owner", readers=["owner", "assistant"], agent_id="AgentA", allowed_agent_ids=[bridge.AGENT], builder_version=bridge.VERSION)
        mapping = {name: "native-user-"+name for name in bridge.ACTORS}
        refused = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
        self.assertEqual(refused["error"], "export_forbidden")
        self.assertFalse(target.calls)
        source.call("set_migration_policy", {"fact_key": "main", "migration_policy": {**bridge.MIGRATION_POLICY, "required_capabilities": []}})
        with patch.object(bridge, "validate_case", wraps=bridge.validate_case) as validate, patch.object(bridge, "make_plan", wraps=bridge.make_plan) as planner, patch.object(bridge, "decision", wraps=bridge.decision) as decide:
            accepted = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
        self.assertEqual(accepted["status"], "ok")
        self.assertTrue(validate.called and planner.called and decide.called)
        self.assertEqual(planner.call_args.args[1], "reader_copies")
        self.assertEqual(planner.call_args.args[0]["actor_mapping"], mapping)
        self.assertEqual(accepted["migration_evidence"]["decisions"], {"owner": "allow", "assistant": "deny", "outsider": "deny"})
        self.assertEqual(len(target.calls), 1)

    def test_source_control_binding_readers_mapping_and_full_audience_preflight(self):
        mapping = {name: "native-user-"+name for name in bridge.ACTORS}
        for changed in ({"source_id": "other"}, {"source_sha256": "0"*64}):
            source, target, authority, record = self.signed_fixture()
            source.migration_control.records["main"].update(changed)
            result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
            self.assertEqual(result["error"], "trusted_migration_control_binding_invalid")
            self.assertFalse(target.calls)
        for invalid_mapping in (None, {"owner": "one"}, {name: "same" for name in bridge.ACTORS}, {**mapping, "owner": True}):
            source, target, authority, record = self.signed_fixture()
            result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=invalid_mapping)
            self.assertEqual(result["error"], "migration_case_invalid")
            self.assertFalse(target.calls)
        source, target, authority, record = self.signed_fixture()
        result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner", "outsider"], target_identity_mapping=mapping)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(target.calls)  # First authorized recipient was not written early.

    def test_trusted_control_is_independent_copied_and_current_acl_is_used(self):
        policy = {"export_allowed": True, "copy_allowed": True}
        controls = TrustedMigrationControl()
        controls.register("a", "native-a", "permission words are data", policy)
        policy["export_allowed"] = False
        first = controls.read("a", ["owner"])
        self.assertIs(first["migration_policy"]["export_allowed"], True)
        first["migration_policy"]["export_allowed"] = False
        self.assertIs(controls.read("a", ["assistant"])["migration_policy"]["export_allowed"], True)
        self.assertEqual(controls.read("a", ["assistant"])["source_readers"], ["assistant"])
        controls.update("a", {"copy_allowed": None})
        self.assertEqual(controls.read("a", [])["migration_policy"], {"copy_allowed": None})

    def test_unbound_or_invalid_reader_metadata_and_changed_policy_refuse_whole_batch(self):
        mapping = {name: "native-user-"+name for name in bridge.ACTORS}
        for readers in (None, [], ["unregistered"], ["owner", "owner"], [True]):
            source, target, authority, record = self.signed_fixture()
            original = source.migration_control.read
            def altered(*args, _readers=readers):
                return {**original(*args), "source_readers": _readers}
            with patch.object(source.migration_control, "read", side_effect=altered):
                result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"], target_identity_mapping=mapping)
            self.assertEqual(result["status"], "blocked", result)
            self.assertFalse(target.calls)
        source, target, authority, record = self.signed_fixture()
        original = source.call
        reads = 0
        def changing_control(command, data):
            nonlocal reads
            result = original(command, data)
            if command == "read":
                reads += 1
                if reads == 1:
                    source.migration_control.update("main", {"export_allowed": True, "copy_allowed": True})
            return result
        with patch.object(source, "call", side_effect=changing_control):
            result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner", "assistant"], target_identity_mapping=mapping)
        self.assertEqual(result["error"], "migration_control_changed_during_planning")
        self.assertFalse(target.calls)

    def test_complete_source_and_canary_never_enter_any_target_rpc(self):
        source, target = FakeSource(), FakeTarget()
        result = bridge.run_scenario(source, target)
        encoded = json.dumps(target.calls)
        self.assertNotIn(result["trusted_fixture"]["source"], encoded)
        self.assertNotIn(result["trusted_fixture"]["source_only_canary"], encoded)
        for row in target.calls:
            if row["command"] == "add":
                self.assertEqual(set(row["data"]), {"actor", "text", "path"})
        self.assertNotIn("access_signature", json.dumps(result))
        self.assertNotIn("label_signature", json.dumps(result))
        self.assertNotIn("issuer_signature", json.dumps(result))

    def test_content_range_actor_agent_epoch_and_unsupported_block_before_add(self):
        source, target, authority, record = self.signed_fixture()
        changes = [({"text": "Unmigrated secret."}, "owner", bridge.AGENT, None),
                   ({"source_start": True}, "owner", bridge.AGENT, None),
                   ({"source_end": 16}, "owner", bridge.AGENT, None),
                   ({}, "outsider", bridge.AGENT, None), ({}, "owner", "AgentC", None),
                   ({}, "owner", bridge.AGENT, ["per_agent_native_acl"])]
        for change, actor, agent, capabilities in changes:
            result = bridge.migrate(source, target, authority, record | change,
                fact_key="main", actors=[actor], agent=agent, required_capabilities=capabilities)
            self.assertEqual(result["status"], "blocked", result)
            self.assertEqual(result["copies"], [])
        authority.bump_epoch()
        self.assertEqual(bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"])["error"], "lifecycle_epoch_changed")
        self.assertFalse(any(row["command"] == "add" for row in target.calls))

    def test_revoked_authority_and_live_source_are_independent_gates(self):
        source, target, authority, record = self.signed_fixture()
        authority.revoke(record["record_id"])
        self.assertEqual(bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"])["error"], "grant_revoked")
        self.assertFalse(target.calls)
        source, target, authority, record = self.signed_fixture()
        source.call("revoke", {"fact_key": "main"})
        self.assertEqual(bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"])["error"], "current_source_denied")
        self.assertFalse(target.calls)

    def test_source_content_or_identity_changed_cannot_be_migrated(self):
        for field, value in (("id", "other"), ("memory", "Changed native source")):
            source, target, authority, record = self.signed_fixture()
            source.rows["main"][field] = value
            result = bridge.migrate(source, target, authority, record, fact_key="main", actors=["owner"])
            self.assertEqual(result["error"], "current_source_content_changed")
            self.assertFalse(target.calls)

    def test_zero_or_missing_independent_observations_cannot_pass(self):
        for target in (FakeTarget(drop_id_rows=True), FakeTarget(corrupt_content=True)):
            result = bridge.run_scenario(FakeSource(), target)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any(not row["passed"] for row in result["checks"]))

    def test_successful_delete_http_without_actual_effect_fails(self):
        result = bridge.run_scenario(FakeSource(), FakeTarget(dishonest_delete=True))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(next(row["passed"] for row in result["checks"] if row["name"] == "all_old_ids_removed_resident_and_valid_control_preserved"))

    def test_outsider_leak_and_ineffective_source_revoke_remain_failures(self):
        for source, target in ((FakeSource(), FakeTarget(leak_outsider=True)), (FakeSource(revoke_works=False), FakeTarget())):
            result = bridge.run_scenario(source, target)
            self.assertEqual(result["status"], "failed")

    def test_guard_blocks_external_dns_dead_llm_and_unapproved_ports(self):
        guard = NetworkGuard()
        guard("socket.bind", (None, ("::1", 0)))  # Observed urllib3 probe, not suppressed.
        self.assertEqual(guard.events[-1]["address"], ["::1", 0])
        guard.allowed_ports.add(19999)
        guard("socket.connect", (None, ("127.0.0.1", 19999)))
        for event, values in (("socket.connect", (None, ("127.0.0.1", 9))),
                ("socket.connect", (None, ("8.8.8.8", 443))), ("socket.getaddrinfo", ("api.openai.com", 443)),
                ("socket.bind", (None, ("0.0.0.0", 0))), ("open", (".env", "r", 0))):
            with self.assertRaises(PermissionError):
                guard(event, values)
            if event.startswith("socket."):
                self.assertTrue(guard.events[-1].get("stack"))

    def test_windows_stdlib_socketpair_exception_is_code_bound_not_arbitrary_loopback(self):
        guard = NetworkGuard()
        def stand_in_for_fixed_stdlib_code():
            guard("socket.connect", (None, ("127.0.0.1", 23456)))
        guard._socketpair_code = stand_in_for_fixed_stdlib_code.__code__
        stand_in_for_fixed_stdlib_code()
        self.assertEqual(guard.events[-1]["kind"], "stdlib_socketpair_internal")
        with self.assertRaises(PermissionError):
            guard("socket.connect", (None, ("127.0.0.1", 23456)))

    def test_partial_checkpoints_preserve_negative_and_precleanup_observations(self):
        progress = []
        result = bridge.run_scenario(FakeSource(), FakeTarget(), checkpoint=lambda value: progress.append(deepcopy(value)))
        self.assertEqual(result["status"], "passed")
        stages = [row["stage"] for row in progress]
        self.assertIn("source_revoked_before_cleanup", stages)
        self.assertIn("cleanup_owner", stages)
        self.assertIn("cleanup_assistant", stages)
        before_cleanup = next(row for row in progress if row["stage"] == "source_revoked_before_cleanup")
        self.assertIn("revoked_before_target_cleanup", before_cleanup["snapshots"])
        self.assertNotIn("after_cleanup", before_cleanup["snapshots"])

    def test_acl_updates_use_existing_frozen_record_acl_contract(self):
        fixture_path = Path(legacy_acl_contract.__file__)
        metadata = json.loads(fixture_path.with_suffix(".provenance.json").read_text(encoding="utf-8"))
        excerpt = fixture_path.read_text(encoding="utf-8").split("# BEGIN FROZEN ACL EXCERPT\n", 1)[1]
        excerpt = excerpt.split("# END FROZEN ACL EXCERPT\n", 1)[0]
        self.assertEqual(hashlib.sha256(excerpt.encode("utf-8")).hexdigest(), metadata["excerpt_sha256"])
        self.assertEqual(metadata["source_sha256"], "280b4d5697e484912b667b5077b931a882895161063c9567123537e736046803")
        principal = legacy_acl_contract.Principal("owner", "storage", "", "")
        acl = MutableResearchACL(legacy_acl_contract.RecordACL,
                                 {"main": ["owner"], "control": ["owner"]}, ["owner"])
        self.assertTrue(acl.allows(principal, "main"))
        acl.revoke("main")
        self.assertFalse(acl.allows(principal, "main"))
        self.assertTrue(acl.allows(principal, "control"))

    def test_project_relative_archive_keeps_exact_eight_sources_after_later_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, output = root/"project", root/"run"
            project.mkdir()
            output.mkdir()
            paths = []
            for index in range(8):
                path = project/"scripts"/("reviewed_"+str(index)+".py")
                path.parent.mkdir(exist_ok=True)
                path.write_text("VERSION = "+str(index), encoding="utf-8")
                paths.append(path)
            hashes = {str(path.resolve()): bridge.file_sha256(path) for path in paths}
            archived = bridge.archive_code(paths, hashes, output, project=project)
            self.assertEqual(len(archived), 8)
            for name, item in archived.items():
                self.assertEqual(item["archive_path"], "implementation/"+item["project_relative_path"])
                self.assertEqual(bridge.file_sha256(output/item["archive_path"]), hashes[name])
            original_archive = (output/archived[str(paths[0].resolve())]["archive_path"]).read_bytes()
            paths[0].write_text("EDITED AFTER RUN", encoding="utf-8")
            self.assertEqual((output/archived[str(paths[0].resolve())]["archive_path"]).read_bytes(), original_archive)
            self.assertEqual(bridge.verify_sha_table(hashes)["status"], "failed")
            copied_hashes = {str(output/item["archive_path"]): item["sha256"] for item in archived.values()}
            self.assertEqual(bridge.verify_sha_table(copied_hashes)["status"], "passed")
            (output/next(iter(archived.values()))["archive_path"]).write_text("TAMPERED", encoding="utf-8")
            self.assertEqual(bridge.verify_sha_table(copied_hashes)["status"], "failed")

    def test_archive_refuses_changed_before_copy_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source.py", root/"run"
            output.mkdir()
            source.write_text("original", encoding="utf-8")
            hashes = {str(source.resolve()): bridge.file_sha256(source)}
            source.write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                bridge.archive_code([source], hashes, output, project=root)
            hashes[str(source.resolve())] = bridge.file_sha256(source)
            bridge.archive_code([source], hashes, output, project=root)
            with self.assertRaises(FileExistsError):
                bridge.archive_code([source], hashes, output, project=root)

    def sdk_fixture(self, root):
        target = root/"site-packages"
        target.mkdir(parents=True)
        rows = []
        for name, raw in (("mem0/__init__.py", b"sdk fixture"), ("mem0/native.pyd", b"binary fixture")):
            path = target/name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            rows.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        (root/"installed_file_hashes.json").write_text(json.dumps(rows), encoding="utf-8")
        return target, rows

    def test_sdk_inventory_hashes_actual_contents_and_rejects_extra_missing_or_same_size_change(self):
        for condition in ("valid", "same_size_change", "missing", "extra"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target, rows = self.sdk_fixture(root)
                if condition == "same_size_change":
                    (target/"mem0/native.pyd").write_bytes(b"BINARY fixture")
                elif condition == "missing":
                    (target/"mem0/native.pyd").unlink()
                elif condition == "extra":
                    (target/"unlisted.py").write_text("unexpected", encoding="utf-8")
                result = bridge.verify_sdk_inventory(root)
                self.assertEqual(result["status"], "passed" if condition == "valid" else "failed", result)
                self.assertEqual(result["manifest_entries"], 2)
                self.assertIsNotNone(result["manifest_sha256"])
                if condition == "valid":
                    self.assertEqual(result["checked_files"], 2)
                    self.assertEqual(result["actual_file_count"], 2)

    def test_sdk_manifest_duplicate_boolean_size_or_path_escape_is_not_a_valid_inventory(self):
        for condition in ("duplicate", "boolean", "escape"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, rows = self.sdk_fixture(root)
                if condition == "duplicate":
                    rows.append(deepcopy(rows[0]))
                elif condition == "boolean":
                    rows[0]["bytes"] = True
                else:
                    rows[0]["path"] = "../outside"
                (root/"installed_file_hashes.json").write_text(json.dumps(rows), encoding="utf-8")
                self.assertEqual(bridge.verify_sdk_inventory(root)["status"], "failed")

    def test_bad_sdk_inventory_prevents_either_native_worker_from_starting(self):
        (bridge.PROJECT / "results").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=bridge.PROJECT / "results", prefix="bridge_inventory_fake_") as directory:
            root = Path(directory).resolve()
            legacy = archive_only_legacy(root / "legacy")
            python = archive_only_webui_python(root / "webui_runtime")
            sdk = root/"sdk"
            target, _ = self.sdk_fixture(sdk)
            (target/"mem0/native.pyd").write_bytes(b"modified")
            (sdk/"pip-report.json").write_text("{}", encoding="utf-8")
            original_hash = bridge.file_sha256
            def avoid_reading_real_weights(path):
                return "0"*64 if Path(path).suffix == ".safetensors" else original_hash(path)
            with patch.object(bridge, "file_sha256", side_effect=avoid_reading_real_weights), patch.object(bridge, "WorkerRPC") as workers:
                result = bridge.run(root/"out", python=python, sdk_root=sdk, legacy_project=legacy)
            workers.assert_not_called()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["sdk_inventory_preflight"]["status"], "failed")
            plan = json.loads((root/"out/plan.json").read_text(encoding="utf-8"))
            self.assertEqual(len(plan["code_archive"]), len(list((bridge.PROJECT/"memory_migration_study").glob("*.py")))+6)
            self.assertIn("memory_migration_study/privacy.py", plan["package_source_inventory"])
            self.assertIn("memory_migration_study/span_answer_evidence.py", plan["package_source_inventory"])
            self.assertTrue((root/"out/report.json").is_file())

    def test_explicit_discovery_off_is_after_legacy_clear_and_before_import_and_lifespan(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=False):
            root = Path(directory)
            config_path = root/"config.py"
            config_path.write_text("fixed-version fixture", encoding="utf-8")
            order = []
            def legacy_configure(state, assets):
                order.append("legacy_configure")
                for name in MODEL_DISCOVERY_OFF:
                    os.environ.pop(name, None)
                os.environ["ENABLE_OLLAMA_API"] = "false"  # v1 also had this, insufficient by itself.
                return {"RAG_EMBEDDING_MODEL": "local-minilm", "ENABLE_MEMORIES": "true"}, None, []
            def loader():
                order.append("native_import")
                for name, value in MODEL_DISCOVERY_OFF.items():
                    self.assertEqual(os.environ[name], value)
                app = SimpleNamespace(state=SimpleNamespace(ef=object(), EMBEDDING_FUNCTION=lambda *args: None))
                config = SimpleNamespace(__file__=str(config_path), ENABLE_OLLAMA_API=False, ENABLE_OPENAI_API=False,
                    OLLAMA_BASE_URL="http://127.0.0.1:9", OLLAMA_BASE_URLS=["http://127.0.0.1:9"])
                return app, config
            settings, handle, egress, app, receipt = configure_native_application(legacy_configure, root, root, loader=loader)
            order.append("native_lifespan_can_start_only_after_returned_app")
            self.assertEqual(order, ["legacy_configure", "native_import", "native_lifespan_can_start_only_after_returned_app"])
            self.assertEqual(settings["RAG_EMBEDDING_MODEL"], "local-minilm")
            self.assertEqual(settings["ENABLE_MEMORIES"], "true")
            self.assertTrue(callable(app.state.EMBEDDING_FUNCTION))
            self.assertEqual(receipt["native_config_sha256"], bridge.file_sha256(config_path))
            self.assertFalse(receipt["dead_endpoint_port_9_allowed"])
            guard = NetworkGuard()
            for port in (9, 11434, 12434, 11435):
                with self.assertRaises(PermissionError):
                    guard("socket.connect", (None, ("127.0.0.1", port)))

    def test_discovery_off_cannot_be_applied_after_native_import(self):
        with patch.dict(sys.modules, {"open_webui.already_loaded": SimpleNamespace()}):
            with patch("scripts.native_exact_fact_target.load_native_application") as loader:
                with self.assertRaises(ValueError):
                    configure_native_application(lambda *args: ({}, None, []), Path("unused"), Path("unused"))
                loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
