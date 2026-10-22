"""Transport-only unit fixtures; these tests are not native product evidence."""
import copy
import contextlib
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_migration_study.evidence import evaluate, probe
from memory_migration_study.native_webui import NativeRecorder, NativeWebUIAdapter, run_native_webui_public
from memory_migration_study.policy import make_plan


def _case():
    return {"case_id": "unit-native-transport", "actors": [
        {"actor_id": actor, "user_id": "public-" + actor, "agent_id": "memory_worker"}
        for actor in ("owner", "assistant", "outsider")],
        "actor_mapping": {actor: "native-" + actor for actor in ("owner", "assistant", "outsider")},
        "records": [
            {"source_id": "customer", "text": "For Maple, the exact external customer is Example Cooperative, but that mapping stays inside.\nunit-marker-private",
             "source_readers": ["owner"], "recipient_readers": ["owner"], "target_readers": ["owner"], "export_allowed": True, "copy_allowed": True},
            {"source_id": "date", "text": "Recording the current Maple target date as June 25, 2026 while review continues.\nunit-marker-date",
             "source_readers": ["owner", "assistant"], "recipient_readers": ["owner", "assistant"],
             "target_readers": ["owner", "assistant"], "export_allowed": True, "copy_allowed": True}], "tasks": []}


class _Cookies:
    def __init__(self):
        self.clear_calls = 0

    def clear(self):
        self.clear_calls += 1


class FakeClient:
    """A small native-response-shaped transport fixture, never used by the runner."""
    def __init__(self, case, plan, controls):
        self.cookies, self.calls, self.responses = _Cookies(), [], {}
        self.rows = {actor["actor_id"]: [] for actor in case["actors"]}
        self.identities = {actor["actor_id"]: {"id": case["actor_mapping"][actor["actor_id"]],
                           "email": actor["actor_id"] + "@example.com", "role": "user"} for actor in case["actors"]}
        for obj in plan["objects"]:
            for actor in obj["readers"]:
                self.rows[actor].append({"id": obj["target_id"], "content": obj["text"], "user_id": case["actor_mapping"][actor]})
        for actor, control in controls.items():
            self.rows[actor].append({"id": control["target_id"], "content": "control-" + actor, "user_id": case["actor_mapping"][actor]})

    def request(self, method, path, headers=None, json=None):
        headers = headers or {}
        actor = headers.get("Authorization", "").removeprefix("Bearer unit-token-")
        self.calls.append({"method": method, "path": path, "headers": dict(headers), "json": json, "actor": actor})
        key = (method, path, actor)
        if key in self.responses:
            status, value = self.responses[key]
        elif path == "/api/v1/auths/":
            status, value = 200, dict(self.identities[actor], token="unit-token-" + actor)
        elif path == "/api/v1/memories/":
            status, value = 200, self.rows[actor]
        elif path == "/api/v1/memories/search":
            status, value = 200, [row for row in self.rows[actor] if row["id"] == json["memory_id"]][:1]
        else:
            status, value = 404, {"detail": "unit fixture route absent"}
        content = __import__("json").dumps(value, ensure_ascii=True).encode()
        return SimpleNamespace(status_code=status, content=content,
                               request=SimpleNamespace(headers={key.lower(): value for key, value in headers.items()}))


class NativeWebUIAdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.case = _case()
        self.plan = make_plan(self.case, "reader_copies", "unit-native")
        self.controls = {actor["actor_id"]: {"target_id": "control-id-" + actor["actor_id"],
                         "text_sha256": hashlib.sha256(("control-" + actor["actor_id"]).encode()).hexdigest()}
                         for actor in self.case["actors"]}
        self.client = FakeClient(self.case, self.plan, self.controls)
        self.recorder = NativeRecorder(self.client, self.output / "responses")
        self.recorder.tokens = {actor["actor_id"]: "unit-token-" + actor["actor_id"] for actor in self.case["actors"]}
        self.recorder.secret_values = list(self.recorder.tokens.values())
        self.adapter = NativeWebUIAdapter(self.recorder, self.case, self.plan, self.client.identities, self.controls)

    def capture(self):
        return probe(self.case, self.plan, self.adapter)

    def test_native_id_filter_empty_contract_completes_with_identity_and_controls(self):
        bundle = self.capture()
        result = evaluate(bundle)
        self.assertEqual((result["known_w_plus"], result["known_w_minus"], result["unknown_count"]), (0, 0, 0))
        self.assertTrue(result["finite_scope_safe"])
        empty = next(observation for observation in bundle["observations"]
                     if observation["endpoint"] == "read" and observation["native_raw_body"] == "[]")
        self.assertEqual(empty["status"], 200)
        self.assertEqual(empty["native_method"], "POST")
        self.assertEqual(empty["native_path"], "/api/v1/memories/search")
        self.assertEqual(empty["native_request_json"], {"memory_id": empty["target_id"], "type": "all", "limit": 1})
        self.assertEqual(Path(empty["native_response_file"]).read_bytes(), b"[]")

    def test_empty_read_contract_requires_all_declared_native_proof_fields(self):
        original = self.capture()
        for mutation in ("contract", "package", "path", "method", "memory_id", "hash", "backend"):
            with self.subTest(mutation=mutation):
                bundle = copy.deepcopy(original)
                empty = next(observation for observation in bundle["observations"]
                             if observation["endpoint"] == "read" and observation["native_raw_body"] == "[]")
                if mutation == "contract":
                    del empty["empty_read_contract"]
                elif mutation == "package":
                    empty["native_package_version"] = "unreviewed"
                elif mutation == "path":
                    empty["native_path"] = "/other"
                elif mutation == "method":
                    empty["native_method"] = "GET"
                elif mutation == "memory_id":
                    empty["native_request_json"]["memory_id"] = "another-target"
                elif mutation == "hash":
                    empty["native_body_sha256"] = "0" * 64
                else:
                    bundle["backend_kind"] = "external_gated"
                result = evaluate(bundle)
                self.assertGreater(result["unknown_count"], 0)
                self.assertIsNone(result["finite_scope_safe"])

    def test_generic_empty_json_200_is_not_native_denial_evidence(self):
        bundle = self.capture()
        empty = next(observation for observation in bundle["observations"]
                     if observation["endpoint"] == "read" and observation["native_raw_body"] == "[]")
        empty["raw_body"] = '{"items":[]}'
        self.assertIsNone(evaluate(bundle)["finite_scope_safe"])

    def test_native_fields_require_matching_bundle_contract_tag(self):
        original = self.capture()
        for tag in (None, "wrong-native-contract"):
            with self.subTest(tag=tag):
                bundle = copy.deepcopy(original)
                if tag is None:
                    del bundle["evidence_contract"]
                else:
                    bundle["evidence_contract"] = tag
                result = evaluate(bundle)
                self.assertIsNone(result["finite_scope_safe"])
                self.assertGreater(result["unknown_count"], 0)
                self.assertIn("native_observation_contract_missing_or_mismatched", result["structural_errors"])

    def test_nonempty_native_raw_hash_is_rechecked_when_bundle_is_reloaded(self):
        bundle = self.capture()
        observation = next(observation for observation in bundle["observations"]
                           if observation["endpoint"] == "read" and json.loads(observation["native_raw_body"]))
        observation["native_body_sha256"] = "0" * 64
        result = evaluate(bundle)
        self.assertIsNone(result["finite_scope_safe"])
        self.assertGreater(result["content_integrity_errors"], 0)

    def test_native_items_cannot_survive_raw_list_being_replaced_by_empty_array(self):
        bundle = self.capture()
        observation = next(observation for observation in bundle["observations"]
                           if observation["endpoint"] == "list" and observation["actor_id"] == "owner")
        normalized = json.loads(observation["raw_body"])
        observation.update(native_raw_body="[]", native_body_sha256=hashlib.sha256(b"[]").hexdigest())
        normalized.update(native_response=[], native_raw_body="[]")
        observation["raw_body"] = json.dumps(normalized)
        result = evaluate(bundle)
        self.assertIsNone(result["finite_scope_safe"])
        self.assertTrue(any(error["reason"] == "native_items_not_derived_from_raw_rows" for error in result["integrity_details"]))

    def test_native_raw_copies_and_items_cannot_be_added_or_removed_by_normalization(self):
        original = self.capture()
        for mutation in ("parsed_copy", "raw_copy", "add_item", "drop_item", "complete"):
            with self.subTest(mutation=mutation):
                bundle = copy.deepcopy(original)
                observation = next(observation for observation in bundle["observations"]
                                   if observation["endpoint"] == "list" and observation["actor_id"] == "owner")
                normalized = json.loads(observation["raw_body"])
                if mutation == "parsed_copy":
                    normalized["native_response"] = []
                elif mutation == "raw_copy":
                    normalized["native_raw_body"] = "[]"
                elif mutation == "add_item":
                    normalized["items"].append(dict(normalized["items"][0]))
                elif mutation == "drop_item":
                    normalized["items"].pop()
                else:
                    normalized["complete"] = False
                observation["raw_body"] = json.dumps(normalized)
                result = evaluate(bundle)
                self.assertIsNone(result["finite_scope_safe"])
                self.assertGreater(result["content_integrity_errors"], 0)

    def test_positive_control_and_identity_remain_required_for_empty_read(self):
        original = self.capture()
        for field in ("identity_valid", "positive_read"):
            bundle = copy.deepcopy(original)
            bundle["actor_controls"]["outsider"][field] = False
            self.assertIsNone(evaluate(bundle)["finite_scope_safe"])
        self.controls["outsider"]["text_sha256"] = "wrong"
        self.assertIsNone(evaluate(self.capture())["finite_scope_safe"])

    def test_auth_raw_responses_and_tokens_are_not_written(self):
        bundle = self.capture()
        serialized = json.dumps(bundle) + json.dumps(self.recorder.requests)
        all_bytes = b"".join(path.read_bytes() for path in (self.output / "responses").glob("*.bin"))
        for secret in self.recorder.secret_values:
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret.encode(), all_bytes)
        identities = [request for request in self.recorder.requests if request["native_path"] == "/api/v1/auths/"]
        self.assertEqual(len(identities), 3)
        self.assertTrue(all(request["auth_response_omitted"] and "native_response_file" not in request for request in identities))

    def test_cookie_jar_is_cleared_and_headers_use_each_native_credential(self):
        self.capture()
        self.assertEqual(self.client.cookies.clear_calls, len(self.client.calls))
        self.assertTrue(all(call["headers"] == {"Authorization": "Bearer unit-token-" + call["actor"]} for call in self.client.calls))
        self.assertFalse(any(request["cookie_present"] for request in self.recorder.requests))

    def test_error_body_json_key_disclosure_remains_a_definite_wplus(self):
        private = self.case["records"][0]["text"]
        self.client.responses[("POST", "/api/v1/memories/search", "outsider")] = (500, {private: "unit-key-only-disclosure"})
        bundle = self.capture()
        result = evaluate(bundle)
        self.assertGreater(result["known_w_plus"], 0)
        self.assertGreater(result["execution_errors"], 0)
        self.assertFalse(result["finite_scope_safe"])
        observation = next(observation for observation in bundle["observations"]
                           if observation["actor_id"] == "outsider" and observation["endpoint"] == "read")
        self.assertEqual(observation["status"], 500)
        self.assertEqual(json.loads(observation["raw_body"])["native_response"], {private: "unit-key-only-disclosure"})
        for observation in bundle["observations"]:
            if observation["actor_id"] == "outsider":
                observation["raw_body"] = '{"items":[]}'
        result = evaluate(bundle)
        self.assertGreater(result["known_w_plus"], 0, "native raw body remains a disclosure witness even if normalization is altered")
        self.assertGreater(result["content_integrity_errors"], 0)

    def test_unknown_native_row_is_not_silently_dropped(self):
        self.client.rows["outsider"].append({"id": "unregistered-copy", "content": self.case["records"][0]["text"], "user_id": "native-outsider"})
        result = evaluate(self.capture())
        self.assertGreater(result["content_integrity_errors"], 0)
        self.assertGreater(result["known_w_plus"], 0)

    def test_identity_uses_actual_native_uuid_and_never_accepts_other_principal(self):
        self.client.responses[("GET", "/api/v1/auths/", "assistant")] = (200, dict(self.client.identities["owner"]))
        valid, receipt = self.adapter.identity("assistant")
        self.assertFalse(valid)
        self.assertEqual(json.loads(receipt["raw_body"])["native_user_id"], "native-owner")
        self.assertIsNone(evaluate(self.capture())["finite_scope_safe"])

    def test_malformed_success_response_is_unknown_with_original_status_retained(self):
        self.client.responses[("POST", "/api/v1/memories/search", "outsider")] = (200, {"unexpected": []})
        bundle = self.capture()
        result = evaluate(bundle)
        self.assertIsNone(result["finite_scope_safe"])
        self.assertGreater(result["execution_errors"], 0)
        self.assertTrue(all(observation["status"] == 200 for observation in bundle["observations"] if observation["actor_id"] == "outsider"))

    def test_credential_contaminated_non_auth_response_is_not_persisted(self):
        self.client.responses[("GET", "/api/v1/memories/", "outsider")] = (500, {"unexpected_secret": "unit-token-outsider"})
        observation = self.adapter.list_pages("outsider")[0][0]
        self.assertEqual(observation["status"], 500)
        self.assertEqual(observation["execution_error"], "credential_contaminated_native_response")
        self.assertNotIn("native_response_file", observation)
        self.assertNotIn("unit-token-outsider", json.dumps(observation))


class NativeRunnerFailureTests(unittest.TestCase):
    def test_native_cli_exit_codes_distinguish_complete_counterexample_and_failures(self):
        from memory_migration_study.cli import main
        for status, expected in (("completed", 0), ("counterexample_found", 2), ("missing_dependency", 1), ("incomplete_evidence", 1)):
            with self.subTest(status=status), contextlib.redirect_stdout(io.StringIO()), \
                 patch("memory_migration_study.native_webui.run_native_webui_public", return_value={"status": status}):
                arguments = ["native-webui-public", "--legacy-project", "unit-project", "--output", "unit-output"]
                if expected:
                    with self.assertRaises(SystemExit) as raised:
                        main(arguments)
                    self.assertEqual(raised.exception.code, expected)
                else:
                    self.assertIsNone(main(arguments))

    def test_missing_dependency_preserves_prepared_fixture_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new-output"
            def prepare(_project, prepared):
                prepared.mkdir()
                runtime, evaluation = prepared / "runtime.json", prepared / "evaluation.json"
                runtime.write_text(json.dumps({"cases": [_case()]}), encoding="utf-8")
                evaluation.write_text(json.dumps({"cases": {}}), encoding="utf-8")
                return {"runtime_path": str(runtime), "evaluation_path": str(evaluation)}
            with patch("memory_migration_study.native_webui.prepare_controlled_fixture", side_effect=prepare), \
                 patch("memory_migration_study.native_webui.importlib.metadata.version", side_effect=importlib.metadata.PackageNotFoundError("open-webui")):
                report = run_native_webui_public(legacy_project=Path(directory) / "source", output=output)
            self.assertEqual(report["status"], "missing_dependency")
            self.assertTrue((output / "fixture/runtime.json").is_file())
            self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "missing_dependency")
            self.assertIsNone(report["real_llm"])
            self.assertEqual(report["remote_model_calls"], 0)

    def test_failed_preparation_has_error_type_and_never_becomes_native_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new-output"
            report = run_native_webui_public(legacy_project=Path(directory) / "absent-project", output=output)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["stage"], "prepare_fixture")
            self.assertEqual(report["error_type"], "FileNotFoundError")
            self.assertTrue(report["error_filename"])
            self.assertTrue(report["error_frames"])
            self.assertEqual(set(report["error_frames"][0]), {"file", "line", "function"})
            self.assertEqual(report["native_status"], "not_run")
            self.assertTrue((output / "manifest.json").is_file())
            with self.assertRaises(FileExistsError):
                run_native_webui_public(legacy_project=Path(directory), output=output)


if __name__ == "__main__":
    unittest.main()
