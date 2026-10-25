"""Build a complete tiny recorded run using fake HTTP and independently audit it."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from memory_migration_study import semantic_memory_benchmark as benchmark
from memory_migration_study.local_detector import MODEL, DIGEST, VERSION
from scripts.run_boundary_transfer_diagnostic import ObservedTransport
from scripts import verify_boundary_transfer_diagnostic as verifier
from tests.test_study_semantic_memory_benchmark import fixture, FakeNerRuntime, FakeAnswerer


class BoundaryTransferVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.corpus, cls.recorded_run = root/"corpus", root/"run"
        split = cls.corpus/"development"
        split.mkdir(parents=True)
        runtime, evaluation = fixture()
        for name, value in (("runtime.json", runtime), ("evaluation.json", evaluation)):
            (split/name).write_text(json.dumps(value), encoding="utf-8")
        cls.config_source = root/"local_config.json"
        config = {"endpoint": "http://127.0.0.1:11435", "model": MODEL, "expected_version": VERSION, "expected_digest": DIGEST}
        cls.config_source.write_text(json.dumps(config), encoding="utf-8")
        answerer = FakeAnswerer()
        def fake_http(client, method, path, body=None):
            if (method, path) == ("GET", "/api/version"):
                return {"version": VERSION}
            if (method, path) == ("GET", "/api/tags"):
                return {"models": [{"name": MODEL, "digest": DIGEST}]}
            if (method, path) != ("POST", "/api/chat"):
                raise AssertionError("unknown_fake_route")
            properties = body.get("format", {}).get("properties", {})
            data = json.loads(body["messages"][1]["content"])
            if "facts" in properties:
                text = data["text"]
                content = json.dumps({"status": "ok", "facts": [{"quote": text, "findings": [
                    {"quote": "Cedar Foundry", "category": "CUSTOMER"},
                    {"quote": "relay@sample.test", "category": "EMAIL"}]}]})
            elif "intent" in properties:
                query = data["query"].casefold()
                content = json.dumps({"intent": "EMAIL" if "email" in query else "STATUS" if "status" in query else "CUSTOMER"})
            else:
                content = answerer(data)["answer"]
            return {"model": MODEL, "done": True, "done_reason": "stop", "message": {"role": "assistant", "content": content},
                    "prompt_eval_count": 200, "eval_count": 60}
        observer = ObservedTransport(cls.recorded_run, fake_http)
        with patch.object(benchmark, "LocalNerRuntime", return_value=FakeNerRuntime()), \
             patch("socket.socket.connect", side_effect=AssertionError("fake_run_must_not_connect")), observer.installed():
            benchmark.run(cls.corpus, cls.recorded_run, "not-loaded", config, paired_boundary=True)
        launcher = Path(__file__).resolve().parents[1]/"scripts"/"run_boundary_transfer_diagnostic.py"
        (cls.recorded_run/"launcher.py").write_bytes(launcher.read_bytes())
        network = {"loopback_connections": 0, "external_attempts_blocked": 0}
        audit = dict(observer.summary(), completed=True, network=network,
            launcher_sha256=verifier.sha(launcher.read_bytes()), launcher_unchanged=True,
            config_sha256=verifier.sha(cls.config_source.read_bytes()))
        (cls.recorded_run/"transport_audit.json").write_text(json.dumps(audit), encoding="utf-8")
        (cls.recorded_run/"network_audit.json").write_text(json.dumps(network), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def verify(self, path):
        return verifier.verify(path, corpus=self.corpus, config_source=self.config_source,
                               expected_stories=1, expected_legal=4, expected_outsiders=1)

    def copied(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name)/"run"
        shutil.copytree(self.recorded_run, target)
        return target

    def mutate(self, folder, name, change):
        path = folder/name
        value = json.loads(path.read_bytes())
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_complete_fake_http_run_passes_without_claiming_independent_masks(self):
        result = self.verify(self.recorded_run)
        self.assertEqual(result["status"], "passed", [item for item in result["checks"] if not item["passed"]])
        self.assertEqual(result["rows_verified"], 55)
        self.assertEqual(result["physical_posts"], 49)
        self.assertEqual(result["observed_stage_posts"], {"build": 1, "intent": 4, "answer": 44})
        self.assertFalse(result["independent_mask_alignment_recomputed"])
        self.assertFalse(result["authenticated_restore_reexecuted"])
        self.assertEqual(result["verification_model_calls"], 0)

    def test_missing_row_score_or_changed_summary_cannot_pass(self):
        for mutation in ("row", "score", "summary"):
            with self.subTest(mutation=mutation):
                target = self.copied()
                if mutation == "row":
                    self.mutate(target, "rows.json", lambda rows: rows.pop())
                elif mutation == "score":
                    self.mutate(target, "rows.json", lambda rows: rows[0]["score"].pop("joint_correct_no_masking_gap"))
                else:
                    self.mutate(target, "report.json", lambda report: report["arms"]["coverage_migration__boundary"].update(correct=99))
                self.assertEqual(self.verify(target)["status"], "failed")

    def test_transport_hash_usage_and_response_binding_tampering_fail(self):
        for mutation in ("hash", "usage", "answer"):
            with self.subTest(mutation=mutation):
                target = self.copied()
                path = target/"request_transport.jsonl"
                events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                if mutation == "hash":
                    events[0]["request_sha256"] = "0"*64
                elif mutation == "usage":
                    response = next(event for event in events if event["phase"] == "response")
                    response["response"]["eval_count"] = 9999
                    response["response_sha256"] = verifier.digest(response["response"])
                else:
                    request = next(event for event in events if event["phase"] == "request" and "format" not in event["request"])
                    response = next(event for event in events if event["phase"] == "response" and event["index"] == request["index"])
                    response["response"]["message"]["content"] = "different_actual_response"
                    response["response_sha256"] = verifier.digest(response["response"])
                path.write_text("\n".join(json.dumps(event) for event in events)+"\n", encoding="utf-8")
                self.assertEqual(self.verify(target)["status"], "failed")

    def test_archive_keys_and_generation_cap_are_checked(self):
        for mutation in ("archive", "key", "cap"):
            with self.subTest(mutation=mutation):
                target = self.copied()
                if mutation == "archive":
                    path = target/"implementation"/"privacy.py"
                    path.write_bytes(path.read_bytes()+b"\n# changed\n")
                elif mutation == "key":
                    self.mutate(target, "report.json", lambda report: report.update(hmac_key="must_never_be_persisted"))
                else:
                    self.mutate(target, "transport_audit.json", lambda audit: audit.update(registered_generation_cap=401))
                self.assertEqual(self.verify(target)["status"], "failed")

    def test_primary_zero_and_secondary_changed_does_not_hide_primary_failure(self):
        target = self.copied()
        def change(rows):
            row = next(row for row in rows if row.get("secondary_serialization"))
            row["secondary_serialization"]["canonical_answer"] = "forged_token"
        self.mutate(target, "rows.json", change)
        result = self.verify(target)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(next(item["passed"] for item in result["checks"]
            if item["check"] == "secondary_exact_current_payload_token_only_primary_retained"))

    def test_incomplete_zero_call_environment_attempt_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/"transport_audit.json").write_text(json.dumps({"completed": False, "physical_generation_attempts": 0}), encoding="utf-8")
            result = self.verify(path)
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(result["zero_call_attempt_confirmed"])


if __name__ == "__main__":
    unittest.main()
