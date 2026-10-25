"""Physical generation accounting and budget checks; no model calls."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.run_boundary_transfer_diagnostic import ObservedTransport
from memory_migration_study.local_detector import MODEL, LocalSensitivityAgent


def request():
    return {"model": MODEL, "stream": False, "messages": [{"role": "user", "content": "authored test"}],
            "options": {"num_ctx": 4096, "num_predict": 64, "temperature": 0, "seed": 42}}


class TransportTests(unittest.TestCase):
    def test_success_and_cap_count_actual_requests(self):
        calls = []
        def transport(*args):
            calls.append(args)
            return {"prompt_eval_count": 40, "eval_count": 10, "message": {"content": "UNKNOWN"}}
        with tempfile.TemporaryDirectory() as tmp:
            observer = ObservedTransport(tmp, transport, max_generations=1)
            observer.call(None, "POST", "/api/chat", request())
            with self.assertRaisesRegex(ValueError, "cap_reached"):
                observer.call(None, "POST", "/api/chat", request())
            self.assertEqual(len(calls), 1)
            rows = [json.loads(line) for line in (Path(tmp)/"request_transport.jsonl").read_text().splitlines()]
            self.assertEqual([row["phase"] for row in rows], ["request", "response"])
            self.assertEqual(rows[0]["request_sha256"], rows[1]["request_sha256"])

    def test_transport_failure_retains_attempt_and_fixed_error(self):
        def transport(*args):
            raise RuntimeError("untrusted raw diagnostic")
        with tempfile.TemporaryDirectory() as tmp:
            observer = ObservedTransport(tmp, transport)
            with self.assertRaises(RuntimeError):
                observer.call(None, "POST", "/api/chat", request())
            self.assertEqual(observer.attempts, 1)
            self.assertEqual(observer.errors, 1)
            self.assertNotIn("untrusted raw", (Path(tmp)/"request_transport.jsonl").read_text())

    def test_actual_usage_error_is_not_a_successful_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = ObservedTransport(tmp, lambda *a: {"prompt_eval_count": 3073, "eval_count": 2})
            with self.assertRaisesRegex(ValueError, "token_budget_invalid"):
                observer.call(None, "POST", "/api/chat", request())
            self.assertEqual(observer.attempts, 1)
            self.assertEqual(observer.token_budget_violations, 1)

    def test_unregistered_configuration_never_contacts_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = ObservedTransport(tmp, lambda *a: self.fail("must not execute"))
            bad = request()
            bad["model"] = "another-model"
            with self.assertRaisesRegex(ValueError, "unregistered"):
                observer.call(None, "POST", "/api/chat", bad)
            self.assertEqual(observer.attempts, 0)

    def test_installed_patch_restores_transport(self):
        original = LocalSensitivityAgent._transport
        with tempfile.TemporaryDirectory() as tmp:
            observer = ObservedTransport(tmp, lambda *a: {"prompt_eval_count": 2, "eval_count": 1})
            with observer.installed():
                LocalSensitivityAgent().transport("POST", "/api/chat", request())
            self.assertIs(LocalSensitivityAgent._transport, original)
            self.assertEqual(observer.attempts, 1)


if __name__ == "__main__":
    unittest.main()
