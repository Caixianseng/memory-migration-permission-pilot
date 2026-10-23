import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from memory_migration_study.provider_preflight import inspect_deepseek


class ProviderPreflightTests(unittest.TestCase):
    def test_escaped_credential_never_written_or_returned(self):
        secret = "FAKE-CREDENTIAL-ONLY"
        raw = b'{"data":[{"id":"\\u0046AKE-CREDENTIAL-ONLY"}],"balance_infos":[{"total_balance":"\\u0046AKE-CREDENTIAL-ONLY"}]}'
        conn = MagicMock()
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = raw
        with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"STUDY_MODEL_API_KEY": secret}), patch("http.client.HTTPSConnection", return_value=conn):
            path = Path(tmp) / "preflight.json"
            report = inspect_deepseek(path)
            self.assertNotIn(secret, path.read_text(encoding="utf-8"))
            self.assertTrue(all(x["error"] == "sensitive_response_rejected" for x in report["checks"].values()))
            self.assertTrue(all(call.args[0] == "GET" for call in conn.request.call_args_list))

    def test_http_error_body_is_not_logged(self):
        conn = MagicMock()
        conn.getresponse.return_value.status = 401
        conn.getresponse.return_value.read.return_value = b'{"error":"private upstream debug"}'
        with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"STUDY_MODEL_API_KEY": "FAKE"}), patch("http.client.HTTPSConnection", return_value=conn):
            path = Path(tmp) / "preflight.json"
            report = inspect_deepseek(path)
            self.assertNotIn("private upstream", path.read_text(encoding="utf-8"))
            self.assertEqual(report["generative_requests"], 0)


if __name__ == "__main__":
    unittest.main()
