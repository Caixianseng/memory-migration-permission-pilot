"""CLI exit status is independent from model score or a green print line."""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from scripts import run_review_read_integration as cli


class IntegrationCLITests(unittest.TestCase):
    def call(self, report):
        output = io.StringIO()
        with patch.object(cli, "run", return_value=report), redirect_stdout(output):
            code = cli.main(["--output", "results/test-only-cli-not-created", "--plan-only"])
        return code, json.loads(output.getvalue())

    def test_native_failure_returns_nonzero_and_preserves_failure(self):
        code, output = self.call({"native": {"status": "unverified_or_incomplete",
            "failure": {"type": "TestOnly", "code": "unqualified_native_reference"}}})
        self.assertEqual(code, 1)
        self.assertEqual(output["failure"]["code"], "unqualified_native_reference")

    def test_plan_only_returns_zero(self):
        code, output = self.call({"status": "plan_only"})
        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "plan_only")

    def test_qualified_execution_returns_zero_without_claiming_quality_or_novelty(self):
        code, output = self.call({"native": {"status": "qualified_finite_native_read_chain", "failure": None},
                                  "consumer": {"model_calls": 56}})
        self.assertEqual(code, 0)
        self.assertEqual(output["consumer_model_calls"], 56)
        self.assertNotIn("paper_novelty_established", output)
