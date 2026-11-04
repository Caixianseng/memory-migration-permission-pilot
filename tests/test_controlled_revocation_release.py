"""Discover the controlled host tests and recompute its public evidence offline."""
from pathlib import Path
import subprocess
import sys
import unittest


class PublicRevocationEvidence(unittest.TestCase):
    def test_public_evidence_recomputes_without_account_or_model(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-S',
             str(root / 'benchmarks/revocation_rebuild_controlled_20261104/reproduce.py')],
            cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def load_tests(loader, tests, pattern):
    for name in ('test_host', 'test_runner', 'test_model_adapter'):
        tests.addTests(loader.loadTestsFromName(
            'experiments.revocation_rebuild_controlled_20261104.' + name))
    return tests
