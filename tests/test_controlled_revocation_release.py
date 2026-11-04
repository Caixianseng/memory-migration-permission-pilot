"""Discover the controlled host tests and recompute its public evidence offline."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


class CanonicalTemporaryRootSuite(unittest.TestSuite):
    """Allocate fixtures below the real temp root, retaining strict path guards."""
    def run(self, result, debug=False):
        previous = tempfile.tempdir
        try:
            # Windows runners can expose TEMP through an 8.3 name or junction.
            tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
            return super().run(result, debug=debug)
        finally:
            tempfile.tempdir = previous


class TemporaryRootPortability(unittest.TestCase):
    def test_noncanonical_temp_root_is_resolved_and_restored(self):
        with tempfile.TemporaryDirectory() as folder:
            real = Path(folder).resolve()
            (real / 'holder').mkdir()
            alias = str(real / 'holder' / '..')

            def fixture_uses_canonical_path():
                self.assertEqual(tempfile.tempdir, str(real))
                with tempfile.TemporaryDirectory() as inner:
                    root = Path(inner).absolute()
                    self.assertEqual(root, root.resolve())

            result = unittest.TestResult()
            with mock.patch.object(tempfile, 'tempdir', alias):
                CanonicalTemporaryRootSuite([
                    unittest.FunctionTestCase(fixture_uses_canonical_path)
                ]).run(result)
                self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
                self.assertEqual(tempfile.tempdir, alias)

    def test_original_none_cache_restored_after_runner_exception(self):
        class ExplodingSuite(unittest.TestSuite):
            def run(self, result, debug=False):
                raise RuntimeError('fixture runner interrupted')

        with mock.patch.object(tempfile, 'tempdir', None):
            with self.assertRaisesRegex(RuntimeError, 'fixture runner interrupted'):
                CanonicalTemporaryRootSuite([ExplodingSuite()]).run(unittest.TestResult())
            self.assertIsNone(tempfile.tempdir)

    def test_explicit_alias_still_rejected_by_production_host(self):
        from experiments.revocation_rebuild_controlled_20261104.host import Host, HostError
        from experiments.revocation_rebuild_controlled_20261104.test_host import SOURCES
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'holder').mkdir()
            with self.assertRaisesRegex(HostError, 'fresh_output_no_resume'):
                Host(SOURCES, case_id='alias-denial', method='B1', view='unchanged',
                     out=root / 'holder' / '..' / 'host', instrument_only=True)


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
    suite = CanonicalTemporaryRootSuite([tests])
    for name in ('test_host', 'test_runner', 'test_model_adapter'):
        suite.addTests(loader.loadTestsFromName(
            'experiments.revocation_rebuild_controlled_20261104.' + name))
    return suite
