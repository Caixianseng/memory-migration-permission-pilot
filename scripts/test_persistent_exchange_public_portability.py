"""Portable companions for the public, inference-disabled test runner.

The archived finalizer test combines terminal-queue accounting with a Windows
drive namespace. This companion runs its accounting checks on ordinary native
paths on every OS, without changing the archived tests or production resolver.
It also checks the POSIX literal-prefix boundary instead of emulating Windows.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from experiments.persistent_exchange_v1 import test_finalize as frozen


class PersistentExchangePublicPortabilityTests(unittest.TestCase):
    def test_terminal_queue_accounting_keeps_unknown_execution_and_cost(self):
        helper_type = frozen.PersistentExchangeFinalAuditTests
        helper_type.setUpClass()
        helper = helper_type('test_terminal_queue_submission_has_unknown_execution_and_namespace_is_same_path')
        audit = frozen.audit
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            terminal = {('exchange-n100-r00', 'A', 'initial', 'chunk0')}
            plans, _, readbacks = helper.fixture(root, terminal_sources=terminal)
            normal = next(path for path, plan in plans.items() if plan['platform'] == 'hy3'
                          and (plan['case_id'], plan['agent'], plan['phase'], plan['group']) not in terminal)
            source = audit._load(normal)
            source['evidence'].update(actual_models=['hy3', 'hy3-x'], request_model_ids=['hy3-x'],
                                      canonical_model_family='Hy3', billing_route_ids=['hy3-x'])
            helper.save(normal, source)
            helper.mock_scope(normal)
            self.assertEqual(audit._path(root, str(normal)), normal)
            report, _ = helper.run_audit(root, readbacks)
            ledger = report['main_physical_ledger']
            planned_native = sum(plan['platform'] == 'hy3' for plan in plans.values()) + 48
            self.assertEqual(ledger['hy3_native_queue_submissions'], planned_native)
            self.assertEqual(ledger['hy3_native_tasks'], planned_native - 1)
            self.assertEqual(ledger['hy3_queue_submission_without_verified_model_execution'], 1)
            self.assertEqual(ledger['model_submission_count_unknown_attempts'], 1)
            self.assertEqual(ledger['source_attempt_outcomes']['terminal_queue_no_artifact_closed'], 1)
            self.assertIsNone(ledger['hy3_physical_supplier_calls'])
            self.assertIsNone(ledger['workbuddy_supplier_fee_cny'])
            closed = next(row for row in report['main_jobs']
                          if row.get('source_attempt_status') == 'terminal_queue_no_artifact_closed')
            self.assertEqual(closed['identity']['native_queue_submissions'], 1)
            self.assertEqual(closed['identity']['native_tasks'], 0)
            self.assertIsNone(closed['identity']['physical_supplier_calls'])
            self.assertIsNone(closed['identity']['model_execution_count'])

    def test_private_outside_and_posix_literal_namespace_boundaries_stay_intact(self):
        audit = frozen.audit
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temporary:
            root = Path(temporary).resolve()
            normal = root / 'MOCK-normal.json'
            normal.write_text('{}', encoding='utf-8')
            self.assertEqual(audit._path(root, normal), normal)
            with self.assertRaisesRegex(audit.FinalizeError, 'artifact_outside_result_root'):
                audit._path(root, root.parent / 'MOCK-outside.json')
            with self.assertRaisesRegex(audit.FinalizeError, 'private_artifact_path_forbidden'):
                audit._path(root, root / 'sdk.private' / 'MOCK-private.json')
            if os.name != 'nt':
                # A Windows-looking prefix on a POSIX path is a literal path,
                # never evidence that the native Windows alias was verified.
                literal = audit._path(root, '\\\\?\\' + str(normal))
                self.assertNotEqual(literal, normal)
                self.assertFalse(literal.exists())
                with self.assertRaises(FileNotFoundError):
                    audit._load(literal)


if __name__ == '__main__':
    unittest.main()
