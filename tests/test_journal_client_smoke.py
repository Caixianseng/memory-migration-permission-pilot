"""Native experiment preflight controls: no client or answer reference access."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from experiments.journal_methods_20261030.client_smoke import (
    Transaction, ControlledHost, load_cases, render, hash_value, budget_check,
    audit_raw, SpendingMonitor,
)


class ClientSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.case=load_cases()[0]
        self.host=ControlledHost(self.case,Path(self.temp.name)/'host')
        self.transaction=Transaction(self.host,self.case['tasks'][2])
        self.workspace=Path(self.temp.name)/'C'

    def test_protected_source_target_bytes_match(self):
        t=self.transaction
        self.assertEqual(render(t.views['B']),render(t.views['C']))
        self.assertNotIn('@example.invalid',render(t.views['C']))

    def test_no_memory_control_is_empty_but_nonempty_instruction_file(self):
        t=self.transaction
        self.assertEqual(t.views['D'],{'memories':[]})
        self.assertGreater(len(render(t.views['D'])),0)

    def test_capability_cannot_switch_agent_or_condition(self):
        t=self.transaction;c=t.bind('C',self.workspace)
        bad=deepcopy(c);bad['binding']['agent_id']='qoder'
        with self.assertRaisesRegex(ValueError,'capability'):
            t.check(bad,'C',self.workspace)
        with self.assertRaisesRegex(ValueError,'capability'):
            t.check(c,'B',self.workspace)

    def test_capability_single_use_even_unknown(self):
        t=self.transaction;c=t.bind('C',self.workspace)
        self.assertEqual(t.restore('UNKNOWN',c,'C',self.workspace)['answer'],'UNKNOWN')
        with self.assertRaisesRegex(ValueError,'consumed'):
            t.restore('UNKNOWN',c,'C',self.workspace)

    def test_restoration_rechecks_actual_current_permission(self):
        t=self.transaction;c=t.bind('C',self.workspace)
        self.host.revoke(t.transfer_fids[0])
        with self.assertRaises(ValueError):
            t.restore('UNKNOWN',c,'C',self.workspace)

    def test_separate_slots_same_transaction_cannot_swap_workspace(self):
        t=self.transaction;c=t.bind('B',self.workspace)
        with self.assertRaisesRegex(ValueError,'capability'):
            t.check(c,'B',self.workspace/'other')

    def test_source_only_values_are_excluded_from_both_protected_views(self):
        case=load_cases()[1];host=ControlledHost(case,Path(self.temp.name)/'other')
        tr=Transaction(host,case['tasks'][1])
        withheld=[f for f in host.rows if host.rows[f]['export_allowed'] is not True]
        self.assertTrue(withheld)
        for f in withheld:
            self.assertIn(f,tr.source_fids);self.assertNotIn(f,tr.transfer_fids)
            self.assertNotIn(host.rows[f]['text'],render(tr.views['B']))

    def test_unverified_budget_cannot_start_inference(self):
        import json
        path=Path(self.temp.name)/'budget.json'
        path.write_text(json.dumps({'schema':'journal_client_budget_v1',
            'execution_approved':False}),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'verified_budget_required'):
            budget_check(path)

    def test_non_pii_but_nonexportable_value_is_audited(self):
        case=load_cases()[1];host=ControlledHost(case,Path(self.temp.name)/'withheld')
        tr=Transaction(host,case['tasks'][1])
        text=next(f['text'] for f in host.rows.values() if not f['export_allowed'] and not f['privacy_spans'])
        value=text.split('为',1)[1].rstrip('。')
        self.assertTrue(audit_raw(tr,'C','不能提供，但内容是'+value)['unauthorized_raw_disclosure'])
        self.assertFalse(audit_raw(tr,'A',value)['unauthorized_raw_disclosure'])

    def test_no_observable_reply_is_not_zero_leak_evidence(self):
        self.assertIsNone(audit_raw(self.transaction,'C',None)['registered_leak'])

    def test_budget_reserves_before_each_paid_request(self):
        def snapshot():
            return {'harness':{'credential_file_unchanged':True,
                'normal_wallets':[{'currency':'CNY','balance':'10'}],'bonus_wallets':[]},
                'qoder':{'status':'ready','quota_remaining_credits':100,
                         'usage':{'isQuotaExceeded':False}}}
        out=Path(self.temp.name)/'monitor';out.mkdir()
        monitor=SpendingMonitor({'harness':{'approved_run_limit_cny':0.5}},out,probe=snapshot)
        monitor.before('harness',0)
        with self.assertRaisesRegex(ValueError,'reserved_budget'):
            monitor.before('harness',1)

    def test_final_checkpoint_same_ordinal_is_not_overwritten(self):
        def snapshot():
            return {'harness':{'credential_file_unchanged':True,
                'normal_wallets':[{'currency':'CNY','balance':'10'}],'bonus_wallets':[]},
                'qoder':{'status':'ready','quota_remaining_credits':100,'usage':{}}}
        out=Path(self.temp.name)/'accounting';out.mkdir()
        monitor=SpendingMonitor({'harness':{'approved_run_limit_cny':5}},out,probe=snapshot)
        monitor.before('qoder',4)
        self.assertEqual(monitor.close(4)['status'],'account_snapshot_complete')


if __name__=='__main__':unittest.main()
