"""Integration contract controls without clients, networks or check answers."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.journal_methods_20261030.controlled_host import ControlledHost
from experiments.journal_methods_20261030.reference_contract import policy_for, requests_for
from experiments.journal_methods_20261030.policy_semantics_reference import evaluate
from experiments.journal_methods_20261030.run_paired_acceptance import (
    HERE, METHODS, prepare_method, request, restoration_probe, context_request,
)


class JournalAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = json.loads((HERE/'data/dev_cases.json').read_text(encoding='utf-8'))['cases'][0]
        self.host = ControlledHost(self.case, Path(self.temp.name)/'host')

    def test_registered_requests_have_no_reference_unjustified_allow(self):
        for fact in self.case['facts']:
            for q in requests_for(self.case, fact):
                observed = self.host.execute(q)
                reference = evaluate(policy_for(self.case, fact), q, {'source_binding': True})
                if observed['decision'] == 'allow':
                    self.assertTrue(reference['deliver'], q)

    def test_read_does_not_supply_export_permission(self):
        self.case['facts'][0]['export_allowed'] = False
        host = ControlledHost(self.case, Path(self.temp.name)/'noexport')
        self.assertEqual(host.execute(request(self.case,self.case['facts'][0],'read'))['decision'], 'allow')
        self.assertEqual(host.execute(request(self.case,self.case['facts'][0]))['code'], 'export_not_allowed')

    def test_distinct_restore_requirement_exposes_existing_contract_limit(self):
        fid = self.case['facts'][2]['fact_id']
        self.host.rows[fid]['restore_allowed'] = False
        result = restoration_probe(self.host, fid, 'separate-restore')
        self.assertEqual(result['raw_current_endpoint']['status'], 'ok')
        self.assertEqual(result['opt_in_gate']['error'], 'explicit_restore_not_allowed')

    def test_bounded_literal_probe_omits_sentence_terminator(self):
        fid = self.case['facts'][0]['fact_id']
        result = restoration_probe(self.host, fid, 'bounded-literal')
        self.assertEqual(result['raw_current_endpoint']['status'], 'ok')
        self.assertFalse(result['input_answer'].endswith('。'))

    def test_unknown_field_is_preserved_not_business_deny(self):
        q = request(self.case,self.case['facts'][0])
        q.pop('policy_version')
        self.assertEqual(self.host.execute(q)['decision'], 'unknown')
        self.assertEqual(evaluate(policy_for(self.case,self.case['facts'][0]),q)['decision'], 'Indeterminate')

    def test_wrong_model_destination_is_denied(self):
        q = dict(request(self.case,self.case['facts'][0]),model_recipient='other-provider')
        self.assertEqual(self.host.execute(q)['decision'], 'deny')

    def test_source_text_does_not_mint_privilege(self):
        q = dict(request(self.case,self.case['facts'][0]),user_id='bob')
        self.assertEqual(self.host.execute(q)['decision'], 'deny')

    def test_same_detector_inputs_fragment_and_existing_isolation_agree(self):
        self.host.rows[self.case['facts'][0]['fact_id']]['detection_status'] = 'needs_review'
        selected = list(self.host.rows)
        for mode in ('per_fragment','existing_selective'):
            p, kept = prepare_method(self.host,mode,selected,'Return one fact.',mode)
            self.assertEqual(p['status'],'ok')
            self.assertNotIn(selected[0],kept)
            self.assertEqual(len(kept),3)
        p, kept = prepare_method(self.host,'current_default',selected,'Return one fact.','default')
        self.assertNotEqual(p['status'],'ok')
        self.assertEqual(kept,[])

    def test_unknown_independence_blocks_fragment_quarantine(self):
        self.host.case['trusted_independent_facts'] = False
        self.host.rows[self.case['facts'][0]['fact_id']]['detection_status'] = 'needs_review'
        for mode in ('per_fragment','existing_selective'):
            p, kept = prepare_method(self.host,mode,list(self.host.rows),'Return one fact.',mode)
            self.assertNotEqual(p['status'],'ok')
            self.assertEqual(kept,[])

    def test_revoked_source_blocks_real_read_and_old_packet(self):
        fact = self.case['facts'][0]
        packet = self.host.export([fact['fact_id']],'old')
        self.host.revoke(fact['fact_id'])
        self.assertEqual(self.host.read(fact['fact_id'])['decision'],'deny')
        with self.assertRaisesRegex(ValueError,'record_revoked'):
            self.host.broker.validate(packet,sender_actor_id='sender',actor_id='receiver')

    def test_scenario_missing_version_is_not_filled(self):
        self.case['request_context'].pop('policy_version',None)
        self.assertNotIn('policy_version',context_request(self.case,self.case['facts'][0]))

    def test_methods_run_without_network_and_maps_not_serialized(self):
        with patch('socket.socket',side_effect=AssertionError('network_forbidden')):
            for method in METHODS:
                p,_ = prepare_method(self.host,method,list(self.host.rows),'Return one fact.',method)
                self.assertEqual(p['status'],'ok')
                with self.assertRaises(TypeError):
                    json.dumps(p['mapping'])


if __name__ == '__main__':
    unittest.main()
