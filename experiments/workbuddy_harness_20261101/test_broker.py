"""Targeted offline checks for explicit WorkBuddy identity and replay grants."""
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from .broker import build_handoff


class WorkBuddyBrokerTests(unittest.TestCase):
    def setUp(self):
        self.sources=[{'source_id':f'S{i:02d}','text':f'Authored public source {i}.'} for i in range(1,5)]
        self.mixed='Mixed statement with S01 and current sources.'
        self.rebuilt='Rebuilt text from S02, S03, S04 only.'

    def build(self):
        with patch('subprocess.Popen',side_effect=AssertionError('NO_MODEL_PROCESS')):
            return build_handoff(self.sources,self.mixed,self.rebuilt)

    def test_workbuddy_sender_and_harness_receiver_are_explicit(self):
        result=self.build()
        self.assertEqual(result['sender'],{'user_id':'alice','agent_id':'workbuddy','workspace_id':'source'})
        self.assertEqual(result['audience'],{'user_id':'alice','agent_id':'deepseek-harness','workspace_id':'target'})
        self.assertNotIn('qoder',json.dumps(result))
        self.assertEqual(result['validation']['status'],'ok')

    def test_old_mixed_denied_but_read_and_other_fields_preserved(self):
        result=self.build()
        self.assertEqual(result['revocation_errors'],{'old_mixed_packet_validate':'export_not_allowed','new_mixed_export':'export_not_allowed'})
        self.assertFalse(result['state_after']['S01']['export_allowed'])
        self.assertFalse(result['state_after']['M']['export_allowed'])
        self.assertTrue(result['state_after']['R']['export_allowed'])
        for rid,before in result['state_before'].items():
            for key in ('text_sha256','source_read','recipient_read','copy_allowed'):
                self.assertEqual(before[key],result['state_after'][rid][key])
        self.assertEqual(result['state_after']['S01']['source_read'],'allow')
        self.assertEqual([x['record_id'] for x in result['legal_source_packet']['items']],['S02','S03','S04'])

    def test_rebuilt_text_is_exact_in_packet_and_rendered_memory(self):
        result=self.build()
        self.assertEqual(result['packet']['items'][0]['text'],self.rebuilt)
        self.assertIn(self.rebuilt,result['memory'])
        self.assertNotIn(self.mixed,result['memory'])
        self.assertEqual(result['memory_sha256'],hashlib.sha256(result['memory'].encode()).hexdigest())
        self.assertFalse(result['generation_event_timing_proven'])
        self.assertIn('caller precondition',result['trace_authentication_scope'])

    def test_missing_duplicate_reordered_and_extra_source_fields_rejected(self):
        variants=[self.sources[:-1],list(reversed(self.sources)),deepcopy(self.sources),deepcopy(self.sources)]
        variants[2][1]['source_id']='S01';variants[3][0]['model_permission']='allow'
        for sources in variants:
            with self.subTest(sources=sources):
                with self.assertRaises(ValueError):
                    build_handoff(sources,self.mixed,self.rebuilt)


if __name__=='__main__':unittest.main()
