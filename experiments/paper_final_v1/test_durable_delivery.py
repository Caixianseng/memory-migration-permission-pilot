"""Safety-relevant tests for the new acknowledgement adapter only."""
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from experiments.persistent_exchange_v1 import store
from experiments.paper_final_v1 import durable_delivery
from experiments.paper_final_v1.runner import fixture, permission, raw_effect_count


class ConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name);self.packet=fixture(self.path)

    def tearDown(self):self.tmp.cleanup()

    def deliver(self,packet=None):
        b=store.AgentStore(self.path/'B.sqlite','B');p=store.TrustedPolicy(self.path/'policy.sqlite')
        try:return durable_delivery.deliver(b,p,packet or self.packet)
        finally:b.close();p.close()

    def test_new_acceptance_and_confirmation_have_distinct_metadata_semantics(self):
        first=self.deliver();second=self.deliver()
        self.assertTrue(first['new_persistent_acceptance'])
        self.assertFalse(second['new_persistent_acceptance'])
        self.assertFalse(first['ack_contains_plaintext']);self.assertFalse(second['ack_contains_plaintext'])
        self.assertNotIn('Derived controlled value-0',json.dumps([first,second]))
        self.assertEqual(raw_effect_count(self.path,'complete_host'),1)

    def test_committed_confirmation_survives_revocation_but_new_packet_does_not(self):
        a=store.AgentStore(self.path/'A.sqlite','A');p=store.TrustedPolicy(self.path/'policy.sqlite')
        try:other=store.export_package(a,p,'B',['M000'],batch_id='never-committed')
        finally:a.close();p.close()
        self.deliver();permission(self.path,[])
        self.assertEqual(self.deliver()['status'],'already_committed')
        with self.assertRaises(store.StoreError):self.deliver(other)
        self.assertEqual(raw_effect_count(self.path,'complete_host'),1)

    def test_same_batch_is_not_sufficient_for_confirmation(self):
        self.deliver()
        a=store.AgentStore(self.path/'A.sqlite','A');p=store.TrustedPolicy(self.path/'policy.sqlite')
        try:other=store.export_package(a,p,'B',['M000'],batch_id=self.packet['batch_id'])
        finally:a.close();p.close()
        with self.assertRaises(store.StoreError):self.deliver(other)
        self.assertEqual(raw_effect_count(self.path,'complete_host'),1)

    def test_self_consistent_changed_packet_cannot_claim_old_receipt(self):
        self.deliver();changed=json.loads(json.dumps(self.packet));changed['nonce']='replacement-nonce'
        changed['content_sha256']=store.digest({k:v for k,v in changed.items()if k!='content_sha256'})
        with self.assertRaises(store.StoreError):self.deliver(changed)

    def test_changed_committed_body_is_detected_before_confirmation(self):
        self.deliver();db=sqlite3.connect(self.path/'B.sqlite')
        try:db.execute("UPDATE memories SET content='corrupted controlled body'");db.commit()
        finally:db.close()
        with self.assertRaises(store.StoreError):self.deliver()

    def test_changed_audit_chain_is_detected_before_confirmation(self):
        self.deliver();db=sqlite3.connect(self.path/'B.sqlite')
        try:db.execute("UPDATE events SET previous='bad-chain' WHERE seq=1");db.commit()
        finally:db.close()
        with self.assertRaises(store.StoreError):self.deliver()

    def test_receiver_identity_cannot_be_rebound(self):
        self.deliver();a=store.AgentStore(self.path/'A.sqlite','A')
        try:
            with self.assertRaises(store.StoreError):durable_delivery.committed_receipt(a,self.packet)
        finally:a.close()

    def test_concurrent_same_packet_has_one_durable_effect_and_two_receipts(self):
        barrier=threading.Barrier(2,timeout=10);answers=[];errors=[]
        def worker():
            try:barrier.wait();answers.append(self.deliver())
            except BaseException as exc:errors.append(repr(exc))
        threads=[threading.Thread(target=worker)for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(15)
        self.assertFalse(any(t.is_alive()for t in threads))
        self.assertFalse(errors);self.assertEqual(len(answers),2)
        self.assertEqual(sum(r['new_persistent_acceptance']for r in answers),1)
        self.assertEqual(raw_effect_count(self.path,'complete_host'),1)


if __name__=='__main__':unittest.main()
