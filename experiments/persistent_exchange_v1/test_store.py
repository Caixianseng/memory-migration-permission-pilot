from copy import deepcopy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from .store import AgentStore,TrustedPolicy,StoreError,export_package,import_package,digest,verify_events


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.a=AgentStore(self.root/'A.sqlite','A')
        self.b=AgentStore(self.root/'B.sqlite','B')
        self.policy=TrustedPolicy(self.root/'policy.sqlite')
        self.sources=[self.a.add_original('A-name','Project North Star.'),
                      self.a.add_original('A-budget','Budget 731800.'),
                      self.a.add_original('A-date','Deadline 2027-02-18.')]
        self.policy.register_sources(self.sources)
        self.policy.set_permissions('B',[r['source_id']for r in self.sources])
        self.policy.set_permissions('A',[r['source_id']for r in self.sources])

    def tearDown(self):
        for store in (self.a,self.b,self.policy):
            try:store.close()
            except sqlite3.ProgrammingError:pass
        self.tmp.cleanup()

    def memory(self,mid='all',text='North Star, 731800, 2027-02-18.',ids=None):
        return self.a.add_memory(mid,text,source_ids=ids or [r['source_id']for r in self.sources],provenance={'actual_model':'hy3'})

    def test_disk_import_survives_reopen_and_receiver_has_no_hidden_originals(self):
        memory=self.memory()
        packet=export_package(self.a,self.policy,'B',[memory['memory_key']],batch_id='first')
        receipt=import_package(self.b,self.policy,packet)
        self.a.close()  # Query cannot depend on a live sender object/connection.
        self.b.close();self.b=AgentStore(self.root/'B.sqlite','B')
        result=self.b.retrieve('first')
        self.assertIn('North Star',result['memory'])
        self.assertEqual(result['source_ids'],['A-budget','A-date','A-name'])
        self.assertEqual(result['query_receipt']['import_event_hash'],receipt['import_event_hash'])
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM originals').fetchone()[0],0)
        db=sqlite3.connect(self.b.readonly_uri,uri=True)
        with self.assertRaises(sqlite3.OperationalError):db.execute("DELETE FROM batches")
        db.close()

    def test_revoked_mixed_memory_denied_without_deleting_words(self):
        memory=self.memory()
        self.policy.set_permissions('B',['A-name','A-date'])
        with self.assertRaisesRegex(StoreError,'not_currently_authorized'):
            export_package(self.a,self.policy,'B',[memory['memory_key']])
        self.assertIn('731800',self.a.get_memory(memory['memory_key'])['content'])
        rebuilt=self.memory('safe','North Star, deadline 2027-02-18.',ids=['A-name','A-date'])
        packet=export_package(self.a,self.policy,'B',[rebuilt['memory_key']],batch_id='safe')
        import_package(self.b,self.policy,packet)
        self.assertNotIn('731800',self.b.retrieve('safe')['memory'])

    def test_revoke_after_export_before_commit_fails_closed_no_partial_import(self):
        packet=export_package(self.a,self.policy,'B',[self.memory()['memory_key']],batch_id='race')
        with self.assertRaisesRegex(StoreError,'stale_policy_epoch'):
            import_package(self.b,self.policy,packet,before_commit=lambda:self.policy.set_permissions('B',['A-name','A-date']))
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0],0)
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM memories').fetchone()[0],0)
        self.assertIsNone(self.policy.db.execute('SELECT consumed_by FROM seals WHERE import_id=?',(packet['import_id'],)).fetchone()[0])

    def test_packet_tampering_rehashed_by_attacker_still_fails_trusted_seal(self):
        packet=export_package(self.a,self.policy,'B',[self.memory()['memory_key']])
        forged=deepcopy(packet);forged['batch_id']='attacker-chosen'
        forged['content_sha256']=digest({k:v for k,v in forged.items()if k!='content_sha256'})
        with self.assertRaisesRegex(StoreError,'trusted_seal_metadata_mismatch'):
            import_package(self.b,self.policy,forged)
        forged=deepcopy(packet);artifact=forged['memories'][0];artifact['content']='Attacker text'
        artifact['content_sha256']=digest(artifact['content'].encode())
        artifact['artifact_sha256']=digest({k:v for k,v in artifact.items()if k!='artifact_sha256'})
        forged['lineage'][0].update(content_sha256=artifact['content_sha256'],artifact_sha256=artifact['artifact_sha256'])
        forged['content_sha256']=digest({k:v for k,v in forged.items()if k!='content_sha256'})
        with self.assertRaisesRegex(StoreError,'trusted_packet_seal_mismatch'):
            import_package(self.b,self.policy,forged)
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0],0)

    def test_replay_global_consumption_and_recipient_binding(self):
        packet=export_package(self.a,self.policy,'B',[self.memory()['memory_key']],batch_id='first')
        with self.assertRaisesRegex(StoreError,'recipient'):
            import_package(self.a,self.policy,packet)
        import_package(self.b,self.policy,packet)
        with self.assertRaisesRegex(StoreError,'replay'):
            import_package(self.b,self.policy,packet)
        other=AgentStore(self.root/'B-copy.sqlite','B')
        try:
            with self.assertRaisesRegex(StoreError,'replay'):
                import_package(other,self.policy,packet)
            self.assertEqual(other.db.execute('SELECT COUNT(*) FROM memories').fetchone()[0],0)
        finally:other.close()

    def test_multilevel_memory_flattens_original_dependencies_and_hides_parent_body(self):
        parent=self.memory('parent','Budget and date original summary.')
        import_package(self.b,self.policy,export_package(self.a,self.policy,'B',[parent['memory_key']],batch_id='incoming'))
        source_b=self.b.add_original('B-contact','Contact qb4927@example.invalid.')
        self.policy.register_sources([source_b]);self.policy.set_permissions('A',[r['source_id']for r in self.sources]+['B-contact'])
        child=self.b.add_memory('child','A joint decision based on project and contact.',source_ids=['B-contact'],parent_memory_ids=[parent['memory_key']],provenance={'actual_model':'deepseek-flash'})
        self.assertEqual({r['source_id']for r in child['dependencies']},{'A-name','A-budget','A-date','B-contact'})
        packet=export_package(self.b,self.policy,'A',[child['memory_key']],batch_id='return')
        self.assertEqual(len(packet['lineage']),2)
        self.assertNotIn('content',next(n for n in packet['lineage']if n['memory_key']==parent['memory_key']))
        import_package(self.a,self.policy,packet)
        result=self.a.retrieve('return')
        self.assertIn('joint decision',result['memory']);self.assertNotIn('Budget and date original summary.',result['memory'])
        self.policy.set_permissions('A',['A-name','A-date','B-contact'])
        with self.assertRaisesRegex(StoreError,'not_currently_authorized'):
            export_package(self.b,self.policy,'A',[child['memory_key']])

    def test_changed_source_version_invalidates_old_memory_and_export(self):
        old=self.memory()
        newer=self.a.add_original('A-date','Deadline 2028-01-01.',version=2)
        self.policy.register_sources([newer])
        with self.assertRaisesRegex(StoreError,'source_version_or_hash'):
            export_package(self.a,self.policy,'B',[old['memory_key']])
        self.assertEqual(len([r for r in self.a.originals()if r['source_id']=='A-date']),2)
        with self.assertRaisesRegex(StoreError,'immutable_original_changed'):
            self.a.add_original('A-date','Other contents',version=2)

    def test_immutable_artifacts_and_original_raw_copies(self):
        original=self.memory('same','Text one.')
        with self.assertRaisesRegex(StoreError,'immutable_memory_artifact_changed'):
            self.memory('same','Text two.')
        v2=self.a.add_memory('same','Text two.',source_ids=['A-name'],version=2)
        self.assertNotEqual(v2['memory_key'],original['memory_key'])
        with self.assertRaisesRegex(StoreError,'raw_memory_must_be_exact_original'):
            self.a.add_memory('raw','not original',source_ids=['A-name'],kind='raw')
        raw=self.a.add_memory('raw','Project North Star.',source_ids=['A-name'],kind='raw')
        self.assertEqual(raw['dependencies'][0]['source_id'],'A-name')

    def test_empty_blocked_package_is_persisted_without_any_memory_or_origin_body(self):
        self.policy.set_permissions('B',[])
        packet=export_package(self.a,self.policy,'B',[],batch_id='empty')
        import_package(self.b,self.policy,packet)
        result=self.b.retrieve('empty')
        self.assertEqual(result['memory'],'');self.assertEqual(result['memories'],[])
        self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM memories').fetchone()[0],0)
        self.assertEqual(verify_events(self.b.db)['events'],2)

    def test_later_insert_conflict_rolls_back_prior_memory_and_seal(self):
        existing=self.memory('same','First version text.')
        import_package(self.b,self.policy,export_package(self.a,self.policy,'B',[existing['memory_key']],batch_id='first'))
        alternate=AgentStore(self.root/'A-alternate.sqlite','A')
        try:
            for r in self.sources:alternate.add_original(r['source_id'],r['text'])
            fresh=alternate.add_memory('fresh','Fresh record.',source_ids=['A-name'])
            changed=alternate.add_memory('same','Different text same immutable identity.',source_ids=['A-name','A-budget','A-date'])
            packet=export_package(alternate,self.policy,'B',[fresh['memory_key'],changed['memory_key']],batch_id='partial')
            with self.assertRaises(StoreError):import_package(self.b,self.policy,packet)
            self.assertIsNone(self.b.db.execute('SELECT 1 FROM memories WHERE memory_key=?',(fresh['memory_key'],)).fetchone())
            self.assertEqual(self.b.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0],1)
            self.assertIsNone(self.policy.db.execute('SELECT consumed_by FROM seals WHERE import_id=?',(packet['import_id'],)).fetchone()[0])
        finally:alternate.close()

    def test_tampered_receiver_body_or_dependencies_detected_after_import(self):
        artifact=self.memory()
        import_package(self.b,self.policy,export_package(self.a,self.policy,'B',[artifact['memory_key']],batch_id='test'))
        self.b.db.execute("UPDATE memory_dependencies SET source_sha256=? WHERE source_id='A-name'",('f'*64,))
        with self.assertRaisesRegex(StoreError,'stored_artifact_import_binding_changed'):
            self.b.retrieve('test')

    def test_store_identity_and_same_db_authority_rejected(self):
        with self.assertRaisesRegex(StoreError,'store_owner_or_schema'):
            AgentStore(self.root/'A.sqlite','WrongAgent')

    def test_source_provenance_cannot_smuggle_raw_input_into_export(self):
        artifact=self.a.add_memory('compact','Only selected summary.',source_ids=['A-name'],
            provenance={'model':'hy3','messages':[{'content':'NOT-RECEIVER-INPUT-731800'}],
                        'job_dir':'D:/a/private/directory','input':'FORBIDDEN-METADATA-TEXT'})
        packet=export_package(self.a,self.policy,'B',[artifact['memory_key']],batch_id='compact')
        from .store import canonical
        self.assertNotIn(b'NOT-RECEIVER-INPUT',canonical(packet))
        self.assertNotIn(b'FORBIDDEN-METADATA-TEXT',canonical(packet))
        self.assertNotIn(b'private/directory',canonical(packet))
        import_package(self.b,self.policy,packet)
        self.assertEqual(self.b.get_memory(artifact['memory_key'])['provenance']['model'],'hy3')

    def test_use_time_dependency_check_is_read_only_and_observes_new_policy(self):
        artifact=self.memory();epoch=self.policy.epoch
        count=self.policy.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        self.assertEqual(self.policy.check_dependencies('B',artifact['dependencies'],epoch),epoch)
        self.assertEqual(self.policy.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],count)
        self.policy.set_permissions('B',['A-name','A-date'])
        with self.assertRaisesRegex(StoreError,'stale_policy_epoch'):
            self.policy.check_dependencies('B',artifact['dependencies'],epoch)
        with self.assertRaisesRegex(StoreError,'not_currently_authorized'):
            self.policy.check_dependencies('B',artifact['dependencies'])


if __name__=='__main__':unittest.main()
