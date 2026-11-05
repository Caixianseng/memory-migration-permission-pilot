from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from .read_receiver import ReceiverReadError, canonical, digest, export_batch, read_batch


def fixture(path, *, empty=False, recipient='AgentB', db_agent='AgentB'):
    """Independent persisted format fixture; no sender process/object is retained."""
    con = sqlite3.connect(path)
    con.executescript('''
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE memories(memory_key TEXT PRIMARY KEY,memory_id TEXT,version INTEGER,
            origin_agent TEXT,content TEXT,content_sha256 TEXT,kind TEXT,artifact_sha256 TEXT,provenance_json TEXT);
        CREATE TABLE memory_dependencies(memory_key TEXT,source_id TEXT,source_version INTEGER,source_sha256 TEXT,owner_id TEXT);
        CREATE TABLE batches(batch_id TEXT PRIMARY KEY,import_id TEXT UNIQUE,sender_id TEXT,
            recipient_id TEXT,epoch INTEGER,packet_sha256 TEXT,import_event_hash TEXT,imported_at TEXT);
        CREATE TABLE batch_memories(batch_id TEXT,position INTEGER,memory_key TEXT,PRIMARY KEY(batch_id,position));
        CREATE TABLE events(seq INTEGER PRIMARY KEY,kind TEXT,previous TEXT,payload_json TEXT,event_hash TEXT);
        CREATE TABLE originals(source_id TEXT,body TEXT);
    ''')
    con.executemany('INSERT INTO metadata VALUES (?,?)', [('agent_id',db_agent),('schema_version','persistent-exchange-v1')])
    con.execute('INSERT INTO originals VALUES (?,?)',('never-read','FORBIDDEN_ORIGINAL_CANARY_5163'))
    content = '北辰项目计划于2027年2月18日完成。'
    source = {'source_id':'A-source-1','version':1,'sha256':digest(b'original A raw body'),'owner_id':'AgentA'}
    bindings = {}
    keys = [] if empty else ['memory-key-1']
    if not empty:
        content_sha = digest(content.encode('utf-8'))
        artifact_sha = digest({'fixture_artifact':'one'})
        con.execute('INSERT INTO memories VALUES (?,?,?,?,?,?,?,?,?)',
                    ('memory-key-1','M1',1,'AgentA',content,content_sha,'derived',artifact_sha,'{}'))
        con.execute('INSERT INTO memory_dependencies VALUES (?,?,?,?,?)',
                    ('memory-key-1',source['source_id'],1,source['sha256'],'AgentA'))
        con.execute('INSERT INTO batch_memories VALUES (?,?,?)',('batch-1',0,'memory-key-1'))
        bindings['memory-key-1'] = {'origin_agent':'AgentA','memory_id':'M1','version':1,'kind':'derived',
            'content_sha256':content_sha,'artifact_sha256':artifact_sha,'dependencies_sha256':digest([source])}
    # A different batch contains data that must never appear in this read.
    other = 'OTHER_BATCH_CANARY_9284'
    con.execute('INSERT INTO memories VALUES (?,?,?,?,?,?,?,?,?)',
                ('other-key','M2',1,'AgentA',other,digest(other.encode()),'derived',digest(b'other-artifact'),'{}'))
    con.execute('INSERT INTO batch_memories VALUES (?,?,?)',('batch-other',0,'other-key'))
    event_payload = {'batch_id':'batch-1','import_id':'import-1','sender_id':'AgentA',
        'recipient_id':recipient,'epoch':3,'packet_sha256':digest(b'transport packet'),
        'memory_keys':keys,'artifact_bindings':bindings}
    event = {'seq':1,'kind':'import_committed','previous':'0'*64,'payload':event_payload}
    event_hash = digest(event)
    con.execute('INSERT INTO events VALUES (?,?,?,?,?)',
                (1,'import_committed','0'*64,canonical(event_payload).decode(),event_hash))
    con.execute('INSERT INTO batches VALUES (?,?,?,?,?,?,?,?)',
                ('batch-1','import-1','AgentA',recipient,3,event_payload['packet_sha256'],event_hash,'2026-11-05T00:00:00Z'))
    con.commit()
    con.close()
    return content


class ReceiverReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root/'receiver.sqlite'
        self.content = fixture(self.database)

    def tearDown(self):
        self.tmp.cleanup()

    def mutate(self, sql, parameters=()):
        con = sqlite3.connect(self.database)
        try:
            con.execute(sql, parameters)
            con.commit()
        finally:
            con.close()

    def test_restart_reads_actual_persisted_receiver_only(self):
        before = self.database.read_bytes()
        first = read_batch(self.database,'batch-1')
        second = read_batch(self.database,'batch-1')
        self.assertEqual(first['payload'],second['payload'])
        self.assertIn(self.content,first['payload']['memory'])
        self.assertNotIn('FORBIDDEN_ORIGINAL_CANARY',json.dumps(first,ensure_ascii=False))
        self.assertNotIn('OTHER_BATCH_CANARY',json.dumps(first,ensure_ascii=False))
        self.assertEqual(before,self.database.read_bytes())
        self.assertEqual(first['receipt']['sqlite_uri_mode'],'ro')
        self.assertTrue(first['receipt']['import_event_binding_verified'])
        self.assertEqual(first['receipt']['records'][0]['dependencies'][0]['source_id'],'A-source-1')

    def test_empty_import_is_real_persisted_empty_batch(self):
        empty = self.root/'empty.sqlite'
        fixture(empty,empty=True)
        result = read_batch(empty,'batch-1')
        self.assertEqual(result['payload']['memory'],'')
        self.assertEqual(result['receipt']['records'],[])
        self.assertEqual(result['receipt']['memory_count'],0)

    def test_sender_store_or_wrong_recipient_rejected(self):
        self.mutate("UPDATE metadata SET value='AgentA' WHERE key='agent_id'")
        with self.assertRaisesRegex(ReceiverReadError,'bound_to_receiver'):
            read_batch(self.database,'batch-1')

    def test_unknown_batch_and_injection_are_not_queries(self):
        for batch in ('missing', "batch-1' OR 1=1 --"):
            with self.assertRaisesRegex(ReceiverReadError,'not_in_this_receiver'):
                read_batch(self.database,batch)

    def test_content_tampering_is_blocked(self):
        self.mutate("UPDATE memories SET content='changed' WHERE memory_key='memory-key-1'")
        with self.assertRaisesRegex(ReceiverReadError,'content_hash_mismatch'):
            read_batch(self.database,'batch-1')

    def test_dependency_tampering_is_bound_to_committed_import(self):
        self.mutate("UPDATE memory_dependencies SET source_id='forged'")
        with self.assertRaisesRegex(ReceiverReadError,'artifact_binding_mismatch'):
            read_batch(self.database,'batch-1')

    def test_memory_identity_tampering_is_bound(self):
        self.mutate("UPDATE memories SET memory_id='forged display label' WHERE memory_key='memory-key-1'")
        with self.assertRaisesRegex(ReceiverReadError,'artifact_identity_mismatch'):
            read_batch(self.database,'batch-1')

    def test_import_commit_event_tampering_is_blocked(self):
        self.mutate("UPDATE events SET previous=?",('f'*64,))
        with self.assertRaisesRegex(ReceiverReadError,'event_hash_mismatch'):
            read_batch(self.database,'batch-1')

    def test_cli_subprocess_exports_same_payload_with_sql_receipt(self):
        output = self.root/'retrieved_memory.json'
        script = Path(__file__).with_name('read_receiver.py')
        completed = subprocess.run([sys.executable,'-B',str(script),'--receiver-db',str(self.database),
            '--batch-id','batch-1','--output',str(output)],capture_output=True,text=True,check=True)
        result = json.loads(completed.stdout)
        payload = json.loads(output.read_bytes())
        receipt_path = Path(result['receipt_path'])
        receipt = json.loads(receipt_path.read_bytes())
        self.assertEqual(payload,read_batch(self.database,'batch-1')['payload'])
        self.assertEqual(receipt['payload_file_sha256'],hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(receipt['queries']['memories']['parameters'],['batch-1'])
        self.assertIn('WHERE bm.batch_id=?',receipt['queries']['memories']['sql'])
        self.assertNotIn('originals',receipt['queries']['memories']['sql'])

    def test_export_never_overwrites_existing_payload(self):
        target = self.root/'retrieved_memory.json'
        target.write_bytes(b'user owned existing file')
        with self.assertRaisesRegex(ReceiverReadError,'fresh_readback_output_required'):
            export_batch(self.database,'batch-1',target)
        self.assertEqual(target.read_bytes(),b'user owned existing file')

    def test_unknown_schema_fails_closed_without_modification(self):
        self.mutate("UPDATE metadata SET value='unknown' WHERE key='schema_version'")
        before = self.database.read_bytes()
        with self.assertRaisesRegex(ReceiverReadError,'schema_mismatch'):
            read_batch(self.database,'batch-1')
        self.assertEqual(before,self.database.read_bytes())

    def test_output_cannot_create_sqlite_sidecar(self):
        with self.assertRaisesRegex(ReceiverReadError,'database_storage'):
            export_batch(self.database,'batch-1',Path(str(self.database)+'-wal'))
        self.assertFalse(Path(str(self.database)+'-wal').exists())

    def test_real_store_import_then_sender_unavailable_cli_readback(self):
        from .store import AgentStore, TrustedPolicy, export_package, import_package
        sender_path = self.root/'actual-sender.sqlite'
        receiver_path = self.root/'actual-receiver.sqlite'
        policy_path = self.root/'actual-policy.sqlite'
        sender = AgentStore(sender_path,'Source-A')
        receiver = AgentStore(receiver_path,'Receiver-B')
        policy = TrustedPolicy(policy_path)
        try:
            source = sender.add_original('origin-A','RAW_SENDER_ONLY_CANARY_3815')
            policy.register_sources([source])
            policy.set_permissions('Receiver-B',['origin-A'])
            memory = sender.add_memory('derived-1','A persistent imported memory.',source_ids=['origin-A'],
                                       provenance={'model':'hy3'})
            packet = export_package(sender,policy,'Receiver-B',[memory['memory_key']],batch_id='actual-batch')
            imported = import_package(receiver,policy,packet)
        finally:
            sender.close()
            receiver.close()
            policy.close()
        # No sender or policy remains at the path recorded during transfer.
        for path in (sender_path,policy_path):
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()))
            path.unlink()
        output = self.root/'actual-retrieved.json'
        completed = subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('read_receiver.py')),
            '--receiver-db',str(receiver_path),'--batch-id','actual-batch','--output',str(output)],
            capture_output=True,text=True,check=True)
        actual = json.loads(output.read_bytes())
        receipt = json.loads(Path(json.loads(completed.stdout)['receipt_path']).read_bytes())
        self.assertEqual(actual['memory'],'A persistent imported memory.')
        self.assertNotIn('RAW_SENDER_ONLY_CANARY',json.dumps(actual))
        self.assertEqual(receipt['packet_sha256'],imported['packet_sha256'])
        self.assertEqual(receipt['import_event_hash'],imported['import_event_hash'])
        self.assertEqual(receipt['records'][0]['memory_key'],memory['memory_key'])


if __name__ == '__main__':
    unittest.main()
