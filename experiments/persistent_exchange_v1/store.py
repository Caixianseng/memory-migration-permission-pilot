"""Disk-backed agent memory and single-host transactional first-delivery gate.

Each agent owns a separate SQLite file. A trusted policy file seals exports and
is ATTACHed during receiver import, so authorization and receipt consumption
commit with the receiver batch. DELETE journals are required. This is a local
trusted-host experiment, not distributed atomicity, a signature from a model,
or erasure of plaintext already delivered. Lineage metadata carries no hidden
ancestor plaintext; receiver queries use its own imported batch only.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
from datetime import datetime, timezone

SCHEMA = 'persistent-exchange-v1'


class StoreError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _need(test, code):
    if not test:
        raise StoreError(code)


def _identifier(value, label):
    _need(isinstance(value, str) and bool(value.strip()) and len(value) <= 2048, 'invalid_'+label)
    return value


def _version(value):
    _need(type(value) is int and value > 0, 'positive_integer_version_required')
    return value


def _sha(value):
    _need(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None, 'invalid_sha256')
    return value


def _json(value):
    return canonical(value).decode('utf-8')


def _connect(path):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, isolation_level=None, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        mode = db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]
        _need(mode == 'delete', 'delete_journal_required_for_attached_commit')
        db.execute('PRAGMA synchronous=FULL')
    except BaseException:
        db.close(); raise
    return path, db


def _events_schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, previous TEXT NOT NULL, payload_json TEXT NOT NULL, event_hash TEXT UNIQUE NOT NULL)')


def _append_event(db, kind, payload):
    previous = db.execute('SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
    seq, old_hash = (previous['seq']+1, previous['event_hash']) if previous else (1, '0'*64)
    event = {'seq': seq, 'kind': kind, 'previous': old_hash, 'payload': payload}
    event_hash = digest(event)
    db.execute('INSERT INTO events VALUES(?,?,?,?,?)', (seq, kind, old_hash, _json(payload), event_hash))
    return {**event, 'event_hash': event_hash}


def verify_events(db):
    """Read-only chain verification, usable by the external receiver CLI."""
    previous, seq = '0'*64, 0
    for row in db.execute('SELECT seq,kind,previous,payload_json,event_hash FROM events ORDER BY seq'):
        r = dict(row) if isinstance(row, sqlite3.Row) else dict(zip(('seq','kind','previous','payload_json','event_hash'), row))
        seq += 1
        _need(r['seq'] == seq and r['previous'] == previous, 'event_chain_order_or_parent_invalid')
        event = {'seq': r['seq'], 'kind': r['kind'], 'previous': r['previous'], 'payload': json.loads(r['payload_json'])}
        _need(digest(event) == r['event_hash'], 'event_chain_hash_invalid')
        previous = r['event_hash']
    return {'events': seq, 'head': previous}


def _source_ref(value):
    _need(isinstance(value, dict) and set(value) == {'source_id','version','sha256','owner_id'}, 'exact_source_binding_required')
    return {'source_id': _identifier(value['source_id'],'source_id'), 'version': _version(value['version']),
            'sha256': _sha(value['sha256']), 'owner_id': _identifier(value['owner_id'],'owner_id')}


def _merge_refs(refs):
    result = {}
    for value in refs:
        ref = _source_ref(value)
        sid = ref['source_id']
        _need(sid not in result or result[sid] == ref, 'mixed_versions_or_origins_for_same_source')
        result[sid] = ref
    return [result[sid] for sid in sorted(result)]


def _memory_key(agent, memory_id, version):
    return 'mem-'+digest({'origin_agent': agent, 'memory_id': memory_id, 'version': version})


def _compact_provenance(value):
    """Never place arbitrary input/messages/raw source text in export metadata."""
    result = {'provided_provenance_sha256': digest(value)}
    for key in ('generator','model','actual_model','task_id','attempt_id','session_id','job_id','evidence_hash'):
        item = value.get(key)
        if isinstance(item,str) and re.fullmatch(r'[A-Za-z0-9_.:/@-]{1,256}',item):
            result[key] = item
    return result


def _node(artifact):
    return {key: deepcopy(artifact[key]) for key in ('memory_key','memory_id','version','origin_agent','kind',
            'content_sha256','artifact_sha256','direct_sources','parents','dependencies')}


def _check_artifact(artifact):
    keys = {'memory_key','memory_id','version','origin_agent','content','content_sha256','kind','provenance',
            'direct_sources','parents','dependencies','artifact_sha256'}
    _need(isinstance(artifact, dict) and set(artifact) == keys, 'exact_artifact_schema_required')
    _identifier(artifact['memory_id'],'memory_id'); _identifier(artifact['origin_agent'],'origin_agent')
    _identifier(artifact['kind'],'kind'); _version(artifact['version'])
    _need(artifact['memory_key'] == _memory_key(artifact['origin_agent'],artifact['memory_id'],artifact['version']), 'memory_identity_binding_invalid')
    _need(isinstance(artifact['content'],str) and bool(artifact['content']), 'nonempty_memory_text_required')
    _need(isinstance(artifact['provenance'],dict), 'provenance_object_required')
    _need(isinstance(artifact['parents'],list) and len(set(artifact['parents'])) == len(artifact['parents'])
          and all(isinstance(p,str) for p in artifact['parents']), 'unique_parent_keys_required')
    _need(artifact['content_sha256'] == digest(artifact['content'].encode('utf-8')), 'memory_content_hash_invalid')
    _need(artifact['direct_sources'] == _merge_refs(artifact['direct_sources'])
          and artifact['dependencies'] == _merge_refs(artifact['dependencies']), 'canonical_source_bindings_required')
    _need(bool(artifact['dependencies']), 'memory_must_have_original_dependencies')
    _need(artifact['artifact_sha256'] == digest({k:v for k,v in artifact.items() if k != 'artifact_sha256'}), 'artifact_hash_invalid')


class AgentStore:
    def __init__(self, path, agent_id):
        self.agent_id = _identifier(agent_id,'agent_id')
        self.path, self.db = _connect(path)
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS originals(source_id TEXT,version INTEGER,text TEXT NOT NULL,sha256 TEXT NOT NULL,owner_id TEXT NOT NULL,metadata_json TEXT NOT NULL,PRIMARY KEY(source_id,version));
        CREATE TABLE IF NOT EXISTS origins(source_id TEXT,version INTEGER,sha256 TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(source_id,version));
        CREATE TABLE IF NOT EXISTS memories(memory_key TEXT PRIMARY KEY,memory_id TEXT NOT NULL,version INTEGER NOT NULL,origin_agent TEXT NOT NULL,content TEXT NOT NULL,content_sha256 TEXT NOT NULL,kind TEXT NOT NULL,provenance_json TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,UNIQUE(origin_agent,memory_id,version));
        CREATE TABLE IF NOT EXISTS memory_dependencies(memory_key TEXT REFERENCES memories(memory_key),source_id TEXT,source_version INTEGER,source_sha256 TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(memory_key,source_id));
        CREATE TABLE IF NOT EXISTS memory_direct_sources(memory_key TEXT REFERENCES memories(memory_key),source_id TEXT,source_version INTEGER,source_sha256 TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(memory_key,source_id));
        CREATE TABLE IF NOT EXISTS memory_parents(memory_key TEXT REFERENCES memories(memory_key),position INTEGER,parent_key TEXT NOT NULL,PRIMARY KEY(memory_key,position));
        CREATE TABLE IF NOT EXISTS lineage_metadata(memory_key TEXT PRIMARY KEY,node_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS batches(batch_id TEXT PRIMARY KEY,import_id TEXT UNIQUE NOT NULL,sender_id TEXT NOT NULL,recipient_id TEXT NOT NULL,epoch INTEGER NOT NULL,packet_sha256 TEXT NOT NULL,import_event_hash TEXT NOT NULL,imported_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS batch_memories(batch_id TEXT REFERENCES batches(batch_id),position INTEGER,memory_key TEXT REFERENCES memories(memory_key),PRIMARY KEY(batch_id,position),UNIQUE(batch_id,memory_key));
        ''')
        _events_schema(self.db)
        found = dict(self.db.execute('SELECT key,value FROM metadata'))
        if found:
            if found.get('schema_version') != SCHEMA or found.get('agent_id') != self.agent_id:
                self.db.close()
                raise StoreError('store_owner_or_schema_mismatch')
        else:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.executemany('INSERT INTO metadata VALUES(?,?)',[('schema_version',SCHEMA),('agent_id',self.agent_id)])
                _append_event(self.db,'store_created',{'agent_id':self.agent_id})
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK'); raise

    @property
    def readonly_uri(self):
        return self.path.as_uri()+'?mode=ro'

    def close(self):
        self.db.close()

    def add_original(self, source_id, text, version=1, metadata=None):
        _identifier(source_id,'source_id'); _version(version)
        _need(isinstance(text,str) and bool(text), 'nonempty_original_text_required')
        _need(metadata is None or isinstance(metadata,dict), 'source_metadata_object_required')
        ref = {'source_id':source_id,'version':version,'sha256':digest(text.encode('utf-8')),'owner_id':self.agent_id}
        previous = self.db.execute('SELECT * FROM originals WHERE source_id=? AND version=?',(source_id,version)).fetchone()
        if previous:
            _need(previous['text'] == text and previous['metadata_json'] == _json(metadata or {}) and previous['owner_id'] == self.agent_id, 'immutable_original_changed')
            return {**ref,'text':text}
        latest = self.db.execute('SELECT MAX(version) FROM originals WHERE source_id=?',(source_id,)).fetchone()[0]
        _need(latest is None or version > latest, 'source_versions_must_increase')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            _insert_origin(self.db,ref)
            self.db.execute('INSERT INTO originals VALUES(?,?,?,?,?,?)',(source_id,version,text,ref['sha256'],self.agent_id,_json(metadata or {})))
            _append_event(self.db,'original_stored',ref)
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        return {**ref,'text':text}

    def originals(self):
        return [dict(row) for row in self.db.execute('SELECT source_id,version,text,sha256,owner_id,metadata_json FROM originals ORDER BY source_id,version')]

    def add_memory(self, memory_id, text, source_ids=(), parent_memory_ids=(), version=1, provenance=None, kind='derived'):
        _identifier(memory_id,'memory_id'); _version(version)
        _need(isinstance(text,str) and bool(text), 'nonempty_memory_text_required')
        _need(provenance is None or isinstance(provenance,dict), 'provenance_object_required')
        _need(isinstance(source_ids,(list,tuple)) and len(set(source_ids)) == len(source_ids), 'unique_actual_source_inputs_required')
        direct = []
        for sid in source_ids:
            row = self.db.execute('SELECT source_id,version,sha256,owner_id FROM originals WHERE source_id=? ORDER BY version DESC LIMIT 1',(sid,)).fetchone()
            _need(row is not None,'actual_original_input_not_in_sender_store')
            direct.append(dict(row))
        direct = _merge_refs(direct)
        parents = [self.get_memory(parent) for parent in parent_memory_ids]
        parent_keys = [parent['memory_key'] for parent in parents]
        _need(len(set(parent_keys)) == len(parent_keys), 'duplicate_parent_memory')
        dependencies = _merge_refs(direct+[dep for parent in parents for dep in parent['dependencies']])
        _need(bool(dependencies), 'memory_must_have_original_dependencies')
        if kind == 'raw':
            _need(len(direct) == 1 and not parents, 'raw_memory_requires_one_original')
            row = self.db.execute('SELECT text FROM originals WHERE source_id=? AND version=?',(direct[0]['source_id'],direct[0]['version'])).fetchone()
            _need(row['text'] == text, 'raw_memory_must_be_exact_original')
        artifact = {'memory_key':_memory_key(self.agent_id,memory_id,version),'memory_id':memory_id,
            'version':version,'origin_agent':self.agent_id,'content':text,'content_sha256':digest(text.encode('utf-8')),
            'kind':kind,'provenance':_compact_provenance(provenance or {}),'direct_sources':direct,
            'parents':parent_keys,'dependencies':dependencies}
        artifact['artifact_sha256'] = digest(artifact)
        _check_artifact(artifact)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            created = _insert_artifact(self.db,artifact)
            if created: _append_event(self.db,'memory_stored',{'memory_key':artifact['memory_key'],'artifact_sha256':artifact['artifact_sha256']})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        return self.get_memory(artifact['memory_key'])

    def get_memory(self, reference):
        if isinstance(reference,dict):
            key = reference.get('memory_key')
            if key:
                return self.get_memory(key)
            row = self.db.execute('SELECT * FROM memories WHERE origin_agent=? AND memory_id=? AND version=?',
                (reference.get('origin_agent',self.agent_id),reference['memory_id'],reference.get('version',1))).fetchone()
        else:
            _identifier(reference,'memory_reference')
            row = self.db.execute('SELECT * FROM memories WHERE memory_key=?',(reference,)).fetchone()
            if row is None:
                candidates = self.db.execute('SELECT * FROM memories WHERE memory_id=? ORDER BY version DESC',(reference,)).fetchall()
                own = [r for r in candidates if r['origin_agent'] == self.agent_id]
                if own: row = own[0]
                elif candidates:
                    _need(len({r['origin_agent'] for r in candidates}) == 1,'ambiguous_imported_memory_reference')
                    row = candidates[0]
        _need(row is not None,'memory_not_found')
        key = row['memory_key']
        def refs(table):
            return [{'source_id':r['source_id'],'version':r['source_version'],'sha256':r['source_sha256'],'owner_id':r['owner_id']}
                    for r in self.db.execute('SELECT * FROM '+table+' WHERE memory_key=? ORDER BY source_id',(key,))]
        result = {k:row[k] for k in ('memory_key','memory_id','version','origin_agent','content','content_sha256','kind','artifact_sha256')}
        result.update(provenance=json.loads(row['provenance_json']),direct_sources=refs('memory_direct_sources'),
            dependencies=refs('memory_dependencies'),parents=[r[0] for r in self.db.execute('SELECT parent_key FROM memory_parents WHERE memory_key=? ORDER BY position',(key,))])
        _check_artifact(result)
        return result

    def retrieve(self, batch_id):
        """Read a committed batch using a fresh read-only connection to this DB."""
        _identifier(batch_id,'batch_id')
        db = sqlite3.connect(self.readonly_uri,uri=True,isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN')
            owner = db.execute("SELECT value FROM metadata WHERE key='agent_id'").fetchone()[0]
            batch = db.execute('SELECT * FROM batches WHERE batch_id=?',(batch_id,)).fetchone()
            _need(batch is not None and batch['recipient_id'] == owner == self.agent_id,'committed_recipient_batch_required')
            rows = [dict(r) for r in db.execute('SELECT bm.position,m.memory_key,m.memory_id,m.version,m.origin_agent,m.content,m.content_sha256,m.kind,m.artifact_sha256 FROM batch_memories bm JOIN memories m USING(memory_key) WHERE bm.batch_id=? ORDER BY bm.position',(batch_id,))]
            for row in rows: _need(digest(row['content'].encode('utf-8')) == row['content_sha256'],'stored_memory_body_changed')
            event = db.execute('SELECT * FROM events WHERE event_hash=?',(batch['import_event_hash'],)).fetchone()
            _need(event is not None and event['kind']=='import_committed','import_event_missing')
            data = json.loads(event['payload_json'])
            _need(data['batch_id']==batch_id and data['import_id']==batch['import_id'] and data['recipient_id']==owner,'batch_event_binding_invalid')
            _need(data['sender_id']==batch['sender_id'] and data['epoch']==batch['epoch']
                  and data['packet_sha256']==batch['packet_sha256']
                  and data['memory_keys']==[r['memory_key']for r in rows],'batch_event_identity_or_order_changed')
            refs = []
            for row in rows:
                dependencies = [{'source_id':r['source_id'],'version':r['source_version'],'sha256':r['source_sha256'],'owner_id':r['owner_id']}
                    for r in db.execute('SELECT * FROM memory_dependencies WHERE memory_key=? ORDER BY source_id',(row['memory_key'],))]
                binding = data['artifact_bindings'][row['memory_key']]
                _need(binding['content_sha256']==row['content_sha256'] and binding['dependencies_sha256']==digest(dependencies),'stored_artifact_import_binding_changed')
                _need(binding['artifact_sha256']==row['artifact_sha256']
                      and all(binding[k]==row[k]for k in ('origin_agent','memory_id','version','kind'))
                      and row['memory_key']==_memory_key(row['origin_agent'],row['memory_id'],row['version']),
                      'stored_memory_identity_changed')
                refs.extend(dependencies)
            verify_events(db)
            # Internal SHA identifiers are audit metadata, not model input.
            # In particular raw export must not pay for a long hash per fact.
            text = '\n\n'.join(row['content'] for row in rows)
            receipt = {'agent_id':owner,'batch_id':batch_id,'import_id':batch['import_id'],
                'receiver_db':str(self.path),'readonly_uri':self.readonly_uri,'import_event_hash':batch['import_event_hash'],
                'memory_keys':[r['memory_key'] for r in rows],'memory_sha256':digest(text.encode('utf-8')),
                'queried_only_receiver_database':True,'policy_epoch_at_import':batch['epoch']}
            db.execute('COMMIT')
            return {'memory':text,'memories':rows,'source_ids':[r['source_id'] for r in _merge_refs(refs)],
                    'dependencies':_merge_refs(refs),'query_receipt':receipt}
        finally:
            db.close()


def _insert_origin(db, ref):
    old = db.execute('SELECT * FROM origins WHERE source_id=? AND version=?',(ref['source_id'],ref['version'])).fetchone()
    if old:
        _need(old['sha256']==ref['sha256'] and old['owner_id']==ref['owner_id'],'origin_metadata_conflict')
    else:
        db.execute('INSERT INTO origins VALUES(?,?,?,?)',(ref['source_id'],ref['version'],ref['sha256'],ref['owner_id']))


def _insert_artifact(db, artifact):
    _check_artifact(artifact)
    old = db.execute('SELECT artifact_sha256 FROM memories WHERE memory_key=?',(artifact['memory_key'],)).fetchone()
    if old:
        _need(old['artifact_sha256']==artifact['artifact_sha256'],'immutable_memory_artifact_changed')
        return False
    db.execute('INSERT INTO memories VALUES(?,?,?,?,?,?,?,?,?)',tuple(artifact[k] for k in
        ('memory_key','memory_id','version','origin_agent','content','content_sha256','kind'))+(_json(artifact['provenance']),artifact['artifact_sha256']))
    for table, refs in (('memory_dependencies',artifact['dependencies']),('memory_direct_sources',artifact['direct_sources'])):
        for ref in refs:
            _insert_origin(db,ref)
            db.execute('INSERT INTO '+table+' VALUES(?,?,?,?,?)',(artifact['memory_key'],ref['source_id'],ref['version'],ref['sha256'],ref['owner_id']))
    db.executemany('INSERT INTO memory_parents VALUES(?,?,?)',[(artifact['memory_key'],i,p) for i,p in enumerate(artifact['parents'])])
    node = _json(_node(artifact))
    existing = db.execute('SELECT node_json FROM lineage_metadata WHERE memory_key=?',(artifact['memory_key'],)).fetchone()
    _need(existing is None or existing[0] == node,'immutable_lineage_changed')
    db.execute('INSERT OR IGNORE INTO lineage_metadata VALUES(?,?)',(artifact['memory_key'],node))
    return True


class TrustedPolicy:
    def __init__(self,path):
        self.path,self.db = _connect(path)
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS policy_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sources(source_id TEXT PRIMARY KEY,version INTEGER NOT NULL,sha256 TEXT NOT NULL,owner_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS source_versions(source_id TEXT,version INTEGER,sha256 TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(source_id,version));
        CREATE TABLE IF NOT EXISTS grants(recipient_id TEXT,source_id TEXT REFERENCES sources(source_id),PRIMARY KEY(recipient_id,source_id));
        CREATE TABLE IF NOT EXISTS seals(import_id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,batch_id TEXT NOT NULL,sender_id TEXT NOT NULL,recipient_id TEXT NOT NULL,epoch INTEGER NOT NULL,packet_sha256 TEXT NOT NULL,consumed_by TEXT);
        INSERT OR IGNORE INTO policy_metadata VALUES('epoch','0');
        ''')
        _events_schema(self.db)

    @property
    def epoch(self):
        return int(self.db.execute("SELECT value FROM policy_metadata WHERE key='epoch'").fetchone()[0])

    def close(self):
        self.db.close()

    def register_sources(self,sources,owner_id=None):
        _need(isinstance(sources,(list,tuple)), 'sources_sequence_required')
        refs=[]
        for source in sources:
            _need(isinstance(source,dict),'source_object_required')
            text = source.get('text')
            actual_hash = digest(text.encode('utf-8')) if isinstance(text,str) else source.get('sha256')
            if 'sha256' in source: _need(source['sha256']==actual_hash,'source_registry_text_hash_mismatch')
            refs.append(_source_ref({'source_id':source['source_id'],'version':source.get('version',1),
                'sha256':actual_hash,'owner_id':source.get('owner_id',owner_id)}))
        refs=_merge_refs(refs)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            for ref in refs:
                old=self.db.execute('SELECT * FROM sources WHERE source_id=?',(ref['source_id'],)).fetchone()
                if old:
                    _need(old['owner_id']==ref['owner_id'],'source_owner_changed')
                    _need(ref['version']>old['version'] or (ref['version']==old['version'] and ref['sha256']==old['sha256']),'source_version_rollback_or_hash_change')
                old_version=self.db.execute('SELECT * FROM source_versions WHERE source_id=? AND version=?',(ref['source_id'],ref['version'])).fetchone()
                _need(old_version is None or dict(old_version)==ref,'immutable_policy_source_version_changed')
                values=tuple(ref[k] for k in ('source_id','version','sha256','owner_id'))
                self.db.execute('INSERT OR IGNORE INTO source_versions VALUES(?,?,?,?)',values)
                self.db.execute('INSERT INTO sources VALUES(?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET version=excluded.version,sha256=excluded.sha256',values)
            self.db.execute("UPDATE policy_metadata SET value=CAST(value AS INTEGER)+1 WHERE key='epoch'")
            _append_event(self.db,'sources_registered',{'epoch':self.epoch,'sources':refs})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        return self.epoch

    def set_permissions(self,recipient,allowed_source_ids):
        _identifier(recipient,'recipient')
        _need(isinstance(allowed_source_ids,(list,tuple,set)),'allowed_source_ids_sequence_required')
        ids=sorted(set(allowed_source_ids))
        self.db.execute('BEGIN IMMEDIATE')
        try:
            for sid in ids: _need(self.db.execute('SELECT 1 FROM sources WHERE source_id=?',(sid,)).fetchone() is not None,'grant_for_unknown_source')
            self.db.execute('DELETE FROM grants WHERE recipient_id=?',(recipient,))
            self.db.executemany('INSERT INTO grants VALUES(?,?)',[(recipient,sid) for sid in ids])
            self.db.execute("UPDATE policy_metadata SET value=CAST(value AS INTEGER)+1 WHERE key='epoch'")
            epoch=self.epoch
            _append_event(self.db,'permissions_committed',{'recipient_id':recipient,'allowed':ids,'epoch':epoch})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        return epoch

    def validate_dependencies(self,recipient,dependencies,expected_epoch=None):
        self.db.execute('BEGIN')
        try:
            epoch=self.epoch
            if expected_epoch is not None: _need(epoch==expected_epoch,'stale_policy_epoch')
            _validate_authority(self.db,'',recipient,_merge_refs(dependencies))
            self.db.execute('COMMIT')
            return epoch
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def check_dependencies(self,recipient,dependencies,expected_epoch=None):
        """Read-only use-time check; does not revoke already disclosed text."""
        return self.validate_dependencies(recipient,dependencies,expected_epoch)


def _validate_authority(db,prefix,recipient,dependencies):
    for ref in dependencies:
        row=db.execute('SELECT * FROM '+prefix+'sources WHERE source_id=?',(ref['source_id'],)).fetchone()
        _need(row is not None and dict(row)==ref,'source_version_or_hash_is_not_current')
        grant=db.execute('SELECT 1 FROM '+prefix+'grants WHERE recipient_id=? AND source_id=?',(recipient,ref['source_id'])).fetchone()
        _need(grant is not None,'source_not_currently_authorized_for_recipient')


def _lineage(sender,artifacts):
    nodes={}
    def collect(key,visiting):
        _need(key not in visiting,'cyclic_lineage')
        if key in nodes:return
        row=sender.db.execute('SELECT node_json FROM lineage_metadata WHERE memory_key=?',(key,)).fetchone()
        _need(row is not None,'complete_parent_lineage_missing')
        node=json.loads(row[0]); nodes[key]=node
        for parent in node['parents']:collect(parent,visiting|{key})
    for artifact in artifacts:collect(artifact['memory_key'],set())
    return [nodes[key] for key in sorted(nodes)]


def _validate_lineage(packet):
    _need(isinstance(packet['lineage'],list) and isinstance(packet['memories'],list),'lineage_and_memories_required')
    nodes={}
    for node in packet['lineage']:
        _need(isinstance(node,dict) and node.get('memory_key') not in nodes,'duplicate_lineage_node')
        nodes[node['memory_key']]=node
    state={}
    def flatten(key):
        _need(key in nodes,'complete_parent_lineage_missing')
        _need(state.get(key)!='visiting','cyclic_lineage')
        node=nodes[key]
        if state.get(key)=='done':return node['dependencies']
        state[key]='visiting'
        _need(node['memory_key']==_memory_key(node['origin_agent'],node['memory_id'],node['version']),'lineage_identity_invalid')
        refs=list(node['direct_sources'])
        for parent in node['parents']:refs.extend(flatten(parent))
        _need(_merge_refs(refs)==node['dependencies'],'lineage_dependency_closure_invalid')
        state[key]='done';return node['dependencies']
    memories=packet['memories'];keys=[];deps=[]
    for artifact in memories:
        _check_artifact(artifact); key=artifact['memory_key'];keys.append(key)
        _need(key in nodes and _node(artifact)==nodes[key],'selected_artifact_lineage_binding_invalid')
        deps.extend(flatten(key))
    _need(len(set(keys))==len(keys),'duplicate_selected_memory')
    _need(set(state)==set(nodes),'extraneous_unpresented_lineage_node')
    _need(_merge_refs(deps)==packet['sources'],'packet_original_dependency_union_invalid')


def export_package(sender,policy,recipient,memory_ids,batch_id=None):
    _identifier(recipient,'recipient')
    _need(recipient!=sender.agent_id,'separate_agent_recipient_required')
    _need(isinstance(memory_ids,(list,tuple)),'memory_reference_sequence_required')
    artifacts=[sender.get_memory(ref) for ref in memory_ids]
    packet={'schema':SCHEMA,'import_id':secrets.token_hex(16),'nonce':secrets.token_hex(32),
        'batch_id':_identifier(batch_id,'batch_id') if batch_id is not None else 'batch-'+secrets.token_hex(16),
        'sender_id':sender.agent_id,'recipient_id':recipient,'epoch':None,
        'memories':artifacts,'lineage':_lineage(sender,artifacts),
        'sources':_merge_refs([dep for artifact in artifacts for dep in artifact['dependencies']])}
    _validate_lineage(packet)
    policy.db.execute('BEGIN IMMEDIATE')
    try:
        packet['epoch']=policy.epoch
        _validate_authority(policy.db,'',recipient,packet['sources'])
        packet['content_sha256']=digest(packet)
        policy.db.execute('INSERT INTO seals VALUES(?,?,?,?,?,?,?,NULL)',tuple(packet[k] for k in ('import_id','nonce','batch_id','sender_id','recipient_id','epoch','content_sha256')))
        _append_event(policy.db,'export_sealed',{'import_id':packet['import_id'],'sender_id':sender.agent_id,
            'recipient_id':recipient,'epoch':packet['epoch'],'packet_sha256':packet['content_sha256']})
        policy.db.execute('COMMIT')
    except BaseException:
        policy.db.execute('ROLLBACK');raise
    return deepcopy(packet)


def import_package(receiver,policy,packet,before_commit=None):
    _need(receiver.path!=policy.path,'separate_policy_and_receiver_database_required')
    keys={'schema','import_id','nonce','batch_id','sender_id','recipient_id','epoch','memories','lineage','sources','content_sha256'}
    _need(isinstance(packet,dict) and set(packet)==keys,'exact_transfer_packet_schema_required')
    packet=json.loads(canonical(packet))
    _need(packet['schema']==SCHEMA and packet['recipient_id']==receiver.agent_id and packet['sender_id']!=receiver.agent_id,'packet_recipient_or_schema_invalid')
    _need(type(packet['epoch'])is int and packet['epoch']>=0,'invalid_packet_epoch')
    for key in ('import_id','nonce','batch_id','sender_id','recipient_id'):_identifier(packet[key],key)
    _need(packet['content_sha256']==digest({k:v for k,v in packet.items()if k!='content_sha256'}),'packet_content_hash_invalid')
    _validate_lineage(packet)
    if before_commit:before_commit()
    db=receiver.db
    _need(not db.in_transaction,'receiver_transaction_already_open')
    db.execute('ATTACH DATABASE ? AS authority',(str(policy.path),))
    try:
        _need(db.execute('PRAGMA authority.journal_mode').fetchone()[0]=='delete','attached_policy_requires_delete_journal')
        db.execute('BEGIN IMMEDIATE')
        try:
            epoch=int(db.execute("SELECT value FROM authority.policy_metadata WHERE key='epoch'").fetchone()[0])
            _need(epoch==packet['epoch'],'stale_policy_epoch')
            seal=db.execute('SELECT * FROM authority.seals WHERE import_id=?',(packet['import_id'],)).fetchone()
            _need(seal is not None,'unsealed_transfer_packet')
            _need(seal['consumed_by']is None,'transfer_replay_rejected')
            for key in ('nonce','batch_id','sender_id','recipient_id','epoch'):_need(seal[key]==packet[key],'trusted_seal_metadata_mismatch')
            _need(seal['packet_sha256']==packet['content_sha256'],'trusted_packet_seal_mismatch')
            _need(db.execute('SELECT 1 FROM batches WHERE batch_id=?',(packet['batch_id'],)).fetchone()is None,'recipient_batch_id_already_exists')
            _validate_authority(db,'authority.',receiver.agent_id,packet['sources'])
            for node in packet['lineage']:
                old=db.execute('SELECT node_json FROM lineage_metadata WHERE memory_key=?',(node['memory_key'],)).fetchone()
                encoded=_json(node)
                _need(old is None or old[0]==encoded,'immutable_imported_lineage_changed')
                db.execute('INSERT OR IGNORE INTO lineage_metadata VALUES(?,?)',(node['memory_key'],encoded))
            for artifact in packet['memories']:_insert_artifact(db,artifact)
            imported_at=datetime.now(timezone.utc).isoformat()
            bindings={a['memory_key']:{'content_sha256':a['content_sha256'],
                'dependencies_sha256':digest(a['dependencies']),'artifact_sha256':a['artifact_sha256'],
                'origin_agent':a['origin_agent'],'memory_id':a['memory_id'],'version':a['version'],'kind':a['kind']}
                for a in packet['memories']}
            event=_append_event(db,'import_committed',{'batch_id':packet['batch_id'],'import_id':packet['import_id'],
                'sender_id':packet['sender_id'],'recipient_id':receiver.agent_id,'epoch':epoch,
                'packet_sha256':packet['content_sha256'],'memory_keys':[a['memory_key']for a in packet['memories']],
                'artifact_bindings':bindings})
            db.execute('INSERT INTO batches VALUES(?,?,?,?,?,?,?,?)',(packet['batch_id'],packet['import_id'],packet['sender_id'],receiver.agent_id,
                epoch,packet['content_sha256'],event['event_hash'],imported_at))
            db.executemany('INSERT INTO batch_memories VALUES(?,?,?)',[(packet['batch_id'],i,a['memory_key'])for i,a in enumerate(packet['memories'])])
            changed=db.execute('UPDATE authority.seals SET consumed_by=? WHERE import_id=? AND consumed_by IS NULL',
                (receiver.agent_id,packet['import_id'])).rowcount
            _need(changed==1,'transfer_concurrent_replay_rejected')
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK');raise
    finally:
        db.execute('DETACH DATABASE authority')
    return {'status':'imported','batch_id':packet['batch_id'],'import_id':packet['import_id'],
        'sender_id':packet['sender_id'],'recipient_id':receiver.agent_id,'policy_epoch':packet['epoch'],
        'packet_sha256':packet['content_sha256'],'import_event_hash':event['event_hash'],
        'memory_keys':[a['memory_key']for a in packet['memories']], 'receiver_db':str(receiver.path),
        'transaction_scope':'single-host SQLite ATTACH, DELETE journal; authorization and import committed together'}


__all__=['AgentStore','TrustedPolicy','StoreError','export_package','import_package','canonical','digest','verify_events','SCHEMA']
