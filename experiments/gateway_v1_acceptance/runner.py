"""Fixed 24 regression rows + 180 normal commit rows. Never auto-run on import.

Production service/delivery/store are unchanged. Test hooks are local to child
workers. An explicit --run and a NEW --output directory are required. The root
coordinator freezes this source/contract/checker before the sole campaign.
"""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from agent_memory_gateway.service import GatewayService
from agent_memory_gateway import delivery
from experiments.persistent_exchange_v1 import store

METHODS = ('acl', 'transaction', 'gateway')
CORE_PATHS = ('agent_memory_gateway/service.py', 'agent_memory_gateway/delivery.py',
              'experiments/persistent_exchange_v1/store.py')


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def utc(): return datetime.now(timezone.utc).isoformat()
def load(path): return json.loads(Path(path).read_text(encoding='utf-8'))


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write('\n'); f.flush(); os.fsync(f.fileno())


def read_packet(data, transfer_id):
    raw = (data / 'spool' / (transfer_id + '.json')).read_bytes()
    packet = json.loads(raw)
    store._need(raw == store.canonical(packet) + b'\n', 'transfer_spool_canonical_encoding_invalid')
    store._need(packet.get('import_id') == transfer_id, 'transfer_spool_identity_mismatch')
    return packet


def preliminary(data, packet):
    store._need(packet['recipient_id'] == 'B', 'wrong_recipient')
    store._need(packet['content_sha256'] == store.digest({k: v for k, v in packet.items() if k != 'content_sha256'}), 'packet_content_hash_invalid')
    store._validate_lineage(packet)
    p = store.TrustedPolicy(data / 'policy.sqlite')
    try:
        p.check_dependencies('B', packet['sources'], packet['epoch'])
        seal = p.db.execute('SELECT * FROM seals WHERE import_id=?', (packet['import_id'],)).fetchone()
        store._need(seal is not None and seal['consumed_by'] is None, 'seal_absent_or_consumed')
        for k in ('nonce', 'batch_id', 'sender_id', 'recipient_id', 'epoch'):
            store._need(seal[k] == packet[k], 'trusted_seal_metadata_mismatch')
        store._need(seal['packet_sha256'] == packet['content_sha256'], 'trusted_packet_seal_mismatch')
    finally: p.close()


def acl_commit(data, packet, prechecked=False):
    if not prechecked: preliminary(data, packet)
    b = store.AgentStore(data / 'agents/B.sqlite', 'B')
    p = store.TrustedPolicy(data / 'policy.sqlite')
    try:
        b.db.execute('BEGIN IMMEDIATE')
        try:
            b.db.execute('INSERT INTO acl_effects(import_id,batch_id,packet_sha256,packet_json) VALUES(?,?,?,?)',
                (packet['import_id'], packet['batch_id'], packet['content_sha256'], json.dumps(packet, sort_keys=True)))
            store._append_event(b.db, 'acl_import_committed', {'import_id': packet['import_id'],
                'batch_id': packet['batch_id'], 'packet_sha256': packet['content_sha256']})
            b.db.execute('COMMIT')
        except BaseException:
            b.db.execute('ROLLBACK'); raise
        # Intentional baseline boundary: this is outside the receiver transaction.
        p.db.execute('UPDATE seals SET consumed_by=? WHERE import_id=?', ('B', packet['import_id']))
        return {'status': 'committed', 'import_id': packet['import_id'], 'batch_id': packet['batch_id'],
            'packet_sha256': packet['content_sha256'], 'metadata_only': True,
            'new_persistent_acceptance': True, 'ack_contains_plaintext': False}
    finally: b.close(); p.close()


def commit(data, transfer_id, method, prechecked=False):
    if method == 'gateway': return GatewayService(data).commit_transfer(transfer_id)
    packet = read_packet(data, transfer_id)
    if method == 'acl': return acl_commit(data, packet, prechecked)
    b = store.AgentStore(data / 'agents/B.sqlite', 'B')
    p = store.TrustedPolicy(data / 'policy.sqlite')
    try: return delivery.deliver(b, p, packet)
    finally: b.close(); p.close()


def snapshot(data, method):
    def ro(path):
        db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row; db.execute('PRAGMA query_only=ON'); return db
    b = ro(data / 'agents/B.sqlite'); p = ro(data / 'policy.sqlite')
    try:
        table = 'acl_effects' if method == 'acl' else 'batches'
        effects = [dict(r) for r in b.execute('SELECT batch_id,import_id,packet_sha256 FROM ' + table + ' ORDER BY batch_id,import_id')]
        seals = [dict(r) for r in p.execute('SELECT import_id,batch_id,packet_sha256,consumed_by FROM seals ORDER BY import_id')]
        kinds = lambda db: [dict(r) for r in db.execute('SELECT seq,kind,event_hash FROM events ORDER BY seq')]
        sizes = {'receiver_db_bytes': (data / 'agents/B.sqlite').stat().st_size,
            'sender_db_bytes': (data / 'agents/A.sqlite').stat().st_size,
            'policy_db_bytes': (data / 'policy.sqlite').stat().st_size,
            'spool_bytes': sum(f.stat().st_size for f in (data / 'spool').glob('*.json')),
            'spool_file_count': sum(1 for _ in (data / 'spool').glob('*.json'))}
        return {'effect_count': len(effects), 'effects': effects, 'seals': seals, 'storage': sizes,
            'consumed_seal_count': sum(r['consumed_by'] is not None for r in seals),
            'receiver_events': kinds(b), 'policy_events': kinds(p),
            'receiver_event_chain': store.verify_events(b), 'policy_event_chain': store.verify_events(p),
            'receiver_quick_check': b.execute('PRAGMA quick_check').fetchone()[0],
            'policy_quick_check': p.execute('PRAGMA quick_check').fetchone()[0],
            'epoch': int(p.execute("SELECT value FROM policy_metadata WHERE key='epoch'").fetchone()[0]),
            'observer_in_transaction': b.in_transaction or p.in_transaction,
            'source_versions': [dict(r) for r in p.execute('SELECT source_id,version FROM sources ORDER BY source_id')]}
    finally: b.close(); p.close()


class SQLTrace:
    def __init__(self, data, worker, fault):
        self.data, self.worker, self.fault = data.resolve(), worker, fault
        self.counts = Counter(); self.receiver_sql = []; self.writer_in_transaction = None
        self.connect = sqlite3.connect

    def install(self):
        def connected(database, *args, **kwargs):
            db = self.connect(database, *args, **kwargs)
            # Resolve ordinary paths and file:...mode=ro URIs without issuing
            # an extra PRAGMA. This also covers AgentStore.retrieve(), which
            # opens sqlite3 directly instead of store._connect.
            text = os.fspath(database)
            readonly = isinstance(text, str) and 'mode=ro' in text
            if isinstance(text, str) and text.startswith('file:'):
                filename = unquote(urlparse(text).path)
                if len(filename) > 3 and filename[0] == '/' and filename[2] == ':': filename = filename[1:]
                actual = Path(filename).resolve()
            else:
                actual = Path(text).resolve()
            def trace(sql):
                normalized = sql.strip().upper(); self.counts[normalized.split()[0] if normalized else 'EMPTY'] += 1
                if actual != self.data / 'agents/B.sqlite': return
                self.receiver_sql.append(normalized.split(' ', 2)[0])
                if not readonly: self.writer_in_transaction = db.in_transaction
                dml = normalized.startswith(('INSERT ', 'UPDATE ', 'DELETE ', 'REPLACE '))
                hit = not readonly and ((self.fault == 'before_dml' and dml) or (self.fault == 'before_commit' and normalized == 'COMMIT'))
                if hit:
                    save(self.worker / 'failpoint.json', {'fault': self.fault, 'reached': True,
                        'writer_in_transaction': db.in_transaction, 'writer_total_changes': db.total_changes,
                        'sql_logical_counts': dict(self.counts), 'sql_is_physical_IO': False,
                        'receiver_sql_verbs_seen': self.receiver_sql, 'ack_delivered': False})
                    os._exit(71 if self.fault == 'before_dml' else 72)
            db.set_trace_callback(trace); return db
        sqlite3.connect = connected


def barrier(worker, shared):
    save(worker / 'ready.json', {'precheck_passed': True})
    limit = time.monotonic() + 15
    while not (shared / 'go.json').is_file():
        if time.monotonic() > limit: raise TimeoutError('concurrency_barrier_timeout')
        time.sleep(0.01)


def one_operation(data, method, transfer_id, worker, trace, mode='normal', shared=None):
    before = snapshot(data, method); prechecked = False; precheck_evidence = None
    if mode in ('revoke', 'concurrent'):
        preliminary(data, read_packet(data, transfer_id)); prechecked = True
        precheck_evidence = {'passed': True, 'epoch': before['epoch']}
        if mode == 'concurrent': barrier(worker, shared)
        else:
            target = worker / 'revoker'
            result = subprocess.run([sys.executable, '-B', '-X', 'utf8', str(Path(__file__).resolve()),
                '--worker', '--action', 'revoke', '--data', str(data), '--worker-output', str(target)],
                cwd=ROOT, capture_output=True, text=True, timeout=20)
            if result.returncode != 0: raise RuntimeError('revoker_did_not_commit:' + result.stderr)
            precheck_evidence['revoker_result'] = load(target / 'mutation.json')
    trace.counts.clear(); begin = time.perf_counter_ns(); cpu = time.process_time_ns()
    try:
        receipt = commit(data, transfer_id, method, prechecked=prechecked)
        accepted, error, reason = True, None, None
    except Exception as exc:
        accepted, receipt, error, reason = False, None, type(exc).__name__, str(exc)
    wall, cpu = time.perf_counter_ns() - begin, time.process_time_ns() - cpu
    counts = dict(trace.counts)
    if mode == 'after_commit' and accepted:
        save(worker / 'failpoint.json', {'fault': 'after_commit_before_ack', 'reached': True,
            'writer_in_transaction': None, 'writer_state_observation': 'Public commit function returned and closed its connections; no live writer property is read.',
            'metadata_returned_locally': True, 'ack_delivered': False,
            'sql_logical_counts': counts, 'sql_is_physical_IO': False})
        os._exit(73)
    after = snapshot(data, method)
    plaintext = bool(receipt and any(k in receipt for k in ('content', 'memory', 'memories')))
    result = {'accepted': accepted, 'receipt': receipt, 'error': error, 'reason': reason,
        'transfer_id': transfer_id, 'wall_ns': wall, 'cpu_ns': cpu, 'sql_logical_statements': sum(counts.values()),
        'sql_logical_counts': counts, 'SQL_is_physical_IO': False, 'physical_IO_operations': None,
        'sql_count_scope': 'All worker sqlite3.connect trace callbacks during timed commit, including retrieve() mode=ro bindings; snapshots/explicit precheck/barrier are outside timer and counts are cleared immediately before commit. Not SQLite internal physical I/O.',
        'receiver_storage_delta_bytes': after['storage']['receiver_db_bytes'] - before['storage']['receiver_db_bytes'],
        'policy_storage_delta_bytes': after['storage']['policy_db_bytes'] - before['storage']['policy_db_bytes'],
        'spool_storage_delta_bytes': after['storage']['spool_bytes'] - before['storage']['spool_bytes'],
        'before_snapshot': before, 'after_snapshot': after, 'plaintext_in_ACK': plaintext,
        'precheck_evidence': precheck_evidence, 'measurement_scope': load(HERE / 'contract.json')['timing_scope']}
    if accepted: save(worker / 'ack.json', receipt)
    save(worker / 'result.json', result); return result


def worker_main(args):
    data, target = Path(args.data).resolve(), Path(args.worker_output).resolve()
    target.mkdir(parents=True, exist_ok=False)
    if args.action == 'revoke':
        result = GatewayService(data).set_permissions('B', [])
        save(target / 'mutation.json', {'status': 'committed', **result}); return
    trace = SQLTrace(data, target, args.fault); trace.install()
    if args.action in ('sweep', 'performance'):
        manifest = load(Path(args.manifest)); results = []
        for index, item in enumerate(manifest['tasks']):
            step = target / ('item-%02d' % index); step.mkdir()
            row = one_operation(data, args.method, item['transfer_id'], step, trace)
            results.append({**item, **row})
        save(target / 'rows.json', results)
    else:
        one_operation(data, args.method, args.transfer, target, trace, args.mode,
                      Path(args.shared) if args.shared else None)


def fixture(data, project, transfers=2):
    service = GatewayService(data); sources = []
    for index in range(1 + project % 4):
        sid = f'P{project:02d}-S{index}'
        service.register_source('A', sid, f'Controlled project {project}, source {index}, value {project * 19 + index}.')
        sources.append(sid)
    service.set_permissions('B', sources)
    # Initialize the baseline table outside every timed/faulted operation.
    for agent in ('A', 'B'):
        conn = store.AgentStore(data / 'agents' / (agent + '.sqlite'), agent)
        try:
            if agent == 'B': conn.db.execute('CREATE TABLE IF NOT EXISTS acl_effects(seq INTEGER PRIMARY KEY,import_id TEXT NOT NULL,batch_id TEXT NOT NULL,packet_sha256 TEXT NOT NULL,packet_json TEXT NOT NULL)')
        finally: conn.close()
    tasks = []
    for index in range(transfers):
        mid = f'P{project:02d}-M{index}'
        service.create_memory('A', mid, f'Controlled project {project} derived delivery {index}.', source_ids=sources,
            provenance={'generator': 'controlled-fixture-no-model'})
        reply = service.prepare_transfer('A', 'B', [mid], batch_id=f'P{project:02d}-batch-{index}')
        tasks.append({'transfer_id': reply['transfer_id'], 'batch_id': reply['batch_id'], 'packet_sha256': reply['packet_sha256']})
    save(data.parent / (data.name + '-tasks.json'), {'tasks': tasks, 'sources': sources})
    return tasks, sources


def start_worker(data, target, method, transfer=None, action='call', mode='normal', fault=None, shared=None, manifest=None):
    command = [sys.executable, '-B', '-X', 'utf8', str(Path(__file__).resolve()), '--worker',
        '--action', action, '--data', str(data), '--worker-output', str(target), '--method', method, '--mode', mode]
    for name, value in (('--transfer', transfer), ('--fault', fault), ('--shared', shared), ('--manifest', manifest)):
        if value is not None: command.extend((name, str(value)))
    return subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def finish_worker(proc, target, timeout=30):
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Kill only this explicitly created worker at its hard deadline; do
        # not retry or replace a missing result with a fabricated success.
        timed_out = True; proc.kill(); stdout, stderr = proc.communicate()
    observation = {'exit_code': proc.returncode, 'stdout': stdout, 'stderr': stderr,
        'worker_directory': str(target), 'hard_timeout_reached': timed_out}
    if not target.exists(): target.mkdir(parents=True)
    save(target / 'process_exit.json', observation)
    if (target / 'result.json').is_file(): observation['result'] = load(target / 'result.json')
    if (target / 'rows.json').is_file(): observation['rows'] = load(target / 'rows.json')
    if (target / 'failpoint.json').is_file(): observation['failpoint'] = load(target / 'failpoint.json')
    return observation


def operation(data, target, method, transfer=None, **kwargs):
    return finish_worker(start_worker(data, target, method, transfer, **kwargs), target)


def metadata_confirmation(op):
    value = op.get('result', {}); ack = value.get('receipt') or {}
    return value.get('accepted') is True and ack.get('status') == 'already_committed' and ack.get('new_persistent_acceptance') is False and not value.get('plaintext_in_ACK')


def regression(output, template, tasks, sources, scenario, method, config):
    case = output / 'regression' / scenario / method; data = case / 'data'
    case.mkdir(parents=True); oracle = deepcopy(config['scenario_oracle'][scenario]); ops = []; checks = {}
    primary, pending = tasks[:2]
    if scenario == 'R8':
        directories, snapshots = [], []
        for probe in oracle['probes']:
            probe_data = data / probe; shutil.copytree(template, probe_data)
            packet = read_packet(probe_data, primary['transfer_id']); artifact = packet['memories'][0]
            artifact['content'] = 'Controlled counterfeit replacement, never authorized as a sealed artifact.'
            if probe == 'probe_rehashed':
                artifact['content_sha256'] = store.digest(artifact['content'].encode('utf-8'))
                artifact['artifact_sha256'] = store.digest({k: v for k, v in artifact.items() if k != 'artifact_sha256'})
                packet['lineage'] = [store._node(artifact)]
                packet['content_sha256'] = store.digest({k: v for k, v in packet.items() if k != 'content_sha256'})
            (probe_data / 'spool' / (primary['transfer_id'] + '.json')).write_bytes(store.canonical(packet) + b'\n')
            op = operation(probe_data, case / (probe + '-worker'), method, primary['transfer_id']); ops.append(op)
            snapshots.append(snapshot(probe_data, method)); directories.append(str(probe_data.relative_to(output)))
        before = {'effect_count': 0}; after = {'effect_count': sum(v['effect_count'] for v in snapshots), 'probe_snapshots': snapshots}
        checks['both_probes_rejected'] = all(not op.get('result', {}).get('accepted', True) for op in ops)
    else:
        shutil.copytree(template, data); before = snapshot(data, method); directories = []
        if scenario in ('R1', 'R2', 'R3'):
            fault = {'R1': 'before_dml', 'R2': 'before_commit'}.get(scenario)
            op = operation(data, case / 'fault-worker', method, primary['transfer_id'],
                mode='after_commit' if scenario == 'R3' else 'normal', fault=fault); ops.append(op)
            at_fault = snapshot(data, method)
            checks['fault_point_reached'] = op['exit_code'] == oracle['fault_exit_code'] and op.get('failpoint', {}).get('reached') is True
            checks['effects_at_fault'] = at_fault['effect_count'] == oracle['effects_at_fault']
            checks['ACK_absent_at_fault'] = not (case / 'fault-worker/ack.json').exists()
            if scenario == 'R2': checks['transaction_had_writes'] = op.get('failpoint', {}).get('writer_in_transaction') is True and op.get('failpoint', {}).get('writer_total_changes', 0) > 0
            retry = operation(data, case / 'retry-worker', method, primary['transfer_id']); ops.append(retry)
            checks['legal_retry_or_confirmation'] = metadata_confirmation(retry) if scenario == 'R3' else retry.get('result', {}).get('accepted') is True
        elif scenario == 'R4':
            first = operation(data, case / 'first-worker', method, primary['transfer_id']); ops.append(first)
            checks['initial_ACK_received'] = (case / 'first-worker/ack.json').is_file() and first.get('result', {}).get('accepted') is True
            again = operation(data, case / 'repeat-worker', method, primary['transfer_id']); ops.append(again)
            checks['duplicate_confirmed'] = metadata_confirmation(again)
        elif scenario == 'R5':
            op = operation(data, case / 'revoke-window-worker', method, primary['transfer_id'], mode='revoke'); ops.append(op)
            evidence = op.get('result', {}).get('precheck_evidence') or {}
            checks['revocation_committed_after_allowed_precheck'] = evidence.get('passed') is True and evidence.get('revoker_result', {}).get('status') == 'committed'
            checks['old_packet_rejected'] = op.get('result', {}).get('accepted') is False
        elif scenario == 'R6':
            op = operation(data, case / 'lost-ACK-worker', method, primary['transfer_id'], mode='after_commit'); ops.append(op)
            checks['initial_worker_committed_then_exited'] = op['exit_code'] == 73 and snapshot(data, method)['effect_count'] == 1
            svc = GatewayService(data)
            svc.register_source('A', sources[0], 'Controlled source v2 after first delivery.', version=2)
            svc.set_permissions('B', [])
            manifest = case / 'recovery_manifest.json'; save(manifest, {'tasks': [primary, pending], 'scope': 'Harness fixed manifest, not autonomous service scan'})
            for index in (1, 2):
                op = operation(data, case / f'recovery-process-{index}', method, action='sweep', manifest=manifest); ops.append(op)
                recovered = op.get('rows', [])
                checks[f'recovery_scan_{index}_classifies_both_tasks'] = len(recovered) == 2 and metadata_confirmation({'result': recovered[0]}) and recovered[1].get('accepted') is False
        elif scenario == 'R7':
            shared = case / 'barrier'; shared.mkdir()
            folders = [case / f'concurrent-worker-{i}' for i in range(2)]
            procs = [start_worker(data, path, method, primary['transfer_id'], mode='concurrent', shared=shared) for path in folders]
            limit = time.monotonic() + 20
            while not all((p / 'ready.json').is_file() for p in folders):
                if time.monotonic() > limit: raise TimeoutError('two_workers_did_not_precheck')
                time.sleep(0.01)
            save(shared / 'go.json', {'both_prechecks_completed': True})
            ops.extend(finish_worker(proc, path) for proc, path in zip(procs, folders))
            checks['both_requests_receive_valid_ACK'] = all(v.get('result', {}).get('accepted') is True for v in ops)
            checks['one_new_one_existing_receipt'] = sum(metadata_confirmation(v) for v in ops) == 1
        after = snapshot(data, method)
    checks['final_effect_count'] = after['effect_count'] == oracle['final_effect_count']
    checks['no_plaintext_ACK'] = all(not op.get('result', {}).get('plaintext_in_ACK', False) and all(not r.get('plaintext_in_ACK', False) for r in op.get('rows', [])) for op in ops)
    return {'kind': 'regression', 'scenario_id': scenario, 'method': method,
        'data_directory': str(data.relative_to(output)), 'probe_directories': directories,
        'expected': oracle, 'before_snapshot': before, 'after_snapshot': after,
        'checks': checks, 'passed': all(checks.values()), 'operations': ops,
        'full_contract_expected_to_pass_for_this_method': config['method_expected_full_contract'][method][scenario],
        'B_C_same_security_core': True, 'new_model_calls': 0}


def campaign(output):
    if output.exists(): raise ValueError('output must not exist; no historical results may be overwritten')
    config = load(HERE / 'contract.json'); frozen = load(HERE / 'freeze_manifest.json')
    for rel, value in frozen['code_sha256'].items():
        if sha(HERE / rel) != value: raise ValueError('acceptance code changed after freeze: ' + rel)
    output.mkdir(parents=True)
    # Preserve the exact pre-frozen contract bytes, not a reordered JSON dump.
    with (output / 'config.json').open('xb') as f: f.write((HERE / 'contract.json').read_bytes())
    save(output / 'config_lock.json', {'contract_sha256': sha(HERE / 'contract.json'), 'runner_sha256': sha(__file__),
        'locked_before_execution': True, 'started_utc': utc(), 'freeze_manifest_sha256': sha(HERE / 'freeze_manifest.json')})
    versions = {p: sha(ROOT / p) for p in CORE_PATHS}
    save(output / 'code_version.json', {'files': [{'path': p, 'sha256': h} for p, h in versions.items()], 'same_B_C_core': True})
    captures = [HERE / p for p in frozen['code_sha256']]
    captures.append(HERE / 'freeze_manifest.json')
    captures.extend(ROOT / p for p in CORE_PATHS)
    for source in captures:
        relative_source = source.relative_to(ROOT)
        target = output / 'code' / relative_source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    template = output / 'regression_template'; tasks, sources = fixture(template, 1)
    regression_rows = []
    with (output / 'raw_regression.jsonl').open('x', encoding='utf-8') as log:
        for scenario in config['scenario_oracle']:
            for method in METHODS:
                try: row = regression(output, template, tasks, sources, scenario, method, config)
                except Exception as exc:
                    row = {'kind': 'regression', 'scenario_id': scenario, 'method': method, 'passed': False,
                        'expected': config['scenario_oracle'][scenario], 'harness_error': type(exc).__name__ + ':' + str(exc), 'traceback': traceback.format_exc()}
                regression_rows.append(row); log.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n'); log.flush()
                print(scenario, method, row['passed'], flush=True)
    performance = []; method_summaries = []
    with (output / 'raw_performance.jsonl').open('x', encoding='utf-8') as log:
        for project in range(1, 11):
            base = output / 'performance_templates' / f'P{project:02d}'
            tasks, _ = fixture(base, project, 6)
            order = METHODS[project % 3:] + METHODS[:project % 3]
            for method in order:
                directory = output / 'performance' / f'P{project:02d}' / method / 'data'
                shutil.copytree(base, directory)
                manifest = directory.parent / 'tasks.json'; save(manifest, {'tasks': tasks})
                proc = operation(directory, directory.parent / 'worker', method, action='performance', manifest=manifest)
                rows = proc.get('rows', [])
                if len(rows) != 6: raise RuntimeError('performance worker did not yield six rows')
                summary = {'project_id': f'P{project:02d}', 'method': method,
                    'data_directory': str(directory.relative_to(output)), 'deliveries': len(rows),
                    'initial_storage': rows[0]['before_snapshot']['storage'],
                    'final_storage': rows[-1]['after_snapshot']['storage'],
                    'initial_effect_count': rows[0]['before_snapshot']['effect_count'],
                    'final_effect_count': rows[-1]['after_snapshot']['effect_count'],
                    'timed_sql_logical_statement_count': sum(v['sql_logical_statements'] for v in rows),
                    'physical_IO_operations': None}
                method_summaries.append(summary); save(directory.parent / 'storage_and_logical_counts.json', summary)
                for index, row in enumerate(rows):
                    value = {'kind': 'performance', 'project_id': f'P{project:02d}', 'method': method,
                        'repeat_index': index, 'data_directory': str(directory.relative_to(output)), **row}
                    performance.append(value); log.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + '\n'); log.flush()
            print(f'P{project:02d} performance done', flush=True)
    save(output / 'performance_method_summaries.json', method_summaries)
    unchanged = all(sha(ROOT / p) == value for p, value in versions.items())
    acceptance_unchanged = all(sha(HERE / p) == value for p, value in frozen['code_sha256'].items())
    artifacts = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob('*') if p.is_file() and not p.name.endswith(('-journal', '-wal', '-shm'))}
    completion = {'status': 'completed', 'finished_utc': utc(), 'regression_rows': len(regression_rows),
        'performance_rows': len(performance), 'new_model_calls': 0, 'old_experiments_reexecuted': 0,
        'artifact_sha256': artifacts, 'code_hashes_unchanged': unchanged and acceptance_unchanged,
        'production_code_hashes_unchanged': unchanged, 'frozen_acceptance_code_hashes_unchanged': acceptance_unchanged, 'B_C_same_core': True,
        'gateway_regression_passes': sum(r.get('passed') is True for r in regression_rows if r['method'] == 'gateway'),
        'transaction_regression_passes': sum(r.get('passed') is True for r in regression_rows if r['method'] == 'transaction'),
        'baseline_failures_retained': True}
    save(output / 'completion.json', completion)
    if not unchanged or not acceptance_unchanged: raise RuntimeError('production or acceptance code changed during campaign')
    print(json.dumps({k: v for k, v in completion.items() if k != 'artifact_sha256'}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true'); parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', action='store_true'); parser.add_argument('--action', default='call')
    parser.add_argument('--data'); parser.add_argument('--worker-output'); parser.add_argument('--method', choices=METHODS, default='gateway')
    parser.add_argument('--transfer'); parser.add_argument('--fault', choices=('before_dml', 'before_commit'))
    parser.add_argument('--mode', default='normal', choices=('normal', 'after_commit', 'revoke', 'concurrent'))
    parser.add_argument('--shared'); parser.add_argument('--manifest')
    args = parser.parse_args()
    if args.worker: worker_main(args)
    elif args.run:
        if args.output is None: parser.error('--run requires an explicit NEW --output directory')
        campaign(args.output.resolve())
    else: parser.print_help()


if __name__ == '__main__': main()
