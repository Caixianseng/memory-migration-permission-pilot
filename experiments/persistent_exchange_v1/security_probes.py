"""Zero-model, read-only audits of actual persisted experiment artifacts.

Old generated memories are inspected offline and are never newly delivered.
Permission checks use read-only SQLite connections; packet attacks run solely
against disposable copies of the trusted authority and new receiver databases.
They are mechanism evidence, separate from the main model-quality comparison.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unicodedata

from .store import (AgentStore, TrustedPolicy, StoreError, canonical, digest,
                    import_package, SCHEMA)

HERE = Path(__file__).resolve().parent
_DIRECTIONS = ('A_to_B', 'B_to_A')


def _need(condition, code):
    if not condition:
        raise RuntimeError(code)


def _load(path):
    return json.loads(Path(path).read_bytes())


def _ro(path):
    """No schema-creating AgentStore/TrustedPolicy constructor touches main DBs."""
    path = Path(path).resolve(strict=True)
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True,
                         timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    # Defense in depth: even an accidental later call cannot write or ATTACH.
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
               sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_FUNCTION}
    db.set_authorizer(lambda action, *unused:
                      sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
    return path, db


class _ReadOnlyStore(AgentStore):
    def __init__(self, path, agent):
        self.path, self.db = _ro(path)
        self.agent_id = agent
        try:
            metadata = dict(self.db.execute('SELECT key,value FROM metadata'))
            _need(metadata.get('agent_id') == agent
                  and metadata.get('schema_version') == SCHEMA,
                  'security_probe_source_store_identity_mismatch')
        except BaseException:
            self.db.close()
            raise


class _ReadOnlyPolicy(TrustedPolicy):
    def __init__(self, path):
        self.path, self.db = _ro(path)


def _binding(path):
    path = Path(path).resolve()
    return {'path': str(path), 'exists': path.is_file(),
            'sha256': digest(path.read_bytes()) if path.is_file() else None,
            'bytes': path.stat().st_size if path.is_file() else None}


def _watch(watched, path, database=False):
    suffixes = ('', '-wal', '-shm', '-journal') if database else ('',)
    for suffix in suffixes:
        target = Path(str(Path(path).resolve())+suffix)
        watched.setdefault(str(target), _binding(target))


def _source_refs(records, owner):
    return sorted([{'source_id': s['source_id'], 'version': s.get('version', 1),
                    'sha256': digest(s['text'].encode('utf-8')), 'owner_id': owner}
                   for s in records], key=lambda s: s['source_id'])


def _normalized(value):
    return ''.join(unicodedata.normalize('NFKC', str(value)).split())


def _whole_permission_probe(root, case, direction, evaluation, watched):
    sender, recipient = direction.split('_to_')
    cid = case['case_id']
    source_file = root/'source_jobs'/cid/sender/'initial'/'whole'/'result.json'
    sender_file = Path(case['case_dir'])/(sender+'.sqlite')
    policy_file = Path(case['case_dir'])/'policy.sqlite'
    _watch(watched, source_file)
    _watch(watched, sender_file, database=True)
    _watch(watched, policy_file, database=True)
    result = _load(source_file)
    records = case['origins'][sender]['sources']
    expected_refs = _source_refs(records, sender)
    expected_ids = [r['source_id'] for r in expected_refs]
    _need(set(result['source_ids']) == set(expected_ids)
          and len(result['source_ids']) == len(expected_ids),
          'security_probe_actual_initial_input_binding_mismatch')
    reference = evaluation[cid][direction]
    event = reference['event']
    _need(event['sender'] == sender and event['recipient'] == recipient,
          'security_probe_permission_reference_identity_mismatch')
    source_evidence = result['evidence']
    protocol_conformance = source_evidence.get('source_protocol_conformance', True)
    mock_only = source_evidence.get('mock_only', False) is True
    identity_verified = (source_evidence.get('actual_models') == ['hy3']
                         if sender == 'A' else
                         source_evidence.get('actual_model') == 'deepseek-flash')
    item = {'case_id': cid, 'direction': direction, 'sender': sender, 'recipient': recipient,
            'source_result_path': str(source_file.resolve()),
            'source_result_sha256': digest(source_file.read_bytes()),
            'source_evidence_sha256': digest(source_evidence),
            'source_protocol_conformance': protocol_conformance,
            'source_protocol_conformance_explicit': 'source_protocol_conformance' in source_evidence,
            'source_model_identity_verified': identity_verified and not mock_only,
            'mock_only_source_fixture': mock_only,
            'source_tool_compliance_is_separate_from_permission_result': True,
            'revoked_source_count': len(event['revoked']),
            'expected_permission_result': 'rejected' if event['revoked'] else 'allowed',
            'actual_generated_memory_available': isinstance(result.get('memory'), str)
                                                 and bool(result['memory']),
            'new_export_or_import_performed_on_main_state': False}
    policy = _ReadOnlyPolicy(policy_file)
    store = _ReadOnlyStore(sender_file, sender)
    try:
        epoch = policy.epoch
        _need(epoch == case['policy_epoch'], 'security_probe_main_policy_epoch_changed')
        own_ids = [s['source_id'] for s in case['origins'][recipient]['sources']]
        current_grants = sorted(r[0] for r in policy.db.execute(
            'SELECT source_id FROM grants WHERE recipient_id=?', (recipient,)))
        _need(current_grants == sorted(set(own_ids+event['allowed'])),
              'security_probe_current_grants_differ_from_registered_withdrawal')
        # Verify the sender's original text/version/hash, not just an asserted
        # dependency list or a source-ID naming convention.
        actual = [dict(row) for row in store.db.execute(
            'SELECT source_id,version,text,sha256,owner_id FROM originals ORDER BY source_id,version')]
        actual_refs = []
        for source in actual:
            _need(source['sha256'] == digest(source['text'].encode('utf-8')),
                  'security_probe_original_body_hash_mismatch')
            actual_refs.append({k: source[k] for k in ('source_id', 'version', 'sha256', 'owner_id')})
        _need(actual_refs == expected_refs, 'security_probe_complete_sender_original_binding_mismatch')
        item.update(policy_epoch=epoch, sender_original_bindings_verified=True,
                    expected_original_binding_sha256=digest(expected_refs))
        if item['actual_generated_memory_available']:
            key = case['artifacts'][sender]['whole']['memory_key']
            artifact = store.get_memory(key)
            _need(artifact['content'] == result['memory']
                  and artifact['dependencies'] == expected_refs
                  and artifact['direct_sources'] == expected_refs
                  and not artifact['parents'], 'security_probe_actual_whole_artifact_binding_mismatch')
            item.update(memory_key=key, content_sha256=artifact['content_sha256'],
                        artifact_sha256=artifact['artifact_sha256'],
                        full_original_dependency_binding_verified=True)
            try:
                checked_epoch = policy.check_dependencies(recipient, artifact['dependencies'], epoch)
            except StoreError as error:
                item.update(permission_result='rejected', rejection_reason=str(error))
            else:
                item.update(permission_result='allowed', checked_epoch=checked_epoch, rejection_reason=None)
            item['matches_expected_permission_result'] = (
                item['permission_result'] == item['expected_permission_result']
                and (not event['revoked'] or item['rejection_reason']
                     == 'source_not_currently_authorized_for_recipient'))
        else:
            _need(source_evidence.get('source_protocol_conformance') is False,
                  'security_probe_unexplained_missing_initial_whole')
            item.update(permission_result='unavailable_no_generated_initial_whole',
                        rejection_reason=None, matches_expected_permission_result=None,
                        full_original_dependency_binding_verified=False)
        _need(policy.epoch == epoch, 'security_probe_read_only_permission_check_changed_epoch')
        probes = []
        for question in reference['questions']:
            if not question.get('unique_value_abstention_provable_in_fixture'):
                continue
            _need(not question['primary_eligible']
                  and set(question['support_ids']) <= set(event['revoked'])
                  and len(question['required_values']) == 1,
                  'security_probe_requires_frozen_unique_withdrawn_value')
            value = question['required_values'][0]
            present = (_normalized(value) in _normalized(result['memory'])
                       if item['actual_generated_memory_available'] else None)
            probes.append({'question_id': question['question_id'],
                           'support_source_ids': question['support_ids'],
                           'reference_value_sha256': digest(str(value).encode('utf-8')),
                           'scan_available': item['actual_generated_memory_available'],
                           'offline_potential_exposure': present,
                           'never_delivered_by_this_probe': True})
        item['unique_withdrawn_value_scans'] = probes
        return item
    finally:
        policy.close()
        store.close()


def _logical_state(store):
    counts, bindings = {}, {}
    tables = [r[0] for r in store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    for name in tables:
        _need(name.replace('_', '').isalnum(), 'security_probe_unexpected_table_name')
        rows = [list(row) for row in store.db.execute('SELECT * FROM '+name)]
        rows.sort(key=canonical)
        counts[name] = len(rows)
        bindings[name] = digest(rows)
    return {'row_counts': counts, 'logical_state_sha256': digest(bindings)}


def _attempt(name, receiver, policy, packet, expected_error):
    before = _logical_state(receiver)
    try:
        receipt = import_package(receiver, policy, packet)
    except StoreError as error:
        result = {'probe': name, 'rejected': True, 'reason': str(error)}
    else:
        result = {'probe': name, 'rejected': False, 'reason': None,
                  'unexpected_import_id': receipt['import_id']}
    after = _logical_state(receiver)
    result.update(expected_reason=expected_error, receiver_state_before=before,
                  receiver_state_after=after, no_partial_receiver_writes=before == after,
                  isolated_copy_only=True, model_invocations=0)
    result['passed'] = (result['rejected'] and result['reason'] == expected_error
                        and result['no_partial_receiver_writes'])
    return result


def _approved_packet_record(manifest, cid, direction):
    candidates = [r for r in manifest['main_records']
                  if r['case_id'] == cid and r['direction'] == direction]
    # The lawful raw arm is always nonempty in the registered <=50% mask and
    # avoids depending on whether a model-generated arm failed its tool audit.
    ordered = sorted(candidates, key=lambda r: (r['arm'] != 'raw', r['arm']))
    for record in ordered:
        if record['delivery'].get('memory_keys'):
            return record
    return None


def _packet_attacks(temporary, case, direction, manifest, watched):
    cid = case['case_id']
    selected = _approved_packet_record(manifest, cid, direction)
    if selected is None:
        return {'case_id': cid, 'direction': direction, 'available': False,
                'reason': 'no_approved_nonempty_packet', 'probes': []}
    delivery = selected['delivery']
    policy_path = Path(delivery['policy_db']).resolve()
    packet_path = Path(delivery['packet_path']).resolve()
    receiver_path = Path(delivery['receiver_db']).resolve()
    for path, is_database in ((policy_path, True), (packet_path, False), (receiver_path, True)):
        _watch(watched, path, database=is_database)
    raw = packet_path.read_bytes()
    _need(digest(raw) == delivery['packet_file_sha256'], 'security_probe_approved_packet_file_changed')
    packet = json.loads(raw)
    _need(packet['content_sha256'] == digest({k: v for k, v in packet.items() if k != 'content_sha256'})
          and packet['batch_id'] == delivery['batch_id']
          and [a['memory_key'] for a in packet['memories']] == delivery['memory_keys'],
          'security_probe_approved_packet_binding_mismatch')
    _, receiver_db = _ro(receiver_path)
    policy = _ReadOnlyPolicy(policy_path)
    try:
        seal = policy.db.execute('SELECT * FROM seals WHERE import_id=?', (packet['import_id'],)).fetchone()
        _need(seal is not None and seal['consumed_by'] == packet['recipient_id']
              and seal['packet_sha256'] == packet['content_sha256']
              and all(seal[k] == packet[k] for k in
                      ('nonce', 'batch_id', 'sender_id', 'recipient_id', 'epoch')),
              'security_probe_approved_nonce_not_consumed_or_binding_changed')
        batch = receiver_db.execute('SELECT * FROM batches WHERE batch_id=?', (packet['batch_id'],)).fetchone()
        _need(batch is not None
              and all(batch[k] == packet[k] for k in ('batch_id', 'import_id', 'sender_id', 'recipient_id', 'epoch'))
              and batch['packet_sha256'] == packet['content_sha256'],
              'security_probe_actual_import_receipt_missing')
        _need(policy.epoch == packet['epoch'] == delivery['policy_epoch'],
              'security_probe_approved_packet_current_epoch_changed')
    finally:
        policy.close()
        receiver_db.close()
    folder = Path(temporary)/(cid+'-'+direction)
    folder.mkdir(parents=True)
    clone_path = folder/'policy-copy.sqlite'
    clone_raw = policy_path.read_bytes()
    clone_path.write_bytes(clone_raw)
    _need(digest(clone_path.read_bytes()) == digest(clone_raw)
          and clone_path.resolve().is_relative_to(Path(temporary).resolve()),
          'security_probe_authority_copy_failed')
    clone = TrustedPolicy(clone_path)
    receiver = AgentStore(folder/'fresh-receiver.sqlite', packet['recipient_id'])
    wrong = AgentStore(folder/'wrong-recipient.sqlite', 'security-probe-wrong-recipient')
    try:
        replay = _attempt('consumed_nonce_replay', receiver, clone, deepcopy(packet),
                          'transfer_replay_rejected')
        # A consumed nonce would mask the later content-binding check. Rearm
        # only this disposable authority copy to isolate that independent gate;
        # no original seal or real receiver is altered and no packet is sent.
        clone.db.execute('UPDATE seals SET consumed_by=NULL WHERE import_id=?', (packet['import_id'],))
        forged = deepcopy(packet)
        artifact = forged['memories'][0]
        artifact['content'] += '\nSECURITY-PROBE-ALTERED-CONTENT'
        artifact['content_sha256'] = digest(artifact['content'].encode('utf-8'))
        artifact['artifact_sha256'] = digest({k: v for k, v in artifact.items() if k != 'artifact_sha256'})
        node = next(n for n in forged['lineage'] if n['memory_key'] == artifact['memory_key'])
        node.update(content_sha256=artifact['content_sha256'], artifact_sha256=artifact['artifact_sha256'])
        forged['content_sha256'] = digest({k: v for k, v in forged.items() if k != 'content_sha256'})
        tamper = _attempt('content_tamper_with_recomputed_internal_hashes', receiver, clone, forged,
                          'trusted_packet_seal_mismatch')
        tamper['disposable_clone_nonce_rearmed_to_isolate_content_binding'] = True
        wrong_recipient = _attempt('wrong_recipient', wrong, clone, deepcopy(packet),
                                   'packet_recipient_or_schema_invalid')
        return {'case_id': cid, 'direction': direction, 'available': True,
                'approved_arm': selected['arm'], 'approved_packet_path': str(packet_path),
                'approved_packet_file_sha256': digest(raw), 'approved_packet_sha256': packet['content_sha256'],
                'approved_import_id': packet['import_id'], 'original_nonce_already_consumed': True,
                'original_import_receipt_verified': True, 'clone_initially_byte_identical_to_main_policy': True,
                'all_attacks_use_disposable_policy_and_receiver_copies': True,
                'probes': [replay, tamper, wrong_recipient]}
    finally:
        wrong.close()
        receiver.close()
        clone.close()


def _save_report(path, report):
    normalized = json.loads(canonical(report))
    if path.exists():
        _need(_load(path) == normalized, 'security_probe_report_inputs_or_outcomes_changed')
        return _load(path)
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('wb') as stream:
        stream.write(canonical(normalized)+b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    return normalized


def run_security_probes(root, manifest, evaluation):
    """Audit after all main model runs; no new model call or real delivery.

    Reads only supplied main result JSON, sender originals/whole artifacts,
    current permissions and selected approved import receipts/packets. It does
    not access supplier credential directories or any other native session.
    """
    root = Path(root).resolve(strict=True)
    _need(Path(manifest['root']).resolve() == root, 'security_probe_manifest_root_mismatch')
    cases = manifest['cases']
    _need(len({c['case_id'] for c in cases}) == len(cases), 'security_probe_duplicate_cases')
    watched, permissions, attacks = {}, [], []
    for case in cases:
        for direction in _DIRECTIONS:
            permissions.append(_whole_permission_probe(root, case, direction, evaluation, watched))
    with tempfile.TemporaryDirectory(prefix='security-probes-', dir=root) as temporary:
        for case in cases:
            for direction in _DIRECTIONS:
                attacks.append(_packet_attacks(temporary, case, direction, manifest, watched))
    after = {path: _binding(path) for path in watched}
    unchanged = all(after[path] == before for path, before in watched.items())
    _need(unchanged, 'security_probe_main_artifact_changed_during_read_only_audit')
    checked = [p for p in permissions if p['matches_expected_permission_result'] is not None]
    scans = [q for p in permissions for q in p['unique_withdrawn_value_scans']]
    attack_rows = [p for a in attacks for p in a['probes']]
    nonzero = [p for p in permissions if p['revoked_source_count']]
    zero = [p for p in permissions if not p['revoked_source_count']]
    report = {'schema': 'persistent-exchange-offline-security-probes-v1',
        'root': str(root), 'model_invocations': 0, 'new_real_deliveries': 0,
        'scope': 'offline mechanism evidence; excluded from twelve-project main quality/cost statistics',
        'old_whole_permission_checks': permissions, 'approved_packet_copy_attacks': attacks,
        'summary': {'project_clusters': len(cases), 'permission_views': len(permissions),
            'registered_expected_project_clusters': 12, 'registered_expected_permission_views': 24,
            'all_registered_views_present': len(cases) == 12 and len(permissions) == 24,
            'nonzero_revocation_views': len(nonzero), 'zero_revocation_views': len(zero),
            'generated_whole_checks_available': len(checked),
            'unavailable_generated_whole_views': len(permissions)-len(checked),
            'nonzero_old_whole_rejected': sum(p.get('permission_result') == 'rejected' for p in nonzero),
            'zero_old_whole_allowed_by_permission_check': sum(p.get('permission_result') == 'allowed' for p in zero),
            'all_available_whole_permission_results_as_expected': all(p['matches_expected_permission_result'] for p in checked),
            'source_protocol_nonconformant_views': sum(p['source_protocol_conformance'] is False for p in permissions),
            'mock_only_source_fixture_views': sum(p['mock_only_source_fixture'] for p in permissions),
            'unique_withdrawn_value_questions': len(scans),
            'unique_withdrawn_value_scans_available': sum(q['scan_available'] for q in scans),
            'offline_potential_exposure_questions': sum(q['offline_potential_exposure'] is True for q in scans),
            'offline_potential_exposure_is_actual_delivery_leakage': False,
            'approved_packets_available': sum(a['available'] for a in attacks),
            'copy_attack_attempts': len(attack_rows),
            'copy_attacks_rejected_as_expected': sum(a['passed'] for a in attack_rows),
            'all_available_copy_attacks_passed': all(a['passed'] for a in attack_rows),
            'all_main_inputs_byte_unchanged': unchanged},
        'read_only_main_input_bindings': [watched[path] for path in sorted(watched)],
        'main_SQLite_access': {'uri_mode': 'ro', 'query_only': True,
            'SQL_authorizer_rejects_write_DDL_and_ATTACH': True,
            'main_policy_check_method': 'TrustedPolicy.check_dependencies inherited by read-only adapter',
            'main_policy_epochs_unchanged': True,
            'schema_creating_main_store_or_policy_constructors_used': False},
        'interpretation': {'offline_potential_exposure': 'a frozen unique withdrawn value occurs in an old generated whole artifact inspected offline; this probe never exports or delivers it',
            'permission_and_tool_compliance': 'a permission-allowed zero-revocation artifact may independently fail the source tool audit; the two results are kept separate',
            'copy_attack_scope': 'local trusted-host import guards on copies of actual approved packets; no distributed transaction, remote model attestation or prior-plaintext erasure claim',
            'content_binding_probe_setup': 'only a disposable policy copy has its already-consumed nonce rearmed to avoid replay rejection masking the independent trusted content-binding guard'}}
    return _save_report(root/'security_probes.json', report)


__all__ = ['run_security_probes']
