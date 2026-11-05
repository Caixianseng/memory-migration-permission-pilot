"""Separate real-model probes for a second generation of exchanged memory.

The main B receiver is copied byte for byte before adding child memories. Its
imported A artifact remains the actual parent, with its immutable import proof.
Only model_runtime can produce the child prose. Mechanism source jobs receive
originals and actual parent bodies, never questions, labels or future grants.
These probes are reported separately from the twelve-case method comparison.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
import unicodedata

from .model_runtime import generate_memory
from .prepare_data import source_projection
from .read_receiver import read_batch
from .store import (AgentStore, StoreError, TrustedPolicy, canonical, digest,
                    export_package, import_package)
from experiments.revocation_grouping_v1.sdk_adapter import MODEL as FLASH_MODEL

HERE = Path(__file__).resolve().parent


def _load(path):
    return json.loads(Path(path).read_bytes())


def _need(condition, message):
    if not condition:
        raise RuntimeError(message)


def _save_once(path, value):
    """Atomic, immutable checkpoints; an interrupted call never forges prose."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value)+b'\n'
    if path.exists():
        _need(path.read_bytes() == raw, 'mechanism_checkpoint_changed:'+path.name)
        return
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _answer_receiver(*args):
    # Lazy import permits source/store-only verification before the receiver
    # runtime is frozen. This path always calls the shared actual-model runner.
    from .receiver_dispatch import answer_receiver
    return answer_receiver(*args)


def _main_parent(main_manifest, spec):
    records = [r for r in main_manifest['main_records']
               if r['case_id'] == spec['case_id']
               and r['direction'] == spec['parent']['direction']
               and r['arm'] == spec['parent']['arm']]
    _need(len(records) == 1, 'one_actual_main_parent_record_required')
    record = records[0]
    _need(record['recipient'] == 'B', 'layered_parent_must_be_imported_by_B')
    delivery = record['delivery']
    readback = read_batch(delivery['receiver_db'], delivery['batch_id'])
    _need(readback['receipt']['presented_memory_keys'] == delivery['memory_keys']
          and len(delivery['memory_keys']) == 1, 'one_imported_full_rebuild_parent_required')
    _need(readback['receipt']['sender_id'] == 'A'
          and readback['receipt']['recipient_id'] == 'B', 'actual_A_to_B_parent_required')
    _need(readback['receipt']['rendered_memory_sha256'] == delivery['reopened_content_sha256'],
          'main_parent_changed_since_delivery')
    # Bind the persisted artifact to the real source-runtime result, rather
    # than accepting arbitrary text merely because it is in a SQLite table.
    matches = []
    for path in record['source_jobs']:
        result = _load(path)
        if result['memory'] == readback['payload']['memory']:
            observed=result['evidence'].get('actual_models',[])
            requested=result['evidence'].get('request_model_ids',[])
            _need(bool(observed) and bool(requested)and set(observed+requested)<={'hy3','hy3-x'},
                  'main_parent_actual_HY3_evidence_required')
            matches.append({'path': str(Path(path).resolve()),
                            'file_sha256': digest(Path(path).read_bytes()),
                            'evidence_sha256': digest(result['evidence'])})
    _need(bool(matches), 'actual_parent_source_result_not_found')
    return record, readback, matches


def _snapshot_B(folder, main_record, parent_readback, source_evidence):
    """Keep the main database frozen, using its actual persisted B snapshot."""
    destination = folder/'stores'/'AgentB.sqlite'
    marker = folder/'parent_snapshot.json'
    source = Path(main_record['delivery']['receiver_db']).resolve()
    raw = source.read_bytes()
    _need(not Path(str(source)+'-wal').exists()
          and not Path(str(source)+'-journal').exists(), 'closed_DELETE_journal_parent_required')
    source_hash = digest(raw)
    _need(parent_readback['receipt']['database_storage_bindings']['main']['sha256'] == source_hash,
          'main_parent_changed_during_snapshot')
    if marker.exists():
        saved = _load(marker)
        _need(saved['main_receiver_db'] == str(source)
              and saved['main_database_sha256'] == source_hash
              and saved['parent_memory_keys'] == main_record['delivery']['memory_keys']
              and saved['main_source_evidence'] == source_evidence,
              'frozen_main_parent_snapshot_changed')
        _need(destination.is_file(), 'mechanism_B_snapshot_missing')
        return destination, saved
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        _need(destination.read_bytes() == raw, 'uncheckpointed_B_snapshot_changed')
    else:
        temporary = destination.with_suffix('.sqlite.tmp')
        with temporary.open('wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    _need(digest(destination.read_bytes()) == source_hash, 'B_snapshot_byte_copy_failed')
    saved = {'main_receiver_db': str(source), 'main_database_sha256': source_hash,
             'snapshot_db': str(destination.resolve()), 'initial_snapshot_sha256': source_hash,
             'byte_identical_when_created': True,
             'parent_batch_id': main_record['delivery']['batch_id'],
             'parent_memory_keys': main_record['delivery']['memory_keys'],
             'parent_logical_snapshot_sha256': parent_readback['receipt']['logical_snapshot_sha256'],
             'main_parent_read_receipt': parent_readback['receipt'],
             'main_source_evidence': source_evidence}
    _save_once(marker, saved)
    return destination, saved


def _state(store):
    """Hash every logical table without copying business text into receipts."""
    counts, hashes = {}, {}
    for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        table = row[0]
        _need(table.replace('_', '').isalnum(), 'unexpected_mechanism_table_name')
        rows = [list(r) for r in store.db.execute('SELECT * FROM '+table)]
        rows.sort(key=canonical)
        counts[table] = len(rows)
        hashes[table] = digest(rows)
    return {'row_counts': counts, 'logical_tables_sha256': digest(hashes)}


def _source_result(folder, sources, parents, source_ids):
    result_file = folder/'result.json'
    inputs = {'sources': sources, 'parent_memories': parents}
    input_hash = digest(inputs)
    if result_file.exists():
        result = _load(result_file)
        _need(result['actual_business_input_sha256'] == input_hash
              and result['source_ids'] == source_ids,
              'mechanism_completed_source_inputs_changed')
        _need(result['memory_sha256'] == digest(result['memory'].encode('utf-8')),
              'mechanism_completed_source_output_changed')
        return result
    began = time.perf_counter()
    memory, evidence = generate_memory('flash', sources, folder, parents=parents,
                                        max_output_tokens=2048)
    _need(evidence.get('actual_model') == FLASH_MODEL,
          'mechanism_actual_Flash_evidence_required')
    result = {'platform': 'flash', 'source_ids': source_ids,
              'parent_memory_keys': [p['memory_key'] for p in parents],
              'actual_business_input_sha256': input_hash,
              'memory': memory, 'memory_sha256': digest(memory.encode('utf-8')),
              'evidence': evidence, 'wall_ms': (time.perf_counter()-began)*1000}
    _save_once(result_file, result)
    return result


def _provenance(result):
    return {'generator': 'Harness-official-SDK',
            'actual_model': result['evidence']['actual_model'],
            'evidence_hash': digest(result['evidence'])}


def _initialize_policy(folder, policy, case, parent_dependencies, initial_ids):
    marker = folder/'initial_policy.json'
    if marker.exists():
        return _load(marker)
    _need(not (folder/'old.packet.json').exists()
          and not (folder/'withdrawal.json').exists(), 'initial_policy_checkpoint_missing')
    for agent in ('A', 'B'):
        policy.register_sources(case['agents'][agent]['sources'], owner_id=agent)
    own_A = [s['source_id'] for s in case['agents']['A']['sources']]
    # B owns the new sources and has already lawfully imported the A parent.
    policy.set_permissions('B', [d['source_id'] for d in parent_dependencies]+initial_ids)
    policy.set_permissions('A', own_A+initial_ids)
    value = {'epoch': policy.epoch, 'recipient': 'A', 'initial_allowed': sorted(own_A+initial_ids),
             'B_current_legal_parent_source_ids': sorted(d['source_id'] for d in parent_dependencies),
             'policy_scope': 'fresh single-host mechanism authority; main policy is untouched'}
    _save_once(marker, value)
    return value


def _check_rejections(folder, policy, sender, receiver, child, old_packet):
    marker = folder/'old_child_rejections.json'
    if marker.exists():
        previous = _load(marker)
        _need(previous['export_blocked'] and previous['import_blocked'],
              'previous_mechanism_gate_failure')
        return previous
    before = _state(receiver)
    _need(before['row_counts']['batches'] == 0 and before['row_counts']['memories'] == 0,
          'old_child_probe_requires_fresh_receiver_before_first_return')
    result = {'old_child_memory_key': child['memory_key'],
              'old_packet_sha256': old_packet['content_sha256'],
              'receiver_before': before, 'export_blocked': False, 'import_blocked': False}
    try:
        unexpected = export_package(sender, policy, 'A', [child['memory_key']],
                                    batch_id=folder.name+'-unexpected-old-export')
    except StoreError as error:
        result.update(export_blocked=True, export_rejection=str(error))
    else:
        _save_once(folder/'unexpected_authorized_old.packet.json', unexpected)
    try:
        unexpected = import_package(receiver, policy, old_packet)
    except StoreError as error:
        result.update(import_blocked=True, import_rejection=str(error))
    else:
        result['unexpected_import_receipt'] = unexpected
    result['receiver_after'] = _state(receiver)
    seal = policy.db.execute('SELECT consumed_by FROM seals WHERE import_id=?',
                             (old_packet['import_id'],)).fetchone()
    result['old_seal_consumed'] = seal is None or seal[0] is not None
    result['no_partial_receiver_writes'] = result['receiver_before'] == result['receiver_after']
    _save_once(marker, result)
    _need(result['export_blocked'] and result['import_blocked']
          and result.get('export_rejection') == 'source_not_currently_authorized_for_recipient'
          and result.get('import_rejection') == 'stale_policy_epoch'
          and result['no_partial_receiver_writes'] and not result['old_seal_consumed'],
          'layered_old_child_gate_did_not_fail_closed')
    return result


def _contains(text, value):
    normalize = lambda s: ''.join(unicodedata.normalize('NFKC', s).split())
    return normalize(str(value)) in normalize(text)


def _run_one(root, main_manifest, evaluation, case, spec):
    mid = spec['mechanism_id']
    folder = root/'mechanisms'/mid
    folder.mkdir(parents=True, exist_ok=True)
    main_record, main_readback, parent_source_evidence = _main_parent(main_manifest, spec)
    B_path, snapshot = _snapshot_B(folder, main_record, main_readback, parent_source_evidence)
    sender = AgentStore(B_path, 'B')
    receiver = policy = None
    try:
        parent_key = main_record['delivery']['memory_keys'][0]
        parent = sender.get_memory(parent_key)
        copied = read_batch(B_path, main_record['delivery']['batch_id'])
        _need(copied['receipt']['logical_snapshot_sha256'] == snapshot['parent_logical_snapshot_sha256'],
              'copied_imported_parent_changed')
        _need(parent['origin_agent'] == 'A'
              and all(d['owner_id'] == 'A' for d in parent['dependencies']),
              'parent_must_flatten_to_original_A_sources')
        initial_ids = list(spec['child_inputs'][1:])
        legal_ids = list(spec['child_rebuild_inputs'][1:])
        revoked_ids = list(spec['withdraw_before_first_return'])
        _need(len(initial_ids) == 2 and len(legal_ids) == 1 and len(revoked_ids) == 1
              and set(initial_ids) == set(legal_ids+revoked_ids), 'frozen_layered_source_split_changed')
        actual_B_originals = {s['source_id']: s for s in sender.originals()}
        for source in source_projection(case, 'B', initial_ids)['sources']:
            original = actual_B_originals.get(source['source_id'])
            _need(original is not None and original['text'] == source['text']
                  and original['version'] == source['version'], 'B_snapshot_own_original_changed')
        parent_input = [{'memory_key': parent_key, 'content': parent['content']}]
        policy = TrustedPolicy(folder/'stores'/'policy.sqlite')
        _initialize_policy(folder, policy, case, parent['dependencies'], initial_ids)
        # Read the current original dependency closure before actual source use.
        two_refs = [{'source_id': sid, 'version': actual_B_originals[sid]['version'],
                     'sha256': actual_B_originals[sid]['sha256'], 'owner_id': 'B'}
                    for sid in initial_ids]
        policy.check_dependencies('B', parent['dependencies']+two_refs)
        initial = _source_result(folder/'source_jobs'/'initial',
                                  source_projection(case, 'B', initial_ids)['sources'],
                                  parent_input, initial_ids)
        old_child = sender.add_memory(mid+'-M5-initial', initial['memory'], initial_ids,
                                      parent_memory_ids=[parent_key], provenance=_provenance(initial))
        expected_old = sorted([d['source_id'] for d in parent['dependencies']]+initial_ids)
        _need([d['source_id'] for d in old_child['dependencies']] == expected_old,
              'old_child_full_actual_input_lineage_missing')
        old_packet_path = folder/'old.packet.json'
        if not old_packet_path.exists():
            packet = export_package(sender, policy, 'A', [old_child['memory_key']],
                                    batch_id=mid+'-old-before-withdrawal')
            _save_once(old_packet_path, packet)
        old_packet = _load(old_packet_path)
        _need(old_packet['memories'][0]['artifact_sha256'] == old_child['artifact_sha256'],
              'old_mechanism_packet_artifact_changed')
        withdrawal_path = folder/'withdrawal.json'
        if not withdrawal_path.exists():
            own_A = [s['source_id'] for s in case['agents']['A']['sources']]
            epoch = policy.set_permissions('A', own_A+legal_ids)
            _save_once(withdrawal_path, {'epoch': epoch, 'recipient': 'A',
                                         'revoked': revoked_ids, 'allowed': sorted(own_A+legal_ids),
                                         'event_boundary': 'after actual child generation, before first return import'})
        withdrawal = _load(withdrawal_path)
        _need(policy.epoch == withdrawal['epoch'], 'mechanism_policy_changed_after_withdrawal')
        receiver = AgentStore(folder/'stores'/'AgentA.sqlite', 'A')
        for source in case['agents']['A']['sources']:
            receiver.add_original(source['source_id'], source['text'], source['version'], source['origin'])
        own = receiver.originals()
        _need(len(own) == len(case['agents']['A']['sources'])
              and all(s['owner_id'] == 'A' for s in own), 'fresh_A_must_contain_only_own_originals')
        rejections = _check_rejections(folder, policy, sender, receiver, old_child, old_packet)
        legal_refs = [d for d in two_refs if d['source_id'] in legal_ids]
        policy.check_dependencies('B', parent['dependencies']+legal_refs)
        rebuilt = _source_result(folder/'source_jobs'/'rebuild',
                                  source_projection(case, 'B', legal_ids)['sources'],
                                  parent_input, legal_ids)
        new_child = sender.add_memory(mid+'-M5-rebuilt', rebuilt['memory'], legal_ids,
                                      parent_memory_ids=[parent_key], provenance=_provenance(rebuilt))
        expected_new = sorted([d['source_id'] for d in parent['dependencies']]+legal_ids)
        _need([d['source_id'] for d in new_child['dependencies']] == expected_new
              and not set(revoked_ids) & set(expected_new), 'rebuilt_child_lineage_is_not_current_legal_closure')
        policy.check_dependencies('A', new_child['dependencies'], withdrawal['epoch'])
        packet_path = folder/'rebuilt.packet.json'
        if not packet_path.exists():
            _save_once(packet_path, export_package(sender, policy, 'A', [new_child['memory_key']],
                                                   batch_id=mid+'-fresh-return'))
        packet = _load(packet_path)
        _need(packet['memories'][0]['artifact_sha256'] == new_child['artifact_sha256'],
              'rebuilt_mechanism_packet_artifact_changed')
        receipt_path = folder/'import_receipt.json'
        existing = receiver.db.execute('SELECT import_id FROM batches WHERE batch_id=?',
                                        (packet['batch_id'],)).fetchone()
        if existing is None:
            receipt = import_package(receiver, policy, packet)
            _save_once(receipt_path, receipt)
        else:
            _need(existing['import_id'] == packet['import_id'], 'mechanism_return_import_changed')
            if receipt_path.exists():
                receipt = _load(receipt_path)
            else:
                # Import committed before a process interruption; reconstruct
                # only its receipt from the actual batch, never replay import.
                row = receiver.db.execute('SELECT * FROM batches WHERE batch_id=?',
                                           (packet['batch_id'],)).fetchone()
                receipt = {'status': 'imported', 'batch_id': row['batch_id'], 'import_id': row['import_id'],
                           'sender_id': row['sender_id'], 'recipient_id': row['recipient_id'],
                           'policy_epoch': row['epoch'], 'packet_sha256': row['packet_sha256'],
                           'import_event_hash': row['import_event_hash'], 'memory_keys': [new_child['memory_key']],
                           'receiver_db': str(receiver.path), 'receipt_recovered_from_committed_database': True}
                _save_once(receipt_path, receipt)
        _need(receiver.db.execute('SELECT COUNT(*) FROM batches').fetchone()[0] == 1
              and receiver.db.execute('SELECT COUNT(*) FROM memories').fetchone()[0] == 1,
              'fresh_A_must_expose_only_the_new_child_batch')
        A_path, policy_path = receiver.path, policy.path
        receiver.close(); receiver = None
        sender.close(); sender = None
        readback = read_batch(A_path, packet['batch_id'])
        _need(readback['payload']['memory'] == rebuilt['memory']
              and readback['receipt']['presented_memory_keys'] == [new_child['memory_key']],
              'mechanism_persistent_return_readback_changed')
        policy.check_dependencies('A', new_child['dependencies'], withdrawal['epoch'])
        policy.close(); policy = None
        # Questions are projected only now, after both actual source calls.
        references = evaluation['_mechanisms'][mid]['questions']
        questions = [{'question_id': q['question_id'], 'question': q['question']} for q in references]
        job_dir = folder/'receiver_job'
        answers, receiver_evidence = _answer_receiver('hy3', A_path, packet['batch_id'], questions, job_dir)
        evidence_checks = []
        for question in references:
            evidence_checks.append({'question_id': question['question_id'],
                'primary_eligible': question['primary_eligible'],
                'all_reference_values_in_return_memory': all(_contains(rebuilt['memory'], value)
                                                               for value in question['required_values']),
                'any_reference_value_in_return_memory': any(_contains(rebuilt['memory'], value)
                                                              for value in question['required_values'])})
        result = {'mechanism_id': mid, 'case_id': spec['case_id'], 'direction': 'B_to_A',
            'arm': 'layered_rebuild', 'recipient': 'A', 'receiver_platform': 'hy3', 'job_dir': str(job_dir),
            'answers': answers, 'receiver_evidence': receiver_evidence,
            'source_jobs': [str(folder/'source_jobs'/phase/'result.json') for phase in ('initial', 'rebuild')],
            'delivery': {'receiver_db': str(A_path), 'batch_id': packet['batch_id'],
                         'memory_keys': [new_child['memory_key']], 'policy_db': str(policy_path),
                         'policy_epoch': withdrawal['epoch'], 'dependencies': new_child['dependencies'],
                         'receipt': receipt, 'packet_path': str(packet_path),
                         'reopened_content_sha256': readback['receipt']['rendered_memory_sha256'],
                         'close_reopen_verified': True},
            'mechanism_evidence': {'snapshot': snapshot, 'parent_memory_key': parent_key,
                'parent_artifact_sha256': parent['artifact_sha256'], 'parent_dependencies': parent['dependencies'],
                'old_child_memory_key': old_child['memory_key'], 'old_child_dependencies': old_child['dependencies'],
                'new_child_memory_key': new_child['memory_key'], 'new_child_dependencies': new_child['dependencies'],
                'revoked_source_ids': revoked_ids, 'old_child_rejections': rejections,
                'fresh_A_own_originals_only': True, 'fresh_A_imported_batches': 1, 'fresh_A_imported_artifacts': 1,
                'reopened_read_receipt': readback['receipt'],
                'reference_values_scan_after_model_calls': evidence_checks,
                'main_database_sha256_unchanged': digest(Path(main_record['delivery']['receiver_db']).read_bytes())
                                                    == snapshot['main_database_sha256'],
                'cost_scope': 'separate mechanism probe; excluded from main twelve-case cost and utility comparisons',
                'planned_additional_Flash_source_calls': 2, 'planned_additional_HY3_receiver_tasks': 1,
                'original_dependencies_flattened_without_ancestor_plaintext_transfer': True}}
        result_path = folder/'result.json'
        if result_path.exists():
            completed = _load(result_path)
            _need(completed['delivery'] == result['delivery']
                  and completed['answers'] == answers
                  and completed['mechanism_evidence']['new_child_dependencies'] == new_child['dependencies'],
                  'completed_mechanism_result_changed')
            return completed
        _save_once(result_path, result)
        # JSON receipts use arrays. Return the same normalized value on the
        # first run and resume (the reader's in-memory SQL parameters include
        # a tuple which otherwise becomes a list only after serialization).
        return _load(result_path)
    finally:
        for resource in (receiver, sender, policy):
            if resource is not None:
                resource.close()


def run_mechanisms(root, main_manifest, evaluation):
    """Run the two registered actual-model layered probes and return records.

    ``root`` is the main result directory. ``main_manifest`` is the frozen
    run_study manifest (``cases`` and ``main_records``). ``evaluation`` is used
    only to project two public receiver questions after all source generation.
    Cached verified runtime artifacts allow interruption recovery without paid
    resubmission; changed inputs or unexplained database states stop the probe.
    """
    root = Path(root).resolve()
    _need(Path(main_manifest['root']).resolve() == root, 'main_manifest_result_root_mismatch')
    contract = _load(HERE/'data'/'contract.json')
    for filename in ('mechanism_spec.json', 'cases.public.jsonl', 'evaluation_only.json'):
        _need(digest((HERE/'data'/filename).read_bytes()) == contract['artifact_sha256'][filename],
              'frozen_mechanism_material_changed:'+filename)
    _need(digest(evaluation) == digest(_load(HERE/'data'/'evaluation_only.json')),
          'mechanism_evaluation_does_not_match_frozen_material')
    specs = _load(HERE/'data'/'mechanism_spec.json')['mechanisms']
    cases = {case['case_id']: case for case in
             (json.loads(line) for line in (HERE/'data'/'cases.public.jsonl').read_text(encoding='utf-8').splitlines())}
    _need(len(specs) == 2, 'exactly_two_registered_layered_probes_required')
    manifest_cases = {case['case_id']: case for case in main_manifest['cases']}
    records = []
    for spec in specs:
        case = cases[spec['case_id']]
        _need(manifest_cases[case['case_id']]['origins'] == case['agents'],
              'mechanism_main_originals_do_not_match_frozen_case')
        records.append(_run_one(root, main_manifest, evaluation, case, spec))
    _save_once(root/'mechanisms'/'records.json', records)
    return records


__all__ = ['run_mechanisms']
