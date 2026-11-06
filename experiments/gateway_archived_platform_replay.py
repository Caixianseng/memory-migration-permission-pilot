"""Two explicit archived-output adapter checks, not new commercial inference.

Raw model text and normalized exports remain ONLY in the requested local out
directory. The public summary contains hashes, counts and decisions, not text,
session IDs, account information or private supplier envelopes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from agent_memory_gateway.adapters import (EXPORT_SCHEMA, import_memory_export,
                                            export_receiver_context)
from agent_memory_gateway.service import GatewayService
from experiments.persistent_exchange_v1.store import StoreError


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive-root', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    archive = Path(args.archive_root).resolve()
    target = Path(args.out).resolve()
    if target.exists():
        raise SystemExit('fresh output directory required')
    target.mkdir(parents=True)
    dataset_path = archive / 'dataset/projects.json'
    project = json.loads(dataset_path.read_text(encoding='utf-8'))['LIVE-P02']
    rows = []
    for direction, source, destination in (
            ('A_to_B', 'workbuddy', 'deepseek_harness'),
            ('B_to_A', 'deepseek_harness', 'workbuddy')):
        case = archive / 'qualification_isolated_v1' / ('LIVE-P02.' + direction + '.r0')
        local = target / direction
        local.mkdir()
        service = GatewayService(local / 'gateway')
        initial_sources = project['sources']
        legal_sources = [s for s in initial_sources if s['kind'] != 'sensitive_controlled_fact']
        all_ids = [s['source_id'] for s in initial_sources]
        legal_ids = [s['source_id'] for s in legal_sources]
        source_hashes = []
        imported = {}
        models = []
        # Existing parsed values are used without changing memory text, scoring
        # or GT. Neither phase invokes the model or rescans semantic accuracy.
        for phase, sources in (('source_initial_generation', initial_sources),
                               ('source_legal_rebuild', legal_sources)):
            result_path = case / phase / 'result.json'
            value = json.loads(result_path.read_text(encoding='utf-8'))
            if value.get('status') != 'ok':
                raise ValueError('this fixed archived adapter check requires already successful recorded output')
            memory_text = value['parsed']['scenarios']['summary']['memory_text']
            label = value['metadata']['model']
            model = ','.join(label) if isinstance(label, list) else label
            models.append(model)
            source_hashes.append({'record': phase + '/result.json', 'sha256': sha(result_path)})
            document = {'schema': EXPORT_SCHEMA, 'source_platform': source,
                'target_platform': destination, 'model': model,
                'sources': [{'source_id': s['source_id'], 'text': s['text'],
                             'source_type': 'controlled_input_record'} for s in sources],
                'memories': [{'memory_id': phase, 'content': memory_text,
                             'source_ids': [s['source_id'] for s in sources]}]}
            exported = local / (phase + '.json')
            write(exported, document)
            imported[phase] = import_memory_export(service, exported, sender_id='sender',
                expected_source_platform=source, expected_target_platform=destination)
            if phase == 'source_initial_generation':
                service.set_permissions('receiver', all_ids)
                prepared = service.prepare_transfer('sender', 'receiver',
                    imported[phase]['memory_keys'], 'old-before-revocation')
                service.set_permissions('receiver', legal_ids)
                try:
                    service.commit_transfer(prepared['transfer_id'])
                    old_blocked, reason = False, None
                except StoreError as exc:
                    old_blocked, reason = True, str(exc)
            else:
                transfer = service.prepare_transfer('sender', 'receiver',
                    imported[phase]['memory_keys'], 'legal-successor')
                receipt = service.commit_transfer(transfer['transfer_id'])
                restarted = GatewayService(local / 'gateway')
                readback = restarted.retrieve_batch('receiver', 'legal-successor')
                context_path = local / 'recipient-context.json'
                context = export_receiver_context(restarted, recipient_id='receiver',
                    batch_id='legal-successor', output=context_path,
                    source_platform=source, target_platform=destination)
                exported_context = json.loads(context_path.read_text(encoding='utf-8'))
                exact = readback['memory'] == memory_text == exported_context['memory']
                retry = restarted.commit_transfer(transfer['transfer_id'])
        rows.append({'direction': direction, 'source_platform': source,
            'target_platform': destination, 'recorded_models': models,
            'execution_mode': 'archived_real_model_output_adapter_replay',
            'new_model_calls': 0, 'old_first_delivery_blocked': old_blocked,
            'old_block_reason': reason,
            'legal_first_committed': receipt['new_persistent_acceptance'],
            'restart_exact_readback': exact,
            'retry_metadata_only': retry['metadata_only'] and not retry['new_persistent_acceptance'],
            'native_memory_imported': context['native_memory_imported'],
            'input_record_hashes': source_hashes,
            'dataset_sha256': sha(dataset_path), 'context_sha256': context['content_sha256'],
            'passed': old_blocked and exact and receipt['new_persistent_acceptance']
                and retry['status'] == 'already_committed'})
    summary = {'schema': 'archived-adapter-replay-v1', 'new_model_calls': 0,
        'not_new_commercial_execution': True, 'raw_material_stays_local': True,
        'passed': all(r['passed'] for r in rows), 'rows': rows}
    write(target / 'public_summary.json', summary)
    print(json.dumps({'passed': summary['passed'], 'directions': len(rows), 'new_model_calls': 0}))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
