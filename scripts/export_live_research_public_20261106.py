"""Export a bounded, credential-free projection of the saved live experiments.

Only named result/contract/output files are read. No client, SDK, model or
database is opened. Historical files are immutable inputs. The default output
is a NEW staging bundle; this script does not publish or modify Git branches.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / 'research_paper_v1/paper_live_v2'
DEFAULT_OUTPUT = ROOT / '_local/publication_20261106/staging/benchmarks/live_research_public_20261106'
RECOVERIES = ('safe_predispatch_retry', 'safe_precreation_retry')
JOB_NAMES = ('source_initial_generation', 'source_legal_rebuild',
    'receiver_initial_raw', 'receiver_initial_summary', 'receiver_initial_multi_source',
    'receiver_legal_successor_raw', 'receiver_legal_successor_summary',
    'receiver_legal_successor_multi_source')
META = frozenset(('platform', 'model', 'actual_model', 'actual_models', 'request_models',
    'request_model_ids', 'provider', 'app_version', 'backend_build', 'backend_build_independently_verified',
    'desktop_bridge_used', 'physical_supplier_calls', 'physical_supplier_requests',
    'actual_cost_cny', 'estimated_cost_cny', 'estimate_is_invoice', 'usage', 'tool_calls',
    'native_user_prompts', 'native_helper_job_type', 'experiment_role',
    'complete_upstream_system_input_observed', 'serialization_adapter', 'receipt'))
RECEIPT = frozenset(('actual_model', 'provider', 'status', 'input_tokens', 'output_tokens',
    'input_total_tokens', 'input_uncached_tokens', 'cache_hit_input_tokens', 'cache_read_tokens',
    'cache_write_tokens', 'cache_write_price_known', 'input_tokens_semantics', 'usage', 'usage_schema',
    'latency_seconds', 'physical_request_count', 'physical_request_evidence',
    'estimated_peak_cost_cny', 'estimated_cache_aware_peak_cost_cny',
    'estimated_cache_aware_offpeak_cost_cny', 'cost_is_supplier_bill', 'price_source',
    'price_verified_date', 'business_messages_sha256', 'request_sha256', 'response_sha256',
    'dispatch_sha256', 'temporary_credentials_removed'))
RESULT = frozenset(('status', 'error', 'type', 'parsed', 'started_unix', 'elapsed_seconds',
    'queue_seconds', 'inference_wall_seconds', 'end_to_end_seconds', 'inference_seconds',
    'prompt_sha256', 'output_sha256', 'automatic_retry', 'raw_output_retained',
    'format_recovery', 'format_adapter', 'human_confirmed', 'business_input_utf8_sha256'))
FORBIDDEN_KEYS = frozenset(('session_id', 'sessionId', 'original_session_id', 'request_id', 'requestId',
    'account_id', 'accountId', 'user_id', 'userId', 'chat_id', 'chatId', 'conversation_id',
    'conversationId', 'thread_id', 'threadId', 'nativeHistoryPath', 'history_path', 'record_path',
    'evidence_path', 'workspace', 'cliElectronPath', 'workbuddyConfigDir', 'cdpPort',
    'sdk_ledger_pointer', 'sdk_ledger_location', 'api_key', 'apiKey', 'access_token',
    'refresh_token', 'authorization', 'cookie', 'password', 'secret', 'credentials',
    'registered_own_session_metadata', 'original_failure_path', 'private_records_do_not_publish'))
UUID = re.compile(r'(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b')
WINDOWS_PATH = re.compile(r'(?i)\b[a-z]:[\\/][^\s"\'<>\r\n]*')
SECRET = re.compile(r'(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?i:bearer\s+[A-Za-z0-9._~-]{24,})')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       separators=(',', ':')) + '\n').encode('utf-8')


def clean_text(text):
    original = text
    # Repository-owned references become relative references, not invented data.
    for prefix in (str(ROOT), ROOT.as_posix()):
        text = text.replace(prefix, '{REPO}')
    text = WINDOWS_PATH.sub('[LOCAL_PATH_REDACTED]', text)
    text = re.sub(r'(?i)/(?:Users|home)/[^/\s"\']+(?:/[^\s"\']*)?', '[USER_PATH_REDACTED]', text)
    text = UUID.sub('[NATIVE_IDENTIFIER_REDACTED]', text)
    if SECRET.search(text):
        raise ValueError('credential-shaped text in selected public field; export stopped')
    return text, text != original


def project(value):
    if isinstance(value, str):
        return clean_text(value)[0]
    if isinstance(value, list):
        return [project(v) for v in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in FORBIDDEN_KEYS:
                continue
            if key in ('source_model_metadata', 'receiver_model_metadata', 'metadata'):
                if key == 'source_model_metadata' and isinstance(item, dict):
                    result[key] = {k: metadata(v) for k, v in item.items()}
                else:
                    result[key] = metadata(item)
            else:
                result[clean_text(key)[0]] = project(item)
        return result
    return value


def metadata(value):
    if not isinstance(value, dict):
        return None
    result = {}
    for key in sorted(META & value.keys()):
        if key == 'receipt':
            receipt = value[key]
            result[key] = project({k: receipt[k] for k in RECEIPT & receipt.keys()}) if isinstance(receipt, dict) else None
        else:
            result[key] = project(value[key])
    return result


class Export:
    def __init__(self):
        self.sources = {}
        self.files = {}
        self.raw_outputs = []
        self.attempts = []
        self.text_redactions = []

    def read(self, path):
        path = path.resolve(strict=True)
        if not path.is_relative_to(LIVE.resolve()):
            raise ValueError('source outside the declared experiment')
        relative = path.relative_to(ROOT).as_posix()
        parts = path.relative_to(LIVE).parts
        if any('private' in part.casefold() or part in ('sdk_records', 'native', '__pycache__') for part in parts):
            raise ValueError('private/native ledger source forbidden')
        if path.suffix not in ('.json', '.jsonl', '.md', '.txt'):
            raise ValueError('unsupported source file')
        raw = path.read_bytes()
        self.sources[relative] = {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}
        return json.loads(raw) if path.suffix == '.json' else raw.decode('utf-8-sig')

    def add(self, name, value, jsonl=False):
        if name in self.files:
            raise ValueError('duplicate public filename')
        self.files[name] = b''.join(encode(v) for v in value) if jsonl else encode(value)

    def text(self, text, declared_sha=None, job_id=None):
        if not isinstance(text, str):
            raise ValueError('raw model output is not text')
        raw_sha = sha(text.encode('utf-8'))
        if declared_sha is not None and declared_sha != raw_sha:
            raise ValueError('raw model text hash mismatch at public job ' + str(job_id))
        public_text, changed = clean_text(text)
        row = {'text': public_text, 'original_text_utf8_sha256': raw_sha,
               'public_text_utf8_sha256': sha(public_text.encode('utf-8')),
               'public_text_is_byte_equal_to_original': not changed,
               'redacted_for_publication': changed}
        if job_id:
            self.raw_outputs.append({'job_id': job_id, **{k: v for k, v in row.items() if k != 'text'}})
        if changed:
            self.text_redactions.append({'job_id': job_id, 'original_sha256': raw_sha})
        return row

    def attempt(self, job, study, logical_job_id=None):
        job_id = job.relative_to(LIVE).as_posix()
        row = {'public_job_id': job_id, 'logical_job_id': logical_job_id or job_id,
               'study': study, 'source_files': []}
        for name in ('contract.json', 'intent.json', 'result.json', 'local_parse_recovery.json',
                     'predispatch_failure_inspection.json', 'precreation_failure_inspection.json',
                     'account_predispatch_failure_inspection.json'):
            path = job / name
            if not path.is_file():
                continue
            value = self.read(path)
            row['source_files'].append(path.relative_to(ROOT).as_posix())
            if name in ('result.json', 'local_parse_recovery.json'):
                selected = {k: value[k] for k in RESULT & value.keys()}
                if 'metadata' in value:
                    selected['metadata'] = metadata(value['metadata'])
                row[name.removesuffix('.json')] = project(selected)
            else:
                row[name.removesuffix('.json')] = project(value)
                if name == 'contract.json' and isinstance(value.get('prompt'), str):
                    changed = clean_text(value['prompt'])[1]
                    row['contract_prompt_publication'] = {
                        'original_prompt_sha256': sha(value['prompt'].encode('utf-8')),
                        'public_prompt_sha256': sha(row['contract']['prompt'].encode('utf-8')),
                        'public_prompt_byte_equal': not changed}
        path = job / 'raw_output.json'
        if path.is_file():
            value = self.read(path)
            row['source_files'].append(path.relative_to(ROOT).as_posix())
            row['raw_output'] = self.text(value['text'], value.get('sha256'), job_id)
        # A failed original and successful local parse remain two explicit views.
        effective = row.get('local_parse_recovery', row.get('result'))
        row['effective_saved_result'] = effective
        row['raw_output_present'] = 'raw_output' in row
        row['commercial_reexecution_created_by_export'] = False
        self.attempts.append(row)
        return row

    def case(self, case, study):
        row = {'public_case_id': case.name, 'study': study, 'source_files': []}
        for name in ('evaluation_records.json', 'delivery_records.json', 'complete.json', 'blocked.json',
                     'project_input.json', 'prepared.json', 'prepare_intent.json', 'receiver_request.json',
                     'safe_precreation_retry_check.json'):
            path = case / name
            if path.is_file():
                value = self.read(path)
                row[name.removesuffix('.json')] = project(value)
                row['source_files'].append(path.relative_to(ROOT).as_posix())
        for name in ('permission_events.json', 'readback.json', 'readback_process.json'):
            path = case / 'persistent' / name
            if path.is_file():
                value = self.read(path)
                row['host_' + name.removesuffix('.json')] = project(value)
                row['source_files'].append(path.relative_to(ROOT).as_posix())
        return row

    def walk_jobs(self, case, names, study):
        rows = []
        for name in names:
            job = case / name
            if not job.is_dir():
                raise ValueError('missing expected saved job ' + name)
            logical = job.relative_to(LIVE).as_posix()
            rows.append(self.attempt(job, study))
            for child in RECOVERIES:
                if (job / child).is_dir():
                    rows.append(self.attempt(job / child, study, logical))
        return rows

    def special_preflights(self):
        rows = []
        for relative, study in (
            ('raw_experiment_data/preflight/workbuddy', 'HY3 arithmetic preflight'),
            ('same_family_control/preflight/workbuddy_flash', 'WorkBuddy Flash arithmetic preflight')):
            folder = LIVE / relative
            envelope = self.read(folder / 'envelope.json')
            submitted = self.read(folder / 'input.json')
            model = envelope.get('actualModels', envelope.get('requestModelIds'))
            raw = self.text(envelope['output'], envelope.get('actualAssistantOutputSha256'), relative)
            rows.append({'public_job_id': relative, 'study': study, 'raw_output': raw,
                'contract': project({k: submitted[k] for k in ('instruction', 'businessInput', 'model', 'timeoutSeconds', 'softOutputCharacters') if k in submitted}),
                'metadata': {'platform': 'WorkBuddy native desktop', 'actual_models': model,
                    'app_version': envelope.get('staticNativeCapability', {}).get('appVersion'),
                    'physical_supplier_calls': envelope.get('workbuddyPhysicalSupplierCalls'),
                    'actual_cost_cny': envelope.get('workbuddyFeeCny'),
                    'complete_upstream_system_input_observed': envelope.get('completeUpstreamSystemInputObserved')},
                'execution': project({k: envelope[k] for k in ('status', 'passed', 'verifiedAt', 'toolCallCount',
                    'nativeUserRequestCount', 'automaticReplay', 'nativeBusinessQueryMatchesSubmitted',
                    'nativeUserPromptMatchesSubmitted', 'submittedUserPromptSha256', 'businessInputSha256') if k in envelope}),
                'native_private_history_publicly_included': False})
        arithmetic = LIVE / 'raw_experiment_data/preflight/harness/escalated/job-arithmetic-20261106'
        response = self.read(arithmetic / 'response.json')
        request = self.read(arithmetic / 'input.json')
        receipt = self.read(arithmetic / 'receipt.json')
        rows.append({'public_job_id': arithmetic.relative_to(LIVE).as_posix(), 'study': 'Harness SDK arithmetic preflight',
            'raw_output': self.text(response['final_assistant_text'], job_id=arithmetic.relative_to(LIVE).as_posix()),
            'contract': project({k: request[k] for k in ('messages', 'business_messages_sha256', 'dispatch_sha256') if k in request}),
            'metadata': {'platform': 'DeepSeek Harness official SDK',
                         'receipt': project({k: receipt[k] for k in RECEIPT & receipt.keys()})},
            'private_account_metadata_publicly_included': False})
        failed = LIVE / 'raw_experiment_data/preflight/harness/job-arithmetic-20261106'
        row = {'public_job_id': failed.relative_to(LIVE).as_posix(), 'study': 'Harness original failed preflight',
               'raw_output': None, 'raw_output_missing_not_success': True}
        for name in ('receipt.json', 'guard.json', 'reservation.json'):
            if (failed / name).is_file():
                value = self.read(failed / name)
                if name == 'receipt.json':
                    row['receipt'] = project({k: value[k] for k in set(RECEIPT) | {'error', 'model_requests', 'allowed_stream_count'} if k in value})
                else:
                    row[name.removesuffix('.json')] = project({k: value[k] for k in ('status', 'allowed_stream_count',
                        'model_requests', 'automatic_retry', 'request_started', 'created_unix') if k in value})
        rows.append(row)
        return rows

    def build(self):
        cases = sorted((LIVE / 'raw_experiment_data/qualification_isolated_v1').glob('LIVE-*'))
        if len(cases) != 60:
            raise ValueError('main case inventory changed')
        for project_id in sorted({p.name.split('.')[0] for p in cases}):
            selected = [p for p in cases if p.name.startswith(project_id + '.')]
            jobs, outcomes = [], []
            for case in selected:
                jobs.extend(self.walk_jobs(case, JOB_NAMES, 'qualification_isolated_v1'))
                outcomes.append(self.case(case, 'qualification_isolated_v1'))
            self.add(f'main_jobs/{project_id}.jobs.jsonl', jobs, True)
            self.add(f'main_cases/{project_id}.cases.jsonl', outcomes, True)
        original_jobs, original_cases = [], []
        for case in sorted((LIVE / 'raw_experiment_data/exact_original_live').glob('LIVE-*')):
            original_jobs.extend(self.walk_jobs(case, ('receiver_raw',), 'exact_original_live'))
            # The saved failed original is preserved; the only recovery used a fresh sibling job.
            recovery = case / 'receiver_raw_safe_precreation_retry_01'
            if recovery.is_dir():
                original_jobs.append(self.attempt(recovery, 'exact_original_live',
                    (case / 'receiver_raw').relative_to(LIVE).as_posix()))
            original_cases.append(self.case(case, 'exact_original_live'))
        self.add('supplemental_jobs/exact_original.jsonl', original_jobs, True)
        self.add('supplemental_cases/exact_original.jsonl', original_cases, True)
        family_jobs, family_cases = [], []
        for case in sorted((LIVE / 'same_family_control/projects').glob('LIVE-*')):
            family_jobs.extend(self.walk_jobs(case, ('workbuddy_flash', 'harness_flash'), 'same_family_control'))
            family_cases.append(self.case(case, 'same_family_control'))
        self.add('supplemental_jobs/same_family.jsonl', family_jobs, True)
        self.add('supplemental_cases/same_family.jsonl', family_cases, True)
        smoke_jobs, smoke_cases = [], []
        for case in sorted((LIVE / 'raw_experiment_data/live').glob('LIVE-*')):
            smoke_jobs.extend(self.walk_jobs(case, ('source_initial_generation', 'source_legal_rebuild',
                'receiver_initial', 'receiver_legal_successor'), 'joint_context_smoke_excluded_from_main'))
            smoke_cases.append(self.case(case, 'joint_context_smoke_excluded_from_main'))
        self.add('supplemental_jobs/smoke.jsonl', smoke_jobs, True)
        self.add('supplemental_cases/smoke.jsonl', smoke_cases, True)
        self.add('supplemental_jobs/preflights.jsonl', self.special_preflights(), True)
        for name in ('projects.json', 'gold.scoring_only.json', 'schemas.json', 'dataset_manifest.json'):
            value = self.read(LIVE / 'raw_experiment_data/dataset' / name)
            self.add('dataset/' + name, project(value))
        # Preserve the saved score fields and all recorded failures. These are
        # public projections of existing evaluations, not new model judgments.
        for relative in ('raw_experiment_data/evaluation/quality_summary.json',
                         'raw_experiment_data/source_evaluation/source_summary.json',
                         'raw_experiment_data/source_evaluation/semantic_review_summary.json',
                         'raw_experiment_data/qualification_isolated_v1/first_pass_driver_observation.json',
                         'raw_experiment_data/exact_original_live/completion_receipt.json',
                         'same_family_control/final_audit.json',
                         'same_family_control/format_error_breakdown.json'):
            value = self.read(LIVE / relative)
            self.add('saved_analysis/' + Path(relative).name, project(value))
        self.add('raw_output_integrity.jsonl', self.raw_outputs, True)
        main = [r for r in self.attempts if r['study'] == 'qualification_isolated_v1']
        summary = {'schema': 'live-research-public-summary-v1', 'exported_utc': datetime.now(timezone.utc).isoformat(),
            'main_project_clusters': 10, 'main_cases': len(cases), 'main_logical_jobs': 480,
            'main_saved_attempt_rows': len(main), 'main_raw_job_outputs': sum(r['raw_output_present'] for r in main),
            'main_evaluation_rows': 360, 'main_delivery_rows': 1800,
            'exact_original_cases': len(original_cases), 'exact_original_saved_attempt_rows': len(original_jobs),
            'same_family_paired_projects': len(family_cases), 'same_family_job_rows': len(family_jobs),
            'smoke_cases_excluded_from_main': len(smoke_cases), 'smoke_job_rows': len(smoke_jobs),
            'raw_job_outputs_with_text': len(self.raw_outputs),
            'raw_output_files_not_provider_request_count': True,
            'original_output_text_hashes_verified': len(self.raw_outputs),
            'redacted_raw_output_texts': sum(r['redacted_for_publication'] for r in self.raw_outputs),
            'new_model_calls': 0, 'databases_opened': 0, 'private_account_directories_read': 0,
            'commercial_client_private_history_included': False,
            'supplier_bills_verified': False,
            'scope': 'Saved synthetic input/output and evidence projections. Public recomputation is possible; commercial platform internals cannot be independently re-audited from this bundle.'}
        if summary['main_saved_attempt_rows'] != 487 or summary['main_raw_job_outputs'] != 480:
            raise ValueError('unexpected main attempt/raw-output count')
        if len(self.raw_outputs) != 571:
            raise ValueError('saved output inventory differs from the audited 571 text-bearing jobs')
        self.add('summary.json', summary)
        self.add('source_file_manifest.json', {'schema': 'public-source-file-projection-v1',
            'original_file_hashes_are_local_integrity_references_not_public_byte_hashes': True,
            'source_files': sorted(self.sources.values(), key=lambda v: v['path']),
            'source_files_all_unchanged_during_export': True})
        self.files['README.md'] = README.encode('utf-8')
        self.files['verify_public_bundle.py'] = VERIFIER.encode('utf-8')
        # Recheck every actually read file before any output is written.
        for source in self.sources.values():
            if sha((ROOT / source['path']).read_bytes()) != source['sha256']:
                raise ValueError('historical input changed during export')
        for name, raw in self.files.items():
            text = raw.decode('utf-8')
            if WINDOWS_PATH.search(text) or UUID.search(text) or SECRET.search(text):
                raise ValueError('public safety check failed: ' + name)
        self.add('public_file_manifest.json', {'schema': 'live-public-bundle-hashes-v1',
            'manifest_self_excluded': True, 'published_by_exporter': False,
            'files': [{'path': name, 'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(self.files.items())],
            'exporter_source_repo_relative': Path(__file__).relative_to(ROOT).as_posix(),
            'exporter_source_sha256': sha(Path(__file__).read_bytes())})
        return summary


README = '''# Live Agent memory research: public evidence projection, 2026-11-06

This bundle contains saved, real commercial-model outputs and synthetic inputs.
It does not run a model. Main qualification: 10 seeded synthetic projects, 60
cases (2 directions × 3 repeats), 480 completed inference jobs, 487 saved outer
attempts. These are repeated measures, not 480 independent projects. WorkBuddy
native user turns and Harness SDK requests are different accounting units.

`main_jobs/` preserves every original failed result and every recorded local
format recovery or proven zero-dispatch retry. `raw_output.text` is the original
text unless `redacted_for_publication=true`; the original and public UTF-8
SHA256 are separate fields. No invalid JSON or failure is replaced by a fabricated
successful response. `effective_saved_result` is a saved parsing/result view,
not an additional model call. Public job IDs are relative experiment paths.

`main_cases/` contains all 360 recipient evaluation rows (1,440 question fields)
and 1,800 delivery rows, plus host permission events and readback projections.
The saved legal-phase analysis uses 720 question fields, of which 540 are legal
task fields and 180 are withdrawn-code probes. Historical 768 fields belong to
a separate 2026-11-05 study and are not merged here. Saved analysis snapshots
predate later evaluation annotations; publish the separate dated ambiguity
revision alongside this bundle. Frozen truth and exact scores are unchanged.

`dataset/` includes original input facts, rules, permissions, frozen scoring
truth and schemas. Ground truth was not supplied to source models. `supplemental_*/`
keeps exact-original controls, same-family cross-platform controls, and smoke/
preflight runs distinct. Same-family aliases do not prove identical backend
weights. Smoke runs shared representation context and are excluded from the
main isolated analysis. The three arithmetic preflights and one original
failed Harness preflight are explicitly labeled. Count raw output rows, saved
attempts and commercial provider physical requests separately.

Original native histories, session/account identifiers, SDK records, private
account homes, credentials and SQLite databases remain local. Public metadata
is field-whitelisted. Machine paths and native UUIDs are removed from public
copies. Original source-file SHA256 values reference unchanged local evidence;
they are not falsely presented as hashes of redacted public bytes. Public file
hashes are in `public_file_manifest.json`.

Observable costs remain null when unknown. Price-based estimates are not bills.
Host-owned SQLite persistence is not observation of private built-in commercial
Agent memory. The data permit public task-score recomputation and output/text
inspection; they do not permit a complete re-audit of commercial internals.

Verify with Python 3.11+ and the standard library, without network or API keys:

    python verify_public_bundle.py

No new license or ownership claim is made by the export. Refer to the repository
and retained third-party notices for applicable code licenses.
'''

VERIFIER = '''"""Verify public bytes, raw UTF-8 text hashes and exact saved row counts."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent
digest=lambda b:hashlib.sha256(b).hexdigest()
manifest=json.loads((root/'public_file_manifest.json').read_text(encoding='utf-8'))
for item in manifest['files']:
    raw=(root/item['path']).read_bytes()
    assert len(raw)==item['bytes'] and digest(raw)==item['sha256'],item['path']
raw_count=0
for folder in ('main_jobs','supplemental_jobs'):
    for p in (root/folder).glob('*.jsonl'):
        for line in p.read_text(encoding='utf-8').splitlines():
            row=json.loads(line);out=row.get('raw_output')
            if out:
                raw_count+=1
                assert digest(out['text'].encode('utf-8'))==out['public_text_utf8_sha256'],row['public_job_id']
                if out['public_text_is_byte_equal_to_original']:
                    assert out['public_text_utf8_sha256']==out['original_text_utf8_sha256']
cases=[json.loads(t) for p in (root/'main_cases').glob('*.jsonl') for t in p.read_text(encoding='utf-8').splitlines()]
assert len(cases)==60
assert sum(len(c['evaluation_records']) for c in cases)==360
assert sum(len(c['delivery_records']) for c in cases)==1800
assert raw_count==571,raw_count
print(json.dumps({'status':'passed','verified_public_files':len(manifest['files']),'main_cases':60,'main_evaluation_rows':360,'main_delivery_rows':1800,'raw_text_bearing_job_rows':raw_count,'new_model_calls':0}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    if output != DEFAULT_OUTPUT.resolve():
        raise ValueError('this dated exporter writes only the declared staging destination')
    if output.exists():
        raise ValueError('output already exists; preserve the existing public projection')
    export = Export()
    summary = export.build()
    output.mkdir(parents=True)
    for name, raw in sorted(export.files.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'status': 'exported', 'file_count': len(export.files),
        'bytes': sum(map(len, export.files.values())),
        'raw_job_outputs_with_text': summary['raw_job_outputs_with_text'],
        'main_saved_attempt_rows': summary['main_saved_attempt_rows'], 'new_model_calls': 0}))


if __name__ == '__main__':
    main()
