"""Bounded official Harness SDK calls; importing sends nothing and reads no login.

Prices are conservative peak estimates, not supplier bills. The SDK owns its
opaque account credential inside a fresh private home; the original is never
parsed or changed. A failed/unknown call keeps its reservation and stops the run.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from memory_migration_study.deepseek_sdk import SDKPeer, summarize_session
from memory_migration_study.deepseek_native import _restrict_private_dir, _environment, _file_hash

INSTALL = Path('D:/deekseek harness')
APP_VERSION = '0.2.1-rc.3'
MODEL = 'deepseek-flash'
MAX_REQUEST_BYTES = 256000
PRICE_SOURCE = 'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/'
PRICE_VERIFIED = '2026-11-04'
PRICES = {'input': Decimal('2'), 'output': Decimal('8')}
USAGE_SCHEMA = 'deepseek-harness-0.2.1-rc.3-anthropic-usage-v2'


class SDKAdapterError(RuntimeError):
    """Stable error code; never includes native errors or account data."""


def need(value, code):
    if not value:
        raise SDKAdapterError(code)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value, *, exclusive=False):
    with Path(path).open('xb' if exclusive else 'wb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())


def peak_cost(input_tokens, output_tokens):
    need(type(input_tokens) is int and type(output_tokens) is int and input_tokens >= 0 and output_tokens >= 0, 'usage_invalid')
    return (input_tokens * PRICES['input'] + output_tokens * PRICES['output']) / Decimal(1_000_000)


def normalize_usage(usage):
    """Official SDK Anthropic mapping: inputTokens is MISS, not total input.

    updateUsage maps cache-read/write separately and translate sums all four
    counters into totalTokens. Only the two cache counters may be absent (zero).
    Raw HTTP/OpenAI aliases are not silently mixed with this native schema.
    """
    need(type(usage) is dict, 'sdk_usage_invalid')
    required = ('inputTokens', 'outputTokens', 'totalTokens')
    optional = ('cacheReadTokens', 'cacheWriteTokens')
    need(all(key in usage for key in required), 'sdk_native_usage_fields_missing')
    need(all(type(usage.get(key, 0)) is int and usage.get(key, 0) >= 0
             for key in required + optional), 'sdk_usage_invalid')
    miss, output = usage['inputTokens'], usage['outputTokens']
    read, write = usage.get('cacheReadTokens', 0), usage.get('cacheWriteTokens', 0)
    total_input = miss + read + write
    need(usage['totalTokens'] == total_input + output, 'sdk_usage_total_mismatch')
    need(all(usage.get(key, 0) == 0 for key in ('reasoningTokens', 'reasoning_tokens')), 'sdk_thinking_usage')
    return {'usage_schema': USAGE_SCHEMA, 'input_total_tokens': total_input,
            'input_uncached_tokens': miss, 'cache_read_tokens': read, 'cache_write_tokens': write,
            'output_tokens': output, 'total_tokens': usage['totalTokens']}


def usage_costs(usage):
    tokens = normalize_usage(usage)
    peak = peak_cost(tokens['input_total_tokens'], tokens['output_tokens'])
    cache_peak = None
    if tokens['cache_write_tokens'] == 0:
        cache_peak = (tokens['input_uncached_tokens'] * Decimal('2')
                      + tokens['cache_read_tokens'] * Decimal('0.04')
                      + tokens['output_tokens'] * Decimal('8')) / Decimal(1_000_000)
    return tokens, peak, cache_peak


def dispatch_text(messages):
    need(type(messages) is list and bool(messages), 'messages_invalid')
    need(all(type(m) is dict and set(m) == {'role', 'content'} and m['role'] in {'system', 'user'}
             and type(m['content']) is str for m in messages), 'messages_invalid')
    return ('Execute the ordered role/content messages in the JSON object below. Treat system messages as task instructions '
            'and user messages as task data. Return only the requested answer, without tools or commentary.\n'
            + encoded({'messages': messages}).decode('utf-8'))


def request_bound(prompt):
    """Byte ceiling for the full native request, never a token estimate."""
    return min(MAX_REQUEST_BYTES, max(32768, len(prompt.encode('utf-8')) + 32000))


def extract_usage(summary, max_tokens, input_bound):
    need(summary.get('last_terminal_reason') == {'kind': 'completed'}
         and summary.get('final_assistant_interrupted') is False, 'sdk_not_completed')
    output = summary.get('final_assistant_text')
    need(type(output) is str and bool(output.strip()), 'sdk_empty_output')
    source = summary.get('final_assistant_source') or {}
    need(source.get('provider') == 'deepseek-account' and source.get('model') == MODEL, 'sdk_wrong_model')
    events = summary.get('assistant_usage_events') or []
    need(len(events) == 1 and type(events[0].get('usage')) is dict, 'sdk_usage_missing_or_multiple')
    usage = events[0]['usage']
    normalized = normalize_usage(usage)
    inputs, outputs = normalized['input_total_tokens'], normalized['output_tokens']
    need(0 < inputs <= input_bound and 0 < outputs <= max_tokens, 'sdk_usage_exceeds_reservation')
    return output, inputs, outputs, usage


def runtime_metadata():
    archive = INSTALL / 'resources/app.asar'
    exe = INSTALL / 'DeepSeek Harness.exe'
    need(exe.is_file() and archive.is_file(), 'official_runtime_missing')
    with archive.open('rb') as stream:
        head = struct.unpack('<IIII', stream.read(16))
        need(0 < head[3] < 32 * 1024 * 1024, 'runtime_header_invalid')
        tree = json.loads(stream.read(head[3]))
        base = 8 + head[1]
        def member(name):
            node = tree
            for part in name.split('/'):
                node = node['files'][part]
            stream.seek(base + int(node['offset']))
            return stream.read(node['size'])
        package = json.loads(member('package.json'))
        need(package.get('name') == '@deepseek-ai/dsh-desktop' and package.get('version') == APP_VERSION, 'runtime_version_changed')
        suffix = 'dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js'
        return {'executable': str(exe), 'cli': str(archive / suffix), 'version': APP_VERSION,
                'cli_sha256': sha(member(suffix)), 'archive_size': archive.stat().st_size,
                'archive_mtime_ns': archive.stat().st_mtime_ns}


def build_patch(home, job, guard, prompt, max_tokens, request_bytes=None):
    template = REPO / 'examples/native_agent_probe_assets/sdk_guard_metadata.patch.template.json'
    rows = json.loads(template.read_text(encoding='utf-8'))
    result = []
    for row in rows:
        if 'insert' in row:
            continue
        if row.get('id') == 'agent-instructions':
            result.append({'id': 'agent-instructions', 'disabled': True})
        elif row.get('id') == 'credentials':
            result.append({'id': 'credentials', 'config': {'path': str(home / '.credentials.yaml'), 'watch': False}})
        elif row.get('id') == 'session-persistence-jsonl':
            result.append({'id': row['id'], 'config': {'root': str(home / 'sessions'), 'compression': 'none'}})
        else:
            result.append(row)
    # dsh-base already owns these official providers. Override its entry instead
    # of mounting a duplicate adapter that the base registration could replace.
    result.append({'id': 'llm-deepseek-account', 'config': {'retryPolicy': {'mode': 'normal', 'maxRetries': 0}}})
    result.append({'insert': [
        {'id': 'study-group-guard', 'name': guard.as_uri(), 'config': {
            'receiptPath': str(job / 'guard.json'), 'requestPath': str(job / 'actual_request.json'),
            'metadataPath': str(job / 'account_metadata.private.json'), 'maxRequests': 1, 'maxTokens': max_tokens,
            'maxRequestBytes': request_bytes or request_bound(prompt), 'dispatchSha256': sha(prompt.encode('utf-8')),
            'workspace': str(job / 'workspace')}},
    ]})
    return result


class FlashSDKClient:
    def __init__(self, root, budget_cap_cny=3.0, max_jobs=160):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        need(self.root.resolve() == self.root, 'ledger_root_alias')
        need(type(max_jobs) is int and max_jobs > 0, 'max_jobs_invalid')
        self.cap = Decimal(str(budget_cap_cny))
        need(self.cap.is_finite() and self.cap > 0, 'budget_cap_invalid')
        self.max_jobs = max_jobs
        _restrict_private_dir(self.root)
        self.config = {'model': MODEL, 'provider': 'deepseek-account', 'app_version': APP_VERSION,
                       'budget_cap_cny': str(self.cap), 'max_jobs': max_jobs,
                       'max_request_bytes': MAX_REQUEST_BYTES, 'price_source': PRICE_SOURCE,
                       'price_verified_date': PRICE_VERIFIED, 'input_peak_cny_per_million': '2',
                       'output_peak_cny_per_million': '8', 'cost_is_supplier_bill': False}
        config_file = self.root / 'config.json'
        if config_file.exists():
            need(config_file.read_bytes() == encoded(self.config), 'frozen_config_changed')
        else:
            save(config_file, self.config, exclusive=True)

    def _totals(self):
        spent = pending = Decimal(0)
        corrections = []
        jobs = list(self.root.glob('job-*'))
        for job in jobs:
            reservation = json.loads((job / 'reservation.json').read_bytes())
            value = Decimal(reservation['reservation_cny'])
            receipt_file = job / 'receipt.json'
            receipt = json.loads(receipt_file.read_bytes()) if receipt_file.exists() else {}
            if receipt.get('status') == 'ok':
                tokens, corrected_peak, _ = usage_costs(receipt.get('usage'))
                recorded_peak = Decimal(receipt['estimated_peak_cost_cny'])
                need(recorded_peak.is_finite() and recorded_peak >= 0, 'ledger_cost_invalid')
                need(receipt.get('input_tokens') == tokens['input_uncached_tokens']
                     and receipt.get('output_tokens') == tokens['output_tokens'], 'ledger_legacy_token_fields_mismatch')
                if 'usage_schema' in receipt:
                    need(receipt['usage_schema'] == USAGE_SCHEMA, 'ledger_usage_schema_unknown')
                    need(all(receipt.get(key) == tokens[key] for key in (
                        'input_total_tokens', 'input_uncached_tokens', 'cache_read_tokens', 'cache_write_tokens')),
                        'ledger_normalized_tokens_mismatch')
                    need(recorded_peak == corrected_peak, 'ledger_corrected_cost_mismatch')
                else:
                    legacy = peak_cost(tokens['input_uncached_tokens'], tokens['output_tokens'])
                    need(recorded_peak in (legacy, corrected_peak), 'ledger_cost_not_recognized_formula')
                    if recorded_peak != corrected_peak:
                        corrections.append({'job_id': job.name, 'legacy_recorded_peak_cny': str(recorded_peak),
                                            'recomputed_total_input_peak_cny': str(corrected_peak)})
                spent += corrected_peak
            else:
                pending += value  # Never refund a failed/unknown dispatch.
        self.legacy_cost_corrections = corrections  # Diagnostics only; old files are never rewritten.
        need(spent + pending <= self.cap, 'corrected_ledger_exceeds_budget_cap')
        return spent, pending, len(jobs)

    def _exchange(self, job, prompt, max_tokens, *, metadata_only=False):
        runtime = runtime_metadata()
        home = job / 'home.private'
        home.mkdir()
        _restrict_private_dir(home)
        (home / 'agents').mkdir()
        workspace = job / 'workspace'
        workspace.mkdir()
        (workspace / '.git').mkdir()
        source = Path.home() / '.dsh/.credentials.yaml'
        copied = home / '.credentials.yaml'
        need(source.is_file() and not source.is_symlink(), 'official_login_missing')
        source_hash = _file_hash(source)  # Opaque bytes; never parsed or logged.
        process = peer = None
        guard_path = Path(__file__).with_name('dsh_group_guard.mjs').absolute()
        guard_hash = _file_hash(guard_path)
        try:
            with source.open('rb') as original, copied.open('xb') as output:
                shutil.copyfileobj(original, output)
            need(_file_hash(source) == source_hash and _file_hash(copied) == source_hash, 'login_copy_changed')
            patch = home / 'study.patch.yml'
            save(patch, build_patch(home, job, guard_path, prompt, max_tokens))
            argv = [runtime['executable'], '--expose-internals', runtime['cli'], '--profile', 'sdk', '--patch', str(patch)]
            save(job / 'runtime.json', {**runtime, 'argv_sha256': sha(encoded(argv)), 'guard_sha256': guard_hash})
            process = subprocess.Popen(argv, cwd=str(workspace), env=_environment(home), shell=False,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding='utf-8', errors='replace',
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            peer = SDKPeer(process, allow_prompts=not metadata_only, max_prompts=0 if metadata_only else 1)
            metadata_file = job / 'account_metadata.private.json'
            deadline = time.monotonic() + 60
            while not metadata_file.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            need(metadata_file.exists(), 'account_load_barrier_timeout')
            metadata = json.loads(metadata_file.read_bytes())
            need(metadata.get('status') == 'ready' and metadata.get('account_service_loaded') is True, 'account_metadata_unavailable')
            need(-2 <= time.time() - metadata['observed_at_unix'] <= 60, 'account_snapshot_stale')
            wallet = Decimal(metadata['wallet_cny'])
            spent, pending, _ = self._totals()
            # The current job's conservative reservation is included in pending.
            need(wallet.is_finite() and wallet >= pending, 'wallet_below_reservations')
            session = str(uuid.uuid4())
            initialized = peer.request('initialize', {'cwd': str(workspace), 'provider': 'deepseek-account',
                'model': MODEL, 'reasoningEffort': 'off', 'maxTokens': max_tokens}, timeout=60)
            need(initialized == {'serverInfo': {'name': 'deepseek-harness-sdk-runtime', 'version': '0.0.1'}}, 'sdk_initialize_invalid')
            ack = None
            summary = None
            if not metadata_only:
                need(peer.request('session/working-directory/set', {'sessionId': session, 'path': str(workspace)}) == {'cwd': str(workspace)}, 'sdk_workspace_mismatch')
                start = len(peer.notifications)
                ack = peer.request('session/prompt', {'sessionId': session, 'contentBlocks': [{'type': 'text', 'text': prompt}]}, timeout=120)
                need(isinstance(ack, dict) and isinstance(ack.get('messageId'), str), 'sdk_ack_invalid')
                need(peer.request('session/wait', {'sessionId': session}, timeout=120) == {}, 'sdk_wait_invalid')
                summary = summarize_session(peer.notifications[start:], session)
                save(job / 'response.json', summary)
            need(peer.request('shutdown', {}, timeout=15) == {}, 'sdk_shutdown_invalid')
            process.stdin.close()
            process.wait(timeout=15)
            need(process.returncode == 0, 'sdk_exit_nonzero')
            need(_file_hash(guard_path) == guard_hash, 'guard_changed')
            archive = INSTALL / 'resources/app.asar'
            need(archive.stat().st_size == runtime['archive_size'] and archive.stat().st_mtime_ns == runtime['archive_mtime_ns'], 'runtime_changed')
            return {'summary': summary, 'ack': ack, 'session_id': session,
                    'guard': json.loads((job / 'guard.json').read_bytes()), 'runtime': runtime}
        finally:
            if process is not None and process.poll() is None:
                process.kill()  # Only this SDK child, never the desktop process.
                process.wait(timeout=10)
            if process is not None:
                for pipe in (process.stdin, process.stdout, process.stderr):
                    try:
                        pipe.close()
                    except (OSError, ValueError):
                        pass
            copied.unlink(missing_ok=True)
            need(not copied.exists() and _file_hash(source) == source_hash, 'login_cleanup_or_original_changed')

    def preflight(self):
        """Official metadata/account query only; never submits a prompt."""
        job = self.root / ('metadata-' + uuid.uuid4().hex)
        job.mkdir()
        try:
            result = self._exchange(job, 'metadata preflight; not sent', 64, metadata_only=True)
            guard = result['guard']
            need(guard['allowed_stream_count'] == guard['agent_attempt_count'] == 0, 'metadata_unexpected_model_call')
            summary = {'ok': True, 'model_requests': 0, 'account_service_ready': True,
                       'official_sdk_initialized': True, 'price_source': PRICE_SOURCE, 'price_verified_date': PRICE_VERIFIED}
            save(job / 'result.json', summary)
            return summary
        except Exception as error:
            save(job / 'result.json', {'ok': False, 'model_requests': 0,
                                     'error': str(error) if isinstance(error, SDKAdapterError) else 'metadata_runtime_failure'})
            raise SDKAdapterError('metadata_preflight_failed_see_private_record') from None

    def generate(self, messages, job_id, max_tokens, role):
        need(role in {'source', 'target'} and type(max_tokens) is int and 1 <= max_tokens <= 2048, 'output_limit_invalid')
        need(type(job_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}', job_id), 'job_id_invalid')
        prompt = dispatch_text(messages)
        need(len(prompt.encode('utf-8')) <= MAX_REQUEST_BYTES - 32000, 'business_input_too_large')
        lock = self.root / 'exclusive.runlock'
        try:
            save(lock, {'pid': os.getpid(), 'job_id': job_id}, exclusive=True)
        except FileExistsError:
            raise SDKAdapterError('exclusive_runlock_exists_no_auto_recovery') from None
        job = self.root / ('job-' + job_id)
        reserved_here = False
        try:
            need((self.root / 'config.json').read_bytes() == encoded(self.config), 'frozen_config_changed')
            spent, pending, jobs = self._totals()
            need(pending == 0 and not (self.root / 'STOPPED.json').exists(), 'unresolved_job_stops_run')
            need(jobs < self.max_jobs and not job.exists(), 'job_limit_or_duplicate_no_retry')
            bound = request_bound(prompt)
            reserve = peak_cost(bound + 2048, max_tokens)
            need(spent + reserve <= self.cap, 'budget_cap_exceeded')
            job.mkdir()
            reserved_here = True
            save(job / 'reservation.json', {'reservation_cny': str(reserve), 'role': role,
                'max_tokens': max_tokens, 'request_byte_bound': bound, 'input_token_bound': bound + 2048}, exclusive=True)
            save(job / 'input.json', {'messages': messages, 'dispatch_text': prompt,
                                    'business_messages_sha256': sha(encoded(messages)), 'dispatch_sha256': sha(prompt.encode('utf-8'))})
            start = time.monotonic()
            result = self._exchange(job, prompt, max_tokens)
            guard = result['guard']
            need(guard['agent_attempt_count'] == guard['stream_attempt_count'] == guard['allowed_stream_count'] == 1
                 and guard['reject_code'] is None and len(guard['requests']) == 1, 'guard_not_single_request')
            request = guard['requests'][0]
            actual_request = (job / 'actual_request.json').read_bytes()
            need(sha(actual_request) == request['bodyhash'] and len(actual_request) == request['bytes']
                 and request['business_input_sha256'] == sha(prompt.encode('utf-8')), 'actual_input_binding_mismatch')
            output, inputs, outputs, usage = extract_usage(result['summary'], max_tokens, request['bytes'] + 2048)
            tokens, cost, cache_peak = usage_costs(usage)
            need(cost <= reserve, 'actual_usage_outside_reservation')
            receipt = {'status': 'ok', 'request_id': result['ack']['messageId'], 'request_id_scope': 'SDK prompt messageId',
                'session_id': result['session_id'], 'input_tokens': tokens['input_uncached_tokens'], 'output_tokens': outputs,
                'input_tokens_semantics': 'legacy_uncached_input_count',
                'usage_schema': USAGE_SCHEMA, 'input_total_tokens': inputs,
                'input_uncached_tokens': tokens['input_uncached_tokens'],
                'cache_read_tokens': tokens['cache_read_tokens'], 'cache_write_tokens': tokens['cache_write_tokens'],
                'estimated_peak_cost_cny': str(cost), 'cost_is_supplier_bill': False,
                'actual_model': result['summary']['final_assistant_source']['model'],
                'provider': 'deepseek-account', 'latency_seconds': time.monotonic() - start,
                'request_sha256': request['bodyhash'], 'response_sha256': sha(output.encode('utf-8')),
                'business_messages_sha256': sha(encoded(messages)), 'dispatch_sha256': sha(prompt.encode('utf-8')),
                'physical_request_count': 1, 'physical_request_evidence': 'one successful text-only SDK stream; retryPolicy.maxRetries=0; no tools or images',
                'usage': usage, 'price_source': PRICE_SOURCE, 'price_verified_date': PRICE_VERIFIED,
                'record_path': str(job), 'temporary_credentials_removed': True}
            receipt['cache_hit_input_tokens'] = tokens['cache_read_tokens']
            receipt['estimated_cache_aware_peak_cost_cny'] = str(cache_peak) if cache_peak is not None else None
            receipt['estimated_cache_aware_offpeak_cost_cny'] = str(cache_peak / 2) if cache_peak is not None else None
            receipt['cache_write_price_known'] = tokens['cache_write_tokens'] == 0
            save(job / 'receipt.json', receipt)
            return {'output': output, 'receipt': receipt}
        except Exception as error:
            if reserved_here:
                code = str(error) if isinstance(error, SDKAdapterError) else 'sdk_runtime_failure'
                failed = {'status': 'failed', 'error': code, 'reservation_retained': True, 'physical_request_count': None}
                try:
                    guard = json.loads((job / 'guard.json').read_bytes())
                    if guard.get('allowed_stream_count') == 0 and type(guard.get('agent_attempt_count')) is int:
                        failed.update(physical_request_count=0, estimated_peak_cost_cny='0',
                                      physical_request_evidence='guard denied before the official adapter',
                                      guard_reject_code=guard.get('reject_code'))
                except (OSError, ValueError, TypeError):
                    pass
                save(job / 'receipt.json', failed)
                save(self.root / 'STOPPED.json', {'job_id': job_id, 'error': code, 'automatic_retry': False})
            raise SDKAdapterError(str(error) if isinstance(error, SDKAdapterError) else 'sdk_runtime_failure') from None
        finally:
            lock.unlink(missing_ok=True)
