"""Bounded native Harness workspace-instruction probe, not a permission layer.

Only an explicit call starts the official SDK. Authentication is an opaque file
copy for this same official application; credential values are never parsed or
returned. The original is only hashed, never passed to the child or modified.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
import uuid

from .deepseek_sdk import SDKPeer, SDKTransportError, summarize_session

ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = ROOT / 'results'
GUARD_ROOT = RESULTS_ROOT / 'native_agent_probe_20261026'
INSTALL = Path('C:/Users/CAI/AppData/Local/Programs/DeepSeek Harness')
DEFAULT_CREDENTIALS = Path.home() / '.dsh' / '.credentials.yaml'
VERSION = 'deepseek-native-question-v3'
APP_VERSION = '0.2.1-rc.3'
PROVIDER, MODEL = 'deepseek-account', 'deepseek-flash'
MAX_PROMPT_BYTES, MAX_MEMORY_BYTES = 4096, 8192
DISABLED_IDS = frozenset({
    'tool-plugin-manager', 'tool-working-directory', 'tool-bash', 'tool-pwsh',
    'tool-jobs', 'tool-fs', 'tool-fs-search', 'tool-skill', 'tool-subagent-control',
    'tool-subagent-list-agents', 'tool-subagent', 'tool-subagent-fork',
    'tool-workflow', 'tool-todo', 'tool-goal', 'tool-web', 'llm-retry',
    'session-title-llm', 'goal-round-driver', 'skill-office', 'workspace-dependencies',
    'skill-filesystem', 'plugin-manager', 'hmr', 'otel', 'session-telemetry-otel',
    'compaction-basic', 'command-compact', 'goal', 'subagent-spawn-in-process',
    'subagent-fork-in-process',
})
# Official base's plan-mode registers exit_plan_mode unconditionally, despite
# lacking a tool-* ID. Always disable it even for older verified templates.
EXTRA_DISABLED_IDS = frozenset({'plan-mode'})
INSTRUCTIONS = {
    'maxBytes': 8192, 'maxSourceBytes': 16384, 'projectRootMarkers': ['.git'],
    'instructionFileCandidates': ['AGENTS.md'], 'localInstructionFileCandidates': [],
}
ENV_KEYS = frozenset({
    'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE',
    'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH', 'PROGRAMFILES',
    'PROGRAMFILES(X86)', 'COMMONPROGRAMFILES', 'OS', 'PROCESSOR_ARCHITECTURE',
})
TOKEN_KEYS = frozenset({
    'inputTokens', 'outputTokens', 'totalTokens', 'cachedInputTokens',
    'cacheReadInputTokens', 'cacheCreationInputTokens', 'input_tokens',
    'output_tokens', 'total_tokens', 'prompt_tokens', 'completion_tokens',
    'cached_input_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens',
})


class _Failure(ValueError):
    pass


def _require(ok, code):
    if not ok:
        raise _Failure(code)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'json_duplicate_key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(_Failure('json_nonfinite')))
    except _Failure:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _Failure('json_invalid') from None


def _regular(path, limit=None):
    path = Path(path).absolute()
    _require(path.resolve(strict=True) == path and not path.is_symlink() and path.is_file(),
             'file_missing_or_linked')
    _require(limit is None or path.stat().st_size <= limit, 'file_too_large')
    return path


def _file_hash(path):
    """Opaque streaming hash. Never decode or parse authentication material."""
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def _under_results(path, *, existing):
    path = Path(path).absolute()
    resolved = path.resolve(strict=existing)
    root = RESULTS_ROOT.resolve(strict=True)
    _require(path == resolved and path != root and path.is_relative_to(root),
             'path_outside_results_or_linked')
    return path


def _workspace(path):
    path = _under_results(path, existing=True)
    _require(path.is_dir() and (path / '.git').is_dir()
             and (path / '.git').resolve() == path / '.git'
             and not (path / '.git').is_symlink(), 'workspace_git_root_missing')
    _require(not any((path / name).exists() for name in
        ('AGENTS.local.md', 'CLAUDE.md', 'CLAUDE.local.md', '.dsh', '.agents')),
        'unexpected_project_context')
    memory = _regular(path / 'AGENTS.md', MAX_MEMORY_BYTES).read_bytes()
    text = memory.decode('utf-8')
    _require(bool(text.strip()) and '\0' not in text, 'memory_invalid')
    return path, memory, text


def _runtime_metadata():
    """Read packaged application metadata/source, never user configuration."""
    exe = _regular(INSTALL / 'DeepSeek Harness.exe')
    archive = _regular(INSTALL / 'resources/app.asar')
    with archive.open('rb') as stream:
        header = struct.unpack('<IIII', stream.read(16))
        _require(0 < header[3] < 32 * 1024 * 1024, 'runtime_archive_invalid')
        tree = _json(stream.read(header[3]))
        data_base = 8 + header[1]
        def member(name):
            node = tree
            for part in name.split('/'):
                node = node['files'][part]
            _require(0 < node['size'] < 4 * 1024 * 1024, 'runtime_member_invalid')
            stream.seek(data_base + int(node['offset']))
            return stream.read(node['size'])
        package = _json(member('package.json'))
        _require(package.get('name') == '@deepseek-ai/dsh-desktop'
                 and package.get('version') == APP_VERSION, 'runtime_version_unverified')
        suffix = 'dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js'
        cli_hash = _sha(member(suffix))
    return {'executable': str(exe), 'cli': str(archive / suffix),
            'version': APP_VERSION, 'cli_entry_sha256': cli_hash,
            'archive': str(archive), 'archive_sha256': _file_hash(archive)}


def _restrict_private_dir(path):
    """Restrict the newly created home before copying any authentication file."""
    if os.name != 'nt':
        path.chmod(0o700)
        return
    system = Path(os.environ.get('SYSTEMROOT', 'C:/Windows')) / 'System32'
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    identity = subprocess.run([str(system / 'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        timeout=10, creationflags=flags)
    rows = list(csv.reader(identity.stdout.splitlines()))
    _require(identity.returncode == 0 and len(rows) == 1 and len(rows[0]) == 2
             and re.fullmatch(r'S-1-5-[0-9-]+', rows[0][1]) is not None,
             'private_home_identity_failed')
    sid = rows[0][1]
    acl = subprocess.run([str(system / 'icacls.exe'), str(path), '/inheritance:r',
        '/grant:r', '*' + sid + ':(OI)(CI)F'], capture_output=True, timeout=10,
        creationflags=flags)
    _require(acl.returncode == 0, 'private_home_acl_failed')


def _patch(template, guard, home, guard_receipt):
    raw = _regular(template, 128 * 1024).read_bytes()
    rows = _json(raw)
    _require(isinstance(rows, list), 'patch_template_invalid')
    seen, insert = set(), None
    for row in rows:
        _require(isinstance(row, dict), 'patch_template_invalid')
        if set(row) == {'insert'}:
            _require(insert is None and isinstance(row['insert'], list)
                     and len(row['insert']) == 1, 'patch_guard_invalid')
            insert = row['insert'][0]
            continue
        key = row.get('id')
        _require(key not in seen, 'patch_duplicate_id')
        seen.add(key)
        if key in DISABLED_IDS | EXTRA_DISABLED_IDS:
            _require(row == {'id': key, 'disabled': True}, 'patch_constraints_changed')
        elif key == 'credentials':
            _require(set(row) == {'id', 'config'} and isinstance(row['config'], dict)
                     and set(row['config']) == {'path', 'watch'}
                     and row['config']['watch'] is False, 'patch_credentials_invalid')
        elif key == 'agent-instructions':
            _require(set(row) == {'id', 'config'} and row['config'] == INSTRUCTIONS,
                     'patch_instructions_changed')
        elif key == 'session-persistence-jsonl':
            _require(set(row) == {'id', 'config'} and isinstance(row['config'], dict)
                     and set(row['config']) == {'root', 'compression'}
                     and row['config']['compression'] == 'none', 'patch_persistence_invalid')
        else:
            raise _Failure('patch_unknown_entry')
    required = DISABLED_IDS | {'credentials', 'agent-instructions', 'session-persistence-jsonl'}
    _require(required <= seen <= required | EXTRA_DISABLED_IDS, 'patch_constraints_missing')
    expected = {'receiptPath', 'maxRequests', 'maxTokens', 'maxRequestBytes', 'provider', 'model'}
    _require(isinstance(insert, dict) and set(insert) == {'id', 'name', 'config'}
             and insert['id'] == 'study-single-request-guard'
             and insert['name'] == guard.as_uri() and isinstance(insert['config'], dict)
             and set(insert['config']) == expected, 'patch_guard_invalid')
    config = insert['config']
    _require(type(config['maxRequests']) is int and config['maxRequests'] == 1
             and type(config['maxTokens']) is int and config['maxTokens'] == 64
             and type(config['maxRequestBytes']) is int and config['maxRequestBytes'] == 65536
             and config['provider'] == PROVIDER and config['model'] == MODEL,
             'patch_guard_constraints_changed')
    generated = [{'id': key, 'disabled': True} for key in sorted(DISABLED_IDS | EXTRA_DISABLED_IDS)]
    generated.extend([
        {'id': 'credentials', 'config': {'path': str(home / '.credentials.yaml'), 'watch': False}},
        {'id': 'agent-instructions', 'config': INSTRUCTIONS},
        # SDK notifications supply synthetic evidence. Do not persist native auth errors.
        {'id': 'session-persistence-jsonl', 'disabled': True},
        {'insert': [{'id': insert['id'], 'name': guard.as_uri(), 'config': {
            **config, 'receiptPath': str(guard_receipt)}}]},
    ])
    return generated, _sha(raw)


def _environment(home):
    env = {key: value for key, value in os.environ.items() if key.upper() in ENV_KEYS}
    env.update(ELECTRON_RUN_AS_NODE='1', DSH_HOME=str(home),
        DSH_AGENTS_HOME=str(home / 'agents'), DSH_TELEMETRY_DISABLED='1',
        DSH_PRIMARY_RUNTIME='', NO_BROWSER='1')
    return env


def _exchange(argv, workspace, env, prompt, timeout_seconds, guard_receipt):
    process = subprocess.Popen(argv, cwd=str(workspace), env=env, shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding='utf-8', errors='replace',
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    peer = SDKPeer(process, allow_prompts=True, max_prompts=1)
    deadline = time.monotonic() + timeout_seconds
    session = str(uuid.uuid4())  # Official SDK creates the caller-supplied identity.
    def rpc(method, params):
        remaining = deadline - time.monotonic()
        _require(remaining > 0, 'process_timeout')
        return peer.request(method, params, timeout=remaining)
    failure = None
    failure_method = None
    result = None
    start = None
    try:
        initialized = rpc('initialize', {'cwd': str(workspace), 'provider': PROVIDER,
            'model': MODEL, 'reasoningEffort': 'off', 'maxTokens': 64})
        _require(initialized == {'serverInfo': {'name': 'deepseek-harness-sdk-runtime',
            'version': '0.0.1'}}, 'sdk_initialize_invalid')
        cwd = rpc('session/working-directory/set', {'sessionId': session, 'path': str(workspace)})
        _require(cwd == {'cwd': str(workspace)}, 'sdk_workspace_mismatch')
        # A successful initialize does not prove an optional plugin was loaded.
        # Require this process's fresh, strictly zero guard receipt BEFORE prompt.
        _guard_ready(guard_receipt)
        start = len(peer.notifications)
        ack = rpc('session/prompt', {'sessionId': session,
            'contentBlocks': [{'type': 'text', 'text': prompt}]})
        _require(isinstance(ack, dict) and isinstance(ack.get('messageId'), str), 'sdk_prompt_ack_invalid')
        _require(rpc('session/wait', {'sessionId': session}) == {}, 'sdk_wait_invalid')
        result = summarize_session(peer.notifications[start:], session)
    except _Failure as error:
        failure = str(error)
        failure_method = getattr(peer, 'failure_method', None)
    except SDKTransportError as error:
        failure = error.code
        failure_method = getattr(peer, 'failure_method', None)
    except (TimeoutError, subprocess.TimeoutExpired):
        failure = 'process_timeout'
        failure_method = getattr(peer, 'failure_method', None)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError):
        failure = 'sdk_transport_or_runtime_failure'
        failure_method = getattr(peer, 'failure_method', None)
    finally:
        # A timed-out RPC may still own stdout: do not pipeline a new request.
        if failure != 'process_timeout' and process.poll() is None:
            try:
                _require(rpc('shutdown', {}) == {}, 'sdk_shutdown_invalid')
                process.stdin.close()
                process.wait(timeout=max(.1, min(10, deadline - time.monotonic())))
            except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired):
                failure = failure or 'sdk_shutdown_failed'
        if process.poll() is None:
            process.kill()  # Exact child only; never the existing GUI application.
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                failure = failure or 'process_did_not_exit'
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
    if result is None and start is not None:
        result = summarize_session(peer.notifications[start:], session)
    return {'summary': result, 'error': failure, 'exit_code': process.returncode,
            'stderr_bytes': peer.stderr_bytes, 'failure_rpc_method': failure_method,
            'rpc_error_code': getattr(peer, 'last_rpc_error_code', None),
            'safe_stderr_codes': sorted(getattr(peer, 'stderr_codes', set())),
            'stdout_catalog_diagnostics': getattr(peer, 'stdout_catalog_diagnostics', 0)}


def _guard_evidence(path):
    counts = _json(_regular(path, 8192).read_bytes())
    base = {'agent_attempt_count', 'stream_attempt_count', 'allowed_stream_count', 'requests'}
    _require(isinstance(counts, dict) and set(counts) in (base, base | {'reject_code', 'shape'},
             base | {'reject_code', 'shape', 'dry_run'}),
        'guard_receipt_invalid')
    _require(all(type(counts[key]) is int and 0 <= counts[key] <= 4096 for key in
        ('agent_attempt_count', 'stream_attempt_count', 'allowed_stream_count')),
        'guard_receipt_invalid')
    _require(counts['allowed_stream_count'] <= 1, 'guard_receipt_invalid')
    items = counts['requests']
    _require(isinstance(items, list) and len(items) == counts['allowed_stream_count'],
             'guard_receipt_invalid')
    for item in items:
        _require(isinstance(item, dict) and set(item) == {'count', 'bodyhash', 'bytes', 'maxTokens'}
            and type(item['count']) is int and item['count'] == 1
            and type(item['bytes']) is int and 0 < item['bytes'] <= 65536
            and type(item['maxTokens']) is int and item['maxTokens'] == 64
            and isinstance(item['bodyhash'], str) and re.fullmatch('[a-f0-9]{64}', item['bodyhash']),
            'guard_receipt_invalid')
    if 'reject_code' in counts:
        _require(counts['reject_code'] is None or counts['reject_code'] in {
            'agent_attempt_limit', 'call_config_bounds', 'stream_attempt_limit',
            'request_bounds', 'route_mismatch', 'tools_not_empty', 'messages_missing',
            'message_role', 'message_content', 'content_not_text',
            'request_not_serializable', 'request_too_large', 'dry_run_block'}, 'guard_receipt_invalid')
        shape = counts['shape']
        if shape is None:
            _require(counts['reject_code'] is None and counts['allowed_stream_count'] == 0,
                     'guard_receipt_invalid')
            if 'dry_run' in counts:
                _require(type(counts['dry_run']) is bool, 'guard_receipt_invalid')
            return counts
        shape_keys = {'stage', 'keys', 'unknown_key_count', 'provider_matches',
            'model_matches', 'max_tokens_present', 'max_tokens_type', 'reasoning_off',
            'reasoning_present', 'tools_type', 'tool_count', 'message_count', 'roles',
            'content_types', 'content_arrays'}
        _require(isinstance(shape, dict) and set(shape) == shape_keys, 'guard_receipt_invalid')
        known = {'provider', 'model', 'maxTokens', 'reasoningEffort', 'messages', 'tools',
            'toolHistory', 'sessionId', 'signal', 'system', 'temperature', 'stop',
            'purpose', 'contextWindow'}
        _require(shape['stage'] in {'agent_request', 'full_request'}
            and isinstance(shape['keys'], list) and len(shape['keys']) <= len(known)
            and all(key in known for key in shape['keys']), 'guard_receipt_invalid')
        _require(all(type(shape[key]) is bool for key in ('provider_matches', 'model_matches',
            'max_tokens_present', 'reasoning_off', 'reasoning_present')), 'guard_receipt_invalid')
        _require(all(type(shape[key]) is int and 0 <= shape[key] <= 4096
            for key in ('unknown_key_count', 'tool_count', 'message_count')), 'guard_receipt_invalid')
        types = {'undefined', 'number', 'string', 'boolean', 'object', 'function', 'symbol', 'bigint'}
        _require(shape['max_tokens_type'] in types and shape['tools_type'] in types | {'array'},
                 'guard_receipt_invalid')
        _require(isinstance(shape['roles'], list) and len(shape['roles']) == shape['message_count']
            and all(role in {'system', 'developer', 'user', 'assistant', 'tool', 'other'}
                    for role in shape['roles']), 'guard_receipt_invalid')
        _require(isinstance(shape['content_arrays'], list)
            and len(shape['content_arrays']) == shape['message_count']
            and all(type(value) is bool for value in shape['content_arrays']), 'guard_receipt_invalid')
        _require(isinstance(shape['content_types'], list)
            and len(shape['content_types']) == shape['message_count'], 'guard_receipt_invalid')
        for blocks in shape['content_types']:
            _require(isinstance(blocks, list) and len(blocks) <= 4096 and all(value in {
                'text', 'thinking', 'tool-call', 'tool-result', 'image', 'system-snapshot',
                'system-prompt', 'tool-addition', 'tool-removal', 'other'} for value in blocks),
                'guard_receipt_invalid')
    if 'dry_run' in counts:
        _require(type(counts['dry_run']) is bool, 'guard_receipt_invalid')
    return counts


def _guard_ready(path):
    try:
        counts = _guard_evidence(path)
        _require(counts == {'agent_attempt_count': 0, 'stream_attempt_count': 0,
            'allowed_stream_count': 0, 'requests': [], 'reject_code': None,
            'shape': None, 'dry_run': False}, 'guard_not_ready')
    except (OSError, ValueError, TypeError, KeyError):
        raise _Failure('guard_not_ready') from None


def _native_instruction_evidence(summary, memory_text):
    """Retain only the registered AGENTS material, independently of QA outcome."""
    if not isinstance(summary, dict):
        return []
    memory_digest = hashlib.sha1(memory_text.encode('utf-8')).hexdigest()
    baselines = []
    for baseline in summary.get('native_instruction_baselines') or []:
        source = baseline.get('source') or {}
        changes = source.get('changes') or []
        content = baseline.get('content') or []
        rendered = ''.join(block.get('text', '') for block in content if block.get('type') == 'text')
        if (source.get('kind') == 'agent-instructions' and source.get('baseline') is True
                and memory_text.strip() in rendered and any(
                item.get('digest') == memory_digest and str(item.get('path', '')).replace('\\', '/').endswith('AGENTS.md')
                for item in changes)):
            matching = [item for item in changes if item.get('digest') == memory_digest
                and str(item.get('path', '')).replace('\\', '/').endswith('AGENTS.md')]
            baselines.append({'seq': baseline.get('seq'), 'source': {
                'kind': 'agent-instructions', 'baseline': True,
                'changes': [{key: item[key] for key in ('action', 'scope', 'path', 'digest') if key in item}
                            for item in matching]},
                # Do not return unrelated text from a combined native baseline.
                'content': [{'type': 'text', 'text': memory_text}],
                'native_rendered_content_sha256': _sha(rendered.encode('utf-8'))})
    return baselines


def _public_summary(summary, memory, memory_text):
    _require(isinstance(summary, dict), 'sdk_summary_missing')
    _require(summary.get('last_terminal_reason') == {'kind': 'completed'}
             and summary.get('final_assistant_interrupted') is False, 'sdk_turn_not_completed')
    answer = summary.get('final_assistant_text')
    _require(isinstance(answer, str) and bool(answer.strip())
             and len(answer.encode('utf-8')) <= 4096, 'result_text_missing')
    baselines = _native_instruction_evidence(summary, memory_text)
    _require(bool(baselines), 'native_instruction_evidence_missing')
    usage_events = []
    for event in summary.get('assistant_usage_events') or []:
        native = event.get('usage')
        _require(native is None or isinstance(native, dict), 'usage_invalid')
        usage = {key: value for key, value in (native or {}).items() if key in TOKEN_KEYS}
        _require(all(type(value) is int and value >= 0 for value in usage.values()), 'usage_invalid')
        _require(all(usage.get(key, 0) <= 64 for key in
            ('outputTokens', 'output_tokens', 'completion_tokens')), 'output_token_limit_exceeded')
        usage_events.append({'turn': event.get('turn'), 'step': event.get('step'), 'usage': usage or None})
    source = summary.get('final_assistant_source') or {}
    _require(source.get('provider') == PROVIDER and source.get('model') == MODEL,
             'response_model_mismatch')
    return {'answer': answer.strip(), 'raw_response': answer,
        'usage': usage_events[-1]['usage'] if usage_events else None,
        'assistant_usage_events': usage_events, 'native_instruction_baselines': baselines,
        'native_instruction_loaded': True, 'last_terminal_reason': {'kind': 'completed'}}


def run_deepseek_question(workspace, prompt, *, runtime_home, patch_template,
                          guard_path, credentials_source=DEFAULT_CREDENTIALS,
                          timeout_seconds=120):
    """One fresh official SDK process, one guarded synthetic question.

    No call occurs at import. The supplied workspace and fresh home must be below
    repo/results. The caller owns overall experiment authorization/cost budget.
    """
    receipt = {'status': 'error', 'answer': None, 'raw_response': None, 'usage': None,
        'model': MODEL, 'version': None, 'wrapper_version': VERSION, 'error': None,
        'invocation_started': False, 'native_instruction_loaded': False,
        'native_instruction_baselines': [], 'guard_counts': None,
        'guard_bytes_scope': 'harness_request_json_without_signal',
        'physical_model_requests': None, 'credentials_source_unchanged': None,
        'temporary_credentials_removed': None, 'exit_code': None}
    source, source_hash, copied, home, guard = None, None, None, None, None
    try:
        _require(isinstance(prompt, str) and bool(prompt.strip()) and '\0' not in prompt, 'prompt_invalid')
        _require(len(prompt.encode('utf-8')) <= MAX_PROMPT_BYTES, 'prompt_too_large')
        _require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
                 and 0 < timeout_seconds <= 120, 'timeout_invalid')
        workspace, memory, memory_text = _workspace(workspace)
        receipt['agent_memory_file_sha256'] = _sha(memory)
        home = _under_results(runtime_home, existing=False)
        _require(not home.exists(), 'runtime_home_not_fresh')
        _require(home.parent.is_dir(), 'runtime_home_parent_missing')
        guard = _regular(guard_path, 128 * 1024)
        _require(guard.is_relative_to(GUARD_ROOT.resolve(strict=True)), 'guard_outside_probe_root')
        receipt['guard_sha256'] = _file_hash(guard)
        guard_receipt = GUARD_ROOT / ('dsh_guard_' + uuid.uuid4().hex + '.json')
        rows, template_hash = _patch(patch_template, guard, home, guard_receipt)
        receipt.update(patch_template_sha256=template_hash, guard_receipt_path=str(guard_receipt))
        runtime = _runtime_metadata()
        receipt.update(version=runtime['version'], cli_entry_sha256=runtime['cli_entry_sha256'],
                       runtime_archive_sha256=runtime['archive_sha256'])
        source = _regular(credentials_source, 2 * 1024 * 1024)
        _require(not source.is_relative_to(home), 'credential_source_not_original')
        source_hash = _file_hash(source)
        home.mkdir(mode=0o700)
        _restrict_private_dir(home)
        (home / 'agents').mkdir(mode=0o700)
        copied = home / '.credentials.yaml'
        with copied.open('xb') as output, source.open('rb') as original:
            shutil.copyfileobj(original, output, 65536)
        copied.chmod(0o600)
        _require(_file_hash(copied) == source_hash and _file_hash(source) == source_hash,
                 'credential_source_changed')
        patch = home / 'study.patch.yml'
        patch.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
        argv = [runtime['executable'], '--expose-internals', runtime['cli'],
                '--profile', 'sdk', '--patch', str(patch)]
        receipt.update(argv_sha256=_sha(json.dumps(argv, ensure_ascii=False).encode('utf-8')),
                       invocation_started=True)
        response = _exchange(argv, workspace, _environment(home), prompt, timeout_seconds, guard_receipt)
        receipt.update(exit_code=response['exit_code'], stderr_bytes=response['stderr_bytes'])
        for key in ('failure_rpc_method', 'rpc_error_code', 'safe_stderr_codes',
                    'stdout_catalog_diagnostics'):
            receipt[key] = response.get(key)
        # Retain only schema-filtered counters, including a failed request with 0.
        try:
            receipt['guard_counts'] = _guard_evidence(guard_receipt)
        except (OSError, ValueError, TypeError, KeyError):
            receipt['guard_evidence_error'] = 'guard_receipt_unavailable_or_invalid'
        summary = response.get('summary') or {}
        matched_baselines = _native_instruction_evidence(summary, memory_text)
        receipt.update(native_instruction_baselines=matched_baselines,
                       native_instruction_loaded=bool(matched_baselines))
        terminal = summary.get('last_terminal_reason') or {}
        if terminal.get('kind') in {'completed', 'max-tokens', 'error', 'aborted', 'blocked'}:
            receipt['last_terminal_reason'] = {'kind': terminal['kind']}
        _require(_sha(_workspace(workspace)[1]) == receipt['agent_memory_file_sha256'],
                 'memory_changed_during_call')
        _require(_file_hash(guard) == receipt['guard_sha256'], 'guard_changed_during_call')
        _require(_file_hash(runtime['archive']) == runtime['archive_sha256'], 'runtime_changed_during_call')
        _require(response['error'] is None, response['error'] or 'sdk_runtime_failure')
        _require(receipt['guard_counts'] is not None and all(
            receipt['guard_counts'][key] == 1 for key in
            ('agent_attempt_count', 'stream_attempt_count', 'allowed_stream_count')),
            'guard_request_limit_or_missing')
        positive = receipt['guard_counts']
        _require(positive.get('dry_run') is False and positive.get('reject_code') is None
            and isinstance(positive.get('shape'), dict), 'guard_positive_evidence_missing')
        shape = positive['shape']
        _require(shape['stage'] == 'full_request' and shape['provider_matches']
            and shape['model_matches'] and shape['reasoning_off'] and shape['max_tokens_present']
            and shape['max_tokens_type'] == 'number' and shape['tool_count'] == 0
            and shape['tools_type'] in {'undefined', 'array'}, 'guard_positive_evidence_invalid')
        _require(response['exit_code'] == 0, 'process_exit_nonzero')
        receipt.update(_public_summary(response['summary'], memory, memory_text))
        receipt.update(status='ok', error=None)
    except _Failure as error:
        receipt.update(error=str(error))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError,
            struct.error, subprocess.SubprocessError):
        receipt.update(error='deepseek_preflight_or_process_failure')
    finally:
        if copied is not None:
            try:
                copied.unlink(missing_ok=True)
                receipt['temporary_credentials_removed'] = not copied.exists()
            except OSError:
                receipt['temporary_credentials_removed'] = False
            if not receipt['temporary_credentials_removed']:
                receipt.update(status='error', error='temporary_credential_cleanup_failed')
        if source is not None and source_hash is not None:
            try:
                receipt['credentials_source_unchanged'] = _file_hash(source) == source_hash
            except OSError:
                receipt['credentials_source_unchanged'] = False
            if not receipt['credentials_source_unchanged']:
                receipt.update(status='error', error='credential_source_changed')
        if receipt['error'] is not None:
            receipt.update(status='error', answer=None, raw_response=None)
    return receipt
