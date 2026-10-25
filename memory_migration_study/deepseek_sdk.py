"""Stdlib client for the installed official DSH SDK JSON-lines transport.

Importing this module never starts a process, reads credentials, or sends input.
The caller owns official CLI launch, workspace isolation, and physical-request
budget enforcement. Prompt RPCs are disabled unless explicitly enabled, with an
independent maximum of four accepted prompt submissions. This is NOT a physical
model-request limiter: use the parent's guarded broker for that purpose.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from collections import Counter


class SDKTransportError(RuntimeError):
    """Fixed diagnostic codes never contain native error/account text."""
    def __init__(self, code, *, rpc_code=None):
        self.code = code
        self.rpc_code = rpc_code
        super().__init__(code)


class SDKPeer:
    METADATA_METHODS = frozenset({
        'initialize', 'session/working-directory/set',
        'session/working-directory/get', 'shutdown',
    })

    def __init__(self, process, *, allow_prompts=False, max_prompts=0):
        if type(max_prompts) is not int or not 0 <= max_prompts <= 4:
            raise ValueError('max_prompts must be an integer from 0 through 4.')
        if not allow_prompts and max_prompts:
            raise ValueError('A prompt budget requires explicit allow_prompts=True.')
        self.process = process
        self.allow_prompts = allow_prompts
        self.max_prompts = max_prompts
        self.prompt_submissions = 0
        self.requests = []
        self.notifications = []
        self.stderr_bytes = 0
        self.stderr_codes = set()
        self.stdout_catalog_diagnostics = 0
        self.failure_method = None
        self.last_rpc_error_code = None
        self._lines = queue.Queue()
        self._call_lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._read_errors, daemon=True).start()

    def _read(self):
        total = 0
        while True:
            line = self.process.stdout.readline(262145)
            if not line:
                break
            total += len(line.encode('utf-8'))
            if len(line) > 262144 or total > 4 * 1024 * 1024:
                self._lines.put({'_transport_error': 'sdk_stdout_limit'})
                break
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError('Expected an object.')
            except (ValueError, TypeError):
                # The shipped account provider uses console.info for catalog
                # notices, contaminating its SDK stdout. Discard only this exact
                # official tag; never retain the diagnostic's account/body text.
                if line.startswith('[llm-deepseek-account] '):
                    self.stdout_catalog_diagnostics += 1
                    continue
                self._lines.put({'_transport_error': 'sdk_non_json_stdout'})
                continue
            self._lines.put(value)
        self._lines.put({'_eof': True})

    def _read_errors(self):
        # Do not print/retain native diagnostic strings: they can contain secrets.
        while True:
            line = self.process.stderr.readline(262145)
            if not line:
                break
            self.stderr_bytes += len(line.encode('utf-8'))
            for needle, code in (
                ('sessionPersistence', 'optional_session_persistence_warning'),
                ('checkpoint', 'checkpoint_warning'),
                ('ACCOUNT_SIGN_IN_REQUIRED', 'account_sign_in_required'),
                ('ACCOUNT_TOKEN_INVALID', 'account_token_invalid'),
                ('ETIMEDOUT', 'network_timeout'), ('ECONNREFUSED', 'network_refused'),
            ):
                if needle in line:
                    self.stderr_codes.add(code)

    def request(self, method, params, *, timeout=60):
        with self._call_lock:
            if method == 'session/prompt':
                if not self.allow_prompts or self.prompt_submissions >= self.max_prompts:
                    raise PermissionError('Prompt RPC disabled or prompt-submission budget exhausted.')
                self.prompt_submissions += 1  # Do not refund a rejected/uncertain send.
            elif method == 'session/wait':
                if not self.allow_prompts:
                    raise PermissionError('Metadata mode refuses session/wait.')
            elif method not in self.METADATA_METHODS:
                # resume can repair interrupted history; do not admit it implicitly.
                raise ValueError('Method is outside this bounded client contract.')
            request_id = len(self.requests) + 1
            self.requests.append({'id': request_id, 'method': method})
            self.failure_method = method
            payload = {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params}
            self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + '\n')
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError('Native SDK response deadline exceeded; caller must terminate its child.')
                try:
                    value = self._lines.get(timeout=left)
                except queue.Empty as exc:
                    raise TimeoutError('Native SDK response deadline exceeded.') from exc
                if value.get('_transport_error') or value.get('_eof'):
                    raise SDKTransportError(value.get('_transport_error') or 'sdk_stdout_eof')
                if value.get('id') == request_id:
                    if 'error' in value:
                        # Only expose stable error code, never native text/payload.
                        code = value['error'].get('code')
                        self.last_rpc_error_code = code if type(code) is int else None
                        raise SDKTransportError('sdk_rpc_error', rpc_code=self.last_rpc_error_code)
                    self.failure_method = None
                    return value.get('result')
                if 'method' in value and 'id' not in value:
                    self.notifications.append(value)
                else:
                    raise SDKTransportError('sdk_unexpected_response')

    def prompt_and_wait(self, session_id, text, *, timeout=90):
        """Explicit opt-in only. Ack is not completion; wait follows all events."""
        if not isinstance(text, str) or not text:
            raise ValueError('A nonempty text prompt is required.')
        start = len(self.notifications)
        ack = self.request('session/prompt', {
            'sessionId': session_id, 'contentBlocks': [{'type': 'text', 'text': text}],
        }, timeout=timeout)
        waited = self.request('session/wait', {'sessionId': session_id}, timeout=timeout)
        result = summarize_session(self.notifications[start:], session_id)
        result.update(prompt_ack=ack, wait_result=waited)
        return result


def summarize_session(notifications, session_id):
    """Parse committed native events; do not treat stream deltas as final text."""
    events = []
    statuses = []
    for value in notifications:
        params = value.get('params') or {}
        if params.get('sessionId') != session_id:
            continue
        if value.get('method') == 'session.event' and isinstance(params.get('event'), dict):
            events.append(params['event'])
        elif value.get('method') == 'session.status':
            statuses.append(params.get('status'))
    counts = Counter(event.get('type') for event in events)
    assistant = [event for event in events if event.get('type') == 'assistant/message']
    final_data = assistant[-1].get('data', {}) if assistant else {}
    message = final_data.get('message') or {}
    text = ''.join(block.get('text', '') for block in message.get('content', [])
                   if block.get('type') == 'text') if assistant else None
    usage = [{'seq': event.get('seq'), 'turn': event.get('data', {}).get('turn'),
              'step': event.get('data', {}).get('step'),
              'usage': event.get('data', {}).get('usage')}
             for event in assistant]
    baselines = []
    for event in events:
        data = event.get('data') or {}
        source = data.get('source') or {}
        if (event.get('type') == 'user/message'
                and source.get('kind') == 'agent-instructions'
                and source.get('baseline') is True):
            baselines.append({
                'seq': event.get('seq'), 'source': source,
                'content': data.get('content'),
            })
    terminals = [event.get('data', {}).get('reason') for event in events
                 if event.get('type') == 'turn/end']
    return {
        'final_assistant_text': text,
        'final_assistant_source': message.get('source'),
        'final_assistant_interrupted': final_data.get('interrupted', False) if assistant else None,
        'assistant_usage_events': usage,  # Missing usage stays null, never becomes 0.
        'terminal_reasons': terminals,
        'last_terminal_reason': terminals[-1] if terminals else None,
        'native_instruction_baselines': baselines,
        'native_instruction_loaded': bool(baselines),
        'native_step_start_count': counts.get('step/start', 0),
        'native_request_header_count': counts.get('request/header', 0),
        'physical_model_requests': None,  # Must come from broker/provider evidence.
        'native_event_counts': dict(counts), 'native_statuses': statuses,
    }


if __name__ == '__main__':
    print('Library only. No process launched, no credentials read, no prompt sent.')
