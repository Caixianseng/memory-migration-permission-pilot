// Workspace-only plugin through the official --patch loader, not a network patch.
import { writeFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

export const name = 'study-single-request-guard';

function reject() { throw new Error('STUDY_NATIVE_REQUEST_GUARD_BLOCKED'); }

const knownKeys = new Set(['provider', 'model', 'maxTokens', 'reasoningEffort',
  'messages', 'tools', 'toolHistory', 'sessionId', 'signal', 'system',
  'temperature', 'stop', 'purpose', 'contextWindow']);
const knownRoles = new Set(['system', 'developer', 'user', 'assistant', 'tool']);
const knownTypes = new Set(['text', 'thinking', 'tool-call', 'tool-result', 'image',
  'system-snapshot', 'system-prompt', 'tool-addition', 'tool-removal']);
function safeShape(options, config, stage) {
  const value = options && typeof options === 'object' ? options : {};
  const messages = Array.isArray(value.messages) ? value.messages : [];
  return {
    stage, keys: Object.keys(value).filter(k => knownKeys.has(k)).sort(),
    unknown_key_count: Object.keys(value).filter(k => !knownKeys.has(k)).length,
    provider_matches: value.provider === config.provider,
    model_matches: value.model === config.model,
    max_tokens_present: Object.hasOwn(value, 'maxTokens'),
    max_tokens_type: typeof value.maxTokens,
    reasoning_off: value.reasoningEffort === 'off',
    reasoning_present: Object.hasOwn(value, 'reasoningEffort'),
    tools_type: Array.isArray(value.tools) ? 'array' : typeof value.tools,
    tool_count: Array.isArray(value.tools) ? value.tools.length : 0,
    message_count: messages.length,
    roles: messages.map(m => knownRoles.has(m.role) ? m.role : 'other'),
    content_types: messages.map(m => Array.isArray(m.content)
      ? m.content.map(b => knownTypes.has(b.type) ? b.type : 'other') : []),
    content_arrays: messages.map(m => Array.isArray(m.content)),
  };
}

export function createGuard(config, persist) {
  if (!config || config.maxRequests !== 1 || config.maxTokens !== 64
      || config.maxRequestBytes !== 65536) reject();
  const state = {
    agent_attempt_count: 0, stream_attempt_count: 0,
    allowed_stream_count: 0, requests: [], reject_code: null, shape: null,
    dry_run: config.dryRun === true,
  };
  const save = () => persist(structuredClone(state));
  const block = (code, options, stage = 'full_request') => {
    state.reject_code = code;
    state.shape = safeShape(options, config, stage);
    save();
    reject();
  };
  save();
  return {
    state,
    async agentRequest(payload, next) {
      state.agent_attempt_count++;
      save();
      if (state.agent_attempt_count > 1) block('agent_attempt_limit', {}, 'agent_request');
      const proposed = await next();
      if (!Number.isSafeInteger(proposed?.maxTokens) || proposed.maxTokens < 1
          || proposed.maxTokens > 64 || proposed.reasoningEffort !== 'off') block('call_config_bounds', proposed, 'agent_request');
      return proposed;
    },
    llmStream(options, next) {
      state.stream_attempt_count++;
      state.shape = safeShape(options, config, 'full_request');
      save();
      if (state.stream_attempt_count > 1 || state.agent_attempt_count !== 1) block('stream_attempt_limit', options);
      if (!options || !Number.isSafeInteger(options.maxTokens) || options.maxTokens < 1
          || options.maxTokens > 64 || options.reasoningEffort !== 'off') block('request_bounds', options);
      if (options.provider !== config.provider || options.model !== config.model) block('route_mismatch', options);
      if (options.tools !== undefined && (!Array.isArray(options.tools) || options.tools.length)) block('tools_not_empty', options);
      // This fixture intentionally permits only a fresh, text-only session.
      // It excludes file upload/stale-id retries and assistant replay payloads.
      if (!Array.isArray(options.messages) || !options.messages.length) block('messages_missing', options);
      for (const message of options.messages) {
        if (!['system', 'user'].includes(message.role)) block('message_role', options);
        if (!Array.isArray(message.content)) block('message_content', options);
        for (const piece of message.content) {
          if (piece.type !== 'text' || typeof piece.text !== 'string') block('content_not_text', options);
        }
      }
      // This is the official harness full request, not adapter-serialized HTTP.
      // signal is a process object and is deliberately excluded from JSON facts.
      const { signal, ...facts } = options;
      let body;
      try { body = JSON.stringify(facts); } catch { block('request_not_serializable', options); }
      const bytes = Buffer.byteLength(body, 'utf8');
      if (bytes > 65536) block('request_too_large', options);
      if (config.dryRun === true) block('dry_run_block', options);
      state.allowed_stream_count++;
      state.requests.push({
        count: state.allowed_stream_count,
        bodyhash: createHash('sha256').update(body).digest('hex'),
        bytes, maxTokens: options.maxTokens,
      });
      save();  // A write failure also fails closed before next()/the adapter.
      return next();
    },
  };
}

export function apply(ctx, config) {
  const root = realpathSync(dirname(fileURLToPath(import.meta.url)));
  const path = resolve(config.receiptPath ?? '');
  const parent = realpathSync(dirname(path));
  const rel = relative(root, parent);
  if ((rel && (rel.startsWith('..') || isAbsolute(rel))) || path === root) reject();
  const guard = createGuard(config, (state) => {
    writeFileSync(path, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
  });
  ctx.on('agent/request', guard.agentRequest, { global: true, prepend: true });
  ctx.on('llm/stream', guard.llmStream, { global: true, prepend: true });
}
