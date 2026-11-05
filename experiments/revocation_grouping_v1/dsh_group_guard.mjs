// Per-process guard loaded by the official SDK --patch interface.
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
export const name = 'study-group-single-request-guard';
export const inject = ['llm', 'deepseekAccount'];
const hash = text => createHash('sha256').update(text).digest('hex');
const stop = () => { throw Error('GROUP_SDK_GUARD_BLOCKED'); };

// Official 0.2.1-rc.3 factories: dsh-working-directory.contextText,
// dsh-sandbox-policy.renderPolicyContext, dsh-user-approval.ASK_SENTENCE,
// and dsh-system-prompt.joinContextSections. No business source is included.
export function runtimeContextText(workspace) {
  const quoted = JSON.stringify(workspace);
  return 'Current runtime context. This snapshot supersedes earlier runtime-context snapshots.\n\n'
    + `Current working directory: ${quoted}.\n\n`
    + `Current DSH file policy: workspace-write. Any available operation enforced by the DSH file sandbox may modify files under the session workspace: ${quoted}. Some platform temporary areas may also be writable.\n\n`
    + 'Approval policy: ask. Operations that require approval may ask through the configured answerers; without an available answerer, the request fails closed.';
}

export function createGuard(config, persist, saveRequest) {
  if (config.maxRequests !== 1 || !Number.isSafeInteger(config.maxTokens) || config.maxTokens < 1 || config.maxTokens > 2048
      || !Number.isSafeInteger(config.maxRequestBytes) || config.maxRequestBytes < 1 || config.maxRequestBytes > 256000
      || !/^[a-f0-9]{64}$/.test(config.dispatchSha256) || typeof config.workspace !== 'string' || !config.workspace) stop();
  const state = { agent_attempt_count: 0, stream_attempt_count: 0, allowed_stream_count: 0, requests: [], reject_code: null };
  const block = code => { state.reject_code = code; persist(structuredClone(state)); stop(); };
  persist(structuredClone(state));
  return {
    state,
    async agentRequest(payload, next) {
      state.agent_attempt_count++;
      persist(structuredClone(state));
      if (state.agent_attempt_count !== 1) block('second_agent_attempt');
      const call = await next();
      if (call?.maxTokens !== config.maxTokens || call.reasoningEffort !== 'off') block('call_config');
      return call;
    },
    llmStream(options, next) {
      state.stream_attempt_count++;
      persist(structuredClone(state));
      if (state.stream_attempt_count !== 1 || state.agent_attempt_count !== 1) block('second_stream');
      if (options?.provider !== 'deepseek-account' || options.model !== 'deepseek-flash'
          || options.maxTokens !== config.maxTokens || options.reasoningEffort !== 'off') block('route');
      if (options.tools !== undefined && (!Array.isArray(options.tools) || options.tools.length)) block('tools');
      if (!Array.isArray(options.messages) || !options.messages.length) block('messages');
      const business = [];
      for (const message of options.messages) {
        if (!['system', 'user'].includes(message.role) || !Array.isArray(message.content)) block('history');
        for (const piece of message.content) {
          if (piece.type !== 'text' || typeof piece.text !== 'string') block('non_text');
          if (message.role === 'user') business.push(piece.text);
        }
      }
      // Fresh official SDK surface is the exact dispatch followed by its exact
      // native runtime snapshot. No extra user block or arbitrary prose passes.
      const runtimeHash = hash(runtimeContextText(config.workspace));
      if (business.length !== 2 || hash(business[0]) !== config.dispatchSha256 || hash(business[1]) !== runtimeHash) block('business_input_mismatch');
      const { signal, ...facts } = options;
      let body;
      try { body = JSON.stringify(facts); } catch { block('unserializable'); }
      const bytes = Buffer.byteLength(body, 'utf8');
      if (bytes > config.maxRequestBytes) block('request_size');
      // No transport credentials have been added at the llm/stream hook.
      saveRequest(body);
      state.allowed_stream_count++;
      state.requests.push({ count: 1, bodyhash: hash(body), bytes, maxTokens: options.maxTokens,
        business_input_sha256: config.dispatchSha256, runtime_context_sha256: runtimeHash,
        user_text_blocks: 2, tools: 0, reasoningEffort: 'off' });
      persist(structuredClone(state));
      return next();
    },
  };
}

export async function apply(ctx, config) {
  const persist = state => writeFileSync(config.receiptPath, JSON.stringify(state, null, 2), { mode: 0o600 });
  const guard = createGuard(config, persist, body => writeFileSync(config.requestPath, body, { flag: 'wx', mode: 0o600 }));
  ctx.on('agent/request', guard.agentRequest, { global: true, prepend: true });
  ctx.on('llm/stream', guard.llmStream, { global: true, prepend: true });
  // Injection is the service-load barrier; the private ready record is written
  // only after official account and provider metadata have actually resolved.
  let metadataStage = 'account_state';
  let accountState;
  let observedRetryPolicy;
  try {
    const account = ctx.get('deepseekAccount');
    const state = await account.getState();
    accountState = ['credential-stored', 'signed-out'].includes(state?.status) ? state.status : 'unknown';
    if (state?.status !== 'credential-stored') throw Error('not_signed_in');
    metadataStage = 'provider_retry_policy';
    // Service injection alone does not order independent adapter registration.
    // Wait only for local registration; this never submits a model request.
    let policy;
    const until = Date.now() + 8000;
    while (Date.now() < until) {
      try { policy = ctx.get('llm').providerRetryPolicy('deepseek-account'); } catch {}
      if (policy?.mode === 'normal' && policy.maxRetries === 0) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    observedRetryPolicy = policy && { mode: policy.mode, maxRetries: policy.maxRetries };
    if (policy?.mode !== 'normal' || policy.maxRetries !== 0) throw Error('retry_policy');
    metadataStage = 'balance_query';
    const balance = await account.getBalance({ version: '0.2.1-rc.3', locale: 'zh-CN', timezoneOffsetSeconds: 28800 });
    metadataStage = 'balance_shape';
    if (balance?.status !== 'ready' || !Array.isArray(balance.value)) throw Error('balance_unavailable');
    const wallets = [...balance.value, ...(Array.isArray(balance.bonusWallets) ? balance.bonusWallets : [])]
      .filter(row => row.currency === 'CNY');
    if (!wallets.length || wallets.some(row => typeof row.balance !== 'string' || !/^\d+(?:\.\d+)?$/.test(row.balance))) throw Error('balance_shape');
    const walletCny = wallets.reduce((sum, row) => sum + Number(row.balance), 0);
    if (!Number.isFinite(walletCny) || walletCny < 0) throw Error('balance_invalid');
    writeFileSync(config.metadataPath, JSON.stringify({ status: 'ready', wallet_cny: String(walletCny),
      observed_at_unix: Date.now() / 1000, account_service_loaded: true, provider_retry_max: 0,
      balance_scope: 'CNY normal plus bonus wallets; official isolated account service', model_requests: 0 }), { mode: 0o600 });
  } catch {
    writeFileSync(config.metadataPath, JSON.stringify({ status: 'unavailable', reason: 'official_account_metadata_not_ready',
      stage: metadataStage, account_state: accountState, retry_policy: observedRetryPolicy, model_requests: 0 }), { mode: 0o600 });
  }
}
