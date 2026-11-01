// Offline metadata-observer qualification. No real queue, session or model API.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { observeMetadata, observerStats, classifySafeError } from './source-memory.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const BUSY = 'Queue record is busy; retry this call without resending the task';
const noWait = async () => {};
const forbiddenTransport = () => ({ send: 0, wake: 0, pump: 0, model: 0 });

test('exact vendor busy exception is reproduced using only an isolated synthetic queue', async () => {
  const base = path.join(root, 'results/pre_delivery_revocation_20261101/source_observer_diagnostic01');
  fs.mkdirSync(base, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(base, 'synthetic-queue-'));
  const attempt = 'run-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const dir = path.join(tmp, attempt); fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ attemptId: attempt,
    taskId: 'synthetic-only', driver: 'desktop-queue', status: 'working',
    sessionId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    deadline: new Date(Date.now() + 60000).toISOString(), updatedAt: new Date().toISOString() }));
  fs.writeFileSync(path.join(dir, 'queue-write.lock'), JSON.stringify({ pid: process.pid }));
  const { DesktopQueue } = await import(pathToFileURL(path.join(root,
    '.runtime/gateways/codex-workbuddy-gateway-windows/dist/desktop-queue.js')).href);
  const queue = new DesktopQueue({ runsDir: tmp, dbFile: path.join(tmp, 'not-opened.sqlite') });
  assert.throws(() => queue.messages(attempt + ':0'), error => {
    assert.equal(error.message, BUSY);
    assert.equal(classifySafeError(error).error_class, 'queue_record_busy');
    return true;
  });
  assert.equal(fs.existsSync(path.join(tmp, 'not-opened.sqlite')), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'state.json'))).status, 'working');
});

test('busy metadata observation succeeds after one bounded reread with zero sends or pumps', async () => {
  const stats = observerStats(), transport = forbiddenTransport(), events = [];
  let reads = 0;
  const answer = await observeMetadata(() => { reads++;
    if (reads === 1) throw new Error(BUSY);
    return { status: 'needs_review', late: true };
  }, { stats, pause: noWait, onRetry: event => events.push(event) });
  assert.equal(answer.status, 'needs_review'); assert.equal(reads, 2);
  assert.equal(stats.metadata_retries, 1); assert.equal(events.length, 1);
  assert.deepEqual(transport, { send: 0, wake: 0, pump: 0, model: 0 });
});

test('persistent exact busy is stopped after two observation retries', async () => {
  const stats = observerStats(), transport = forbiddenTransport(); let reads = 0;
  await assert.rejects(observeMetadata(() => { reads++; throw new Error(BUSY); },
    { stats, pause: noWait }), { message: BUSY });
  assert.equal(reads, 3); assert.equal(stats.metadata_retries, 2);
  assert.deepEqual(transport, { send: 0, wake: 0, pump: 0, model: 0 });
});

test('the shared total retry limit also applies to later and final sync observations', async () => {
  const stats = observerStats(); let reads = 0;
  for (let operation = 0; operation < 3; operation++) {
    await assert.rejects(observeMetadata(() => { reads++; throw new Error(BUSY); },
      { stats, pause: noWait }), { message: BUSY });
  }
  assert.equal(stats.metadata_operations, 3); assert.equal(stats.metadata_retries, 4);
  assert.equal(reads, 7);
});

test('unconfirmed database or unknown errors are never silently retried', async () => {
  for (const error of [new TypeError('unknown private detail'),
    Object.assign(new Error('database is locked'), { code: 'SQLITE_BUSY' })]) {
    const stats = observerStats(); let reads = 0;
    await assert.rejects(observeMetadata(() => { reads++; throw error; },
      { stats, pause: () => assert.fail('unknown error must not sleep/retry') }), e => e === error);
    assert.equal(reads, 1); assert.equal(stats.metadata_retries, 0);
  }
});

test('safe error details retain only approved name/code/class and a hash', () => {
  const secret = 'lease-do-not-print-test-only';
  const detail = classifySafeError(Object.assign(new TypeError(secret), { code: 'ERR_INVALID_ARG_TYPE' }));
  assert.equal(detail.error_name, 'TypeError'); assert.equal(detail.error_code, 'ERR_INVALID_ARG_TYPE');
  assert.equal(detail.error_class, 'native_operation_unknown');
  assert.match(detail.message_sha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(detail).includes(secret), false);
  assert.equal(classifySafeError(Object.assign(new Error(secret), { code: secret })).error_code, null);
});
