// Node tests for web/logic.js (no browser, no network). Run: node web/test_client.js
import assert from 'node:assert/strict';
import { Api, ApiError, PAGE, createPayload, dateError, diffChanges, label, messageFor, newClientKey, titleError,
  STATUSES } from './logic.js';

let passed = 0;
const test = async (name, fn) => { await fn(); passed += 1; console.log('ok', name); };

function fakeFetch(responses) {
  const calls = [];
  const fn = async (path, init) => {
    calls.push({ path, init });
    const next = responses.shift() || { status: 200, body: {} };
    return { ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.body };
  };
  fn.calls = calls;
  return fn;
}

await test('labels and messages', () => {
  assert.equal(label(STATUSES, 'blocked'), 'Блокирована');
  assert.equal(label(STATUSES, 'unknown'), 'unknown');
  assert.equal(messageFor(409).includes('изменились'), true);
  assert.equal(messageFor(500), 'Сервис временно недоступен.');
  assert.equal(new ApiError(404).message, 'Не найдено или нет доступа.');
});

await test('validation', () => {
  assert.equal(titleError('  '), 'Введите название.');
  assert.equal(titleError('x'.repeat(201)).length > 0, true);
  assert.equal(titleError(' ok '), '');
  assert.equal(dateError(''), '');
  assert.equal(dateError('2026-12-31'), '');
  assert.equal(dateError('31.12.2026').length > 0, true);
  assert.equal(dateError('2026-13-45').length > 0, true);
});

await test('client key is stable per call and fits the server limit', () => {
  const key = newClientKey(() => '123e4567-e89b-12d3-a456-426614174000');
  assert.equal(key, '123e4567e89b12d3a456426614174000');
  assert.equal(newClientKey().length, 32);
});

await test('create payload', () => {
  const p = createPayload({ title: ' Задача ', description: '', priority: '', owner: '', team: 't1', assignee: '', due_date: '' },
    { userId: 'u1' }, 'k');
  assert.deepEqual(p, { title: 'Задача', description: '', priority: 'normal', result_owner_user_id: 'u1',
    executor_team_id: 't1', client_key: 'k' });
  const q = createPayload({ title: 'a', description: 'd', priority: 'high', owner: 'u2', team: 't1', assignee: 'u3', due_date: '2026-12-31' },
    { userId: 'u1' }, 'k');
  assert.equal(q.assignee_user_id, 'u3');
  assert.equal(q.due_date, '2026-12-31');
});

await test('only changed fields are sent', () => {
  const original = { title: 'A', description: 'd', status: 'new', priority: 'normal', due_date: '2026-12-31' };
  assert.deepEqual(diffChanges(original, { ...original }), {});
  assert.deepEqual(diffChanges(original, { ...original, title: ' B ', status: 'done' }), { title: 'B', status: 'done' });
  assert.deepEqual(diffChanges(original, { ...original, due_date: '' }), { due_date: null });
  assert.deepEqual(diffChanges({ ...original, due_date: null }, { ...original, due_date: '' }), {});
});

await test('csrf only on mutations, kept in memory, same-origin credentials', async () => {
  const f = fakeFetch([{ status: 200, body: { csrf_token: 'c1' } }, { status: 200, body: { csrf_token: 'c2', password_change_required: false } },
    { status: 200, body: [] }, { status: 200, body: { id: 't' } }]);
  const api = new Api(f);
  await api.bootstrap();
  assert.equal(api.csrf, 'c1');
  const r = await api.login('user', 'secret');
  assert.equal(api.csrf, 'c2');
  assert.equal(r.password_change_required, false);
  await api.workspaces();
  await api.createTask('w1', { title: 'x' });
  const [pre, login, read, write] = f.calls;
  assert.equal(pre.init.headers['X-CSRF-Token'], undefined);
  assert.equal(login.init.headers['X-CSRF-Token'], 'c1');
  assert.equal(read.init.headers['X-CSRF-Token'], undefined);
  assert.equal(write.init.headers['X-CSRF-Token'], 'c2');
  for (const c of f.calls) { assert.equal(c.init.credentials, 'same-origin'); assert.equal(c.init.cache, 'no-store'); assert.equal(c.path.startsWith('/api/v1/'), true); }
  assert.deepEqual(JSON.parse(login.init.body), { login: 'user', password: 'secret' });
});

await test('401 signals lost session, other errors keep it, nothing from the body leaks', async () => {
  let lost = 0;
  const api = new Api(fakeFetch([{ status: 401, body: { detail: 'secret detail' } }, { status: 409, body: { detail: 'x' } }, { status: 500, body: {} }]), () => { lost += 1; });
  await assert.rejects(api.me(), (e) => e instanceof ApiError && e.status === 401 && !e.message.includes('secret'));
  assert.equal(lost, 1);
  await assert.rejects(api.updateTask('t', 3, { title: 'x' }), (e) => e.status === 409);
  await assert.rejects(api.workspaces(), (e) => e.status === 500);
  assert.equal(lost, 1);
});

await test('requests: pagination, filters, optimistic version', async () => {
  const f = fakeFetch([]);
  const api = new Api(f);
  await api.tasks('w1', 'done', 'last-id');
  await api.tasks('w1');
  await api.updateTask('t1', 7, { title: 'N' });
  assert.equal(f.calls[0].path, `/api/v1/workspaces/w1/tasks?limit=${PAGE}&status=done&after=last-id`);
  assert.equal(f.calls[1].path, `/api/v1/workspaces/w1/tasks?limit=${PAGE}`);
  assert.equal(f.calls[2].init.method, 'PATCH');
  assert.deepEqual(JSON.parse(f.calls[2].init.body), { expected_version: 7, changes: { title: 'N' } });
});

console.log(`${passed} passed`);
