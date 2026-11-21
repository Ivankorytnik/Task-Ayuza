// Node tests for web/logic.js (no browser, no network). Run: node web/test_client.js
import assert from 'node:assert/strict';
import { ganttRows, monthGrid, shiftMonth, dependencyPayload, checkPayload, riskPayload, severityLevel, Api, ApiError, PAGE, allowedTargets, blockerPayload, columns, transitionAllowed, unread, createPayload, dateError, diffChanges, label, messageFor, newClientKey, titleError,
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

await test('status transitions follow D04', () => {
  assert.equal(transitionAllowed('new', 'blocked'), true);
  assert.equal(transitionAllowed('in_progress', 'done'), true);
  assert.equal(transitionAllowed('done', 'cancelled'), false);
  assert.equal(transitionAllowed('cancelled', 'done'), false);
  assert.equal(transitionAllowed('done', 'in_progress'), true);
  assert.deepEqual(allowedTargets('done'), ['new', 'planned', 'in_progress']);
  assert.equal(allowedTargets('new').includes('new'), false);
  assert.equal(allowedTargets('new').length, 5);
});

await test('kanban columns keep order and unknown statuses are ignored', () => {
  const cols = columns([{ id: 1, status: 'done' }, { id: 2, status: 'new' }, { id: 3, status: 'new' }, { id: 4, status: 'weird' }]);
  assert.deepEqual(cols.map((c) => c.key), ['new', 'planned', 'in_progress', 'blocked', 'done', 'cancelled']);
  assert.deepEqual(cols[0].tasks.map((t) => t.id), [2, 3]);
  assert.equal(cols.reduce((n, c) => n + c.tasks.length, 0), 3);
});

await test('notifications and blockers helpers', async () => {
  assert.equal(unread([{ read_at: null }, { read_at: '2026-01-01' }, {}]), 2);
  assert.deepEqual(blockerPayload({ title: ' Ждём ', responsible: 'u1', due_date: '' }), { title: 'Ждём', responsible_user_id: 'u1' });
  assert.deepEqual(blockerPayload({ title: 'a', responsible: '', due_date: '2026-12-20' }), { title: 'a', expected_resolution_date: '2026-12-20' });
  const f = fakeFetch([]);
  const api = new Api(f);
  await api.notifications(true); await api.unreadCount(); await api.markRead('n1'); await api.blockers('t1');
  await api.createBlocker('t1', { title: 'x' }); await api.dependencies('t1');
  assert.deepEqual(f.calls.map((c) => c.init.method + ' ' + c.path), [
    'GET /api/v1/notifications?limit=100&unread_only=true', 'GET /api/v1/notifications/unread-count',
    'POST /api/v1/notifications/n1/read', 'GET /api/v1/tasks/t1/blockers', 'POST /api/v1/tasks/t1/blockers',
    'GET /api/v1/tasks/t1/dependencies']);
  assert.equal(f.calls[2].init.headers['X-CSRF-Token'], undefined);   // no token yet: the server would answer 403
});

await test('risk helpers: severity, payloads, green needs evidence', () => {
  assert.equal(severityLevel(2, 2), 'Низкая'); assert.equal(severityLevel(3, 3), 'Средняя');
  assert.equal(severityLevel(4, 4), 'Высокая'); assert.equal(severityLevel(5, 5), 'Критическая');
  assert.ok(riskPayload({ category: 'legal', description: ' ', probability: '3', impact: '3' }).error);
  assert.ok(riskPayload({ category: 'legal', description: 'x', probability: '6', impact: '3' }).error);
  assert.ok(riskPayload({ category: 'legal', description: 'x', probability: '2.5', impact: '3' }).error);
  assert.deepEqual(riskPayload({ category: 'backup', description: ' Нет копии ', probability: '4', impact: '5', measures: '', due_date: '' }).payload,
    { category: 'backup', description: 'Нет копии', probability: 4, impact: 5 });
  assert.ok(riskPayload({ category: 'backup', description: 'x', probability: '1', impact: '1', due_date: '31.12.2026' }).error);
  assert.ok(checkPayload({ result: 'pass', evidence: '', valid_until: '' }).error);
  assert.ok(checkPayload({ result: 'pass', evidence: 'отчёт', valid_until: '2026-13-40' }).error);
  assert.deepEqual(checkPayload({ result: 'fail', evidence: '', valid_until: '' }).payload, { result: 'fail' });
  assert.deepEqual(checkPayload({ result: 'pass', evidence: 'отчёт 12', valid_until: '2026-12-31' }).payload,
    { result: 'pass', evidence_reference: 'отчёт 12', valid_until: '2026-12-31T23:59:59+00:00' });
});

await test('export reads text and row count; errors keep status', async () => {
  const ok = { ok: true, status: 200, headers: { get: (k) => ({ 'X-Export-Row-Count': '3' })[k] || null }, text: async () => 'a,b\n' };
  const api = new Api(async () => ok);
  assert.deepEqual(await api.exportTasks('w1', 'csv', ''), { text: 'a,b\n', rows: 3, name: 'tasks.csv' });
  const denied = new Api(async () => ({ ok: false, status: 403 }));
  await assert.rejects(() => denied.exportTasks('w1', 'json', 'done'), (e) => e.status === 403);
});

await test('dependency payload direction and link requests', async () => {
  assert.ok(dependencyPayload('a', '', 'blocked_by', '').error);
  assert.ok(dependencyPayload('a', 'a', 'blocks', '').error);
  assert.ok(dependencyPayload('a', 'b', 'blocks', 'x'.repeat(501)).error);
  assert.deepEqual(dependencyPayload('a', 'b', 'blocked_by', ' нужен ').payload, { blocker_task_id: 'b', dependent_task_id: 'a', reason: 'нужен' });
  assert.deepEqual(dependencyPayload('a', 'b', 'blocks', '').payload, { blocker_task_id: 'a', dependent_task_id: 'b', reason: '' });
  const f = fakeFetch([]); const api = new Api(f);
  await api.resolveBlocker('b1', 3, true); await api.removeDependency('e1', 2, 'ошибка'); await api.riskLinks('r1'); await api.linkRiskTask('r1', 't1', false);
  assert.deepEqual(f.calls.map((c) => c.init.method + ' ' + c.path), ['POST /api/v1/blockers/b1/resolved', 'POST /api/v1/dependencies/e1/remove',
    'GET /api/v1/risks/r1/links', 'PUT /api/v1/risks/r1/tasks/t1']);
  assert.deepEqual(JSON.parse(f.calls[0].init.body), { expected_version: 3, resolved: true });
});

await test('gantt rows and undated tasks', () => {
  const g = ganttRows([{ id: 1, start_date: '2026-12-01', due_date: '2026-12-10' }, { id: 2, start_date: null, due_date: '2026-12-05' },
    { id: 3, start_date: null, due_date: null }, { id: 4, start_date: '2026-12-20', due_date: '2026-12-20' }]);
  assert.equal(g.span, 20); assert.equal(g.rows.length, 3); assert.deepEqual(g.undated.map((t) => t.id), [3]);
  assert.equal(g.rows[0].left, 0); assert.equal(g.rows[0].width, 50);
  assert.equal(g.rows[1].width, 5); assert.equal(g.rows[1].left, 20);
  assert.deepEqual(ganttRows([]), { rows: [], undated: [], span: 0, min: 0 });
});

await test('calendar month grid is Monday based and holds due tasks', () => {
  const cells = monthGrid(2026, 10, [{ id: 1, due_date: '2026-11-21' }, { id: 2, due_date: '2026-12-01' }]);
  assert.equal(cells.length % 7, 0);
  assert.equal(cells.filter((c) => c.day).length, 30);
  assert.equal(cells.findIndex((c) => c.day === 1), 6);               // 1 Nov 2026 is a Sunday
  assert.deepEqual(cells.find((c) => c.day === 21).tasks.map((t) => t.id), [1]);
  assert.equal(cells.reduce((n, c) => n + c.tasks.length, 0), 1);
  assert.deepEqual(shiftMonth(2026, 11, 1), { year: 2027, month: 0 });
  assert.deepEqual(shiftMonth(2026, 0, -1), { year: 2025, month: 11 });
});

console.log(`${passed} passed`);
