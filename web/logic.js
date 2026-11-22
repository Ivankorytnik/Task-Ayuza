// Pure client logic: no DOM, no storage, no external hosts. Tested with Node (web/test_client.js).
export const STATUSES = [['new', 'Новая'], ['planned', 'Запланирована'], ['in_progress', 'В работе'],
  ['blocked', 'Блокирована'], ['done', 'Выполнена'], ['cancelled', 'Отменена']];
export const PRIORITIES = [['low', 'Низкий'], ['normal', 'Обычный'], ['high', 'Высокий'], ['critical', 'Критический']];
export const PAGE = 50;
export const TERMINAL = ['done', 'cancelled'];
export const REOPEN = ['new', 'planned', 'in_progress'];
export const EVENTS = { task_assigned: 'Вам назначена задача', comment_added: 'Новый комментарий',
  blocker_resolved: 'Блокер снят', dependency_changed: 'Изменены зависимости',
  task_due_soon: 'Срок задачи близко', task_overdue: 'Задача просрочена' };

export const label = (pairs, key) => (pairs.find((p) => p[0] === key) || [key, key])[1];

export class ApiError extends Error {
  constructor(status) { super(messageFor(status)); this.status = status; }
}

export function messageFor(status) {
  return ({
    0: 'Нет связи. Данные на устройстве не сохраняются, повторите позже.',
    401: 'Войдите заново.',
    403: 'Недостаточно прав или запрос отклонён.',
    404: 'Не найдено или нет доступа.',
    409: 'Данные изменились. Обновите карточку и повторите.',
    422: 'Проверьте введённые данные.',
    429: 'Слишком много попыток. Подождите и повторите.',
  })[status] || 'Сервис временно недоступен.';
}

export function newClientKey(random = () => globalThis.crypto.randomUUID()) {
  return String(random()).replace(/-/g, '').slice(0, 32);
}

export function titleError(title) {
  const t = String(title || '').trim();
  if (!t) return 'Введите название.';
  if (t.length > 200) return 'Название длиннее 200 символов.';
  return '';
}

// A real calendar date: Date.parse accepts 2026-02-30, so the parts are compared after a round trip.
function realDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(Date.UTC(+value.slice(0, 4), +value.slice(5, 7) - 1, +value.slice(8, 10)));
  return d.toISOString().slice(0, 10) === value;
}

export function dateError(value) {
  if (!value) return '';
  return realDate(value) ? '' : 'Дата в формате ГГГГ-ММ-ДД.';
}

export function createPayload(form, ctx, clientKey) {
  const payload = {
    title: form.title.trim(), description: form.description || '', priority: form.priority || 'normal',
    result_owner_user_id: form.owner || ctx.userId, executor_team_id: form.team, client_key: clientKey,
  };
  if (form.assignee) payload.assignee_user_id = form.assignee;
  if (form.due_date) payload.due_date = form.due_date;
  return payload;
}

// Only fields that really changed; an emptied date becomes null. The caller sends expected_version.
export function diffChanges(original, edited) {
  const out = {};
  for (const name of ['title', 'description', 'status', 'priority', 'start_date', 'due_date']) {
    const before = original[name] == null ? '' : String(original[name]);
    const after = edited[name] == null ? '' : String(edited[name]).trim();
    if (before !== after) out[name] = after === '' && (name === 'due_date' || name === 'start_date') ? null : after;
  }
  return out;
}

// Mirrors D04 for the UI only; the server stays the authority. Terminal statuses can only be reopened.
export function transitionAllowed(from, to) {
  if (from === to) return true;
  return TERMINAL.includes(from) ? REOPEN.includes(to) : true;
}

export function allowedTargets(from) { return STATUSES.map((s) => s[0]).filter((to) => to !== from && transitionAllowed(from, to)); }

export function columns(tasks) {
  const out = STATUSES.map(([key, text]) => ({ key, text, tasks: [] }));
  for (const task of tasks) { const col = out.find((c) => c.key === task.status); if (col) col.tasks.push(task); }
  return out;
}

export function unread(list) { return list.filter((n) => !n.read_at).length; }

export function blockerPayload(form) {
  const payload = { title: form.title.trim() };
  if (form.responsible) payload.responsible_user_id = form.responsible;
  if (form.due_date) payload.expected_resolution_date = form.due_date;
  return payload;
}

export const RISK_CATEGORIES = [['legal', 'Юридический'], ['personal_data', 'Персональные данные'], ['cybersecurity', 'Кибербезопасность'],
  ['access', 'Доступы'], ['availability', 'Доступность'], ['database', 'База данных'], ['backup', 'Резервные копии'],
  ['quality', 'Качество'], ['release', 'Релиз'], ['organizational', 'Организационный'], ['other', 'Другое']];
export const TRAFFIC = [['gray', 'Серый: не проверено'], ['green', 'Зелёный: проверено'], ['yellow', 'Жёлтый: требует внимания'], ['red', 'Красный: критично']];
export const CHECK_RESULTS = [['pass', 'Пройдена'], ['fail', 'Не пройдена'], ['critical', 'Критично']];

export function severityLevel(probability, impact) {
  const v = probability * impact;
  return v <= 4 ? 'Низкая' : v <= 9 ? 'Средняя' : v <= 16 ? 'Высокая' : 'Критическая';
}

const scaleOk = (v) => Number.isInteger(v) && v >= 1 && v <= 5;

export function riskPayload(form) {
  const p = Number(form.probability); const i = Number(form.impact);
  if (!scaleOk(p) || !scaleOk(i)) return { error: 'Вероятность и влияние: целые числа от 1 до 5.' };
  const description = (form.description || '').trim();
  if (!description || description.length > 2000) return { error: 'Описание: от 1 до 2000 символов.' };
  const payload = { category: form.category, description, probability: p, impact: i };
  if (form.measures && form.measures.trim()) payload.measures = form.measures.trim();
  if (form.due_date) { const e = dateError(form.due_date); if (e) return { error: e }; payload.due_date = form.due_date; }
  return { payload };
}

export function checkPayload(form) {
  const payload = { result: form.result };
  if (form.evidence && form.evidence.trim()) payload.evidence_reference = form.evidence.trim();
  if (form.valid_until) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(form.valid_until) || dateError(form.valid_until)) return { error: 'Срок действия: дата ГГГГ-ММ-ДД.' };
    payload.valid_until = `${form.valid_until}T23:59:59+00:00`;
  }
  if (payload.result === 'pass' && !(payload.evidence_reference && payload.valid_until)) {
    return { error: 'Для зелёного статуса нужны подтверждение и срок действия.' };
  }
  return { payload };
}

export function dependencyPayload(taskId, otherId, direction, reason) {
  if (!otherId || otherId === taskId) return { error: 'Выберите другую задачу.' };
  const text = (reason || '').trim();
  if (text.length > 500) return { error: 'Причина: не более 500 символов.' };
  const blocked = direction === 'blocked_by';
  return { payload: { blocker_task_id: blocked ? otherId : taskId, dependent_task_id: blocked ? taskId : otherId, reason: text } };
}

const DAY = 86400000;
const dayNumber = (iso) => Date.UTC(+iso.slice(0, 4), +iso.slice(5, 7) - 1, +iso.slice(8, 10)) / DAY;
const hasDate = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);

// Gantt rows: a bar from start to due; one date alone gives a one-day bar; tasks without dates go to `undated`.
export function ganttRows(tasks) {
  const rows = []; const undated = [];
  for (const t of tasks) {
    const start = hasDate(t.start_date) ? t.start_date : t.due_date; const end = hasDate(t.due_date) ? t.due_date : t.start_date;
    if (!hasDate(start) || !hasDate(end)) { undated.push(t); continue; }
    rows.push({ task: t, from: dayNumber(start), to: Math.max(dayNumber(end), dayNumber(start)) });
  }
  if (!rows.length) return { rows: [], undated, span: 0, min: 0 };
  const min = Math.min(...rows.map((r) => r.from)); const max = Math.max(...rows.map((r) => r.to));
  const span = max - min + 1;
  return { rows: rows.map((r) => ({ task: r.task, left: ((r.from - min) / span) * 100, width: ((r.to - r.from + 1) / span) * 100 })), undated, span, min };
}

// Dependency connectors for the Gantt: all rows share one scale, so a blocker's end and a dependent's start are comparable
export const MAX_DEP_TASKS = 60;
export function dependencyLinks(rows, edgesByTask) {
  const byId = new Map(rows.map((r) => [r.task.id, r]));
  const out = {};
  for (const r of rows) {
    const links = [];
    for (const e of edgesByTask[r.task.id] || []) {
      const blocker = e.direction === 'blocked_by' ? byId.get(e.task_id) : null;
      if (!blocker) continue;
      const from = blocker.left + blocker.width; const to = r.left;
      links.push({ from, to, left: Math.min(from, to), width: Math.max(Math.abs(to - from), 0.5), conflict: from > to, title: e.title });
    }
    if (links.length) out[r.task.id] = links;
  }
  return out;
}

export const OPEN = (task) => task.status !== 'done' && task.status !== 'cancelled';
export const isOverdue = (task, today) => Boolean(today) && OPEN(task) && hasDate(task.due_date) && task.due_date < today;

export function rangeError(start, due) {
  return hasDate(start) && hasDate(due) && start > due ? 'Начало не может быть позже срока.' : '';
}

export const SCALES = [['day', 'День'], ['week', 'Неделя'], ['month', 'Месяц']];
const PX_PER_DAY = { day: 28, week: 9, month: 3 };
export const trackWidth = (span, scale) => Math.max(span * (PX_PER_DAY[scale] || 9), 320);

// Axis ticks for the chosen scale: every day, every Monday, or every first of a month.
export function scaleTicks(min, span, scale) {
  const ticks = [];
  for (let i = 0; i < span; i += 1) {
    const d = new Date((min + i) * DAY);
    const dom = d.getUTCDate(); const monday = d.getUTCDay() === 1;
    const text = scale === 'day' ? String(dom)
      : scale === 'week' ? (monday ? `${String(dom).padStart(2, '0')}.${String(d.getUTCMonth() + 1).padStart(2, '0')}` : null)
        : (dom === 1 ? `${MONTHS[d.getUTCMonth()].slice(0, 3)} ${d.getUTCFullYear()}` : null);
    if (text !== null) ticks.push({ left: (i / span) * 100, text });
  }
  return ticks;
}

export const todayLeft = (today, min, span) => (hasDate(today) && span ? ((dayNumber(today) - min) / span) * 100 : null);

// Groups by project; independent tasks are shown separately as "Без проекта". Names come from the project list.
export function groupRows(rows, names) {
  const groups = new Map();
  for (const row of rows) {
    const key = row.task.project_id || '';
    if (!groups.has(key)) groups.set(key, { key, title: key ? (names[key] || 'Проект') : 'Без проекта', rows: [] });
    groups.get(key).rows.push(row);
  }
  return [...groups.values()].sort((a, b) => (a.key === '') - (b.key === '') || a.title.localeCompare(b.title, 'ru'));
}

// Project bar on the shared Gantt scale: from the project's own dates, clipped to the visible range; null without dates
export function projectBar(project, min, span) {
  if (!project || !hasDate(project.start_date) || !hasDate(project.due_date) || !span) return null;
  const from = dayNumber(project.start_date) - min; const to = dayNumber(project.due_date) - min + 1;
  if (to <= 0 || from >= span || to <= from) return null;
  const left = Math.max(from, 0) / span * 100; const right = Math.min(to, span) / span * 100;
  return { left, width: Math.max(right - left, 0.5) };
}

// Month grid starting on Monday; each cell holds the tasks due that day.
export function monthGrid(year, month, tasks) {
  const first = Date.UTC(year, month, 1) / DAY;
  const lead = (new Date(Date.UTC(year, month, 1)).getUTCDay() + 6) % 7;
  const days = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const cells = [];
  for (let i = 0; i < Math.ceil((lead + days) / 7) * 7; i += 1) {
    const day = i - lead + 1;
    if (day < 1 || day > days) { cells.push({ day: null, tasks: [] }); continue; }
    const iso = new Date((first + day - 1) * DAY).toISOString().slice(0, 10);
    cells.push({ day, iso, tasks: tasks.filter((t) => t.due_date === iso) });
  }
  return cells;
}

export function shiftMonth(year, month, delta) {
  const d = new Date(Date.UTC(year, month + delta, 1));
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() };
}

export const MONTHS = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];

export const SNAPSHOT_LABELS = [['total', 'Всего'], ['active', 'Активные'], ['in_progress', 'В работе'], ['done', 'Выполнены'],
  ['blocked', 'Заблокированы'], ['overdue', 'Просрочены'], ['upcoming', 'Ближайшие сроки'], ['no_due_date', 'Без срока'], ['no_project', 'Без проекта']];

export function snapshotItems(snapshot) {
  return SNAPSHOT_LABELS.filter(([key]) => Number.isInteger(snapshot[key])).map(([key, text]) => ({ key, text, value: snapshot[key] }));
}

// Only the filters that are set go into the query; an empty filter is not sent at all.
export function taskQuery(limit, filters, after) {
  const q = new URLSearchParams({ limit: String(limit) });
  const f = filters || {};
  if (f.status) q.set('status', f.status);
  if (f.mine) q.set('mine', 'true');
  if (f.overdue) q.set('overdue', 'true');
  if (f.blocked) q.set('blocked', 'true');
  if (f.team) q.set('team_id', f.team);
  if (f.project) q.set('project_id', f.project);
  if (after) q.set('after', after);
  return q.toString();
}

export const filtersActive = (f) => Boolean(f && (f.mine || f.overdue || f.blocked || f.team || f.project));

export const METRIC_LABELS = [['created', 'Создано'], ['completed', 'Завершено'], ['cancelled', 'Отменено'], ['reopened', 'Открыто повторно']];
export const MAX_PERIOD_DAYS = 366;

// The default period ends on the workspace-local "today" (from the directory) and covers the last `days` days.
export function defaultPeriod(today, days) {
  if (!hasDate(today)) return { from: '', to: '' };
  return { from: new Date((dayNumber(today) - (days - 1)) * DAY).toISOString().slice(0, 10), to: today };
}

export function periodError(from, to) {
  if (!hasDate(from) || !hasDate(to)) return 'Период: даты в формате ГГГГ-ММ-ДД.';
  if (dateError(from) || dateError(to)) return 'Период: такой даты нет.';
  if (from > to) return 'Начало периода позже конца.';
  if (dayNumber(to) - dayNumber(from) >= MAX_PERIOD_DAYS) return `Период не длиннее ${MAX_PERIOD_DAYS} дней.`;
  return '';
}

export class Api {
  constructor(fetchImpl, onAuthLost = () => {}) {
    this.fetch = fetchImpl;
    this.onAuthLost = onAuthLost;
    this.csrf = null;                                   // kept in memory only, never persisted
  }

  async request(method, path, body, mutate = false) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (mutate && this.csrf) headers['X-CSRF-Token'] = this.csrf;
    let res;
    try {
      res = await this.fetch(path, {
        method, headers, credentials: 'same-origin', cache: 'no-store',
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch { throw new ApiError(0); }            // offline or unreachable
    if (!res.ok) {
      if (res.status === 401) this.onAuthLost();
      throw new ApiError(res.status);
    }
    return res.status === 204 ? null : res.json();
  }

  async bootstrap() { const r = await this.request('GET', '/api/v1/auth/prelogin'); this.csrf = r.csrf_token; return r; }
  async login(login, password) {
    const r = await this.request('POST', '/api/v1/auth/login', { login, password }, true);
    this.csrf = r.csrf_token;
    return r;
  }
  changePassword(newPassword, current) {
    const body = { new_password: newPassword };
    if (current) body.current_password = current;
    return this.request('POST', '/api/v1/auth/password', body, true);
  }
  me() { return this.request('GET', '/api/v1/auth/me'); }
  logout() { return this.request('POST', '/api/v1/auth/logout', undefined, true); }
  workspaces() { return this.request('GET', '/api/v1/workspaces'); }
  projects(ws) { return this.request('GET', `/api/v1/workspaces/${ws}/projects?limit=200`); }
  directory(ws) { return this.request('GET', `/api/v1/workspaces/${ws}/directory`); }
  tasks(ws, filters, after) { return this.request('GET', `/api/v1/workspaces/${ws}/tasks?${taskQuery(PAGE, filters, after)}`); }
  createTask(ws, payload) { return this.request('POST', `/api/v1/workspaces/${ws}/tasks`, payload, true); }
  task(id) { return this.request('GET', `/api/v1/tasks/${id}`); }
  updateTask(id, version, changes) {
    return this.request('PATCH', `/api/v1/tasks/${id}`, { expected_version: version, changes }, true);
  }
  comments(id) { return this.request('GET', `/api/v1/tasks/${id}/comments`); }
  notifications(unreadOnly) { return this.request('GET', `/api/v1/notifications?limit=100${unreadOnly ? '&unread_only=true' : ''}`); }
  unreadCount() { return this.request('GET', '/api/v1/notifications/unread-count'); }
  markRead(id) { return this.request('POST', `/api/v1/notifications/${id}/read`, undefined, true); }
  blockers(id) { return this.request('GET', `/api/v1/tasks/${id}/blockers`); }
  createBlocker(id, payload) { return this.request('POST', `/api/v1/tasks/${id}/blockers`, payload, true); }
  dependencies(id) { return this.request('GET', `/api/v1/tasks/${id}/dependencies`); }
  release() { return this.request('GET', '/api/v1/release'); }
  risks() { return this.request('GET', '/api/v1/risks?limit=200'); }
  createRisk(payload) { return this.request('POST', '/api/v1/risks', payload, true); }
  recordCheck(id, payload) { return this.request('POST', `/api/v1/risks/${id}/checks`, payload, true); }
  async exportTasks(ws, format, status) {
    const body = { format }; if (status) body.status = status;
    const headers = { Accept: '*/*', 'Content-Type': 'application/json' };
    if (this.csrf) headers['X-CSRF-Token'] = this.csrf;
    let res;
    try {
      res = await this.fetch(`/api/v1/workspaces/${ws}/exports`, { method: 'POST', headers, credentials: 'same-origin',
        cache: 'no-store', body: JSON.stringify(body) });
    } catch { throw new ApiError(0); }            // offline or unreachable
    if (!res.ok) { if (res.status === 401) this.onAuthLost(); throw new ApiError(res.status); }
    return { text: await res.text(), rows: Number(res.headers.get('X-Export-Row-Count') || 0), name: `tasks.${format}` };
  }
  resolveBlocker(id, version, resolved) { return this.request('POST', `/api/v1/blockers/${id}/resolved`, { expected_version: version, resolved }, true); }
  addDependency(payload) { return this.request('POST', '/api/v1/dependencies', payload, true); }
  removeDependency(id, version, reason) { return this.request('POST', `/api/v1/dependencies/${id}/remove`, { expected_version: version, reason }, true); }
  riskLinks(id) { return this.request('GET', `/api/v1/risks/${id}/links`); }
  linkRiskBlocker(riskId, blockerId, linked) { return this.request('PUT', `/api/v1/risks/${riskId}/blockers/${blockerId}`, { linked }, true); }
  linkRiskTask(riskId, taskId, linked) { return this.request('PUT', `/api/v1/risks/${riskId}/tasks/${taskId}`, { linked }, true); }
  metrics(ws, from, to) { return this.request('GET', `/api/v1/workspaces/${ws}/metrics?${new URLSearchParams({ from, to })}`); }
  snapshot(ws, includeSubtasks) { return this.request('GET', `/api/v1/workspaces/${ws}/snapshot?include_subtasks=${includeSubtasks ? 'true' : 'false'}`); }
  addComment(id, body) { return this.request('POST', `/api/v1/tasks/${id}/comments`, { body }, true); }
}
