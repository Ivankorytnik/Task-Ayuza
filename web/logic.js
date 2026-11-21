// Pure client logic: no DOM, no storage, no external hosts. Tested with Node (web/test_client.js).
export const STATUSES = [['new', 'Новая'], ['planned', 'Запланирована'], ['in_progress', 'В работе'],
  ['blocked', 'Блокирована'], ['done', 'Выполнена'], ['cancelled', 'Отменена']];
export const PRIORITIES = [['low', 'Низкий'], ['normal', 'Обычный'], ['high', 'Высокий'], ['critical', 'Критический']];
export const PAGE = 50;

export const label = (pairs, key) => (pairs.find((p) => p[0] === key) || [key, key])[1];

export class ApiError extends Error {
  constructor(status) { super(messageFor(status)); this.status = status; }
}

export function messageFor(status) {
  return ({
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

export function dateError(value) {
  if (!value) return '';
  return /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value)) ? '' : 'Дата в формате ГГГГ-ММ-ДД.';
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
  for (const name of ['title', 'description', 'status', 'priority', 'due_date']) {
    const before = original[name] == null ? '' : String(original[name]);
    const after = edited[name] == null ? '' : String(edited[name]).trim();
    if (before !== after) out[name] = after === '' && name === 'due_date' ? null : after;
  }
  return out;
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
    const res = await this.fetch(path, {
      method, headers, credentials: 'same-origin', cache: 'no-store',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
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
  directory(ws) { return this.request('GET', `/api/v1/workspaces/${ws}/directory`); }
  tasks(ws, status, after) {
    const q = new URLSearchParams({ limit: String(PAGE) });
    if (status) q.set('status', status);
    if (after) q.set('after', after);
    return this.request('GET', `/api/v1/workspaces/${ws}/tasks?${q}`);
  }
  createTask(ws, payload) { return this.request('POST', `/api/v1/workspaces/${ws}/tasks`, payload, true); }
  task(id) { return this.request('GET', `/api/v1/tasks/${id}`); }
  updateTask(id, version, changes) {
    return this.request('PATCH', `/api/v1/tasks/${id}`, { expected_version: version, changes }, true);
  }
  comments(id) { return this.request('GET', `/api/v1/tasks/${id}/comments`); }
  addComment(id, body) { return this.request('POST', `/api/v1/tasks/${id}/comments`, { body }, true); }
}
