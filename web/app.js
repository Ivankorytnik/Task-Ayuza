// DOM layer. Dynamic strings are inserted only as text nodes; nothing is persisted in the browser; no external hosts.
import { Api, ApiError, EVENTS, PAGE, PRIORITIES, STATUSES, allowedTargets, blockerPayload, columns, createPayload,
  dateError, diffChanges, label, newClientKey, titleError, unread } from './logic.js';

const root = document.getElementById('app');
const state = { user: null, phase: 'login', login: '', workspaces: [], ws: null, dir: null, tasks: [], status: '',
  more: false, selected: null, comments: [], message: '', error: '', view: 'list', notes: [], unread: 0,
  blockers: [], deps: null };
const api = new Api((...args) => fetch(...args), () => { state.user = null; state.phase = 'login'; render(); });
let pendingKey = null;                                  // one client_key per creation attempt, kept until it succeeds

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (name === 'on') for (const [evt, fn] of Object.entries(value)) node.addEventListener(evt, fn);
    else if (value !== false && value != null) node.setAttribute(name, value === true ? '' : String(value));
  }
  for (const child of children.flat()) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}

function options(pairs, current, blank) {
  const list = pairs.map(([value, text]) => h('option', { value, selected: value === current }, text));
  return blank ? [h('option', { value: '' }, blank), ...list] : list;
}

function fail(error) { state.error = error instanceof ApiError ? error.message : 'Сервис временно недоступен.'; render(); }

// ---- screens

function loginView() {
  const form = h('form', { class: 'card login', on: { submit: async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    state.login = String(data.get('login')).trim();
    try {
      const result = await api.login(state.login, String(data.get('password')));
      state.error = '';
      if (result.password_change_required) { state.phase = 'password'; return render(); }
      await enter();
    } catch (error) { fail(error); }
  } } },
  h('h1', {}, 'Task-Ayuza'),
  h('label', { for: 'login' }, 'Логин'), h('input', { id: 'login', name: 'login', autocomplete: 'username', required: true, maxlength: 256 }),
  h('label', { for: 'password' }, 'Пароль'), h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'current-password', required: true, maxlength: 128 }),
  h('div', { class: 'error', role: 'alert' }, state.error),
  h('button', { class: 'primary', type: 'submit' }, 'Войти'));
  return form;
}

function passwordView() {
  const form = h('form', { class: 'card login', on: { submit: async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    const next = String(data.get('next'));
    if (next !== String(data.get('again'))) { state.error = 'Пароли не совпадают.'; return render(); }
    try {
      await api.changePassword(next);
      await api.bootstrap();
      await api.login(state.login, next);
      state.error = '';
      await enter();
    } catch (error) { fail(error); }
  } } },
  h('h1', {}, 'Новый пароль'),
  h('p', { class: 'muted' }, 'Временный пароль нужно заменить на постоянный.'),
  h('label', { for: 'next' }, 'Новый пароль'), h('input', { id: 'next', name: 'next', type: 'password', autocomplete: 'new-password', required: true, maxlength: 128 }),
  h('label', { for: 'again' }, 'Повторите пароль'), h('input', { id: 'again', name: 'again', type: 'password', autocomplete: 'new-password', required: true, maxlength: 128 }),
  h('div', { class: 'error', role: 'alert' }, state.error),
  h('button', { class: 'primary', type: 'submit' }, 'Сохранить и войти'));
  return form;
}

function taskRow(task) {
  return h('tr', { class: `row${state.selected && state.selected.id === task.id ? ' on' : ''}`, tabindex: 0,
    on: { click: () => openTask(task.id), keydown: (e) => { if (e.key === 'Enter') openTask(task.id); } } },
  h('td', {}, task.title),
  h('td', {}, h('span', { class: `badge ${task.status}` }, label(STATUSES, task.status))),
  h('td', {}, h('span', { class: `badge ${task.priority}` }, label(PRIORITIES, task.priority))),
  h('td', {}, task.due_date || ''));
}

function createView() {
  const form = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    const problem = titleError(data.title) || dateError(data.due_date);
    if (problem) { state.error = problem; return render(); }
    pendingKey = pendingKey || newClientKey();
    try {
      await api.createTask(state.ws, createPayload(data, { userId: state.user.id }, pendingKey));
      pendingKey = null; state.error = ''; state.message = 'Задача создана.';
      await loadTasks(true);
    } catch (error) { fail(error); }
  } } },
  h('h3', {}, 'Новая задача'),
  h('label', { for: 'ntitle' }, 'Название'), h('input', { id: 'ntitle', name: 'title', required: true, maxlength: 200 }),
  h('label', { for: 'ndesc' }, 'Описание'), h('textarea', { id: 'ndesc', name: 'description', maxlength: 10000 }),
  h('div', { class: 'bar' },
    h('div', {}, h('label', { for: 'nteam' }, 'Команда-исполнитель'),
      h('select', { id: 'nteam', name: 'team', required: true }, state.dir.teams.map((t) => h('option', { value: t.id, selected: state.dir.my_team_ids.includes(t.id) }, t.name)))),
    h('div', {}, h('label', { for: 'nowner' }, 'Владелец результата'),
      h('select', { id: 'nowner', name: 'owner' }, state.dir.members.map((m) => h('option', { value: m.user_id, selected: m.user_id === state.user.id }, m.display_name)))),
    h('div', {}, h('label', { for: 'nprio' }, 'Приоритет'), h('select', { id: 'nprio', name: 'priority' }, options(PRIORITIES, 'normal'))),
    h('div', {}, h('label', { for: 'ndue' }, 'Срок (ГГГГ-ММ-ДД)'), h('input', { id: 'ndue', name: 'due_date', placeholder: '2026-12-31', maxlength: 10 }))),
  h('button', { class: 'primary', type: 'submit' }, 'Создать'));
  return form;
}

function detailView() {
  const task = state.selected;
  const form = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    const problem = titleError(data.title) || dateError(data.due_date);
    if (problem) { state.error = problem; return render(); }
    const changes = diffChanges(task, data);
    if (!Object.keys(changes).length) { state.message = 'Изменений нет.'; return render(); }
    try {
      await api.updateTask(task.id, task.version, changes);
      state.error = ''; state.message = 'Сохранено.';
      await openTask(task.id); await loadTasks(true);
    } catch (error) { if (error.status === 409) await openTask(task.id); fail(error); }
  } } },
  h('h3', {}, 'Карточка задачи'),
  h('label', { for: 'dtitle' }, 'Название'), h('input', { id: 'dtitle', name: 'title', value: task.title, maxlength: 200, required: true }),
  h('label', { for: 'ddesc' }, 'Описание'), h('textarea', { id: 'ddesc', name: 'description', maxlength: 10000 }, task.description || ''),
  h('div', { class: 'bar' },
    h('div', {}, h('label', { for: 'dstatus' }, 'Статус'), h('select', { id: 'dstatus', name: 'status' }, options(STATUSES, task.status))),
    h('div', {}, h('label', { for: 'dprio' }, 'Приоритет'), h('select', { id: 'dprio', name: 'priority' }, options(PRIORITIES, task.priority))),
    h('div', {}, h('label', { for: 'ddue' }, 'Срок'), h('input', { id: 'ddue', name: 'due_date', value: task.due_date || '', placeholder: '2026-12-31', maxlength: 10 }))),
  h('div', { class: 'muted' }, `Версия ${task.version}`),
  h('button', { class: 'primary', type: 'submit' }, 'Сохранить'));
  const comment = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const body = new FormData(comment).get('body');
    if (!String(body).trim()) return;
    try { await api.addComment(task.id, String(body)); state.comments = await api.comments(task.id); state.error = ''; render(); }
    catch (error) { fail(error); }
  } } },
  h('h3', {}, 'Комментарии'),
  state.comments.map((c) => h('div', { class: 'comment' }, c.body, h('div', { class: 'muted' }, String(c.created_at || '')))),
  h('label', { for: 'cbody' }, 'Новый комментарий'), h('textarea', { id: 'cbody', name: 'body', maxlength: 10000 }),
  h('button', { type: 'submit' }, 'Добавить'));
  return [form, comment];
}

async function move(id, version, to) {
  try { await api.updateTask(id, version, { status: to }); state.error = ''; await loadTasks(true); if (state.selected && state.selected.id === id) await openTask(id); }
  catch (error) { if (error.status === 409) await loadTasks(true); fail(error); }
}

function boardView() {
  return h('div', { class: 'board' }, columns(state.tasks).map((col) => h('section', { class: 'col', 'data-status': col.key,
    on: { dragover: (e) => e.preventDefault(), drop: (e) => {
      e.preventDefault();
      const task = state.tasks.find((t) => t.id === e.dataTransfer.getData('text/plain'));
      if (task && task.status !== col.key) move(task.id, task.version, col.key);
    } } },
  h('h3', {}, `${col.text} (${col.tasks.length})`),
  col.tasks.map((task) => h('article', { class: 'tcard', draggable: true,
    on: { dragstart: (e) => e.dataTransfer.setData('text/plain', task.id) } },
  h('div', { class: 'ttitle', on: { click: () => openTask(task.id) } }, task.title),
  h('div', { class: 'muted' }, task.due_date || ''),
  h('select', { 'aria-label': 'Перенести в статус', on: { change: (e) => { if (e.target.value) move(task.id, task.version, e.target.value); } } },
    [h('option', { value: '' }, 'Перенести…'), ...allowedTargets(task.status).map((to) => h('option', { value: to }, label(STATUSES, to)))]))))));
}

function notesView() {
  return h('div', {}, h('div', { class: 'bar' }, h('button', { on: { click: loadNotes } }, 'Обновить')),
    state.notes.length ? '' : h('p', { class: 'muted' }, 'Уведомлений нет.'),
    state.notes.map((n) => h('div', { class: 'card note' },
      h('strong', {}, EVENTS[n.event_type] || 'Событие'), h('span', { class: 'muted' }, ` ${n.created_at || ''}`),
      h('div', { class: 'bar' },
        h('button', { on: { click: async () => { state.view = 'list'; await openTask(n.task_id); } } }, 'Открыть задачу'),
        n.read_at ? h('span', { class: 'muted' }, 'Прочитано')
          : h('button', { on: { click: async () => { try { await api.markRead(n.id); await loadNotes(); } catch (error) { fail(error); } } } }, 'Отметить прочитанным')))));
}

function blockersView() {
  const task = state.selected;
  const form = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    const problem = titleError(data.title) || dateError(data.due_date);
    if (problem) { state.error = problem; return render(); }
    try { await api.createBlocker(task.id, blockerPayload(data)); state.error = ''; await openTask(task.id); }
    catch (error) { fail(error); }
  } } },
  h('h3', {}, 'Блокеры и зависимости'),
  state.blockers.length ? '' : h('p', { class: 'muted' }, 'Блокеров нет.'),
  state.blockers.map((b) => h('div', { class: 'comment' }, h('strong', {}, b.title), ` · ${b.status === 'resolved' ? 'снят' : 'активен'}`,
    b.expected_resolution_date ? h('div', { class: 'muted' }, `Ожидаемый срок: ${b.expected_resolution_date}`) : '')),
  state.deps ? [state.deps.edges.map((e) => h('div', { class: 'comment' }, e.direction === 'blocked_by' ? 'Зависит от: ' : 'Блокирует: ', e.title, ` (${label(STATUSES, e.status)})`)),
    state.deps.hidden_external ? h('div', { class: 'muted' }, `Скрытых внешних зависимостей: ${state.deps.hidden_external}`) : ''] : '',
  h('label', { for: 'btitle' }, 'Новый блокер'), h('input', { id: 'btitle', name: 'title', maxlength: 200, required: true }),
  h('div', { class: 'bar' },
    h('div', {}, h('label', { for: 'bresp' }, 'Ответственный'),
      h('select', { id: 'bresp', name: 'responsible' }, (state.dir ? state.dir.members : []).map((m) => h('option', { value: m.user_id, selected: m.user_id === state.user.id }, m.display_name)))),
    h('div', {}, h('label', { for: 'bdue' }, 'Ожидаемый срок'), h('input', { id: 'bdue', name: 'due_date', placeholder: '2026-12-31', maxlength: 10 }))),
  h('button', { type: 'submit' }, 'Добавить блокер'));
  return form;
}

function mainView() {
  const bar = h('div', { class: 'bar' },
    h('label', { for: 'ws' }, 'Пространство'),
    h('select', { id: 'ws', on: { change: async (e) => { state.ws = e.target.value; await loadDirectory(); await loadTasks(true); } } },
      state.workspaces.map((w) => h('option', { value: w.id, selected: w.id === state.ws }, w.name))),
    h('label', { for: 'st' }, 'Статус'),
    h('select', { id: 'st', on: { change: async (e) => { state.status = e.target.value; await loadTasks(true); } } }, options(STATUSES, state.status, 'Все')));
  const tabs = h('div', { class: 'bar' }, [['list', 'Список'], ['board', 'Kanban'], ['notes', `Уведомления${state.unread ? ` (${state.unread})` : ''}`]]
    .map(([key, text]) => h('button', { class: state.view === key ? 'primary' : '', on: { click: async () => {
      state.view = key; state.error = ''; state.message = '';
      if (key === 'notes') await loadNotes(); else await loadTasks(true);
    } } }, text)));
  const table = h('table', {}, h('thead', {}, h('tr', {}, ['Название', 'Статус', 'Приоритет', 'Срок'].map((t) => h('th', {}, t)))),
    h('tbody', {}, state.tasks.map(taskRow)));
  const messages = [h('div', { class: 'error', role: 'alert' }, state.error), h('div', { class: 'ok' }, state.message)];
  if (state.view === 'notes') return [tabs, messages, notesView()];
  return [bar, tabs, messages, state.dir ? createView() : '', state.view === 'board' ? boardView() : table,
    state.more ? h('button', { on: { click: async () => { await loadTasks(false); } } }, 'Показать ещё') : '',
    state.selected ? [detailView(), blockersView()] : ''];
}

function render() {
  root.replaceChildren();
  if (!state.user) { root.append(state.phase === 'password' ? passwordView() : loginView()); return; }
  root.append(h('header', {}, h('div', { class: 'brand' }, 'Task-Ayuza'), h('span', {}, state.user.display_name),
    h('button', { on: { click: async () => { try { await api.logout(); } catch { /* the session may already be gone */ }
      state.user = null; state.phase = 'login'; state.tasks = []; state.selected = null; render(); } } }, 'Выйти')),
  h('main', {}, mainView()));
}

// ---- data

async function loadDirectory() { state.dir = state.ws ? await api.directory(state.ws) : null; }

async function loadTasks(reset) {
  try {
    const after = !reset && state.tasks.length ? state.tasks[state.tasks.length - 1].id : null;
    const page = await api.tasks(state.ws, state.view === 'list' ? state.status : '', after);
    state.tasks = reset ? page : state.tasks.concat(page);
    state.more = page.length === PAGE;
  } catch (error) { state.tasks = []; state.more = false; state.error = error.message; }
  render();
}

async function openTask(id) {
  try {
    state.selected = await api.task(id); state.comments = await api.comments(id);
    state.blockers = await api.blockers(id); state.deps = await api.dependencies(id);
  }
  catch (error) { state.selected = null; state.error = error.message; }
  render();
}

async function loadNotes() {
  try { state.notes = await api.notifications(false); state.unread = unread(state.notes); state.error = ''; }
  catch (error) { state.error = error.message; }
  render();
}

async function refreshUnread() {
  if (!state.user) return;
  try { const r = await api.unreadCount(); if (r.count !== state.unread) { state.unread = r.count; render(); } } catch { /* shown on the next action */ }
}

async function enter() {
  state.user = await api.me();
  state.workspaces = await api.workspaces();
  state.ws = state.workspaces.length ? state.workspaces[0].id : null;
  state.message = state.workspaces.length ? '' : 'У вас пока нет доступных пространств.';
  await loadDirectory();
  if (state.ws) await loadTasks(true); else render();
}

async function start() {
  try { await api.bootstrap(); await enter(); }            // an existing session cookie recovers a fresh CSRF token
  catch { state.user = null; state.phase = 'login'; render(); }
}

setInterval(refreshUnread, 60000);                      // polling instead of push; no storage involved
start();
