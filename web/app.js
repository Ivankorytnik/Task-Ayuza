// DOM layer. Dynamic strings are inserted only as text nodes; nothing is persisted in the browser; no external hosts.
import { METRIC_LABELS, defaultPeriod, periodError, filtersActive, SCALES, groupRows, isOverdue, rangeError, scaleTicks, todayLeft, trackWidth, snapshotItems, MONTHS, ganttRows, metricsCsv, projectBar, stageBars, MAX_STAGE_PROJECTS, dependencyLinks, MAX_DEP_TASKS, monthGrid, shiftMonth, dependencyPayload, CHECK_RESULTS, RISK_CATEGORIES, TRAFFIC, checkPayload, riskPayload, severityLevel, Api, ApiError, EVENTS, PAGE, PRIORITIES, STATUSES, allowedTargets, blockerPayload, columns, createPayload,
  dateError, diffChanges, label, newClientKey, titleError, unread } from './logic.js';

const root = document.getElementById('app');
const fresh = () => ({ user: null, phase: 'login', login: '', workspaces: [], ws: null, dir: null, tasks: [], status: '',
  more: false, selected: null, comments: [], message: '', error: '', view: 'list', notes: [], unread: 0,
  blockers: [], deps: null, ganttDeps: {}, ganttStages: {}, projDates: {}, risks: [], snap: null, period: { from: '', to: '' }, metrics: null, subs: false, release: '', riskLinks: {}, filters: { mine: false, overdue: false, blocked: false, team: '', project: '' }, scale: 'week', projNames: {}, cal: (() => { const n = new Date(); return { year: n.getFullYear(), month: n.getMonth() }; })() });
const state = fresh();
function clearSession() { Object.assign(state, fresh()); }       // nothing of the previous user may stay in memory
const api = new Api((...args) => fetch(...args), () => { clearSession(); render(); });
let pendingKey = null;                                  // one client_key per creation attempt, kept until it succeeds

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (name === 'css') for (const [prop, v] of Object.entries(value)) node.style.setProperty(prop, v);   // CSSOM is allowed by CSP, a style attribute is not
    else if (name === 'on') for (const [evt, fn] of Object.entries(value)) node.addEventListener(evt, fn);
    else if (value !== false && value != null) node.setAttribute(name, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
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
    const problem = titleError(data.title) || dateError(data.start_date) || dateError(data.due_date) || rangeError(data.start_date, data.due_date);
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
    h('div', {}, h('label', { for: 'dstart' }, 'Начало'), h('input', { id: 'dstart', name: 'start_date', value: task.start_date || '', placeholder: '2026-12-01', maxlength: 10 })),
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

function download(result) {
  const url = URL.createObjectURL(new Blob([result.text], { type: 'text/plain;charset=utf-8' }));
  const link = h('a', { href: url, download: result.name });
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}

async function exportTasks(format) {
  try {
    const result = await api.exportTasks(state.ws, format, state.status);
    download(result); state.error = ''; state.message = `Выгружено строк: ${result.rows}.`;
  } catch (error) { state.message = ''; state.error = error.status === 403 ? 'Выгрузка требует права и свежего подтверждения MFA.' : error.message; }
  render();
}

async function loadRisks() {
  try { state.risks = await api.risks(); state.error = ''; }
  catch (error) { state.risks = []; state.error = error.status === 404 ? 'Центр рисков доступен только контролёру рисков.' : error.message; }
  render();
}

function riskCard(risk) {
  const form = h('form', { class: 'bar', on: { submit: async (e) => {
    e.preventDefault();
    const out = checkPayload(Object.fromEntries(new FormData(form).entries()));
    if (out.error) { state.error = out.error; return render(); }
    try { await api.recordCheck(risk.id, out.payload); state.error = ''; await loadRisks(); } catch (error) { fail(error); }
  } } },
  h('select', { name: 'result', 'aria-label': 'Результат проверки' }, CHECK_RESULTS.map(([k, t]) => h('option', { value: k }, t))),
  h('input', { name: 'evidence', placeholder: 'Подтверждение', maxlength: 500, 'aria-label': 'Подтверждение' }),
  h('input', { name: 'valid_until', placeholder: 'Действует до 2026-12-31', maxlength: 10, 'aria-label': 'Действует до' }),
  h('button', { type: 'submit' }, 'Записать проверку'));
  return h('div', { class: 'card' },
    h('span', { class: `light ${risk.control_status}`, role: 'img', 'aria-label': label(TRAFFIC, risk.control_status) }, label(TRAFFIC, risk.control_status)),
    h('div', {}, h('strong', {}, risk.description)),
    h('div', { class: 'muted' }, `${label(RISK_CATEGORIES, risk.category)} · вероятность ${risk.probability}, влияние ${risk.impact} · ${severityLevel(risk.probability, risk.impact)}`),
    form, linksBlock(risk));
}

function linksBlock(risk) {
  const links = state.riskLinks[risk.id];
  const pick = h('select', { 'aria-label': 'Привязать к задаче', on: { change: async (e) => {
    if (!e.target.value) return;
    try { await api.linkRiskTask(risk.id, e.target.value, true); state.error = ''; await showRiskLinks(risk.id); } catch (error) { fail(error); }
  } } }, [h('option', { value: '' }, 'Привязать к задаче…'), ...state.tasks.map((t) => h('option', { value: t.id }, t.title))]);
  return h('div', {},
    h('button', { type: 'button', on: { click: () => showRiskLinks(risk.id) } }, 'Связанные задачи'),
    links ? [links.tasks.map((t) => h('div', { class: 'comment' }, `${t.title} (${label(STATUSES, t.status)}) `,
      h('button', { type: 'button', on: { click: async () => { try { await api.linkRiskTask(risk.id, t.task_id, false); await showRiskLinks(risk.id); } catch (error) { fail(error); } } } }, 'Отвязать'))),
    links.hidden_tasks ? h('div', { class: 'muted' }, `Скрытых связей: ${links.hidden_tasks}`) : '',
    (links.blockers || []).map((b) => h('div', { class: 'comment' }, `Блокер: ${b.title || b.blocker_id} · ${b.status === 'resolved' ? 'снят' : 'активен'} `,
      h('button', { type: 'button', on: { click: async () => { try { await api.linkRiskBlocker(risk.id, b.blocker_id, false); await showRiskLinks(risk.id); } catch (error) { fail(error); } } } }, 'Отвязать блокер'))),
    links.hidden_blockers ? h('div', { class: 'muted' }, `Скрытых блокеров: ${links.hidden_blockers}`) : '', pick] : '');
}

async function showRiskLinks(id) {
  try { state.riskLinks[id] = await api.riskLinks(id); state.error = ''; } catch (error) { state.error = error.message; }
  render();
}

function risksView() {
  const form = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const out = riskPayload(Object.fromEntries(new FormData(form).entries()));
    if (out.error) { state.error = out.error; return render(); }
    try { await api.createRisk({ ...out.payload, owner_user_id: state.user.id }); state.error = ''; await loadRisks(); } catch (error) { fail(error); }
  } } },
  h('h3', {}, 'Новый риск'),
  h('label', { for: 'rcat' }, 'Категория'), h('select', { id: 'rcat', name: 'category' }, RISK_CATEGORIES.map(([k, t]) => h('option', { value: k }, t))),
  h('label', { for: 'rdesc' }, 'Описание'), h('textarea', { id: 'rdesc', name: 'description', maxlength: 2000, required: true }),
  h('div', { class: 'bar' },
    h('div', {}, h('label', { for: 'rp' }, 'Вероятность 1-5'), h('input', { id: 'rp', name: 'probability', value: '3', maxlength: 1 })),
    h('div', {}, h('label', { for: 'ri' }, 'Влияние 1-5'), h('input', { id: 'ri', name: 'impact', value: '3', maxlength: 1 })),
    h('div', {}, h('label', { for: 'rdue' }, 'Срок мер'), h('input', { id: 'rdue', name: 'due_date', placeholder: '2026-12-31', maxlength: 10 }))),
  h('label', { for: 'rmeas' }, 'Меры'), h('textarea', { id: 'rmeas', name: 'measures', maxlength: 5000 }),
  h('button', { type: 'submit' }, 'Добавить риск'));
  return h('div', {}, h('div', { class: 'bar' }, h('button', { on: { click: loadRisks } }, 'Обновить')),
    state.risks.length ? '' : h('p', { class: 'muted' }, 'Рисков нет.'), state.risks.map(riskCard), form);
}

async function loadSnapshot() {
  if (!state.ws) return;
  try { state.snap = await api.snapshot(state.ws, state.subs); } catch { state.snap = null; }
}

function snapshotView() {
  if (!state.snap) return '';
  return h('div', { class: 'card snap' },
    snapshotItems(state.snap).map((i) => h('span', { class: `snapitem ${i.key}` }, `${i.text}: `, h('strong', {}, String(i.value)))),
    h('label', { class: 'muted' }, h('input', { type: 'checkbox', checked: state.subs, on: { change: async (e) => { state.subs = e.target.checked; await loadSnapshot(); render(); } } }), ' включать подзадачи'));
}

async function loadMetrics() {
  if (!state.ws) return;
  const bad = periodError(state.period.from, state.period.to);
  if (bad) { state.metrics = null; state.error = bad; return; }
  try { state.metrics = await api.metrics(state.ws, state.period.from, state.period.to); state.error = ''; } catch (error) { state.metrics = null; state.error = error.message; }
}

function metricsView() {
  if (!state.dir) return '';
  if (!state.period.from) state.period = defaultPeriod(state.dir.today, 30);
  const form = h('form', { class: 'card snap', on: { submit: async (e) => {
    e.preventDefault();
    const data = new FormData(form); state.period = { from: String(data.get('from')).trim(), to: String(data.get('to')).trim() };
    await loadMetrics(); render();
  } } },
  h('strong', {}, 'За период'),
  h('input', { name: 'from', value: state.period.from, maxlength: 10, 'aria-label': 'С' }), h('input', { name: 'to', value: state.period.to, maxlength: 10, 'aria-label': 'По' }),
  h('button', { type: 'submit' }, 'Показать'),
  state.metrics ? METRIC_LABELS.map(([key, text]) => h('span', { class: 'snapitem' }, `${text}: `, h('strong', {}, String(state.metrics[key])))) : '',
  state.metrics ? h('button', { type: 'button', on: { click: () => download({ text: metricsCsv(state.metrics, state.period), name: `metrics_${state.period.from}_${state.period.to}.csv` }) } }, 'Выгрузить метрики CSV') : '');
  return form;
}

function ganttView() {
  const g = ganttRows(state.tasks);
  const today = state.dir ? state.dir.today : '';
  const width = `${trackWidth(g.span, state.scale)}px`;
  const marker = todayLeft(today, g.min, g.span);
  const links = dependencyLinks(g.rows, state.ganttDeps);
  const track = (r) => h('div', { class: 'gtrack', css: { width } },
    (links[r.task.id] || []).map((l) => [
      h('div', { class: `gdep${l.conflict ? ' conflict' : ''}`, css: { left: `${l.left}%`, width: `${l.width}%` }, title: `${l.conflict ? 'Конфликт сроков: ' : 'После: '}${l.title}` }),
      h('div', { class: `garrow${l.conflict ? ' conflict' : ''}`, css: { left: `${l.to}%` } })]),
    marker !== null && marker >= 0 && marker <= 100 ? h('div', { class: 'gtoday', css: { left: `${marker}%` } }) : '',
    h('div', { class: `gbar ${r.task.status}${isOverdue(r.task, today) ? ' late' : ''}`, css: { left: `${r.left}%`, width: `${Math.max(r.width, 1)}%` },
      title: `${r.task.start_date || ''} ${r.task.due_date || ''}${isOverdue(r.task, today) ? ' просрочена' : ''}` }));
  return h('div', { class: 'gantt' },
    h('div', { class: 'bar' }, SCALES.map(([key, text]) => h('button', { class: state.scale === key ? 'primary' : '',
      on: { click: () => { state.scale = key; render(); } } }, text))),
    g.rows.length ? h('div', { class: 'gscroll' }, h('div', { class: 'grow axis' }, h('div', { class: 'glabel' }, ''),
      h('div', { class: 'gtrack', css: { width } }, scaleTicks(g.min, g.span, state.scale).map((t) => h('span', { class: 'tick', css: { left: `${t.left}%` } }, t.text))))) : h('p', { class: 'muted' }, 'Нет задач со сроками.'),
    groupRows(g.rows, state.projNames).map((group) => h('div', { class: 'ggroup' }, h('h3', {}, group.title),
      h('div', { class: 'gscroll' }, (() => {
        const bar = group.key ? projectBar(state.projDates[group.key], g.min, g.span) : null;
        return bar ? h('div', { class: 'grow' }, h('div', { class: 'glabel muted' }, 'Сроки проекта'),
          h('div', { class: 'gtrack', css: { width } }, h('div', { class: 'gproj', css: { left: `${bar.left}%`, width: `${bar.width}%` },
            title: `${state.projDates[group.key].start_date} - ${state.projDates[group.key].due_date}` }))) : '';
      })(), (group.key ? stageBars(state.ganttStages[group.key], g.min, g.span) : []).map((st) => h('div', { class: 'grow' },
        h('div', { class: 'glabel muted' }, `Этап: ${st.title}`),
        h('div', { class: 'gtrack', css: { width } }, h('div', { class: 'gstage', css: { left: `${st.left}%`, width: `${st.width}%` }, title: `${st.start} - ${st.due}` })))),
      group.rows.map((r) => h('div', { class: 'grow' },
        h('div', { class: 'glabel', on: { click: () => openTask(r.task.id) } }, r.task.title), track(r)))))),
    g.undated.length ? h('div', { class: 'card' }, h('h3', {}, `Без дат (${g.undated.length})`),
      g.undated.map((t) => h('div', { class: 'ctask', on: { click: () => openTask(t.id) } }, t.title))) : '');
}

function calendarView() {
  const cells = monthGrid(state.cal.year, state.cal.month, state.tasks);
  const go = (d) => { state.cal = shiftMonth(state.cal.year, state.cal.month, d); render(); };
  return h('div', {},
    h('div', { class: 'bar' }, h('button', { on: { click: () => go(-1) } }, 'Назад'),
      h('strong', {}, `${MONTHS[state.cal.month]} ${state.cal.year}`), h('button', { on: { click: () => go(1) } }, 'Вперёд')),
    h('div', { class: 'cal' }, ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'].map((d) => h('div', { class: 'chead' }, d)),
      cells.map((c) => h('div', { class: 'cell' }, c.day ? [h('div', { class: 'muted' }, String(c.day)),
        c.tasks.map((t) => h('div', { class: 'ctask', on: { click: () => openTask(t.id) } }, t.title))] : ''))));
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
    b.expected_resolution_date ? h('div', { class: 'muted' }, `Ожидаемый срок: ${b.expected_resolution_date}`) : '',
    h('button', { type: 'button', on: { click: async () => { try { await api.resolveBlocker(b.id, b.version, b.status !== 'resolved'); state.error = ''; await openTask(task.id); } catch (error) { if (error.status === 409) await openTask(task.id); fail(error); } } } },
      b.status === 'resolved' ? 'Вернуть блокер' : 'Снять блокер'),
    state.risks.length ? h('select', { 'aria-label': 'Связать блокер с риском', on: { change: async (e) => {
      if (!e.target.value) return;
      try { await api.linkRiskBlocker(e.target.value, b.id, true); state.error = ''; state.message = 'Блокер связан с риском.'; delete state.riskLinks[e.target.value]; render(); } catch (error) { fail(error); }
    } } }, [h('option', { value: '' }, 'Связать с риском…'), ...state.risks.map((r) => h('option', { value: r.id }, r.description.slice(0, 40)))]) : '')),
  state.deps ? [state.deps.edges.map((e) => h('div', { class: 'comment' }, e.direction === 'blocked_by' ? 'Зависит от: ' : 'Блокирует: ', e.title, ` (${label(STATUSES, e.status)})`,
    h('button', { type: 'button', on: { click: async () => { try { await api.removeDependency(e.id, e.version, 'Убрано из карточки'); state.error = ''; await openTask(task.id); } catch (error) { if (error.status === 409) await openTask(task.id); fail(error); } } } }, 'Убрать'))),
    state.deps.hidden_external ? h('div', { class: 'muted' }, `Скрытых внешних зависимостей: ${state.deps.hidden_external}`) : ''] : '',
  h('label', { for: 'btitle' }, 'Новый блокер'), h('input', { id: 'btitle', name: 'title', maxlength: 200, required: true }),
  h('div', { class: 'bar' },
    h('div', {}, h('label', { for: 'bresp' }, 'Ответственный'),
      h('select', { id: 'bresp', name: 'responsible' }, (state.dir ? state.dir.members : []).map((m) => h('option', { value: m.user_id, selected: m.user_id === state.user.id }, m.display_name)))),
    h('div', {}, h('label', { for: 'bdue' }, 'Ожидаемый срок'), h('input', { id: 'bdue', name: 'due_date', placeholder: '2026-12-31', maxlength: 10 }))),
  h('button', { type: 'submit' }, 'Добавить блокер'));
  const dep = h('form', { class: 'card', on: { submit: async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(dep).entries());
    const out = dependencyPayload(task.id, data.other, data.direction, data.reason);
    if (out.error) { state.error = out.error; return render(); }
    try { await api.addDependency(out.payload); state.error = ''; await openTask(task.id); } catch (error) { fail(error); }
  } } },
  h('h3', {}, 'Новая зависимость'),
  h('label', { for: 'ddir' }, 'Тип'), h('select', { id: 'ddir', name: 'direction' },
    h('option', { value: 'blocked_by' }, 'Эта задача зависит от'), h('option', { value: 'blocks' }, 'Эта задача блокирует')),
  h('label', { for: 'doth' }, 'Другая задача'), h('select', { id: 'doth', name: 'other' },
    state.tasks.filter((t) => t.id !== task.id).map((t) => h('option', { value: t.id }, t.title))),
  h('label', { for: 'drsn' }, 'Причина'), h('input', { id: 'drsn', name: 'reason', maxlength: 500 }),
  h('button', { type: 'submit' }, 'Добавить зависимость'));
  return [form, dep];
}

function mainView() {
  const bar = h('div', { class: 'bar' },
    h('label', { for: 'ws' }, 'Пространство'),
    h('select', { id: 'ws', on: { change: async (e) => { state.ws = e.target.value; await loadDirectory(); await loadTasks(true); } } },
      state.workspaces.map((w) => h('option', { value: w.id, selected: w.id === state.ws }, w.name))),
    h('label', { for: 'st' }, 'Статус'),
    h('select', { id: 'st', on: { change: async (e) => { state.status = e.target.value; await loadTasks(true); } } }, options(STATUSES, state.status, 'Все')));
  const toggle = (key, text) => h('label', { class: 'muted' }, h('input', { type: 'checkbox', checked: state.filters[key],
    on: { change: async (e) => { state.filters[key] = e.target.checked; await loadTasks(true); } } }), ` ${text} `);
  const pick = (key, text, pairs) => [h('label', { for: `f${key}` }, text), h('select', { id: `f${key}`, on: { change: async (e) => { state.filters[key] = e.target.value; await loadTasks(true); } } },
    options(pairs, state.filters[key], 'Все'))];
  const filters = h('div', { class: 'bar filters' }, toggle('mine', 'Мои'), toggle('overdue', 'Просроченные'), toggle('blocked', 'С блокером'),
    pick('team', 'Команда', state.dir ? state.dir.teams.map((t) => [t.id, t.name]) : []),
    pick('project', 'Проект', Object.entries(state.projNames)),
    filtersActive(state.filters) ? h('button', { on: { click: async () => { state.filters = { mine: false, overdue: false, blocked: false, team: '', project: '' }; await loadTasks(true); } } }, 'Сбросить') : '');
  const tabs = h('div', { class: 'bar' }, [['list', 'Список'], ['board', 'Kanban'], ['gantt', 'Гант'], ['calendar', 'Календарь'], ['risks', 'Риски'], ['notes', `Уведомления${state.unread ? ` (${state.unread})` : ''}`]]
    .map(([key, text]) => h('button', { class: state.view === key ? 'primary' : '', on: { click: async () => {
      state.view = key; state.error = ''; state.message = '';
      if (key === 'notes') await loadNotes(); else if (key === 'risks') await loadRisks(); else await loadTasks(true);
    } } }, text)));
  const table = h('table', {}, h('thead', {}, h('tr', {}, ['Название', 'Статус', 'Приоритет', 'Срок'].map((t) => h('th', {}, t)))),
    h('tbody', {}, state.tasks.map(taskRow)));
  const messages = [h('div', { class: 'error', role: 'alert' }, state.error), h('div', { class: 'ok' }, state.message)];
  if (state.view === 'notes') return [tabs, messages, notesView()];
  if (state.view === 'risks') return [tabs, messages, risksView(), h('p', { class: 'muted' }, state.release)];
  return [bar, filters, tabs, messages, snapshotView(), metricsView(), state.dir ? createView() : '', h('div', { class: 'bar' }, h('button', { on: { click: () => exportTasks('csv') } }, 'Выгрузить CSV'),
      h('button', { on: { click: () => exportTasks('json') } }, 'Выгрузить JSON')),
    state.view === 'board' ? boardView() : state.view === 'gantt' ? ganttView() : state.view === 'calendar' ? calendarView() : table,
    state.more ? h('button', { on: { click: async () => { await loadTasks(false); } } }, 'Показать ещё') : '',
    state.selected ? [detailView(), blockersView()] : ''];
}

function render() {
  root.replaceChildren();
  if (!state.user) { root.append(state.phase === 'password' ? passwordView() : loginView()); return; }
  root.append(h('header', {}, h('div', { class: 'brand' }, 'Task-Ayuza'), h('span', {}, state.user.display_name),
    h('button', { on: { click: async () => { try { await api.logout(); } catch { /* the session may already be gone */ }
      try { await api.bootstrap(); } catch { /* a new pre-login token is needed for the next sign-in */ }
      clearSession(); render(); } } }, 'Выйти')),
  h('main', {}, mainView()));
}

// ---- data

async function loadDirectory() {
  state.dir = state.ws ? await api.directory(state.ws) : null;
  state.projNames = {}; state.projDates = {};
  if (state.ws) {
    try { for (const p of await api.projects(state.ws)) { state.projNames[p.id] = p.title; state.projDates[p.id] = p; } } catch { /* groups fall back to a generic name */ }
  }
}

async function loadTasks(reset) {
  try {
    const after = !reset && state.tasks.length ? state.tasks[state.tasks.length - 1].id : null;
    const page = await api.tasks(state.ws, { ...state.filters, status: state.view === 'list' ? state.status : '' }, after);
    state.tasks = reset ? page : state.tasks.concat(page);
    state.more = page.length === PAGE;
    if (reset) await loadSnapshot();
    if (state.view === 'gantt') await Promise.all([loadGanttDeps(), loadGanttStages()]);
  } catch (error) { state.tasks = []; state.more = false; state.error = error.message; }
  render();
}

async function loadGanttDeps() {                          // existing per-task API, only for dated tasks and with a cap
  const dated = ganttRows(state.tasks).rows.map((r) => r.task.id).slice(0, MAX_DEP_TASKS);
  const found = {};
  await Promise.all(dated.map(async (id) => {
    try { found[id] = (await api.dependencies(id)).edges; } catch { /* a task without access simply has no connectors */ }
  }));
  state.ganttDeps = found;
}

async function loadGanttStages() {                        // existing per-project API, only for projects present on the Gantt, with a cap
  const ids = [...new Set(ganttRows(state.tasks).rows.map((r) => r.task.project_id).filter(Boolean))].slice(0, MAX_STAGE_PROJECTS);
  const found = {};
  await Promise.all(ids.map(async (id) => {
    try { found[id] = await api.stages(id); } catch { /* a project without access simply shows no stages */ }
  }));
  state.ganttStages = found;
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
  try { state.release = (await api.release()).label; } catch { state.release = ''; }
  if (state.ws) await loadTasks(true); else render();
}

async function start() {
  try { await api.bootstrap(); await enter(); }            // an existing session cookie recovers a fresh CSRF token
  catch (error) { state.user = null; state.phase = 'login'; state.error = error.status === 0 ? error.message : ''; render(); }
}

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => { /* the app works without it */ });
setInterval(refreshUnread, 60000);                      // polling instead of push; no storage involved
start();
