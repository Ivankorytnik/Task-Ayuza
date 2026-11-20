'use strict';
/* Task-Ayuza DEMO. Только синтетические данные, хранение в localStorage браузера.
   Не заменяет backend (FastAPI/PostgreSQL); голос здесь через браузерный SpeechRecognition,
   в продукте по ТЗ 5.1 это серверный whisper.cpp. */
const KEY = 'ta-demo-v1';
const STATUSES = ['Новая', 'Запланирована', 'В работе', 'Блокирована', 'Выполнена', 'Отменена'];
const PRIOS = ['Низкий', 'Обычный', 'Высокий', 'Критический'];
const CLOSED = ['Выполнена', 'Отменена'];
const ME = 'u1';
const USERS = [
  { id: 'u1', name: 'Иван К.', teams: ['ЭЛМА', 'Аналитика', 'Продажи'] },
  { id: 'u2', name: 'Анна С.', teams: ['ЭЛМА'] },
  { id: 'u3', name: 'Пётр Л.', teams: ['Производство'] },
  { id: 'u4', name: 'Мария Т.', teams: ['Продажи', 'Аналитика'] },
];
const TEAMS = ['ЭЛМА', 'Продажи', 'Аналитика', 'Производство'];
const PROJECTS = ['Электромобиль АТОМ', 'Без проекта'];
const uname = id => (USERS.find(u => u.id === id) || {}).name || 'не назначен';
const today = () => new Date().toISOString().slice(0, 10);
const addDays = n => { const d = new Date(); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); };
const uid = p => p + Math.random().toString(36).slice(2, 8);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function seed() {
  const t = (id, title, status, prio, owner, team, assignee, project, start, due, desc = '') =>
    ({ id, title, desc, status, prio, owner, team, assignee, project, start, due, labels: [], closedAt: CLOSED.includes(status) ? today() : null, version: 1 });
  return {
    tasks: [
      t('T1', 'Собрать требования к сквозной аналитике', 'Выполнена', 'Высокий', 'u1', 'Аналитика', 'u1', PROJECTS[0], addDays(-20), addDays(-8)),
      t('T2', 'Настроить выгрузку продаж из CRM', 'В работе', 'Высокий', 'u1', 'Продажи', 'u4', PROJECTS[0], addDays(-7), addDays(3)),
      t('T3', 'Построить дашборд воронки продаж', 'Запланирована', 'Обычный', 'u1', 'Аналитика', 'u1', PROJECTS[0], addDays(2), addDays(12)),
      t('T4', 'Согласовать комплектацию тестовой партии', 'Блокирована', 'Критический', 'u3', 'Производство', 'u3', PROJECTS[0], addDays(-5), addDays(-1)),
      t('T5', 'Подготовить КП для дилеров', 'Новая', 'Обычный', 'u1', 'Продажи', null, PROJECTS[0], '', addDays(9)),
      t('T6', 'Проверить схему зарядного узла (ЭЛМА)', 'В работе', 'Высокий', 'u2', 'ЭЛМА', 'u2', PROJECTS[0], addDays(-3), addDays(5)),
      t('T7', 'Сводный отчет для руководства', 'Новая', 'Низкий', 'u1', 'Аналитика', 'u1', PROJECTS[1], '', addDays(20)),
      t('T8', 'Заказать оснастку для испытаний', 'Запланирована', 'Высокий', 'u3', 'Производство', null, PROJECTS[0], addDays(1), addDays(10)),
    ],
    deps: [
      { id: 'D1', blocker: 'T2', dependent: 'T3', reason: 'Нужны данные продаж' },
      { id: 'D2', blocker: 'T6', dependent: 'T4', reason: 'Ждем заключение по зарядному узлу' },
      { id: 'D4', blocker: 'T6', dependent: 'T5', reason: 'Нужны характеристики зарядного узла' },
      { id: 'D3', blocker: 'T4', dependent: 'T8', reason: 'Оснастка зависит от комплектации' },
    ],
    blockers: [
      { id: 'B1', title: 'Нет подтверждения от поставщика', reason: 'Поставщик не подтвердил сроки по модулям', task: 'T4', blockingTask: 'T6', responsible: 'Производство', raised: addDays(-4), expected: addDays(-1), status: 'Активен', history: ['создан'] },
    ],
  };
}
let S = load();
function load() { try { const x = JSON.parse(localStorage.getItem(KEY)); if (x && x.tasks) return x; } catch (e) { } return seed(); }
function save() { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) { toast('Не удалось сохранить в браузере'); } }
let view = 'my';
const F = { q: '', status: '', prio: '', team: '', project: '', deps: false, overdue: false };

/* ---------- логика ---------- */
const task = id => S.tasks.find(t => t.id === id);
const isOverdue = t => t.due && t.due < today() && !CLOSED.includes(t.status);
const activeDeps = t => S.deps.filter(d => d.dependent === t.id && task(d.blocker) && !CLOSED.includes(task(d.blocker).status));
const activeBlockers = t => S.blockers.filter(b => b.task === t.id && b.status === 'Активен');
function reaches(from, to) { // есть ли путь from -> to по ребрам blocker -> dependent
  const seen = new Set(), st = [from];
  while (st.length) { const x = st.pop(); if (x === to) return true; if (seen.has(x)) continue; seen.add(x); S.deps.filter(d => d.blocker === x).forEach(d => st.push(d.dependent)); }
  return false;
}
function addDep(blocker, dependent, reason) {
  if (!blocker || !dependent || !task(blocker) || !task(dependent)) return 'Выберите существующие задачи';
  if (blocker === dependent) return 'Задача не может блокировать саму себя';
  if (S.deps.some(d => d.blocker === blocker && d.dependent === dependent)) return 'Такая зависимость уже есть';
  if (reaches(dependent, blocker)) return 'Зависимость создает цикл';
  S.deps.push({ id: uid('D'), blocker, dependent, reason: reason || '' });
  return '';
}
function filtered(base) {
  const q = F.q.trim().toLowerCase();
  return base.filter(t => (!q || (t.title + ' ' + t.desc).toLowerCase().includes(q)) && (!F.status || t.status === F.status) && (!F.prio || t.prio === F.prio) &&
    (!F.team || t.team === F.team) && (!F.project || t.project === F.project) && (!F.deps || activeDeps(t).length || activeBlockers(t).length) && (!F.overdue || isOverdue(t)));
}
const baseFor = v => v === 'my' ? S.tasks.filter(t => t.assignee === ME || t.owner === ME) : S.tasks;

/* ---------- отрисовка ---------- */
const NAV = [['my', 'Мои задачи'], ['list', 'Все задачи'], ['kanban', 'Kanban'], ['blockers', 'Блокеры'], ['ext', 'Внешние ожидания']];
function toast(m) { const e = document.getElementById('toast'); e.textContent = m; e.className = 'on'; clearTimeout(toast.t); toast.t = setTimeout(() => e.className = '', 2600); }
function badges(t) {
  let h = `<span class="badge s-${t.status}">${esc(t.status)}</span><span class="badge p-${t.prio}">${esc(t.prio)}</span>`;
  const ad = activeDeps(t).length, ab = activeBlockers(t).length;
  if (ad) h += `<span class="badge warn">зависимостей: ${ad}</span>`;
  if (ab) h += `<span class="badge over">блокеров: ${ab}</span>`;
  if (isOverdue(t)) h += `<span class="badge over">просрочена</span>`;
  return h;
}
function renderNav() {
  document.getElementById('nav').innerHTML = NAV.map(([k, n]) => `<button class="${view === k ? 'on' : ''}" data-v="${k}">${n}</button>`).join('');
}
function renderFilters() {
  const o = (arr, v) => '<option value="">все</option>' + arr.map(x => `<option ${x === v ? 'selected' : ''}>${esc(x)}</option>`).join('');
  document.getElementById('filters').style.display = view === 'blockers' || view === 'ext' ? 'none' : 'flex';
  document.getElementById('filters').innerHTML = `
  <input id="fq" placeholder="Поиск" value="${esc(F.q)}">
  <select id="fs" title="Статус">${o(STATUSES, F.status)}</select>
  <select id="fp" title="Приоритет">${o(PRIOS, F.prio)}</select>
  <select id="ft" title="Команда">${o(TEAMS, F.team)}</select>
  <select id="fj" title="Проект">${o(PROJECTS, F.project)}</select>
  <label><input type="checkbox" id="fd" ${F.deps ? 'checked' : ''}> зависимости/блокеры</label>
  <label><input type="checkbox" id="fo" ${F.overdue ? 'checked' : ''}> просроченные</label>`;
}
function kpis(list) {
  const open = list.filter(t => !CLOSED.includes(t.status));
  return `<div class="kpis"><div class="kpi"><b>${open.length}</b>открытых</div><div class="kpi"><b>${list.filter(isOverdue).length}</b>просрочено</div>
  <div class="kpi"><b>${list.filter(t => t.status === 'Блокирована').length}</b>блокировано</div><div class="kpi"><b>${S.blockers.filter(b => b.status === 'Активен').length}</b>активных блокеров</div>
  <div class="kpi"><b>${list.filter(t => t.status === 'Выполнена').length}</b>выполнено</div></div>`;
}
function renderList(list) {
  if (!list.length) return '<div class="panel muted">Задач по фильтру нет.</div>';
  return `<table><thead><tr><th>Задача</th><th>Статус</th><th>Команда</th><th>Владелец</th><th>Исполнитель</th><th>Срок</th></tr></thead><tbody>` +
    list.map(t => `<tr class="row" data-id="${t.id}"><td><b>${esc(t.title)}</b><div class="muted">${esc(t.project)}</div></td><td>${badges(t)}</td><td>${esc(t.team)}</td><td>${esc(uname(t.owner))}</td><td>${esc(uname(t.assignee))}</td><td>${esc(t.due || '')}</td></tr>`).join('') + '</tbody></table>';
}
function renderKanban(list) {
  return '<div class="board">' + STATUSES.map(s => {
    const items = list.filter(t => t.status === s);
    return `<div class="col" data-s="${s}"><h3>${s}<span>${items.length}</span></h3>` + items.map(t =>
      `<div class="card" draggable="true" data-id="${t.id}"><div class="t">${esc(t.title)}</div><div class="m">${esc(t.team)} / ${esc(uname(t.assignee))}${t.due ? ' / ' + esc(t.due) : ''}</div>${badges(t).replace(/<span class="badge s-[^"]*">[^<]*<\/span>/, '')}</div>`).join('') + '</div>';
  }).join('') + '</div><p class="muted">Перетащите карточку в другой столбец, чтобы сменить статус вручную. Зависимости и блокеры статус сами не меняют.</p>';
}
function renderBlockers() {
  const rows = S.blockers.map(b => {
    const tk = task(b.task), bt = b.blockingTask ? task(b.blockingTask) : null, late = b.status === 'Активен' && b.expected && b.expected < today();
    return `<tr><td><b>${esc(b.title)}</b><div class="muted">${esc(b.reason)}</div></td><td>${tk ? esc(tk.title) : ''}</td><td>${bt ? esc(bt.title) : ''}</td><td>${esc(b.responsible)}</td>
    <td>${esc(b.raised)}<br>${esc(b.expected || '')}${late ? ' <span class="badge over">просрочен</span>' : ''}</td><td><span class="badge ${b.status === 'Активен' ? 'over' : ''}">${esc(b.status)}</span></td>
    <td><button data-bt="${b.id}">${b.status === 'Активен' ? 'Снять' : 'Открыть снова'}</button></td></tr>`;
  }).join('');
  return `<div class="row-end" style="margin:0 0 8px"><button class="primary" id="newBlocker">+ Новый блокер</button></div>` +
    (rows ? `<table><thead><tr><th>Блокер</th><th>Блокируемая задача</th><th>Блокирующая</th><th>Ответственный</th><th>Возник / срок</th><th>Статус</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="panel muted">Блокеров нет.</div>');
}
function renderExt() {
  const mine = S.tasks.filter(t => t.assignee === ME || t.owner === ME).map(t => t.id);
  const rows = S.deps.filter(d => mine.includes(d.dependent) && !mine.includes(d.blocker) && task(d.blocker) && !CLOSED.includes(task(d.blocker).status))
    .map(d => { const b = task(d.blocker), t = task(d.dependent); return `<tr class="row" data-id="${t.id}"><td>${esc(b.title)}<div class="muted">${esc(b.team)} / ${esc(uname(b.assignee))}</div></td><td>${esc(t.title)}</td><td>${esc(d.reason)}</td><td>${esc(b.due || '')}</td></tr>`; }).join('');
  return `<p class="muted">Задачи других людей и команд, от которых зависят мои задачи. В «Мои задачи» они не попадают.</p>` +
    (rows ? `<table><thead><tr><th>Чего жду</th><th>Моя задача</th><th>Причина</th><th>Срок</th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="panel muted">Внешних ожиданий нет.</div>');
}
function render() {
  renderNav(); renderFilters();
  const v = document.getElementById('view'); let h = '';
  if (view === 'blockers') h = renderBlockers();
  else if (view === 'ext') h = renderExt();
  else { const l = filtered(baseFor(view)); h = kpis(baseFor(view)) + (view === 'kanban' ? renderKanban(l) : renderList(l)); }
  v.innerHTML = h;
}

/* ---------- диалог задачи ---------- */
const dlg = document.getElementById('dlg');
let rec = null;
function opts(arr, sel, withEmpty) { return (withEmpty ? '<option value="">не назначен</option>' : '') + arr.map(x => { const v = x.id || x, n = x.name || x; return `<option value="${esc(v)}" ${v === sel ? 'selected' : ''}>${esc(n)}</option>`; }).join(''); }
function openTask(id) {
  const t = id ? task(id) : { title: '', desc: '', status: 'Новая', prio: 'Обычный', owner: ME, team: 'Аналитика', assignee: null, project: PROJECTS[0], start: '', due: '', labels: [] };
  const members = team => USERS.filter(u => u.teams.includes(team));
  const depsHtml = id ? `<div class="full panel" style="background:#f3f5f8"><b>Зависимости (A блокирует B)</b><div id="depList"></div>
    <div class="inline" style="margin-top:6px"><select id="depKind"><option value="in">Эту задачу блокирует</option><option value="out">Эта задача блокирует</option></select>
    <select id="depTask">${S.tasks.filter(x => x.id !== id).map(x => `<option value="${x.id}">${esc(x.title)}</option>`).join('')}</select>
    <input id="depReason" placeholder="Причина"><button id="depAdd">Добавить</button></div><div class="err" id="depErr"></div></div>` : '';
  dlg.innerHTML = `<h2>${id ? 'Задача' : 'Новая задача'}</h2><form id="tf" class="grid" method="dialog" novalidate>
  <label class="full">Название *<span class="inline"><input id="f_title" value="${esc(t.title)}" maxlength="200"><button type="button" data-mic="f_title">Надиктовать</button></span></label>
  <label class="full">Описание<span class="inline"><textarea id="f_desc" rows="3">${esc(t.desc)}</textarea><button type="button" data-mic="f_desc">Надиктовать</button></span></label>
  <div class="full muted" id="micBox"></div>
  <label>Статус<select id="f_status">${opts(STATUSES, t.status)}</select></label>
  <label>Приоритет<select id="f_prio">${opts(PRIOS, t.prio)}</select></label>
  <label>Владелец результата *<select id="f_owner">${opts(USERS, t.owner)}</select></label>
  <label>Команда-исполнитель *<select id="f_team">${opts(TEAMS, t.team)}</select></label>
  <label>Персональный исполнитель<select id="f_assignee">${opts(members(t.team), t.assignee, true)}</select></label>
  <label>Проект<select id="f_project">${opts(PROJECTS, t.project)}</select></label>
  <label>Плановое начало<input type="date" id="f_start" value="${esc(t.start)}"></label>
  <label>Срок<input type="date" id="f_due" value="${esc(t.due)}"></label>
  ${depsHtml}<div class="full err" id="tErr"></div>
  <div class="full row-end"><button type="button" id="tCancel">Закрыть без сохранения</button>${id ? '<button type="button" class="danger" id="tDel">Удалить</button>' : ''}<button type="button" class="primary" id="tSave">${id ? 'Сохранить' : 'Создать задачу'}</button></div></form>`;
  dlg.showModal();
  const refreshDeps = () => {
    const el = document.getElementById('depList'); if (!el) return;
    const li = S.deps.filter(d => d.dependent === id || d.blocker === id).map(d => {
      const inc = d.dependent === id, o = task(inc ? d.blocker : d.dependent);
      return `<div class="dep"><span>${inc ? 'Блокируется:' : 'Блокирует:'} <b>${esc(o ? o.title : '?')}</b> <span class="muted">${esc(d.reason)}</span></span><button data-rm="${d.id}" class="danger">Убрать</button></div>`;
    }).join('');
    el.innerHTML = li || '<div class="muted">Зависимостей нет.</div>';
  };
  refreshDeps();
  document.getElementById('f_team').onchange = e => { document.getElementById('f_assignee').innerHTML = opts(members(e.target.value), null, true); };
  document.getElementById('tCancel').onclick = () => { stopRec(true); dlg.close(); };
  document.getElementById('tSave').onclick = () => saveTask(id);
  if (id) {
    document.getElementById('tDel').onclick = () => { if (confirm('Удалить задачу вместе со связями?')) { S.tasks = S.tasks.filter(x => x.id !== id); S.deps = S.deps.filter(d => d.blocker !== id && d.dependent !== id); S.blockers = S.blockers.filter(b => b.task !== id && b.blockingTask !== id); save(); dlg.close(); render(); } };
    document.getElementById('depAdd').onclick = () => {
      const other = document.getElementById('depTask').value, kind = document.getElementById('depKind').value, why = document.getElementById('depReason').value;
      const err = kind === 'in' ? addDep(other, id, why) : addDep(id, other, why);
      document.getElementById('depErr').textContent = err; if (!err) { save(); refreshDeps(); render(); document.getElementById('depReason').value = ''; }
    };
    document.getElementById('depList').onclick = e => { const r = e.target.dataset.rm; if (r) { S.deps = S.deps.filter(d => d.id !== r); save(); refreshDeps(); render(); } };
  }
}
function saveTask(id) {
  const g = k => document.getElementById('f_' + k).value;
  const err = document.getElementById('tErr');
  if (!g('title').trim()) return err.textContent = 'Укажите название';
  if (!g('owner') || !g('team')) return err.textContent = 'Нужны владелец результата и команда';
  if (g('start') && g('due') && g('due') < g('start')) return err.textContent = 'Срок раньше начала';
  const asg = g('assignee') || null;
  if (asg && !USERS.find(u => u.id === asg).teams.includes(g('team'))) return err.textContent = 'Исполнитель должен состоять в команде задачи';
  stopRec(true);
  let t = id ? task(id) : { id: uid('T'), labels: [], closedAt: null, version: 0 };
  const was = t.status;
  Object.assign(t, { title: g('title').trim(), desc: g('desc'), status: g('status'), prio: g('prio'), owner: g('owner'), team: g('team'), assignee: asg, project: g('project'), start: g('start'), due: g('due') });
  if (CLOSED.includes(t.status) && !CLOSED.includes(was || '')) t.closedAt = today();
  if (!CLOSED.includes(t.status)) t.closedAt = null;
  t.version++;
  if (!id) S.tasks.push(t);
  save(); dlg.close(); render(); toast(id ? 'Задача сохранена' : 'Задача создана');
}

/* ---------- диктовка (демо) ---------- */
function stopRec(cancel) { if (rec) { rec.cancel = !!cancel; try { rec.r.stop(); } catch (e) { } clearInterval(rec.timer); rec = null; const b = document.getElementById('micBox'); if (b && cancel) b.textContent = ''; } }
function startRec(fieldId) {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition, box = document.getElementById('micBox');
  if (!SR) { box.innerHTML = '<span class="err">Диктовка в этом браузере недоступна. Введите текст вручную.</span>'; return; }
  if (rec) stopRec(true);
  const r = new SR(); r.lang = 'ru-RU'; r.interimResults = true; r.continuous = true;
  let text = '', sec = 0;
  rec = { r, cancel: false };
  const draw = () => box.innerHTML = `<span class="rec">Запись ${sec} с</span> <button type="button" id="micStop">Остановить</button> <button type="button" id="micCancel">Отменить</button> <span class="muted">Демо: распознает браузер, в продукте whisper.cpp на сервере</span>`;
  draw(); rec.timer = setInterval(() => { sec++; draw(); bind(); }, 1000);
  const bind = () => { const s = document.getElementById('micStop'), c = document.getElementById('micCancel'); if (s) s.onclick = () => { r.stop(); }; if (c) c.onclick = () => stopRec(true); };
  bind();
  r.onresult = e => { text = ''; for (let i = 0; i < e.results.length; i++) text += e.results[i][0].transcript; };
  r.onerror = e => { box.innerHTML = `<span class="err">Ошибка записи (${esc(e.error)}). Введите текст вручную.</span>`; clearInterval(rec && rec.timer); rec = null; };
  r.onend = () => {
    const cancelled = rec ? rec.cancel : true; if (rec) clearInterval(rec.timer); rec = null;
    if (cancelled) return;
    const f = document.getElementById(fieldId);
    if (f && text.trim()) { f.value = (f.value ? f.value + ' ' : '') + text.trim(); box.textContent = 'Расшифровка добавлена в поле, проверьте и исправьте. Задача не создана, пока вы не нажмете «Создать задачу».'; }
    else box.textContent = 'Речь не распознана. Попробуйте еще раз или введите вручную.';
  };
  try { r.start(); } catch (e) { box.innerHTML = '<span class="err">Не удалось начать запись.</span>'; rec = null; }
}

/* ---------- блокер ---------- */
function openBlocker() {
  dlg.innerHTML = `<h2>Новый блокер</h2><div class="grid"><label class="full">Название *<input id="b_title"></label><label class="full">Причина<textarea id="b_reason" rows="2"></textarea></label>
  <label>Блокируемая задача *<select id="b_task">${S.tasks.map(t => `<option value="${t.id}">${esc(t.title)}</option>`).join('')}</select></label>
  <label>Блокирующая задача<select id="b_by"><option value="">нет</option>${S.tasks.map(t => `<option value="${t.id}">${esc(t.title)}</option>`).join('')}</select></label>
  <label>Ответственная команда<select id="b_resp">${opts(TEAMS, TEAMS[0])}</select></label><label>Ожидаемый срок<input type="date" id="b_exp"></label></div><div class="err" id="bErr"></div>
  <div class="row-end"><button id="bCancel">Отмена</button><button class="primary" id="bSave">Создать</button></div>`;
  dlg.showModal();
  document.getElementById('bCancel').onclick = () => dlg.close();
  document.getElementById('bSave').onclick = () => {
    const v = k => document.getElementById('b_' + k).value;
    if (!v('title').trim()) return document.getElementById('bErr').textContent = 'Укажите название';
    if (v('by') && v('by') === v('task')) return document.getElementById('bErr').textContent = 'Блокирующая задача совпадает с блокируемой';
    S.blockers.push({ id: uid('B'), title: v('title').trim(), reason: v('reason'), task: v('task'), blockingTask: v('by') || null, responsible: v('resp'), raised: today(), expected: v('exp'), status: 'Активен', history: ['создан'] });
    save(); dlg.close(); render(); toast('Блокер создан');
  };
}

/* ---------- события ---------- */
document.addEventListener('click', e => {
  const n = e.target.closest('[data-v]'); if (n && n.closest('nav')) { view = n.dataset.v; render(); return; }
  const mic = e.target.closest('[data-mic]'); if (mic) { startRec(mic.dataset.mic); return; }
  const bt = e.target.closest('[data-bt]'); if (bt) { const b = S.blockers.find(x => x.id === bt.dataset.bt); b.status = b.status === 'Активен' ? 'Снят' : 'Активен'; b.history.push(b.status); save(); render(); return; }
  if (e.target.id === 'newBlocker') return openBlocker();
  const row = e.target.closest('tr.row,.card'); if (row && !dlg.open) openTask(row.dataset.id);
});
document.getElementById('btnNew').onclick = () => openTask(null);
document.getElementById('btnExport').onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(S, null, 2)], { type: 'application/json' })); a.download = 'task-ayuza-demo.json'; a.click(); };
document.getElementById('btnReset').onclick = () => { if (confirm('Вернуть демо-данные?')) { S = seed(); save(); render(); } };
document.getElementById('filters').addEventListener('input', e => {
  const m = { fq: ['q', e.target.value], fs: ['status', e.target.value], fp: ['prio', e.target.value], ft: ['team', e.target.value], fj: ['project', e.target.value], fd: ['deps', e.target.checked], fo: ['overdue', e.target.checked] }[e.target.id];
  if (m) { F[m[0]] = m[1]; const pos = e.target.selectionStart; render(); const el = document.getElementById(e.target.id); if (el && e.target.id === 'fq') { el.focus(); el.setSelectionRange(pos, pos); } }
});
let dragId = null;
document.addEventListener('dragstart', e => { const c = e.target.closest && e.target.closest('.card'); if (c) dragId = c.dataset.id; });
document.addEventListener('dragover', e => { const c = e.target.closest && e.target.closest('.col'); if (c) { e.preventDefault(); c.classList.add('drop'); } });
document.addEventListener('dragleave', e => { const c = e.target.closest && e.target.closest('.col'); if (c) c.classList.remove('drop'); });
document.addEventListener('drop', e => {
  const c = e.target.closest && e.target.closest('.col'); if (!c || !dragId) return; e.preventDefault();
  const t = task(dragId), s = c.dataset.s; dragId = null;
  if (t.status !== s) { if (CLOSED.includes(s) && !CLOSED.includes(t.status)) t.closedAt = today(); if (!CLOSED.includes(s)) t.closedAt = null; t.status = s; t.version++; save(); toast('Статус изменен: ' + s); }
  render();
});
dlg.addEventListener('close', () => stopRec(true));
if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => { });
render();
