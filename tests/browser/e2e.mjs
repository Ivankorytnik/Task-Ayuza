// Browser E2E against the real backend. Usage: node tests/browser/e2e.mjs <base-url> <user.json>
// Needs google-chrome. Synthetic data only. Exits 1 on a CSP violation, a page exception or a missing element.
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const [base, userFile] = process.argv.slice(2);
const user = JSON.parse(readFileSync(userFile, 'utf8'));
const ch = spawn('google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', '--ignore-certificate-errors',
  '--remote-debugging-port=9335', '--user-data-dir=/tmp/e2e-chrome', 'about:blank'], { stdio: ['ignore', 'ignore', 'inherit'] });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let list = null;
for (let i = 0; i < 60 && !list; i += 1) {                      // the debugging port needs a moment on a cold runner
  await wait(500);
  try { const found = await (await fetch('http://127.0.0.1:9335/json')).json(); if (found.some((t) => t.type === 'page')) list = found; } catch { /* not up yet */ }
}
if (!list) { console.error('Chrome did not open its debugging port'); ch.kill(); process.exit(1); }
const ws = new WebSocket(list.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => { ws.onopen = r; });
let id = 0; const pend = new Map(); const problems = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); }
  if (d.method === 'Runtime.exceptionThrown') problems.push(`exception: ${JSON.stringify(d.params).slice(0, 300)}`);
  if (d.method === 'Log.entryAdded' && /Content Security Policy|Refused to/i.test(d.params.entry.text)) problems.push(`csp: ${d.params.entry.text.slice(0, 300)}`);
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (e) => (await send('Runtime.evaluate', { expression: e, awaitPromise: true, returnByValue: true })).result.result.value;
const text = () => ev("document.body.innerText");
const steps = [];
const check = (name, ok, detail = '') => { steps.push(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : ` ${detail}`}`); if (!ok) problems.push(`step failed: ${name} ${detail}`); };
const click = (t) => ev(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim().startsWith(${JSON.stringify(t)})); if (!b) return false; b.click(); return true; })()`);
const until = async (expr, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await ev(expr)) return true; await wait(250); } return false; };
const fill = (selector, value) => ev(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.value = ${JSON.stringify(value)}; return true; })()`);

const signIn = async (login, password) => {
  await fill('#login', login); await fill('#password', password); await click('Войти');
};
const signOut = async () => { await click('Выйти'); return until("!!document.querySelector('#login')"); };
const loggedIn = () => until("[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Выйти')");
const setSelect = (selector, value) => ev(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);

await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');
await send('Page.navigate', { url: `${base}/app/` });
check('login form shown', await until("!!document.querySelector('#login')"));
await fill('#login', user.login); await fill('#password', user.password);
await click('Войти');
check('signed in (header with logout)', await until("[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Выйти')"), (await text()).slice(0, 200));
check('workspace tasks listed', await until("document.body.innerText.includes('Синтетическая задача 1')"), (await text()).slice(0, 300));
check('snapshot shown', (await text()).includes('Всего'));

await fill('#ntitle', 'Задача из браузера');
await ev("document.querySelector('#ntitle').form.querySelector('button[type=submit]').click()");
check('created task appears in the list', await until("document.body.innerText.includes('Задача из браузера')"), (await text()).slice(0, 300));
await ev("[...document.querySelectorAll('td, .ttitle, a')].find((e) => e.textContent.trim() === 'Задача из браузера')?.click()");
check('task card opens with blockers block', await until("document.body.innerText.includes('Карточка задачи') && document.body.innerText.includes('Блокеры и зависимости')"));

for (const [tab, marker] of [['Kanban', 'Перенести'], ['Гант', 'Без дат'], ['Календарь', 'Пн'], ['Уведомления', 'Уведомлений нет'], ['Список', 'Синтетическая задача 1']]) {
  await click(tab);
  check(`tab ${tab}`, await until(`document.body.innerText.includes(${JSON.stringify(marker)})`), (await text()).slice(0, 200));
}
await click('Риски');
check('risk centre says access is for the controller only (no role)', await until("document.body.innerText.includes('только контролёру рисков')"));

// Gantt: dependency connector from A to B
await click('Гант');
check('gantt shows a dependency connector after the blocker', await until("[...document.querySelectorAll('.gdep')].some((e) => e.getAttribute('title') === 'После: Гант A' && !e.classList.contains('conflict'))"), (await text()).slice(0, 300));
check('gantt shows the project bar in its group', await until("document.querySelectorAll('.gproj').length === 1"), (await text()).slice(0, 300));
check('gantt connector has an arrow head', await ev("document.querySelectorAll('.garrow').length >= 1"));
await click('Список');

// blocker: create in the card, then resolve it
await click('Список');
await ev("[...document.querySelectorAll('td')].find((e) => e.textContent.trim() === 'Синтетическая задача 2')?.click()");
check('card of task 2 opens', await until("document.body.innerText.includes('Блокеры и зависимости') && !!document.querySelector('#btitle')"));
await fill('#btitle', 'Ждём ответ e2e');
await ev("document.querySelector('#btitle').form.querySelector('button[type=submit]').click()");
check('blocker created', await until("document.body.innerText.includes('Ждём ответ e2e') && document.body.innerText.includes('активен')"), (await text()).slice(-300));
await click('Снять блокер');
check('blocker resolved', await until("document.body.innerText.includes('снят') && [...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Вернуть блокер')"));

// Kanban: move through the status select
await click('Kanban');
check('kanban shows task cards', await until("document.querySelectorAll('.tcard').length >= 2"));
await ev("(() => { const sel = [...document.querySelectorAll('.col[data-status=new] .tcard')].find((e) => e.querySelector('.ttitle').textContent.trim() === 'Синтетическая задача 2').querySelector('select'); sel.value = 'in_progress'; sel.dispatchEvent(new Event('change', { bubbles: true })); })()");
check('task moved to in_progress column', await until("document.querySelectorAll('.col[data-status=in_progress] .tcard').length === 1"));
await click('Список');
await signOut();

// temporary password: forced change in the browser
await signIn(user.temp.login, user.temp.temporary);
check('password change screen shown', await until("document.body.innerText.includes('Новый пароль') && !!document.querySelector('#next')"), (await text()).slice(0, 200));
await fill('#next', user.temp.new_password); await fill('#again', user.temp.new_password);
await click('Сохранить и войти');
check('signed in after the password change', await loggedIn(), (await text()).slice(0, 300));
check('signing out after a password change works', await signOut());
await signIn(user.temp.login, user.temp.new_password);
check('new password works for a fresh sign-in', await loggedIn());
await signOut();

// risk controller: fresh MFA is a fixture here (the browser has no authenticator)
await signIn(user.controller.login, user.controller.password);
check('controller signed in', await loggedIn());
execFileSync('python', ['tests/e2e/mark_mfa.py', user.controller.id], { stdio: 'inherit' });
await click('Риски');
check('risk centre opens for the controller', await until("document.body.innerText.includes('Новый риск') && !!document.querySelector('#rdesc')"), (await text()).slice(0, 300));
await setSelect('#rcat', 'backup'); await fill('#rdesc', 'Синтетический риск e2e');
await ev("document.querySelector('#rdesc').form.querySelector('button[type=submit]').click()");
check('risk created and gray by default', await until("document.body.innerText.includes('Синтетический риск e2e') && document.body.innerText.includes('Серый: не проверено')"), (await text()).slice(0, 400));
const valid = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
await setSelect('select[name=result]', 'pass');
await fill('input[name=evidence]', 'отчёт e2e'); await fill('input[name=valid_until]', valid);
await click('Записать проверку');
check('passing check with evidence turns the light green', await until("document.body.innerText.includes('Зелёный: проверено')"), (await text()).slice(0, 400));

// a blocker of the controller's own task is linked to the risk and unlinked again
await click('Список');
await until("!!document.querySelector('#ntitle')");
await fill('#ntitle', 'Задача контролёра');
await ev("document.querySelector('#ntitle').form.querySelector('button[type=submit]').click()");
await until("document.body.innerText.includes('Задача контролёра')");
await ev("[...document.querySelectorAll('td')].find((e) => e.textContent.trim() === 'Задача контролёра')?.click()");
await until("!!document.querySelector('#btitle')");
await fill('#btitle', 'Блокер для риска e2e');
await ev("document.querySelector('#btitle').form.querySelector('button[type=submit]').click()");
check('controller blocker created', await until("document.body.innerText.includes('Блокер для риска e2e')"), (await text()).slice(-300));
const sel = "select[aria-label=\"Связать блокер с риском\"]";
check('risk picker shown in the blocker block', await until(`!!document.querySelector('${sel}')`));
await ev(`(() => { const el = document.querySelector('${sel}'); el.value = el.options[1].value; el.dispatchEvent(new Event('change', { bubbles: true })); })()`);
check('blocker linked to the risk', await until("document.body.innerText.includes('Блокер связан с риском.')"), (await text()).slice(0, 300));
await click('Риски');
await until("[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Связанные задачи')");
await click('Связанные задачи');
check('linked blocker shown in the risk centre with its title', await until("document.body.innerText.includes('Блокер: Блокер для риска e2e')"), (await text()).slice(0, 400));
await click('Отвязать блокер');
check('blocker unlinked from the risk', await until("!document.body.innerText.includes('Блокер: Блокер для риска e2e')"));
await signOut();

// export without the grant, drag and drop in Kanban, loss of network
await signIn(user.login, user.password);
check('signed in again for the export and network checks', await loggedIn());
check('nothing of the previous user is left on screen after a new sign-in', await ev("!document.body.innerText.includes('Синтетический риск e2e')"));
await click('Список');
await until("[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Выгрузить CSV')");
await click('Выгрузить CSV');
check('export without a grant shows the access message', await until("document.body.innerText.includes('Выгрузка требует права')"), (await text()).slice(0, 300));
await click('Kanban');
check('kanban cards present', await until("document.querySelectorAll('.col[data-status=new] .tcard').length >= 1"));
const before = await ev("document.querySelectorAll('.col[data-status=planned] .tcard').length");
await ev(`(() => { const card = [...document.querySelectorAll('.col[data-status=new] .tcard')].find((e) => e.querySelector('.ttitle').textContent.trim() === 'Синтетическая задача 1'); const col = document.querySelector('.col[data-status=planned]');
  const dt = new DataTransfer();
  card.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: dt }));
  col.dispatchEvent(new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer: dt }));
  col.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt })); })()`);
check('drag and drop moved the card to planned', await until(`document.querySelectorAll('.col[data-status=planned] .tcard').length === ${before + 1}`), (await text()).slice(0, 300));
await send('Network.enable');
await send('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
await click('Выгрузить JSON');
check('offline: the client shows a no-connection message and stays alive', await until("document.body.innerText.includes('Нет связи')"), (await text()).slice(0, 300));
check('offline: nothing is stored on the device', await ev("localStorage.length === 0 && sessionStorage.length === 0"));
await send('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
await click('Выгрузить JSON');
check('back online: the client works again', await until("document.body.innerText.includes('Выгрузка требует права')"), (await text()).slice(0, 300));
await signOut();

// API reference page: rendered from the service's own openapi.json under the same CSP
await send('Page.navigate', { url: `${base}/app/api.html` });
check('api reference lists the login endpoint', await until("document.body.innerText.includes('POST /api/v1/auth/login')"), (await text()).slice(0, 300));
check('api reference marks mutating calls', await ev("document.body.innerText.includes('изменяющий, нужен CSRF')"));

// mobile: narrow touch screen, no sideways page scroll, controls reachable
await send('Emulation.setDeviceMetricsOverride', { width: 360, height: 740, deviceScaleFactor: 2, mobile: true });
await send('Emulation.setTouchEmulationEnabled', { enabled: true });
await send('Page.navigate', { url: `${base}/app/` });
check('mobile: login form shown', await until("!!document.querySelector('#login')"));
const fits = () => ev("document.documentElement.scrollWidth <= window.innerWidth + 1");
const overflow = () => ev("(() => { const w = window.innerWidth; return [...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > w + 1 && !e.closest('.gantt,.gscroll,.scroll')).slice(0, 4).map((e) => e.tagName + '.' + e.className + ' ' + Math.round(e.getBoundingClientRect().right)).join(' | '); })()");
check('mobile: login fits the screen', await fits(), await overflow());
await signIn(user.login, user.password);
check('mobile: signed in', await loggedIn());
for (const tab of ['Список', 'Kanban', 'Гант', 'Календарь', 'Уведомления', 'Риски']) {
  await click(tab);
  await new Promise((r) => setTimeout(r, 400));
  check(`mobile: tab ${tab} fits the screen`, await fits(), await overflow());
}
await click('Список');
await until("[...document.querySelectorAll('td')].some((e) => e.textContent.trim() === 'Синтетическая задача 1')");
await ev("[...document.querySelectorAll('td')].find((e) => e.textContent.trim() === 'Синтетическая задача 1')?.click()");
check('mobile: card opens', await until("document.body.innerText.includes('Блокеры и зависимости')"));
check('mobile: card fits the screen', await fits(), await overflow());
check('mobile: buttons are at least 32px tall', await ev("[...document.querySelectorAll('button')].every((b) => b.getBoundingClientRect().height >= 32)"));
await signOut();

console.log(steps.join('\n'));
ch.kill();
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('E2E passed');
process.exit(0);
