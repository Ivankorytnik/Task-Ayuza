// Browser E2E against the real backend. Usage: node tests/browser/e2e.mjs <base-url> <user.json>
// Needs google-chrome. Synthetic data only. Exits 1 on a CSP violation, a page exception or a missing element.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';

const [base, userFile] = process.argv.slice(2);
const user = JSON.parse(readFileSync(userFile, 'utf8'));
const ch = spawn('google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', '--ignore-certificate-errors',
  '--remote-debugging-port=9335', 'about:blank'], { stdio: 'ignore' });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
await wait(3000);
const list = await (await fetch('http://localhost:9335/json')).json();
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

for (const [tab, marker] of [['Kanban', 'Перенести'], ['Гант', 'Нет задач со сроками'], ['Календарь', 'Пн'], ['Уведомления', 'Уведомлений нет'], ['Список', 'Синтетическая задача 1']]) {
  await click(tab);
  check(`tab ${tab}`, await until(`document.body.innerText.includes(${JSON.stringify(marker)})`), (await text()).slice(0, 200));
}
await click('Риски');
check('risk centre says access is for the controller only (no role)', await until("document.body.innerText.includes('только контролёру рисков')"));
await click('Список');
await ev("document.querySelector('#fmine') && (document.querySelector('#fmine').click(), true)");
await click('Выйти');
check('signed out (login form again)', await until("!!document.querySelector('#login')"));

console.log(steps.join('\n'));
ch.kill();
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('E2E passed');
process.exit(0);
