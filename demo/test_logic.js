// Запуск: node demo/test_logic.js. Проверка логики демо без браузера (заглушки DOM).
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const el = () => new Proxy(function () { }, { get: (t, k) => k === 'style' ? {} : k === 'addEventListener' ? () => { } : el(), set: () => true, apply: () => el() });
const store = {};
const ctx = { console, localStorage: { getItem: k => store[k] || null, setItem: (k, v) => { store[k] = v; } }, document: { getElementById: () => el(), addEventListener() { }, createElement: el }, window: {}, navigator: {}, location: { protocol: 'file:' }, setTimeout, clearTimeout, setInterval, clearInterval, URL, Blob };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/app.js', 'utf8') + ';this.api={renderList,renderKanban,renderBlockers,renderExt,kpis,S:()=>S,addDep,activeDeps,activeBlockers,isOverdue,filtered,baseFor,task,F,seed,reset:()=>{S=seed()}}', ctx);
const a = ctx.api;
let n = 0; const ok = (c, m) => { assert(c, m); n++; };
ok(a.addDep('T1', 'T1') !== '', 'самоссылка запрещена');
ok(a.addDep('T2', 'T3') !== '', 'дубль запрещен');
ok(a.addDep('T8', 'T6') !== '', 'цикл T6->T4->T8->T6 запрещен');
ok(a.addDep('T3', 'T2') !== '', 'обратное ребро цикл');
ok(a.addDep('T1', 'T5', 'ok') === '', 'корректная зависимость добавляется');
a.reset();
ok(a.activeDeps(a.task('T3')).length === 1, 'T3 ждет T2');
ok(a.activeDeps(a.task('T2')).length === 0, 'T2 без зависимостей');
a.task('T2').status = 'Выполнена';
ok(a.activeDeps(a.task('T3')).length === 0, 'после выполнения блокера зависимость не активна');
ok(a.task('T3').status === 'Запланирована', 'статус сам не меняется');
ok(a.isOverdue(a.task('T4')) && !a.isOverdue(a.task('T1')), 'просрочка считается только для открытых');
ok(a.activeBlockers(a.task('T4')).length === 1, 'активный блокер T4');
ok(a.baseFor('my').every(t => t.assignee === 'u1' || t.owner === 'u1'), 'Мои = исполнитель ИЛИ владелец');
ok(!a.baseFor('my').some(t => t.id === 'T6'), 'членство в команде не делает задачу моей');
a.F.status = 'Блокирована'; ok(a.filtered(a.S().tasks).length === 1, 'фильтр статуса'); a.F.status = '';
a.F.q = 'дашборд'; ok(a.filtered(a.S().tasks).length === 1, 'поиск'); a.F.q = '';
for (const v of ['my','list','kanban','blockers','ext']) { const l = a.filtered(a.baseFor(v)); const h = a.kpis(l) + (v==='kanban'?a.renderKanban(l):v==='blockers'?a.renderBlockers():v==='ext'?a.renderExt():a.renderList(l)); ok(h.length > 50, 'отрисовка ' + v); }
ok(a.renderExt().includes('характеристики зарядного'), 'внешние ожидания содержат причину');
console.log('OK', n, 'проверок');
