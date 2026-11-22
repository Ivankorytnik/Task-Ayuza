import { apiDocRows, groupByArea } from './apidocs.js';

const root = document.getElementById('app');
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };

async function main() {
  root.append(el('h1', '', 'Справочник API Task-Ayuza'));
  root.append(el('p', 'muted', 'Собрано из openapi.json самого сервиса. Изменяющие запросы (все, кроме GET) требуют вход и заголовок X-CSRF-Token.'));
  let spec;
  try {
    const res = await fetch('/openapi.json', { credentials: 'same-origin', cache: 'no-store' });
    if (!res.ok) throw new Error('status');
    spec = await res.json();
  } catch { root.append(el('p', 'error', 'Не удалось загрузить описание API.')); return; }
  for (const [area, rows] of groupByArea(apiDocRows(spec))) {
    const card = el('div', 'card');
    card.append(el('h3', '', area));
    for (const r of rows) {
      const line = el('div', 'comment');
      line.append(el('strong', '', `${r.method} ${r.path}`));
      if (r.summary) line.append(el('div', '', r.summary));
      const meta = [r.mutating ? 'изменяющий, нужен CSRF' : 'чтение', r.body ? 'есть тело запроса' : '', r.params.length ? `параметры: ${r.params.join(', ')}` : '', `ответы: ${r.codes.join(', ')}`].filter(Boolean).join(' · ');
      line.append(el('div', 'muted', meta));
      card.append(line);
    }
    root.append(card);
  }
}
main();
