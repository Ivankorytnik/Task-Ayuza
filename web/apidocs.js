// Human-readable API reference built from the service's own openapi.json. No external code, text nodes only.
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];

export function apiDocRows(spec) {
  const rows = [];
  for (const [path, item] of Object.entries((spec && spec.paths) || {})) {
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const params = (op.parameters || []).map((p) => `${p.name} (${p.in}${p.required ? ', обязательный' : ''})`);
      rows.push({
        method: method.toUpperCase(), path,
        summary: op.summary || op.operationId || '',
        mutating: method !== 'get',
        params,
        body: Boolean(op.requestBody),
        codes: Object.keys(op.responses || {}).sort(),
      });
    }
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path) || METHODS.indexOf(a.method.toLowerCase()) - METHODS.indexOf(b.method.toLowerCase()));
}

export function groupByArea(rows) {                    // /api/v1/<area>/... gives the section name
  const groups = new Map();
  for (const row of rows) {
    const area = (row.path.split('/')[3] || 'other');
    if (!groups.has(area)) groups.set(area, []);
    groups.get(area).push(row);
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}
