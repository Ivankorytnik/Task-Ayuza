"""M04.3 internal service: release metadata and task export (TZ 12-13). No HTTP.

Release metadata is read only from the releases table, which the runtime role cannot write: it is filled by
the authorized release procedure with the real publication time, never by a client or at first migration.
Without a record the honest answer is "version not determined".

Export needs the separate export administrative grant with fresh MFA and, for every row, the caller's own
read access to that task (the grant does not read tasks). CSV is UTF-8 with BOM and cells that could start
a spreadsheet formula are neutralised. export_events stores only the parameters and the result count,
never a copy of the exported data.
"""
from __future__ import annotations

import csv
import io
import json
import uuid

from backend.acl import AclError, _forbidden, _not_found, as_uuid, audit, membership
from backend.auth import execute, one
from backend.risks import RisksService
from backend.work import STATUSES, _grant_ok

COLUMNS = ('id', 'title', 'status', 'priority', 'project_id', 'result_owner_user_id', 'assignee_user_id',
           'start_date', 'due_date', 'created_at')
FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
UNDEFINED = 'Версия не определена'


def safe_cell(value):
    text = '' if value is None else (value.isoformat() if hasattr(value, 'isoformat') else str(value))
    return "'" + text if text.startswith(FORMULA_START) else text


class ExportsService(RisksService):
    EXPORT_LIMIT = 2000

    def release_info(self, token):
        def run(c, u, s):
            row = one(c, 'SELECT * FROM task_ayuza.releases ORDER BY published_at DESC, id DESC LIMIT 1')
            if row is None:
                return {'version': None, 'label': UNDEFINED}
            return {'version': row['version'], 'commit_sha': row['commit_sha'], 'published_at': row['published_at'],
                    'environment': row['environment'], 'label': row['version']}
        return self.auth.protected(token, run)

    def export_tasks(self, token, csrf, workspace_id, fmt, status=None, request_id=None):
        wid = as_uuid(workspace_id)
        if fmt not in ('csv', 'json'):
            raise AclError(422, 'Invalid format')
        if status is not None and status not in STATUSES:
            raise AclError(422, 'Invalid status')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            if not _grant_ok(c, s, u['id'], wid, 'export'):  # raises 403 when the grant exists but MFA is stale
                if membership(c, u['id'], wid) is None:
                    raise _not_found()
                raise _forbidden()
            visible = []
            for task in execute(c, '''SELECT * FROM task_ayuza.tasks WHERE workspace_id=:w AND archived_at IS NULL
                AND (CAST(:st AS text) IS NULL OR status=CAST(:st AS text)) ORDER BY id''', w=wid, st=status).mappings().all():
                if self._can(c, u, s, task, 'read'):
                    visible.append(task)
                    if len(visible) > self.EXPORT_LIMIT:
                        raise AclError(422, 'Export is too large')
            if fmt == 'csv':
                buffer = io.StringIO()
                writer = csv.writer(buffer, lineterminator='\r\n')
                writer.writerow(COLUMNS)
                for task in visible:
                    writer.writerow([safe_cell(task[name]) for name in COLUMNS])
                content = '﻿' + buffer.getvalue()
            else:
                content = json.dumps([{name: (task[name].isoformat() if hasattr(task[name], 'isoformat')
                                              else (str(task[name]) if task[name] is not None else None))
                                       for name in COLUMNS} for task in visible], ensure_ascii=False)
            eid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.export_events (id, actor_id, workspace_id, format, filters, row_count, request_id)
                VALUES (:id, :a, :w, :f, CAST(:filters AS jsonb), :n, :r)''',
                    id=eid, a=u['id'], w=wid, f=fmt, filters=json.dumps({'status': status} if status else {}),
                    n=len(visible), r=request_id)
            audit(c, u, s, request_id=request_id, entity_kind='export', entity_id=eid, action='export.completed',
                  workspace_id=wid, old=None, new={'fields': ['export']})
            return {'event_id': eid, 'format': fmt, 'row_count': len(visible), 'content': content}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)
