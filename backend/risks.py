"""M04.2 internal service: platform risk center (TZ 11). No HTTP.

Access is by system role only (risk_controller or system_admin); it is a separate area that never inherits
task rights, and a link to a task or blocker neither gives the task's users any risk access nor opens the
task to the risk controller: each side is read by its own rights. Writes need a fresh MFA (D03).

The traffic light never defaults to green: no check is gray, only a passing human or system check with
evidence and an expiry is green, an expired confirmation shows as yellow, a critical result is red.
An automatic system check never declares legal or personal data compliance proven (stays yellow).
risk_checks is append-only. Audit snapshots hold identifiers and field names only, never risk text.
"""
from __future__ import annotations

import uuid

from backend.acl import AclError, _not_found, as_uuid, audit, check_version, clean_text, has_system_role
from backend.auth import clock, execute, one
from backend.mfa import mfa_fresh
from backend.notifications import NotificationsService
from backend.work import _date

CATEGORIES = frozenset({'legal', 'personal_data', 'cybersecurity', 'access', 'availability', 'database', 'backup',
                        'quality', 'release', 'organizational', 'other'})
LEGAL_CATEGORIES = frozenset({'legal', 'personal_data'})
RISK_FIELDS = frozenset({'category', 'description', 'probability', 'impact', 'owner_user_id', 'owner_team_id',
                         'measures', 'due_date'})
RESULTS = {'pass': 'green', 'fail': 'yellow', 'critical': 'red'}


def severity_of(probability, impact):
    score = probability * impact
    return 'low' if score <= 4 else 'medium' if score <= 9 else 'high' if score <= 16 else 'critical'


def _scale(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise AclError(422, 'Invalid value')
    return value


class RisksService(NotificationsService):
    def _risk_actor(self, c, u, s, write):
        if not (has_system_role(c, u['id'], 'risk_controller') or has_system_role(c, u['id'], 'system_admin')):
            raise _not_found()                      # the area is hidden from everyone else
        if write and not mfa_fresh(c, s):
            raise AclError(403, 'MFA required')

    def _risk(self, c, risk_id, lock=False):
        risk = one(c, f'SELECT * FROM task_ayuza.risk_register WHERE id=:id{" FOR UPDATE" if lock else ""}', id=risk_id)
        if risk is None:
            raise _not_found()
        return risk

    def _check_owner(self, c, u, user_id, team_id):
        if user_id is None and team_id is None:
            raise AclError(422, 'A risk owner is required')
        if user_id is not None and one(c, 'SELECT 1 AS x FROM task_ayuza.users WHERE id=:id AND organization_id=:o AND active',
                                       id=user_id, o=u['organization_id']) is None:
            raise AclError(422, 'Owner is not available')
        if team_id is not None and one(c, 'SELECT 1 AS x FROM task_ayuza.teams WHERE id=:id AND organization_id=:o AND active',
                                       id=team_id, o=u['organization_id']) is None:
            raise AclError(422, 'Owner team is not available')

    def _effective(self, c, risk):
        view = dict(risk)
        if view['control_status'] == 'green':
            check = one(c, 'SELECT valid_until FROM task_ayuza.risk_checks WHERE id=:id', id=view['last_check_id'])
            if check is None or check['valid_until'] is None or check['valid_until'] <= clock(c):
                view['control_status'] = 'yellow'   # an expired confirmation is never shown as green
        return view

    # ------------------------------------------------------------------ register

    def create_risk(self, token, csrf, category, description, probability, impact, owner_user_id=None,
                    owner_team_id=None, measures='', due_date=None, request_id=None):
        if category not in CATEGORIES:
            raise AclError(422, 'Invalid category')
        description = clean_text(description, 2000)
        probability, impact = _scale(probability), _scale(impact)
        if not isinstance(measures, str) or len(measures) > 5000:
            raise AclError(422, 'Invalid value')
        owner = as_uuid(owner_user_id) if owner_user_id is not None else None
        team = as_uuid(owner_team_id) if owner_team_id is not None else None
        due = _date(due_date)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            self._check_owner(c, u, owner, team)
            rid = uuid.uuid4()
            execute(c, '''INSERT INTO task_ayuza.risk_register (id, category, description, probability, impact, severity,
                    owner_user_id, owner_team_id, measures, due_date, created_by)
                VALUES (:id, :cat, :d, :p, :i, :sev, :ou, :ot, :m, :due, :u)''',
                    id=rid, cat=category, d=description, p=probability, i=impact, sev=severity_of(probability, impact),
                    ou=owner, ot=team, m=measures, due=due, u=u['id'])
            audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=rid, action='risk.created',
                  old=None, new={'active': True})
            return {'id': rid, 'version': 1, 'control_status': 'gray'}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def update_risk(self, token, csrf, risk_id, expected_version, changes, request_id=None):
        rid, expected = as_uuid(risk_id), check_version(expected_version)
        if not isinstance(changes, dict) or not changes or set(changes) - RISK_FIELDS:
            raise AclError(422, 'Invalid fields')
        values = {}
        for name, value in changes.items():
            if name == 'category':
                if value not in CATEGORIES:
                    raise AclError(422, 'Invalid category')
                values[name] = value
            elif name == 'description':
                values[name] = clean_text(value, 2000)
            elif name in ('probability', 'impact'):
                values[name] = _scale(value)
            elif name == 'measures':
                if not isinstance(value, str) or len(value) > 5000:
                    raise AclError(422, 'Invalid value')
                values[name] = value
            elif name == 'due_date':
                values[name] = _date(value)
            else:
                values[name] = as_uuid(value) if value is not None else None
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            risk = self._risk(c, rid, lock=True)
            if risk['archived_at'] is not None:
                raise AclError(409, 'Risk is archived')
            if all(risk[k] == v for k, v in values.items()):
                return {'id': rid, 'version': risk['version'], 'changed': False}
            if expected is None or expected != risk['version']:
                raise AclError(409, 'Version conflict')
            self._check_owner(c, u, values.get('owner_user_id', risk['owner_user_id']),
                              values.get('owner_team_id', risk['owner_team_id']))
            values['severity'] = severity_of(values.get('probability', risk['probability']),
                                             values.get('impact', risk['impact']))
            sets = ', '.join(f'{k}=:v_{k}' for k in values)
            row = one(c, f'''UPDATE task_ayuza.risk_register SET {sets}, version=version+1, updated_at=clock_timestamp()
                WHERE id=:id AND version=:version RETURNING version''', id=rid, version=expected,
                      **{f'v_{k}': v for k, v in values.items()})
            if row is None:
                raise AclError(409, 'Version conflict')
            audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=rid, action='risk.updated',
                  old=None, new={'fields': sorted(set(values) - {'severity'})})
            return {'id': rid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_risk_archived(self, token, csrf, risk_id, archived, expected_version, request_id=None):
        rid, expected = as_uuid(risk_id), check_version(expected_version)
        if not isinstance(archived, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            risk = self._risk(c, rid, lock=True)
            if (risk['archived_at'] is not None) == archived:
                return {'id': rid, 'version': risk['version'], 'changed': False}
            if expected is None or expected != risk['version']:
                raise AclError(409, 'Version conflict')
            row = one(c, '''UPDATE task_ayuza.risk_register SET archived_at = CASE WHEN :a THEN clock_timestamp() ELSE NULL END,
                version=version+1, updated_at=clock_timestamp() WHERE id=:id AND version=:v RETURNING version''',
                      a=archived, id=rid, v=expected)
            audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=rid,
                  action='risk.archived' if archived else 'risk.restored', old=None, new={'archived': archived})
            return {'id': rid, 'version': row['version'], 'changed': True}
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def get_risk(self, token, risk_id):
        rid = as_uuid(risk_id)

        def run(c, u, s):
            self._risk_actor(c, u, s, False)
            return self._effective(c, self._risk(c, rid))
        return self.auth.protected(token, run)

    def list_risks(self, token, control_status=None, include_archived=False, limit=50, after=None):
        if control_status not in (None, 'gray', 'green', 'yellow', 'red'):
            raise AclError(422, 'Invalid status')
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise AclError(422, 'Invalid limit')
        after = as_uuid(after) if after else None

        def run(c, u, s):
            self._risk_actor(c, u, s, False)
            rows = execute(c, '''SELECT * FROM task_ayuza.risk_register
                WHERE (CAST(:inc AS boolean) OR archived_at IS NULL) AND (CAST(:after AS uuid) IS NULL OR id > CAST(:after AS uuid))
                ORDER BY id''', inc=bool(include_archived), after=after).mappings().all()
            views = [self._effective(c, r) for r in rows]
            return [v for v in views if control_status is None or v['control_status'] == control_status][:limit]
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ checks (append-only)

    def _apply_check(self, c, risk, result, system):
        status = RESULTS[result]
        if status == 'green' and system and risk['category'] in LEGAL_CATEGORIES:
            status = 'yellow'      # no automatic proof of legal or personal data compliance
        return status

    def _insert_check(self, c, risk, *, user_id, code, result, evidence, valid_until):
        if result not in RESULTS:
            raise AclError(422, 'Invalid result')
        if evidence is not None and (not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 500):
            raise AclError(422, 'Invalid evidence')
        if result == 'pass':
            if evidence is None or valid_until is None:
                raise AclError(422, 'A passing check needs evidence and an expiry')
            if one(c, 'SELECT 1 AS x WHERE CAST(:v AS timestamptz) > clock_timestamp()', v=valid_until) is None:
                raise AclError(422, 'Expiry must be in the future')
        cid = uuid.uuid4()
        execute(c, '''INSERT INTO task_ayuza.risk_checks (id, risk_id, checker_user_id, system_check_code, result,
                evidence_reference, valid_until, severity)
            VALUES (:id, :r, :u, :code, :res, :ev, CAST(:vu AS timestamptz), :sev)''',
                id=cid, r=risk['id'], u=user_id, code=code, res=result, ev=evidence, vu=valid_until, sev=risk['severity'])
        status = self._apply_check(c, risk, result, user_id is None)
        row = one(c, '''UPDATE task_ayuza.risk_register SET control_status=:st, last_check_id=:cid, version=version+1,
            updated_at=clock_timestamp() WHERE id=:id RETURNING version''', st=status, cid=cid, id=risk['id'])
        return {'id': cid, 'control_status': status, 'risk_version': row['version']}

    def record_check(self, token, csrf, risk_id, result, evidence_reference=None, valid_until=None, request_id=None):
        rid = as_uuid(risk_id)
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            risk = self._risk(c, rid, lock=True)
            if risk['archived_at'] is not None:
                raise AclError(409, 'Risk is archived')
            out = self._insert_check(c, risk, user_id=u['id'], code=None, result=result,
                                     evidence=evidence_reference, valid_until=valid_until)
            audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=rid, action='risk.check_recorded',
                  old=None, new={'fields': ['check']})
            return out
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def record_system_check(self, risk_id, system_check_code, result, evidence_reference=None, valid_until=None):
        """Identified local automatic check (a job, not a person). The immutable check row is its record."""
        rid = as_uuid(risk_id)
        if not isinstance(system_check_code, str) or not system_check_code:
            raise AclError(422, 'Invalid check code')

        def run(c):
            risk = self._risk(c, rid, lock=True)
            if risk['archived_at'] is not None:
                raise AclError(409, 'Risk is archived')
            return self._insert_check(c, risk, user_id=None, code=system_check_code, result=result,
                                      evidence=evidence_reference, valid_until=valid_until)
        return self.auth.transaction(run)

    def list_checks(self, token, risk_id):
        rid = as_uuid(risk_id)

        def run(c, u, s):
            self._risk_actor(c, u, s, False)
            self._risk(c, rid)
            return [dict(r) for r in execute(c, 'SELECT * FROM task_ayuza.risk_checks WHERE risk_id=:r ORDER BY checked_at, id',
                                             r=rid).mappings().all()]
        return self.auth.protected(token, run)

    # ------------------------------------------------------------------ links to tasks and blockers

    def _link(self, c, u, s, request_id, risk, table, column, target_id, readable_task, add, action):
        existing = one(c, f'''SELECT id FROM task_ayuza.{table} WHERE risk_id=:r AND {column}=:t AND removed_at IS NULL FOR UPDATE''',
                       r=risk['id'], t=target_id)
        if add:
            if risk['archived_at'] is not None:
                raise AclError(409, 'Risk is archived')
            self._task_access(c, u, s, readable_task, 'read')   # the controller needs the target's own read right
            if existing is not None:
                return {'id': existing['id'], 'changed': False}
            lid = uuid.uuid4()
            execute(c, f'INSERT INTO task_ayuza.{table} (id, risk_id, {column}, created_by) VALUES (:id, :r, :t, :u)',
                    id=lid, r=risk['id'], t=target_id, u=u['id'])
            audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=risk['id'], action=action,
                  old=None, new={'active': True})
            return {'id': lid, 'changed': True}
        if existing is None:
            return {'id': None, 'changed': False}
        execute(c, f'UPDATE task_ayuza.{table} SET removed_at=clock_timestamp() WHERE id=:id', id=existing['id'])
        audit(c, u, s, request_id=request_id, entity_kind='risk', entity_id=risk['id'], action=action,
              old=None, new={'active': False})
        return {'id': existing['id'], 'changed': True}

    def set_risk_task_link(self, token, csrf, risk_id, task_id, linked, request_id=None):
        rid, tid = as_uuid(risk_id), as_uuid(task_id)
        if not isinstance(linked, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            risk = self._risk(c, rid, lock=True)
            task = self._task(c, tid)
            return self._link(c, u, s, request_id, risk, 'risk_task_links', 'task_id', tid, task, linked,
                              'risk.task_linked' if linked else 'risk.task_unlinked')
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def set_risk_blocker_link(self, token, csrf, risk_id, blocker_id, linked, request_id=None):
        rid, bid = as_uuid(risk_id), as_uuid(blocker_id)
        if not isinstance(linked, bool):
            raise AclError(422, 'Invalid value')
        request_id = as_uuid(request_id) if request_id else uuid.uuid4()

        def run(c, u, s):
            self._risk_actor(c, u, s, True)
            risk = self._risk(c, rid, lock=True)
            blocker = one(c, 'SELECT * FROM task_ayuza.blockers WHERE id=:id', id=bid)
            if blocker is None:
                raise _not_found()
            task = self._task(c, blocker['blocked_task_id'])
            return self._link(c, u, s, request_id, risk, 'risk_blocker_links', 'blocker_id', bid, task, linked,
                              'risk.blocker_linked' if linked else 'risk.blocker_unlinked')
        return self.auth.protected(token, run, csrf=csrf, mutation=True)

    def list_risk_links(self, token, risk_id):
        """Each side is shown by its own rights; the rest is only a counter (no id, title or status)."""
        rid = as_uuid(risk_id)

        def run(c, u, s):
            self._risk_actor(c, u, s, False)
            self._risk(c, rid)
            tasks, blockers, hidden_tasks, hidden_blockers = [], [], 0, 0
            for link in execute(c, 'SELECT * FROM task_ayuza.risk_task_links WHERE risk_id=:r AND removed_at IS NULL ORDER BY id',
                                r=rid).mappings().all():
                task = self._task(c, link['task_id'])
                if self._can(c, u, s, task, 'read'):
                    tasks.append({'task_id': task['id'], 'title': task['title'], 'status': task['status']})
                else:
                    hidden_tasks += 1
            for link in execute(c, 'SELECT * FROM task_ayuza.risk_blocker_links WHERE risk_id=:r AND removed_at IS NULL ORDER BY id',
                                r=rid).mappings().all():
                blocker = one(c, 'SELECT * FROM task_ayuza.blockers WHERE id=:id', id=link['blocker_id'])
                if self._can(c, u, s, self._task(c, blocker['blocked_task_id']), 'read'):
                    blockers.append({'blocker_id': blocker['id'], 'status': blocker['status'], 'title': blocker['title']})
                else:
                    hidden_blockers += 1
            return {'tasks': tasks, 'blockers': blockers, 'hidden_tasks': hidden_tasks, 'hidden_blockers': hidden_blockers}
        return self.auth.protected(token, run)
