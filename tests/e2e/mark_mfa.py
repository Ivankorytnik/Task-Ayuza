"""E2E fixture only: marks the sessions of one synthetic user as freshly MFA-verified (the browser has no authenticator).
Usage: python tests/e2e/mark_mfa.py <user-id>. Same effect as mark_mfa in the acceptance tests."""
import os
import sys

from sqlalchemy import create_engine, text

url = 'postgresql+psycopg://task_ayuza_migrator:%s@%s:%s/task_ayuza_test' % (
    os.environ['TA_MIGRATOR_PW'], os.environ.get('TA_DB_HOST', '127.0.0.1'), os.environ.get('TA_DB_PORT', '5432'))
with create_engine(url, hide_parameters=True).begin() as c:
    c.execute(text('UPDATE task_ayuza.sessions SET mfa_verified_at = clock_timestamp() WHERE user_id = CAST(:u AS uuid)'), {'u': sys.argv[1]})
