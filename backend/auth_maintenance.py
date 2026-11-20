"""Explicit maintenance command; schedule only during authorized deployment.

Run: python -m backend.auth_maintenance
No startup migrations and no audit deletion. Reads the runtime DSN explicitly.
"""
from backend.auth import AuthService
from backend.db import make_engine, verify_schema
import os


def main():
    engine=make_engine()
    try:
        verify_schema(engine)
        key=bytes.fromhex(os.environ.get('TASK_AYUZA_AUTH_HMAC_KEY',''))
        AuthService(engine,key).cleanup()
    finally:
        engine.dispose()


if __name__=='__main__':
    main()
