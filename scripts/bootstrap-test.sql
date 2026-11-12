-- Run ONLY as a privileged test-cluster administrator, on a new empty task_ayuza_test DB.
-- CREATE DATABASE task_ayuza_test separately. Do not run on production.
-- Credentials are assigned out-of-band; roles initially have no passwords.
REVOKE ALL ON DATABASE task_ayuza_test FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE ROLE task_ayuza_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE task_ayuza_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE task_ayuza_backup LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT CONNECT ON DATABASE task_ayuza_test TO task_ayuza_migrator, task_ayuza_runtime, task_ayuza_backup;
CREATE SCHEMA task_ayuza AUTHORIZATION task_ayuza_migrator;
GRANT USAGE ON SCHEMA task_ayuza TO task_ayuza_runtime, task_ayuza_backup;
-- Importantly, runtime/backup do not receive CREATE on any usable schema.
