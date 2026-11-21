# Task-Ayuza | Статус
Срез STATUS-22 от 21.11.2026 (МСК). Проверенный интегрированный `main`: `676330ac54a5c685609a47faf6609f573aadcbe9`. Управление проектом передано владельцем Claude (20-21.11.2026); основной исполнитель по AGENTS остаётся Codex, Claude выполняет задачи по явной передаче в Issue/PR.

## Интегрированные факты на проверенном main
- M01.1 интегрирован (PR #1/#5): PostgreSQL/Alembic, organization, append-only аудит, роли БД, проверка схемы. Исторический отчёт: [M01-1-RESULTS.md](docs/M01-1-RESULTS.md).
- Оптимизация контекста v1.2 интегрирована PR #7; STATUS-7-1 — PR #9.
- **M01.2 (авторизация B1–B2) интегрирована** через [PR #11](https://github.com/Ivankorytnik/Task-Ayuza/pull/11), merge commit `bd956cee6d1a834802114148d52c4cac06350369` от 20.11.2026. HEAD PR: `20731296fa65c0864466f2a2e1e911a59f7d4fc7`; [Issue #10](https://github.com/Ivankorytnik/Task-Ayuza/issues/10) закрыт (completed).
- **PR #16** (синхронизация статуса) влит. **PR #18 (CI-LOCAL-1)** влит: GitHub Actions (`.github/workflows/ci.yml`: тесты демо, acceptance M01 на одноразовом PostgreSQL, проверка локального стека), локальный запуск (`docker-compose.yml`, `scripts/local_init.py`, `scripts/run-local.ps1`, Caddy на `https://localhost:8443`), в `requirements-m01.txt` добавлены argon2-cffi и httpx. CI на HEAD PR: demo, backend, local-stack = success; `docker compose up` в среде разработки не выполнялся.
- **PR #13 (DEMO-MVP-1)** влит: статический PWA-демо в `demo/`, синтетические данные, 30 логических проверок. Демо не заменяет серверную реализацию и не является приёмкой F01-F37.
- В `main` присутствует `migrations/versions/0002_m01_auth.py`. Включены users/sessions, Argon2id, временные пароли, cookie/CSRF, PostgreSQL login/IP/prelogin limiter, отзыв сессий и атомарный аудит. Публичных административных операций нет.
- **M01.3 (ACL, пространства и команды) интегрирована** через [PR #22](https://github.com/Ivankorytnik/Task-Ayuza/pull/22) (Issue реализации #21), squash merge commit `676330ac54a5c685609a47faf6609f573aadcbe9`. Миграция `0003_m01_acl` (workspaces, teams, workspace_members, team_members, workspace_teams, workspace_team_access, system_role_assignments, расширение аудита), внутренний сервис `backend/acl.py` без HTTP-маршрутов. CI на HEAD PR (66a35bb), два прогона: backend 66 passed, 0 skipped на PostgreSQL 16.16, local-stack и demo success; после merge CI на `main` зелёный. Независимого ревью не было, обзор diff выполнил автор.
- Отложено, не принято: project/task ACL (нет таблиц, M02); MFA, administrative_grants, bootstrap первого системного администратора и администратора пространства, делегирование assign/archive_restore/manage_access/export, публичный административный API (M01.4); операции архивации пространства и деактивации команды. Системные роли и первый администратор пространства в M01.3 заводятся только вне приложения (runtime не может их выдать).
- M01.4 не реализована. F01–F37 не приняты.

## Доказательства приёмки и пределы
- Независимый [TEST-10-PG-RUN](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7043206921) (предыдущий исполнитель Claude Code, 20.11.2026): новый одноразовый PostgreSQL 16.15, `127.0.0.1`, непривилегированный пользователь, синтетика. Исполняемый код на `f649e29eab420367ab567d1a8ce35772d93966a4`: A01–A09 и **50 passed / 0 failed / 0 skipped**, пять повторов без флаки, шесть независимых проб; A10 проверена статически. Отдельный исторический прогон PostgreSQL 17.11 с **45 passed** относится к реализации до FIX-10-1 и не считается подтверждением актуальной M01.2.
- [OWNER-MERGE-10-DECISION](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7044040015) подтвердил эквивалентность кода проверенному (`ast.dump` для трёх файлов после удаления лишних конечных переводов строки), `git diff --check` rc=0 и отсутствие конфликтов; владелец отдельно принял PG-приёмку взамен CI и разрешил merge. Интеграционные тесты на итоговом HEAD `20731296…` и merge commit **не перезапускались**; эти результаты не выдаются за CI PASS.
- На merge commit `bd956cee…` CI не было. С PR #18 CI запускается на каждом PR и push в `main`; обязательной защитой ветки он становится только после включения branch protection владельцем.
- Независимое [REVIEW-10-FINAL](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7043481155): **GO для Ready, NO-GO для production**. Merge разрешён и выполнен только для интеграции кода, не для публикации/эксплуатации.
- Реальная инфраструктура и рабочие данные не использовались. Merge не изменял ТЗ 2.2, D01–D06, 0001 и бизнес-логику. Полный журнал разработки/приёмки — [M01-2-RESULTS.md](docs/M01-2-RESULTS.md).

## Открытые production-гейты — NO-GO
- Явный предел конкурентных Argon2id (семафор/fail-fast 503), бюджет памяти по workers, политика IPv6 /64, доверенный reverse proxy и корректный источник IP; нагрузочная проверка без ослабления Argon2id.
- Лимитирование и аудит неверного `current_password` при смене пароля; браузерная/PWA-проверка prelogin GET/Referer, включая разные вкладки и реальные устройства.
- аудит транзитивных зависимостей; целевые PostgreSQL/нагрузочные испытания, MFA/ACL, TLS, настройка cleanup, backup/restore и подтверждение размещения сервера и данных в РФ.
- До отдельного допуска **деплой, production, реальные данные и платные операции запрещены**. Текущий статус production: **NO-GO**.

## Единственная карточка следующей задачи
**ID: M01.4.** MFA/TOTP, первичная настройка владельцем, независимое одобрение, administrative_grants только на пространства, выдача и отзыв, защищённое управление членствами и системными ролями, открытие административного API только после этого. Основание: docs/M01-CODEX-TASK.md §§1/4/5, docs/DATA-MODEL-ACCESS-2.2.md §§2.1/4/9 (D03), docs/TZ-2.2.md §15.
- Отдельный Issue, ветка от свежего `main`, один PR, миграция 0004 после 0003, без изменения 0001-0003; без обхода D03.
- Каждая приёмка подтверждается тестами в CI; отложенное помечается deferred, а не PASS.
- Без деплоя, production, реальных данных и платных операций.
