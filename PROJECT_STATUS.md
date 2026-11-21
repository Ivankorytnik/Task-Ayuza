# Task-Ayuza | Статус
Срез POSTMERGE-10-SYNC от 20.11.2026 (МСК). Проверенный интегрированный `main`: `bd956cee6d1a834802114148d52c4cac06350369`.
Синхронизация предложена в [PR #16](https://github.com/Ivankorytnik/Task-Ayuza/pull/16) (ветка `docs/15-postmerge-10-sync`, Issue #15): на контрольном срезе PR в статусе Ready. До фактического merge эта редакция отсутствует в `main`; merge требует отдельного разрешения владельца.

## Интегрированные факты на проверенном main
- M01.1 интегрирован (PR #1/#5): PostgreSQL/Alembic, organization, append-only аудит, роли БД, проверка схемы. Исторический отчёт: [M01-1-RESULTS.md](docs/M01-1-RESULTS.md).
- Оптимизация контекста v1.2 интегрирована PR #7; STATUS-7-1 — PR #9.
- **M01.2 (авторизация B1–B2) интегрирована** через [PR #11](https://github.com/Ivankorytnik/Task-Ayuza/pull/11), merge commit `bd956cee6d1a834802114148d52c4cac06350369` от 20.11.2026. HEAD PR: `20731296fa65c0864466f2a2e1e911a59f7d4fc7`; [Issue #10](https://github.com/Ivankorytnik/Task-Ayuza/issues/10) закрыт (completed).
- В `main` присутствует `migrations/versions/0002_m01_auth.py`. Включены users/sessions, Argon2id, временные пароли, cookie/CSRF, PostgreSQL login/IP/prelogin limiter, отзыв сессий и атомарный аудит. Публичных административных операций нет.
- M01.3–M01.4 **не реализованы и не разрешены в рамках этой задачи**. F01–F37 не приняты. PR #13 — отдельный [Draft PWA-демо](https://github.com/Ivankorytnik/Task-Ayuza/pull/13), только `demo/`, не является интегрированным функционалом и не заменяет серверную реализацию.

## Доказательства приёмки и пределы
- Независимый [TEST-10-PG-RUN](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7043206921) (предыдущий исполнитель Claude Code, 20.11.2026): новый одноразовый PostgreSQL 16.15, `127.0.0.1`, непривилегированный пользователь, синтетика. Исполняемый код на `f649e29eab420367ab567d1a8ce35772d93966a4`: A01–A09 и **50 passed / 0 failed / 0 skipped**, пять повторов без флаки, шесть независимых проб; A10 проверена статически. Отдельный исторический прогон PostgreSQL 17.11 с **45 passed** относится к реализации до FIX-10-1 и не считается подтверждением актуальной M01.2.
- [OWNER-MERGE-10-DECISION](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7044040015) подтвердил эквивалентность кода проверенному (`ast.dump` для трёх файлов после удаления лишних конечных переводов строки), `git diff --check` rc=0 и отсутствие конфликтов; владелец отдельно принял PG-приёмку взамен CI и разрешил merge. Интеграционные тесты на итоговом HEAD `20731296…` и merge commit **не перезапускались**; эти результаты не выдаются за CI PASS.
- На merge commit `bd956cee…` GitHub API показал **0 check runs и 0 workflow runs**. Автоматизированная GitHub CI-приёмка отсутствует; дальнейшие изменения не защищены автоматически.
- Независимое [REVIEW-10-FINAL](https://github.com/Ivankorytnik/Task-Ayuza/pull/11#issuecomment-7043481155): **GO для Ready, NO-GO для production**. Merge разрешён и выполнен только для интеграции кода, не для публикации/эксплуатации.
- Реальная инфраструктура и рабочие данные не использовались. Merge не изменял ТЗ 2.2, D01–D06, 0001 и бизнес-логику. Полный журнал разработки/приёмки — [M01-2-RESULTS.md](docs/M01-2-RESULTS.md).

## Открытые production-гейты — NO-GO
- Явный предел конкурентных Argon2id (семафор/fail-fast 503), бюджет памяти по workers, политика IPv6 /64, доверенный reverse proxy и корректный источник IP; нагрузочная проверка без ослабления Argon2id.
- Лимитирование и аудит неверного `current_password` при смене пароля; браузерная/PWA-проверка prelogin GET/Referer, включая разные вкладки и реальные устройства.
- GitHub CI; аудит транзитивных зависимостей; целевые PostgreSQL/нагрузочные испытания, MFA/ACL, TLS, настройка cleanup, backup/restore и подтверждение размещения сервера и данных в РФ.
- До отдельного допуска **деплой, production, реальные данные и платные операции запрещены**. Текущий статус production: **NO-GO**.

## Единственная карточка следующей задачи
**ID: OWNER-DOC16-MERGE-DECISION (Issue #15, PR #16 Ready).** Отдельное решение владельца о документальном исключении отсутствующего CI и разрешении либо запрете merge.
- REVIEW-DOC-POSTMERGE-10-SYNC завершён: **GO**; результат READY-DOC-16 [зафиксирован в PR #16](https://github.com/Ivankorytnik/Task-Ayuza/pull/16#issuecomment-7044404577), PR переведён в Ready. Отсутствие CI (0 check runs) не означает CI PASS.
- Перед любым решением повторно сверить актуальные SHA `main` и HEAD, Ready, `mergeable_state=clean`, diff только из двух Markdown-файлов и отсутствие пересечений с PR #13. Без отдельного явного решения владельца по CI-исключению и merge — **MERGE HOLD**.
- Существующий [Issue #14](https://github.com/Ivankorytnik/Task-Ayuza/issues/14) — подготовительный gate M01.3, **не разрешение** реализации M01.3–M01.4. Не запускать этот этап в рамках карточки.
- Без изменения кода, миграций, тестов, бизнес-логики, без auto-merge, деплоя, production, платных операций и реальных данных.
