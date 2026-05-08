# Методология тестирования

Этот документ описывает **подходы**, которые используются в тестовом наборе censprobe — какие виды проверок применяются, какими инструментами, на каких слоях и почему. Конкретный inventory «какой тест что покрывает» лежит в [`TEST_COVERAGE.md`](TEST_COVERAGE.md). Гайд по запуску тестов локально — в [`CONTRIBUTING.md`](CONTRIBUTING.md).

> ⚠️ **SonarCloud Quality Gate vs Docker Hub push.**
> SonarCloud Quality Gate `Sonar way` требует `new_coverage ≥ 80%`. Этот порог — настройка платного плана; на free-плане его нельзя опустить. Текущий overall coverage ≈40% (см. `TEST_COVERAGE.md`), поэтому `sonar` job в `ci.yml` **систематически красный** на любом PR, который не приносит сильно тестов больше, чем кода.
>
> Чтобы это не блокировало релизы, `build.yml` **разрешает push образов в Docker Hub при failure-конклюзии CI, если упал ровно `SonarCloud` и больше никто** (см. шаг `Check CI jobs status (allow sonar-only failure)` в начале build job-а). Любой другой red job (lint, test, security-fast, e2e-dashboard, …) по-прежнему хард-блокирует push. Это сознательный компромисс между «не платить Sonar за повышенный лимит организаций» и «образ всегда отражает последний green-кроме-coverage main».
>
> Когда test coverage добегает до 80% — убрать особый случай в `build.yml`, оставить только `conclusion == 'success'`.

---

## Цели и принципы

1. **Зелёный main всегда зелёный.** Каждый PR обязан проходить полный набор required-CI-checks (lint + validate-config + per-package pytest-matrix + cross-package-tests + network-tests + e2e-dashboard + security-fast + SonarCloud) до merge. Все они также прогоняются на каждый push в любую ветку. Не required-чеки (CodeQL — раз в неделю) — informational, дают сигнал, но не блокируют merge. Исключение по SonarCloud — см. предупреждение выше: его failure не блокирует Docker Hub push, но в required-checks ветки он формально остаётся (как сигнал для PR-reviewer-а).
2. **Тесты должны падать когда что-то реально сломалось.** Вакуумные ассерты (`assert True`, `assert x is not None` без последующей проверки), широкие `except Exception`, `xfail` без `strict=True`, моки которые «всегда возвращают OK» запрещены code-review'ом и SonarCloud правилами.
3. **Конфиг — последняя истина.** Тесты, как и продакшн-код, не должны вводить fallback-значения за `censprobe.yaml`. Если поле обязательно — пытайся его не задать и проверь, что код упадёт с ясным сообщением.
4. **Изоляция через autouse-фикстуры, а не через рефакторинг.** Глобалы (`_CONFIG`, DoH/ASN HTTP-клиенты, ASN кеш + backoff) сбрасываются в `conftest.py` каждого пакета. Это позволило не переписывать probe-core под DI и одновременно гарантировать, что один тест не «заражает» соседний.
5. **Реальное I/O маскируется на transport layer, а не на API уровне.** `respx.mock()` ловит httpx на уровне транспорта — и неважно, успел ли тест сбросить `_DOH_CLIENT` синглтон или нет. Аналогично `monkeypatch.setattr(asyncio, "open_connection", ...)` для прямых TCP-проб.

---

## Layer cake

Тесты распределены по 6 слоям с разными бюджетами по latency и I/O. **Все 6 слоёв прогоняются на каждый push (любая ветка) и на каждый PR против main**; разница между ними — в каком CI-job они исполняются и сколько занимают.

| Слой | Что покрывает | I/O | Скорость одного теста | Где запускается |
|------|---------------|-----|------------------------|------------------|
| **A. Pure unit** | `scoring`, `subcategories`, `models`, `validate_id`, `parser` (coercions, verdict-helpers, `_majority`, `_compute_health_score`), credentials format constraints, MTProto byte-frame, конфиг-валидация | нет | < 50 мс | CI job `test` (matrix) |
| **B. Mocked unit** | модули измерений (dns/tcp/tls/http/throttling/telegram/cloudflare/middlebox), `ProbeRunner`, `SubprocessResponder` lifecycle, `_fetch_credentials` | моки `httpx`/`asyncio.open_connection`/`subprocess` | < 200 мс | CI job `test` (matrix) |
| **C. Integration** | sync-api endpoints + Postgres, `_import_loop`, схема БД и cascade-deletes, импорт фикстурных JSON через всю pipeline | реальный Postgres (`services:` matrix) | < 10 с | CI job `test (sync-api)` |
| **D. Contracts / Snapshots** | subcategories ↔ Grafana SQL, `targets/*.yaml` валидируются `TargetFile`, JSON-схема солист/листенер отчётов, byte-signature пакетных билдеров | нет | < 100 мс | CI job `cross-package-tests` |
| **E. Property-based** | `validate_id`, `subcategories.derive`, AmneziaWG H1..H4 + S1+56≠S2 invariants, scoring ranges | нет | < 1 с | CI job `test` (matrix) |
| **F. E2E + network + needs_*** | `docker compose up postgres + sync-api → /health`, MTProto live, real DoH, протоколы которым нужны бинари (wg, xray) | docker / сеть | 30 с – 3 мин | CI jobs `e2e-dashboard` + `network-tests` (опт-ин по маркеру) |

Маркеры pytest, контролирующие что попадает в default-run:

```toml
addopts = "-m 'not e2e and not network and not needs_wg and not needs_xray'"
```

Этот фильтр действует на **локальный** `pytest` и на per-package job'ы в матрице — там e2e/network исключаются, чтобы matrix-job-ы оставались быстрыми. Маркеры явно опт-инятся в выделенных CI-job'ах:

- `e2e-dashboard` — `pytest tests/e2e/test_dashboard_stack.py -m e2e`. Билдит sync-api локально, поднимает postgres + sync-api через `docker compose -f docker-compose.yml -f tests/e2e/compose.test.yml`, проверяет `/health` + базовые endpoint-ы.
- `network-tests` — `pytest -m network`. Сейчас 0 тестов с этим маркером, exit-code 5 трактуется как pass; job оставлен под будущие live-MTProto / DoH / Cloudflare ECH тесты.
- `needs_wg`, `needs_xray` — локально, если `shutil.which("wg")` / `which("xray")` находит бинарь.

---

## Слой A — Pure unit

Без I/O, без сети, без подпроцессов. Большая часть «логических» функций censprobe — pure, и тесты их закрывают граничными случаями.

Примеры зон покрытия:

- **Скоринг** (`censprobe_core.scoring`): `_ok_pct` (empty list / all-OK / all-blocked / mixed), `_latency_to_score` (граница `<50/<100/<200/<500/>=500`), `_recommend_protocols` (приоритет, signature-blocked фильтр), `compute_scores` (listener fallback, веса суммой ≠1.0).
- **Subcategories** (`subcategories.derive`): все 4 уровня (prefix → suffix → substring → name override), unknown name → fallback.
- **Конфиг-валидация** (`config.ProtocolsConfig._check_ports_cover_enabled`): missing port для enabled-протокола, orphan port-entry, неправильный диапазон.
- **`validate_id`** (`utils.py`): `..`, `/`, `\x00`, U+200B, empty, max length — исключения с понятным сообщением.
- **MTProto frame** (`modules.telegram._test_dc_port`): байт-точная сверка `b"\xef" + bytes([len//4]) + struct.pack("<qqi", 0, msg_id, 4)`.
- **HTTP verdict** (`modules.http._verdict_from_response`): порядок проверок load-bearing — 200/403/451 + valid_tls → `GEOBLOCK_NOT_CENSORSHIP`, expected_status, body length.
- **Throttling Method-B** (`modules.throttling._decide_method_b_verdict`): trigger < 0.25 × min(correct, typo) → `YOUTUBE_SNI_THROTTLED`; vantage не RU/BY → `INCONCLUSIVE`; деление на ноль.
- **TCP attribution** (`modules.tcp._majority`, `modules.tls._attribute_tls_failure`): tie-breaker, all-error, single result.
- **AmneziaWG constraints** (`listener.credentials`): H1..H4 distinct + не 1..4, S1+56 ≠ S2.
- **`creds_to_yaml` round-trip** + **`parse_protocols_yaml` fail-loud**: каждое операционное поле обязательно (метод шифра, SNI, AWG-обфускация, ключи); пропуск → `ValueError` с понятным сообщением.

---

## Слой B — Mocked unit

I/O запретами выгрезает на уровне transport-layer mock'ов и `monkeypatch`.

### Инструменты

- **`respx`** (`>=0.21`) — для всех `httpx.AsyncClient` в dns/http/cloudflare/telegram. Перехватывает на transport layer, нивелирует риск утечки реальных HTTP-запросов даже при «забытом» сбросе синглтона.
- **`monkeypatch.setattr(asyncio, "open_connection", AsyncMock(...))`** — для tcp/tls/telegram DC/middlebox прямых соединений.
- **`mocker.patch("asyncio.create_subprocess_exec")`** (`pytest-mock>=3`) — для throttling (curl), responder lifecycle, генерации ключей `wg`/`xray`/`openvpn`.
- **`monkeypatch.setattr(dns, "_resolve_via", AsyncMock(return_value=[...]))`** — для DNS resolver-функций. Для DoT — мокаем `aiodns.DNSResolver`.
- **`freezegun.freeze_time`** (`>=1.5`) — для проверки timing-границ типа `fast_rst_threshold_ms`.

### Особо важные блоки

- **runner orchestration** (`runner.py`): `asyncio.gather(*tasks, return_exceptions=True)` действительно изолирует исключения. Тест specifically проверяет, что одна упавшая модуль не обрушит весь suite, а `module_failures` появляется в `_summarize`.
- **Cloudflare wire-format** (`modules.cloudflare`): byte-shape проверки для `_build_quic_vn_trigger`, `_build_masque_probe_packet`, `_build_wg_handshake_init`. Параллельно с этим в `tests/snapshots/test_wire_format_byte_snapshots.py` есть pytest-regressions snapshot — любая «невинная» перегруппировка байтов отлавливается.
- **Telegram health** (`modules.telegram._compute_health_score`, `_ok_ratio`): weighted-avg dc/web/cdn по `health_weights` из `targets/telegram.yaml`.
- **Owned-cert match** (`modules.telegram._match_owned_cert`, `_compile_owned_patterns`): RFC 6125 wildcard semantics — single label match, no embedded wildcards.

---

## Слой C — Integration

Поднимается **реальный Postgres 16-alpine** через GitHub Actions `services:` (в матрице `test` каждый раз). Локально fallback — `testcontainers[postgres]>=4`, который запускается из `conftest.py` если переменная `DATABASE_URL` пустая.

Что покрыто:

- **Endpoints** (`sync_api.main`): `GET /health`, `GET /test-runs`, `GET /test-runs/{id}`, `GET /results/{id}`, `GET /protocols/{id}`. Через `httpx.AsyncClient(transport=ASGITransport(app))` против реальной FastAPI-инстанции и реального коннекта к Postgres.
- **Import pipeline** (`sync_api.main._import_once`): disk reports → DB rows + UPSERT-by-session + path-traversal/symlink guards.
- **DB schema round-trip** (`sync_api.db`): `init_db()` создаёт все 4 таблицы; unique constraints (`uq_test_results_run_file_test_target`, `uq_listener_sessions_run_file`); cascade-delete: `TestRun` → `TestResult` + `ListenerSession` + `ProtocolResult`.

Конфигурация asyncio loop scope: `asyncio_default_fixture_loop_scope = "session"` + `asyncio_default_test_loop_scope = "session"` — единственный event loop через всю сессию, чтобы `asyncpg`-коннекты не теряли валидность между тестами.

---

## Слой D — Contracts + Snapshots

Контрактные тесты живут в **`tests/contracts/`** (workspace-level, кросс-пакетные).

### `test_subcategories_contract.py`

Самый высокоплечный тест в всей сюите.

1. Парсит все `packages/dashboard/grafana/dashboards/*.json`, regex'ом извлекает SQL-литералы вида `subcategory = 'X'` и `subcategory IN ('a', 'b')`.
2. Получает множество subcategory, на которых **держится Grafana**.
3. Для всех тестовых имён, генерируемых модулями (через registry), вызывает `subcategories.derive(name)`.
4. Assert: множество derive-результатов ⊇ множества Grafana-фильтров.

Без этого теста переименование одной subcategory в `subcategories.py` молча превращает половину панелей в пустые.

### `test_targets_yaml_validate.py`

Каждый `targets/*.yaml` парсится через `TargetFile`. `load_targets()` сейчас warn-only (логирует и пропускает битый YAML); CI-job `validate-config` уже промотит warning до failure, но контрактный тест дублирует это в pytest для локального воспроизведения.

### `test_censprobe_yaml_round_trip.py`

`load_config()` → `model_dump()` → `safe_dump` → `safe_load` → `model_validate` идентичность. Catches опечатки, которые pydantic пропустил бы (extra fields, mistyped enum values).

### Snapshots — `tests/snapshots/`

- **JSON Schema** (`test_report_schemas.py`): `model_json_schema()` от pydantic-моделей `TestResult` / `ListenerReport`, плюс `jsonschema.validate(...)` против фикстур (`tests/snapshots/fixtures/test_result_minimal.json`, `listener_report_minimal.json`). Регенерация — `CENSPROBE_REGENERATE_SCHEMAS=1 pytest tests/snapshots/`.
- **Wire-format snapshots** (`test_wire_format_byte_snapshots.py`): byte-точные снимки билдеров `_build_quic_vn_trigger`, `_build_wg_handshake_init`, `_build_masque_probe_packet`. Реализовано через `pytest-regressions.data_regression` — первый запуск коммитит baseline, далее сравнение побайтово. Любая перегруппировка байтов, незаметная для type checker и unit-тестов, но рушащая wire-compat, ловится здесь.

---

## Слой E — Property-based (Hypothesis)

Используется на 4 узких местах с большим ROI:

1. **`validate_id`** — strategy `text(alphabet=ascii_letters+digits+"_.-", min_size=1, max_size=64)` плюс контр-стратегии с `..`, `/`, `\x00`. Гейтит все filesystem paths и SQL keys.
2. **`subcategories.derive`** — для любого test_name результат должен быть непустым и принадлежать замкнутому множеству правил. Catches typos в новых правилах.
3. **AmneziaWG H1..H4 + S1/S2 constraints** — `@given(_seed=integers())` + сидируемая обёртка над `_awg_magic_headers`. С `@settings(max_examples=500)` тестирует все 4 инварианта (pairwise distinct, не в `{1,2,3,4}`, S1+56 ≠ S2). Детерминизм на 500 примерах обеспечивает hypothesis-профиль из conftest, см. ниже.
4. **Scoring ranges** — для произвольных списков results, `_ok_pct ∈ [0.0, 1.0]`, `_latency_to_score ∈ [0.0, 100.0]`, `_protocol_reachability ∈ [0.0, 1.0]`.

Детерминизм property-тестов **не пишется руками на каждом `@settings`**, а навязывается централизованно. `packages/probe-core/tests/conftest.py` и `packages/listener/tests/conftest.py` на верхнем уровне регистрируют и грузят hypothesis-профиль `censprobe-deterministic` (`derandomize=True`). Поскольку это происходит при импорте conftest — то есть до того, как `@settings(...)` decorator на тестовой функции исполнится, — все property-тесты в этих двух пакетах автоматически прогоняются на одном и том же sequence примеров на каждом CI runner-е. Не нужно помнить про `derandomize=True` в каждом новом тесте: добавил `@given/@settings`, и он уже детерминирован.

---

## Слой F — E2E + network + needs_*

### E2E (`pytest -m e2e`, CI job `e2e-dashboard`)

`tests/e2e/test_dashboard_stack.py`:
- CI-job сначала билдит sync-api локально через `docker/build-push-action@v7` под тегом `${DOCKERHUB_USERNAME}/censprobe-sync-api:${DOCKERHUB_TAG}` (env-vars выставлены на local-only sentinel'ы — `censprobe-ci/...:e2e-local`), чтобы тестировать **код этого же PR**, а не вчерашний `:main` из Docker Hub.
- `compose.test.yml` — минимальный overlay: только переезд порта 8080→18080, чтобы не конфликтовать с runner-ом. Postgres подтягивается digest-pinned из базового compose.
- `docker compose -f docker-compose.yml -f tests/e2e/compose.test.yml --profile dashboard up -d --wait postgres sync-api`.
- Assert: `/health` возвращает 200, schema migration отработала, `/test-runs/` отдаёт пустой список (или сидованные данные).
- На failure CI грузит `compose logs` артефактом для диагностики.

### Network (`pytest -m network`, CI job `network-tests`)

Закладка под live MTProto handshake, real DoH, Cloudflare ECH probes. Сейчас тестов с этим маркером нет — job обрабатывает exit-code 5 («no tests collected») как pass, но остаётся в workflow для будущих тестов.

### needs_wg / needs_xray

`@pytest.mark.needs_wg` / `@pytest.mark.needs_xray` — тесты, требующие реального бинаря. На default-runner'е GitHub Actions их нет, поэтому в `addopts` они скипаются. Локально включаются если бинарь установлен (`shutil.which("wg")`).

---

## Стратегии изоляции глобалов

Без рефакторинга на DI — текущих экспортов хватает.

| Глобал | Где | Стратегия |
|--------|-----|-----------|
| `_CONFIG` | `config.py:309` | autouse `loaded_config` в `packages/probe-core/tests/conftest.py`: `set_config(test_cfg)` setup → `reset_config()` teardown |
| `_DOH_CLIENT`, `_ASN_CLIENT` | `modules/dns.py:42-43` | autouse `reset_dns_globals` в `tests/modules/conftest.py`: `dns._DOH_CLIENT = None; dns._ASN_CLIENT = None`. Параллельно `respx.mock()` перехватывает на transport layer независимо от инстанса |
| `_ASN_CACHE`, `_ASN_BACKOFF_UNTIL` | `modules/dns.py:612-613` | тот же `reset_dns_globals`: `_ASN_CACHE.clear(); _ASN_BACKOFF_UNTIL = 0.0` |
| `set_vantage_country` | `server_meta.py:51` | фикстуры `vantage_ru` / `vantage_neutral` со своим teardown |
| Env vars (`IPAPI_IS_KEY`, `DATABASE_URL`) | global | `monkeypatch.setenv` per-test |

---

## Coverage targets

Координируется per-package. Steady-state цели после полного завершения Этапа 5 (см. план в `replicated-crafting-origami.md`):

| Пакет | Initial gate (новый код) | Steady-state |
|-------|--------------------------|--------------|
| `probe-core` (без `modules/`) | 70% / 60% branch | 90% / 80% |
| `probe-core/modules/` | 40% / 30% | 75% / 65% |
| `sync-api` | 60% / 50% | 85% / 75% |
| `listener` | 30% / 25% | 60% / 50% |
| `client` | 50% / 40% | 75% / 65% |
| `solo` | 50% / 40% | 75% / 65% |

`pytest --cov` per matrix-entry; `coverage-${slug}.xml` подгружается SonarCloud-job'ой и экспонируется через Quality Gate `Coverage on New Code`. Текущее состояние общего покрытия и план поэтапного роста — в [`TEST_COVERAGE.md`](TEST_COVERAGE.md).

---

## Quality gates за пределами pytest

Полный набор не-pytest проверок описан в [`TEST_COVERAGE.md`](TEST_COVERAGE.md). Кратко:

- **Static analysis**: `ruff check + ruff format --check` (E/F/W/B/I/UP/S), `mypy strict` (полный `packages/*/src` tree, 47 файлов), `bandit -ll` (Python security), `hadolint` (Dockerfile), `actionlint` (workflow YAML), `yamllint` (configuration YAML).
- **Dependency security**: `pip-audit` (PyPI vuln feed), `actions/dependency-review-action@v4` (PR-only, fail-on `high`), `gitleaks` (secret scanning, PR-diff и full history).
- **Configuration validation**: `validate-config` job — pydantic-load `censprobe.yaml` + `targets/*.yaml`; warn-уровень логи промотятся в errors. Pre-commit hook `validate-targets` дублирует это локально.
- **Container scanning** (`security-fast` job, push/PR): `aquasecurity/trivy-action` filesystem-scan (`scan-ref: .`, scanners `vuln,secret,config`, severity `HIGH,CRITICAL`, `exit-code: 0` — surfaced через SARIF, не блокирует merge на transient feed update). Image-registry scanning против опубликованных `outtakes/censprobe-*:main` снят вместе с удалением nightly. Image budgets enforced post-build в `build.yml` (`solo` ≤ 600 MB, `listener`/`client` ≤ 400 MB, `sync-api` ≤ 250 MB) + non-root verification для `sync-api`.
- **Static taint analysis** (weekly): GitHub CodeQL Python с `queries: security-and-quality`.
- **SonarCloud**: cognitive-complexity (S3776 < 15), unused params (S1172), security hotspots, новые bugs/code-smells на Quality Gate за «Sonar way».

---

## Что мы НЕ делаем (anti-patterns)

- **`xfail` без `strict=True`** — запрещено. `xfail` без strict превращает now-passing test в silent skip, регрессия незаметна.
- **Широкий `pytest.raises(Exception)`** — конкретный exception type только.
- **`assert_called_once()` без аргументов** — для проверки seamless mock-wiring достаточно, но если тест проверяет что probe вызвалась с правильными SNI/cfg — нужен `assert_called_once_with(...)` или `sentinel.call_args.args[0] is cfg.modules.X`.
- **Mocking обоих сторон взаимодействия** — например, мок энкодера И декодера: тест уже не может упасть. Для wire-format такого типа ровно противоположно — byte snapshot теста.
- **Глобальный `respx.mock(assert_all_called=False)` catch-all** — все respx-рутки имеют конкретные `route(...)` matcher'ы.

---

## Связанные документы

- [`README.md`](../README.md) — обзор проекта, configuration reference, dashboard.
- [`TEST_COVERAGE.md`](TEST_COVERAGE.md) — конкретный inventory: какой test-файл какой src-модуль покрывает + список CI quality gates.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — как запустить тесты локально, что должно быть зелёным перед `git push`, как добавить новый модуль/тест/протокол.
