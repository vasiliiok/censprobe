# Contributing

Этот гайд для разработки **самого** censprobe (не для контрибуции отчётов — про это в [`README.md`](../README.md)). Описывает локальный запуск тестов, ожидания CI и правила поддержания quality bar.

Связанные документы:
- [`TESTING.md`](TESTING.md) — методология тестирования (layer cake, инструменты, anti-patterns).
- [`TEST_COVERAGE.md`](TEST_COVERAGE.md) — конкретное покрытие: какой тест-файл какой src-модуль покрывает + полный список CI quality gates.

## Локальная установка

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e packages/probe-core[test] \
            -e packages/solo[test] \
            -e packages/listener[test] \
            -e packages/client[test] \
            -e packages/dashboard/sync-api[test] \
            -e .[dev]
pre-commit install --hook-type pre-commit --hook-type pre-push
```

`-e` важно: пакеты ссылаются друг на друга через `from censprobe_core import ...`, без editable install импорты не разрешатся.

## Запуск тестов

```bash
# Весь suite, исключая e2e/network/needs_*
pytest

# Один пакет
pytest packages/probe-core/tests

# Только integration (требует Postgres — поднимется через testcontainers)
pytest -m integration

# С coverage в терминал
pytest --cov --cov-report=term-missing
```

Маркеры:

| Маркер | Когда запускается |
|---|---|
| (без маркера) | каждый push/PR (CI job `test`, matrix per-package) |
| `integration` | каждый push/PR, отдельный setup (Postgres `services:` в matrix `test (sync-api)`) |
| `e2e` | каждый push/PR (CI job `e2e-dashboard`, билдит sync-api локально + `docker compose up postgres + sync-api`) |
| `network` | каждый push/PR (CI job `network-tests`; placeholder, exit-code 5 → pass пока тестов нет) |
| `needs_wg`, `needs_xray` | только если соответствующий бинарь установлен (локально) |

## Что должно быть зелёным перед `git push`

`pre-commit` пишет за вас:
- `ruff check` + `ruff format`
- `yamllint`, `gitleaks`, `actionlint`
- `mypy` (на pre-push)
- Pydantic-валидация `targets/*.yaml` и `censprobe.yaml`

Вручную полезно перед PR:

```bash
pytest                         # < 1 мин
ruff check . && ruff format --check .
mypy packages/probe-core/src packages/solo/src packages/listener/src \
     packages/client/src packages/dashboard/sync-api/src   # все strict
```

## Что проверяет CI

Все required для merge — в `ci.yml`. Nightly workflow удалён: всё, что в нём раньше жило (network-tests, e2e-dashboard, trivy-fs), переехало в `ci.yml` и теперь блокирует merge на каждый push/PR. Image-registry CVE сканирование (`outtakes/*:main`) снято.

```
ci.yml (каждый push в любую ветку + каждый PR в main)
  lint                              ruff + yamllint + actionlint + hadolint + mypy strict
  validate-config                   pydantic-load censprobe.yaml + targets/*.yaml
  test (×5 пакетов matrix)          per-package pytest --cov, postgres services
  cross-package-tests               pytest tests/contracts tests/snapshots
  network-tests                     pytest -m network (placeholder, 0 тестов сейчас)
  e2e-dashboard                     local sync-api build + docker compose up + pytest -m e2e
  security-fast                     bandit + pip-audit + gitleaks + dep-review + trivy-fs SARIF
  sonar                             SonarCloud Quality Gate (Sonar way)

build.yml (workflow_run после CI на main, + tag push, + PR)
  4 образа: solo / listener / client / sync-api
  - PR: build с push: false (review feedback)
  - main: build + push в Docker Hub. Push разрешён, если ВСЕ CI-job-ы
    зелёные ИЛИ упал только `SonarCloud` (Quality Gate `new_coverage`
    на free-плане не отключаемая, см. TESTING.md preamble).
  - image gates: non-root (sync-api only), size budget (250-600 MB)

codeql.yml (informational, weekly Mon 04:00 UTC)
  CodeQL Python security-and-quality
```

`test` job запускается с реальным Postgres `services:` для `dashboard/sync-api`. Остальные пакеты — без БД.

`sonar` Quality Gate смотрит **только на новый код PR**: coverage ≥ 70%, no new code smells/security hotspots, дубли ≤ 3%. Legacy long tail не блокирует merge.

`build.yml` триггерится через `workflow_run` от `ci.yml` — broken CI никогда не пушит образ. PR-сборка идёт параллельно с CI с `push: false` для быстрой обратной связи.

Push в feature/develop ветку (без открытого PR) **тоже** прогоняет полный CI — поломку видно сразу, не ждёте PR. Форки гейтятся через `if: github.repository == 'vasiliiok/censprobe'` на job-ах, которым нужны org secrets (`security-fast`, `sonar`).

## Правила добавления кода

### Новый модуль = новый тест-файл

При добавлении модуля в `packages/<pkg>/src/...` создайте парный `tests/unit/test_<module>.py` минимум с двумя сценариями:

- **OK-путь** — happy path, всё штатно.
- **BLOCKED-/error-путь** — что происходит при некорректном входе или сбое зависимости.

Один сценарий мало: модель «всё либо работает, либо я не покрыл код» вырождается в зелёный suite, который ничего не проверяет.

### Глобальные синглтоны

Не вводите новые. Существующие (`_CONFIG` в probe-core, `_DOH_CLIENT` в `modules/dns.py`, и т. д.) — наследие и закрыты autouse-фикстурами в `conftest.py`. Если очень нужен модульный кэш — пишите autouse-фикстуру сразу, не оставляйте на потом.

### Mypy strict

Все `src/`-модули во всех 5 пакетах прогоняются под `[[tool.mypy.overrides]] strict = true`. CI-шаг — одна команда:

```bash
mypy packages/probe-core/src packages/solo/src packages/listener/src \
     packages/client/src packages/dashboard/sync-api/src
```

При добавлении нового модуля — добавляйте strict-override сразу. Workspace-level `strict = false` сохранён только потому, что тесты содержат типичные pytest-fixture патерны (Any-bleed через mocker/AsyncMock), которые под strict шумят без пользы. Не возвращайте `strict = true` на корне до того, как `tests/` тоже подчищены.

### Subcategories и Grafana

Если меняете `subcategories.derive` или добавляете новый source name — прогоните `pytest tests/contracts/test_subcategories_contract.py`. Этот тест проверяет, что все subcategory, на которые опираются Grafana SQL-фильтры, остаются достижимыми. Без этого теста переименование subcategory незаметно превращает половину панелей в пустые.

### YAML targets

Любой новый `targets/*.yaml` должен пройти `python -c "from censprobe_core.targets import load_targets; load_targets(Path('targets'))"` без warning'ов. CI-job `validate-config` промотит warning до failure. Это защита от опечаток, которые `load_targets` иначе тихо проглатывает.

### Wire-format и snapshot'ы

Любые изменения в:
- MTProto frame (`modules/telegram.py`)
- QUIC version-negotiation trigger (`modules/cloudflare.py`)
- WireGuard handshake-init (`modules/cloudflare.py`)
- AmneziaWG magic headers (`listener/credentials.py`)

— перетряхивают `tests/snapshots/` baseline'ы, потому что байты меняются. Если изменение **намеренное**, перегенерируйте snapshot:

```bash
pytest tests/snapshots/ --regen-all
```

И **внимательно** прочитайте diff перед коммитом. Snapshot-тест — последний рубеж против случайной перегруппировки байтов, незаметной для type checker и unit-тестов, но рушащей wire-compat.

## Работа с CI

- **Failing job — не значит баг в вашем коде.** Trivy ловит CVE из upstream-фидов (трактуется как informational через `exit-code: 0` + SARIF, не блокирует merge); SonarCloud периодически меняет правила. Сначала разберитесь, что именно красное.
- **`SonarCloud` job хронически красный** из-за coverage Quality Gate (free-tier не позволяет опустить порог 80%). Это известная ситуация — `build.yml` пушит образы и при failure-конклюзии CI, если упал только sonar (см. TESTING.md preamble). Но если PR-reviewer хочет понять, сколько новой строки покрыто — отчёт лежит в самом sonar-job-е.
- **PR build идёт параллельно с CI.** Это by design — reviewer-у видны и тесты, и собирающиеся образы одновременно.
- **`e2e-dashboard` — самый медленный required job (~3 мин).** Если хотите сэкономить — пропихните мелкие правки серией коммитов в один и тот же PR; CI отменяет предыдущие run-ы того же ref.
- **Force-push в main запрещён** branch protection'ом. Срочный hotfix → отдельный PR.

## Когда что-то ломается

| Симптом | Куда смотреть |
|---|---|
| `pytest` пропускает все тесты сразу | проверьте, что вы в venv (`which pytest` → `.venv/bin/pytest`) |
| Integration-тесты висят | свободен ли порт 5432? testcontainers переиспользует `docker ps` |
| `mypy` ругается на `pydantic.mypy` | `pip install pydantic>=2.7` (плагин подтягивается из основной зависимости) |
| `pre-commit` бесконечно качает hooks | `pre-commit clean && pre-commit install --install-hooks` |
| `validate-config` job красный, локально не воспроизводится | проверьте `targets/*.yaml` — warning от `load_targets()` промотится в CI |

## Что почитать ещё

- [`README.md`](../README.md) — обзор проекта, как запустить, configuration reference, дашборд.
- [`TESTING.md`](TESTING.md) — методология тестирования: layer cake, инструменты (respx, pytest-mock, freezegun, hypothesis, testcontainers), стратегии изоляции глобалов, anti-patterns.
- [`TEST_COVERAGE.md`](TEST_COVERAGE.md) — карта тестов: какой test-файл покрывает какой src-модуль; gap analysis; полный список CI quality gates с конфигурацией tooling'а.
