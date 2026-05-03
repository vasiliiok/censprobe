# Censprobe

Censprobe — инструмент измерения цензуры и оценки устойчивости серверов к сетевым блокировкам в России. Автоматически проверяет достижимость публичных ресурсов с аплинка сервера, тестирует протоколы обхода цензуры через DPI и оценивает наличие троттлинга и SNI-блокировок.

Все тесты работают автономно через Docker Compose, а результаты сохраняются в `reports/<TEST_ID>/` локально — публикация в git-репозиторий выполняется вручную, и Grafana собирает дашборды из импортированных отчётов.

## Vantage (важно)

Часть атрибуции откалибрована **для RU-вантажа** — листенер/solo ожидают, что цензор находится в пути:
- `tcp.py` помечает быстрый RST как RST_INJECTED (только в RU; вне RU heuristic отключается, downgrade в REFUSED).
- `cloudflare.py` помечает QUIC-таймаут на UDP 443 как `QUIC_DROPPED` (только в RU).
- `throttling.py` (Method B против `speedtest.selectel.ru`) полностью пропускается вне RU — относительная разница bandwidth доминируется географией, а не SNI-policy.

Vantage определяется автоматически из `country_code` ipapi.is enrichment в `solo` и пробрасывается через `set_vantage_country()` в общий probe-core. Если запускаете solo с не-RU VM (Frankfurt, Vultr и т.д.), увидите большее количество INCONCLUSIVE-вердиктов в throttling/QUIC — это by design, не баг.

## Архитектура развертывания

Система состоит из 4 независимых компонентов (профилей Docker), запускаемых на разных машинах:

| Профиль | Где запускается | Назначение |
|-----------|-----------------|------------|
| `solo` | RU-сервер | Тестирует видимость публичных ресурсов с аплинка сервера |
| `listener` | RU-сервер | Запускает dummy-респондеры 6 протоколов для приёма handshake от клиента |
| `client` | Клиентское устройство | Пытается подключиться к listener по 6 протоколам |
| `dashboard` | Любая машина | Локальная аналитика в Grafana |

Все вердикты считаются inline:
- **DNS** — CERTainty (PETS 2023): валидность TLS-сертификата + согласие с DoH/DoT.
- **TLS** — системный trust store; SNI attribution через neutral-SNI control в том же запуске.
- **HTTP** — `expected_status` из `targets/*.yaml` + отдельный `GEOBLOCK_NOT_CENSORSHIP` вердикт для 403/451 с валидным TLS.
- **SNI throttling (Method B)** — относительная разница bandwidth между correct/trigger/typo SNI **внутри одного запуска** (устойчиво к разной ширине uplink).
- **Telegram reconcile** — cdn1/cdn5 серверы globally broken (отдают cert на `*.t.me` вместо хоста). Если cert chain валиден И SAN/CN попадает в `owned_cert_patterns` (`*.telegram.org`/`*.t.me`/`*.cdn-telegram.org`) — это аутентичный Telegram-эндпоинт с misrouted cert, не цензура (ТСПУ не может подделать публично-подписанный cert). Reclassified BLOCKED → INCONCLUSIVE.

---

## Первоначальная настройка

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/censprobe.git
cd censprobe
```

Готово. Файл `.env` уже лежит в репозитории с дефолтами, которые работают «из коробки»: passwords для localhost-only сервисов (Postgres/Grafana), `DOCKERHUB_USERNAME` указывает на публичные образы maintainer'а. Если хотите свои значения — отредактируйте `.env` локально, ничего больше делать не нужно.

> Образы публикуются в публичный репозиторий Docker Hub — `docker login` для pull не требуется.

---

## Быстрый старт: Запуск тестов

Тестирование конкретного сервера всегда начинается с прогона **solo**, затем переходит в фазу тестирования протоколов обхода цензуры связкой **listener + client**. Соблюдайте порядок.

### Шаг 1. Тест аплинка (Solo)

Запускается на тестируемом RU-сервере. Отвечает на вопрос: *«Заблокировано ли что-то на аплинке провайдера сервера?»*

```bash
docker compose --profile solo run --rm solo --test-id selectel-spb-001
```

> Дождитесь завершения. Отчёт сохранится в `reports/<TEST_ID>/server-solo-<timestamp>.json`. Контейнер ничего не пушит — публикация ручная (см. ниже).

### Шаг 2. Ожидание подключений (Listener)

Запускается на тестируемом RU-сервере **после** solo. Слушает порты протоколов (OpenVPN, WireGuard, AmneziaWG, Shadowsocks, VLESS+Reality, Hysteria 2) и поднимает одноразовый HTTPS-эндпоинт `8443/tcp` для выдачи credentials клиенту.

```bash
docker compose --profile listener run --rm listener --test-id selectel-spb-001 --session-id client-home-rt-spb
```

> Listener генерирует одноразовые credentials в памяти, выдаёт self-signed cert + bearer token и **печатает готовую команду** для запуска client'а на клиентской машине. Скопируйте её — она содержит `TEST_ID`, `SESSION_ID`, `SERVER_HOST`, `CREDS_TOKEN` и `CREDS_CERT_SHA256`.
>
> Открытый порт **8443/tcp** должен быть доступен с клиентской сети. После того как Client отработал, нажмите `Ctrl+C` — Listener сохранит отчёт в `reports/<TEST_ID>/`. Credentials живут только в памяти процесса и не записываются на диск.

### Шаг 3. Имитация подключения (Client)

На клиентской машине (ноутбук, мобильный интернет) откройте локальную копию репозитория и **вставьте команду, напечатанную listener'ом**. Команда — одна строка, работает идентично в bash/zsh (Linux, macOS), PowerShell и cmd.exe (Windows), потому что значения летят как CLI-аргументы docker'а, а не shell-префиксом env-переменных:

```
docker compose --profile client run --rm client --test-id selectel-spb-001 --session-id client-home-rt-spb --server-host 1.2.3.4 --creds-port 8443 --creds-token <one-time-token> --creds-cert-sha256 <sha256-fingerprint>
```

> Client тянет credentials с listener'а через TLS-pinning (cert проверяется по SHA-256), проверяет bearer-token и пробует 6 протоколов. По завершении возвращайтесь в терминал сервера и нажмите `Ctrl+C` в процессе Listener.

### Шаг 4 (опционально). Тестирование другой клиентской сети

Для каждой дополнительной сети просто перезапустите listener с новым `SESSION_ID` — он напечатает свежую команду с новыми credentials/cert/token, скопируйте её на клиентскую машину.

Формат `SESSION_ID`: `client-<тип>-<провайдер>-<город>`. Примеры:
- `client-home-rt-spb` — домашний Ростелеком, СПб
- `client-mob-mts-msk` — мобильный МТС, Москва
- `client-wifi-cafe-msk` — публичный Wi-Fi

---

## Настройка (censprobe.yaml)

Все runtime-knob'ы лежат в одном файле `censprobe.yaml` в корне репо. Файл коммитится с дефолтами; локальные правки не пушатся автоматически. Если файла нет, всё работает с дефолтами (схема в `packages/probe-core/src/censprobe_core/config.py::CensprobeConfig`).

Что можно настроить:

- **`vantage.censoring_countries`** — список стран ISO-3166 alpha-2, где включаются censor-specific эвристики (TCP fast-RST, QUIC drop, Method-B throttling). По умолчанию `[RU, BY]`. Расширяйте при тестах из CN/IR/KZ.
- **`modules.<name>.enabled: false`** — отключить модуль. Дашборд просто не получит данные по нему.
- **Пороги** в `modules.tcp.fast_rst_threshold_ms`, `modules.http.body_cap_bytes`, `modules.throttling.bandwidth_ratio_threshold` и т.д.
- **`protocols.enabled`** — какие из 6 VPN-протоколов листенер реально поднимает. Клиент мирорит этот список через креды; неизвестные имена дропаются с warning'ом.
- **`scoring.entry/exit/relay`** — веса в формулах score'ов.
- **`throughput.target_bytes` / `timeout_sec`** — ниже какой скорости срабатывает флаг `throttled`.
- **`targets.directory` + auto-discovery** — любой `*.yaml` в `targets/` подбирается автоматически. См. ниже.

Опечатка в имени поля = fatal startup error с понятным сообщением, не silent fallback.

---

## Настройка целей тестирования (Targets)

Все цели хранятся в папке `targets/` в формате YAML и **подбираются автоматически** — runner глобит `*.yaml` и валидирует каждый файл против `TargetFile` (`packages/probe-core/src/censprobe_core/targets.py`).

Текущие файлы:

- `targets/news.yaml` — СМИ
- `targets/social.yaml` — социальные сети
- `targets/messengers.yaml` — мессенджеры
- `targets/vpn.yaml` — VPN-сервисы
- `targets/neutral.yaml` — нейтральные ресурсы (VK, Yandex, Wikipedia) + список TCP-проб (anycast DNS на 443/853)
- `targets/telegram.yaml` — дата-центры Telegram, web/aux/CDN-домены, owned_cert_patterns, health_weights. Потребляется только модулем `telegram`.
- `targets/cloudflare.yaml` — инфраструктура Cloudflare и WARP. Потребляется только модулем `cloudflare`.

`telegram.yaml` и `cloudflare.yaml` помечены как `targets.module_owned` в `censprobe.yaml` — они грузятся в общий `TargetSet`, но не попадают в выборку для модулей dns/tcp/tls/http (у них своя модель данных).

**Как добавить новый сайт:**

1. Откройте нужный файл в `targets/` и добавьте domain по аналогии с существующими (поля: `domain`, `urls`, `expected_status`, `category`, `ech_advertised`, `notes`).
2. Сделайте `git commit` и `git push` локально, когда готовы поделиться изменениями.

**Как добавить новый файл целей:** просто положите `targets/<my>.yaml` со схемой `targets: [...]` (или другие поля из `TargetFile`). Pydantic провалидирует, runner автоматически включит его в общий список.

**Как добавить новый протокол** (например, MTProto-proxy, TUIC):

1. Дополните `ProtocolSpec` в `packages/probe-core/src/censprobe_core/protocol_registry.py`.
2. Добавьте responder в `packages/listener/src/censprobe_listener/_responder_dispatch.py`.
3. Добавьте probe-coroutine в `packages/probe-core/src/censprobe_core/protocol_probes.py` + dispatch в `packages/client/src/censprobe_client/_probe_dispatch.py`.
4. Расширьте `ProtocolCredentials` (listener `credentials.py` + probe-core `credentials_reader.py`).
5. Включите в `protocols.enabled` в `censprobe.yaml`.

Параметры VPN-протоколов (порты, ключи, AmneziaWG-обфускация) генерируются `listener` в памяти при каждом старте и передаются клиенту через одноразовый TLS-pinned эндпоинт. На диск ничего не пишется и в git ничего не коммитится.

---

## Дашборд (Grafana)

Запускается на любой машине с доступом к репозиторию:

```bash
docker compose --profile dashboard up -d
```

1. Откройте `http://localhost:3000` — логин `admin`, пароль из `GRAFANA_PASSWORD` в `.env`.
2. Чтобы подтянуть новые отчёты, выполните `git pull` — sync-api сканирует `reports/` в фоне (`CENSPROBE_IMPORT_INTERVAL_SEC`, по умолчанию 60 с) и импортирует новые `.json` в Postgres автоматически.

**Дашборды:**

| Дашборд | Что показывает |
|---------|----------------|
| **01 — Test Overview** | Основные метрики: Censorship Resistance Score, DNS/TLS/Telegram, техники цензуры, рекомендуемые протоколы. Точка входа со ссылками на drill-down дашборды |
| **02 — Blocking Matrix** | Полная матрица всех тестов с цветовой раскраской по вердикту |
| **03 — Telegram Deep Dive** | Детальная досягаемость Telegram DC, health score, RTT-распределение |
| **04 — Protocol Reachability** | Матрица досягаемости протоколов по клиентским сессиям + ASN сетей клиентов |
| **05 — Technique Attribution** | Атрибуция техник цензуры (DNS poisoning, RST injection, throttling, middlebox) |
| **06 — Compare Tests** | Сравнение двух серверов: scores, server info, техники |
| **07 — Cloudflare & WARP** | WARP control plane (TCP 443), MASQUE и WireGuard UDP fallback-порты, Cloudflare CDN/HTTP |
| **08 — QUIC & ECH** | QUIC-блокировка (TSPU/UDP 443), ECH-тесты, Hysteria2 досягаемость |
| **09 — DNS Deep Dive** | DNS integrity, DoH-резолверы, DNS poisoning детектирование |
| **10 — TLS Deep Dive** | SNI inspection (paired blocked/neutral SNI), TLS-методы цензуры, RTT |

---

## Публикация результатов

Контейнеры пишут отчёты в `reports/<TEST_ID>/` на хосте и больше ничего не делают. Публикация — ручная: вы сами решаете, когда и куда коммитить и пушить.

```bash
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID> ..."
git push
```

Если GitHub недоступен с тестируемой машины (бывает, особенно при тестах из RU-сетей), скопируйте каталог отчёта на любой хост с доступом и опубликуйте оттуда:

```bash
# С тестового сервера:
scp -r reports/<TEST_ID>/ user@other-host:~/censprobe/reports/

# На машине с доступом к GitHub:
cd ~/censprobe
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID> from <node>"
git push
```

---

## Контрибуция отчётов через PR

Если вы хотите, чтобы ваш отчёт попал в основной публичный реестр — сделайте fork репозитория и пришлите Pull Request:

```bash
# 1. Fork через GitHub UI, затем у себя локально:
git clone https://github.com/<YOUR_GITHUB_USERNAME>/censprobe.git
cd censprobe

# 2. Запустите тесты — отчёты появятся в reports/<TEST_ID>/.
docker compose --profile solo run --rm solo --test-id <provider>-<city>-<NN>
docker compose --profile listener run --rm listener --test-id <provider>-<city>-<NN> --session-id client-<...>
# (плюс client на клиентской машине — см. Шаг 3)

# 3. Закоммитьте и откройте PR против main upstream-репозитория.
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID>"
git push origin main
# затем gh pr create или через GitHub UI
```

Соглашения по `TEST_ID`: `<provider>-<city>-<NN>` (например `selectel-spb-001`, `vultr-frankfurt-002`). По `SESSION_ID`: `client-<тип>-<провайдер>-<город>` (`client-home-rt-spb`, `client-mob-mts-msk`).

Оба идентификатора пропускают через валидатор: `[A-Za-z0-9_.-]{1,64}`. Кириллица, пробелы, `/` или путевые символы будут отклонены click'ом до запуска контейнера — это закрывает path-traversal через имя отчёта.

> **Что review-ится в PR**: путь `reports/<TEST_ID>/` (новые файлы), целостность JSON, разумность `meta.yaml`. Изменения в коде/`targets/` обсуждаются отдельно — желательно открывать на них отдельные PR.

> **Workflow в форках**: `.github/workflows/build.yml` не запускается на форках (guard `if: github.repository == 'vasiliiok/censprobe'`) — это убирает шум красных CI у контрибуторов без `DOCKERHUB_TOKEN`. Если форкер хочет собирать свои образы — снимает guard и ставит свои `vars.DOCKERHUB_USERNAME` + `secrets.DOCKERHUB_TOKEN`.

---

## Переменные окружения

`.env` — статическая конфигурация: порты, пароли, ключи, настройки. Закоммичен в репо со значениями по умолчанию; редактируете локально, чтобы переопределить. Если ключ удалили из `.env` — контейнер упадёт явной ошибкой. Per-run параметры (`--test-id`, `--session-id` и т.д.) — CLI-аргументы `docker compose run`, не переменные окружения.

| Переменная | Профили | Дефолт | Описание |
|------------|---------|--------|----------|
| `DOCKERHUB_USERNAME` | все | `outtakes` | Docker Hub username, из которого берутся образы (поменяйте на свой при fork'е) |
| `DOCKERHUB_TAG` | все | `main` | Тег образа |
| `DB_PASSWORD` | dashboard | `<random>` | Пароль PostgreSQL (loopback-only сервис) |
| `GRAFANA_PASSWORD` | dashboard | `admin` | Пароль admin Grafana (`127.0.0.1:3000`) |
| `RUNS_COUNT` | solo | `3` | Количество повторных замеров |
| `CREDS_PORT` | listener, client | `8443` | Порт credentials-эндпоинта на listener'е |
| `CENSPROBE_IMPORT_INTERVAL_SEC` | dashboard | `60` | Интервал импорта отчётов в Postgres (с) |
| `IPAPI_IS_KEY` | solo, listener | `<key>` | API-ключ ipapi.is для ASN/geo (пустая строка — бесплатный tier) |

Контейнеры не имеют git/SSH зависимостей — `git push` запускаете вы сами с хоста, когда готовы публиковать отчёты.

---

## Структура репозитория

```
censprobe/
├── .env                        # коммитнутые дефолты (можно править локально)
├── docker-compose.yml          # профили: solo, listener, client, dashboard
├── packages/                   # исходный код всех контейнеров
│   ├── probe-core/             # общая библиотека измерений (censprobe_core)
│   ├── solo/                   # запуск solo-тестирования
│   ├── listener/               # протокол-респондеры + listener
│   ├── client/                 # клиентские пробы
│   └── dashboard/              # Grafana + sync-api + PostgreSQL
├── targets/                    # что тестировать (YAML)
├── reports/                    # результаты тестирований
│   └── <test_id>/
│       ├── meta.yaml           # auto-detected server info
│       └── *.json              # solo + listener отчёты
```
