# Censprobe

Censprobe — инструмент измерения цензуры и оценки устойчивости серверов к сетевым блокировкам в России. Автоматически проверяет достижимость публичных ресурсов с аплинка сервера, тестирует протоколы обхода цензуры через DPI и оценивает наличие троттлинга и SNI-блокировок.

Все тесты работают автономно через Docker Compose, а результаты сохраняются в `reports/<TEST_ID>/` локально — публикация в git-репозиторий выполняется вручную, и Grafana собирает дашборды из импортированных отчётов.

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
TEST_ID=selectel-spb-001 docker compose --profile solo up
```

> Дождитесь завершения. Отчёт сохранится в `reports/<TEST_ID>/server-solo-<timestamp>.json`. Контейнер ничего не пушит — публикация ручная (см. ниже).

### Шаг 2. Ожидание подключений (Listener)

Запускается на тестируемом RU-сервере **после** solo. Слушает порты протоколов (OpenVPN, WireGuard, AmneziaWG, Shadowsocks, VLESS+Reality, Hysteria 2) и поднимает одноразовый HTTPS-эндпоинт `8443/tcp` для выдачи credentials клиенту.

```bash
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up
```

> Listener генерирует одноразовые credentials в памяти, выдаёт self-signed cert + bearer token и **печатает готовую команду** для запуска client'а на клиентской машине. Скопируйте её — она содержит `TEST_ID`, `SESSION_ID`, `SERVER_HOST`, `CREDS_TOKEN` и `CREDS_CERT_SHA256`.
>
> Открытый порт **8443/tcp** должен быть доступен с клиентской сети. После того как Client отработал, нажмите `Ctrl+C` — Listener сохранит отчёт в `reports/<TEST_ID>/`. Credentials живут только в памяти процесса и не записываются на диск.

### Шаг 3. Имитация подключения (Client)

На клиентской машине (ноутбук, мобильный интернет) откройте локальную копию репозитория и **вставьте команду, напечатанную listener'ом**. Она выглядит так:

```bash
TEST_ID=selectel-spb-001 \
  SESSION_ID=client-home-rt-spb \
  SERVER_HOST=1.2.3.4 \
  CREDS_PORT=8443 \
  CREDS_TOKEN=<one-time-token> \
  CREDS_CERT_SHA256=<sha256-fingerprint> \
  docker compose --profile client up
```

> Client тянет credentials с listener'а через TLS-pinning (cert проверяется по SHA-256), проверяет bearer-token и пробует 6 протоколов. По завершении возвращайтесь в терминал сервера и нажмите `Ctrl+C` в процессе Listener.

### Шаг 4 (опционально). Тестирование другой клиентской сети

Для каждой дополнительной сети просто перезапустите listener с новым `SESSION_ID` — он напечатает свежую команду с новыми credentials/cert/token, скопируйте её на клиентскую машину.

Формат `SESSION_ID`: `client-<тип>-<провайдер>-<город>`. Примеры:
- `client-home-rt-spb` — домашний Ростелеком, СПб
- `client-mob-mts-msk` — мобильный МТС, Москва
- `client-wifi-cafe-msk` — публичный Wi-Fi

---

## Настройка целей тестирования (Targets)

Все цели хранятся в папке `targets/` в формате YAML:

- `targets/news.yaml` — СМИ
- `targets/social.yaml` — социальные сети
- `targets/messengers.yaml` — мессенджеры
- `targets/vpn.yaml` — VPN-сервисы
- `targets/telegram.yaml` — дата-центры Telegram
- `targets/neutral.yaml` — нейтральные ресурсы (VK, Yandex, Wikipedia)
- `targets/cloudflare.yaml` — инфраструктура Cloudflare и WARP: QUIC/HTTP3 (UDP 443), WARP control plane (engage/connectivity/zero-trust на TCP 443), MASQUE-anycast (162.159.197.0/24 — основной протокол WARP с дек. 2024) и WireGuard-anycast (162.159.193.0/24 — legacy). Покрываются все UDP-ports реальной WARP-fallback-лестницы: MASQUE 443→4443/8443, WG 2408→4500. Используется модулем cloudflare.

**Как добавить новый сайт:**

1. Откройте нужный файл в `targets/`.
2. Добавьте домен по аналогии с существующими.
3. Сделайте `git commit` и `git push` локально, когда готовы поделиться изменениями.

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
TEST_ID=<provider>-<city>-<NN> docker compose --profile solo up
TEST_ID=<provider>-<city>-<NN> SESSION_ID=client-<...> docker compose --profile listener up
# (плюс client на клиентской машине — см. Шаг 3)

# 3. Закоммитьте и откройте PR против main upstream-репозитория.
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID>"
git push origin main
# затем gh pr create или через GitHub UI
```

Соглашения по `TEST_ID`: `<provider>-<city>-<NN>` (например `selectel-spb-001`, `vultr-frankfurt-002`). По `SESSION_ID`: `client-<тип>-<провайдер>-<город>` (`client-home-rt-spb`, `client-mob-mts-msk`).

> **Что review-ится в PR**: путь `reports/<TEST_ID>/` (новые файлы), целостность JSON, разумность `meta.yaml`. Изменения в коде/`targets/` обсуждаются отдельно — желательно открывать на них отдельные PR.

> **Workflow в форках**: `.github/workflows/build.yml` не запускается на форках (guard `if: github.repository == 'vasiliiok/censprobe'`) — это убирает шум красных CI у контрибуторов без `DOCKERHUB_TOKEN`. Если форкер хочет собирать свои образы — снимает guard и ставит свои `vars.DOCKERHUB_USERNAME` + `secrets.DOCKERHUB_TOKEN`.

---

## Переменные окружения

Все переменные хранятся в `.env` (закоммичен в репо как набор дефолтов). Локальные правки в файле не пушатся автоматически — это ваше рабочее дерево.

| Переменная | Профили | Описание |
|------------|---------|----------|
| `DOCKERHUB_USERNAME` | все | Docker Hub username, из которого берутся образы (по умолчанию — публичный аккаунт maintainer'а) |
| `DOCKERHUB_TAG` | все | Тег образа (по умолчанию: `main`) |
| `DB_PASSWORD` | dashboard | Пароль PostgreSQL (loopback-only сервис) |
| `GRAFANA_PASSWORD` | dashboard | Пароль admin Grafana (`127.0.0.1:3000`) |
| `TEST_ID` | solo, listener, client | Идентификатор сервера (например, `selectel-spb-001`) |
| `SESSION_ID` | listener, client | Идентификатор клиентской сети (например, `client-home-rt-spb`) |
| `SERVER_HOST` | client | IPv4-адрес сервера с Listener |
| `CREDS_PORT` | client | Порт listener'овского credentials-эндпоинта (по умолчанию: `8443`) |
| `CREDS_TOKEN` | client | One-time bearer token, печатается listener'ом при старте |
| `CREDS_CERT_SHA256` | client | SHA-256 fingerprint self-signed cert listener'а (cert pinning) |
| `RUNS_COUNT` | solo | Количество повторных замеров (по умолчанию: 3) |
| `IPAPI_IS_KEY` | solo, listener | API-ключ ipapi.is для ASN/geo (без ключа — бесплатный tier) |
| `CENSPROBE_IMPORT_INTERVAL_SEC` | dashboard | Интервал импорта отчётов в Postgres (по умолчанию: 60 с) |

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
