# Censprobe

Censprobe — инструмент измерения цензуры и оценки устойчивости серверов к сетевым блокировкам в России. Автоматически проверяет достижимость публичных ресурсов с аплинка сервера, тестирует протоколы обхода цензуры через DPI и оценивает наличие троттлинга и SNI-блокировок.

Все тесты работают автономно через Docker Compose, а результаты агрегируются в git-репозиторий для визуализации в Grafana.

## Архитектура развертывания

Система состоит из 5 независимых компонентов (профилей Docker), запускаемых на разных машинах:

| Профиль | Где запускается | Назначение |
|-----------|-----------------|------------|
| `solo` | RU-сервер | Тестирует видимость публичных ресурсов с аплинка сервера |
| `listener` | RU-сервер | Запускает dummy-респондеры 6 протоколов для приёма handshake от клиента |
| `client` | Клиентское устройство | Пытается подключиться к listener по 6 протоколам |
| `control` | Чистый EU-сервер | Генерирует эталонный baseline |
| `dashboard` | Любая машина | Локальная аналитика в Grafana |

---

## Первоначальная настройка

Выполните один раз на каждой машине перед первым запуском:

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/censprobe.git
cd censprobe

cp .env.example .env
# Отредактируйте .env: задайте DOCKERHUB_USERNAME, DB_PASSWORD, GRAFANA_PASSWORD
```

Минимально необходимые переменные в `.env`:

```bash
DOCKERHUB_USERNAME=your-dockerhub-username  # username на Docker Hub (откуда берутся образы)
DB_PASSWORD=<strong-password>               # пароль PostgreSQL (используется dashboard)
GRAFANA_PASSWORD=<strong-password>          # пароль admin в Grafana
```

> Образы публикуются в публичный репозиторий Docker Hub — `docker login` для pull не требуется.

Для генерации паролей: `openssl rand -base64 32`

---

## Быстрый старт: Запуск тестов

Тестирование конкретного сервера всегда начинается с прогона **solo**, затем переходит в фазу тестирования протоколов обхода цензуры связкой **listener + client**. Соблюдайте порядок.

### Шаг 1. Тест аплинка (Solo)

Запускается на тестируемом RU-сервере. Отвечает на вопрос: *«Заблокировано ли что-то на аплинке провайдера сервера?»*

```bash
TEST_ID=selectel-spb-001 docker compose --profile solo up
```

> Дождитесь завершения. Отчёт загрузится в репозиторий автоматически.

### Шаг 2. Ожидание подключений (Listener)

Запускается на тестируемом RU-сервере **после** solo. Слушает порты протоколов (OpenVPN, WireGuard, AmneziaWG, Shadowsocks, VLESS+Reality, Hysteria 2).

```bash
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up
```

> Listener генерирует credentials и ожидает подключений от Client. После того как Client отработал, нажмите `Ctrl+C` — Listener сохранит и запушит результаты.

### Шаг 3. Имитация подключения (Client)

Запускается на клиентской машине (ноутбук, мобильный интернет).

```bash
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  SERVER_HOST=1.2.3.4 \
  docker compose --profile client up
```

> **SERVER_HOST** — IP-адрес тестируемого RU-сервера. Client попробует подключиться по 6 протоколам. После завершения перейдите в терминал сервера и нажмите `Ctrl+C` в процессе Listener.

### Шаг 4 (опционально). Тестирование другой клиентской сети

Для каждой дополнительной сети listener перезапускается с новым `SESSION_ID`:

```bash
# На сервере — новая сессия:
TEST_ID=selectel-spb-001 SESSION_ID=client-mob-mts-msk \
  docker compose --profile listener up

# На клиентской машине (переключитесь на другой интернет):
TEST_ID=selectel-spb-001 SESSION_ID=client-mob-mts-msk \
  SERVER_HOST=1.2.3.4 \
  docker compose --profile client up
```

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
3. Сделайте `git commit` и `git push`.
4. Перегенерация baseline (`control`) **нужна только** если добавили Telegram-эндпоинт или цель для Method A throttling — для DNS/TLS/HTTP вердикты считаются inline и baseline не используется.

Параметры VPN-протоколов (порты, ключи, AmneziaWG-обфускация) генерируются `listener` per-test в `reports/<test_id>/protocols.yaml`. Отпечатки блок-страниц — в `signatures/blockpages.yaml`.

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

## Эталонный Baseline (Control)

Baseline — это снимок с чистого зарубежного сервера, который Censprobe использует **только** в двух случаях:

1. **Telegram reconcile.** Часть эндпоинтов Telegram (порт `2001`, `k.web.telegram.org`/`a.web.telegram.org` отвечают NXDOMAIN извне РФ, CDN `cdn1..5` отдают «не тот» сертификат) и без эталона с EU-сервера на нейтральном VPS они выглядят как «заблокировано». Baseline помечает их `INCONCLUSIVE` (reason: `baseline_also_unreachable`).
2. **Method A throttling.** Для верификации замеров YouTube/CDN bandwidth используется порог `< baseline_p10 × 0.3` → `THROTTLED`.

Для DNS/TLS/HTTP и Method B SNI-throttling baseline **не используется**:

- DNS — подход CERTainty (PETS 2023): валидность TLS-сертификата + согласие с DoH/DoT.
- TLS — системный trust store; cert-chain hash-сравнение убрано (ложные срабатывания на CDN-rotation).
- HTTP — сигнатуры блок-страниц + `expected_status` из `targets/*.yaml`.
- Method B — относительная разница bandwidth между correct/trigger/typo SNI внутри одного запуска (устойчиво к разной ширине uplink).

Baseline генерируется профилем **control** на чистом EU/DE-сервере:

```bash
# Выполнять на DE/NL сервере, минимум раз в 1–2 недели
docker compose --profile control up
```

`CONTROL_ID` и `CONTROL_COUNTRY` задаются в `.env` (по умолчанию: `control-de-01` и `DE`). Количество повторных замеров — `RUNS_COUNT` (по умолчанию: 5).

Эталон сохранится в `baseline/latest.json` (≈9 КБ — только две секции: `telegram` и `throttling`). Запуск solo без актуального baseline допустим: DNS/TLS/HTTP всё равно дадут полноценные вердикты, потеряются только Telegram-reconcile (NXDOMAIN/wrong-cert эндпоинты вернут `BLOCKED` вместо `INCONCLUSIVE`) и Method A throttling (вернёт `INCONCLUSIVE`). Обновлять baseline имеет смысл при добавлении новых Telegram/throttling-целей или раз в 1–2 недели для актуализации Telegram DC reachability.

---

## Ручная публикация результатов (при недоступности GitHub)

Если `git push` не удаётся (GitHub заблокирован из текущей сети), система уведомит вас и предложит действия. Все результаты всегда сохраняются локально.

### Вариант 1: Повторный push

Результаты зафиксированы в локальном git-коммите. При восстановлении связи:

```bash
cd /workspace   # или каталог репозитория
git push
```

### Вариант 2: Ручное копирование файлов

```bash
# С тестового сервера (solo/listener):
scp -r /workspace/reports/<TEST_ID>/ user@other-host:~/censprobe/reports/

# На другой машине (с доступом к GitHub):
cd ~/censprobe
git add reports/<TEST_ID>/
git commit -m "manual: add reports for <TEST_ID>"
git push
```

### Вариант 3: Передача credentials для клиента

Если listener запушил credentials (`protocols.yaml`), но клиент не может сделать `git pull`:

```bash
# Скопируйте файл с сервера listener на клиент:
scp /workspace/reports/<TEST_ID>/protocols.yaml \
  user@client-host:~/censprobe/reports/<TEST_ID>/protocols.yaml
```

---

## Переменные окружения

Все переменные задаются в `.env` (скопируйте из `.env.example`). Переменные с пометкой **required** обязательны — без них контейнеры не запустятся.

| Переменная | Профили | Описание |
|------------|---------|----------|
| `DOCKERHUB_USERNAME` | все | **required** — Docker Hub username, из которого берутся образы |
| `DB_PASSWORD` | dashboard | **required** — пароль PostgreSQL |
| `GRAFANA_PASSWORD` | dashboard | **required** — пароль admin Grafana |
| `TEST_ID` | solo, listener, client | Идентификатор сервера (например, `selectel-spb-001`) |
| `SESSION_ID` | listener, client | Идентификатор клиентской сети (например, `client-home-rt-spb`) |
| `SERVER_HOST` | client | IPv4-адрес сервера с Listener |
| `RUNS_COUNT` | solo, control | Количество повторных замеров (solo: 3, control: 5) |
| `DOCKERHUB_TAG` | все | Тег образа (по умолчанию: `main`) |
| `CONTROL_ID` | control | Идентификатор эталонного сервера (по умолчанию: `control-de-01`) |
| `CONTROL_COUNTRY` | control | Страна эталонного сервера (по умолчанию: `DE`) |
| `IPAPI_IS_KEY` | solo, listener, client, control | API-ключ ipapi.is для ASN/geo (без ключа — бесплатный tier) |
| `CENSPROBE_GIT_EMAIL` | solo, listener, client, control | Email git-коммитов внутри контейнеров (по умолчанию: `noreply@censprobe.local`) |
| `CENSPROBE_GIT_NAME` | solo, listener, client, control | Имя автора git-коммитов (по умолчанию: `censprobe-bot`) |
| `CENSPROBE_IMPORT_INTERVAL_SEC` | dashboard | Интервал импорта отчётов в Postgres (по умолчанию: 60 с) |

SSH-ключи монтируются через volume: `~/.ssh:/root/.ssh:ro`.

---

## Структура репозитория

```
censprobe/
├── .env.example                # шаблон для .env
├── docker-compose.yml          # профили: solo, listener, client, control, dashboard
├── packages/                   # исходный код всех контейнеров
│   ├── probe-core/             # общая библиотека измерений (censprobe_core)
│   ├── solo/                   # запуск solo-тестирования
│   ├── listener/               # протокол-респондеры + listener
│   ├── client/                 # клиентские пробы
│   ├── control/                # генератор baseline
│   └── dashboard/              # Grafana + sync-api + PostgreSQL
├── targets/                    # что тестировать (YAML)
├── signatures/                 # отпечатки блок-страниц
│   └── blockpages.yaml
├── baseline/                   # эталон от control-контейнера
│   ├── latest.json
│   └── archive/
├── reports/                    # результаты тестирований
│   └── <test_id>/
│       ├── meta.yaml
│       ├── protocols.yaml      # credentials (генерируется listener)
│       └── *.json              # результаты тестов
```
