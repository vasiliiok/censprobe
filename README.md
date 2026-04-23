# Censprobe

**Автоматизированная оценка пригодности российских VPS для использования в качестве узлов VPN-каскада.**

Измеряет:
1. Что видит сервер из своего аплинка — DNS, TLS, HTTP, Telegram, throttling (Solo)
2. Дойдут ли VPN-пакеты от клиента до сервера по 6 протоколам (Listener + Client)
3. Какие техники цензуры применяются (DNS poisoning, SNI blocking, ТСПУ, etc.)

Результат: числовые score 0–100 для ролей **Entry / Exit / Relay**, список рабочих протоколов, Grafana-дашборды, HTML/PDF-отчёты.

---

## Быстрый старт

```bash
# 1. Клонируй на тестируемый RU-сервер
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

# 2. Solo-тест (5–15 минут)
TEST_ID=selectel-spb-001 docker compose --profile solo up --build

# 3. Смотри дашборд (запусти локально)
docker compose --profile dashboard up --build -d
# → http://localhost:3000  (admin/admin) → нажми "Pull & Refresh"
```

---

## Контейнеры

| Профиль | Где запускать | Что делает |
|---------|---------------|------------|
| `solo` | RU-сервер | Тесты наружу: DNS, TLS, HTTP, Telegram, throttling, middlebox |
| `listener` | RU-сервер | Открывает VPN-порты (6 протоколов), пишет отчёт при Ctrl+C |
| `client` | Ноут / телефон | Handshake-пробы к listener, результаты в stdout |
| `control` | DE/NL-VPS | Эталонный baseline — **запускать не в России** |
| `dashboard` | Где угодно | Grafana + Postgres + sync-api |
| `reporter` | Где угодно | HTML/PDF-отчёт из сохранённых данных |

---

## Полный сценарий (Solo → Listener → Client)

> **Важно:** Solo должен запускаться **до** Listener.

```bash
# === RU-сервер ===

# Шаг 1: Solo
TEST_ID=selectel-spb-001 docker compose --profile solo up --build

# Шаг 2: Listener (Ctrl+C чтобы остановить)
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up --build

# === Клиентская машина ===

# Шаг 3: Client (после того как listener запушил credentials)
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb SERVER_HOST=1.2.3.4 \
  docker compose --profile client up --build
```

---

## Control (Baseline)

```bash
# На DE/NL-VPS (не в России):
RUNS_COUNT=5 CONTROL_ID=control-de-01 \
  docker compose --profile control up --build

# Обновляй раз в неделю — baseline действует 7 дней
```

Подробнее: [docs/BASELINE.md](docs/BASELINE.md)

---

## Dashboard

```bash
docker compose --profile dashboard up --build -d
# http://localhost:3000  (admin/admin)

# Обновить данные вручную:
curl -X POST http://localhost:8080/refresh
```

7 Grafana-дашбордов:
- `01` — Test Overview (оценки, техники, рекомендации)
- `02` — Blocking Matrix (все тесты с цветовой маркировкой)
- `03` — Telegram Deep Dive
- `04` — VPN Reachability (матрица протокол × клиент)
- `05` — Technique Attribution (DNS poisoning, throttling, middlebox)
- `06` — Compare Tests (сравнение двух серверов)
- `07` — Server Suitability (главный дашборд)

---

## Reporter (HTML/PDF)

```bash
# HTML
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter

# HTML + PDF
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter --pdf

# → reports/selectel-spb-001/report.html
```

---

## Переменные окружения

| Переменная | Контейнер | По умолчанию | Описание |
|------------|-----------|-------------|----------|
| `TEST_ID` | solo, listener, client, reporter | — | Идентификатор сервера |
| `SESSION_ID` | listener, client | — | Метка клиентской сессии |
| `SERVER_HOST` | client | — | IP-адрес listener-сервера |
| `RUNS_COUNT` | solo, control | 3 / 5 | Количество повторных прогонов |
| `CONTROL_ID` | control | `control-de-01` | Идентификатор control-точки |
| `CONTROL_COUNTRY` | control | `DE` | Страна control-VPS |
| `DB_PASSWORD` | dashboard | `censprobe` | Пароль Postgres |
| `GRAFANA_PASSWORD` | dashboard | `admin` | Пароль Grafana |

---

## VPN-протоколы

| Протокол | Порт | Транспорт |
|----------|------|-----------|
| OpenVPN (static-key) | 1194/UDP | UDP |
| WireGuard | 51820/UDP | UDP |
| AmneziaWG | 51821/UDP | UDP |
| Shadowsocks 2022 | 8388/TCP | TCP |
| VLESS + Reality | 443/TCP | TCP+TLS |
| Hysteria 2 (salamander) | 443/UDP | QUIC |

---

## Структура данных

```
reports/<test_id>/
  meta.yaml                              ← описание испытания
  protocols.yaml                         ← VPN credentials (одноразовые)
  server-solo-<ts>.json.gz               ← solo-отчёт
  server-listener-<session>-<ts>.json.gz ← listener-отчёт
  report.html                            ← HTML-отчёт (reporter)
  report.pdf                             ← PDF-отчёт (reporter, опционально)

baseline/
  latest.json                            ← актуальный эталон (от control)
  archive/<version>.json                 ← архив предыдущих baseline
```

---

## Privacy & Opsec

- Репозиторий **private** — IP-адреса маскируются до /24 в отчётах
- SSH Deploy Keys — никаких PAT-токенов в контейнерах
- Клиент **ничего не коммитит** — только читает из репо
- Одноразовые credentials на каждый `test_id`
- Control-VPS изолирован — не видит данных RU-серверов

Подробнее: [docs/QUICKSTART.md](docs/QUICKSTART.md)

---

## Milestones

- **M1** ✅ probe-core + solo
- **M2** ✅ control + baseline builder
- **M3** ✅ dashboard (Grafana + sync-api, 7 дашбордов)
- **M4** ✅ Telegram-модуль (реализован в M1)
- **M5** ✅ listener (6 VPN responders, inc. DPI-resistant AmneziaWG and Hysteria 2)
- **M6** ✅ client (handshake probes, jitter obfs)
- **M7** ✅ reporter (HTML/PDF) + все дашборды

**Status: Production Ready** ✅
