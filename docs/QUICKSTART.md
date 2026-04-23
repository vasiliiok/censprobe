# Censprobe — Quickstart Guide

## Что нужно

| Компонент | Требование |
|-----------|-----------|
| Docker + Docker Compose | v2.20+ |
| SSH Deploy Key | Добавлен в репо как **Deploy Key** с write-доступом |
| Тестируемый сервер (RU-VPS) | Для `solo` и `listener` |
| Клиентская машина | Для `client` — ноутбук, телефон через USB-tether |
| Control-VPS (DE/NL/FI) | Для `control` — **не в России** |
| Dashboard-машина | Для `dashboard` — где угодно |

---

## Быстрый старт — Solo (минимум)

**Solo** тестирует что видит сервер из своего аплинка: DNS, TLS, HTTP, Telegram, throttling.

```bash
# 1. Клонируй репозиторий на тестируемый RU-сервер
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

# 2. Запусти solo-прогон (5–15 минут)
TEST_ID=selectel-spb-001 docker compose --profile solo up --build

# Или через helper-скрипт:
TEST_ID=selectel-spb-001 ./run-test.sh
```

Результат появится в `reports/selectel-spb-001/` и будет автоматически запушен на GitHub.

---

## Полный тест (Solo → Listener → Client)

### Порядок запуска (ВАЖНО)

```
Solo → Listener → Client
```

Solo должен запускаться ДО Listener — иначе в baseline будут данные с уже открытыми VPN-портами.

### Шаг 1 — Solo (на RU-сервере)

```bash
TEST_ID=selectel-spb-001 docker compose --profile solo up --build
```

### Шаг 2 — Listener (на RU-сервере, другой машине)

```bash
# Первый запуск: сгенерирует credentials и запушит protocols.yaml
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up --build

# Нажми Ctrl+C чтобы остановить — результаты сохранятся и запушатся автоматически
```

### Шаг 3 — Client (на клиентской машине)

```bash
# После того как listener запушил protocols.yaml
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb SERVER_HOST=1.2.3.4 \
  docker compose --profile client up --build
```

`SERVER_HOST` — это IP тестируемого сервера (где работает listener). Указывай IP напрямую, не через DNS.

---

## Control (Эталонный Baseline)

Запускай **на DE/NL/FI VPS** — не в России.

```bash
# На control-VPS:
RUNS_COUNT=5 CONTROL_ID=control-de-01 \
  docker compose --profile control up --build
```

Обновляй baseline минимум раз в неделю (указано в `validity_until`).

---

## Dashboard (Grafana)

Запускай где удобно — локально или на отдельном сервере.

```bash
docker compose --profile dashboard up --build -d

# Открой http://localhost:3000 (admin/admin)
# Нажми "Pull & Refresh" для загрузки данных из репозитория
```

Или вручную через curl:

```bash
curl -X POST http://localhost:8080/refresh
```

---

## Reporter (HTML/PDF)

```bash
# HTML отчёт
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter

# HTML + PDF
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter --pdf

# Результат: reports/selectel-spb-001/report.html (и .pdf)
```

---

## Переменные окружения

| Переменная | Контейнер | Описание |
|------------|-----------|----------|
| `TEST_ID` | solo, listener, client, reporter | Идентификатор тестируемого сервера |
| `SESSION_ID` | listener, client | Метка клиентской сессии (e.g. `client-home-rt-spb`) |
| `SERVER_HOST` | client | IP сервера с listener |
| `RUNS_COUNT` | solo, control | Количество прогонов (default: 3 для solo, 5 для control) |
| `CONTROL_ID` | control | Идентификатор control-точки (default: `control-de-01`) |
| `CONTROL_COUNTRY` | control | Страна control-VPS (default: `DE`) |
| `DB_PASSWORD` | dashboard | Пароль Postgres (default: `censprobe`) |
| `GRAFANA_PASSWORD` | dashboard | Пароль Grafana admin (default: `admin`) |

---

## SSH Deploy Key

Каждый сервер должен иметь свой SSH-ключ с правом записи в репозиторий.

```bash
# Создай ключ (на сервере)
ssh-keygen -t ed25519 -C "censprobe-selectel-spb-001" -f ~/.ssh/censprobe_deploy

# Скопируй публичную часть в GitHub:
# Settings → Deploy Keys → Add key → Enable write access
cat ~/.ssh/censprobe_deploy.pub

# Настрой ~/.ssh/config (или смонтируй ключ в контейнер через volumes)
```

Ключ монтируется в контейнер через `volumes: ["~/.ssh:/root/.ssh:ro"]` в docker-compose.yml.
