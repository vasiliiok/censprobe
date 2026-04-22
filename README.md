# Censprobe

**Автоматизированная оценка пригодности российских VPS для использования в качестве узлов VPN-каскада.**

Измеряет:
1. Что видит сервер из своего аплинка (Solo)
2. Дойдут ли клиентские VPN-пакеты до сервера по 6 протоколам (Listener + Client)
3. Какие техники цензуры применяются (DNS poisoning, SNI blocking, throttling, etc.)

## Быстрый старт

### Требования
- Docker + Docker Compose
- SSH-ключ добавлен в репозиторий как Deploy Key

### Первый тест

```bash
# 1. Клонируй репозиторий на тестируемый сервер
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

# 2. Запусти solo-прогон (5-15 минут)
TEST_ID=selectel-spb-001 ./run-test.sh

# 3. Запусти дашборд где удобно
docker compose --profile dashboard up -d
# → http://localhost:3000 (admin/admin) → "Pull & Refresh"
```

### Порядок запуска (ВАЖНО)
```
Solo → Listener → Client
```
Solo должен запускаться ДО listener: listener открывает VPN-порты, ТСПУ может усилить фильтрацию исходящего трафика.

## Контейнеры

| Профиль | Где | Что делает |
|---------|-----|------------|
| `solo` | RU-сервер | Тесты наружу: DNS, TLS, HTTP, Telegram, throttling |
| `listener` | RU-сервер | Слушает VPN-порты (6 протоколов) |
| `client` | Ноут/телефон | Handshake-тесты к listener |
| `control` | DE-VPS | Эталонный baseline |
| `dashboard` | Где удобно | Grafana + Postgres |

## Переменные окружения

```bash
TEST_ID=selectel-spb-001          # для solo, listener, client
SESSION_ID=client-home-rt-spb    # только для listener
SERVER_HOST=1.2.3.4              # только для client
RUNS_COUNT=3                      # количество повторов (для solo, control)
```

## Milestones

- **M1** (текущий): probe-core + solo ✅
- **M2**: control + baseline
- **M3**: dashboard (Grafana + sync-api)
- **M4**: Telegram модуль
- **M5**: listener (VPN responders)
- **M6**: client
- **M7**: все дашборды + HTML/PDF reporter

## Privacy & Opsec

- Репозиторий **private** — IP серверов маскируются до /24 в отчётах
- SSH Deploy Keys — никаких PAT-токенов
- Клиент ничего не коммитит — только читает из репо
- Одноразовые credentials на каждый test_id

## Структура данных

```
reports/<test_id>/
  meta.yaml                        ← описание испытания
  protocols.yaml                   ← credentials VPN-протоколов
  server-solo-<ts>.json.gz         ← solo отчёт
  server-listener-<session>-<ts>.json.gz ← listener отчёты
baseline/
  latest.json                      ← эталон от control-контейнера
```
