# Censprobe

Censprobe — измерительная платформа для оценки качества и устойчивости серверов к сетевым блокировкам (ТСПУ) в России. Инструмент автоматически проверяет достижимость серверов по VPN-протоколам (с учётом DPI) и оценивает качество аплинка сервера (отсутствие BGP-блэкхолов, SNI-блокировок и троттлинга).

Все тесты работают автономно через Docker Compose, а результаты агрегируются в локальный репозиторий для визуализации в Grafana. Подробное описание архитектуры и методологии: [docs/passport.md](docs/passport.md).

## Системные требования

- **Docker + Docker Compose** (v2.20+) на всех машинах.
- **SSH Deploy Key**: сгенерируйте ed25519-ключ на каждой машине и добавьте его в GitHub-репозиторий как *Deploy Key* с write-доступом.

## Архитектура развертывания

Система состоит из 6 независимых компонентов (профилей Docker), запускаемых на разных машинах:

| Профиль | Где запускается | Назначение |
|-----------|-----------------|------------|
| `solo` | RU-сервер | Тестирует видимость публичных ресурсов из аплинка сервера |
| `listener` | RU-сервер | Запускает dummy-респондеры 6 VPN-протоколов для приёма handshake от клиента |
| `client` | Клиентское устройство | Пытается подключиться к listener по VPN-протоколам |
| `control` | Чистый EU-сервер | Генерирует эталонный baseline |
| `dashboard` | Любая машина | Локальная аналитика в Grafana |
| `reporter` | Любая машина | Генерация HTML/PDF-отчётов |

---

## Быстрый старт: Запуск тестов

Тестирование конкретного сервера всегда начинается с прогона **solo**, затем переходит в фазу тестирования VPN-протоколов связкой **listener + client**. Соблюдайте порядок.

### Шаг 1. Тест аплинка (Solo)

Запускается на тестируемом RU-сервере. Отвечает на вопрос: *«Заблокировано ли что-то на аплинке провайдера сервера?»*

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

TEST_ID=selectel-spb-001 docker compose --profile solo up --build
```

> Дождитесь завершения. Отчёт загрузится в репозиторий автоматически.

### Шаг 2. Ожидание подключений (Listener)

Запускается на тестируемом RU-сервере **после** solo. Слушает VPN-порты (OpenVPN, WireGuard, AmneziaWG, Shadowsocks, VLESS+Reality, Hysteria 2).

```bash
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up --build
```

> Listener генерирует credentials и ожидает подключений от Client. После того как Client отработал, нажмите `Ctrl+C` — Listener сохранит и запушит результаты тестирования с этой сессии.

### Шаг 3. Имитация подключения (Client)

Запускается на клиентской машине (ноутбук, мобильный интернет).

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  SERVER_HOST=1.2.3.4 \
  docker compose --profile client up --build
```

> **SERVER_HOST** — IP-адрес тестируемого RU-сервера. Client попробует подключиться по 6 протоколам. После его завершения перейдите в терминал сервера и нажмите `Ctrl+C` в процессе Listener.

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

**Как добавить новый сайт:**

1. Откройте нужный файл в `targets/`.
2. Добавьте домен по аналогии с существующими.
3. Сделайте `git commit` и `git push`.
4. Запустите `control` для обновления эталонного baseline.

Порты протоколов настраиваются в `protocols/default.yaml`, отпечатки блокировок — в `signatures/`.

---

## Дашборд и отчёты

### Локальная аналитика (Grafana)

Запускается на любой машине с SSH-доступом к репозиторию:

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

docker compose --profile dashboard up --build -d
```

1. Откройте `http://localhost:3000` (логин: `admin`, пароль: `admin`).
2. Нажмите **Pull & Refresh** на главном дашборде для загрузки результатов из GitHub.
3. Дашборд **Server Suitability** — результаты одного сервера. **Compare Tests** — сравнение двух серверов.

### Экспорт в HTML/PDF

Статичный отчёт для конкретного тестирования:

```bash
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter
# С PDF: добавьте флаг --pdf
TEST_ID=selectel-spb-001 docker compose --profile reporter run --rm reporter --pdf
```

Отчёты сохраняются в `reports/<TEST_ID>/`.

---

## Эталонный Baseline (Control)

Для того чтобы отличить блокировку ТСПУ от реальной недоступности сайта (например, 403 от самого ресурса), Censprobe сравнивает результаты с эталонным *baseline*.

Baseline генерируется профилем **control**, который нужно периодически запускать на чистом зарубежном сервере (например, в Германии).

```bash
# Выполнять на DE/NL сервере, минимум раз в 1-2 недели
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

RUNS_COUNT=5 CONTROL_ID=control-de-01 \
  docker compose --profile control up --build
```

Эталон сохранится в `baseline/latest.json`. Рекомендуется обновлять его перед проведением серии тестов новых серверов.

---

## Ручная публикация результатов (при недоступности GitHub)

Если `git push` не удаётся (GitHub заблокирован из текущей сети, сетевые ограничения), система уведомит вас об этом и предложит действия. Все результаты всегда сохраняются локально.

### Вариант 1: Повторный push

Результаты зафиксированы в локальном git-коммите. При восстановлении связи:

```bash
cd /workspace   # или каталог репозитория
git push
```

### Вариант 2: Ручное копирование файлов

Если доступ к GitHub невозможен на данной машине, скопируйте файлы отчётов вручную:

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

| Переменная | Профили | Описание |
|------------|---------|----------|
| `TEST_ID` | solo, listener, client, reporter | Идентификатор сервера (например, `selectel-spb-001`) |
| `SESSION_ID` | listener, client | Идентификатор сети клиента (например, `client-home-rt-spb`) |
| `SERVER_HOST` | client | IPv4-адрес сервера с Listener |
| `RUNS_COUNT` | solo, control | Количество повторных замеров (Solo: 3, Control: 5) |
| `CONTROL_ID` | control | Идентификатор эталонного сервера (по умолчанию: `control-de-01`) |
| `CONTROL_COUNTRY` | control | Страна эталонного сервера (по умолчанию: `DE`) |
| `DB_PASSWORD` | dashboard | Пароль PostgreSQL (по умолчанию: `censprobe`) |
| `GRAFANA_PASSWORD` | dashboard | Пароль администратора Grafana (по умолчанию: `admin`) |

SSH-ключи монтируются через volume: `~/.ssh:/root/.ssh:ro`.

---

## Структура репозитория

```
censprobe/
├── docker-compose.yml          # профили: solo, listener, client, control, dashboard, reporter
├── packages/                   # код всех контейнеров
│   ├── probe-core/             # общая библиотека измерений
│   ├── solo/
│   ├── listener/
│   ├── client/
│   ├── control/
│   ├── reporter/
│   └── dashboard/
├── targets/                    # что тестировать (YAML)
├── signatures/                 # отпечатки блокировок
├── protocols/                  # конфигурация VPN-протоколов
│   └── default.yaml
├── baseline/                   # эталон от control-контейнера
│   ├── latest.json
│   └── archive/
├── reports/                    # отчёты испытаний
│   └── <test_id>/
│       ├── meta.yaml
│       ├── protocols.yaml
│       └── *.json.gz
└── docs/
    └── passport.md             # архитектурная спецификация
```
