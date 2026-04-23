# Censprobe

Censprobe — это измерительная платформа для оценки качества и устойчивости серверов к сетевым блокировкам (ТСПУ) в России. Инструмент автоматически проверяет достижимость серверов по VPN-протоколам (с учетом DPI) и оценивает качество аплинка сервера (отсутствие BGP-блэкхолов, SNI-блокировок и троттлинга).

Все тесты работают автономно через Docker Compose, а результаты агрегируются в локальный репозиторий для удобной визуализации в Grafana. Более подробное описание архитектуры и методологии читайте в паспорте проекта: [docs/passport.md](docs/passport.md).

> **Status: Production Ready** ✅

## Системные требования

- **Docker + Docker Compose** (v2.20+) на всех машинах.
- **SSH Deploy Key**: Сгенерируйте ed25519 ключ на серверах тестирования и добавьте его в GitHub-репозиторий как *Deploy Key* с write-доступом.

## Архитектура развертывания

Система состоит из 5 независимых компонентов (профилей Docker), запускаемых на разных машинах:
1. **solo** — (на RU-сервере) Тестирует видимость публичных ресурсов из аплинка сервера.
2. **listener** — (на RU-сервере) Запускает dummy-респондеры 6-ти VPN-протоколов, готовых принять handshake от клиента.
3. **client** — (на клиентском устройстве) Пытается подключиться к listener по VPN-протоколам.
4. **control** — (на чистом EU-сервере) Генерирует эталонный baseline.
5. **dashboard** — (любая машина) Локальная аналитика в Grafana.

---

## 🛠 Быстрый старт: Запуск тестов

Тестирование конкретного сервера всегда начинается с прогона **solo**, а затем переходит в фазу тестирования VPN-протоколов связкой **listener + client**. Обязательно соблюдайте порядок!

### Шаг 1. Тест аплинка (Solo)
Запускается на тестируемом RU-сервере. Отвечает на вопрос: *«Заблокировано ли что-то прямо на аплинке провайдера сервера?»*

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

TEST_ID=selectel-spb-001 docker compose --profile solo up --build
```
> Дождитесь завершения. Отчет загрузится в репозиторий автоматически.

### Шаг 2. Ожидание подключений (Listener)
Запускается на тестируемом RU-сервере **после** solo. Слушает VPN-порты (OpenVPN, WireGuard, AmneziaWG, Shadowsocks, VLESS, Hysteria 2).

```bash
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up --build
```
> Listener генерирует credentials и ожидает подключений от Client. После того как Client отработал, нажмите `Ctrl+C` — Listener сохранит и запушит результаты тестирования с этой конкретной сессии.

### Шаг 3. Имитация подключения (Client)
Запускается на клиентской машине (ноутбук, мобильный интернет).

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

TEST_ID=selectel-spb-001 SERVER_HOST=1.2.3.4 \
  docker compose --profile client up --build
```
> **SERVER_HOST** — IP-адрес тестируемого RU-сервера. Client попробует "пробить" 6 протоколов. После его завершения, перейдите в терминал сервера и нажмите `Ctrl+C` в процессе Listener.

---

## ⚙️ Настройка целей тестирования (Targets)

Censprobe позволяет легко изменять список проверяемых ресурсов. Все цели хранятся в папке `targets/` в формате YAML:
- `targets/news.yaml` (СМИ)
- `targets/social.yaml` (Соцсети)
- `targets/messengers.yaml` (Мессенджеры)
- `targets/vpn.yaml` (VPN-сервисы)
- `targets/telegram.yaml` (DC Telegram)

**Как добавить новый сайт:**
1. Откройте нужный файл в `targets/`.
2. Добавьте домен по аналогии с существующими.
3. Сделайте `git commit` и `git push`.
4. Запустите `control` для обновления эталонного baseline, чтобы система знала, как должен отвечать новый сайт!

Вы также можете изменять порты протоколов в `protocols/default.yaml` и обновлять отпечатки блокировок в `signatures/`.

---

## 📊 Дашборд и Отчеты

### Локальная аналитика (Grafana)
Вы можете запустить интерфейс на любой машине, у которой есть SSH-ключ для доступа к GitHub-репозиторию:

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

docker compose --profile dashboard up --build -d
```
1. Откройте `http://localhost:3000` (логин: `admin`, пароль: `admin`).
2. Нажмите кнопку **Pull & Refresh** на главном дашборде, чтобы подтянуть результаты из GitHub.
3. Используйте дашборд **"Server Suitability"** для просмотра результатов по одному серверу, или **"Compare Tests"** для сравнения двух серверов (провайдеров) между собой.

### Экспорт в HTML/PDF
Вы можете сгенерировать статичный отчет для конкретного тестирования:

```bash
TEST_ID=selectel-spb-001 FORMAT=html,pdf \
  docker compose --profile reporter run --rm reporter
```
Отчеты сохраняются в папку: `reports/<TEST_ID>/render/`.

---

## 🧭 Эталонный Baseline (Control)

Для того чтобы отличить блокировку ТСПУ от реальной недоступности сайта (например, 403 ошибка самого ресурса), Censprobe сравнивает результаты с эталонным *baseline*. 

Baseline генерируется профилем **control**, который нужно периодически запускать **на чистом зарубежном сервере** (например, в Германии).

```bash
# Выполнять на DE/NL сервере, минимум раз в 1-2 недели
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe

RUNS_COUNT=5 CONTROL_ID=control-de-01 \
  docker compose --profile control up --build
```
Эталон сохранится в `baseline/latest.json`. Рекомендуется обновлять его перед проведением большой серии тестов новых серверов.

---

## Переменные окружения

| Переменная | Профили | Описание |
|------------|---------|----------|
| `TEST_ID` | solo, listener, client, reporter | Идентификатор сервера (например, `selectel-spb-001`) |
| `SESSION_ID` | listener, client | Идентификатор сети клиента (например, `client-home-rt`) |
| `SERVER_HOST` | client | Прямой IPv4-адрес сервера с Listener |
| `RUNS_COUNT` | solo, control | Кол-во повторных замеров (Solo=3, Control=5) |
| `CONTROL_ID` | control | Идентификатор эталонного сервера (default: `control-de-01`) |
| `CONTROL_COUNTRY` | control | Страна эталонного сервера (default: `DE`) |
| `DB_PASSWORD` | dashboard | Пароль базы PostgreSQL (default: `censprobe`) |
| `GRAFANA_PASSWORD` | dashboard | Пароль администратора Grafana (default: `admin`) |

*Ключи SSH всегда монтируются через volume: `~/.ssh:/root/.ssh:ro`.*
