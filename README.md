# Censprobe

**Censprobe** — инструмент измерения цензуры и оценки устойчивости серверов к сетевым блокировкам в России и других странах с глубокой инспекцией трафика. Автоматически проверяет видимость публичных ресурсов с аплинка сервера, тестирует семь протоколов обхода цензуры через DPI и атрибутирует троттлинг и SNI-блокировки.

Все компоненты работают автономно через Docker Compose, результаты сохраняются в `reports/<TEST_ID>/` локально и публикуются вручную (`git push`). Grafana собирает дашборды из импортированных отчётов.

**Что почитать:**
- [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — гайд для разработки самого censprobe (тесты локально, CI, правила).
- [`docs/TESTING.md`](docs/TESTING.md) — методология тестирования: layer cake, инструменты, anti-patterns.
- [`docs/TEST_COVERAGE.md`](docs/TEST_COVERAGE.md) — карта покрытия: какой тест что покрывает + CI quality gates.

---

## Содержание

- [Архитектура развёртывания](#архитектура-развёртывания)
- [Что измеряется](#что-измеряется)
- [Vantage (важно)](#vantage-важно)
- [Первоначальная настройка](#первоначальная-настройка)
- [Быстрый старт: запуск тестов](#быстрый-старт-запуск-тестов)
- [CLI-параметры](#cli-параметры)
- [Конфигурация: `censprobe.yaml`](#конфигурация-censprobeyaml)
- [Цели тестирования: `targets/`](#цели-тестирования-targets)
- [Семь VPN-протоколов](#семь-vpn-протоколов)
- [Восемь модулей измерения](#восемь-модулей-измерения)
- [Скоринг](#скоринг)
- [Дашборд (Grafana)](#дашборд-grafana)
- [Переменные окружения (`.env`)](#переменные-окружения-env)
- [Структура отчётов](#структура-отчётов)
- [CI/CD и quality gates](#cicd-и-quality-gates)
- [Публикация результатов](#публикация-результатов)
- [Контрибуция отчётов](#контрибуция-отчётов)
- [Разработка проекта](#разработка-проекта)
- [Структура репозитория](#структура-репозитория)
- [Контракт: конфиг — последняя истина](#контракт-конфиг--последняя-истина)

---

## Архитектура развёртывания

Система состоит из 4 независимых компонентов (Docker-профилей), запускаемых на разных машинах:

| Профиль | Где запускается | Назначение |
|---------|-----------------|------------|
| `solo` | RU-сервер | Прогон всех восьми модулей измерения с перспективы аплинка тестируемого сервера |
| `listener` | RU-сервер | Поднимает dummy-respondery 7 VPN-протоколов + одноразовый HTTPS-эндпоинт credentials |
| `client` | Клиентское устройство | Подключается к listener'у по 7 протоколам, проверяет handshake + throughput |
| `dashboard` | Любая машина | Локальная аналитика: PostgreSQL + sync-api + Grafana |

Все 4 компонента — отдельные Docker-образы (`censprobe-solo`, `censprobe-listener`, `censprobe-client`, `censprobe-sync-api`), публикуются на Docker Hub под namespace `${DOCKERHUB_USERNAME}` (по умолчанию `outtakes`).

---

## Что измеряется

Все вердикты считаются inline в момент прогона (не post-hoc):

- **DNS** — CERTainty-style (PETS 2023): валидность TLS-сертификата на возвращённом IP + согласие с публичными DoH/DoT-резолверами.
- **TCP reachability** — `OK` / `IP_DROPPED` (SYN/timeout = null-route) / `REFUSED` (legitimate RST). В RU vantage быстрый RST атрибутируется как `SUSPECTED RST_INJECTED` (DPI-инъекция).
- **TLS / SNI** — paired blocked-SNI / neutral-SNI handshake в одном прогоне; ECH-проба отдельно.
- **HTTP** — `expected_status` из `targets/*.yaml` + отдельный `GEOBLOCK_NOT_CENSORSHIP` вердикт для 403/451 с валидным TLS (geoblock от провайдера, не цензура).
- **SNI throttling (Method B)** — Vetrov/Habr 2024: три curl-прогона на один IP с разными SNI (correct / trigger=`googlevideo.com` / typo). Относительная разница bandwidth внутри одного запуска устойчива к разной ширине uplink'а.
- **Telegram reconcile** — DC IPv4/IPv6 на 443/80/5222, web/CDN, owned-cert match. Если cert chain валиден И SAN/CN попадает в `owned_cert_patterns` — это аутентичный Telegram-эндпоинт с misrouted cert (cdn1/cdn5 globally broken), не цензура. Reclassified `BLOCKED` → `INCONCLUSIVE`.
- **Cloudflare/WARP/QUIC** — QUIC vn-trigger (UDP 443), WARP TCP control plane, MASQUE и WireGuard UDP fallback. QUIC-таймаут → `QUIC_DROPPED` (только в RU vantage).
- **Middlebox / DPI** — OONI-style HTTP Header Field Manipulation + HTTP Invalid Request Line.

---

## Vantage (важно)

Часть атрибуции откалибрована **для RU-вантажа**. По умолчанию censoring vantages: `[RU, BY]` (`vantage.censoring_countries` в `censprobe.yaml`).

- `tcp.py` помечает быстрый RST как `RST_INJECTED` (только в censoring vantage; вне — heuristic отключён, downgrade в `REFUSED`).
- `cloudflare.py` помечает QUIC-таймаут на UDP 443 как `QUIC_DROPPED` (только в censoring vantage).
- `throttling.py` (Method B против `speedtest.selectel.ru`) полностью пропускается вне censoring vantage — относительная разница bandwidth доминируется географией, а не SNI-policy. Эмитит один `INCONCLUSIVE` маркер с `evidence.reason=non_censoring_vantage_method_b_skipped`.

Vantage определяется автоматически из `country_code` ipapi.is enrichment в `solo` и пробрасывается через `set_vantage_country()` в общий probe-core. Если запускаете solo с не-RU VM (Frankfurt, Vultr и т.д.), увидите больше `INCONCLUSIVE`-вердиктов в throttling/QUIC — это by design.

Для тестов из CN/IR/KZ — расширьте `vantage.censoring_countries` в `censprobe.yaml`. Можно форсировать страну через `vantage.override` (для тестирования heuristics или туннелированного хоста).

---

## Первоначальная настройка

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/censprobe.git
cd censprobe
```

Файл `.env` в репо коммитится с safe defaults для localhost-only сервисов (Postgres / Grafana) — `docker compose up` работает out of the box. Если разворачиваете dashboard на машине, до которой кто-то может дотянуться по сети, перегенерируйте пароли локально:

```bash
# Сгенерировать пароль для Postgres
sed -i -E "s/^DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -base64 24)/" .env
# Установить Grafana admin пароль
sed -i -E "s/^GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$(openssl rand -base64 16)/" .env
```

Опционально — ASN/geo enrichment через ipapi.is:

```bash
# Получить бесплатный ключ на https://ipapi.is/, тогда solo и listener получат
# обогащённый country_code + ASN. Без ключа всё работает, но через rate-limited
# free tier с меньшей точностью.
sed -i "s/^IPAPI_IS_KEY=$/IPAPI_IS_KEY=<your_key>/" .env
```

Образы публикуются в публичный Docker Hub — `docker login` для pull не требуется.

---

## Быстрый старт: запуск тестов

Тестирование сервера всегда начинается с прогона **solo**, затем переходит в фазу listener+client. Соблюдайте порядок: открытие VPN-портов в `listener` после `solo` исключает влияние на outbound-фильтрацию.

### Шаг 1. Solo (RU-сервер)

```bash
docker compose --profile solo run --rm solo --test-id selectel-spb-001
```

Прогоняет восемь модулей измерения (DNS, TCP, TLS, HTTP, throttling, telegram, cloudflare, middlebox). Отчёт → `reports/<TEST_ID>/server-solo-<timestamp>.json`.

`TEST_ID`: формат `<provider>-<city>-<NN>` (например `selectel-spb-001`, `vultr-fra-002`). Валидируется регуляркой `[A-Za-z0-9_.-]{1,64}` — кириллица/пробелы/`/` отклоняются click'ом ещё до запуска (защита от path traversal).

### Шаг 2. Listener (RU-сервер, после solo)

```bash
docker compose --profile listener run --rm listener \
  --test-id selectel-spb-001 \
  --session-id client-home-rt-spb
```

Listener генерирует одноразовые credentials в памяти, поднимает все respondery (OpenVPN UDP, WireGuard UDP, AmneziaWG UDP, Shadowsocks 2022 TCP, VLESS+Reality TCP, Hysteria 2 UDP, MTProto-proxy TCP), запускает HTTPS endpoint для credentials на `CREDS_PORT` (по умолчанию 8443/tcp) и **печатает готовую команду для запуска client'а**. Скопируйте её — она содержит TEST_ID, SESSION_ID, SERVER_HOST, CREDS_TOKEN и CREDS_CERT_SHA256.

> Открытый порт **8443/tcp** должен быть доступен с клиентской сети. Credentials живут только в памяти процесса, на диск не пишутся.

`SESSION_ID`: формат `client-<тип>-<провайдер>-<город>`:
- `client-home-rt-spb` — домашний Ростелеком, СПб
- `client-mob-mts-msk` — мобильный МТС, Москва
- `client-wifi-cafe-msk` — публичный Wi-Fi

### Шаг 3. Client (клиентская машина)

На клиентской машине (ноутбук, мобильный интернет) откройте локальную копию репо и **вставьте команду, напечатанную listener'ом**. Команда — одна строка, идентично работает в bash/zsh, PowerShell, cmd.exe (CLI-аргументы docker'а):

```
docker compose --profile client run --rm client \
  --test-id selectel-spb-001 \
  --session-id client-home-rt-spb \
  --server-host 1.2.3.4 \
  --creds-port 8443 \
  --creds-token <one-time-token> \
  --creds-cert-sha256 <sha256-fingerprint>
```

Client тянет credentials с listener'а через TLS-pinning (cert проверяется по SHA-256), bearer-token проверяется через `hmac.compare_digest`, потом пробует все 7 протоколов с opsec-jitter (0.5–3 с между пробами). Probe для каждого протокола различает `OK`, `HANDSHAKE_ONLY` (handshake прошёл, но throughput не подтверждён), `BLOCKED`, `ERROR`.

После завершения клиента — вернитесь в терминал сервера и нажмите `Ctrl+C` в процессе Listener. Listener сохранит отчёт в `reports/<TEST_ID>/server-listener-<SESSION_ID>-<timestamp>.json`.

### Шаг 4. Дополнительные клиентские сети

Просто перезапустите listener с новым `SESSION_ID` — он напечатает свежую команду с новыми credentials/cert/token.

---

## CLI-параметры

### `solo`

```
docker compose --profile solo run --rm solo [OPTIONS]

  --test-id TEXT          Test identifier (e.g. selectel-spb-001)  [required]
                          [env: TEST_ID]
  --repeats INTEGER       Number of test repeats per measurement   [required]
                          [env: RUNS_COUNT, default: 3]
  -v, --verbose           Verbose logging
```

### `listener`

```
docker compose --profile listener run --rm listener [OPTIONS]

  --test-id TEXT          Test identifier (must match solo report) [required]
                          [env: TEST_ID]
  --session-id TEXT       Client network session ID, e.g. client-home-rt-spb
                          [required] [env: SESSION_ID]
  --creds-port INTEGER    Port for credentials HTTPS endpoint      [required]
                          [env: CREDS_PORT, default: 8443]
  -v, --verbose           Verbose logging
```

### `client`

```
docker compose --profile client run --rm client [OPTIONS]

  --test-id TEXT              Test identifier (must match listener) [required]
                              [env: TEST_ID]
  --session-id TEXT           Your session label                    [required]
                              [env: SESSION_ID]
  --server-host TEXT          IP of the server running listener     [required]
                              [env: SERVER_HOST]
  --creds-port INTEGER        Listener creds HTTPS port             [required]
                              [env: CREDS_PORT]
  --creds-token TEXT          One-shot bearer token (printed by listener)
                              [required] [env: CREDS_TOKEN]
  --creds-cert-sha256 TEXT    SHA-256 fingerprint of listener cert  [required]
                              [env: CREDS_CERT_SHA256]
  --no-jitter                 Disable opsec jitter between probes
                              (faster, less stealthy)
  -v, --verbose               Verbose logging
```

`SERVER_HOST` принимается как IPv4/IPv6 — client **не делает DNS-резолва** (anti-correlation: имя сервера никогда не пересекает client-side resolver).

---

## Конфигурация: `censprobe.yaml`

Все runtime-knob'ы — в одном файле в корне. Парсится в `CensprobeConfig` (`packages/probe-core/src/censprobe_core/config.py`). **Каждое поле обязательно** (`extra="forbid"` на всех sub-моделях): опечатка или отсутствие = fatal startup error с указанием поля. Никаких silent fallback'ов.

### `vantage`

| Поле | Тип | Описание |
|------|-----|----------|
| `censoring_countries` | `list[str]` | ISO-3166 alpha-2 коды стран, где включаются censor-specific эвристики. Дефолт `[RU, BY]`. Расширяйте при тестах из CN/IR/KZ. |
| `override` | `str \| null` | Форсирует код страны независимо от ipapi.is auto-detection. Полезно при тестах из туннелированного хоста. |

### `modules.<name>`

Все 8 модулей разделяют `enabled: bool`. Отключённый модуль не отдаёт результаты в дашборд.

| Модуль | Поля (помимо `enabled`) |
|--------|-------------------------|
| `dns` | `repeats`, `doh_resolvers` (list of DoH URLs), `doh_timeout_sec`, `asn_lookup_backoff_sec` |
| `tcp` | `repeats`, `syn_timeout_sec`, `fast_rst_threshold_ms` (RTT below = SUSPECTED RST_INJECTED), `max_parallel` |
| `tls` | `repeats`, `timeout_sec`, `max_parallel` |
| `http` | `repeats`, `body_cap_bytes`, `timeout_connect_sec`, `timeout_read_sec`, `max_parallel` |
| `telegram` | `targets_file` (basename without .yaml), `timeout_sec` |
| `cloudflare` | `targets_file` |
| `throttling` | `require_censoring_vantage`, `target_url`, `correct_sni`, `typo_sni`, `trigger_sni`, `sequential_runs`, `bandwidth_ratio_threshold`, `curl_timeout_sec` |
| `middlebox` | (placeholder — только `enabled`) |

### `protocols`

| Поле | Описание |
|------|----------|
| `enabled` | Список протоколов, которые listener реально поднимает. Имена не из `protocol_registry` дропаются с warning'ом. |
| `priority` | Порядок first-match-wins для recommendation'а в scoring summary. |
| `ports` | `dict[name, port]`. Validator `_check_ports_cover_enabled` гарантирует: каждый enabled-протокол имеет порт, нет orphan port-entry, все порты в `1..65535`. |

### `throughput`

Sustained-data probe через SOCKS-routed протоколы (Shadowsocks, VLESS+Reality, Hysteria 2). OpenVPN/WireGuard/AmneziaWG игнорируют (handshake-only).

| Поле | Описание |
|------|----------|
| `target_bytes` | Байт для трансфера (1 MiB = 1048576). |
| `timeout_sec` | Транспорт таймаут. Floor "throttled" detection. |

### `scoring`

Линейная комбинация. `score = sum(component·weight) × 100` ∈ `[0, 100]`.

| Sub | Поля | Формула |
|-----|------|---------|
| `entry` | `protocol`, `uplink`, `latency` | `entry = protocol·W_p + uplink·W_u + latency·W_l` |
| `exit` | `uplink`, `censorship` | `exit = uplink·W_u + censorship·W_c` |
| `relay` | `tcp`, `latency` | `relay = tcp·W_t + latency·W_l` |

Веса в дефолте: `entry=(0.6, 0.3, 0.1)`, `exit=(0.6, 0.4)`, `relay=(0.7, 0.3)`. Не обязаны суммироваться в 1.

### `targets`

| Поле | Описание |
|------|----------|
| `directory` | Путь к директории targets (дефолт `targets`). |
| `files` | Если непуст — explicit basenames (без `.yaml`); иначе auto-discovery `*.yaml`. |
| `module_owned` | Basenames, потребляемые только специализированными модулями (исключаются из generic dns/tcp/tls/http view). Дефолт `[telegram, cloudflare]`. |

---

## Цели тестирования: `targets/`

Все YAML в `targets/` подбираются автоматически runner'ом и валидируются против `TargetFile` (permissive — `extra="allow"`, union-of-shapes).

| Файл | Что внутри | Кем потребляется |
|------|------------|------------------|
| `targets/news.yaml` | СМИ (`meduza.io`, `novayagazeta.eu`, `mediazona.ca`, `tvrain.ru`, ...) | dns/tcp/tls/http (generic) |
| `targets/social.yaml` | Соцсети (`youtube.com`, `instagram.com`, `facebook.com`, `twitter.com`, ...) | dns/tcp/tls/http |
| `targets/messengers.yaml` | Мессенджеры (`signal.org`, `whatsapp.com`, `web.whatsapp.com`, `discord.com`, ...) | dns/tcp/tls/http |
| `targets/vpn.yaml` | VPN-провайдеры (`nordvpn.com`, `protonvpn.com`, `expressvpn.com`, `mullvad.net`) | dns/tcp/tls/http |
| `targets/neutral.yaml` | Нейтральные (`vk.com`, `yandex.ru`, `wikipedia.org`, `google.com`) + anycast TCP-цели на 443/853 | dns/tcp/tls/http (negative control) |
| `targets/telegram.yaml` | DC IPv4/IPv6 + ports, web/aux/CDN-домены, `owned_cert_patterns`, `health_weights` | **только `modules.telegram`** (`module_owned`) |
| `targets/cloudflare.yaml` | QUIC/WARP TCP/WARP UDP/HTTP цели Cloudflare | **только `modules.cloudflare`** (`module_owned`) |

**Как добавить новый сайт**: открыть нужный файл (например `targets/news.yaml`), добавить запись с полями `domain`, `urls` (list), `expected_status`, `category`, `ech_advertised`, `notes`. Pydantic провалидирует, runner подхватит автоматически.

**Как добавить новый файл**: положите `targets/<my>.yaml` со схемой `targets: [...]` (или другие поля из `TargetFile`). Auto-discovery + pydantic validate включит на следующем запуске.

**TelegramDC.ports — обязательное поле** (с момента aудита mai 2026): silent default `[443]` удалён, чтобы typo'd `port: 443` (singular) не падал в `extra="allow"` без проверки.

---

## Семь VPN-протоколов

`packages/probe-core/src/censprobe_core/protocol_registry.py` — single source of truth.

| Имя | Label | Transport | Default port | uses_socks_echo |
|-----|-------|-----------|---------------|-----------------|
| `openvpn` | OpenVPN | UDP | 1194 | False |
| `wireguard` | WireGuard | UDP | 51820 | False |
| `amneziawg` | AmneziaWG | UDP | 51821 | False |
| `shadowsocks` | Shadowsocks 2022 | TCP | 8388 | True |
| `vless_reality` | VLESS+Reality | TCP | 443 | True |
| `hysteria2` | Hysteria 2 | UDP | 443 | True |
| `mtproto_proxy` | MTProto Proxy | TCP | 9443 | False |

Поле `uses_socks_echo` отмечает протоколы с SOCKS-routed data-phase через listener echo server (для throughput-проб). Остальные — handshake-only.

Параметры VPN-протоколов (порты, ключи, AmneziaWG-обфускация — H1..H4 magic headers, S1/S2 junk-payload sizes, jc/jmin/jmax counters) генерируются `listener` в памяти при каждом старте через реальные бинари (`wg genkey`/`wg pubkey`/`wg genpsk`, `xray x25519`, `openvpn --genkey secret`). Передаются клиенту через одноразовый TLS-pinned эндпоинт; на диск ничего не пишется и в git ничего не коммитится.

**Контракт credentials**: каждое поле каждой секции YAML — обязательное (port, server_public_key, client_*_key, preshared_key, method, server_name, AWG h1..h4 + s1/s2/jc/jmin/jmax, hy2_auth, mtproxy_secret и т.д.). Парсер `parse_protocols_yaml` (`packages/probe-core/src/censprobe_core/credentials_reader.py`) raises `ValueError` при пропуске любого поля — listener и client деплоятся в lockstep одной compose-сборкой, schema mismatch значит баг.

**Как добавить новый протокол** (например, TUIC, Trojan):

1. Дополнить `ProtocolSpec` в `packages/probe-core/src/censprobe_core/protocol_registry.py`.
2. Добавить responder в `packages/listener/src/censprobe_listener/_responder_dispatch.py`.
3. Добавить probe-coroutine в `packages/probe-core/src/censprobe_core/protocol_probes.py` + dispatch в `packages/client/src/censprobe_client/_probe_dispatch.py`.
4. Расширить `ProtocolCredentials` (listener `credentials.py` + probe-core `credentials_reader.py`) — `_required_str` / `_required_int` хелперы для всех новых полей.
5. Включить в `protocols.enabled` + добавить в `protocols.ports` в `censprobe.yaml`.
6. Если нужны новые бинари — добавить в Dockerfile listener'а (`packages/listener/Dockerfile`).

---

## Восемь модулей измерения

`packages/probe-core/src/censprobe_core/modules/`. Все async, регистрируются через `module_registry.py`. Phase: `parallel` (dns/tcp/tls/http/throttling/telegram/cloudflare/middlebox запускаются параллельно через `asyncio.gather(return_exceptions=True)`); упавший модуль отображается в `module_failures` summary, не сабатирует остальное.

### `dns.py`
Per-domain ladder: системный resolver → ISP upstream (parsed from `/etc/resolv.conf` или systemd-resolved) → public 8.8.8.8 / 1.1.1.1 / 77.88.8.8 (Yandex) / 9.9.9.9 (Quad9) → DoH (`cloudflare-dns.com`, `dns.google`, `mozilla.cloudflare-dns.com`) → DoT (`1.1.1.1:853`, `8.8.8.8:853`). Для каждого IP — TLS-cert validation (CERTainty-style). Обогащение через `ipapi.is` (опционально через `IPAPI_IS_KEY`).

### `tcp.py`
Direct (ip, port) reachability с repeats. Verdicts: `OK` / `IP_DROPPED` (SYN timeout) / `REFUSED` (legitimate RST). В censoring vantage RTT ниже `fast_rst_threshold_ms` атрибутируется как `SUSPECTED RST_INJECTED`. `_majority` aggregator для устранения шума.

### `tls.py`
Paired handshake per (IP, domain): `tls_<domain>_sni_blocked` (SNI=domain, system trust store), `tls_<domain>_sni_neutral` (SNI=cloudflare.com, контроль того же IP в том же запуске), плюс ECH-проба. `_attribute_tls_failure` различает SNI-блокировку, cert-mismatch и network error.

### `http.py`
GET/HEAD с `expected_status` из targets. `_verdict_from_response`:
- 200 + ожидаемый статус → `OK`
- 403/451 + valid TLS → `GEOBLOCK_NOT_CENSORSHIP` (порядок проверок load-bearing)
- неожиданный статус → `BLOCKED` с network attribution
- timeout/connection-reset → `BLOCKED` (DPI/middlebox)

Body cap (`body_cap_bytes`, дефолт 512 KB) защита от bandwidth abuse при тестах через медленные uplink'и.

### `throttling.py`
Method B (Vetrov/Habr 2024). Vantage-gated через `require_censoring_vantage`. Три curl-прогона:
- `--connect-to <correct_sni>:<correct_sni>` (control)
- `--connect-to <correct_sni>:<trigger_sni>` (`trigger_sni=googlevideo.com`)
- `--connect-to <correct_sni>:<typo_sni>` (`typo_sni=googleviideo.com`)

Verdict `YOUTUBE_SNI_THROTTLED` если `bw_trigger < bandwidth_ratio_threshold × min(bw_correct, bw_typo)`. Robust к разной ширине uplink'а — относительная разница в одном запуске.

### `telegram.py`
DC reachability (5 DC × {v4, v6} × {443, 80, 5222}) + Web (`web.telegram.org`, `webk.telegram.org`, `weba.telegram.org`) + CDN (`cdn.telegram.org`, ...). MTProto abridged-frame для `_test_dc_port` byte-точно: `b"\xef" + bytes([len//4]) + struct.pack("<qqi", 0, msg_id, 4)`.

`owned_cert_patterns` (RFC 6125 wildcard semantics, single label match): cdn1/cdn5 globally broken (отдают cert на `*.t.me` вместо хоста). Если cert валиден И SAN/CN matches owned pattern — это аутентичный Telegram, не цензура. Reclassified `BLOCKED` → `INCONCLUSIVE`.

`_compute_health_score` — weighted avg `dc:55% / web:25% / cdn:20%` (веса из `health_weights` в `targets/telegram.yaml`).

### `cloudflare.py`
Mixed: QUIC vn-trigger (UDP 443) — `_build_quic_vn_trigger` строит long-header пакет с version=0x00000001 для триггера version negotiation; WARP TCP control plane; WARP UDP/MASQUE — `_build_masque_probe_packet` UDP encap; WireGuard UDP 51820 — `_build_wg_handshake_init` (148-byte payload, message_type=1).

QUIC-таймаут на UDP 443 в censoring vantage → `QUIC_DROPPED` (TSPU-specific behavior).

### `middlebox.py`
OONI-style detection. HTTP Header Field Manipulation: меняет регистр заголовков (`HoSt:` etc), сравнивает echo. HTTP Invalid Request Line: невалидные методы (`GeT`, `XX`), смотрит чьё RST.

---

## Скоринг

`packages/probe-core/src/censprobe_core/scoring.py` — `compute_scores`. Принимает `RunSummary` (агрегат всех модулей) + `protocol_results` (handshake-вердикты), возвращает `Scores`.

`Scores` имеет 4 числа в `[0.0, 100.0]`:

- **`entry_score`** — насколько хорошо клиент может **войти** на сервер (handshake протоколов с client side, latency, uplink reachability).
- **`exit_score`** — насколько хорошо сервер может **выходить** в публичный интернет с RU-вантажа (uplink reachability + censorship pressure).
- **`relay_score`** — TCP-метрики + latency без учёта протоколов (для серверов в роли transit relay, не endpoint).
- **`overall`** — `(entry + exit + relay) / 3`.

Также:
- **`techniques_detected`** — list[BlockingMethod] (DNS_POISONED, RST_INJECTED, SNI_BLOCKED, GEOBLOCK_NOT_CENSORSHIP, QUIC_DROPPED, YOUTUBE_SNI_THROTTLED).
- **`recommended_protocols`** — список протоколов, упорядоченных по `protocols.priority` где handshake прошёл (signature-blocked отфильтрованы).

Веса все настраиваются через `scoring.entry/exit/relay` в `censprobe.yaml`.

---

## Дашборд (Grafana)

Запускается на любой машине с доступом к репозиторию:

```bash
docker compose --profile dashboard up -d
```

1. Откройте `http://localhost:3000`.
2. Логин — `admin`, пароль — из `GRAFANA_PASSWORD` в `.env` (default: `admin`; перегенерируйте при удалённом доступе).
3. Чтобы подтянуть новые отчёты — выполните `git pull` в репо. `sync-api` сканирует `reports/` в фоне (`CENSPROBE_IMPORT_INTERVAL_SEC`, дефолт 60 с) и импортирует новые `.json` в Postgres автоматически.

### Grafana stripped to dashboards-only

В `docker-compose.yml` Grafana настроена как read-only viewer:
- `GF_EXPLORE_ENABLED=false`, `GF_ALERTING_ENABLED=false`, `GF_UNIFIED_ALERTING_ENABLED=false`
- `GF_ANALYTICS_REPORTING_ENABLED=false`, `GF_ANALYTICS_CHECK_FOR_UPDATES=false`
- `GF_USERS_ALLOW_SIGN_UP=false`, `GF_USERS_ALLOW_ORG_CREATE=false`
- `GF_SNAPSHOTS_EXTERNAL_ENABLED=false`, `GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false`

Grafana порт `3000:3000` (всё локально); sync-api на `127.0.0.1:8080:8080` (loopback only — нет auth, единственный потребитель в кластере — Grafana через Postgres datasource).

Postgres + Grafana образы pinned по digest (`postgres:16@sha256:...`, `grafana/grafana:11.5.4@sha256:...`) — minor bumps на Docker Hub не могут silently изменить бинарь.

### Дашборды

| Дашборд | Что показывает |
|---------|----------------|
| **01 — Test Overview** | Censorship Resistance Score, DNS/TLS/Telegram, техники цензуры, рекомендуемые протоколы. Точка входа со ссылками на drill-down |
| **02 — Blocking Matrix** | Полная матрица всех тестов с цветовой раскраской по вердикту |
| **03 — Telegram Deep Dive** | Детальная досягаемость Telegram DC, health score, RTT-распределение |
| **04 — Protocol Reachability** | Матрица досягаемости протоколов по клиентским сессиям + ASN сетей клиентов |
| **05 — Technique Attribution** | Атрибуция техник цензуры (DNS poisoning, RST injection, throttling, middlebox) |
| **06 — Compare Tests** | Сравнение двух серверов: scores, server info, техники |
| **07 — Cloudflare & WARP** | WARP control plane (TCP 443), MASQUE и WireGuard UDP fallback-порты, Cloudflare CDN/HTTP |
| **08 — QUIC & ECH** | QUIC-блокировка (TSPU/UDP 443), ECH-тесты, Hysteria2 досягаемость |
| **09 — DNS Deep Dive** | DNS integrity, DoH-резолверы, DNS poisoning детектирование |
| **10 — TLS Deep Dive** | SNI inspection (paired blocked/neutral SNI), TLS-методы цензуры, RTT |

### sync-api endpoints

FastAPI на `127.0.0.1:8080`:
- `GET /health` — readiness probe.
- `GET /test-runs` — список всех `TestRun` записей.
- `GET /test-runs/{id}` — конкретный `TestRun` + связанные `TestResult`.
- `GET /results/{id}` — все результаты для теста.
- `GET /protocols/{id}` — все `ProtocolResult` для сессии (listener report).

Schema создаётся при первом старте через SQLAlchemy `create_all` (без alembic — single-developer project). Таблицы: `test_runs`, `test_results`, `listener_sessions`, `protocol_results`. Cascade delete при удалении `TestRun`.

---

## Переменные окружения (`.env`)

`.env` — статическая конфигурация (порты, пароли, ключи, тюнинг). Закоммичен в репо с safe defaults для localhost-only сервисов. Per-run параметры (`--test-id`, `--session-id` и т.д.) — CLI-аргументы `docker compose run`, не env.

| Переменная | Профили | Дефолт в `.env` | Описание |
|------------|---------|-----------------|----------|
| `DOCKERHUB_USERNAME` | все | `outtakes` | Docker Hub аккаунт, из которого pull-ятся образы. Поменяйте на свой при fork'е. |
| `DOCKERHUB_TAG` | все | `main` | Тег образа. |
| `CREDS_PORT` | listener, client | `8443` | Порт credentials-эндпоинта на listener'е. |
| `DB_PASSWORD` | dashboard | (случайный 32-hex) | Postgres password. Loopback-only сервис; перегенерируйте при удалённом доступе. |
| `GRAFANA_PASSWORD` | dashboard | `admin` | `GF_SECURITY_ADMIN_PASSWORD` для admin Grafana. Перегенерируйте при удалённом доступе. |
| `DATABASE_URL` | dashboard | (закомментирован) | Опциональный override `sync-api → postgres` URL для external DB. |
| `RUNS_COUNT` | solo | `3` | Количество повторных замеров (solo). |
| `CENSPROBE_IMPORT_INTERVAL_SEC` | dashboard | `60` | Интервал импорта отчётов в Postgres (с). |
| `IPAPI_IS_KEY` | solo, listener | (пустой) | API-ключ ipapi.is для ASN/geo enrichment. Пусто → бесплатный rate-limited tier. Client никогда не делает outbound-вызовов. |

Контейнеры не имеют git/SSH зависимостей — `git push` запускаете вы сами с хоста.

---

## Структура отчётов

```
reports/<TEST_ID>/
├── meta.yaml                                       # auto-detected server info
├── server-solo-<timestamp>.json                    # solo report
├── server-listener-<SESSION_ID>-<timestamp>.json   # listener report (per session)
└── server-listener-<SESSION_ID2>-<timestamp>.json  # ... ещё одна сессия
```

`meta.yaml` — server metadata (kernel, distro, IPv6, country_code, ASN). Auto-detected при первом solo-запуске; кешируется локально, повторные solo-запуски используют cache.

Solo report (`server-solo-*.json`):
- `test_id`, `started_at`, `completed_at`
- `server` — кешированный `meta.yaml`
- `results: list[TestResult]` — все вердикты от 8 модулей
- `scores: Scores` — entry/exit/relay/overall
- `module_failures: dict[str, str]` — модули, упавшие с исключением

Listener report (`server-listener-<SESSION_ID>-*.json`):
- `test_id`, `session_id`, `client` (EndpointMeta — IP-free network identity, country/ASN/network family)
- `protocol_results: list[ProtocolResult]` — handshake/throughput per protocol
- `connection_count`, `handshake_count` — operator status counters

JSON Schema снимки (regen-able через `CENSPROBE_REGENERATE_SCHEMAS=1 pytest tests/snapshots/`) — `tests/snapshots/schemas/solo_report.schema.json`, `listener_report.schema.json`. Pinned против фикстур (`solo_minimal.json`, `solo_full.json`, `listener_full.json`).

---

## CI/CD и quality gates

См. [`docs/TEST_COVERAGE.md`](docs/TEST_COVERAGE.md) для полного списка с конфигурацией. Кратко:

### Required для merge (`ci.yml`)

| Job | Что делает |
|-----|-----------|
| `lint` | ruff (E/F/W/B/I/UP/S), ruff format, yamllint, actionlint, hadolint, mypy strict over `packages/*/src` (47 файлов) |
| `validate-config` | inline `load_config()` + `load_targets()` с promotion warning'ов в errors |
| `test (probe-core)` `test (solo)` `test (listener)` `test (client)` `test (sync-api)` | matrix pytest с `services: postgres:16-alpine` |
| `cross-package-tests` | `pytest tests/contracts tests/snapshots` (Grafana ↔ subcategories, yaml round-trip, wire-format snapshots) |
| `network-tests` | `pytest -m network`, exit 5 → pass (placeholder под live-сети) |
| `e2e-dashboard` | локальный билд sync-api + `docker compose up postgres + sync-api` + `pytest -m e2e` |
| `security-fast` | bandit, pip-audit, gitleaks, dependency-review, trivy filesystem scan |
| `sonar` | SonarCloud Quality Gate (Sonar way: новый код coverage, no new bugs/hotspots/duplicates) |

### Required (`build.yml`, post-CI)

`workflow_run` от CI on main + tag pushes. PR builds с `push: false`. Per-image: paths-filter (rebuild только если затронуты `packages/${path}/**`, `probe-core/**`, или `build.yml`); `docker/build-push-action` с buildkit cache. **Post-build gates**: image size (`solo` ≤ 600 MB, `listener`/`client` ≤ 400 MB, `sync-api` ≤ 250 MB), non-root verification (`sync-api` only).

> **Push разрешён и при sonar-only failure CI.** Перед билдом шаг `Check CI jobs status` через `gh run view --json jobs` проверяет, что единственный упавший job — `SonarCloud`. Любая другая red job блокирует push. Это обход coverage Quality Gate (`new_coverage ≥ 80`), который на free-плане SonarCloud не отключаемая. Подробности — TESTING.md preamble.

### Informational

- `codeql.yml` (cron `Mon 04:00 UTC`): CodeQL Python `security-and-quality` queries.

> `network-tests`, `e2e-dashboard`, `trivy-fs` ранее жили в `nightly.yml`; nightly удалён, эти job'ы перенесены в `ci.yml` и теперь required на каждый push/PR. Image-registry CVE сканирование (`outtakes/censprobe-*:main`) снято.

### Pre-commit (`.pre-commit-config.yaml`)

- **На commit** (cheap): pre-commit-hooks, ruff/ruff-format, yamllint, gitleaks, actionlint, validate-targets.
- **На pre-push** (slow): mypy (probe-core only локально; CI покрывает full tree), hadolint-docker.

Активация: `pre-commit install --hook-type pre-commit --hook-type pre-push`.

---

## Публикация результатов

Контейнеры пишут отчёты в `reports/<TEST_ID>/` на хосте — больше ничего. Публикация — ручная:

```bash
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID> ..."
git push
```

Если GitHub недоступен с тестируемой машины (бывает в RU-сетях), скопируйте каталог отчёта на любой хост с доступом:

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

## Контрибуция отчётов

Если хотите, чтобы отчёт попал в публичный реестр — fork репо и Pull Request:

```bash
# 1. Fork через GitHub UI, локально:
git clone https://github.com/<YOUR_USERNAME>/censprobe.git
cd censprobe

# 2. Прогоните тесты — отчёты появятся в reports/<TEST_ID>/.
docker compose --profile solo run --rm solo --test-id <provider>-<city>-<NN>
docker compose --profile listener run --rm listener --test-id <provider>-<city>-<NN> --session-id client-<...>
# (плюс client на клиентской машине)

# 3. Закоммитьте и откройте PR.
git add reports/<TEST_ID>/
git commit -m "reports: <TEST_ID>"
git push origin main
gh pr create  # или через GitHub UI
```

Соглашения по `TEST_ID`: `<provider>-<city>-<NN>` (`selectel-spb-001`, `vultr-fra-002`). По `SESSION_ID`: `client-<тип>-<провайдер>-<город>` (`client-home-rt-spb`, `client-mob-mts-msk`).

Оба валидируются регуляркой `[A-Za-z0-9_.-]{1,64}` — кириллица, пробелы, `/` отклоняются click'ом до запуска контейнера. Path-traversal через имя отчёта закрыт.

> **Что review-ится в PR**: путь `reports/<TEST_ID>/` (новые файлы), целостность JSON, разумность `meta.yaml`. Изменения в коде / `targets/` — отдельный PR.

> **Workflow в форках**: `build.yml` не запускается на форках (guard `if: github.repository == 'vasiliiok/censprobe'`) — это убирает шум красных CI у контрибуторов без `DOCKERHUB_TOKEN`. Если форкер хочет собирать свои образы — снимает guard и ставит свои `vars.DOCKERHUB_USERNAME` + `secrets.DOCKERHUB_TOKEN`.

---

## Разработка проекта

Гайд для разработки **самого censprobe** (не контрибуции отчётов) — в [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md):

- Локальная установка (`pip install -e packages/...[test] -e .[dev]`).
- Запуск тестов (`pytest`, маркеры).
- Что должно быть зелёным перед `git push`.
- Правила добавления кода, mypy strict policy, snapshot regen.
- Когда что-то ломается — troubleshooting.

Методология тестов и подходы — в [`docs/TESTING.md`](docs/TESTING.md).

Конкретное покрытие и CI quality gates — в [`docs/TEST_COVERAGE.md`](docs/TEST_COVERAGE.md).

---

## Структура репозитория

```
censprobe/
├── .env                              # static config с safe defaults (override локально перед удалённым деплоем)
├── docker-compose.yml                # 4 профиля: solo, listener, client, dashboard
├── censprobe.yaml                    # все runtime knobs (валидируется CensprobeConfig)
├── pyproject.toml                    # workspace deps + ruff/mypy/bandit/pytest/coverage конфиги
├── .pre-commit-config.yaml           # двухстадийные хуки (commit/push)
├── sonar-project.properties          # SonarCloud config
├── .yamllint.yaml, .hadolint.yaml    # tooling configs
├── .github/workflows/
│   ├── ci.yml                        # required: lint + validate + test + cross-package + network + e2e + security + sonar
│   ├── build.yml                     # required (post-CI on main): build + push + image gates; PR builds with push: false
│   └── codeql.yml                    # informational: weekly CodeQL Python
├── packages/
│   ├── probe-core/                   # censprobe-core: общая библиотека
│   │   └── src/censprobe_core/
│   │       ├── modules/              # 8 модулей измерения
│   │       ├── config.py, models.py, scoring.py, subcategories.py
│   │       ├── runner.py, module_registry.py, protocol_registry.py
│   │       ├── targets.py, credentials_reader.py
│   │       └── server_meta.py
│   ├── solo/                         # censprobe-solo: server-side probe runner
│   ├── listener/                     # censprobe-listener: VPN respondery + cred-server
│   ├── client/                       # censprobe-client: handshake probes
│   └── dashboard/
│       ├── grafana/                  # provisioning + dashboards/*.json
│       └── sync-api/                 # censprobe-sync-api: FastAPI + SQLAlchemy
├── targets/                          # YAML с целями (auto-discovery)
│   ├── news.yaml, social.yaml, messengers.yaml, vpn.yaml, neutral.yaml
│   ├── telegram.yaml                 # module_owned by modules.telegram
│   └── cloudflare.yaml               # module_owned by modules.cloudflare
├── tests/                            # workspace-level: contracts + snapshots + e2e
│   ├── contracts/                    # subcategories ↔ Grafana, targets validate, yaml round-trip
│   ├── snapshots/                    # JSON Schema + wire-format byte snapshots
│   └── e2e/                          # dashboard stack (CI job e2e-dashboard, every push/PR)
├── reports/<TEST_ID>/                # результаты тестов (закоммичиваются вручную)
├── docs/                             # CONTRIBUTING.md, TESTING.md, TEST_COVERAGE.md
└── README.md
```

---

## Контракт: конфиг — последняя истина

Принцип, на котором держится вся configurable-часть censprobe:

> **`censprobe.yaml` + `targets/*.yaml` — единственная истина для всех runtime-параметров. Никаких silent fallback'ов в коде, никаких hardcoded дефолтов на «жизненно важные» поля.**

Что это означает практически:

- Опечатка в `censprobe.yaml` (`enabledd: true` вместо `enabled: true`) → fatal startup error с указанием поля. `extra="forbid"` на всех sub-моделях.
- Пропущенное поле в `protocols.ports` для enabled-протокола → `_check_ports_cover_enabled` raises `ValueError`.
- Пропущенный `ports:` в `targets/telegram.yaml` для `TelegramDC` → pydantic `ValidationError` (с момента mai 2026 — `Field(min_length=1)`).
- Пропущенное поле в credentials YAML (например `vless_reality.server_name`) → `parse_protocols_yaml` raises `ValueError`. Listener и client деплоятся в lockstep одной compose-сборкой, schema mismatch → баг.

Единственные намеренные исключения:
- **Секреты** (`IPAPI_IS_KEY`, `DB_PASSWORD`, `GRAFANA_PASSWORD`) — в `.env`, не в YAML. Это явный карвaут от правила «yaml only» — секреты в публично-коммитнутом YAML недопустимы.
- **`DOCKERHUB_USERNAME` / `DOCKERHUB_TAG`** — Docker-level config, не runtime application config.
