# Censorship Probe

**Документ:** архитектурная спецификация и план реализации.
**Цель проекта:** автоматизированная оценка пригодности российских VPS для использования в качестве узлов VPN-каскада с учётом современной инфраструктуры цензуры (ТСПУ, DPI, throttling, блокировки протоколов).

## Обзор

Censorship Probe — распределённая система из пяти независимых Docker-контейнеров, координирующихся через два GitHub-репозитория. Система измеряет:

1. **Что видит тестируемый сервер из своего аплинка** — какие внешние ресурсы доступны, какие блокируются, какие замедляются. Это определяет пригодность сервера как VPN-exit.
2. **Дойдут ли клиентские VPN-пакеты до тестируемого сервера** — по разным протоколам (OpenVPN, WireGuard, Shadowsocks, VLESS+Reality, Hysteria 2) с разных клиентских сетей (мобильный, домашний, корпоративный, публичный Wi-Fi). Это определяет пригодность сервера как VPN-entry.
3. **Какие техники цензуры применяются на каждом участке** — DNS poisoning, SNI blocking, TCP RST injection, протокольные сигнатуры, throttling. Это нужно для выбора стратегии обхода в каскаде.

Каждое испытание одного сервера — это отдельный `test_id`, под которым в private-репозитории собираются отчёты от пяти типов vantage points:
- Сам сервер (автономный прогон тестов наружу).
- Сам сервер как приёмник VPN-подключений.
- Клиенты с разных сетей (сколько удалось собрать).
- Плюс сравнение с baseline от control-point в чистой юрисдикции.

Визуализация — через локальный Grafana-дашборд с кнопкой "Pull & Refresh", который пуллит отчёты из GitHub по требованию пользователя.

## Документ

- **Часть 1** — Модель угроз: что блокирует РФ в 2025–2026.
- **Часть 2** — Методология: как мы это измеряем.
- **Часть 3** — Системная архитектура: пять контейнеров.
- **Часть 4** — Test ID: идентификация испытаний.
- **Части 5–9** — Спецификации каждого из пяти контейнеров.
- **Часть 10** — Public-репозиторий: baseline, targets, signatures.
- **Часть 11** — Что видно в Grafana.
- **Часть 12** — Deployment.
- **Часть 13** — Privacy и opsec.
- **Часть 14** — План реализации.

---

## Часть 1. Модель угроз: что именно блокирует РФ в 2025–2026

### 1.1. Архитектура контроля

- **ТСПУ (Технические средства противодействия угрозам)** — программно-аппаратный DPI-комплекс, установленный in-line у всех операторов связи, централизованно управляемый Роскомнадзором. К 2026 обрабатывает ~100% трафика рунета.
- **АСБИ** — зонтичная система, включающая ТСПУ. К 2030 планируется мощность 954 Тбит/с.
- **Режим bypass**: при перегрузке ТСПУ пропускают трафик без фильтрации. Это важный артефакт — одни и те же тесты могут давать разный результат в разное время суток / при нагрузке. Нужно учитывать в повторяемости замеров.
- **ML-анализ (с 2025)**: кроме сигнатурного DPI используется поведенческий анализ — длительность сессий, частота подключений к IP, распределение размеров пакетов, соотношение upload/download.
- **Региональная вариативность**: фильтрация применяется не единообразно; у разных операторов и в разных регионах правила могут отличаться. Тест фиксирует срез именно для этого аплинка / этой связи — отсюда и необходимость multi-vantage архитектуры.

### 1.2. Классификация техник блокировки

Группирую по уровню OSI / механизму:

**L3 — IP-уровень**

- Null-route / blackhole на заблокированные IP и подсети.
- BGP-перехват для отдельных префиксов.

**L4 — Транспорт**

- TCP RST injection (подделка reset-пакета при попытке подключения).
- Блокировка по (IP, port).
- Throttling — принудительное уменьшение bandwidth для конкретных flow (классический кейс — YouTube, ~128 kbps).
- Искусственные потери пакетов / задержки.
- QUIC-блокировка (UDP/443 к определённым IP).

**L7 — Приложение (ключевой слой)**

- **DNS poisoning** — фильтрация DNS-ответов, возврат подставных IP или NXDOMAIN при UDP/53 и TCP/53.
- **DoH/DoT блокировка** — блокировка известных resolver'ов (1.1.1.1, 8.8.8.8, dns.google, [cloudflare-dns.com](http://cloudflare-dns.com/), [mozilla.cloudflare-dns.com](http://mozilla.cloudflare-dns.com/)).
- **SNI inspection** — анализ ClientHello, блокировка по доменному имени в SNI.
- **ESNI/ECH-блокировка** — блокировка TLS-соединений с зашифрованным SNI.
- **HTTP Host header inspection** — для plain HTTP.
- **TLS/JA3-JA4 fingerprinting** — идентификация клиента по отпечатку ClientHello.
- **Сигнатурный анализ протоколов** — OpenVPN (первый байт opcode), WireGuard (type=0x01), IKEv2, L2TP, классический Shadowsocks, VMess.
- **Active probing** — ТСПУ отправляет запросы на подозрительный сервер, проверяет, не ведёт ли он себя как VPN/proxy.
- **Behavioral ML-детекция** — распознавание обфусцированных протоколов по поведению.
- **HTTP header manipulation** — middlebox может модифицировать заголовки.

### 1.3. Статус протоколов (октябрь 2025 — апрель 2026)

| Протокол | Статус | Метод блокировки |
| --- | --- | --- |
| OpenVPN (UDP/TCP) | Блокируется ~100%, ~30 сек после handshake | Сигнатура opcode |
| WireGuard (ванильный) | Блокируется ~100% | Сигнатура handshake initiation |
| IKEv2/IPsec | Блокируется с мая 2022 | Сигнатура |
| L2TP/PPTP | Блокируется | Сигнатура |
| Shadowsocks (classic) | Блокируется ~95% | Active probing + entropy-анализ |
| Shadowsocks-2022 | Частично работает | Сложнее детектировать, но ML подтягивается |
| VMess | Блокируется | Сигнатуры V2Ray |
| Trojan (plain TLS) | Частично блокируется | JA3/fingerprinting |
| VLESS + Reality | **Работает стабильно** | Маскируется под валидный TLS к реальному SNI |
| VLESS + WS + CDN | Работает | Трафик идёт через CDN |
| AmneziaWG | Работает | Модифицированный WG с junk-пакетами |
| Hysteria 2 | Работает, но QUIC подвержен throttling | QUIC over UDP |
| NaiveProxy | Работает | HTTP/2 masquerading |
| Cloak (обёртка) | Работает | TLS-мимикрия |

### 1.4. Telegram — отдельный случай

Хронология:

- Август 2025 — блокировка voice/video calls (RTP over UDP).
- Январь–февраль 2026 — throttling скорости загрузки медиа.
- 10 февраля 2026 — официальное замедление.
- Апрель 2026 — планируемый полный блок.

Компоненты, которые нужно тестировать **раздельно**:

- API через 5 дата-центров (IPv4 + IPv6).
- `web.telegram.org` + `k.web.telegram.org` (WebK/WebA).
- `core.telegram.org`, `my.telegram.org`, `translations.telegram.org`.
- `telegram.org` (маркетинговый сайт).
- CDN: `cdn1.cdn-telegram.org` … `cdn5.cdn-telegram.org`.
- `t.me` — превью/invite-ссылки.
- STUN/voice-сервера — порты для голоса/видео.
- MTProto-порты: 443, 80, 5222, 2001.
- MTProxy-эндпоинты (если есть тестовый).

### 1.5. Побочные эффекты и подводные камни

- Случаются ложные срабатывания из-за bypass-режима ТСПУ — в перегруженные часы цензура фактически не работает.
- Некоторые "блоки" на самом деле — региональные geo-блокировки сервиса (Instagram даёт 403 для RU IP не из-за ТСПУ, а сам). Нужно отличать.
- Результаты меняются во времени — один тест = один снимок. Отсюда N-повторы и time series в дашборде.
- Цензурирование может быть **таргетированным на подсеть**: у разных серверов одного датацентра может быть разный результат. Отсюда — важность мульти-vantage с явной фиксацией, с какого сервера снимок.

---

## Часть 2. Методология детектирования

### 2.1. Базовые принципы

1. **Всё сравниваем с эталоном (baseline).** Baseline — это результаты тех же тестов, снятые с чистой юрисдикции (см. Часть 9 — контейнер `control`). Probe делает сравнение локально, не обращаясь к control в runtime. Без эталона невозможно отличить цензуру от обычных сетевых проблем, CDN-гео-маршрутизации, временных сбоев сервиса.
2. **Повторяем** тесты N раз (по умолчанию 3) и агрегируем — это снижает влияние bypass-режима ТСПУ и временных сбоев.
3. **Для каждого теста фиксируем "сырые" сигналы** (err-код, байты ответа, RTT, packet capture при необходимости) — а не только вердикт. Это нужно для пост-анализа и для ручного разбора пограничных случаев.
4. **Чёткая таксономия результатов**: OK / BLOCKED / THROTTLED / ANOMALY / ERROR / INCONCLUSIVE.
5. **Атрибуция метода блокировки** — не просто "не работает", а "DNS-poisoning" vs "SNI-block" vs "IP-drop" vs "RST-injection" и т.д. Это критично для выбора стратегии обхода в каскаде.

### 2.2. Матрица "метод блокировки → тест"

| Метод блокировки | Как детектируем |
| --- | --- |
| IP null-route | TCP SYN к IP, timeout при отсутствии RST и отсутствие ICMP unreachable |
| TCP RST injection | TCP SYN проходит, RST приходит через N мс после ClientHello, raw socket подтверждает источник |
| DNS poisoning | Сравнение resolved ASN против baseline ASN + валидация cert по возвращённому IP |
| DoH/DoT блокировка | Прямое TCP/443 к `cloudflare-dns.com`, `dns.google` + HTTP/2 DoH query |
| SNI-блокировка | TCP-коннект устанавливается, ClientHello с блокируемым SNI → TLS alert / RST / timeout; с fake SNI → OK |
| ESNI/ECH-блокировка | TLS handshake с ECH extension → fail; без ECH → OK |
| Host-header блокировка | plain HTTP к IP с разным Host header |
| Протокол-сигнатура (OpenVPN/WG) | Отправка raw handshake на listener тестируемого сервера, ожидание валидного ответа |
| Throttling (bandwidth) | Скачивание тестового файла с throttled-домена, сравнение bandwidth с baseline percentile |
| Throttling (SNI-attribution) | Три прогона на один IP с разным SNI: корректный, целевой (например `googlevideo.com`), опечатка. Если режется только при целевом SNI — атрибуция к SNI-инспекции ТСПУ |
| QUIC-блокировка | UDP/443 к Google, Cloudflare — успех handshake vs drop |
| JA3/JA4 fingerprinting | Проба с разными TLS-библиотеками: curl (стандартный JA3) vs uTLS-мимикрия под Chrome |
| Middlebox/HTTP-модификация | GET с кастомным регистром (`gET`, `Host:` vs `hOsT:`) → middlebox обычно нормализует |
| Geo-блок (не цензура, а гео) | Получение HTTP 403/451 на TLS-уровне с валидным cert — скорее всего не ТСПУ |

### 2.3. Контрольная точка

Архитектура использует **baseline-based сравнение** вместо live-control-API:
- Контрольная точка — это отдельный контейнер `control`, развёрнутый на VPS в чистой юрисдикции (см. Часть 9).
- Он при старте делает полный прогон тех же тестов и пушит результат как `baseline.json` в GitHub public-репозиторий.
- Probes (solo, client) скачивают baseline при запуске и сравниваются локально.
- Прямого API-канала между probes и control нет — это снижает attack surface и self-detection риски.

**Дополнение через публичные источники.** Для некоторых тестов probe может использовать публичные сервисы как вторичный источник сравнения:
- Cloudflare DoH: `https://cloudflare-dns.com/dns-query`
- Google DoH: `https://dns.google/dns-query`
- `https://www.cloudflare.com/cdn-cgi/trace` — определение своего exit IP и ASN
- `https://icanhazip.com/` — publicly known exit IP

Эти источники используются для:
1. Определения своего outbound ASN при автоопределении vantage metadata.
2. Cross-verification DNS-ответов (если baseline говорит "AS13335", а системный resolver — "AS12345", запрос через DoH подтвердит, что правда на стороне baseline).

### 2.4. Интерпретация результатов

Каждый тест возвращает структуру вида:

```json
{
  "test": "telegram_dc1_tcp",
  "target": "149.154.175.53:443",
  "verdict": "BLOCKED",
  "method": "tcp_rst_after_tls_ch",
  "confidence": 0.92,
  "evidence": {
    "tcp_syn_ack_received": true,
    "tls_client_hello_sent": true,
    "rst_received_after_ms": 150,
    "rst_ttl": 57,
    "expected_ttl_range": [52, 56]
  },
  "rtt_ms": 45.2,
  "attempts": 3,
  "control_comparison": {
    "control_verdict": "OK",
    "control_rtt_ms": 12.1
  }
}
```

Возможные значения `verdict`:

- `OK` — соответствует baseline / control.
- `BLOCKED` — ресурс недоступен, method-атрибуция заполнена.
- `THROTTLED` — доступен, но bandwidth ниже baseline.p10 * 0.3.
- `HANDSHAKE_ONLY` — для VPN-протоколов: handshake завершён, но последующие данные не проходят (подозрение на active probing / deep inspection данных).
- `ANOMALY` — расхождение с baseline, но не классифицировано (идёт в пост-анализ).
- `GEOBLOCK_NOT_CENSORSHIP` — 403/451 от самого сервиса (cert валиден, TLS проходит).
- `ERROR` — ошибка в самом probe (не network-ошибка).
- `INCONCLUSIVE` — недостаточно данных (например, control недоступен, baseline устарел).

Возможные значения `method` (атрибуция):

- `dns_poisoning`
- `dns_blocked_nxdomain`
- `doh_blocked`
- `ip_dropped`
- `tcp_rst_injection`
- `tcp_rst_after_tls_ch` — SNI-блок
- `tls_handshake_failure`
- `ech_blocked`
- `blockpage_returned`
- `bandwidth_throttling`
- `sni_throttling` — троттлинг атрибутирован к SNI (Метод B из 2.5.5)
- `quic_dropped`
- `openvpn_signature_blocked`
- `wireguard_signature_blocked`
- `shadowsocks_active_probed`
- `vpn_data_phase_blocked` — handshake прошёл, data-фаза заблокирована
- `middlebox_http_manipulation`

### 2.5. Детальные спецификации тестов

### 2.5.1. DNS-тесты

**Что делаем:**

1. Разрешаем каждый домен из test list'а через:
    - Системный resolver (`/etc/resolv.conf`).
    - Прямо на upstream ISP resolver (UDP/53 + TCP/53).
    - Публичные DNS: 8.8.8.8, 1.1.1.1, 77.88.8.8 (Yandex), 9.9.9.9 (Quad9).
    - DoH: `cloudflare-dns.com`, `dns.google`, `mozilla.cloudflare-dns.com`.
    - DoT: `1.1.1.1:853`, `8.8.8.8:853`.
2. Для каждого ответа — валидируем цепочку: подключаемся к TCP/443 на полученном IP, делаем TLS handshake с корректным SNI, проверяем, что cert соответствует запрошенному домену (CERTainty-подход).
3. Сравниваем с baseline / control.

**Вердикты:**

- `OK` — все resolver'ы вернули консистентный ответ, cert валиден.
- `DNS_POISONING` — системный/ISP resolver вернул IP, cert на котором невалидный для этого домена, тогда как DoH/control/baseline вернули другой IP.
- `DNS_BLOCKED` — NXDOMAIN от ISP resolver при корректном ответе от control.
- `DOH_BLOCKED` — соединение с DoH-эндпоинтом не удаётся.

### 2.5.2. TCP reachability

**Что делаем:**

- TCP SYN к (IP, port). Используем raw socket (`AF_PACKET` / Scapy) или обычный `asyncio.open_connection`.
- Если обычный socket — засекаем время до SYN-ACK или до ошибки; различаем timeout vs RST vs connection refused.
- Дополнительно (raw): ловим, приходит ли RST из чужого места (spoofed RST — у injected RST часто другой TTL).

**Вердикты:**

- `OK` — SYN-ACK получен, соединение устанавливается.
- `IP_DROPPED` — SYN уходит, ничего не возвращается, timeout.
- `RST_INJECTED` — получили RST, но характеристики указывают на injection (IP TTL расходится с control-flow, или RST приходит слишком быстро).
- `REFUSED` — корректный RST от самого хоста (сервис недоступен, но не блок).

### 2.5.3. TLS/SNI тесты

**Сценарии для одного и того же IP:**

| Сценарий | SNI | Ожидание |
| --- | --- | --- |
| `sni_blocked` | блокируемый (`youtube.com`) | fail → блок по SNI |
| `sni_ok` | нейтральный (`cloudflare.com`) | success |
| `sni_empty` | пустой | success / fail зависит от сервера |
| `sni_fake_ok` | нейтральный, но IP от блокируемого сервиса | success → значит, блок идёт по SNI, а не по IP |
| `ech_on` | ECH + inner=блокируемый | fail → ECH-детекция |
| `esni_legacy` | ESNI (legacy draft) | fail → блок ESNI |

**Библиотека:** стандартный Python `ssl`, плюс нужно подменять SNI через low-level API.
Для ECH — `python-cryptography` пока не поддерживает напрямую, можно вызывать `curl --ech` как subprocess.

### 2.5.4. HTTP/HTTPS

**Тестируем:**

- Fetch URL полностью (headers + body).
- Сравниваем с baseline:
    - `status` совпадает с ожидаемым?
    - `body_length` в диапазоне `body_length_range`?
    - Stable fragments (logo, footer и т.п.) по SHA256 совпадают?
    - TLS cert chain совпадает?
    - Есть ли block page по fingerprint'у?
- Block page fingerprints: у ТСПУ есть узнаваемые страницы "Доступ ограничен Роскомнадзором", но чаще применяется просто RST.

**Важно**: геоблок (Instagram 403) ≠ цензура. Детектируем это по: cert валиден, TLS работает, HTTP 403/451 с телом от самого сервиса.

### 2.5.5. Throttling detection

Два независимых метода. Первый — классический bandwidth-диагноз, второй — специфичный тест YouTube/SNI-троттлинга через подмену SNI.

**Метод A: базовый профиль bandwidth.**

1. Скачиваем тестовый файл (~10 MB) с целевого домена несколько раз.
2. Измеряем bandwidth в скользящем окне (по секундам).
3. Сравниваем с baseline `throttling.bandwidth_mbps_p50/p10` для этого ресурса.
4. Паттерн "первые 1–2 секунды — полная скорость, потом резкое падение до 128 kbps" = сигнатура TSPU-throttling (ТСПУ часто позволяет burst в начале).

**Целевые ресурсы для Метода A:**
- `googlevideo.com` (YouTube) — классический кейс.
- `cdninstagram.com` / `scontent.cdninstagram.com`.
- Telegram CDN (`cdn1.cdn-telegram.org`).
- Control: `speed.cloudflare.com`, `speedtest.selectel.ru` (внутрироссийский, эталон без троттлинга).

**Метод B: YouTube SNI-throttling probe (атрибуция троттлинга к SNI-инспекции).**

Техника основана на публикации Vadim Vetrov (Habr, 2024): ТСПУ определяет YouTube не по IP, а по SNI-полю в TLS ClientHello. Значит, если отправить трафик на **не-Google IP** (например, `speedtest.selectel.ru`), но поставить в ClientHello SNI `googlevideo.com`, ТСПУ должен всё равно отрезать скорость — и это докажет, что троттлит именно SNI-инспекция, а не что-то связанное с инфраструктурой Google.

**Тест:**

Solo делает три параллельных скачивания одинакового по размеру файла с одного и того же IP (`speedtest.selectel.ru`), различающихся только SNI:

1. **Прогон 1 — корректный SNI.** SNI = `speedtest.selectel.ru`. Это честное соединение, должно давать полную скорость (подтверждает, что canal work).
2. **Прогон 2 — googlevideo SNI (trigger).** SNI = `googlevideo.com`, но IP всё равно selectel. Cert validation отключена. Ожидаем burst-then-drop профиль если ТСПУ активен.
3. **Прогон 3 — контрольная опечатка.** SNI = `googleviideo.com` (с опечаткой). Должна быть полная скорость, потому что ТСПУ не сматчил SNI. Это контроль: доказывает, что IP-блокировки или внешняя проблема не влияют.

Как отправить такой запрос — через `curl` с `--connect-to`:
```bash
# Прогон 2: IP selectel, но SNI и Host = googlevideo.com
curl --connect-to ::speedtest.selectel.ru \
     -k -o /dev/null \
     --write-out 'time=%{time_total}  speed=%{speed_download}\n' \
     https://manifest.googlevideo.com/100MB
```

`-k` — отключает проверку TLS-сертификата (selectel отдаст свой cert, не googlevideo). `--connect-to` заставляет curl резолвить `manifest.googlevideo.com` как `speedtest.selectel.ru`, но в SNI и HTTP Host отправлять `googlevideo.com`.

**Интерпретация результатов:**

| Прогон 1 (SNI=selectel) | Прогон 2 (SNI=googlevideo) | Прогон 3 (SNI=googleviideo) | Verdict |
|-------------------------|----------------------------|----------------------------|---------|
| полная скорость | полная скорость | полная скорость | `OK` — нет SNI-троттлинга |
| полная скорость | burst-then-drop к ~120 KB/s | полная скорость | `YOUTUBE_SNI_THROTTLED` — ТСПУ режет по SNI |
| полная скорость | burst-then-drop | burst-then-drop | `ANOMALY` — троттлится даже опечатка (странно, надо разбираться) |
| низкая везде | низкая везде | низкая везде | `INCONCLUSIVE` — проблема канала в целом |

Solo фиксирует bandwidth-профиль всех трёх прогонов в отчёте. Метод B даёт надёжный signal "это именно ТСПУ по SNI, а не сетевая проблема".

**Другие кандидаты для SNI-троттлинга теста** (если ТСПУ расширит список):
- `instagram.com`, `cdninstagram.com` — при текущих блокировках Instagram в РФ.
- `fastly.net` — у Reddit и многих новостных.
- Любой новый сервис, попавший под замедление.

Solo может запускать Метод B для нескольких SNI из `targets/throttling_sni.yaml`.

### 2.5.6. Протокол-тесты

Самый нетривиальный модуль. Нужно отправить **handshake-пакет каждого протокола** на наш control-vp (protocol-endpoints) и посмотреть, долетает ли он и приходит ли осмысленный ответ.

**Тест OpenVPN:**

- Формируем `P_CONTROL_HARD_RESET_CLIENT_V2` пакет.
- Отправляем на `control-vp:1194/UDP`.
- Control отвечает `P_CONTROL_HARD_RESET_SERVER_V2`.
- Нет ответа → сигнатура блокируется.

**Тест WireGuard:**

- Формируем handshake initiation (type=0x01, 148 байт).
- Отправляем на `control-vp:51820/UDP`.
- Control игнорирует или отвечает response (type=0x02).
- Если пакет не доходит — блок.

**Тест Shadowsocks (classic, AEAD-2022):**

- Устанавливаем TCP-соединение.
- Отправляем корректно зашифрованный request.
- Контроль подтверждает приём.

**Тест VLESS + Reality / Trojan / NaiveProxy:**

- Используем `xray-core` / `sing-box` CLI как подпроцесс (не реализуем протоколы сами).
- Конфигурируем минимальный клиент, делаем HTTP-запрос через туннель до control.
- Измеряем латентность и успех.

**Тест Hysteria 2:**

- QUIC UDP/443 к control с Hysteria.
- Критично: работает ли UDP/443 вообще к этому IP.

**AmneziaWG:**

- Тот же WG handshake, но с junk-пакетами перед handshake'ом.

Для МVP достаточно OpenVPN/WG сырыми пакетами + wrapper'ы для xray-core.

### 2.5.7. Telegram — детальный план

**Блок 1: API DC reachability**

```
Для dc ∈ {1,2,3,4,5}:
  Для ip ∈ {v4, v6}:
    Для port ∈ {443, 80, 5222, 2001}:
      - TCP connect
      - Send MTProto init (простейший ReqPqMulti)
      - Ожидать valid response
  verdict[dc] = OK если хотя бы одна комбинация работает
```

IP DC (актуальные на начало 2026):

- DC1 (pluto, Miami): 149.154.175.53 | 2001:b28:f23d:f001::a
- DC2 (venus, Amsterdam): 149.154.167.51 | 2001:67c:4e8:f002::a
- DC3 (aurora, Miami): 149.154.175.100 | 2001:b28:f23d:f003::a
- DC4 (vesta, Amsterdam): 149.154.167.91 | 2001:67c:4e8:f004::a
- DC5 (flora, Singapore): 91.108.56.130 | 2001:b28:f23f:f005::a

**Блок 2: Web**

- `web.telegram.org`, `k.web.telegram.org`, `a.web.telegram.org` — HTTPS, сравнение с baseline.

**Блок 3: Auxiliary domains**

- `core.telegram.org` (API-docs) — HTTPS.
- `my.telegram.org` (app registration) — HTTPS.
- `t.me` — превью ссылок.
- `telegram.org`, `desktop.telegram.org`, `macos.telegram.org`.

**Блок 4: CDN**

- `cdn1.cdn-telegram.org` … `cdn5.cdn-telegram.org` — HTTPS, скачивание пробного медиа.

**Блок 5: Voice calls**

- Telegram для звонков использует UDP к своим серверам. Без реального RTP-стрима можно проверить косвенно:
    - UDP-коннективность к IP DC на портах голосовой связи.
    - STUN binding request к Telegram STUN endpoint'у.
- В расчёте `telegram_health` голос — отдельный субскор `telegram_voice_health`.

**Блок 6: Throttling**

- Скачивание тестового медиа через CDN — проверка, не замедлено ли (сравнение с baseline).

**Блок 7: MTProxy**

- Если в конфиге указан тестовый MTProxy — проверяем connect к нему и проведение хэндшейка.

**Итоговый Telegram health score:**

```
telegram_health = weighted_avg([
  dc_reachability:      40%,
  web_access:           20%,
  cdn_access:           15%,
  voice_health:         15%,
  throttling_absence:   10%
])
```

### 2.5.8. Middlebox detection

Инспирировано OONI HTTP Header Field Manipulation test:

- Отправляем HTTP-запрос с заголовками в нестандартном регистре: `hOsT:`, `uSeR-aGeNt:`.
- Middlebox обычно нормализует → регистр в ответе изменится.
- Control возвращает всё как есть (через echo-сервер на control-vp).

Дополнительно:

- HTTP Invalid Request Line test: отправляем запрос с кривой request-line.
- TCP fragmentation test: шлём ClientHello, разделённый на 2 TCP-пакета — некоторые DPI не собирают фрагменты корректно.

### 2.5.9. IPv6

Отдельные проходы всех тестов над v6, потому что:

- У многих операторов v6 фильтруется слабее / вообще не фильтруется.
- Это прямо влияет на то, какие стратегии обхода будут работать в каскаде.
- Telegram v6-endpoints часто работают там, где v4 заблокированы.

### 2.5.10. Дополнительные тесты

- **Tor directory authorities** — подключение к 9 известным DA.
- **Tor bridges (obfs4)** — к публичным bridges.
- **Public VPN services** (NordVPN, Proton и т.д.) — как индикатор общего состояния сети.
- **MTU / PMTUD** — работает ли path MTU discovery (на некоторых ТСПУ бывают проблемы).

---

## Приложение A. Telegram IP (на апрель 2026)

```yaml
# config/targets/telegram.yaml
api_datacenters:
  - id: 1
    name: pluto
    location: Miami
    ipv4: 149.154.175.53
    ipv6: 2001:b28:f23d:f001::a
    ports: [443, 80, 5222, 2001]
  - id: 2
    name: venus
    location: Amsterdam
    ipv4: 149.154.167.51
    ipv6: 2001:67c:4e8:f002::a
    ports: [443, 80, 5222, 2001]
  - id: 3
    name: aurora
    location: Miami
    ipv4: 149.154.175.100
    ipv6: 2001:b28:f23d:f003::a
    ports: [443, 80, 5222, 2001]
  - id: 4
    name: vesta
    location: Amsterdam
    ipv4: 149.154.167.91
    ipv6: 2001:67c:4e8:f004::a
    ports: [443, 80, 5222, 2001]
  - id: 5
    name: flora
    location: Singapore
    ipv4: 91.108.56.130
    ipv6: 2001:b28:f23f:f005::a
    ports: [443, 80, 5222, 2001]

web:
  - web.telegram.org
  - k.web.telegram.org
  - a.web.telegram.org

auxiliary:
  - core.telegram.org
  - my.telegram.org
  - translations.telegram.org
  - t.me
  - telegram.org
  - desktop.telegram.org
  - macos.telegram.org

cdn:
  - cdn1.cdn-telegram.org
  - cdn2.cdn-telegram.org
  - cdn3.cdn-telegram.org
  - cdn4.cdn-telegram.org
  - cdn5.cdn-telegram.org

asn: AS62041
ip_ranges_v4:
  - 149.154.160.0/20
  - 91.108.4.0/22
  - 91.108.56.0/22
```

> ВАЖНО: IP могут меняться. Первым шагом при запуске — `censprobe refresh-telegram-dcs` —
> 

## Часть 3. Системная архитектура

### 3.1. Принципы

1. **Один private GitHub-репозиторий.** Всё (код, конфиги, baseline, targets, отчёты, credentials одного теста) лежит в `vasiliiok/censprobe`. Репо не светится, клонируется только по SSH.
2. **SSH-ключи как единственная авторизация.** На каждой машине (RU-сервер, немецкий VPS, ноут, dashboard-хост) добавляется SSH-ключ в GitHub как Deploy Key с read+write доступом. Никаких PAT-токенов, никаких секретов рядом с контейнерами.
3. **Пять Docker-контейнеров, один `docker-compose.yml`, профили.** На любой машине:
   ```
   git clone git@github.com:vasiliiok/censprobe.git
   cd censprobe
   docker compose --profile <solo|listener|client|control|dashboard> up
   ```
4. **Control-point есть, но не центральный.** Отдельный контейнер (профиль `control`) запускается вручную на немецком VPS, делает эталонный прогон, коммитит baseline в тот же репо, выходит.
5. **Один тест = один сервер.** `test_id` связывает все отчёты испытания.
6. **Multi-vantage естественным образом.** Solo (что видит сервер) + несколько сессий listener (реальность с разных клиентских сетей).
7. **Прямой коннект только там, где это суть теста.** Клиент стучится по VPN-протоколам к listener'у на тестируемом сервере — это и есть измерение.

### 3.2. Пять контейнеров

| # | Профиль | Где запускается | Что делает | Когда завершается |
|---|---------|-----------------|------------|-------------------|
| 1 | `dashboard` | Где удобно (ноут/VPS) | Grafana + Postgres + sync. Пуллит репо по кнопке, визуализирует. | До ручной остановки |
| 2 | `solo` | Тестируемый RU-сервер | Тесты с перспективы сервера наружу (DNS, TLS, HTTP, Telegram, throttling). `git commit && git push`, выходит. | После push'а |
| 3 | `listener` | Тот же тестируемый RU-сервер | Слушает OpenVPN/WG/SS/VLESS+Reality/Hy2 порты. По Ctrl+C коммитит лог сессии и пушит. | Ctrl+C |
| 4 | `client` | Ноут/телефон с клиентской сетью | `git pull`, стучится к listener по всем протоколам, выводит в stdout. **Ничего не коммитит.** | Сразу после прогона |
| 5 | `control` | VPS в чистой юрисдикции (Германия) | Эталонный прогон, коммитит baseline. | После push'а |

### 3.3. Топология данных

```
┌─ Control VPS (Germany) ──────────────┐
│  git clone censprobe (SSH, once)     │
│  docker compose --profile control up │
│  → baseline генерируется             │
│  → git commit && git push            │
└────────────────┬─────────────────────┘
                 │ SSH push
                 ▼
┌───────────────────────────────────────────────────────┐
│ git@github.com:vasiliiok/censprobe.git (private)      │
│                                                       │
│ ├── docker-compose.yml  (profiles: solo|listener|...) │
│ ├── packages/           (код всех контейнеров)        │
│ ├── targets/*.yaml                                    │
│ ├── signatures/*.yaml                                 │
│ ├── protocols/default.yaml                            │
│ ├── baseline/                                         │
│ │   └── latest.json     ← пишет control               │
│ └── reports/                                          │
│     └── <test_id>/                                    │
│         ├── meta.yaml            ← пишет listener    │
│         ├── protocols.yaml       ← пишет listener    │
│         ├── server-solo-*.json.gz         ← solo     │
│         └── server-listener-<sess>-*.json.gz ← listen│
└──────┬─────────────────┬──────────────┬───────────────┘
       │ SSH clone+push  │ SSH clone    │ SSH clone (read-only по факту)
       ▼                 ▼              ▼
┌─ RU server ──────┐ ┌─ Dashboard host ┐ ┌─ Клиент (ноут) ─┐
│ --profile solo   │ │ --profile       │ │ --profile client│
│ --profile listener │ │    dashboard   │ │ git pull →      │
│                  │ │                 │ │ читает baseline │
│                  │ │ Grafana + sync  │ │ + protocols.yaml│
│  ┌ UDP/TCP ◄──── │ │ Postgres        │ │ → handshakes    │
│  │ handshakes    │ │ "Pull & Refresh"│ │   на server     │
│  └ listener      │ │  по кнопке      │ └─────────────────┘
└──────────────────┘ └─────────────────┘
```

### 3.4. Компоненты системы

- **probe-core** — общая библиотека. Модули DNS/TCP/TLS/HTTP/throttling/Telegram/middlebox/protocols. Используется в solo, client и control — все три делают одни и те же измерения, различаясь только тем, откуда запущены и что коммитят.
- **GitHub как транспорт** — один private репо. Все данные, код, конфиги, отчёты, credentials — здесь.
- **SSH-ключи как авторизация** — Deploy Keys с read+write, по одному на каждую машину. Никаких PAT-токенов.
- **Baseline** — эталонные результаты от control-контейнера, хранятся в том же репо, обновляются вручную перед испытанием.
- **Сравнение с baseline** — локальное, внутри probe. ASN-based для DNS, SHA256-based для TLS/HTTP, percentile-based для throttling.
- **Dashboard** — Grafana с Postgres-кэшем, независимый контейнер. Запускается где удобно, пуллит из GitHub по кнопке.

### 3.5. Конфигурационная модель

Весь проект — один private git-репозиторий. На любой машине:

```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe
docker compose --profile <role> up
```

SSH-ключ машины предварительно добавлен в GitHub → Settings → SSH Keys (или как Deploy Key в репо с write-доступом). Никаких PAT-токенов, никаких `.env` с секретами.

Структура репозитория:
```
censprobe/
├── docker-compose.yml             # единый compose-файл с профилями
├── packages/                      # код всех контейнеров
│   ├── probe-core/
│   ├── solo/
│   ├── listener/
│   ├── client/
│   ├── control/
│   └── dashboard/
├── targets/                       # что тестировать
│   ├── news.yaml
│   ├── social.yaml
│   ├── messengers.yaml
│   ├── telegram.yaml
│   └── neutral.yaml
├── signatures/                    # атрибуция блокировок
│   ├── protocols.yaml
│   ├── blockpages.yaml
│   └── dns_fingerprints.yaml
├── protocols/
│   └── default.yaml               # какие VPN-протоколы и на каких портах
├── baseline/                      # эталон от control-контейнера
│   ├── latest.json
│   └── archive/
└── reports/                       # отчёты испытаний
    └── <test_id>/
        ├── meta.yaml              # описание испытания
        ├── protocols.yaml         # credentials этого теста
        └── *.json.gz
```

`protocols/default.yaml` — одинаковый для listener и client:
```yaml
# Перечень тестируемых VPN-протоколов и их дефолтные порты.
# Listener запускает responders для всех; client бьёт по каждому.
# Ни один из протоколов НЕ требует владения доменом.
#
# Разнообразие маскировки:
#  - openvpn:      классика без маскировки (baseline "как легко блокируют")
#  - wireguard:    классика без маскировки (второй baseline)
#  - amneziawg:    WireGuard + header randomization + junk packets (DPI-resistant fork)
#  - shadowsocks:  чистая энтропия без структуры, AEAD
#  - vless_reality: mimicry реального TLS к внешнему домену
#  - hysteria2:    QUIC/HTTP/3 mimicry + Salamander obfs

protocols:
  - name: openvpn
    port: 1194
    transport: udp

  - name: wireguard
    port: 51820
    transport: udp

  - name: amneziawg
    port: 51821
    transport: udp
    # Параметры AmneziaWG 2.0 обфускации —
    # junk packets до handshake + рандомизация заголовков.
    # Конкретные значения в reports/<test_id>/protocols.yaml.

  - name: shadowsocks
    port: 8388
    transport: tcp
    method: "2022-blake3-aes-256-gcm"

  - name: vless_reality
    port: 443
    transport: tcp
    # Reality не требует твоего домена.
    # sni_cover — это домен, под который маскируется handshake.
    # Требования к нему: поддерживает TLS 1.3 + HTTP/2,
    # не редиректит на основной домен.
    sni_cover: "apimaps.yandex.ru"

  - name: hysteria2
    port: 443
    transport: udp
    obfs: "salamander"
```

**Параметры запуска (не в git, не в `.env`, а в shell):**

Переменные, которые меняются от запуска к запуску, передаются в момент `docker compose up`:
- `TEST_ID=selectel-spb-001` — для solo/listener/client.
- `SESSION_ID=client-mob-mts-msk` — для listener (какую сеть сейчас тестируем).
- `SERVER_HOST=1.2.3.4` — для client (куда стучаться).

**Итог.** На каждой машине есть только склонированный репозиторий и SSH-ключ. Всё настройки и код — в самом репо. Параметры конкретного запуска — в переменных окружения shell.

---

## Часть 4. Test ID — идентификация испытаний

### 4.1. Концепция

**Test** — это одно испытание одного конкретного российского сервера на пригодность для VPN. Состоит из набора отчётов с разных vantage points, собранных в одном окне времени.

Формат `test_id`:
```
<provider>-<location>-<NNN>
```

Примеры:
- `selectel-spb-001` — первый тест Selectel VPS в Санкт-Петербурге
- `timeweb-msk-007` — седьмой тест Timeweb в Москве
- `vdsina-ekb-003` — третий тест VDSina в Екатеринбурге

Где:
- `provider` — slug провайдера (selectel, timeweb, vdsina, rulovpn, ihor, …)
- `location` — slug города (msk, spb, ekb, nsk, kzn, …) или `ru` если неважно
- `NNN` — инкрементальный порядковый номер. Увеличивается вручную при каждом новом испытании того же провайдера/города.

Это человекочитаемый slug. Главное — уникальность в пределах репо.

### 4.2. Идентификация сессий внутри одного test_id

Внутри `test_id` различаем три типа вкладов:

**1. Server-solo отчёт** — один на весь test_id, от контейнера `solo`. Внутренний тип отчёта: `report_type: solo`.

**2. Server-listener отчёты** — **по одному на каждую сетевую сессию**, от контейнера `listener`. Внутренний тип: `report_type: listener`. Каждый отчёт принадлежит конкретной сессии и имеет свой `session_id`.

**3. Клиентские сессии** — identified by `session_id`, задаваемый на стороне listener'а при запуске. Клиент-контейнер на ноутбуке `session_id` не знает — он просто бьёт по протоколам к серверу. Listener, который запущен под этот session_id, привязывает все пришедшие ему handshakes к этой сессии.

**Клиентский контейнер ничего не пушит в GitHub сам** — только читает (`protocols/default.yaml` из public, `protocols.yaml` из reports). Всё хранение и идентификация — на стороне listener'а.

**Как работает связка на практике:**

1. Пользователь решает протестировать сервер с нескольких сетей.
2. На тестируемом сервере запускает listener: `TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb docker compose up listener`.
3. На ноутбуке (подключенном к домашнему Ростелекому) запускает клиент-контейнер — он стучится на listener по всем протоколам.
4. Пользователь хочет протестировать мобильный МТС.
5. На сервере останавливает listener (Ctrl+C) → он пушит отчёт сессии `client-home-rt-spb` и выходит.
6. Снова запускает listener с новым `SESSION_ID=client-mob-mts-msk`.
7. На ноутбуке переключается на мобильный hotspot, запускает клиент снова.
8. И так далее для каждой сети.

В итоге в reports для одного test_id накопится:
- `server-solo-<timestamp>.json.gz` — один файл.
- `server-listener-<session_id>-<timestamp>.json.gz` — по одному на каждую сетевую сессию.

**Соглашение именования для session_id:**
```
client-<connection-type>-<isp-slug>-<region-slug>
```

`connection-type` ∈ {`home`, `mob`, `wifi`, `corp`, `ethernet`}.

Примеры ISP slugs: `rt` (Ростелеком), `mts`, `mf` (МегаФон), `bln` (Билайн), `t2` (Tele2), `yota`, `er` (ЭР-Телеком), `dom` (Дом.ру).

Полные session_id: `client-home-rt-spb`, `client-mob-mts-msk`, `client-mob-mf-ekb`, `client-wifi-cafe-msk`, `client-corp-company-msk`.

### 4.3. Структура папок `reports/`

```
reports/
├── selectel-spb-001/
│   ├── meta.yaml                                                      # описание теста
│   ├── protocols.yaml                                                 # shared credentials listener ↔ client
│   ├── server-solo-2026-04-21T12-00-12Z.json.gz                       # от solo (один раз)
│   ├── server-listener-client-home-rt-spb-2026-04-21T13-30-00Z.json.gz  # сессия с домашнего Ростелекома
│   ├── server-listener-client-mob-mts-msk-2026-04-21T14-15-31Z.json.gz  # сессия с мобильного МТС
│   └── server-listener-client-mob-mf-ekb-2026-04-21T16-04-02Z.json.gz   # сессия с МегаФона
├── timeweb-msk-001/
│   └── …
├── selectel-spb-002/    # повторный тест того же сервера через месяц
│   └── …
```

Имя файла listener-отчёта содержит `session_id`, что позволяет dashboard'у различать, с какой сети приходили пакеты.

### 4.4. meta.yaml

Создаётся первым запущенным контейнером (обычно listener или solo) при инициализации теста:

```yaml
# reports/selectel-spb-001/meta.yaml
test_id: selectel-spb-001
created_at: 2026-04-21T12:00:00Z
description: "Selectel SPb VPS — оценка для VPN entry"
server:
  provider: Selectel
  location: "Saint Petersburg"
  asn: AS49505
  as_name: "JSC Selectel"
  ipv4_masked: "XXX.XXX.XXX.0/24"
  ipv6_available: true
  plan: "Cloud VPS Basic"
  kernel: "Linux 6.8"
  distro: "Ubuntu 24.04"
purpose: "vpn-entry"    # или vpn-exit, vpn-relay
planned_sessions:
  - client-mob-mts-msk
  - client-home-rt-spb
  - client-mob-mf-ekb
probe_core_version: "0.3.0"
baseline_version: "2026-04-15-01"
```

### 4.5. protocols.yaml — shared credentials

Listener при первом запуске генерирует ключи для всех протоколов и кладёт в репо (в plaintext, репо приватный). Клиентский контейнер читает их при запуске.

Это **необходимо**: чтобы клиент мог сделать handshake с listener'ом, ему нужны совпадающие credentials. Реального секрета в этих ключах нет — listener всё равно dummy proxy, не форвардит трафик, после теста credentials неиспользуемы.

Полный пример — все 6 протоколов, конфиги основаны на документации разработчиков:

```yaml
# reports/selectel-spb-001/protocols.yaml (plaintext в приватном репо)
generated_at: 2026-04-21T12:00:00Z
test_id: selectel-spb-001
server_ip: "X.X.X.X"          # для client'а, чтобы собрать готовые URI

# ── OpenVPN (классика, UDP, TLS-auth mode) ────────────────────────
# Не требует домена. PSK для TLS-auth + self-signed server cert.
# Docs: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/
openvpn:
  port: 1194
  protocol: udp
  mode: static-key            # простейший режим — PSK, никаких PKI
  tls_auth_key: |             # openvpn --genkey tls-auth ta.key
    -----BEGIN OpenVPN Static key V1-----
    <hex-256-bit PSK>
    -----END OpenVPN Static key V1-----
  cipher: "AES-256-GCM"
  auth: "SHA256"
  # server и client обменяются P_CONTROL_HARD_RESET_V2 и перейдут в TLS,
  # где listener ответит self-signed cert. Client не валидирует cert —
  # нам достаточно факта завершения handshake.

# ── WireGuard (классика, UDP, Curve25519) ─────────────────────────
# Docs: https://www.wireguard.com/quickstart/
wireguard:
  port: 51820
  server_public_key: "<base64-32-bytes>"      # wg genkey | wg pubkey
  server_private_key: "<base64-32-bytes>"     # только на listener'е
  client_private_key: "<base64-32-bytes>"     # для client'а
  client_public_key: "<base64-32-bytes>"      # preshared, listener знает
  allowed_ips: "10.200.0.0/24"                # dummy, трафик никуда не идёт
  # Listener отвечает handshake response + ожидает keepalive/data packet
  # через туннель для подтверждения data-фазы.

# ── AmneziaWG (WireGuard + DPI obfuscation) ───────────────────────
# Те же Curve25519 ключи что у WG, плюс junk+header параметры.
# Docs: https://docs.amnezia.org/documentation/amnezia-wg/
# Github: https://github.com/amnezia-vpn/amneziawg-go
amneziawg:
  port: 51821                                  # другой порт чтобы не конфликтовать с wg
  server_public_key: "<base64-32-bytes>"
  server_private_key: "<base64-32-bytes>"
  client_private_key: "<base64-32-bytes>"
  client_public_key: "<base64-32-bytes>"
  allowed_ips: "10.201.0.0/24"
  # AmneziaWG 2.0 параметры обфускации.
  # Должны быть одинаковыми на server и client, иначе handshake не пройдёт.
  jc: 4                        # число junk packets перед handshake (генерируется 3-7)
  jmin: 40                     # мин. размер junk packet (в байтах, генерируется 40-59)
  jmax: 70                     # макс. размер junk packet (генерируется 70-99)
  s1: 86                       # padding bytes перед handshake init (15-150; S1+56 != S2)
  s2: 42                       # padding bytes перед handshake response (15-150)
  h1: 1779637668               # magic header для init (из диапазона, случайно сгенерирован)
  h2: 3162648211               # magic header для response
  h3: 2390956198               # magic header для cookie
  h4: 947548365                # magic header для data packet
  # Значения H1-H4 должны быть разные и не равны 1/2/3/4 (стандартные WG типы).
  # Генерируется случайно на первом запуске listener'а для этого test_id.

# ── Shadowsocks-2022 (TCP, entropy, AEAD) ─────────────────────────
# Docs: https://sing-box.sagernet.org/configuration/inbound/shadowsocks/
# Spec: https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
shadowsocks:
  port: 8388
  transport: tcp
  method: "2022-blake3-aes-256-gcm"    # требует 32-байтный ключ в base64
  password: "<base64-32-bytes>"        # openssl rand -base64 32
  # Server: sing-box inbound type=shadowsocks.
  # Client: sing-box outbound аналогично.
  # После handshake client шлёт короткий HTTP-GET через шифр-канал, listener эхит.

# ── VLESS + Reality (TCP/443, TLS mimicry) ────────────────────────
# Docs: https://github.com/XTLS/REALITY/blob/main/README.en.md
# Examples: https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY
vless_reality:
  port: 443
  transport: tcp
  uuid: "<uuid-v4>"                    # xray uuid
  flow: "xtls-rprx-vision"             # рекомендованный Xray flow
  # Reality target — внешний домен, под который маскируемся.
  # НЕ требует владения этим доменом. Требования к нему:
  #   - TLS 1.3 + HTTP/2 поддержка
  #   - не редиректит на www
  #   - географически близко к серверу (опц.)
  dest: "apimaps.yandex.ru:443"
  server_names:
    - "apimaps.yandex.ru"
  private_key: "<x25519-private, base64>"   # xray x25519
  public_key: "<x25519-public, base64>"     # для клиента
  short_id: "<hex-0-to-16-chars>"            # openssl rand -hex 8
  fingerprint: "chrome"                      # клиент имитирует Chrome TLS fingerprint

# ── Hysteria 2 (UDP/443, QUIC) ────────────────────────────────────
# Docs: https://v2.hysteria.network/docs/advanced/Full-Server-Config/
# Self-signed cert на IP — Hysteria поддерживает из коробки.
hysteria2:
  port: 443
  transport: udp
  auth: "<random-password-string>"      # password auth mode
  obfs:
    type: "salamander"                  # XOR-based traffic obfuscation
    password: "<random-password>"       # должен совпадать на клиенте
  # TLS: self-signed cert для IP сервера (генерирует listener при старте).
  tls:
    cert_path: "/data/hysteria.crt"     # листовой cert (self-signed)
    key_path: "/data/hysteria.key"
    cert_sha256: "<hex-sha256>"         # для pinning на клиенте, если не insecure
  bandwidth:
    up_mbps: 100                        # для congestion control
    down_mbps: 500
  # Client вариант connection URI:
  # hysteria2://<auth>@<server_ip>:443/?insecure=1&obfs=salamander
  #            &obfs-password=<...>&pinSHA256=<cert_sha256>
```

---

## Часть 5. Контейнер 1: `censprobe-dashboard`

### 5.1. Назначение

Визуализация отчётов через Grafana. **Независимый контейнер** — запускается где удобно: локально на ноутбуке, на отдельном VPS, на том же немецком VPS, где крутится control. Единственное требование — у машины должен быть доступ к GitHub (для pull отчётов).

Пуллит отчёты и baseline из git-репозитория **только по явному запросу пользователя** (кнопка "Pull & Refresh" в Grafana или CLI команда). Никаких таймеров, никаких автообновлений.

### 5.2. Независимость от других контейнеров

Dashboard не знает о существовании solo/listener/client/control. Он знает только про один private git-репозиторий, куда пуллит по SSH. Это значит:
- Его можно запустить до того, как любой тестовый контейнер стартовал.
- Его можно запустить на любой машине, где есть SSH-ключ с доступом к репо.
- Его остановка не влияет на процесс тестирования.

### 5.3. Состав

Внутри общего `docker-compose.yml` проекта, профиль `dashboard` включает:
- **postgres** — хранит распарсенные отчёты.
- **grafana** — UI, datasource: Postgres.
- **sync-api** — маленький FastAPI на Python. Эндпоинт `POST /refresh` делает `git pull` в локальном `/workspace` (то есть в склонированный репо, смонтированный как volume), парсит новые файлы из `baseline/` и `reports/`, пишет в Postgres.

Фрагмент docker-compose:
```yaml
services:
  postgres:
    profiles: [dashboard]
    image: postgres:16
    environment:
      POSTGRES_DB: censprobe
      POSTGRES_USER: censprobe
      POSTGRES_PASSWORD: ${DB_PASSWORD:-censprobe}
    volumes:
      - db_data:/var/lib/postgresql/data

  sync-api:
    profiles: [dashboard]
    build: ./packages/dashboard/sync-api
    environment:
      DATABASE_URL: postgresql+asyncpg://censprobe:${DB_PASSWORD:-censprobe}@postgres/censprobe
      WORKSPACE: /workspace
    volumes:
      - ./:/workspace          # репозиторий для git pull
      - ~/.ssh:/root/.ssh:ro   # SSH-ключ для git pull
    depends_on: [postgres]

  grafana:
    profiles: [dashboard]
    image: grafana/grafana:11.2.0
    volumes:
      - grafana_data:/var/lib/grafana
      - ./packages/dashboard/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./packages/dashboard/grafana/dashboards:/var/lib/grafana/dashboards:ro
    ports: ["3000:3000"]
    depends_on: [postgres, sync-api]
```

### 5.4. Кнопка "Pull & Refresh" в Grafana

В Grafana создаётся панель типа `Text` в HTML-режиме с кнопкой:
```html
<button onclick="fetch('/sync-api/refresh', {method:'POST'})
  .then(r=>r.json())
  .then(d=>alert('Synced: '+d.new_reports+' new reports'))">
  🔄 Pull & Refresh from GitHub
</button>
```

Grafana проксирует `/sync-api/*` на контейнер sync-api. Sync-api делает `cd /workspace && git pull` по SSH и парсит новые файлы.

Fallback — CLI:
```bash
docker compose exec sync-api python -m sync_api.cli refresh
```

### 5.5. Схема Postgres

```sql
CREATE TABLE tests (
  test_id         VARCHAR(64) PRIMARY KEY,
  created_at      TIMESTAMPTZ,
  description     TEXT,
  server_meta     JSONB,
  purpose         VARCHAR(32),
  planned_sessions TEXT[]
);

CREATE TABLE reports (
  id              UUID PRIMARY KEY,
  test_id         VARCHAR(64) REFERENCES tests(test_id),
  report_type     VARCHAR(32),   -- solo | listener
  session_id      VARCHAR(128),  -- для listener-отчётов: client-mob-mts-msk; для solo: NULL
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  report_data     JSONB,
  scores          JSONB,
  detected_techniques TEXT[],
  network_meta    JSONB,          -- ASN, ISP, region (только то, на что есть consent)
  submitted_at    TIMESTAMPTZ
);

CREATE INDEX idx_reports_test       ON reports(test_id, report_type, session_id);
CREATE INDEX idx_reports_type_time  ON reports(report_type, started_at DESC);
CREATE INDEX idx_reports_scores     ON reports USING GIN(scores);
CREATE INDEX idx_reports_techniques ON reports USING GIN(detected_techniques);

CREATE TABLE test_results (
  id              BIGSERIAL PRIMARY KEY,
  report_id       UUID REFERENCES reports(id) ON DELETE CASCADE,
  category        VARCHAR(32),    -- dns | tcp | tls | http | telegram | protocols | throttling | middlebox
  test_name       VARCHAR(128),
  target          TEXT,
  verdict         VARCHAR(32),
  method          VARCHAR(64),    -- атрибуция
  confidence      REAL,
  evidence        JSONB
);

CREATE INDEX idx_tr_report ON test_results(report_id);
CREATE INDEX idx_tr_target ON test_results(target, verdict);

CREATE TABLE protocol_attempts (   -- из listener log, events array
  id              BIGSERIAL PRIMARY KEY,
  test_id         VARCHAR(64),
  session_id      VARCHAR(128),   -- from the listener report that produced this event
  protocol        VARCHAR(32),
  from_ip_masked  INET,
  from_asn        VARCHAR(16),
  handshake_ok    BOOLEAN,
  rtt_ms          REAL,
  ts              TIMESTAMPTZ
);
```

### 5.5. Grafana-дашборды (набор)

Поставляются как JSON-файлы в `deploy/dashboard/grafana/dashboards/`, provisioning через Grafana API при старте.

**Dashboard 1 — "Test Overview":**
- Variable `test_id` — dropdown всех известных test_id.
- Panel: meta информация (провайдер, локация, ASN, дата).
- Panel: список session'ов (клиентских сетей) этого test_id со scores.
- Panel: overall scores bar chart (session × score).
- Panel: matrix вердиктов по категориям.

**Dashboard 2 — "Blocking Matrix" (по solo-отчётам):**
- Variable `test_id`.
- Panel: большая таблица target × (solo vs baseline) → verdict (цвета).
- Panel: filter по категориям (news, social, messengers, VPN, Telegram).

**Dashboard 3 — "Telegram Deep Dive":**
- Variable `test_id`.
- Panel: матрица Telegram-таргет (DC, web, CDN, voice) × (solo view vs baseline).
- Panel: throttling profile.

**Dashboard 4 — "VPN Protocol Reachability" (главная панель для VPN-каскада):**
- Variable `test_id`.
- Panel: матрица протокол × session_id → handshake_ok? (OK / BLOCKED).
- Panel: RTT к серверу по протоколам и сессиям.
- Panel: таблица successful/failed attempts из listener events.

**Dashboard 5 — "Technique Attribution":**
- Variable `test_id`.
- Panel: теплокарта techniques × solo.
- Panel: счётчик уникальных техник, обнаруженных solo.

**Dashboard 6 — "Compare Tests":**
- Variables `test_id_a`, `test_id_b`.
- Diff двух тестов side-by-side.
- Для выбора лучшего сервера между кандидатами.

**Dashboard 7 — "Server Suitability Score":**
- Главный "executive summary" дашборд.
- Variable `test_id`.
- Одна большая цифра: итоговый VPN-suitability score.
- Разбивка: entry/exit/relay suitability.
- Краткие рекомендации, какие протоколы использовать.

### 5.6. Запуск

На любой машине, где SSH-ключ добавлен в GitHub как Deploy Key:
```bash
git clone git@github.com:vasiliiok/censprobe.git
cd censprobe
docker compose --profile dashboard up -d
# открой http://<host>:3000 (Grafana)
```

При первом запуске Grafana автоматически провизионируется с Postgres-datasource и набором предустановленных дашбордов из `packages/dashboard/grafana/dashboards/`. В главной панели — кнопка "Pull & Refresh".

---

## Часть 6. Контейнер 2: `censprobe-solo`

### 6.1. Назначение

Автономный прогон всех тестов с перспективы тестируемого сервера. Запустился → сделал → запушил → вышел.

Отвечает на вопрос: **"Что видит из своего аплинка сам сервер?"** Это важно для понимания пригодности сервера как VPN-exit (пользователи через него ходят наружу).

### 6.2. Что делает

1. Работает внутри склонированного репозитория (смонтирован как `/workspace`). SSH-ключ хоста смонтирован read-only для `git push`.
2. `TEST_ID` берётся из переменных окружения запуска.
3. Если `reports/<TEST_ID>/meta.yaml` не существует — инициализирует его на основе автоопределения сервера.
4. Читает `baseline/latest.json`, `targets/*.yaml`, `signatures/*.yaml` из рабочей копии репо.
5. Прогоняет полный набор тестов:
   - DNS (системный, публичные, DoH, DoT).
   - TCP reachability к ключевым IP.
   - TLS/SNI варианты.
   - HTTP-fetch к news/social/messengers.
   - Telegram deep-dive (все DC, web, CDN, voice).
   - Throttling detection — bandwidth-профиль (Метод A): YouTube, Instagram-CDN, Telegram-CDN.
   - **YouTube SNI-throttling probe (Метод B из Части 2.5.5)** — три прогона на `speedtest.selectel.ru` с разными SNI (корректный / `googlevideo.com` / опечатка), сравнение профилей. Даёт атрибуцию троттлинга к SNI-инспекции ТСПУ.
   - Middlebox detection.
   - Тесты IPv6 если доступен.
6. Собирает JSON-отчёт и сохраняет как `reports/<TEST_ID>/server-solo-<timestamp>.json.gz`.
7. Делает `git add && git commit && git push` по SSH.
8. Выходит.

### 6.3. Конфигурация

Никакого `.env` с секретами. Всё нужное — в самом склонированном репозитории и SSH-ключе хоста.

Фрагмент `docker-compose.yml` в репо:
```yaml
services:
  solo:
    profiles: [solo]
    build: ./packages/solo
    network_mode: host
    cap_add: [NET_RAW, NET_ADMIN]
    environment:
      TEST_ID: ${TEST_ID}
    volumes:
      - ./:/workspace            # сам репо — для чтения конфигов и коммитов
      - ~/.ssh:/root/.ssh:ro     # SSH-ключ хоста для git push
    working_dir: /workspace
    restart: "no"
```

### 6.4. Запуск

`TEST_ID` передаётся переменной окружения:
```bash
cd censprobe
TEST_ID=selectel-spb-001 docker compose --profile solo up
# контейнер отработает, сделает git push, завершится
```

### 6.5. Offline buffer

Если `git push` не удался (GitHub недоступен / сеть):
1. Отчёт остаётся в рабочей копии (`reports/<TEST_ID>/...`) и в локальном git commit.
2. Следующий `docker compose --profile solo up` или просто `git push` из репо отправит накопленные коммиты.
3. Принудительный retry: `cd censprobe && git push`.

---

## Часть 7. Контейнер 3: `censprobe-listener`

### 7.1. Назначение

Работает на тестируемом сервере. Слушает на портах известных VPN-протоколов, отвечает на попытки handshake от клиентов, и **по нажатию Ctrl+C пушит отчёт в GitHub**.

Отвечает на вопрос: **"Могут ли клиенты с этой конкретной сети достучаться до этого сервера по каждому из VPN-протоколов?"** Это главный тест пригодности сервера как VPN-entry.

**Ключевой принцип работы — "пустые результаты по умолчанию, заполняем успешными":**
- При старте listener считает, что **ни один протокол не доступен** (все verdict'ы = `BLOCKED`).
- Когда приходит handshake по какому-то протоколу и он корректно завершается — verdict для этого протокола становится `OK`.
- Если протокол так и не получил успешный handshake к моменту Ctrl+C → остаётся `BLOCKED`.

Такой подход даёт честное измерение: мы **не можем знать**, была ли проблема на стороне ноута, на стороне ТСПУ, или где-то в промежутке. Но для оценки пригодности VPN-каскада это не важно — если пакет не дошёл, канал всё равно непригоден, какая бы причина ни была. Поэтому мы сознательно считаем такой случай блокировкой.

### 7.2. Идентификация сессии

Listener запускается с **двумя** идентификаторами:

1. `TEST_ID` — идентификатор всего испытания (например, `selectel-spb-001`).
2. `SESSION_ID` — идентификатор конкретной тестируемой сети (например, `client-mob-mts-msk`).

`SESSION_ID` определяет имя итогового файла отчёта: `server-listener-<SESSION_ID>-<timestamp>.json.gz`. По этому имени dashboard различает, с какой сети шло тестирование.

Для каждой новой сети listener перезапускается с новым `SESSION_ID`. Сам listener не умеет переключаться между сессиями на лету — это сознательное упрощение, чтобы не разбираться с корреляцией входящих пакетов.

### 7.3. Что делает

1. Работает внутри склонированного репозитория (смонтирован как `/workspace`). SSH-ключ хоста — для `git push`. `TEST_ID` и `SESSION_ID` из переменных окружения запуска.
2. При первом запуске для `TEST_ID` (если `reports/<TEST_ID>/meta.yaml` не существует):
   - Генерирует credentials для всех протоколов.
   - Записывает `reports/<TEST_ID>/protocols.yaml`.
   - Записывает `meta.yaml` с автоопределённой информацией о сервере.
   - Делает промежуточный `git add && git commit && git push`, чтобы клиент мог забрать credentials.
3. Инициализирует in-memory result-matrix. **Проверяем две фазы: handshake и передачу небольших данных после него.** Простого handshake недостаточно — TSPU может пропустить handshake и заблокировать передачу данных (shadowsocks active-probing, VLESS+Reality inspection и т.п.).
   ```python
   results = {
       "openvpn":      {"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, "rtt_ms": None, ...},
       "wireguard":    {"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, ...},
       "amneziawg":    {"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, ...},
       "shadowsocks":  {"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, ...},
       "vless_reality":{"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, ...},
       "hysteria2":    {"verdict": "BLOCKED", "handshake_count": 0, "data_transfer_ok": False, ...},
   }
   ```
4. Запускает listener'ы с **протоколом проверки "handshake + echo data"**:
   - **OpenVPN** — `openvpn` бинарь в static-key mode с self-signed cert (минимальный PSK-режим, никаких сертификатов). Отвечает на `P_CONTROL_HARD_RESET_CLIENT_V2`. После handshake ожидает `P_DATA_V1` с тестовым payload (64-256 байт), отправляет эхо обратно.
   - **WireGuard** — `wg-quick`/`wireguard-go` с публичным ключом из protocols.yaml. После установления transport data session ожидает ping-пакет через туннель, отвечает.
   - **AmneziaWG** — `amneziawg-go` с теми же ключами что WG плюс junk/header параметры (Jc/Jmin/Jmax, H1-H4, S1/S2) из protocols.yaml. Логика проверки идентична WG — но пакеты обфусцированы на транспортном уровне.
   - **Shadowsocks** — `sing-box` с inbound type=`shadowsocks` (метод `2022-blake3-aes-256-gcm`) и credentials из protocols.yaml. После handshake ожидает короткий HTTP-like payload через шифрованный канал, эхо.
   - **VLESS+Reality** — `xray-core` с inbound конфигом (`security: reality`, `dest: apimaps.yandex.ru:443`, `serverNames`, X25519 ключи, `flow: xtls-rprx-vision`). Полный TLS handshake с Reality-маскировкой + короткий HTTP GET через туннель, ответ 200 OK.
   - **Hysteria 2** — `hysteria server` бинарь с self-signed cert (generated on first run) + Salamander obfs + auth password. QUIC handshake + UDP datagram с тестовым payload, эхо.
5. При каждом входящем подключении обновляет `results[protocol]`:
   - Если handshake завершён успешно → `handshake_count += 1`, сохраняем RTT.
   - Если после handshake успешно прошёл echo-exchange → `data_transfer_ok = True`.
   - Логирует в in-memory event-log: timestamp, протокол, from_ip_masked, from_asn, handshake_duration_ms, data_transfer_duration_ms, data_bytes_echoed.
6. По сигналу SIGINT (Ctrl+C) или SIGTERM (`docker stop`):
   - Финализирует результаты для каждого протокола:
     - `handshake_count > 0` И `data_transfer_ok = True` → `verdict = OK`.
     - `handshake_count > 0` И `data_transfer_ok = False` → `verdict = HANDSHAKE_ONLY` (подозрение на deep inspection данных).
     - `handshake_count == 0` → `verdict = BLOCKED` (TSPU срубил ещё на handshake).
   - Записывает сводный отчёт `reports/<TEST_ID>/server-listener-<SESSION_ID>-<timestamp>.json.gz`.
   - `git add && git commit && git push`.
   - Выходит.

Формат итогового отчёта:
```json
{
  "test_id": "selectel-spb-001",
  "session_id": "client-mob-mts-msk",
  "listener_started_at": "2026-04-21T13:20:00Z",
  "listener_stopped_at": "2026-04-21T13:35:22Z",
  "duration_sec": 922,
  "results": {
    "openvpn": {
      "verdict": "BLOCKED",
      "handshake_count": 0,
      "data_transfer_ok": false,
      "first_handshake_at": null,
      "avg_rtt_ms": null
    },
    "wireguard": {
      "verdict": "BLOCKED",
      "handshake_count": 0,
      "data_transfer_ok": false,
      ...
    },
    "amneziawg": {
      "verdict": "OK",
      "handshake_count": 3,
      "data_transfer_ok": true,
      "first_handshake_at": "2026-04-21T13:22:08Z",
      "avg_rtt_ms": 62.4,
      "avg_data_echo_ms": 65.1,
      "from_asn": "AS8359",
      "note": "WireGuard прошёл после добавления AmneziaWG junk+header obfuscation"
    },
    "shadowsocks": {
      "verdict": "HANDSHAKE_ONLY",
      "handshake_count": 3,
      "data_transfer_ok": false,
      "first_handshake_at": "2026-04-21T13:22:40Z",
      "avg_rtt_ms": 48.2,
      "note": "handshake проходит, но эхо-данные не доходят — подозрение на active probing / deep inspection"
    },
    "vless_reality": {
      "verdict": "OK",
      "handshake_count": 3,
      "data_transfer_ok": true,
      "first_handshake_at": "2026-04-21T13:23:14Z",
      "avg_rtt_ms": 42.5,
      "avg_data_echo_ms": 48.1,
      "from_asn": "AS8359"
    },
    "hysteria2": {
      "verdict": "OK",
      "handshake_count": 2,
      "data_transfer_ok": true,
      "first_handshake_at": "2026-04-21T13:25:01Z",
      "avg_rtt_ms": 51.2,
      "avg_data_echo_ms": 55.7
    }
  },
  "events": [
    {"ts": "2026-04-21T13:23:14Z", "protocol": "vless_reality", "phase": "handshake", "from_asn": "AS8359", "duration_ms": 40},
    {"ts": "2026-04-21T13:23:14Z", "protocol": "vless_reality", "phase": "data_echo", "bytes": 128, "duration_ms": 48},
    {"ts": "2026-04-21T13:23:45Z", "protocol": "vless_reality", "phase": "handshake", "from_asn": "AS8359", "duration_ms": 45},
    ...
  ]
}
```

### 7.4. Конфигурация

Всё необходимое — в склонированном репо. SSH-ключ хоста монтируется в контейнер для `git push`.

Фрагмент `docker-compose.yml`:
```yaml
services:
  listener:
    profiles: [listener]
    build: ./packages/listener
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    environment:
      TEST_ID: ${TEST_ID}
      SESSION_ID: ${SESSION_ID}
    volumes:
      - ./:/workspace
      - ~/.ssh:/root/.ssh:ro
    working_dir: /workspace
    stop_grace_period: 60s   # чтобы успеть дописать и запушить на SIGTERM
    restart: "no"
```

Список протоколов и портов listener берёт из `protocols/default.yaml` — он уже в репо.

### 7.5. Запуск и цикл сессий

Полный цикл теста с несколькими сетями:

```bash
# --- Сессия 1: домашний Ростелеком ---
TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb \
  docker compose --profile listener up
# foreground, чтобы легко остановить Ctrl+C
# На ноутбуке подключился к домашнему Wi-Fi, запустил клиент-контейнер
# → клиент стучится на listener, handshakes летят
# После нескольких минут — Ctrl+C
# listener коммитит server-listener-client-home-rt-spb-<ts>.json.gz
# делает git push и выходит

# --- Сессия 2: мобильный МТС ---
TEST_ID=selectel-spb-001 SESSION_ID=client-mob-mts-msk \
  docker compose --profile listener up

# --- Сессия 3: МегаФон ---
TEST_ID=selectel-spb-001 SESSION_ID=client-mob-mf-ekb \
  docker compose --profile listener up
```

`TEST_ID` внутри одного испытания не меняется (тестируем один сервер); `SESSION_ID` меняется на каждую сеть. Между сессиями полезно делать `git pull` на случай, если control или другой контейнер что-то запушил.

### 7.6. Безопасность listener'а

- Все протоколы — в **тестовом dummy-режиме**. OpenVPN не раздаёт IP, WG не форвардит, SS не проксирует. Listener только делает handshake и сразу закрывает сессию.
- Credentials в `protocols.yaml` — одноразовые для теста. После завершения теста использовать их нельзя для реальных VPN-коннектов.
- Порты слушают только на время теста. После Ctrl+C всё закрыто.
- Listener не функционирует как реальный VPN — он не открывает порты в обычную сеть. Роскомнадзор может сделать active probing и увидеть, что "VPN здесь" — но это ровно то, что мы хотим измерить.

---

## Часть 8. Контейнер 4: `censprobe-client`

### 8.1. Назначение

Запускается на клиентской машине (ноутбук, телефон через hotspot, VPS с другим аплинком). **Единственная задача — стучаться по VPN-протоколам на listener тестируемого сервера.**

Отвечает на вопрос: **"Дойдут ли пакеты по каждому из VPN-протоколов до конкретного сервера с этой конкретной клиентской сети?"**

Специально минималистичный:
- **Не пушит никаких отчётов** в GitHub — только читает.
- **Не знает про session_id** — это ответственность listener'а.
- **Не делает внешних тестов** (DNS/HTTP/Telegram) — эти тесты делают solo и control. Если надо оценить, что видит клиентская сеть — можно запустить solo-контейнер на этом же ноуте как отдельную задачу.

Клиент — просто "стукач-тренажёр" для listener'а: скачал список протоколов и креды, прошёл по списку, вывел результат в терминал.

### 8.2. Что делает

1. Работает внутри склонированного репозитория (смонтирован как `/workspace`). SSH-ключ монтируется для `git pull`.
2. `TEST_ID` и `SERVER_HOST` берутся из переменных окружения запуска.
3. При старте делает `git pull`, чтобы получить свежий `reports/<TEST_ID>/protocols.yaml` (вдруг listener только что его сгенерировал) и `protocols/default.yaml`.
4. Для каждого протокола из `protocols/default.yaml` делает **две фазы: handshake + echo-exchange** (просто handshake недостаточно — TSPU может пропустить handshake и блокировать данные):
   - **OpenVPN**: через `openvpn --client` (static-key режим) на `<SERVER_HOST>:1194/UDP` с PSK из `protocols.yaml`. Ждёт установления туннеля, шлёт ping 128 байт через `tun`, ждёт эхо.
   - **WireGuard**: через `wg-quick up` с кастомным конфигом на `<SERVER_HOST>:51820/UDP`. Ждёт handshake response (type 2). После установления transport data session посылает ping через туннель, ждёт pong.
   - **AmneziaWG**: через `amneziawg-go` с ключами + junk/header параметрами из `protocols.yaml` на `<SERVER_HOST>:51821/UDP`. Логика как у WG, но сначала идут junk packets, handshake с padded header.
   - **Shadowsocks-2022**: через `sing-box` outbound (type=shadowsocks, `2022-blake3-aes-256-gcm`) на `<SERVER_HOST>:8388/TCP`. Encrypted handshake + HTTP-like payload через канал, ждёт эхо.
   - **VLESS+Reality**: через `xray-core` outbound с Reality settings (pbk, short_id, sni=apimaps.yandex.ru, fp=chrome, flow=xtls-rprx-vision) на `<SERVER_HOST>:443/TCP`. TLS handshake с подстановкой серверного сертификата microsoft, затем HTTP GET через туннель.
   - **Hysteria 2**: через `hysteria client` с URI `hysteria2://<auth>@<host>:443/?insecure=1&obfs=salamander&obfs-password=...`. QUIC handshake + UDP datagram с тестовым payload.
5. Повторяет каждый тест 3 раза с джиттером между попытками (чтобы listener успел набрать `handshake_count > 1`).
6. Завершается. **Ничего не коммитит в git.**

Для каждого протокола в stdout выводится:
- Успех handshake (ms) / fail.
- Успех data echo (ms, bytes) / fail.
- Итог по попытке: `connected` / `handshake-only` / `no response` / `reset`.

Логи клиент пишет только в stdout — пользователь видит в терминале, до каких протоколов долетело и насколько полноценно.

### 8.3. Конфигурация

Всё необходимое — в склонированном репо. SSH-ключ для `git pull`:

```yaml
services:
  client:
    profiles: [client]
    build: ./packages/client
    network_mode: host
    cap_add: [NET_RAW]
    environment:
      TEST_ID: ${TEST_ID}
      SERVER_HOST: ${SERVER_HOST}
    volumes:
      - ./:/workspace
      - ~/.ssh:/root/.ssh:ro
    working_dir: /workspace
    restart: "no"
```

### 8.4. Запуск

```bash
cd censprobe
git pull
TEST_ID=selectel-spb-001 SERVER_HOST=<IP_или_FQDN_сервера> \
  docker compose --profile client up
```

Типичный вывод в терминале:
```
[client] git pull ... OK
[client] Reading protocols/default.yaml ... OK
[client] Reading reports/selectel-spb-001/protocols.yaml ... OK
[client] Testing handshakes to <SERVER_HOST>:

  openvpn      (UDP/1194)   ... attempt 1/3 ... no handshake response (timeout)
                             attempt 2/3 ... no handshake response
                             attempt 3/3 ... no handshake response
                             RESULT: BLOCKED (handshake не доходит)

  wireguard    (UDP/51820)  ... attempt 1/3 ... no handshake response
                             attempt 2/3 ... no handshake response
                             attempt 3/3 ... no handshake response
                             RESULT: BLOCKED

  amneziawg    (UDP/51821)  ... attempt 1/3 ... junk packets sent (8x random 40-70B),
                                               handshake OK (64ms), echo OK (68ms, 128B)
                             attempt 2/3 ... handshake OK (62ms), echo OK (65ms)
                             attempt 3/3 ... handshake OK (61ms), echo OK (67ms)
                             RESULT: CONNECTED (WireGuard прошёл после обфускации!)

  shadowsocks  (TCP/8388)   ... attempt 1/3 ... handshake OK (48ms), echo-data timeout
                             attempt 2/3 ... handshake OK (51ms), echo-data timeout
                             attempt 3/3 ... handshake OK (49ms), echo-data timeout
                             RESULT: HANDSHAKE_ONLY (подозрение на active probing)

  vless+reality (TCP/443)   ... attempt 1/3 ... handshake OK (42ms), echo 200 OK (48ms, 128B)
                             attempt 2/3 ... handshake OK (40ms), echo 200 OK (46ms)
                             attempt 3/3 ... handshake OK (41ms), echo 200 OK (47ms)
                             RESULT: CONNECTED

  hysteria2    (UDP/443)    ... attempt 1/3 ... handshake OK (55ms), echo OK (58ms, 128B)
                             attempt 2/3 ... handshake OK (52ms), echo OK (55ms)
                             RESULT: CONNECTED

[client] Done. Stop listener on the server (Ctrl+C) to push results to GitHub.
```

### 8.5. Цикл тестирования нескольких сетей

На стороне пользователя, который хочет протестировать сервер с нескольких клиентских сетей:

```bash
# --- Сессия 1: домашний Ростелеком ---
# На сервере: SESSION_ID=client-home-rt-spb, docker compose up listener
# На ноуте (подключён к домашнему Wi-Fi):
docker compose run --rm client
# → видит в терминале, что работает, что не работает
# → идёт на сервер, жмёт Ctrl+C на listener, тот пушит отчёт

# --- Сессия 2: мобильный МТС ---
# На сервере: изменил SESSION_ID=client-mob-mts-msk, docker compose up listener
# На ноуте (переключился на hotspot МТС):
docker compose run --rm client
# → снова видит результаты
# → Ctrl+C на listener — второй отчёт запушен

# И так далее для других сетей.
```

### 8.6. Opsec для client

Клиентский контейнер по факту генерирует очень характерный трафик — 5 разных VPN-протоколов к одному IP за короткое время. Это палит и его, и тестируемый сервер. Митигации:

- Джиттер между handshake'ами разных протоколов (5–15 сек).
- Рандомизация порядка протоколов.
- Warning при первом запуске о том, что такой паттерн может быть классифицирован ТСПУ как "тест VPN-инфраструктуры" и может потенциально привлечь внимание.
- Клиент не пишет на диск сведений о сервере кроме того, что приходит в переменной окружения `SERVER_HOST` при запуске (не сохраняется).

Рекомендация пользователю: тесты делать **не с основного рабочего устройства**, использовать отдельный ноут/флешку с live Linux, если опсек критичен.

---

## Часть 9. Контейнер 5: `censprobe-control`

### 9.1. Назначение

Запускается на VPS в чистой юрисдикции (Германия — Hetzner, либо другая страна вне РФ). **Производит эталонный baseline**, с которым потом сравнивают свои результаты solo/client.

Отвечает на вопрос: **"Как должен выглядеть ответ из чистого интернета для этих тестов?"** Без эталона мы не можем различать "ресурс заблокирован" vs "ресурс сам упал".

**Ключевой принцип: контейнер запускается пользователем вручную перед каждым новым испытанием.** Никаких cron'ов, никаких автоматических обновлений. Пользователь запускает control с флагом `--rm` (удаляется сразу после завершения работы), тот прогоняет тесты, пушит baseline в GitHub и исчезает.

Это даёт полный контроль над тем, когда baseline актуален, и гарантирует, что каждое испытание тестируемого сервера сравнивается со свежим эталоном.

### 9.2. Что делает

По сути это **тот же набор тестов, что и у solo**, но:
- Запущен с чистого немецкого аплинка → результаты = "чистый интернет".
- Агрегирует N повторов (default 5) для устойчивости.
- Формирует статистики (median, percentiles) для throttling и body_length.
- Коммитит результат в `baseline/` в репо, не в `reports/`.

Шаги:
1. Работает внутри склонированного репо (смонтирован как `/workspace`). SSH-ключ хоста — для `git push`. `RUNS_COUNT` (default 5) — переменная окружения запуска.
2. Читает `targets/*.yaml` из локального репо (чтобы тестировать тот же набор, что и probes).
3. Прогоняет полный набор тестов N раз:
   - DNS (A/AAAA/NS записи + ASN IP-адресов).
   - TLS cert chains для всех HTTPS-таргетов.
   - HTTP fetch: status, headers, body_length, stable fragments SHA256.
   - Telegram DC reachability + web + CDN.
   - Throttling profile: bandwidth p50/p10/p90 для YouTube/Instagram-CDN/Telegram-CDN.
   - **SNI-throttling baseline** — все три прогона (корректный SNI / `googlevideo.com` / опечатка) на selectel, чтобы у solo был эталон "вот как должен выглядеть трёх-прогонный профиль без ТСПУ". На чистом немецком аплинке все три должны показать одинаковую полную скорость.
4. Агрегирует: median для численных, union для категориальных, range для throttling.
5. Собирает `baseline.json` с метаданными control-point'а.
6. Записывает в `baseline/<YYYY-MM-DD>-<hash>.json` и обновляет `baseline/latest.json`.
7. `git add && git commit && git push`, контейнер останавливается.

### 9.3. Формат baseline

```json
{
  "version": "2026-04-21-control-de-01",
  "generated_at": "2026-04-21T02:00:00Z",
  "generated_from": {
    "control_id": "control-de-hetzner-fsn-01",
    "asn": "AS24940",
    "country": "DE",
    "city": "Falkenstein",
    "ipv6_available": true
  },
  "probe_core_version": "0.3.0",
  "targets_version": "2026-04-18-01",
  "validity_until": "2026-04-28T02:00:00Z",
  "runs_count": 5,
  
  "dns": {
    "meduza.io": {
      "a_records_asn": ["AS13335"],
      "aaaa_records_asn": ["AS13335"],
      "observed_ips_v4": ["104.18.5.10", "104.18.4.10"],
      "ttl_range": [60, 300]
    }
  },
  
  "tls": {
    "meduza.io": {
      "cert_chain_sha256": ["ab:cd:..."],
      "cert_subject_cn": "meduza.io",
      "cert_issuer_cn": "Cloudflare Inc ECC CA-3",
      "ja4_server": "t13d1516h2_...",
      "alpn": ["h2", "http/1.1"]
    }
  },
  
  "http": {
    "https://meduza.io/": {
      "status": 200,
      "title_regex": "Meduza",
      "body_length_range": [45000, 200000],
      "stable_fragments_sha256": {
        "logo_svg": "abc123...",
        "footer_copyright": "def456..."
      }
    }
  },
  
  "telegram": {
    "dc1_ipv4_443": {"reachable": true, "rtt_range_ms": [80, 140]},
    "dc2_ipv4_443": {"reachable": true, "rtt_range_ms": [15, 40]}
  },
  
  "throttling": {
    "googlevideo.com": {
      "bandwidth_mbps_p50": 125.4,
      "bandwidth_mbps_p10": 80.0,
      "ttfb_ms_p50": 45
    }
  },

  "sni_throttling": {
    "_comment": "Baseline для Метода B. На чистом аплинке все три прогона должны быть похожими — это подтверждает, что selectel.ru отдаёт полную скорость независимо от SNI.",
    "target_ip_host": "speedtest.selectel.ru",
    "runs": {
      "correct_sni":      {"sni": "speedtest.selectel.ru", "bandwidth_mbps_p50": 480, "drop_pattern": "none"},
      "googlevideo_sni":  {"sni": "googlevideo.com",       "bandwidth_mbps_p50": 478, "drop_pattern": "none"},
      "typo_sni":         {"sni": "googleviideo.com",      "bandwidth_mbps_p50": 481, "drop_pattern": "none"}
    }
  }
}
```

### 9.4. Сравнение с baseline — как работает verdict

Probe (solo/client) после прогона сравнивает свои результаты с baseline:

```python
def compute_verdict(probe_result, baseline, target):
    b = baseline.get(target)
    if not b:
        return ANOMALY   # таргета нет в baseline — странно

    # Сравнение по ASN устойчиво к IP-ротации CDN
    if probe_result.resolved_asn not in b.dns.a_records_asn:
        if probe_result.cert_valid_for_domain is False:
            return DNS_POISONING
        return ANOMALY

    # Для bandwidth: сравнение с baseline.p10 * 0.3
    if probe_result.bandwidth_mbps < b.throttling.bandwidth_mbps_p10 * 0.3:
        return THROTTLED

    # Для TLS: если cert chain hash не совпадает — MITM или другой сервер
    if probe_result.cert_chain_sha256 != b.tls.cert_chain_sha256:
        return TLS_MITM  # или смена cert-а у сервиса (редкое)

    # Для HTTP body: проверяем stable fragments и длину
    if probe_result.body_length not in range(*b.http.body_length_range):
        if probe_result.body_contains_blockpage_fingerprint():
            return BLOCKPAGE
        return ANOMALY

    return OK
```

Критичный момент: **сравниваем ASN, а не конкретный IP**. Cloudflare ротирует IP, но все остаются в AS13335. Это устраняет 90% ложных срабатываний.

### 9.5. Конфигурация

Всё нужное — в склонированном репо. SSH-ключ хоста для `git push`:

```yaml
services:
  control:
    profiles: [control]
    build: ./packages/control
    network_mode: host
    cap_add: [NET_RAW, NET_ADMIN]
    environment:
      RUNS_COUNT: ${RUNS_COUNT:-5}
    volumes:
      - ./:/workspace
      - ~/.ssh:/root/.ssh:ro
    working_dir: /workspace
    restart: "no"
```

### 9.6. Запуск

Control запускается **вручную перед каждым новым испытанием** или когда есть основания считать baseline устаревшим.

```bash
# На немецком VPS:
cd censprobe
git pull
docker compose --profile control up
```

Контейнер стартует, прогоняет тесты (~5–10 минут), записывает baseline, делает `git push` и завершается. Запускался с `up`, поэтому Docker Compose уберёт остановленный контейнер; при необходимости можно запустить с `docker compose --profile control up --abort-on-container-exit`.

**Типичный сценарий использования:**
1. Решаешь протестировать новый сервер в РФ.
2. Перед запуском solo/listener/client — заходишь на немецкий VPS, `git pull && docker compose --profile control up`.
3. Через ~5–10 минут свежий baseline в репе.
4. На тестируемом сервере делаешь `git pull`, запускаешь тесты.

### 9.7. Где разместить control-point

Варианты по приоритету:
1. **Собственный VPS в DE/NL/FI** — рекомендуется. Полный контроль, предсказуемое окружение. Для текущего проекта — существующий VPS в Hetzner (Falkenstein).
2. **Несколько control-points в разных юрисдикциях** — для усреднения и устойчивости. Архитектурно возможно, но за рамками MVP.

### 9.8. Когда запускать control

Понимание, когда нужен свежий baseline, — на усмотрение пользователя. Очевидные триггеры:

- Перед началом нового испытания тестируемого сервера.
- После добавления новых таргетов в `targets/`.
- После изменения landscape (крупный сервис сменил провайдера, CDN сменили IP-ranges).
- Если прошлый baseline старше ~2 недель и есть сомнения в его актуальности.

Слишком редкое обновление baseline ведёт к ложным "poisoning"/"MITM" вердиктам из-за устаревших IP/certs. Слишком частое — к избыточным коммитам в репо. Разумный ритм — перед каждой серьёзной тестовой сессией или раз в 1–2 недели.

### 9.9. Опсек самого control-point

- Control-point не светится для ТСПУ напрямую — он в Германии, трафик от него не проходит через РФ.
- Но он делает HTTP-запросы к meduza.io, CDN Telegram и т.п. — это характерный паттерн. Для анти-fingerprinting:
  - Рандомизация порядка тестов.
  - Джиттер между запросами.
  - Смешивание с нейтральными запросами.
- SSH-ключ для git push хранится только на control-VPS, не переиспользуется.

---

## Часть 10. Содержимое репозитория

### 10.1. Назначение

`vasiliiok/censprobe` — один private git-репозиторий, клонируемый по SSH. Содержит код всех контейнеров, их общие конфиги, эталонный baseline и отчёты испытаний. Private, потому что:
- Хранятся credentials протоколов тестирования (одноразовые, но всё же).
- Хранятся IP/ASN тестируемых RU-серверов (маскированные, но репо не стоит светить).
- Нет необходимости в публичности.

### 10.2. Структура

```
censprobe/
├── README.md
├── docker-compose.yml             # профили: solo, listener, client, control, dashboard
├── pyproject.toml                 # Python workspace
│
├── packages/                      # код контейнеров
│   ├── probe-core/
│   ├── solo/
│   ├── listener/
│   ├── client/
│   ├── control/
│   └── dashboard/
│
├── targets/
│   ├── news.yaml
│   ├── social.yaml
│   ├── messengers.yaml
│   ├── vpn.yaml
│   ├── telegram.yaml
│   └── neutral.yaml               # для mix (vk.com, yandex.ru, wikipedia.org)
│
├── signatures/
│   ├── protocols.yaml
│   ├── blockpages.yaml
│   └── dns_fingerprints.yaml
│
├── protocols/
│   └── default.yaml               # какие VPN-протоколы и на каких портах
│
├── baseline/
│   ├── latest.json                # актуальный baseline
│   └── archive/
│       ├── 2026-04-21-01.json
│       ├── 2026-04-15-01.json
│       └── 2026-04-08-01.json
│
├── reports/                       # отчёты испытаний
│   └── <test_id>/
│       ├── meta.yaml
│       ├── protocols.yaml
│       ├── server-solo-*.json.gz
│       └── server-listener-<session>-*.json.gz
│
└── docs/
    ├── QUICKSTART.md
    └── BASELINE.md
```

### 10.3. Генерация baseline

Единственный источник baseline — контейнер `control` (см. Часть 9), запускаемый вручную на немецком VPS:

```bash
# На немецком VPS
cd censprobe
git pull
docker compose --profile control up
```

Контейнер стартует, прогоняет тесты (~5–10 минут), записывает результат в `baseline/latest.json` и архивирует предыдущий в `baseline/archive/`, делает `git push` и завершается. Никаких фоновых процессов, никаких таймеров. Пользователь решает, когда нужен свежий baseline — см. Часть 9.8 о разумных триггерах.

### 10.4. Обновление targets

`targets/*.yaml` редактируются прямо в рабочей копии репо: меняешь, `git commit`, `git push`. На других машинах — `git pull` при следующем запуске контейнеров автоматически подхватит обновления.

После существенных изменений в `targets/` обязательно запусти control-контейнер, чтобы baseline покрывал новые ресурсы.

После существенного обновления targets.yaml обязательно запусти control-контейнер, чтобы эталон покрывал новые ресурсы.

---

## Часть 11. Что видно в Grafana — финальный отчёт

### 11.1. Структура Dashboard 7 "Server Suitability" (главный)

Открываешь Grafana → выбираешь test_id из dropdown → видишь:

```
┌────────────────────────────────────────────────────────────┐
│  Test: selectel-spb-001                         [Refresh]  │
│  Selectel SPb VPS — оценка для VPN entry                   │
│  Started: 2026-04-21 12:00 | Vantages: 5                   │
├────────────────────────────────────────────────────────────┤
│                                                            │
│       ┌─────────────────────────────────────────┐          │
│       │         VPN Suitability Score           │          │
│       │                                         │          │
│       │              64 / 100                   │          │
│       │                                         │          │
│       │         ▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░             │          │
│       └─────────────────────────────────────────┘          │
│                                                            │
│  ┌─ By role ────────────────────────────────────────────┐  │
│  │ As VPN entry:   ████████████████░░░░   77/100        │  │
│  │ As VPN exit:    ████████░░░░░░░░░░░░   41/100        │  │
│  │ As relay node:  ██████████████████░░   85/100        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─ Reachability to this server by protocol ───────────┐   │
│  │                                                     │   │
│  │              │ home-rt │ mob-mts │ mob-mf │ wifi-ct │   │
│  │  OpenVPN     │    ✗    │    ✗    │   ✗    │    ✗    │   │
│  │  WG (vanilla)│    ✗    │    ✗    │   ✗    │    ✗    │   │
│  │  SS-2022     │    ~    │    ✗    │   ✗    │    ✓    │   │
│  │  VLESS+Reali.│    ✓    │    ✓    │   ✓    │    ✓    │   │
│  │  Hysteria 2  │    ✓    │    ~    │   ✓    │    ✓    │   │
│  │                                                     │   │
│  │  Recommendation: VLESS+Reality primary,             │   │
│  │                  Hysteria 2 fallback                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                            │
│  ┌─ Server's own uplink (server-solo) ──────────────────┐  │
│  │  DNS integrity:   95/100                             │  │
│  │  TLS integrity:   92/100                             │  │
│  │  Telegram:        65/100                             │  │
│  │  Throttling:      detected (youtube, instagram)      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─ Detected techniques (union) ────────────────────────┐  │
│  │  - DNS poisoning (client vantages)                   │  │
│  │  - SNI blocking (all)                                │  │
│  │  - TCP RST injection (all)                           │  │
│  │  - OpenVPN signature blocking (all)                  │  │
│  │  - Bandwidth throttling                              │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─ Vantages ───────────────────────────────────────────┐  │
│  │  server-solo         OK   (prev test: 2026-03-15)    │  │
│  │  server-listener     OK   (123 inbound attempts)     │  │
│  │  client-home-rt-spb  OK   (score: 38/100)            │  │
│  │  client-mob-mts-msk  OK   (score: 29/100)            │  │
│  │  client-mob-mf-ekb   WARN (partial data)             │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### 11.2. Scoring — как считается "Server Suitability"

**As VPN entry** — для клиентов в РФ, которые через этот сервер ходят в интернет:
```
entry_score = (
  avg_protocol_reachability_from_clients * 60%  +
  avg_server_uplink_quality * 30%               +
  avg_latency_score * 10%
)
```
Где `avg_protocol_reachability_from_clients` — какая доля протоколов работает хотя бы с половины клиентских vantage'ов.

**As VPN exit** — для тех, кто хочет получить российский IP:
```
exit_score = (
  server_external_ip_reachable * 40%     +
  server_uplink_low_censorship * 40%     +
  no_geoblock_inbound * 20%
)
```

**As relay** — чисто TCP/UDP без политики:
```
relay_score = (
  basic_tcp_udp_reachability * 70%       +
  throughput * 30%
)
```

**Overall VPN Suitability:**
```
overall = max(entry_score, exit_score, relay_score)  # берём лучшее применение
```

Полные формулы и веса — в `packages/probe-core/scoring.py`.

### 11.3. Композитный HTML/PDF отчёт

Для использования вне Grafana (отчёт в статью, отправить коллеге) — отдельный профиль `reporter` в общем `docker-compose.yml`:

```bash
cd censprobe
git pull
TEST_ID=selectel-spb-001 FORMAT=html,pdf \
  docker compose --profile reporter up
# → HTML/PDF появится в ./reports/<test_id>/render/
```

Контейнер читает отчёты из рабочей копии репо, генерит self-contained HTML (Tailwind inline, Chart.js inline) и PDF (WeasyPrint). Структура — executive summary, blocking matrix, technique attribution, time series.

---



## Часть 13. Privacy и opsec

### 13.1. Матрица privacy

| Данные | solo | listener | client | control | В отчёт GitHub | Публично видно |
|--------|------|----------|--------|---------|----------------|----------------|
| Полный IP тестируемого сервера | да | да | видит | нет | маскируется до /24 | нет (репо приватный) |
| ASN тестируемого сервера | да | да | да | нет | да | нет |
| Full IP клиента | — | видит в inbound | — | нет | маскируется до /24 | нет |
| ASN клиента | — | да | — | нет | да | нет |
| ISP клиента | — | определяется listener'ом | — | нет | opt-in | нет |
| Regions | да | — | — | нет | opt-in (solo) | нет |
| Полный IP control-VPS | — | — | — | да | нет | нет |
| ASN control-VPS | — | — | — | да | да (в baseline) | нет |
| Credentials VPN | — | генерит | использует | — | plaintext в приватном репо | нет |
| Body заблок. страниц | — | — | — | — | SHA256+len | нет |

Клиентский контейнер **ничего не публикует в GitHub сам** — только скачивает `protocols.yaml`. Все данные о клиентской сети (ASN, тип соединения) собирает listener на стороне сервера, где видит входящие коннекты.

Контрольный сервер не видит никаких данных о клиентах и тестируемых серверах — он полностью изолирован. В baseline попадает только ASN control-VPS, что само по себе не раскрывает приватной информации.

### 13.2. Threat model

**Что может злоумышленник, получивший read-доступ к репозиторию `censprobe`:**
- Узнать список серверов, которые ты тестируешь (через IP /24 в meta.yaml).
- Узнать ASN/ISP клиентских сессий (SESSION_ID имена).
- Не узнать: точные IP клиентов, точные IP серверов (только /24), физические локации, реальные VPN-credentials (те, что в `protocols.yaml`, одноразовые для теста).

**Митигация:**
- Private репо, 2FA на GitHub аккаунте.
- Deploy Keys с write-доступом только к этому одному репо (не к аккаунту целиком).
- На каждой машине отдельный SSH-ключ — при компрометации одной машины удаляешь только её ключ из Deploy Keys, не трогая остальных.
- Регулярная ревизия Deploy Keys в настройках репо.

### 13.3. Legal disclaimer

Инструмент запускается **на собственной инфраструктуре пользователя** для оценки её качества. Это не:
- Distributed testing третьих лиц.
- Попытка обхода блокировок.
- Публикация методов обхода.

При запуске первый раз — дисклеймер, пользователь явно соглашается.



---

## Приложение A. Полезные источники

- OONI Probe + spec: https://github.com/ooni/probe, https://github.com/ooni/spec
- Citizen Lab test-lists: https://github.com/citizenlab/test-lists
- ТСПУ detailed docs (community): https://github.com/DanielLavrushin/tspu-docs
- net4people/bbs — дискуссии: https://github.com/net4people/bbs
- Censored Planet: https://censoredplanet.org/
- DNEye paper (DoH/DoT/ESNI accessibility): https://arxiv.org/pdf/2202.00663
- CERTainty paper (DNS manipulation via TLS certs): https://arxiv.org/pdf/2305.08189
- xray-core (VLESS+Reality): https://github.com/XTLS/Xray-core
- sing-box (universal): https://github.com/SagerNet/sing-box
- hysteria 2: https://github.com/apernet/hysteria