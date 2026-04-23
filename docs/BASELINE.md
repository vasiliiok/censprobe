# Censprobe — Baseline Guide

## Что такое Baseline

Baseline — это эталонные измерения с **чистого** (не-российского) сервера.
Он нужен чтобы отличить реальную блокировку от нормального поведения сайта.

Например: если `meduza.io` возвращает 403 и в России, и в Германии — это не блокировка.
Если в России DNS отвечает другим IP чем в Германии — это DNS poisoning.

---

## Структура baseline/latest.json

```json
{
  "version": "2026-04-21-control-de-01-01",
  "generated_at": "2026-04-21T10:00:00Z",
  "validity_until": "2026-04-28T10:00:00Z",
  "runs_count": 5,
  "generated_from": {
    "control_id": "control-de-01",
    "asn": "AS13335",
    "country": "DE"
  },
  "dns": {
    "meduza.io": {
      "a_records_asn": ["AS9049"],
      "observed_ips_v4": ["185.22.153.56"]
    }
  },
  "tls": {
    "meduza.io": {
      "cert_chain_sha256": ["abc123..."],
      "cert_subject_cn": "meduza.io",
      "alpn": ["h2"]
    }
  },
  "http": {
    "https://meduza.io": {
      "status": 200,
      "body_length_range": [45000, 65000]
    }
  },
  "telegram": {
    "telegram_dc1_v4_443": {
      "reachable": true,
      "rtt_range_ms": [20.0, 80.0]
    }
  },
  "throttling": {
    "youtube.com": {
      "bandwidth_mbps_p10": 85.0,
      "bandwidth_mbps_p50": 120.0
    }
  }
}
```

---

## Как обновить baseline

```bash
# На DE-VPS (control):
RUNS_COUNT=5 docker compose --profile control up --build

# Проверь что обновился:
cat baseline/latest.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['version'], d['validity_until'])"
```

Baseline автоматически архивируется в `baseline/archive/<version>.json`.

---

## Срок действия

По умолчанию baseline действителен **7 дней** (`validity_until`).

Если baseline просрочен, solo будет выдавать `INCONCLUSIVE` вместо реальных вердиктов.

Рекомендуется обновлять baseline **раз в неделю** по cron:

```bash
# На control-VPS, crontab -e:
0 3 * * 1 cd /home/censprobe && RUNS_COUNT=5 docker compose --profile control up --build >> /var/log/censprobe-control.log 2>&1
```

---

## Как solo использует baseline

1. Загружает `baseline/latest.json` при старте
2. Для каждого теста сравнивает с baseline-значением
3. Если baseline просрочен или отсутствует → вердикт `INCONCLUSIVE` с пометкой
4. Если baseline устарел (> 14 дней) → продолжает работать но с предупреждением

---

## Минимальный baseline (заглушка)

При первом запуске до появления настоящего baseline используется `baseline/latest.json` из репозитория:

```json
{"version": "stub-0.1", "dns": {}, "tls": {}, "http": {}, "telegram": {}, "throttling": {}}
```

В этом режиме solo работает, но все вердикты будут `INCONCLUSIVE`.
Запусти `control` как можно скорее для получения реального baseline.
