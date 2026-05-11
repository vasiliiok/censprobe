# Тестовое покрытие проекта

Этот документ — **конкретный inventory**: какие тест-файлы какие части кодовой базы реально покрывают на текущий момент. Подходы и методология описаны в [`TESTING.md`](TESTING.md). Гайд по запуску — в [`CONTRIBUTING.md`](CONTRIBUTING.md).

Цифры:

- **58 тест-файлов** в 7 деревьях.
- **765 collected test** (после расширения `parametrize`); из них 763 default + 2 deselected (e2e, `e2e-dashboard` job).
- **Coverage on new code: ~40%** (общая coverage растёт по плану — см. раздел «Roadmap»; точное число — в SonarCloud отчёте последнего PR).
- **8 required CI gates** (`lint`, `validate-config`, `test × 6-package matrix`, `cross-package-tests`, `network-tests`, `e2e-dashboard`, `security-fast`, `sonar`) + image gates в `build.yml` (size + non-root) + 1 informational (weekly CodeQL).

---

## Карта тестов: src-модуль → покрывающие тесты

### `packages/probe-core/`

#### Pure-unit (`tests/unit/`, 15 файлов, 261 тест)

| Src-модуль | Тест-файл(ы) | Тестов | Что покрыто |
|------------|--------------|-------:|-------------|
| `censprobe_core` (whole pkg) | `test_smoke_imports.py` | 1 | `pkgutil.walk_packages` обход — каждый submodule импортится без side-effects, циклических импортов, недостающих зависимостей |
| `censprobe_core.config.ProtocolsConfig` | `test_config_validation.py` | 24 | `_check_ports_cover_enabled` (missing port, orphan port, invalid range), `extra="forbid"` на typo-полях, fatal startup error на missing field |
| `censprobe_core.credentials_reader` | `test_credentials_reader.py` | 14 | fail-loud контракт: `_protocols_enabled` обязателен (missing/null/non-list/non-string-entries), все операционные поля каждой секции обязательны (port, method, server_name, AWG h1..h4 и s1/s2/jc/jmin/jmax), invalid port range, top-level non-mapping, section non-mapping, absent section keeps zero defaults |
| `censprobe_core.protocol_probes` (helpers) | `test_protocol_probes_helpers.py` | 41 | `_classify_proxy_outcome` SOCKS-routed verdict mapping; `_wg_peer_rx_bytes` parser; `_build_obfuscated2_init` byte-shape (transport tag = `\xdd\xdd\xdd\xdd`, forbidden first-int32 set, second-int32 ≠ 0); `_validate_res_pq` (truncated body, bad auth_key_id, bad TL ID, nonce mismatch); **`_exchange_obfuscated2_respq` length-timeout-after-init = BLOCKED in BOTH raw obfuscated2 and faketls paths** (Bug A regression); **`ping_echo` returns `(ok, avg_rtt_ms)`** parsed from iputils `rtt min/avg/max/mdev` line — full success / partial above threshold / below threshold / total failure / zero-received-no-rtt-line |
| `censprobe_core.runner.ProbeRunner` | `test_runner_orchestration.py` | 9 | `asyncio.gather(return_exceptions=True)` изолирует упавшие модули, `module_failures` появляется в `_summarize`, enabled/disabled-фильтрация, parallel + serial phase, registry-driven lookup |
| `censprobe_core.scoring` | `test_scoring.py` | 35 | `_ok_pct` / `_latency_to_score` / `_protocol_reachability` / `_recommend_protocols` (priority order, signature-blocked filter), `compute_scores` (empty results / all-OK / all-blocked / mixed / listener-fallback / weights ≠ 1.0), log-line `entry=N/A` rendering when `listener_session_count == 0` |
| `censprobe_core.subcategories.derive` | `test_subcategories.py` | 35 | все 4 уровня (prefix → suffix → substring → name override), unknown name → fallback |
| `censprobe_core.targets` | `test_targets_load.py` | 20 | `Target`, `CfHttpTarget` host/domain coercion, `TelegramDC.ports` required + min_length=1, `load_targets()` (auto-discovery, explicit files, module_owned exclusion, malformed YAML warn-skip, non-mapping, symlink rejection), `TargetSet` views (`domains` dedup+sort, `tcp_targets`, `tls_targets`, `http_targets`) |
| `censprobe_core.modules.telegram._test_dc_port` | `test_telegram_frame.py` | 1 | байт-точная сверка MTProto abridged-transport frame |
| `censprobe_core.modules.telegram` (DC enumeration) | `test_telegram_enumerate.py` | 6 | DC × IP-family × port matrix expansion |
| `censprobe_core.utils.validate_id` | `test_utils_validate_id.py` | 27 | path-traversal (`..`, `/`, `\`), `\x00`, U+200B, empty, max length, valid IDs |
| `censprobe_core.modules.dns._cert_san_covers_domain_family` | `test_dns_cert_san.py` | 18 | wildcard-apex relaxation, single-label match, RFC 6125 |
| `censprobe_core.modules.tls._pick_neutral_sni` | `test_tls_neutral_sni.py` | 17 | per-IP-family neutral SNI selection (Cloudflare/Akamai/AWS prefixes) |
| `censprobe_core.modules.http._verdict_from_response` (basic) | `test_http_classify.py` | 7 | 200/expected_status, 403/451 + valid_tls → `GEOBLOCK_NOT_CENSORSHIP` |
| `censprobe_core.models.ProtocolResult.finalize` | `test_protocol_result_finalize.py` | 6 | truth-table `(handshake_count, data_transfer_ok) → Verdict`; load-bearing case `(0, True) → OK` guards SOCKS-routed / mtproto_proxy log-parse drift from collapsing to false BLOCKED |

#### Mocked-unit modules (`tests/modules/`, 10 файлов, 99 тестов)

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_core.modules.cloudflare` (builders) | `test_cloudflare_packets.py` | 12 | `_build_quic_vn_trigger` (long-header version=0x00000001, dst_cid_len, packet number 0), `_build_masque_probe_packet` (UDP encap, length, CID), `_build_wg_handshake_init` (148-byte payload, message_type=1, ephemeral key shape) |
| `censprobe_core.modules.dns` | `test_dns_helpers.py` | 10 | `_parse_first_nameserver` (resolv.conf parsing), `_get_isp_resolver` (systemd-resolved fallback chain) |
| `censprobe_core.modules.http._verdict_from_response` | `test_http_verdict.py` | 20 | 200/expected_status, 403/451 + valid_tls → `GEOBLOCK_NOT_CENSORSHIP` (порядок проверок load-bearing), body length / cap |
| `censprobe_core.modules.middlebox._test_header_manipulation` | `test_middlebox_parsing.py` | 7 | OONI-style header field manipulation parsing |
| `censprobe_core.modules.tcp` | `test_tcp.py` | 11 | `_single_tcp_attempt` (OK / IP_DROPPED / REFUSED / fast-RST → SUSPECTED RST_INJECTED только в RU vantage), `_majority` aggregator (tie-breaker, all-error, single result) |
| `censprobe_core.modules.telegram` (`_compute_health_score`, `_ok_ratio`) | `test_telegram_health.py` | 11 | weighted avg dc:55%/web:25%/cdn:20%, `_ok_ratio` empty/all-OK/mixed |
| `censprobe_core.modules.telegram` (`_compile_owned_patterns`, `_match_owned_cert`) | `test_telegram_owned_cert.py` | 8 | RFC 6125 wildcard semantics — single label match, no embedded wildcards, SAN/CN matching против `owned_cert_patterns` |
| `censprobe_core.modules.throttling.run_throttling_tests` | `test_throttling_vantage.py` | 3 | off-vantage → INCONCLUSIVE marker (not real probe); on-vantage → real probe invoked with cfg.modules.throttling; `require_censoring_vantage=False` bypasses gate |
| `censprobe_core.modules.throttling._decide_method_b_verdict` | `test_throttling_verdict.py` | 11 | trigger < 0.25 × min(correct, typo) → `YOUTUBE_SNI_THROTTLED`, INCONCLUSIVE при bw=0, OK иначе, division-by-zero |
| `censprobe_core.modules.tls._attribute_tls_failure` | `test_tls_attribution.py` | 7 | SNI-blocked vs cert-mismatch vs network-error attribution |

#### Property-based (`tests/property/`, 3 файла, 12 тестов)

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_core.scoring` | `test_scoring_property.py` | 4 | range invariants для `_ok_pct ∈ [0.0, 1.0]`, `_latency_to_score ∈ [0.0, 100.0]`, `_protocol_reachability ∈ [0.0, 1.0]` |
| `censprobe_core.subcategories.derive` | `test_subcategories_property.py` | 4 | для любого test_name результат непуст и принадлежит замкнутому множеству |
| `censprobe_core.utils.validate_id` | `test_validate_id_property.py` | 4 | accept-set / reject-set дискриминируются |

**Probe-core total: 28 файлов, 373 теста.**

---

### `packages/solo/`

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_solo` (whole pkg) | `unit/test_smoke_imports.py` | 1 | submodule import |

**Solo total: 1 файл, 1 тест.** Domain-тестов нет — на текущий момент CLI и orchestration solo не покрыты pytest'ом, верификация только через ручной запуск + smoke-import.

---

### `packages/listener/`

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_listener` (whole pkg) | `unit/test_smoke_imports.py` | 1 | submodule import |
| `censprobe_listener.credentials._awg_magic_headers`, `_apply_ports` | `unit/test_credentials_constraints.py` | 153 | H1..H4 pairwise distinct + не в `{1,2,3,4}`, S1+56 ≠ S2, `_apply_ports` complete-map требование (heavily parametrized — 50 итераций × несколько inv проверок) |
| `censprobe_listener.credentials.creds_to_yaml`, `ProtocolCredentials` | `unit/test_credentials_yaml_roundtrip.py` | 14 | round-trip всех секций (включая `mtproto_proxy_alt` и `mtproto_orig` с `dd<32-hex>` секретом без SNI hex-suffix) без `wg`/`xray`/`openvpn` (synthetic creds), `enabled_protocols` filter, server-private fields НЕ leak в YAML, `_protocols_enabled` echo, alt-секрет независим от primary, mtproto_orig секрет независим от обоих mtg |
| `censprobe_listener.preflight` | `unit/test_preflight.py` | 14 | conntrack health (`_check_conntrack` low-max + NOTRACK downgrade, high-water warn, missing /proc skip), `_check_iptables_capability` (no PATH = warn, rule-absent = ok proves CAP_NET_ADMIN, EPERM = warn with hint), `_cleanup_orphan_rules` (no rules → ok, orphans deleted via `-A→-D` conversion), `_check_telegram_dc_reach` (3 DC parallel TCP, all-unreachable warn), `run_preflight` orchestrator order |
| `censprobe_listener.cred_server.CredServer` (snapshot endpoint) | `unit/test_cred_server_snapshot.py` | 9 | `/snapshot` bearer-token auth (401 / 403 / 200 paths), lifecycle (503 before `attach_responders` and after `detach_responders`), multi-serve (no exhaustion), per-protocol error surfacing (one responder's `live_snapshot` raising → typed `error` field, others still serialised), 404 on unrelated paths |
| `censprobe_listener.openvpn_responder` | `unit/test_openvpn_status_parsing.py` | 18 | scanner-noise + tun-noise rejection (only `Auth read bytes` is unforgeable), 1500-byte fallback for hosts without iptables, **iptables INPUT counter AND-gated against `handshake_count > 0`** (Bug B regression: `data_pkts=8 + Auth=0 → not data_transfer_ok`), **`_max_auth_bytes_seen` latch** (real handshake captured before peer aged out via `keepalive 60` → counter zeroed → latched value still surfaces handshake) |
| `censprobe_listener.mtproto_orig_responder` | `unit/test_mtproto_orig_responder.py` | 5 | secret parsing (dd-prefix stripped for `-S` argv), iptables OUTPUT PSH+ACK rule shape, idempotent re-install path |
| `censprobe_listener` handshake-pattern snapshot | `unit/test_handshake_pattern_snapshot.py` | 6 | regression: each responder uses the documented kernel-counter shape (mtproto-orig PSH+ACK iptables rule, openvpn UDP length filter, mtg PSH+ACK on OUTPUT) — guards against silent regression on rule semantics |
| `censprobe_listener.main._generate_session_id` | `unit/test_session_id_generation.py` | 8 | prefix encoding for `--mobile`/`--white` flag combos (`plain-`, `mob-`, `white-`, `mob-white-`), 4-uppercase-hex suffix shape, distinct IDs across calls, SAFE_ID_RE contract for filesystem + FastAPI path |
| `censprobe_listener.credentials._awg_magic_headers` | `property/test_credentials_property.py` | 4 | Hypothesis @settings(derandomize=True, max_examples=500) на AWG header invariants + S-сравнение |

**Listener total: 10 файлов, 236 collected tests.** Большая часть — `parametrize`-расширения в `test_credentials_constraints.py`. Subprocess-respondery (ss/vless/hysteria/openvpn/wg) verifyются via `e2e-dashboard` или ручной запуск. `cred_server.CredServer` POW покрывает только snapshot endpoint; `_serve_creds` остаётся покрытым только E2E.

---

### `packages/client/`

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_client` (whole pkg) | `unit/test_smoke_imports.py` | 1 | submodule import |
| `censprobe_client.main` (cross-verification helpers) | `unit/test_cross_verification.py` | 10 | `_listener_verdict` mirrors `ProtocolResult.finalize` — `data_transfer_ok=True ⇒ OK` (cryptographic ground truth wins over log-parsed handshake counter), handshake-only-no-data ⇒ HANDSHAKE_ONLY, neither signal ⇒ BLOCKED; `_agreed_verdict` listener-wins matrix — both-OK no note, client-overconfident → "client overread", listener-OK + client-not → "listener saw data", other disagreements → `client=X` note |
| `censprobe_client.main` (retry policy) | `unit/test_retry.py` | 20 | `_pinned_get_with_retry`: first-attempt success no retry, transient-then-success, exhausted retries propagate `_TransientEndpointError`, permanent (`_PermanentEndpointError`) short-circuits on first attempt, `ValueError` (cert-format input error) propagates without retry; HTTP status classification matrix (5xx + 408 → transient; 4xx → permanent; malformed status line → permanent; non-numeric → permanent) |

**Client total: 3 файла, 31 тест.** Probe-dispatch и main CLI orchestration domain-тестами не покрыты — verifycaция via end-to-end run.

---

### `packages/sync/`

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `censprobe_sync` (whole pkg) | `unit/test_smoke_imports.py` | 1 | `pkgutil.walk_packages` обход — каждый submodule импортится без ошибок |
| `censprobe_sync.main._normalise_fingerprint` + `_fetch_and_verify_peer_cert` + `_generate_self_signed_cert` + `_detect_external_ip` | `unit/test_pinning.py` | 22 | fingerprint normalisation (canonical/uppercase/colon-separated/whitespace + 6 malformed-input rejections); pinned TLS-fetch с моками `socket.create_connection` + `ssl.SSLContext.wrap_socket` (matching FP → PEM round-trip; mismatching FP → ValueError; missing peer cert → ValueError; malformed FP → short-circuit БЕЗ network call); self-signed cert generation (PEM/PEM/64-char-hex + DER fingerprint match + SAN covers loopback + each call returns fresh fingerprint); external IP detection (routable local→returned, RFC1918→falls through to echo, CGNAT 100.64/10→falls through, no outbound→None) |
| `censprobe_sync.main` CLI (click groups) | `unit/test_cli.py` | 4 | `--help` shows both `serve` and `pull` subcommands; `serve --help` surfaces default port 8444; `pull` без options → click missing-option error; `pull` с malformed fingerprint → exit 1 + execvp NOT called (tripwire-mocked, asserts network not touched) |

**Sync total: 3 файла, 27 тестов.** Network I/O (rclone subprocess execution, real TLS handshake to a serving rclone) покрывается via the manual end-to-end Vultr→GCP verification — there's no rclone-bin in CI runners. The pure-Python pinning/normalisation/cert-generation paths get full unit coverage.

---

### `packages/dashboard/sync-api/`

#### Unit (`tests/unit/`, 5 файлов, 70 тестов)

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `sync_api` (whole pkg) | `test_smoke_imports.py` | 1 | submodule import (`monkeypatch.setenv("DATABASE_URL", "sqlite:///")` до импорта) |
| `sync_api.parser` (`_to_float`, `_to_int`, `_parse_dt`, `is_solo_report`, `is_listener_report`) | `test_parser_coercions.py` | 12 | None/str/int/float/dict combos, malformed datetime, filename predicates |
| `sync_api.parser.parse_listener_report` | `test_parser_listener.py` | 10 | listener report → `ListenerSession` + `ProtocolResult` rows, missing keys, schema-drift defence |
| `sync_api.parser.load_json` | `test_parser_load_json_security.py` | 8 | symlink reject + log warn, oversize file (51 MB) → None + tracemalloc < 10 MB, malformed JSON → None |
| `sync_api.parser.parse_solo_report` | `test_parser_solo.py` | 10 | solo report → `TestRun` + `TestResult` rows, subcategory derivation propagation, missing keys |

#### Integration (`tests/integration/`, 3 файла, 29 тестов; требуют Postgres)

| Src-модуль | Тест-файл | Тестов | Что покрыто |
|------------|-----------|-------:|-------------|
| `sync_api.main` (FastAPI app) + `sync_api.db` | `test_endpoints.py` | 14 | `GET /health` / `/test-runs` / `/test-runs/{id}` / `/results/{id}` / `/protocols/{id}` через `httpx.AsyncClient(transport=ASGITransport(app))` против реального Postgres |
| `sync_api.main._import_once`, `parser`, `db` | `test_import_pipeline.py` | 8 | disk reports → DB rows + UPSERT-by-session, path-traversal/symlink guards |
| `sync_api.db` (engine, ORM models) | `test_schema_round_trip.py` | 7 | `init_db()` создаёт все 4 таблицы, unique constraints (`uq_test_results_run_file_test_target`, `uq_listener_sessions_run_file`), индексы (`ix_test_results_run_file`), cascade delete `TestRun` → `TestResult`/`ListenerSession`/`ProtocolResult` |

**Sync-api total: 8 файлов, 105 тестов.** Самое плотное покрытие после probe-core.

---

### `tests/` (workspace-level)

#### Contracts (`tests/contracts/`, 3 файла, 7 тестов)

| Что | Тест-файл | Тестов | Что покрыто |
|-----|-----------|-------:|-------------|
| `subcategories` ↔ Grafana SQL | `test_subcategories_contract.py` | 2 | Парсит `packages/dashboard/grafana/dashboards/*.json` regex'ом по `subcategory = 'X'` / `IN ('a','b')`. Assert: derive-output ⊇ Grafana-фильтров |
| `targets/*.yaml` validation | `test_targets_yaml_validate.py` | 3 | каждый `targets/*.yaml` проходит `TargetFile.model_validate`, `load_targets()` не warn-skip'ает |
| `censprobe.yaml` round-trip | `test_censprobe_yaml_round_trip.py` | 2 | `load_config()` → `model_dump` → `safe_dump` → `safe_load` → `model_validate` идентичность; extra fields на любом уровне → fatal |

#### Snapshots (`tests/snapshots/`, 2 файла, 6 тестов)

| Что | Тест-файл | Тестов | Что покрыто |
|-----|-----------|-------:|-------------|
| JSON-Schema solo + listener reports | `test_report_schemas.py` | 3 | `model_json_schema()` от `TestResult` / `ListenerReport` против фикстур `tests/snapshots/fixtures/test_result_minimal.json` и `listener_report_minimal.json` |
| Wire-format byte snapshots | `test_wire_format_byte_snapshots.py` | 3 | `_build_quic_vn_trigger`, `_build_wg_handshake_init`, `_build_masque_probe_packet` — pytest-regressions baseline побайтово |

#### E2E (`tests/e2e/`, 1 файл, 2 теста; CI job `e2e-dashboard` на push/PR)

| Что | Тест-файл | Тестов | Что покрыто |
|-----|-----------|-------:|-------------|
| Dashboard stack (postgres + sync-api) | `test_dashboard_stack.py` | 2 | `docker compose pull` → `up -d` → `/health` 200 → schema migration отработала → `/test-runs/` отдаёт ответ |

**Workspace total: 6 файлов, 15 тестов.**

---

### Итого

| Tree | Файлы | Тестов (collected) | Покрытие |
|------|-------:|-------:|----------|
| `packages/probe-core/tests` | 28 | 373 | плотное (config, scoring, subcategories, runner, все 8 модулей измерений, credentials_reader, protocol_probes helpers + ping_echo + mtproto BLOCKED-on-timeout, ProtocolResult.finalize truth table) |
| `packages/solo/tests` | 1 | 1 | smoke-only |
| `packages/listener/tests` | 10 | 236 | credentials + AWG invariants (parametrize-heavy), preflight checks, openvpn AND-gate + auth-bytes latch, mtproto-orig responder, cred_server `/snapshot` endpoint, `_generate_session_id` prefix encoding + SAFE_ID contract |
| `packages/client/tests` | 3 | 31 | smoke + cross-verification helpers + retry policy (transient/permanent classification) |
| `packages/sync/tests` | 3 | 33 | smoke + cert pinning (FP normalisation, pinned TLS fetch, DER→PEM round-trip, fresh-fingerprint per session) + click CLI shape |
| `packages/dashboard/sync-api/tests` | 8 | 105 | parser + endpoints + DB schema |
| `tests/` (workspace) | 6 | 14 | contracts + snapshots + e2e (`e2e-dashboard` job, 2 deselected по дефолту) |
| **Total** | **59** | **795** (после parametrize, из них 793 default + 2 deselected e2e) | — |

---

## Что НЕ покрыто (gap analysis)

### Высокий приоритет

- **`packages/solo/src/censprobe_solo/main.py`** — Click CLI, orchestration. Нет тестов на argument parsing, CLI flag handling, server_meta caching, report writing.
- **`packages/listener/src/censprobe_listener/cred_server.py` (creds endpoint)** — `/snapshot` lifecycle и serialisation покрыты unit-тестом `test_cred_server_snapshot.py`; `/creds` (one-shot bearer token, single-use exhaustion, client_ip capture) и сам TLS-pinning + cert-генерация остаются покрыты только через `e2e-dashboard` и ручные прогоны.
- **`packages/probe-core/src/censprobe_core/server_meta.py`** — `detect_server_meta` orchestration, ipapi.is enrichment fallback chains.

### Средний приоритет

- **Listener responder lifecycle** — `_responder_base` (mkdtemp → 0o600 config → spawn → wait), `ss/vless/hysteria/wg` wrappers. Subprocess-heavy, требует extensive `mocker.patch("asyncio.create_subprocess_exec")`. **`openvpn_responder` (status parsing + AND-gate + auth-latch) и `mtproto_orig_responder` (PSH+ACK rule shape) покрыты unit-тестами.**
- **`modules/dns.py` высокоуровневый `run_dns_tests`** — есть тесты helpers, но не сама ladder ISP→public→DoH→DoT с полной CERTainty-attribution.
- **`modules/tls.py` высокоуровневый `run_tls_tests`** — есть `_attribute_tls_failure` unit-тест, но не блок paired blocked/neutral SNI handshake.
- **`modules/http.py` высокоуровневый `run_http_tests`** — есть `_verdict_from_response`, но не сам fetch loop с body cap и redirect handling.
- **`packages/client/src/censprobe_client/main.py` orchestration** — `_async_main` flow (probe ordering, jitter, `_print_cross_verification` rendering), `_pinned_get` сама I/O-функция (TLS cert SHA-256 mismatch reject, bearer token roundtrip) покрыты только через end-to-end. **Pure helpers (`_listener_verdict`, `_agreed_verdict`, `_pinned_get_with_retry`, status-code classification) покрыты unit-тестами.**

### Низкий приоритет (косвенно покрыто)

- `protocol_registry.py` — статическая `dict`, изменения ловит smoke-import + любой тест который её читает.
- `module_registry.py` — runner-тесты её эффективно тестируют через behaviour.

---

## Roadmap по покрытию

План поэтапного роста (из `replicated-crafting-origami.md`):

| Этап | Что добавляется | Coverage gate |
|------|------------------|---------------|
| **1. Foundation** ✅ | dep-groups, root pytest/coverage/bandit config, mypy strict для probe-core, conftest skeletons, smoke-import per package, `.pre-commit-config.yaml`, sonar-project.properties, `ci.yml` | `continue-on-error: true` первую неделю |
| **2. Pure unit** ✅ | Layer A (16 целей): scoring + subcategories + models + parser coercions + solo/listener/load_json security + targets validation + telegram MTProto frame + AWG constraints + creds round-trip. Workspace contract tests | probe-core non-modules ≥ 70%; lint+mypy required |
| **3. Mocked unit** ⏳ partial | Layer B: 8 модулей измерений + runner + responder lifecycle + cred_server pure + client _fetch_credentials | probe-core/modules ≥ 40%; security-fast required |
| **4. Integration** ✅ | Postgres setup + sync-api endpoints + parser + import pipeline + DB schema, cred-server localhost TLS-pinning, echo-server localhost | sync-api ≥ 60%; integration tests required |
| **5. Property + Snapshots + Sonar gate** ✅ | Hypothesis (validate_id, subcategories, AWG, scoring ranges). JSON Schema snapshots. Byte-signature snapshots. Custom SonarCloud Quality Gate | coverage gates → steady-state; SonarCloud QG required |
| **6. Build dependency + image gates** ✅ | `workflow_run` build после CI. Image size + non-root verification | broken image не попадает в Docker Hub |
| **7. Heavy push/PR jobs** ✅ | `e2e-dashboard` (sync-api build + compose up), `network-tests` placeholder, `trivy-fs` в `security-fast`, `codeql.yml` weekly. Изначально жили в `nightly.yml`; nightly целиком удалён вместе с image-registry CVE сканированием. | все три job'а зелёные на main |
| **8. Maintenance posture** 🔄 ongoing | Каждую неделю +1 модуль остальных пакетов на mypy strict; новый модуль = новый тест-файл с минимум 1 OK + 1 BLOCKED | — |

Этапы 3 (mocked unit для всех 8 модулей измерений) и 8 (тесты для solo/listener/client domain logic) ещё не завершены, но прогрессируют — 5 из 9 listener-модулей (preflight, openvpn-responder, mtproto-orig-responder, cred_server snapshot endpoint, handshake-pattern snapshot) и 2 client-helper модуля (cross-verification, retry-policy) перешли с smoke-only на полный unit-coverage (см. таблицы выше). Тестовый suite растёт с каждым PR.

---

## CI quality gates

Покрытие через pytest — **только часть** total quality assurance. Полный список не-pytest проверок:

### Required для merge (`ci.yml` jobs)

| Job | Бюджет | Что запускает |
|-----|--------|---------------|
| `lint` | ~30 с | `ruff check .` + `ruff format --check .` (E/F/W/B/I/UP/S правила, ignore S101/S404/S603/S607); `yamllint` (`.github/`, `targets/`, `censprobe.yaml`, `docker-compose.yml`); `actionlint` (workflow YAML); `hadolint` рекурсивно (`failure-threshold: warning`, ignore DL3008/DL3003); `mypy strict` для всего `packages/*/src` (53 файл) |
| `validate-config` | ~25 с | inline Python — `load_config(Path("."))` + `load_targets(Path("targets"))` с capture WARNING-уровня логов и promotion в errors |
| `test (probe-core)` `test (solo)` `test (listener)` `test (client)` `test (sync-api)` | matrix, ~25–60 с per entry | `pytest <pkg>/tests --cov --cov-report=xml --junitxml=junit.xml -v` с реальным `services: postgres:16-alpine`. Артефакты `coverage-${slug}.xml` + `junit-${slug}.xml` загружаются для SonarCloud |
| `cross-package-tests` | ~30 с | `pytest tests/contracts tests/snapshots --cov=censprobe_core` — Grafana ↔ subcategories contract, censprobe.yaml round-trip, targets/*.yaml validate, JSON Schema + wire-format byte snapshots. Coverage загружается под `coverage-cross.xml` для Sonar |
| `network-tests` | ~25 с | `pytest -m network -v`; exit-code 5 (no tests collected) → pass. Placeholder под будущие live-MTProto / DoH / Cloudflare ECH тесты |
| `e2e-dashboard` | ~3 мин | `docker/build-push-action@v7` билдит sync-api локально (`load: true`, теги — local-only sentinel `censprobe-ci/...:e2e-local`), затем `docker compose -f docker-compose.yml -f tests/e2e/compose.test.yml --profile dashboard up -d --wait postgres sync-api`, далее `pytest tests/e2e/test_dashboard_stack.py -m e2e`. На failure — `compose logs` загружается артефактом |
| `security-fast` | ~70 с | `bandit -r packages/ -ll -c pyproject.toml`; `pip-audit --skip-editable`; `gitleaks` (PR-diff vs full history); `dependency-review-action` (`fail-on-severity: high`, PR only); `aquasecurity/trivy-action@v0.36.0` filesystem scan (`scan-ref: .`, scanners `vuln,secret,config`, severity `HIGH,CRITICAL`, `exit-code: 0`, SARIF к Security tab) |
| `sonar` | ~60 с | Скачивает все `coverage-*` артефакты (включая `coverage-cross.xml`), `SonarSource/sonarqube-scan-action@v6` с `SONAR_TOKEN` против `https://sonarcloud.io`. Quality Gate `Sonar way` (built-in): новый код coverage, no new bugs / hotspots / duplicates. `needs: [test, cross-package-tests]` |

### Required для merge (`build.yml` post-CI)

Триггерится `workflow_run` от CI на main + tag pushes; PR builds с `push: false` для review feedback.

> **Sonar-only failure permitted.** `build.yml` пушит образы и в случае failure-конклюзии CI, если шаг `Check CI jobs status (allow sonar-only failure)` подтвердит, что **единственный** упавший job — `SonarCloud`. Это обход coverage Quality Gate (`new_coverage ≥ 80`), который на free-плане не отключаемая. Любая другая red job (lint, test, security-fast, e2e-dashboard, …) хард-блокирует push.

| Job | Что запускает |
|-----|---------------|
| `build (solo)` `build (listener)` `build (client)` `build (sync-api)` | `dorny/paths-filter@v3` (PR — только если затронуты `packages/${path}/**`, `packages/probe-core/**`, или `.github/workflows/build.yml`); `docker/build-push-action@v7` (`load: true`, `push: github.event_name != 'pull_request'`, `cache-from/to: type=gha,scope=${name}`); **post-build gates**: non-root verification (только для `sync-api`, `allow_root: false`), image size budget (`solo` ≤ 600 MB, `listener`/`client` ≤ 400 MB, `sync-api` ≤ 250 MB) |

### Informational

| Workflow | Триггер | Job-ы |
|----------|---------|-------|
| `codeql.yml` | `cron: "0 4 * * 1"` (weekly Mon 04:00 UTC), PR с Python-изменениями | CodeQL Python `queries: security-and-quality` |

> Ранее существовавший `nightly.yml` (Trivy image-registry CVE сканирование, network-tests, e2e-dashboard) удалён. Network-tests, e2e-dashboard, trivy-fs перенесены в `ci.yml` и теперь required на каждый push/PR. Image-registry CVE сканирование (`outtakes/censprobe-*:main`) снято целиком — повторно вернётся отдельным workflow если потребуется.

### Local pre-commit (`.pre-commit-config.yaml`)

Двухстадийная стратегия: cheap hooks на каждый commit, slow на pre-push.

**На commit**: `pre-commit-hooks` (EOF, trailing-whitespace, merge-conflict, check-yaml, check-json, check-added-large-files maxkb=500, mixed-line-ending), `ruff` (`--fix --exit-non-zero-on-fix`), `ruff-format`, `yamllint`, `gitleaks`, `actionlint`, локальный `validate-targets` (Python: `load_config` + `load_targets`).

**На pre-push**: `mypy --config-file=pyproject.toml` (probe-core only локально; CI покрывает full tree), `hadolint-docker`.

Активация: `pre-commit install --hook-type pre-commit --hook-type pre-push`.

---

## Tooling configuration

### `pyproject.toml [tool.ruff]`

- `line-length = 100`, `target-version = "py311"`.
- `select = ["E", "F", "W", "B", "I", "UP", "S"]` — pycodestyle errors/warnings, pyflakes, bugbear, isort, pyupgrade, bandit-via-ruff.
- `ignore = ["S101", "S404", "S603", "S607"]` — asserts (S101) разрешены в тестах; subprocess (S404/S603/S607) — намеренно в CLI launchers.
- `[tool.ruff.lint.per-file-ignores] "**/tests/**" = ["S", "B"]`.
- `[tool.ruff.lint.flake8-bugbear].extend-immutable-calls` — whitelist для FastAPI DI markers (`Depends`, `Query`, `Path`, `Body`, `Header`, `Cookie`, `File`, `Form`).

### `pyproject.toml [tool.mypy]`

- `python_version = "3.11"`, `strict = false` (default), `ignore_missing_imports = true`, `plugins = ["pydantic.mypy"]`.
- `[[tool.mypy.overrides]] strict = true` для:
  - `censprobe_core.*` (whole package — Этап 1).
  - `sync_api.parser`, `sync_api.db`, `sync_api.main`.
  - `censprobe_listener.{ss_responder, _responder_dispatch, vless_reality_wrapper, hysteria_wrapper, openvpn_responder, mtproxy_responder, wg_responder, echo_server, credentials, cred_server, _responder_base, main}`.
  - `censprobe_client.{_probe_dispatch, main}`.
  - `censprobe_solo.main`.
- CI один раз: `mypy packages/probe-core/src packages/solo/src packages/listener/src packages/client/src packages/dashboard/sync-api/src` — 53 файл всё strict.

### `pyproject.toml [tool.bandit]`

- `exclude_dirs = ["tests", "*/tests/*", "build", "dist"]`.
- `skips = ["B101", "B404", "B603", "B607"]` — asserts (B101) и subprocess (B404/B603/B607) — намеренно.

### `pyproject.toml [tool.pytest.ini_options]`

- `testpaths` — все 6 деревьев.
- `asyncio_mode = "auto"`, `asyncio_default_fixture_loop_scope = "session"`, `asyncio_default_test_loop_scope = "session"` — единственный event loop через всю сессию (asyncpg-коннекты не теряют валидность).
- `markers`: `integration`, `e2e`, `network`, `needs_wg`, `needs_xray`, `slow`.
- `filterwarnings = ["error::DeprecationWarning", "ignore::pytest.PytestCollectionWarning"]` — второй для silencing `Test`-prefixed pydantic models.
- `addopts = "-ra --strict-markers --strict-config --import-mode=importlib -m 'not e2e and not network and not needs_wg and not needs_xray'"` — `--import-mode=importlib` снимает cross-package `tests` package-name collision.

### `pyproject.toml [tool.coverage]`

- `branch = true`, `source = ["packages"]`, `omit = ["*/tests/*", "*/_privsep.py", "*/__init__.py"]`.
- `concurrency = ["thread"]`.
- `exclude_lines` — `pragma: no cover`, `raise NotImplementedError`, `if TYPE_CHECKING:`, `if __name__ == .__main__.:`.

### `sonar-project.properties`

- `sonar.organization=vasiliiok`, `sonar.projectKey=vasiliiok_censprobe`.
- `sonar.sources=packages`, `sonar.tests=packages,tests`.
- `sonar.python.coverage.reportPaths=coverage-*.xml`, `sonar.python.xunit.reportPath=junit-*.xml`.
- `sonar.exclusions=**/__pycache__/**,**/_privsep.py,packages/dashboard/grafana/**,reports/**`.
- `sonar.cpd.exclusions=tests/snapshots/**,tests/contracts/**,**/grafana/dashboards/**` — snapshots и contracts intentionally repetitive.

### `.yamllint.yaml`

- `extends: default`.
- `line-length: max: 200`.
- `truthy: allowed-values: ['true', 'false'], check-keys: false` — позволяет `on:` bare key в GitHub Actions.
- `colons: max-spaces-after: -1`, `commas: max-spaces-after: -1` — для alignment в `censprobe.yaml`.

### `.hadolint.yaml`

- `ignore: [DL3008, DL3003]` — apt version pinning impractical для VPN/build-system пакетов; `cd` в multi-stage build scripts intentional.

---

## Связанные документы

- [`README.md`](../README.md) — обзор проекта, configuration reference, быстрый старт.
- [`TESTING.md`](TESTING.md) — методология (layer cake, инструменты, anti-patterns).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — как запустить, что должно быть зелёным перед `git push`, как добавить новый тест/модуль/протокол.
