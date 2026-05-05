"""
Property tests for scoring helpers.

Three range invariants:
  * ``_ok_pct`` returns a value in [0, 100].
  * ``_latency_to_score`` returns a value in [0, 100].
  * ``_protocol_reachability`` returns a value in [0, 1].

These look trivial but catch refactor regressions where someone
accidentally returns a percentage as a [0, 1] fraction (or vice versa)
— the consequence in the scoring math is silent and the unit test only
fails for specific inputs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from censprobe_core.models import (
    ListenerReport,
    ProtocolResult,
    TestResult,
    Verdict,
)
from censprobe_core.scoring import (
    _latency_to_score,
    _ok_pct,
    _protocol_reachability,
)
from hypothesis import given, settings
from hypothesis import strategies as st

_VERDICTS = list(Verdict)


def _result(v: Verdict) -> TestResult:
    return TestResult(test="t", category="c", target="x", verdict=v)


@given(verdicts=st.lists(st.sampled_from(_VERDICTS), min_size=0, max_size=50))
@settings(max_examples=200)
def test_ok_pct_in_range(verdicts: list[Verdict]) -> None:
    results = [_result(v) for v in verdicts]
    pct = _ok_pct(results)
    assert 0.0 <= pct <= 100.0


@given(rtts=st.lists(st.floats(min_value=0.0, max_value=60_000.0), max_size=50))
@settings(max_examples=200)
def test_latency_to_score_in_range(rtts: list[float]) -> None:
    score = _latency_to_score(rtts)
    assert 0.0 <= score <= 100.0


def _proto_result(v: Verdict) -> ProtocolResult:
    pr = ProtocolResult(verdict=v)
    if v == Verdict.OK:
        pr.handshake_count = 1
        pr.data_transfer_ok = True
    elif v == Verdict.HANDSHAKE_ONLY:
        pr.handshake_count = 1
    return pr


_PROTO_VERDICTS = st.sampled_from(
    [Verdict.OK, Verdict.HANDSHAKE_ONLY, Verdict.BLOCKED, Verdict.INCONCLUSIVE]
)


@given(
    reports=st.lists(
        st.dictionaries(
            keys=st.sampled_from(["wireguard", "openvpn", "shadowsocks"]),
            values=_PROTO_VERDICTS,
            min_size=1,
            max_size=3,
        ),
        max_size=5,
    )
)
@settings(max_examples=150)
def test_protocol_reachability_in_unit_range(
    reports: list[dict[str, Verdict]],
) -> None:
    listener_reports = [
        ListenerReport(
            test_id="t",
            session_id=f"s{i}",
            listener_started_at=datetime.now(UTC),
            results={k: _proto_result(v) for k, v in r.items()},
        )
        for i, r in enumerate(reports)
    ]
    score = _protocol_reachability(listener_reports or None)
    assert 0.0 <= score <= 1.0


def test_protocol_reachability_neutral_on_none() -> None:
    # Boundary case Hypothesis can't easily synthesise.
    assert _protocol_reachability(None) == 0.5
    assert _protocol_reachability([]) == 0.5
