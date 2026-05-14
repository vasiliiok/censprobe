"""Test that _fetch_snapshot surfaces listener/client schema drift loudly.

Pre-2026-05 the client caught Pydantic.ValidationError via bare
``except Exception`` and logged it at DEBUG. The result: a listener
version that emitted a renamed field (e.g. ``handshake_count`` →
``handshake_cnt``) silently produced empty snapshot cells on the
client side, and the cross-verify table looked like the listener
just didn't observe anything. The fix narrows the exception type,
logs at WARNING with the specific validation errors, and keeps the
empty-LiveSnapshot fallback for back-compat.

These tests use the public ``LiveSnapshot.model_validate`` surface
to simulate drift without standing up the full HTTPS endpoint.
"""

from __future__ import annotations

import logging

import pytest
from censprobe_core.models import LiveSnapshot


def test_validation_error_carries_loc_and_msg_for_logging() -> None:
    """Sanity: pydantic ValidationError exposes ``loc`` + ``msg`` that
    the fixed _fetch_snapshot formats into the WARNING log. If pydantic
    ever changes that shape we'll need to update the log formatter."""
    import pydantic

    with pytest.raises(pydantic.ValidationError) as exc:
        # ``handshake_count`` typed as int — passing a non-coercible
        # string surfaces a ValidationError with the field path.
        LiveSnapshot.model_validate({"handshake_count": "not a number"})

    errors = exc.value.errors()
    assert errors, "ValidationError should expose .errors()"
    # Each error has loc (tuple of path parts) and msg (str). The
    # log formatter joins loc with '.' and emits both — verify both
    # keys exist so our format string doesn't KeyError.
    for err in errors:
        assert "loc" in err
        assert "msg" in err


def test_unknown_extra_field_is_accepted_silently() -> None:
    """LiveSnapshot uses Pydantic's default 'ignore' for extras, so a
    listener that adds a new field doesn't trigger a drift warning on
    older clients. The client just doesn't see the new info — same
    behaviour as the pre-fix path for forward-compat scenarios.

    The WARNING path is reserved for INCOMPATIBLE drift (renamed
    fields, type changes) where the client genuinely can't parse
    the payload. New fields are by design backwards-compatible.
    """
    snap = LiveSnapshot.model_validate(
        {
            "handshake_count": 1,
            "data_transfer_ok": True,
            # Hypothetical future field — must NOT raise.
            "future_diagnostic_field": "from-newer-listener",
        }
    )
    assert snap.handshake_count == 1
    assert snap.data_transfer_ok is True


def test_warning_log_message_is_grepable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End-to-end of the drift logging path through the production
    ``_fetch_snapshot`` parser — verify the WARNING line includes the
    'schema drift' phrase so an operator scanning logs can grep for it.
    """
    from censprobe_client.main import _fetch_snapshot

    # Stub the pinned-GET so we don't open a real socket; the body is
    # a JSON dict where one entry has an invalid field type to trigger
    # ValidationError. Other entries parse normally to prove the parser
    # doesn't bail early on the first bad row.
    body = b"""{
        "shadowsocks": {"handshake_count": 2, "data_transfer_ok": true},
        "mtproto_proxy": {"handshake_count": "not-a-number"}
    }"""

    def _stub_get_with_retry(*args: object, **kwargs: object) -> bytes:
        return body

    import censprobe_client.main as client_main

    real = client_main._pinned_get_with_retry
    client_main._pinned_get_with_retry = _stub_get_with_retry  # type: ignore[assignment]
    try:
        with caplog.at_level(logging.WARNING, logger="censprobe_client.main"):
            out = _fetch_snapshot(
                host="127.0.0.1",
                port=8443,
                token="dummy",
                expected_sha256="0" * 64,
            )
    finally:
        client_main._pinned_get_with_retry = real  # type: ignore[assignment]

    # Healthy entry parsed correctly.
    assert out["shadowsocks"].handshake_count == 2
    # Drifted entry fell back to empty snapshot.
    assert out["mtproto_proxy"].handshake_count == 0
    # The warning was emitted and is grep-friendly.
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected a WARNING for schema drift"
    assert any("schema drift" in r.message for r in warnings)
    assert any("mtproto_proxy" in r.message for r in warnings)
