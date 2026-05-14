"""Shared INFO-line formatters used by listener and client.

Three line shapes flow through this module:

  * ``preflight[STATUS] name: message`` — listener startup
  * ``probe[name] verdict=... elapsed=... rtt=... throughput=...`` — client per-probe
  * ``cross-verify[name] client=... listener=... dc_reach_ok=... → final=... note=...``
    — client cross-verify per row

Keeping the format strings here (rather than inline at the
``logger.info(...)`` call site) means an operator's grep pattern for
``probe[<name>] verdict=`` doesn't break the next time someone adds
a column. A single edit here updates every emitter.

Snapshot-tested in ``tests/snapshots/test_log_format_lines.py``
so accidental whitespace / punctuation drift is caught early.
"""

from __future__ import annotations

from censprobe_core.models import Verdict


def format_preflight_line(name: str, status: str, message: str) -> str:
    """Plain-text mirror of the Rich preflight panel.

    ``status`` is the lowercase severity word (``ok`` / ``warn`` /
    ``skip``) so an operator can grep ``preflight[warn]`` to find
    every non-clean check across a multi-vantage log.
    """
    return f"preflight[{status}] {name}: {message}"


def format_probe_line(
    name: str,
    verdict: Verdict,
    elapsed_ms: float | None,
    rtt_ms: float | None,
    throughput_mbps: float | None,
    error: str | None,
) -> str:
    """One-line summary of a single probe result.

    ``elapsed_ms`` is the full probe duration (TCP-connect + handshake
    + data phase); ``rtt_ms`` is protocol-specific (TCP-connect for
    most, ICMP-ping for VPN families). ``throughput_mbps`` is None
    for handshake-only protocols (mtg family). ``error`` mirrors the
    text in the per-probe table's Error column; "none" when empty.
    """
    rtt = f"{rtt_ms:.0f}ms" if rtt_ms is not None else "n/a"
    throughput = f"{throughput_mbps:.2f}Mbps" if throughput_mbps is not None else "n/a"
    elapsed = f"{elapsed_ms:.0f}" if elapsed_ms is not None else "0"
    return (
        f"probe[{name}] verdict={verdict} elapsed={elapsed}ms "
        f"rtt={rtt} throughput={throughput} error={error or 'none'}"
    )


def format_cross_verify_line(
    name: str,
    client: Verdict,
    listener: Verdict,
    dc_reach_ok: bool | None,
    client_error: str | None,
    final: str,
    note: str,
) -> str:
    """One-line summary of a cross-verify decision.

    Preserves the (client, listener, dc_reach_ok, client_error) inputs
    that fed the (final, note) output — so an operator reviewing a
    log can see WHY a given final verdict was chosen without rerunning
    the probe. ``note=agree`` when the two sides matched and no
    rewrite was needed (otherwise it carries the diagnostic string).
    """
    return (
        f"cross-verify[{name}] "
        f"client={client} listener={listener} dc_reach_ok={dc_reach_ok} "
        f"client_error={client_error or 'none'} → final={final} note={note or 'agree'}"
    )
