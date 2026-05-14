"""Contract: ASYMMETRIC_DPI_ERROR_MARKERS prefixes must actually appear
in ``_mtg_error_result(...)`` call sites within ``protocol_probes.py``.

Why this exists: the client-side cross-verifier (and any downstream
analyser) imports :data:`ASYMMETRIC_DPI_ERROR_MARKERS` from
``censprobe_core.protocol_probes`` to recognise the read-timeout-after-
handshake shape. If a refactor renames the error string emitted by
``_mtg_error_result`` (say ``welcome_read_timeout_record0`` →
``mtg_welcome_timeout``) but the marker tuple isn't updated, the
asymmetric-DPI attribution silently breaks — regression of commit
280cf77 / memory ``mts_round_2026-05-13``.

This contract test fails loudly when that drift happens by parsing the
source of ``protocol_probes.py`` and verifying that every exported
marker is reachable as a substring of at least one ``_mtg_error_result``
literal argument.
"""

from __future__ import annotations

import inspect
import re

from censprobe_core import protocol_probes


def test_every_marker_appears_in_protocol_probes_source() -> None:
    source = inspect.getsource(protocol_probes)
    # Match the first string-literal positional argument of every
    # _mtg_error_result(...) call. Captures both f-strings and plain
    # strings, single- and double-quoted. We don't need to evaluate
    # the literals — substring match below is sufficient.
    literal_args: list[str] = re.findall(r"_mtg_error_result\(\s*[fF]?[\"']([^\"']+)[\"']", source)
    assert literal_args, (
        "no _mtg_error_result literal arguments found — parser is broken or the helper was renamed"
    )

    for marker in protocol_probes.ASYMMETRIC_DPI_ERROR_MARKERS:
        matching = [arg for arg in literal_args if marker in arg]
        assert matching, (
            f"ASYMMETRIC_DPI_ERROR_MARKERS includes {marker!r} but no "
            f"_mtg_error_result(...) literal in protocol_probes.py "
            f"contains that substring — either the producer renamed "
            f"its error tag without updating the marker tuple "
            f"(silent regression of the asymmetric-DPI cross-verify), "
            f"or the marker is stale and should be removed."
        )


def test_markers_are_distinct() -> None:
    markers = protocol_probes.ASYMMETRIC_DPI_ERROR_MARKERS
    assert len(set(markers)) == len(markers), (
        f"ASYMMETRIC_DPI_ERROR_MARKERS contains duplicates: {markers}"
    )
