"""Shared Chrome-on-Windows User-Agent string.

Centralised so the HTTP probe (which uses the full sec-ch-ua + sec-fetch
header set to defeat Meta's anti-bot inconsistency check) and the
middlebox probe (which only needs the UA string to look uniform across
both probes — a different UA here would let UA-aware middleboxes
selectively rewrite our traffic and confuse the case-mutation verdict)
both pin the same value.

Maintenance: refresh the Chrome major version every ~6 months. Stale
versions become their own fingerprint and start tripping the same
heuristics we're trying to pass.
"""

from __future__ import annotations

CHROME_VERSION = "145"

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_VERSION}.0.0.0 Safari/537.36"
)
