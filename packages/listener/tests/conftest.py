"""
listener test fixtures.

Phase 1 placeholder — substantive fixtures (creds_factory, dummy_ports,
self-signed cert cache, mocked subprocess responder) land in Phase 2-3.
"""

from __future__ import annotations

from hypothesis import settings

# Force every property test in this package onto a derandomised profile so a
# CI runner can't generate a different example sequence than a local one. The
# `@settings(derandomize=True)` decorators in tests/property/* are now
# redundant under this profile; they're kept harmless. Documented in
# docs/TESTING.md ("Слой E — Property-based").
settings.register_profile("censprobe-deterministic", derandomize=True)
settings.load_profile("censprobe-deterministic")
