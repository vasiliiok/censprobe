"""
Module-test-only fixtures.

The parent conftest already resets ``modules.dns`` globals before/after
every test. This file re-asserts that reset on the modules subtree (in
case a future refactor moves the parent conftest), and provides a
``mock_socket`` fixture that lets tests fake ``asyncio.open_connection``
without each test re-implementing it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest


class FakeReader:
    """Async-stream stub for asyncio.open_connection."""

    def __init__(self, payload: bytes = b"") -> None:
        self._payload = payload

    async def read(self, n: int) -> bytes:
        data = self._payload[:n]
        self._payload = self._payload[n:]
        return data

    async def readexactly(self, n: int) -> bytes:
        if len(self._payload) < n:
            raise EOFError
        out = self._payload[:n]
        self._payload = self._payload[n:]
        return out


class FakeWriter:
    """Async-write stub for asyncio.open_connection."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.fixture
def fake_pair() -> tuple[FakeReader, FakeWriter]:
    """Pre-built (reader, writer) pair — most tests just need an empty pair."""
    return FakeReader(), FakeWriter()


@pytest.fixture
def patch_open_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Any]:
    """Patch ``asyncio.open_connection`` on the *module* under test.

    Each module imports ``asyncio`` then calls ``asyncio.open_connection``
    via attribute access — patching the asyncio module directly is the
    only way to keep monkeypatch.setattr from breaking type binding.
    """

    def _factory(module: Any, side_effect: Any) -> None:
        async def _impl(*args: Any, **kwargs: Any) -> Any:
            if isinstance(side_effect, BaseException):
                raise side_effect
            if callable(side_effect):
                return side_effect(*args, **kwargs)
            return side_effect

        monkeypatch.setattr(module.asyncio, "open_connection", _impl)

    yield _factory
