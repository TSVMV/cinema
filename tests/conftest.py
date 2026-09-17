"""Shared fixtures: one real recording, reused by every test.

Nothing here fabricates trace data. The single source of truth is
``fixtures/hello_static``, a static ELF whose behaviour is known exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cinema import _core as core
from cinema._core import Trace

FIXTURES: Path = Path(__file__).resolve().parent / "fixtures"
HELLO_STATIC: Path = FIXTURES / "hello_static"

EXPECTED_OUTPUT: bytes = b"hello, winVpwn\n"
EXPECTED_ENTRY: int = 0x401000


@pytest.fixture(scope="session")
def hello_bytes() -> bytes:
    return HELLO_STATIC.read_bytes()


@pytest.fixture(scope="session")
def trace(hello_bytes: bytes) -> Trace:
    """A real recording of ``hello_static`` under the emulator."""
    return core.record(hello_bytes)


@pytest.fixture(scope="session")
def ctrace_path(trace: Trace, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The same recording persisted to a ``.ctrace`` file."""
    path = tmp_path_factory.mktemp("ctrace") / "hello.ctrace"
    path.write_bytes(trace.encode())
    return path


@pytest.fixture()
def missing_path(tmp_path: Path) -> Path:
    return tmp_path / "absent.ctrace"


@pytest.fixture()
def corrupt_path(tmp_path: Path) -> Path:
    """A file whose header passes the magic check but nothing else."""
    path = tmp_path / "broken.ctrace"
    path.write_bytes(b"CTRC" + b"\x00\x01" + b"\x00" * 4096)
    return path
