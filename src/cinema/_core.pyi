# Type stubs for the cinema._core native extension (maturin / PyO3).

from __future__ import annotations

from typing import TypedDict

__version__: str


class Trace:
    """A recorded execution: base image, event stream and snapshot index.

    Frame numbers are event indices: frame 0 is the state before any event,
    and ``len(trace)`` is the final frame.
    """

    def __len__(self) -> int: ...

    def len(self) -> int: ...

    def is_empty(self) -> bool: ...

    def frame_count(self) -> int: ...

    def entry(self) -> int: ...

    def image_hash(self) -> str: ...

    def base_page_count(self) -> int: ...

    def snapshot_frames(self) -> list[int]: ...

    def initial_regs(self) -> dict[str, int]: ...

    def encode(self) -> bytes: ...

    def state_at(self, frame: int) -> State: ...

    def read_memory(self, frame: int, addr: int, length: int) -> bytes: ...

    def event_at(self, frame: int) -> dict[str, object] | None: ...

    def events(self, start: int, end: int) -> list[dict[str, object]]: ...

    class TraceSummary(TypedDict):
        entry: int
        image_hash: str
        events: int
        snapshots: int
        base_pages: int
        final_frame: int
        output: bytes
        final_rip: int
        exit_kind: str
        exit_value: int

    def summary(self) -> TraceSummary: ...


class State:
    """A materialized machine state at one frame."""

    def frame(self) -> int: ...

    def rip(self) -> int: ...

    def reg(self, name: str) -> int | None: ...

    def regs(self) -> dict[str, int]: ...

    def output(self) -> bytes: ...

    def read_memory(self, addr: int, length: int) -> bytes: ...

    def dirty_page_count(self) -> int: ...


# record(image: bytes, timeout_ms: int = 0, max_events: int = 0) -> Trace
#   Runs the ELF under the emulator and returns its trace.
def record(image: bytes, timeout_ms: int = 0, max_events: int = 0) -> Trace: ...


# load_ctrace(data: bytes) -> Trace
#   Decodes .ctrace bytes. Raises ValueError on a bad or corrupt file.
def load_ctrace(data: bytes) -> Trace: ...
