"""Replay projector: record a binary's execution and seek back to any frame.

The Python package is a thin shell over the Rust engine in ``cinema._core``.
``record`` captures a real run into a :class:`~cinema._core.Trace`; ``load``
reads a ``.ctrace`` back. Both return an object that can rebuild the machine
state at any frame without re-running the program.
"""

from __future__ import annotations

from cinema._core import State, Trace, load_ctrace, record

__all__ = ["State", "Trace", "__version__", "load_ctrace", "record"]
__version__ = "0.1.0"
