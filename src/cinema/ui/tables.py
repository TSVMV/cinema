"""Table helpers with a consistent projector look."""

from __future__ import annotations

from rich.table import Table


def base_table(title: str | None = None) -> Table:
    return Table(
        title=title,
        title_style="bold",
        box=None,
        border_style="bright_black",
        show_header=True,
        header_style="bright_black",
        pad_edge=False,
        show_lines=False,
        expand=False,
    )
