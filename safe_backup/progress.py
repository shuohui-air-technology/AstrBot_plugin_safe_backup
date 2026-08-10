"""Redaction-safe progress values shared by the engine and visible runner."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable


PHASES = (
    "preflight", "inventory", "copy", "sqlite", "archive", "verify", "publish",
)
STATUSES = {"started", "progress", "complete", "failed"}
UNITS = {"items", "directories", "bytes", "families", "entries", "archive"}
MAX_COUNTER = (1 << 63) - 1
_DETAIL = re.compile(r"[A-Za-z0-9_.-]{0,128}\Z")


@dataclass(frozen=True)
class ProgressEvent:
    """A finite, path-free status update that is safe to render and log."""

    phase: str
    index: int
    total: int
    current: int
    unit: str
    status: str
    detail_token: str = ""

    def __post_init__(self) -> None:
        if self.phase not in PHASES or self.index != PHASES.index(self.phase) + 1:
            raise ValueError("invalid progress phase")
        if self.unit not in UNITS or self.status not in STATUSES:
            raise ValueError("invalid progress enum")
        if any(type(value) is not int or value < 0 or value > MAX_COUNTER
               for value in (self.total, self.current)):
            raise ValueError("invalid progress counter")
        if self.total == 0 and self.current != 0:
            raise ValueError("unknown progress total requires zero current")
        if self.total and self.current > self.total:
            raise ValueError("progress exceeds total")
        if not isinstance(self.detail_token, str) or _DETAIL.fullmatch(self.detail_token) is None:
            raise ValueError("unsafe progress detail")

    def record(self) -> dict[str, object]:
        return asdict(self)


ProgressSink = Callable[[ProgressEvent], None]
