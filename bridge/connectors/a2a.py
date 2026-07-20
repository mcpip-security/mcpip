"""
MCPIP V2 — Connector binding: A2A (Agent-to-Agent) task envelope.

Covers a representative A2A ``Task`` envelope (A2A v1.0.1 data model — Task /
Message / Part) carrying EXACTLY one ``DataPart`` skill invocation
(``{skill:<alias>, arguments:{...}}``). This is the 7th SOURCE_FORMAT, added as a
DELIBERATE, vendor-mapped connector wave (it forces the conscious registry re-pin).

MCPIP does NOT sit on the A2A message bus and does NOT dial A2A — it gates the ONE
side-effecting alias call a single governed identity proposes, normalizing the A2A
task envelope into the SAME NormalizedIntent every other dialect produces so it flows
through the identical Obfuscator / Auth / Audit path and the UNCHANGED payload lock.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("a2a",)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.A2A_TASK
PARSER: Final[FormatParser] = formats.parse_a2a_task
