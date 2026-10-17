"""Raw file forensics tools that do not depend on a Ghidra import.

program_open can only handle formats Ghidra auto-detects. For headerless raw
binaries (firmware dumps and the like), before the correct language and base
address are known, the tools here let a caller inspect the file's bytes
directly (printable strings, hex snippets) to look for chip names, known
header structures, and other clues.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace


def _read_range(path: Path, offset: int, length: int | None) -> bytes:
    size = path.stat().st_size
    if offset < 0 or offset > size:
        raise ValueError(f"offset is out of range for this file (size {size})")
    with path.open("rb") as stream:
        stream.seek(offset)
        if length is None:
            return stream.read()
        return stream.read(max(0, length))


def _collect_strings(data: bytes, base_offset: int, min_length: int) -> list[dict[str, object]]:
    floor = max(1, min_length)
    ascii_run = re.compile(rb"[\x20-\x7e]{%d,}" % floor)
    utf16le_run = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % floor)
    found: list[dict[str, object]] = []
    for match in ascii_run.finditer(data):
        found.append(
            {
                "offset": base_offset + match.start(),
                "encoding": "ascii",
                "text": match.group().decode("ascii"),
            }
        )
    for match in utf16le_run.finditer(data):
        try:
            text = match.group().decode("utf-16le")
        except UnicodeDecodeError:
            continue
        found.append(
            {
                "offset": base_offset + match.start(),
                "encoding": "utf-16le",
                "text": text,
            }
        )
    found.sort(key=lambda item: item["offset"])
    return found


def register_raw_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def file_strings(
        binary_path: str,
        offset: int = 0,
        length: int | None = None,
        min_length: int = 4,
        limit: int = 500,
    ) -> list[dict[str, object]]:
        binary = workspace.resolve_input(Path(binary_path))
        data = _read_range(binary, offset, length)
        strings = _collect_strings(data, offset, min_length)
        return strings[: max(0, limit)]

    def file_hexdump(
        binary_path: str,
        offset: int = 0,
        length: int = 256,
    ) -> dict[str, object]:
        binary = workspace.resolve_input(Path(binary_path))
        bounded_length = max(1, min(length, 65536))
        data = _read_range(binary, offset, bounded_length)
        ascii_preview = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in data)
        return {
            "offset": offset,
            "length": len(data),
            "hex": data.hex(),
            "ascii": ascii_preview,
        }

    definitions = (
        ToolDefinition(
            "file_strings",
            """Extract printable strings (ASCII and UTF-16LE) directly from a file's bytes, without importing it into Ghidra.

Inputs/outputs and side effects: takes a local file path, an optional byte range (offset/length), a minimum string length (default 4), and a maximum number of results (default 500); returns a list of {offset, encoding, text} sorted by offset; read-only, creates or modifies no Ghidra project.

When to use: when program_open fails because the format can't be recognized, use it to look for chip names, vendor names, firmware versions, and other clues to supply the language and base address program_open_raw needs; also useful for a quick string scan of any file without first establishing a program session.
""",
            file_strings,
        ),
        ToolDefinition(
            "file_hexdump",
            """Read a byte range from a file directly and return it as hex plus a printable-character preview, without importing it into Ghidra.

Inputs/outputs and side effects: takes a local file path, an offset (default 0), and a length (default 256, capped at 65536); returns {offset, length, hex, ascii}; read-only, creates or modifies no Ghidra project.

When to use: when you suspect a known header structure (ELF, u-boot uImage, WinCE ROMHDR, etc.) at a particular offset, use it to check magic bytes and fields directly before deciding on program_open_raw's parameters; not suited to scanning an entire large file — locate an offset of interest first with file_strings or a known layout.
""",
            file_hexdump,
        ),
    )
    for definition in definitions:
        registry.register(definition)
