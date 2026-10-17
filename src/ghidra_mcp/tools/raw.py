"""不依赖 Ghidra 导入的原始文件取证工具。

program_open 只能处理 Ghidra 能自动识别的格式；面对无格式头的裸二进制（固件转储等），
在知道正确的语言和基址之前，这里的工具让调用方可以直接检视文件字节本身
（可打印字符串、十六进制片段），寻找芯片型号、已知头部结构等线索。
"""

from __future__ import annotations

import re
from pathlib import Path

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace

def _read_range(path: Path, offset: int, length: int | None) -> bytes:
    size = path.stat().st_size
    if offset < 0 or offset > size:
        raise ValueError(f"offset 超出文件范围（文件大小 {size}）")
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
            """在不导入 Ghidra 的情况下，直接从文件字节中提取可打印字符串（ASCII 与 UTF-16LE）。

输入输出与副作用：输入本地文件路径、可选字节范围（offset/length）、最短字符串长度（默认 4）和返回条数上限（默认 500）；返回按偏移排序的 {offset, encoding, text} 列表；只读，不创建或修改任何 Ghidra 项目。

何时使用：program_open 因无法识别格式而失败时，用它寻找芯片型号、厂商名、固件版本等线索，为 program_open_raw 所需的语言和基址提供依据；也适用于任意文件的快速字符串扫描，无需先建立程序会话。
""",
            file_strings,
        ),
        ToolDefinition(
            "file_hexdump",
            """在不导入 Ghidra 的情况下，直接读取文件某个字节范围并返回十六进制与可打印字符预览。

输入输出与副作用：输入本地文件路径、偏移 offset（默认 0）和长度 length（默认 256，上限 65536）；返回 {offset, length, hex, ascii}；只读，不创建或修改任何 Ghidra 项目。

何时使用：怀疑某个偏移处存在已知头部结构（ELF、u-boot uImage、WinCE ROMHDR 等）时，用它直接核对魔数和字段，再决定 program_open_raw 的参数；不适合扫描整个大文件，应先用 file_strings 或已知布局定位感兴趣的偏移。
""",
            file_hexdump,
        ),
    )
    for definition in definitions:
        registry.register(definition)
