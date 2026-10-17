from pathlib import Path

from ghidra_mcp.registry import ToolRegistry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace
from ghidra_mcp.tools.raw import register_raw_tools


def write_ghidra_version(install_dir: Path) -> None:
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.1.2\n", encoding="utf-8")


class FakePyGhidra:
    def start(self, *, install_dir: Path) -> object:
        return install_dir


def _workspace(tmp_path: Path, *, input_root: Path | None = None) -> ProgramWorkspace:
    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    return ProgramWorkspace(
        GhidraRuntime(install_dir=install_dir, pyghidra_module=FakePyGhidra()),
        input_root=input_root,
    )


def test_file_strings_finds_ascii_and_utf16le(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.bin"
    payload = b"\x00\x00ClarionQY8\x00\x00" + "Nissan LEAF".encode("utf-16le") + b"\x00\x00"
    binary.write_bytes(payload)
    workspace = _workspace(tmp_path, input_root=tmp_path)
    registry = ToolRegistry()
    register_raw_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    assert list(tools) == ["file_strings", "file_hexdump"]

    results = tools["file_strings"].handler(str(binary), min_length=4)
    texts = {entry["text"] for entry in results}
    assert "ClarionQY8" in texts
    assert "Nissan LEAF" in texts
    ascii_entry = next(entry for entry in results if entry["text"] == "ClarionQY8")
    assert ascii_entry["encoding"] == "ascii"
    assert ascii_entry["offset"] == payload.index(b"ClarionQY8")
    utf16_entry = next(entry for entry in results if entry["text"] == "Nissan LEAF")
    assert utf16_entry["encoding"] == "utf-16le"


def test_file_strings_respects_offset_length_and_limit(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"AAAA" + b"\x00" * 4 + b"BBBB" + b"\x00" * 4 + b"CCCC")
    workspace = _workspace(tmp_path, input_root=tmp_path)
    registry = ToolRegistry()
    register_raw_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    limited = tools["file_strings"].handler(str(binary), min_length=4, limit=1)
    assert len(limited) == 1

    windowed = tools["file_strings"].handler(str(binary), offset=8, length=4, min_length=4)
    assert [entry["text"] for entry in windowed] == ["BBBB"]
    assert windowed[0]["offset"] == 8


def test_file_hexdump_returns_hex_and_ascii_preview(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"\x7fELF" + b"\x01\x02\x03")
    workspace = _workspace(tmp_path, input_root=tmp_path)
    registry = ToolRegistry()
    register_raw_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    dump = tools["file_hexdump"].handler(str(binary), offset=0, length=7)
    assert dump == {
        "offset": 0,
        "length": 7,
        "hex": "7f454c46010203",
        "ascii": ".ELF...",
    }


def test_file_tools_reject_paths_outside_input_root(tmp_path: Path) -> None:
    allowed_root = tmp_path / "input"
    allowed_root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not allowed")
    workspace = _workspace(tmp_path, input_root=allowed_root)
    registry = ToolRegistry()
    register_raw_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    try:
        tools["file_strings"].handler(str(outside))
    except Exception as error:
        assert "输入路径超出允许的输入根目录" in str(error)
    else:
        raise AssertionError("expected WorkspaceError for path outside input root")
