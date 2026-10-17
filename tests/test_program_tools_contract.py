from contextlib import contextmanager
from pathlib import Path

from ghidra_mcp.registry import ToolRegistry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace


class FakeCompilerSpec:
    def getCompilerSpecID(self) -> str:
        return "default"


class FakeProgram:
    def save(self, _: str, __: object) -> None:
        pass

    def getName(self) -> str:
        return "sample.bin"

    def getLanguageID(self) -> str:
        return "x86:LE:64:default"

    def getCompilerSpec(self) -> FakeCompilerSpec:
        return FakeCompilerSpec()

    def getImageBase(self) -> str:
        return "00400000"

    def getExecutableFormat(self) -> str:
        return "Executable and Linking Format (ELF)"

    def getMinAddress(self) -> str:
        return "00400000"

    def getMaxAddress(self) -> str:
        return "00401fff"


class FakeAPI:
    def __init__(self, binary: Path) -> None:
        self.binary = binary

    def getCurrentProgram(self) -> FakeProgram:
        return FakeProgram()


class FakePyGhidra:
    def __init__(self) -> None:
        self.raw_open_calls: list[tuple[Path, dict[str, object]]] = []

    def start(self, *, install_dir: Path) -> object:
        return install_dir

    def task_monitor(self) -> object:
        return object()

    @contextmanager
    def _program_context_factory(self, binary_path: Path, **_: object):
        yield FakeAPI(binary_path)

    @contextmanager
    def _program_context_raw_factory(self, binary_path: Path, **options: object):
        self.raw_open_calls.append((binary_path, options))
        yield FakeAPI(binary_path)


def write_ghidra_version(install_dir: Path) -> None:
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.1.2\n", encoding="utf-8")


def test_program_tools_cover_open_list_info_and_close(tmp_path: Path) -> None:
    from ghidra_mcp.tools.programs import register_program_tools

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir=install_dir, pyghidra_module=FakePyGhidra())
    )
    registry = ToolRegistry()

    register_program_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    assert list(tools) == [
        "program_open",
        "program_list",
        "program_info",
        "program_close",
        "program_open_raw",
    ]
    close_annotations = tools["program_close"].annotations
    assert close_annotations is not None
    assert close_annotations.readOnlyHint is False
    assert close_annotations.destructiveHint is True
    assert close_annotations.idempotentHint is False
    assert close_annotations.openWorldHint is False

    opened = tools["program_open"].handler(str(binary), analyze=False)
    program_id = opened["program_id"]
    assert opened == {"program_id": program_id, "path": str(binary.resolve())}
    assert tools["program_list"].handler() == [
        {"program_id": program_id, "path": str(binary.resolve())}
    ]
    assert tools["program_info"].handler(program_id) == {
        "program_id": program_id,
        "name": "sample.bin",
        "language": "x86:LE:64:default",
        "compiler": "default",
        "image_base": "00400000",
        "format": "Executable and Linking Format (ELF)",
        "min_address": "00400000",
        "max_address": "00401fff",
    }
    assert tools["program_close"].handler(program_id) == {"closed": program_id}
    assert tools["program_list"].handler() == []


def test_program_open_raw_passes_language_and_base_address(tmp_path: Path) -> None:
    from ghidra_mcp.tools.programs import register_program_tools

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"firmware")
    fake_pyghidra = FakePyGhidra()
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir=install_dir, pyghidra_module=fake_pyghidra)
    )
    registry = ToolRegistry()

    register_program_tools(registry, workspace)
    tools = {tool.name: tool for tool in registry.enabled_tools()}

    opened = tools["program_open_raw"].handler(
        str(binary),
        "ARM:LE:32:Cortex",
        "0x88000000",
        analyze=False,
    )
    program_id = opened["program_id"]
    assert opened == {"program_id": program_id, "path": str(binary.resolve())}
    assert len(fake_pyghidra.raw_open_calls) == 1
    opened_path, options = fake_pyghidra.raw_open_calls[0]
    assert opened_path == binary.resolve()
    assert options["language_id"] == "ARM:LE:32:Cortex"
    assert options["base_address"] == "0x88000000"
    assert options["compiler_id"] == "default"
    assert tools["program_close"].handler(program_id) == {"closed": program_id}
