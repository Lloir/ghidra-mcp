from dataclasses import dataclass

import pytest

from ghidra_mcp.registry import ToolRegistry


@dataclass
class FakeBlock:
    name: str
    start: str
    end: str
    size: int
    read: bool = True
    write: bool = False
    execute: bool = True
    initialized: bool = True

    def getName(self) -> str:
        return self.name

    def getStart(self) -> str:
        return self.start

    def getEnd(self) -> str:
        return self.end

    def getSize(self) -> int:
        return self.size

    def isRead(self) -> bool:
        return self.read

    def isWrite(self) -> bool:
        return self.write

    def isExecute(self) -> bool:
        return self.execute

    def isInitialized(self) -> bool:
        return self.initialized


class FakeMemory:
    def getBlocks(self) -> list[FakeBlock]:
        return [FakeBlock(".text", "00400000", "004000ff", 256)]


@dataclass
class FakeFunction:
    name: str
    entry: str

    def getName(self) -> str:
        return self.name

    def getEntryPoint(self) -> str:
        return self.entry

    def getSignature(self) -> str:
        return f"void {self.name}(void)"

    def isExternal(self) -> bool:
        return False

    def isThunk(self) -> bool:
        return False


class FakeFunctionManager:
    def getFunctions(self, forward: bool) -> list[FakeFunction]:
        assert forward is True
        return [FakeFunction("entry", "00400010"), FakeFunction("worker", "00400030")]


class FakeProgram:
    def getMemory(self) -> FakeMemory:
        return FakeMemory()

    def getFunctionManager(self) -> FakeFunctionManager:
        return FakeFunctionManager()


class FakeAPI:
    def getCurrentProgram(self) -> FakeProgram:
        return FakeProgram()

    def toAddr(self, address: str) -> str | None:
        return address if address.startswith("0040") else None

    def getBytes(self, address: str, length: int) -> list[int]:
        assert address == "00400000"
        assert length == 3
        return [-1, 0, 65]

    def getFunctionContaining(self, address: str) -> FakeFunction | None:
        return FakeFunction("worker", "00400030") if address == "00400031" else None


class FakeWorkspace:
    def get(self, program_id: str) -> FakeAPI:
        if program_id != "program-1":
            raise AssertionError("unexpected program id")
        return FakeAPI()


def test_navigation_tools_return_stable_json_contracts() -> None:
    from ghidra_mcp.tools.navigation import register_navigation_tools

    registry = ToolRegistry()
    register_navigation_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert list(tools) == ["memory_blocks_list", "memory_read", "functions_list", "function_get"]
    assert tools["memory_blocks_list"]("program-1") == [
        {
            "name": ".text",
            "start": "00400000",
            "end": "004000ff",
            "size": 256,
            "read": True,
            "write": False,
            "execute": True,
            "initialized": True,
        }
    ]
    assert tools["memory_read"]("program-1", "00400000", 3) == {
        "address": "00400000",
        "length": 3,
        "hex": "ff0041",
    }
    assert tools["memory_read"](
        "program-1",
        "00400000",
        3,
        interpret=True,
        unit_size=2,
        byte_order="little",
    ) == {
        "address": "00400000",
        "length": 3,
        "hex": "ff0041",
        "ascii": "..A",
        "unit_size": 2,
        "byte_order": "little",
        "unsigned_values": [255],
        "trailing_hex": "41",
    }
    assert tools["functions_list"]("program-1", offset=1, limit=1) == [
        {
            "name": "worker",
            "entry_point": "00400030",
            "signature": "void worker(void)",
            "external": False,
            "thunk": False,
        }
    ]
    assert tools["function_get"]("program-1", "00400031") == {
        "requested_address": "00400031",
        "resolution": "contained",
        "function": {
            "name": "worker",
            "entry_point": "00400030",
            "signature": "void worker(void)",
            "external": False,
            "thunk": False,
        },
        "reason": None,
    }
    assert tools["function_get"]("program-1", "00400020") == {
        "requested_address": "00400020",
        "resolution": "unassigned",
        "function": None,
        "reason": "address_not_in_ghidra_function_body",
    }


def test_navigation_tools_reject_invalid_bounds_and_addresses() -> None:
    from ghidra_mcp.tools.navigation import ToolInputError, register_navigation_tools

    registry = ToolRegistry()
    register_navigation_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    with pytest.raises(ToolInputError, match="length"):
        tools["memory_read"]("program-1", "00400000", 0)
    with pytest.raises(ToolInputError, match="address"):
        tools["memory_read"]("program-1", "invalid", 3)
    with pytest.raises(ToolInputError, match="unit_size"):
        tools["memory_read"]("program-1", "00400000", 3, interpret=True, unit_size=3)
    with pytest.raises(ToolInputError, match="byte_order"):
        tools["memory_read"]("program-1", "00400000", 3, interpret=True, byte_order="middle")
    with pytest.raises(ToolInputError, match="limit"):
        tools["functions_list"]("program-1", offset=0, limit=1001)


def test_functions_list_stops_after_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    from ghidra_mcp.tools.navigation import register_navigation_tools

    def guarded(_self, _forward):
        yield FakeFunction("entry", "00400010")
        raise AssertionError("function pagination read went past limit")

    monkeypatch.setattr(FakeFunctionManager, "getFunctions", guarded)
    registry = ToolRegistry()
    register_navigation_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert tools["functions_list"]("program-1", limit=1)[0]["name"] == "entry"
