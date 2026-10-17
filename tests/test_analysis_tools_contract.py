from dataclasses import dataclass

import pytest

from ghidra_mcp.registry import ToolRegistry


@dataclass(frozen=True)
class FakeFunction:
    name: str
    entry: str

    def getName(self) -> str:
        return self.name

    def getEntryPoint(self) -> str:
        return self.entry

    def getCallingFunctions(self, monitor: object) -> set["FakeFunction"]:
        assert monitor is None
        return {FakeFunction("caller", "00400000")}

    def getCalledFunctions(self, monitor: object) -> set["FakeFunction"]:
        assert monitor is None
        return {FakeFunction("callee", "00400030")}

    def getBody(self) -> set[str]:
        return {"00400010", "00400012"}


@dataclass
class FakeInstruction:
    address: str
    flows: tuple[str, ...]
    fallthrough: str | None
    computed: bool = False

    def getAddress(self) -> str:
        return self.address

    def getFlows(self) -> tuple[str, ...]:
        return self.flows

    def getFallThrough(self) -> str | None:
        return self.fallthrough

    def getDefaultFlows(self) -> tuple[str, ...]:
        return () if self.computed else self.flows

    def getFlowType(self) -> object:
        return type("FlowType", (), {"isComputed": lambda _self: self.computed})()


class FakeListing:
    def getInstructions(self, body: set[str], forward: bool) -> list[FakeInstruction]:
        assert forward is True
        assert body == {"00400010", "00400012"}
        return [
            FakeInstruction("00400010", ("00400030",), "00400012", computed=True),
            FakeInstruction("00400012", (), None),
        ]


class FakeProgram:
    def getListing(self) -> FakeListing:
        return FakeListing()


class FakeAPI:
    function = FakeFunction("worker", "00400010")

    def getCurrentProgram(self) -> FakeProgram:
        return FakeProgram()

    def toAddr(self, address: str) -> str | None:
        return address if address.startswith("0040") else None

    def getFunctionContaining(self, address: str) -> FakeFunction | None:
        return self.function if address in self.function.getBody() else None


class FakeWorkspace:
    def get(self, program_id: str) -> FakeAPI:
        assert program_id == "program-1"
        return FakeAPI()


class FakeDecompiledFunction:
    def getC(self) -> str:
        return "int worker(void) { return 7; }"


class FakeResults:
    def decompileCompleted(self) -> bool:
        return True

    def getDecompiledFunction(self) -> FakeDecompiledFunction:
        return FakeDecompiledFunction()


class FakeDecompiler:
    def __init__(self) -> None:
        self.disposed = False

    def openProgram(self, program: FakeProgram) -> bool:
        return True

    def decompileFunction(
        self, function: FakeFunction, timeout_seconds: int, monitor: object
    ) -> FakeResults:
        assert function.name == "worker"
        assert timeout_seconds == 30
        assert monitor is None
        return FakeResults()

    def getLastMessage(self) -> str:
        return ""

    def dispose(self) -> None:
        self.disposed = True


def test_analysis_tools_decompile_and_build_graphs(monkeypatch: pytest.MonkeyPatch) -> None:
    from ghidra_mcp.tools import analysis

    decompiler = FakeDecompiler()
    monkeypatch.setattr(analysis, "_new_decompiler", lambda: decompiler)
    registry = ToolRegistry()
    analysis.register_analysis_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert list(tools) == ["decompile_function", "call_graph", "control_flow_graph"]
    assert tools["decompile_function"]("program-1", "00400010", 30) == {
        "name": "worker",
        "entry_point": "00400010",
        "c": "int worker(void) { return 7; }",
        "truncated": False,
    }
    assert decompiler.disposed is True
    assert tools["call_graph"]("program-1", "00400010") == {
        "function": {"name": "worker", "entry_point": "00400010"},
        "callers": [{"name": "caller", "entry_point": "00400000"}],
        "callees": [{"name": "callee", "entry_point": "00400030"}],
        "callers_truncated": False,
        "callees_truncated": False,
    }


def test_analysis_outputs_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from ghidra_mcp.tools import analysis

    registry = ToolRegistry()
    decompiler = FakeDecompiler()
    monkeypatch.setattr(analysis, "_new_decompiler", lambda: decompiler)
    analysis.register_analysis_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    decompiled = tools["decompile_function"]("program-1", "00400010", 30, max_chars=10)
    assert decompiled == {
        "name": "worker",
        "entry_point": "00400010",
        "c": "int worker",
        "truncated": True,
    }
    graph = tools["call_graph"]("program-1", "00400010", limit=1)
    assert len(graph["callers"]) <= 1
    assert len(graph["callees"]) <= 1
    assert tools["control_flow_graph"]("program-1", "00400010") == {
        "function": {"name": "worker", "entry_point": "00400010"},
        "nodes": ["00400010", "00400012"],
        "edges": [
            {
                "from": "00400010",
                "to": "00400012",
                "kind": "fallthrough",
                "provenance": "instruction_fallthrough",
                "confidence": "high",
            },
            {
                "from": "00400010",
                "to": "00400030",
                "kind": "computed_flow",
                "provenance": "ghidra_non_default_flow",
                "confidence": "inferred",
            },
        ],
        "coverage": {"scope": "ghidra_function_body", "defined_instructions": 2},
        "incomplete": True,
        "incomplete_reasons": [
            "ghidra_function_body_only",
            "non_default_flow_targets_are_inferred",
            "computed_flow_targets_are_inferred",
        ],
    }


def test_decompile_default_truncates_conversation_sized_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import analysis

    monkeypatch.setattr(FakeDecompiledFunction, "getC", lambda _self: "x" * 50_001)
    monkeypatch.setattr(analysis, "_new_decompiler", FakeDecompiler)
    registry = ToolRegistry()
    analysis.register_analysis_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["decompile_function"]

    result = tool("program-1", "00400010")

    assert len(result["c"]) == 50_000
    assert result["truncated"] is True


def test_control_flow_graph_rejects_at_bound_without_consuming_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import analysis

    def guarded(_self, _body, _forward):
        for index in range(10_001):
            yield FakeInstruction(f"{0x400000 + index:x}", (), None)
        raise AssertionError("control-flow read went past the rejection threshold")

    monkeypatch.setattr(FakeListing, "getInstructions", guarded)
    registry = ToolRegistry()
    analysis.register_analysis_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    with pytest.raises(RuntimeError, match="10000"):
        tools["control_flow_graph"]("program-1", "00400010")


def test_control_flow_graph_marks_non_default_flow_as_inferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import analysis

    instruction = FakeInstruction("00400010", ("00400030", "00400040"), None)
    monkeypatch.setattr(
        instruction,
        "getDefaultFlows",
        lambda: ("00400030",),
    )
    monkeypatch.setattr(
        FakeListing,
        "getInstructions",
        lambda _self, _body, _forward: [instruction],
    )
    registry = ToolRegistry()
    analysis.register_analysis_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["control_flow_graph"]

    graph = tool("program-1", "00400010")

    assert graph["edges"] == [
        {
            "from": "00400010",
            "to": "00400030",
            "kind": "direct_flow",
            "provenance": "instruction_default_flow",
            "confidence": "high",
        },
        {
            "from": "00400010",
            "to": "00400040",
            "kind": "inferred_flow",
            "provenance": "ghidra_non_default_flow",
            "confidence": "inferred",
        },
    ]
