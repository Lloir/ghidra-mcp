from dataclasses import dataclass

import pytest

from ghidra_mcp.registry import ToolRegistry


@dataclass
class FakeInstruction:
    address: str
    mnemonic: str
    operands: tuple[str, ...]
    length: int

    def getAddress(self) -> "FakeAddress":
        return FakeAddress(self.address)

    def getMnemonicString(self) -> str:
        return self.mnemonic

    def getNumOperands(self) -> int:
        return len(self.operands)

    def getDefaultOperandRepresentation(self, index: int) -> str:
        return self.operands[index]

    def getLength(self) -> int:
        return self.length

    def getFlowType(self) -> object:
        return type("FlowType", (), {"isComputed": lambda _self: False})()


class FakeAddress(str):
    def add(self, offset: int) -> "FakeAddress":
        return FakeAddress(f"{int(self, 16) + offset:08x}")

    def subtract(self, other: object) -> int:
        return int(self, 16) - int(str(other), 16)

    def getAddressSpace(self) -> str:
        return "ram"

    def getOffset(self) -> int:
        return int(self, 16)


class OtherSpaceAddress(FakeAddress):
    def getAddressSpace(self) -> str:
        return "other"


@dataclass
class FakeSymbol:
    name: str
    address: str

    def getName(self) -> str:
        return self.name

    def getAddress(self) -> str:
        return self.address

    def getSymbolType(self) -> str:
        return "Function"

    def getSource(self) -> str:
        return "ANALYSIS"

    def isPrimary(self) -> bool:
        return True


@dataclass
class FakeReference:
    source: str
    target: str

    def getFromAddress(self) -> str:
        return self.source

    def getToAddress(self) -> str:
        return self.target

    def getReferenceType(self) -> object:
        return type(
            "ReferenceType",
            (),
            {
                "__str__": lambda _self: "UNCONDITIONAL_CALL",
                "isFlow": lambda _self: True,
            },
        )()

    def getOperandIndex(self) -> int:
        return 0

    def isPrimary(self) -> bool:
        return True

    def getSource(self) -> str:
        return "ANALYSIS"


@dataclass
class FakeData:
    address: str
    value: str

    def hasStringValue(self) -> bool:
        return True

    def getAddress(self) -> str:
        return self.address

    def getLength(self) -> int:
        return len(self.value) + 1

    def getDataType(self) -> str:
        return "string"

    def getDefaultValueRepresentation(self) -> str:
        return f'"{self.value}"'


class FakeListing:
    def getInstructions(self, *args: object) -> list[FakeInstruction]:
        assert args in (
            (True,),
            (FakeAddress("00400010"), True),
            (FakeAddress("00400008"), True),
            (OtherSpaceAddress("00000008"), True),
        )
        return [FakeInstruction("00400010", "MOV", ("EAX", "EBX"), 2)]

    def getDefinedData(self, forward: bool) -> list[FakeData]:
        assert forward is True
        return [FakeData("00401000", "hello")]

    def getInstructionAt(self, address: FakeAddress) -> FakeInstruction | None:
        return (
            None
            if str(address) == "00400008"
            else FakeInstruction(str(address), "MOV", ("EAX", "EBX"), 2)
        )

    def getInstructionContaining(self, address: FakeAddress) -> object | None:
        return self.getInstructionAt(address)

    def getDefinedDataContaining(self, _address: FakeAddress) -> object | None:
        return None


class FakeSymbolTable:
    def getAllSymbols(self, include_dynamic: bool) -> list[FakeSymbol]:
        assert include_dynamic is True
        return [FakeSymbol("entry", "00400010")]


class FakeReferenceManager:
    def getReferencesFrom(self, address: str) -> list[FakeReference]:
        return [FakeReference(address, "00400030")]

    def getReferencesTo(self, address: str) -> list[FakeReference]:
        return [FakeReference("00400008", address)]


class FakeProgram:
    def getListing(self) -> FakeListing:
        return FakeListing()

    def getSymbolTable(self) -> FakeSymbolTable:
        return FakeSymbolTable()

    def getReferenceManager(self) -> FakeReferenceManager:
        return FakeReferenceManager()

    def getLanguage(self) -> object:
        return type("Language", (), {"getInstructionAlignment": lambda _self: 4})()


class FakeAPI:
    def getCurrentProgram(self) -> FakeProgram:
        return FakeProgram()

    def toAddr(self, address: str) -> str | None:
        return FakeAddress(address) if address.startswith("0040") else None


class FakeWorkspace:
    def get(self, program_id: str) -> FakeAPI:
        assert program_id == "program-1"
        return FakeAPI()


def test_listing_tools_return_stable_json_contracts() -> None:
    from ghidra_mcp.tools.listing import register_listing_tools

    registry = ToolRegistry()
    register_listing_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert list(tools) == ["instructions_list", "symbols_list", "references_list", "strings_list"]
    assert tools["instructions_list"]("program-1", address="00400010") == {
        "requested_address": "00400010",
        "effective_address": "00400010",
        "returned_start_address": "00400010",
        "exact_start": True,
        "skipped_bytes": 0,
        "instructions": [
            {
                "address": "00400010",
                "mnemonic": "MOV",
                "operands": ["EAX", "EBX"],
                "length": 2,
            }
        ],
    }
    assert tools["symbols_list"]("program-1") == [
        {
            "name": "entry",
            "address": "00400010",
            "type": "Function",
            "source": "ANALYSIS",
            "primary": True,
        }
    ]
    assert tools["references_list"]("program-1", "00400010", direction="both") == {
        "requested_address": "00400010",
        "references": [
            {
                "from": "00400010",
                "to": "00400030",
                "type": "UNCONDITIONAL_CALL",
                "operand_index": 0,
                "primary": True,
                "direction": "from",
                "provenance": "ghidra_reference_manager",
                "source": "ANALYSIS",
                "confidence": "high",
            },
            {
                "from": "00400008",
                "to": "00400010",
                "type": "UNCONDITIONAL_CALL",
                "operand_index": 0,
                "primary": True,
                "direction": "to",
                "provenance": "ghidra_reference_manager",
                "source": "ANALYSIS",
                "confidence": "high",
            },
        ],
        "coverage": {"mode": "listing_only", "scan": None},
        "incomplete": True,
        "incomplete_reasons": ["ghidra_reference_manager_depends_on_defined_listing"],
        "truncated": False,
    }
    assert tools["strings_list"]("program-1", contains="ell") == [
        {"address": "00401000", "length": 6, "data_type": "string", "value": '"hello"'}
    ]


def test_listing_tools_validate_direction_address_and_page_size() -> None:
    from ghidra_mcp.tools.listing import ToolInputError, register_listing_tools

    registry = ToolRegistry()
    register_listing_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    with pytest.raises(ToolInputError, match="limit"):
        tools["instructions_list"]("program-1", limit=0)
    with pytest.raises(ToolInputError, match="direction"):
        tools["references_list"]("program-1", "00400010", direction="sideways")
    with pytest.raises(ToolInputError, match="address"):
        tools["references_list"]("program-1", "invalid")


def test_instructions_list_reports_when_ghidra_advances_to_defined_instruction() -> None:
    from ghidra_mcp.tools.listing import ToolInputError, register_listing_tools

    registry = ToolRegistry()
    register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["instructions_list"]

    assert tool("program-1", address="00400008") == {
        "requested_address": "00400008",
        "effective_address": "00400010",
        "returned_start_address": "00400010",
        "exact_start": False,
        "skipped_bytes": 8,
        "instructions": [
            {
                "address": "00400010",
                "mnemonic": "MOV",
                "operands": ["EAX", "EBX"],
                "length": 2,
            }
        ],
    }
    with pytest.raises(ToolInputError, match="next defined instruction.*00400010"):
        tool("program-1", address="00400008", require_exact_start=True)


def test_instructions_list_does_not_subtract_addresses_from_different_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools.listing import register_listing_tools

    monkeypatch.setattr(FakeAPI, "toAddr", lambda _self, _value: OtherSpaceAddress("00000008"))
    registry = ToolRegistry()
    register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["instructions_list"]

    result = tool("program-1", address="other:00000008")

    assert result["requested_address"] == "00000008"
    assert result["effective_address"] == "00400010"
    assert result["exact_start"] is False
    assert result["skipped_bytes"] is None


def test_listing_page_does_not_consume_past_requested_window() -> None:
    from ghidra_mcp.tools.listing import _page

    def guarded():
        yield "skip"
        yield "first"
        yield "second"
        raise AssertionError("pagination read went past offset + limit")

    assert _page(guarded(), offset=1, limit=2) == ["first", "second"]


def test_references_stop_after_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    from ghidra_mcp.tools.listing import register_listing_tools

    def guarded_from(_self, address):
        yield FakeReference(address, "00400030")
        yield FakeReference(address, "00400034")
        raise AssertionError("reference read went past limit")

    def forbidden_to(_self, _address):
        raise AssertionError("should not read the other direction once there are already enough results")

    monkeypatch.setattr(FakeReferenceManager, "getReferencesFrom", guarded_from)
    monkeypatch.setattr(FakeReferenceManager, "getReferencesTo", forbidden_to)
    registry = ToolRegistry()
    register_listing_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    result = tools["references_list"]("program-1", "00400010", limit=1)
    assert len(result["references"]) == 1
    assert result["truncated"] is True


def test_references_scan_undefined_instructions_for_direct_flows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import listing

    class FakePseudoInstruction:
        def getDefaultFlows(self) -> tuple[FakeAddress, ...]:
            return (FakeAddress("00400010"),)

        def getFlowType(self) -> str:
            return "UNCONDITIONAL_JUMP"

    class FakePseudoDisassembler:
        def disassemble(self, address: FakeAddress) -> FakePseudoInstruction:
            assert str(address) == "00400008"
            return FakePseudoInstruction()

    monkeypatch.setattr(
        listing, "_new_pseudo_disassembler", lambda _program: FakePseudoDisassembler()
    )
    monkeypatch.setattr(
        FakeReferenceManager,
        "getReferencesTo",
        lambda _self, address: [FakeReference("00400004", address)],
    )
    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    result = tool(
        "program-1",
        "00400010",
        direction="to",
        scan_start="00400008",
        scan_end="0040000c",
    )

    assert result["references"] == [
        {
            "from": "00400004",
            "to": "00400010",
            "type": "UNCONDITIONAL_CALL",
            "operand_index": 0,
            "primary": True,
            "direction": "to",
            "provenance": "ghidra_reference_manager",
            "source": "ANALYSIS",
            "confidence": "high",
        },
        {
            "from": "00400008",
            "to": "00400010",
            "type": "UNCONDITIONAL_JUMP",
            "operand_index": -1,
            "primary": False,
            "direction": "to",
            "provenance": "pseudo_disassembly",
            "source": "PSEUDO_DISASSEMBLY",
            "confidence": "inferred",
        },
    ]
    assert result["coverage"] == {
        "mode": "listing_and_pseudo_disassembly",
        "scan": {
            "start": "00400008",
            "end": "0040000c",
            "instruction_alignment": 4,
            "candidate_addresses": 2,
            "scanned_addresses": 2,
            "decoded_instructions": 1,
            "decode_failures": 0,
            "complete": True,
        },
    }
    assert result["incomplete"] is True
    assert result["incomplete_reasons"] == [
        "ghidra_reference_manager_depends_on_defined_listing",
        "pseudo_scan_is_explicit_range_only",
    ]


def test_references_scan_counts_null_decode_as_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import listing

    monkeypatch.setattr(FakeReferenceManager, "getReferencesTo", lambda _self, _address: [])
    monkeypatch.setattr(
        listing,
        "_new_pseudo_disassembler",
        lambda _program: type(
            "NullPseudoDisassembler",
            (),
            {"disassemble": lambda _self, _address: None},
        )(),
    )
    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    result = tool(
        "program-1",
        "00400010",
        direction="to",
        scan_start="00400008",
        scan_end="00400008",
    )

    assert result["references"] == []
    assert result["coverage"]["scan"]["decoded_instructions"] == 0
    assert result["coverage"]["scan"]["decode_failures"] == 1
    assert result["coverage"]["scan"]["complete"] is False


def test_references_scan_rejects_more_than_4096_candidates() -> None:
    from ghidra_mcp.tools import listing
    from ghidra_mcp.tools.navigation import ToolInputError

    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    with pytest.raises(ToolInputError, match="4096"):
        tool(
            "program-1",
            "00400010",
            direction="to",
            scan_start="00400000",
            scan_end="00404000",
        )


def test_references_scan_stops_when_result_limit_is_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import listing

    calls = 0

    class FakePseudoInstruction:
        def getDefaultFlows(self) -> tuple[FakeAddress, ...]:
            return (FakeAddress("00400010"),)

        def getFlowType(self) -> str:
            return "UNCONDITIONAL_JUMP"

    class CountingPseudoDisassembler:
        def disassemble(self, _address: FakeAddress) -> FakePseudoInstruction:
            nonlocal calls
            calls += 1
            return FakePseudoInstruction()

    monkeypatch.setattr(FakeReferenceManager, "getReferencesTo", lambda _self, _address: [])
    monkeypatch.setattr(
        listing,
        "_new_pseudo_disassembler",
        lambda _program: CountingPseudoDisassembler(),
    )
    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    result = tool(
        "program-1",
        "00400010",
        direction="to",
        limit=1,
        scan_start="00400008",
        scan_end="0040000c",
    )

    assert calls == 1
    assert result["truncated"] is True
    assert result["coverage"]["scan"]["scanned_addresses"] == 1
    assert result["coverage"]["scan"]["complete"] is False


def test_references_report_reference_source_without_overstating_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import listing

    computed_instruction = type(
        "ComputedInstruction",
        (),
        {"getFlowType": lambda _self: type("Flow", (), {"isComputed": lambda _self: True})()},
    )()
    monkeypatch.setattr(
        FakeListing,
        "getInstructionContaining",
        lambda _self, _address: computed_instruction,
    )
    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    result = tool("program-1", "00400010", direction="to")

    assert result["references"][0]["provenance"] == "ghidra_reference_manager"
    assert result["references"][0]["source"] == "ANALYSIS"
    assert result["references"][0]["confidence"] == "inferred"


def test_references_scan_skips_instruction_offcuts_and_defined_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import listing

    monkeypatch.setattr(FakeListing, "getInstructionAt", lambda _self, _address: None)
    monkeypatch.setattr(FakeReferenceManager, "getReferencesTo", lambda _self, _address: [])
    monkeypatch.setattr(
        FakeListing,
        "getInstructionContaining",
        lambda _self, address: object() if str(address) == "00400008" else None,
    )
    monkeypatch.setattr(
        FakeListing,
        "getDefinedDataContaining",
        lambda _self, address: object() if str(address) == "0040000c" else None,
    )
    monkeypatch.setattr(
        listing,
        "_new_pseudo_disassembler",
        lambda _program: type(
            "ForbiddenPseudoDisassembler",
            (),
            {"disassemble": lambda _self, _address: pytest.fail("offcut/data must not be decoded")},
        )(),
    )
    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    result = tool(
        "program-1",
        "00400010",
        direction="to",
        scan_start="00400008",
        scan_end="0040000c",
    )

    assert result["coverage"]["scan"]["decoded_instructions"] == 0


def test_references_scan_rejects_unaligned_range() -> None:
    from ghidra_mcp.tools import listing
    from ghidra_mcp.tools.navigation import ToolInputError

    registry = ToolRegistry()
    listing.register_listing_tools(registry, FakeWorkspace())
    tool = {item.name: item.handler for item in registry.enabled_tools()}["references_list"]

    with pytest.raises(ToolInputError, match="alignment"):
        tool(
            "program-1",
            "00400010",
            direction="to",
            scan_start="00400009",
            scan_end="00400010",
        )
