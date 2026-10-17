from dataclasses import dataclass

from ghidra_mcp.registry import ToolRegistry


@dataclass
class FakeData:
    address: str = "00401000"

    def getAddress(self):
        return self.address

    def getLength(self):
        return 4

    def getDataType(self):
        return "dword"

    def getDefaultValueRepresentation(self):
        return "0x1234"


@dataclass
class FakeVariable:
    name: str
    parameter: bool

    def getName(self):
        return self.name

    def getDataType(self):
        return "int"

    def getVariableStorage(self):
        return "Stack[0x4]"

    def isParameter(self):
        return self.parameter

    def getComment(self):
        return None


class FakeTag:
    def getName(self):
        return "reviewed"

    def getComment(self):
        return "checked"


class FakeFunction:
    def getName(self):
        return "worker"

    def getEntryPoint(self):
        return "00400010"

    def getBody(self):
        return {"00400010"}

    def getAllVariables(self):
        return [FakeVariable("arg1", True), FakeVariable("local_4", False)]

    def getTags(self):
        return [FakeTag()]


class FakeInstruction:
    def getAddress(self):
        return "00400010"

    def getPcode(self):
        return ["COPY r0, 1", "RETURN r0"]


class FakeDataType:
    def getName(self):
        return "dword"

    def getPathName(self):
        return "/dword"

    def getLength(self):
        return 4

    def getDescription(self):
        return "32-bit value"


class FakeDataTypeManager:
    def getAllDataTypes(self):
        return [FakeDataType()]


class FakeListing:
    def getDefinedData(self, forward):
        assert forward is True
        return [FakeData()]

    def getDefinedDataContaining(self, address):
        return FakeData() if address == "00401000" else None

    def getCommentAddressIterator(self, memory, forward):
        assert forward is True
        return ["00400010"]

    def getComment(self, kind, address):
        return "entry note" if kind == "EOL" and address == "00400010" else None

    def getInstructions(self, body, forward):
        return [FakeInstruction()]


class FakeBookmark:
    def getAddress(self):
        return "00400010"

    def getTypeString(self):
        return "Analysis"

    def getCategory(self):
        return "Review"

    def getComment(self):
        return "inspect"


class FakeBookmarkManager:
    def getBookmarksIterator(self):
        return [FakeBookmark()]


class FakeProgram:
    def getListing(self):
        return FakeListing()

    def getMemory(self):
        return "memory"

    def getDataTypeManager(self):
        return FakeDataTypeManager()

    def getBookmarkManager(self):
        return FakeBookmarkManager()


class FakeAPI:
    def getCurrentProgram(self):
        return FakeProgram()

    def toAddr(self, address):
        return address if address.startswith("0040") else None

    def getFunctionContaining(self, address):
        return FakeFunction() if address == "00400010" else None


class FakeWorkspace:
    def get(self, program_id):
        assert program_id == "program-1"
        return FakeAPI()


def test_inspection_tools_return_data_comments_variables_pcode_types_tags_and_bookmarks(
    monkeypatch,
):
    from ghidra_mcp.tools import inspection

    monkeypatch.setattr(inspection, "_comment_types", lambda: {"eol": "EOL", "plate": "PLATE"})
    monkeypatch.setattr(inspection, "_is_parameter", lambda variable: variable.parameter)
    registry = ToolRegistry()
    inspection.register_inspection_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert list(tools) == [
        "data_list",
        "data_get",
        "comments_list",
        "variables_list",
        "pcode_list",
        "data_types_list",
        "function_tags",
        "bookmarks_list",
    ]
    assert tools["data_list"]("program-1")[0]["data_type"] == "dword"
    assert tools["data_get"]("program-1", "00401000")["value"] == "0x1234"
    assert tools["comments_list"]("program-1") == [
        {"address": "00400010", "kind": "eol", "text": "entry note"}
    ]
    assert [item["role"] for item in tools["variables_list"]("program-1", "00400010")] == [
        "parameter",
        "local",
    ]
    assert tools["pcode_list"]("program-1", "00400010")[0]["ops"] == ["COPY r0, 1", "RETURN r0"]
    assert tools["data_types_list"]("program-1")[0]["path"] == "/dword"
    assert tools["function_tags"]("program-1", "00400010") == [
        {"name": "reviewed", "comment": "checked"}
    ]
    assert tools["bookmarks_list"]("program-1")[0]["category"] == "Review"


def test_inspection_page_does_not_consume_past_requested_window():
    from ghidra_mcp.tools.inspection import _page

    def guarded():
        yield "skip"
        yield "first"
        raise AssertionError("pagination read went past offset + limit")

    assert _page(guarded(), 1, 1) == ["first"]


def test_comments_and_pcode_stop_after_limit(monkeypatch):
    from ghidra_mcp.tools import inspection

    def guarded_addresses(_self, _memory, _forward):
        yield "00400010"
        raise AssertionError("comment read went past limit")

    def guarded_instructions(_self, _body, _forward):
        yield FakeInstruction()
        raise AssertionError("P-code read went past limit")

    monkeypatch.setattr(FakeListing, "getCommentAddressIterator", guarded_addresses)
    monkeypatch.setattr(FakeListing, "getInstructions", guarded_instructions)
    monkeypatch.setattr(inspection, "_comment_types", lambda: {"eol": "EOL"})
    monkeypatch.setattr(inspection, "_is_parameter", lambda variable: variable.parameter)
    registry = ToolRegistry()
    inspection.register_inspection_tools(registry, FakeWorkspace())
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    assert len(tools["comments_list"]("program-1", limit=1)) == 1
    assert len(tools["pcode_list"]("program-1", "00400010", limit=1)) == 1
