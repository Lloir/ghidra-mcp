"""Read-only inspection tools for data, comments, variables, P-code, and bookmarks."""

from itertools import islice
from typing import Any, Iterable

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from .navigation import ToolInputError


def _page(values: Iterable[Any], offset: int, limit: int) -> list[Any]:
    if offset < 0 or not 1 <= limit <= 1000:
        raise ToolInputError("offset must not be less than 0, and limit must be between 1 and 1000")
    return list(islice(values, offset, offset + limit))


def _address(api: Any, value: str) -> Any:
    resolved = api.toAddr(value)
    if resolved is None:
        raise ToolInputError(f"could not resolve address: {value}")
    return resolved


def _function(api: Any, value: str) -> Any:
    function = api.getFunctionContaining(_address(api, value))
    if function is None:
        raise ToolInputError(f"address is not contained in a function: {value}")
    return function


def _data_json(data: Any) -> dict[str, object]:
    return {
        "address": str(data.getAddress()),
        "length": int(data.getLength()),
        "data_type": str(data.getDataType()),
        "value": str(data.getDefaultValueRepresentation()),
    }


def _comment_types() -> dict[str, Any]:
    from ghidra.program.model.listing import CommentType

    return {
        "eol": CommentType.EOL,
        "pre": CommentType.PRE,
        "post": CommentType.POST,
        "plate": CommentType.PLATE,
        "repeatable": CommentType.REPEATABLE,
    }


def _is_parameter(variable: Any) -> bool:
    from ghidra.program.model.listing import Parameter

    return isinstance(variable, Parameter)


def register_inspection_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def data_list(
        program_id: str, contains_type: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        values = workspace.get(program_id).getCurrentProgram().getListing().getDefinedData(True)
        if contains_type is not None:
            needle = contains_type.casefold()
            values = (item for item in values if needle in str(item.getDataType()).casefold())
        return [_data_json(item) for item in _page(values, offset, limit)]

    def data_get(program_id: str, address: str) -> dict[str, object]:
        api = workspace.get(program_id)
        data = api.getCurrentProgram().getListing().getDefinedDataContaining(_address(api, address))
        if data is None:
            raise ToolInputError(f"no defined data at address: {address}")
        return _data_json(data)

    def comments_list(program_id: str, offset: int = 0, limit: int = 100) -> list[dict[str, str]]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        listing = program.getListing()
        addresses = listing.getCommentAddressIterator(program.getMemory(), True)

        def comments() -> Iterable[dict[str, str]]:
            for address in addresses:
                for name, kind in _comment_types().items():
                    text = listing.getComment(kind, address)
                    if text is not None:
                        yield {"address": str(address), "kind": name, "text": str(text)}

        return _page(comments(), offset, limit)

    def variables_list(program_id: str, address: str) -> list[dict[str, object]]:
        api = workspace.get(program_id)
        return [
            {
                "name": str(variable.getName()),
                "data_type": str(variable.getDataType()),
                "storage": str(variable.getVariableStorage()),
                "role": "parameter" if _is_parameter(variable) else "local",
                "comment": None if variable.getComment() is None else str(variable.getComment()),
            }
            for variable in _function(api, address).getAllVariables()
        ]

    def pcode_list(program_id: str, address: str, limit: int = 1000) -> list[dict[str, object]]:
        if not 1 <= limit <= 10_000:
            raise ToolInputError("limit must be between 1 and 10000")
        api = workspace.get(program_id)
        function = _function(api, address)
        instructions = (
            api.getCurrentProgram().getListing().getInstructions(function.getBody(), True)
        )
        return [
            {
                "address": str(instruction.getAddress()),
                "ops": [str(op) for op in instruction.getPcode()],
            }
            for instruction in islice(instructions, limit)
        ]

    def data_types_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        values = (
            workspace.get(program_id).getCurrentProgram().getDataTypeManager().getAllDataTypes()
        )
        if contains is not None:
            needle = contains.casefold()
            values = (item for item in values if needle in str(item.getPathName()).casefold())
        return [
            {
                "name": str(item.getName()),
                "path": str(item.getPathName()),
                "length": int(item.getLength()),
                "description": str(item.getDescription()),
            }
            for item in _page(values, offset, limit)
        ]

    def function_tags(program_id: str, address: str) -> list[dict[str, str]]:
        api = workspace.get(program_id)
        tags = sorted(_function(api, address).getTags(), key=lambda item: str(item.getName()))
        return [{"name": str(tag.getName()), "comment": str(tag.getComment())} for tag in tags]

    def bookmarks_list(program_id: str, offset: int = 0, limit: int = 100) -> list[dict[str, str]]:
        values = (
            workspace.get(program_id)
            .getCurrentProgram()
            .getBookmarkManager()
            .getBookmarksIterator()
        )
        return [
            {
                "address": str(item.getAddress()),
                "type": str(item.getTypeString()),
                "category": str(item.getCategory()),
                "comment": str(item.getComment()),
            }
            for item in _page(values, offset, limit)
        ]

    definitions = (
        ToolDefinition(
            "data_list",
            """List defined data, paginated, optionally filtered by type.\n\nInputs/outputs and side effects: takes a program session, an optional type fragment, and pagination parameters; returns address, length, type, and value; read-only.\n\nWhen to use: call to browse structured data definitions; use strings_list if you only need strings, and memory_read to read raw bytes.\n""",
            data_list,
        ),
        ToolDefinition(
            "data_get",
            """Read the defined data containing a given address.\n\nInputs/outputs and side effects: takes a program session and address; returns the data's start, length, type, and value; read-only.\n\nWhen to use: call when you know an address inside data and need its full definition; use data_list when browsing in bulk.\n""",
            data_get,
        ),
        ToolDefinition(
            "comments_list",
            """List all standard comments in the program, paginated.\n\nInputs/outputs and side effects: takes a program session and pagination parameters; returns address, comment kind, and text; read-only.\n\nWhen to use: call to recover existing analysis notes; use comment_set to add or remove comments.\n""",
            comments_list,
        ),
        ToolDefinition(
            "variables_list",
            """List a function's parameters and local variables.\n\nInputs/outputs and side effects: takes a program session and an address inside a function; returns name, type, storage, role, and comment; read-only.\n\nWhen to use: call to inspect a function's prototype and local state; use function_get for function-level identity information.\n""",
            variables_list,
        ),
        ToolDefinition(
            "pcode_list",
            """Read the Ghidra P-code for a function's instructions.\n\nInputs/outputs and side effects: takes a program session, an address inside a function, and an instruction cap; returns each instruction's address and P-code ops; read-only.\n\nWhen to use: call for architecture-independent semantic analysis; use decompile_function for high-level C text, and instructions_list for machine instructions.\n""",
            pcode_list,
        ),
        ToolDefinition(
            "data_types_list",
            """List program data types, paginated, optionally filtered by path.\n\nInputs/outputs and side effects: takes a program session, an optional path fragment, and pagination parameters; returns name, path, length, and description; read-only.\n\nWhen to use: call to find an existing type to apply; use data_get to see the current data definition at an address.\n""",
            data_types_list,
        ),
        ToolDefinition(
            "function_tags",
            """List the tags currently assigned to a function.\n\nInputs/outputs and side effects: takes a program session and an address inside a function; returns tag names and descriptions; read-only.\n\nWhen to use: call to read a function's classification state; use function_get for the meaning of the name itself.\n""",
            function_tags,
        ),
        ToolDefinition(
            "bookmarks_list",
            """List program bookmarks, paginated.\n\nInputs/outputs and side effects: takes a program session and pagination parameters; returns address, type, category, and description; read-only.\n\nWhen to use: call to browse manually marked to-dos and points of interest; use comments_list for analysis notes in the program itself.\n""",
            bookmarks_list,
        ),
    )
    for definition in definitions:
        registry.register(definition)
