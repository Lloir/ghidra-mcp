"""Search, analysis, and classification write tools."""

from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from ..transaction import program_transaction
from .navigation import ToolInputError


def _address(api: Any, value: str) -> Any:
    resolved = api.toAddr(value)
    if resolved is None:
        raise ToolInputError(f"could not resolve address: {value}")
    return resolved


def _data_type(program: Any, path: str) -> Any:
    value = program.getDataTypeManager().getDataType(path)
    if value is None:
        raise ToolInputError(f"data type does not exist: {path}")
    return value


def _data_type_json(value: Any) -> dict[str, object]:
    return {
        "name": str(value.getName()),
        "path": str(value.getPathName()),
        "length": int(value.getLength()),
        "description": str(value.getDescription()),
    }


def register_operation_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def memory_search(program_id: str, hex_pattern: str, max_results: int = 100) -> list[str]:
        try:
            pattern = bytes.fromhex(hex_pattern)
        except ValueError as error:
            raise ToolInputError("hex_pattern must be an even number of hex digits") from error
        if not pattern or len(pattern) > 4096:
            raise ToolInputError("hex pattern length must be between 1 and 4096 bytes")
        if not 1 <= max_results <= 1000:
            raise ToolInputError("max_results must be between 1 and 1000")
        api = workspace.get(program_id)
        results: list[str] = []
        scanned = 0
        scan_limit = 64 * 1024 * 1024
        chunk_size = 1024 * 1024
        for block in api.getCurrentProgram().getMemory().getBlocks():
            if not block.isInitialized():
                continue
            offset = 0
            carry = b""
            size = int(block.getSize())
            while offset < size and scanned < scan_limit:
                length = min(chunk_size, size - offset, scan_limit - scanned)
                raw = bytes(
                    (int(item) & 0xFF)
                    for item in api.getBytes(block.getStart().add(offset), length)
                )
                data = carry + raw
                cursor = 0
                while (found := data.find(pattern, cursor)) >= 0:
                    absolute = offset - len(carry) + found
                    results.append(str(block.getStart().add(absolute)))
                    if len(results) >= max_results:
                        return results
                    cursor = found + 1
                carry = data[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
                offset += length
                scanned += length
        return results

    def analysis_run(program_id: str) -> dict[str, int]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        manager = program.getFunctionManager()
        before = int(manager.getFunctionCount())
        with program_transaction(
            program, "Run analysis", persist=lambda: workspace.save(program_id)
        ):
            workspace.analyze(program_id)
        return {"functions_before": before, "functions_after": int(manager.getFunctionCount())}

    def data_type_get(program_id: str, path: str) -> dict[str, object]:
        program = workspace.get(program_id).getCurrentProgram()
        return _data_type_json(_data_type(program, path))

    def data_type_apply(program_id: str, address: str, path: str) -> dict[str, object]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        resolved = _address(api, address)
        value = _data_type(program, path)
        with program_transaction(
            program, "Apply data type", persist=lambda: workspace.save(program_id)
        ):
            data = program.getListing().createData(resolved, value)
        return {
            "address": str(data.getAddress()),
            "length": int(data.getLength()),
            "data_type": str(data.getDataType()),
        }

    def function_tag_update(
        program_id: str, address: str, action: str, name: str
    ) -> dict[str, object]:
        if action not in {"add", "remove"}:
            raise ToolInputError("action must be add or remove")
        normalized = name.strip()
        if not normalized:
            raise ToolInputError("name must not be empty")
        api = workspace.get(program_id)
        function = api.getFunctionContaining(_address(api, address))
        if function is None:
            raise ToolInputError(f"address is not contained in a function: {address}")
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Update function tag", persist=lambda: workspace.save(program_id)
        ):
            if action == "add":
                function.addTag(normalized)
            else:
                function.removeTag(normalized)
        tags = sorted(function.getTags(), key=lambda item: str(item.getName()))
        return {
            "tags": [{"name": str(tag.getName()), "comment": str(tag.getComment())} for tag in tags]
        }

    def bookmark_set(
        program_id: str, address: str, kind: str, category: str, comment: str | None
    ) -> dict[str, str | None]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        resolved = _address(api, address)
        manager = program.getBookmarkManager()
        with program_transaction(
            program, "Set bookmark", persist=lambda: workspace.save(program_id)
        ):
            if comment is None:
                existing = manager.getBookmark(resolved, kind, category)
                if existing is not None:
                    manager.removeBookmark(existing)
            else:
                manager.setBookmark(resolved, kind, category, comment)
        return {"address": str(resolved), "type": kind, "category": category, "comment": comment}

    definitions = (
        ToolDefinition(
            "memory_search",
            """Search initialized memory for an exact byte pattern.\n\nInputs/outputs and side effects: takes a program session, a hex pattern, and a result cap; returns matching addresses, scanning at most 64 MiB per call; read-only.\n\nWhen to use: call to locate addresses by machine code, constants, or file signatures; use memory_read to read content at a known address, and strings_list for textual clues.\n""",
            memory_search,
        ),
        ToolDefinition(
            "analysis_run",
            """Synchronously run Ghidra auto-analysis on an already-open program.\n\nInputs/outputs and side effects: takes a program session; returns the function count before and after; runs within the configured time limit, rolling back this analysis pass on timeout or persistence failure.\n\nWhen to use: call to analyze after opening with analyze=false, or to re-analyze after modifying definitions; on first open, let program_open run analysis directly instead.\n""",
            analysis_run,
        ),
        ToolDefinition(
            "data_type_get",
            """Read a data type by its full path.\n\nInputs/outputs and side effects: takes a program session and a type path; returns name, path, length, and description; read-only.\n\nWhen to use: use to confirm a type's exact definition before applying it; use data_types_list to discover candidate types by fragment.\n""",
            data_type_get,
        ),
        ToolDefinition(
            "data_type_apply",
            """Create an existing data type definition at a given address.\n\nInputs/outputs and side effects: takes a program session, address, and full type path; returns the created data definition; the transaction rolls back automatically on failure and does not proactively clear conflicting code units.\n\nWhen to use: call once the address and type are confirmed and no conflicting definition exists; find the type first with data_types_list, and check the existing definition with data_get.\n""",
            data_type_apply,
        ),
        ToolDefinition(
            "function_tag_update",
            """Precisely add or remove a function tag.\n\nInputs/outputs and side effects: takes a program session, an address inside a function, add/remove, and the exact tag name; returns the updated tags; the transaction rolls back automatically on failure.\n\nWhen to use: call to maintain objective function classification; read tags with function_tags, and rename a function with function_rename.\n""",
            function_tag_update,
        ),
        ToolDefinition(
            "bookmark_set",
            """Set or delete a bookmark at a given address.\n\nInputs/outputs and side effects: takes a program session, address, type, category, and comment; a null comment deletes the exact matching bookmark; the transaction rolls back automatically on failure.\n\nWhen to use: call to record to-dos or review anchors; use comment_set to save analysis findings in the program body.\n""",
            bookmark_set,
        ),
    )
    for definition in definitions:
        registry.register(definition)
