"""Transactional write tools for functions, symbols, and comments."""

from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from ..transaction import program_transaction
from .navigation import ToolInputError


def _user_defined_source() -> Any:
    from ghidra.program.model.symbol import SourceType

    return SourceType.USER_DEFINED


def _comment_type(value: str) -> Any:
    from ghidra.program.model.listing import CommentType

    try:
        return getattr(CommentType, value.upper())
    except AttributeError as error:
        raise ToolInputError("kind must be eol, pre, post, plate, or repeatable") from error


def _address_set(start: Any, end: Any) -> Any:
    from ghidra.program.model.address import AddressSet

    return AddressSet(start, end)


def _body_ranges(body: Any) -> list[dict[str, str]]:
    return [
        {"start": str(address_range.getMinAddress()), "end": str(address_range.getMaxAddress())}
        for address_range in body.getAddressRanges()
    ]


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"could not resolve address: {value}")
    return address


def _name(value: str) -> str:
    name = value.strip()
    if not name:
        raise ToolInputError("name must not be empty")
    return name


def register_write_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def function_rename(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionContaining(resolved)
        if function is None:
            raise ToolInputError(f"address is not contained in a function: {address}")
        program = api.getCurrentProgram()
        old_name = str(function.getName())
        new_name = _name(name)
        with program_transaction(
            program, "Rename function", persist=lambda: workspace.save(program_id)
        ):
            function.setName(new_name, _user_defined_source())
        return {
            "entry_point": str(function.getEntryPoint()),
            "old_name": old_name,
            "name": new_name,
        }

    def symbol_rename(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        symbol = program.getSymbolTable().getPrimarySymbol(resolved)
        if symbol is None:
            raise ToolInputError(f"address has no primary symbol: {address}")
        old_name = str(symbol.getName())
        new_name = _name(name)
        with program_transaction(
            program, "Rename symbol", persist=lambda: workspace.save(program_id)
        ):
            symbol.setName(new_name, _user_defined_source())
        return {
            "address": str(symbol.getAddress()),
            "old_name": old_name,
            "name": new_name,
        }

    def comment_set(
        program_id: str, address: str, kind: str, text: str | None
    ) -> dict[str, str | None]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        normalized_kind = kind.lower()
        comment_type = _comment_type(normalized_kind)
        with program_transaction(
            program, "Set comment", persist=lambda: workspace.save(program_id)
        ):
            program.getListing().setComment(resolved, comment_type, text)
        return {"address": str(resolved), "kind": normalized_kind, "text": text}

    def function_create(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        if api.getFunctionAt(resolved) is not None:
            raise ToolInputError(f"address already has a function: {address}")
        program = api.getCurrentProgram()
        new_name = _name(name)
        with program_transaction(
            program, "Create function", persist=lambda: workspace.save(program_id)
        ):
            function = api.createFunction(resolved, new_name)
            if function is None:
                raise RuntimeError(f"Ghidra failed to create a function at {address}")
        return {"name": str(function.getName()), "entry_point": str(function.getEntryPoint())}

    def function_delete(program_id: str, address: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionAt(resolved)
        if function is None:
            raise ToolInputError(f"address is not a function entry point: {address}")
        entry_point = str(function.getEntryPoint())
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Delete function", persist=lambda: workspace.save(program_id)
        ):
            api.removeFunction(function)
        return {"deleted": entry_point}

    def function_body_add(
        program_id: str, entry_point: str, start: str, end: str
    ) -> dict[str, object]:
        api = workspace.get(program_id)
        resolved_entry = _address(api, entry_point)
        resolved_start = _address(api, start)
        resolved_end = _address(api, end)
        if resolved_start.compareTo(resolved_end) > 0:
            raise ToolInputError("start must not be greater than end")
        function = api.getFunctionAt(resolved_entry)
        if function is None:
            raise ToolInputError(f"address is not a function entry point: {entry_point}")
        previous_body = function.getBody()
        previous_ranges = _body_ranges(previous_body)
        new_body = previous_body.union(_address_set(resolved_start, resolved_end))
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Add function body range", persist=lambda: workspace.save(program_id)
        ):
            function.setBody(new_body)
        return {
            "entry_point": str(function.getEntryPoint()),
            "added_range": {"start": str(resolved_start), "end": str(resolved_end)},
            "previous_body_ranges": previous_ranges,
            "body_ranges": _body_ranges(function.getBody()),
        }

    definitions = (
        ToolDefinition(
            "function_rename",
            """Rename the function containing a given address.

Inputs/outputs and side effects: takes a program session, an address inside a function, and the new name; returns the entry point and old/new names; modifies within a single Ghidra transaction, rolling back on failure.

When to use: use once you've confirmed a function's semantics and want to give it a stable name; use symbol_rename if you only need to change a non-function label.
""",
            function_rename,
        ),
        ToolDefinition(
            "symbol_rename",
            """Rename the primary symbol at a given address.

Inputs/outputs and side effects: takes a program session, a symbol address, and the new name; returns the address and old/new names; modifies within a single transaction, rolling back on failure.

When to use: use to change a label, data, or external symbol's name; prefer function_rename when the target is a function's semantic name.
""",
            symbol_rename,
        ),
        ToolDefinition(
            "comment_set",
            """Set or delete one kind of comment at a given address.

Inputs/outputs and side effects: takes a program session, address, comment kind, and text; returns what was written, deleting the comment when text is null; the transaction rolls back automatically on failure.

When to use: use to save verifiable analysis conclusions; use function_rename or symbol_rename when renaming an entity instead.
""",
            comment_set,
        ),
        ToolDefinition(
            "function_create",
            """Create a named function at an entry address that does not yet have one.

Inputs/outputs and side effects: takes a program session, entry address, and name; returns the new function's name and entry point; the transaction rolls back automatically on failure.

When to use: call when analysis missed a confirmed code entry point; use function_rename if the entry already has a function.
""",
            function_create,
        ),
        ToolDefinition(
            "function_delete",
            """Delete the function definition whose entry point exactly matches the given address.

Inputs/outputs and side effects: takes a program session and a function entry point; returns the deleted entry point; the transaction rolls back automatically on failure, and the underlying bytes are not deleted.

When to use: call when a function definition is confirmed wrong or misidentified; do not delete just to rename — use function_rename for that.
""",
            function_delete,
        ),
        ToolDefinition(
            "function_body_add",
            """Add one confirmed address range to the body of the function whose entry point exactly matches the given address.

Inputs/outputs and side effects: takes a program session, a function entry point, and an inclusive start/end address range; returns the added range plus the function's body ranges before and after; modifies and saves within a single transaction, and Ghidra rejects (rolling back) a range that overlaps another function.

When to use: call once control-flow evidence confirms a detached continuation belongs to the target function; use function_get first when attribution is still uncertain — never guess from a nearby address.
""",
            function_body_add,
        ),
    )
    for definition in definitions:
        registry.register(definition)
