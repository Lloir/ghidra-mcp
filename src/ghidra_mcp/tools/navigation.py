"""Read-only navigation tools for memory and functions."""

from itertools import islice
from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace


class ToolInputError(ValueError):
    """Tool input could not be parsed or exceeds a public boundary."""


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"could not resolve address: {value}")
    return address


def _function_json(function: Any) -> dict[str, object]:
    return {
        "name": str(function.getName()),
        "entry_point": str(function.getEntryPoint()),
        "signature": str(function.getSignature()),
        "external": bool(function.isExternal()),
        "thunk": bool(function.isThunk()),
    }


def register_navigation_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def memory_blocks_list(program_id: str) -> list[dict[str, object]]:
        memory = workspace.get(program_id).getCurrentProgram().getMemory()
        return [
            {
                "name": str(block.getName()),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "initialized": bool(block.isInitialized()),
            }
            for block in memory.getBlocks()
        ]

    def memory_read(
        program_id: str,
        address: str,
        length: int,
        interpret: bool = False,
        unit_size: int = 8,
        byte_order: str = "little",
    ) -> dict[str, object]:
        if not 1 <= length <= 1_048_576:
            raise ToolInputError("length must be between 1 and 1048576")
        if unit_size not in {1, 2, 4, 8}:
            raise ToolInputError("unit_size must be 1, 2, 4, or 8")
        if byte_order not in {"little", "big"}:
            raise ToolInputError("byte_order must be little or big")
        if interpret and length > 4096:
            raise ToolInputError("length must not exceed 4096 for interpreted memory_read")
        api = workspace.get(program_id)
        resolved = _address(api, address)
        data = bytes((int(value) & 0xFF) for value in api.getBytes(resolved, length))
        result: dict[str, object] = {
            "address": str(resolved),
            "length": len(data),
            "hex": data.hex(),
        }
        if not interpret:
            return result
        complete_length = len(data) - (len(data) % unit_size)
        result.update(
            {
                "ascii": "".join(chr(value) if 32 <= value < 127 else "." for value in data),
                "unit_size": unit_size,
                "byte_order": byte_order,
                "unsigned_values": [
                    int.from_bytes(data[offset : offset + unit_size], byte_order)
                    for offset in range(0, complete_length, unit_size)
                ],
                "trailing_hex": data[complete_length:].hex(),
            }
        )
        return result

    def functions_list(
        program_id: str, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        if offset < 0:
            raise ToolInputError("offset must not be less than 0")
        if not 1 <= limit <= 1000:
            raise ToolInputError("limit must be between 1 and 1000")
        program = workspace.get(program_id).getCurrentProgram()
        functions = program.getFunctionManager().getFunctions(True)
        return [_function_json(function) for function in islice(functions, offset, offset + limit)]

    def function_get(program_id: str, address: str) -> dict[str, object]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionContaining(resolved)
        if function is None:
            return {
                "requested_address": str(resolved),
                "resolution": "unassigned",
                "function": None,
                "reason": "address_not_in_ghidra_function_body",
            }
        return {
            "requested_address": str(resolved),
            "resolution": "contained",
            "function": _function_json(function),
            "reason": None,
        }

    definitions = (
        ToolDefinition(
            "memory_blocks_list",
            """List all of a program's memory blocks and their access attributes.

Inputs/outputs and side effects: takes a program session id; returns block name, address range, size, and read/write/execute attributes; read-only.

When to use: call to determine code/data layout or choose a read range; use memory_read to read actual bytes.
""",
            memory_blocks_list,
        ),
        ToolDefinition(
            "memory_read",
            """Read a bounded sequence of bytes from program memory.

Inputs/outputs and side effects: takes a program session id, address, and length; returns hex bytes by default; optionally interprets up to 4096 bytes as ASCII and 1/2/4/8-byte unsigned values in the given byte order; read-only, raw reads capped at 1 MiB.

When to use: call when you need raw bytes, string clues, integer or pointer candidates; use memory_blocks_list if you only need to see memory layout, and instructions_list for machine instructions.
""",
            memory_read,
        ),
        ToolDefinition(
            "functions_list",
            """List defined functions in address order, paginated.

Inputs/outputs and side effects: takes a program session id, offset, and count; returns name, entry point, signature, and external/thunk attributes; read-only.

When to use: call to browse the function set or find candidate targets; use function_get instead if you already know an address inside a function and need its details.
""",
            functions_list,
        ),
        ToolDefinition(
            "function_get",
            """Read details of the function containing a given address.

Inputs/outputs and side effects: takes a program session id and address; returns a "contained" or "unassigned" resolution status, including function details on a hit, and clearly stating the address is not in a Ghidra function body on a miss; read-only.

When to use: call when you know an address and need the function it belongs to; use functions_list when you need to enumerate or page through functions.
            """,
            function_get,
            contract_version=2,
        ),
    )
    for definition in definitions:
        registry.register(definition)
