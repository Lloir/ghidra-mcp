"""Read-only tools for instructions, symbols, references, and strings."""

from itertools import chain, islice
from typing import Any, Iterable

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from .navigation import ToolInputError


def _page(values: Iterable[Any], *, offset: int, limit: int) -> list[Any]:
    if offset < 0:
        raise ToolInputError("offset must not be less than 0")
    if not 1 <= limit <= 1000:
        raise ToolInputError("limit must be between 1 and 1000")
    return list(islice(values, offset, offset + limit))


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"could not resolve address: {value}")
    return address


def _reference_json(reference: Any, direction: str, listing: Any) -> dict[str, object]:
    source_instruction = listing.getInstructionContaining(reference.getFromAddress())
    inferred = bool(
        source_instruction is not None
        and source_instruction.getFlowType().isComputed()
        and reference.getReferenceType().isFlow()
    )
    return {
        "from": str(reference.getFromAddress()),
        "to": str(reference.getToAddress()),
        "type": str(reference.getReferenceType()),
        "operand_index": int(reference.getOperandIndex()),
        "primary": bool(reference.isPrimary()),
        "direction": direction,
        "provenance": "ghidra_reference_manager",
        "source": str(reference.getSource()),
        "confidence": "inferred" if inferred else "high",
    }


def _new_pseudo_disassembler(program: Any) -> Any:
    from ghidra.app.util import PseudoDisassembler

    return PseudoDisassembler(program)


def register_listing_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def instructions_list(
        program_id: str,
        address: str | None = None,
        offset: int = 0,
        limit: int = 100,
        require_exact_start: bool = False,
    ) -> dict[str, object]:
        api = workspace.get(program_id)
        listing = api.getCurrentProgram().getListing()
        requested = None if address is None else _address(api, address)
        iterator = iter(
            listing.getInstructions(True)
            if requested is None
            else listing.getInstructions(requested, True)
        )
        first = next(iterator, None)
        effective = None if first is None else first.getAddress()
        exact_start = None if requested is None else effective == requested
        skipped_bytes = (
            None
            if requested is None
            or effective is None
            or effective.getAddressSpace() != requested.getAddressSpace()
            else int(effective.subtract(requested))
        )
        if require_exact_start and exact_start is not True:
            next_address = "none" if effective is None else str(effective)
            raise ToolInputError(
                f"requested address is not a defined instruction start; "
                f"next defined instruction: {next_address}"
            )
        instructions = _page(
            () if first is None else chain((first,), iterator), offset=offset, limit=limit
        )
        instruction_json = [
            {
                "address": str(instruction.getAddress()),
                "mnemonic": str(instruction.getMnemonicString()),
                "operands": [
                    str(instruction.getDefaultOperandRepresentation(index))
                    for index in range(instruction.getNumOperands())
                ],
                "length": int(instruction.getLength()),
            }
            for instruction in instructions
        ]
        return {
            "requested_address": None if requested is None else str(requested),
            "effective_address": None if effective is None else str(effective),
            "returned_start_address": (
                None if not instructions else str(instructions[0].getAddress())
            ),
            "exact_start": exact_start,
            "skipped_bytes": skipped_bytes,
            "instructions": instruction_json,
        }

    def symbols_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        program = workspace.get(program_id).getCurrentProgram()
        symbols = program.getSymbolTable().getAllSymbols(True)
        if contains is not None:
            symbols = (symbol for symbol in symbols if contains in str(symbol.getName()))
        return [
            {
                "name": str(symbol.getName()),
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource()),
                "primary": bool(symbol.isPrimary()),
            }
            for symbol in _page(symbols, offset=offset, limit=limit)
        ]

    def references_list(
        program_id: str,
        address: str,
        direction: str = "both",
        limit: int = 100,
        scan_start: str | None = None,
        scan_end: str | None = None,
    ) -> dict[str, object]:
        if direction not in {"from", "to", "both"}:
            raise ToolInputError("direction must be from, to, or both")
        if not 1 <= limit <= 1000:
            raise ToolInputError("limit must be between 1 and 1000")
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        manager = program.getReferenceManager()
        listing = program.getListing()

        def references() -> Iterable[dict[str, object]]:
            if direction in {"from", "both"}:
                for reference in manager.getReferencesFrom(resolved):
                    yield _reference_json(reference, "from", listing)
            if direction in {"to", "both"}:
                for reference in manager.getReferencesTo(resolved):
                    yield _reference_json(reference, "to", listing)

        found = list(islice(references(), limit + 1))
        truncated = len(found) > limit
        found = found[:limit]
        scan = None
        if (scan_start is None) != (scan_end is None):
            raise ToolInputError("scan_start and scan_end must both be provided or both omitted")
        if scan_start is not None and direction == "from":
            raise ToolInputError("pseudo-disassembly scanning is only for the to or both directions")
        if scan_start is not None and scan_end is not None:
            start = _address(api, scan_start)
            end = _address(api, scan_end)
            if start.getAddressSpace() != end.getAddressSpace() or end.subtract(start) < 0:
                raise ToolInputError(
                    "the scan range must be in the same address space and scan_end must not be "
                    "less than scan_start"
                )
            alignment = int(program.getLanguage().getInstructionAlignment())
            if start.getOffset() % alignment or end.getOffset() % alignment:
                raise ToolInputError(
                    "scan_start and scan_end must satisfy the language's instruction alignment"
                )
            candidate_count = int(end.subtract(start)) // alignment + 1
            if candidate_count > 4_096:
                raise ToolInputError(
                    "the scan range may contain at most 4096 aligned addresses; "
                    "query a larger range in chunks"
                )
            pseudo = _new_pseudo_disassembler(program)
            existing_pairs = {(item["from"], item["to"]) for item in found}
            decoded = 0
            failures = 0
            scanned = 0
            for index in range(candidate_count):
                if len(found) >= limit:
                    truncated = True
                    break
                candidate = start.add(index * alignment)
                scanned += 1
                if (
                    listing.getInstructionContaining(candidate) is not None
                    or listing.getDefinedDataContaining(candidate) is not None
                ):
                    continue
                try:
                    instruction = pseudo.disassemble(candidate)
                except Exception:
                    failures += 1
                    continue
                if instruction is None:
                    failures += 1
                    continue
                decoded += 1
                if direction not in {"to", "both"}:
                    continue
                flows = instruction.getDefaultFlows() or ()
                if resolved not in flows:
                    continue
                pair = (str(candidate), str(resolved))
                if pair in existing_pairs:
                    continue
                existing_pairs.add(pair)
                found.append(
                    {
                        "from": pair[0],
                        "to": pair[1],
                        "type": str(instruction.getFlowType()),
                        "operand_index": -1,
                        "primary": False,
                        "direction": "to",
                        "provenance": "pseudo_disassembly",
                        "source": "PSEUDO_DISASSEMBLY",
                        "confidence": "inferred",
                    }
                )
            if len(found) > limit:
                truncated = True
                found = found[:limit]
            scan = {
                "start": str(start),
                "end": str(end),
                "instruction_alignment": alignment,
                "candidate_addresses": candidate_count,
                "scanned_addresses": scanned,
                "decoded_instructions": decoded,
                "decode_failures": failures,
                "complete": failures == 0 and scanned == candidate_count,
            }
        return {
            "requested_address": str(resolved),
            "references": found,
            "coverage": {
                "mode": ("listing_only" if scan is None else "listing_and_pseudo_disassembly"),
                "scan": scan,
            },
            "incomplete": True,
            "incomplete_reasons": [
                "ghidra_reference_manager_depends_on_defined_listing",
                *(["pseudo_scan_is_explicit_range_only"] if scan is not None else []),
            ],
            "truncated": truncated,
        }

    def strings_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        listing = workspace.get(program_id).getCurrentProgram().getListing()
        values = (data for data in listing.getDefinedData(True) if data.hasStringValue())
        if contains is not None:
            values = (
                data for data in values if contains in str(data.getDefaultValueRepresentation())
            )
        return [
            {
                "address": str(data.getAddress()),
                "length": int(data.getLength()),
                "data_type": str(data.getDataType()),
                "value": str(data.getDefaultValueRepresentation()),
            }
            for data in _page(values, offset=offset, limit=limit)
        ]

    definitions = (
        ToolDefinition(
            "instructions_list",
            """Read instructions, paginated, starting from the program start or a given address.

Inputs/outputs and side effects: takes a program session id, an optional starting address, and pagination parameters; returns the requested start, Ghidra's actual start, the number of bytes skipped, and the instruction list; when require_exact_start is true, rejects an address that is not a defined instruction start; read-only.

When to use: call to inspect concrete machine instructions or verify decompilation results; use memory_read if you only need the raw bytes.
            """,
            instructions_list,
            contract_version=2,
        ),
        ToolDefinition(
            "symbols_list",
            """List symbols, paginated, optionally filtered by a name fragment.

Inputs/outputs and side effects: takes a program session id, an optional name fragment, and pagination parameters; returns name, address, type, source, and primary-symbol status; read-only.

When to use: call to discover functions, labels, or external symbols by name; prefer functions_list when you only need the set of functions.
""",
            symbols_list,
        ),
        ToolDefinition(
            "references_list",
            """Read incoming, outgoing, or both-direction references at a given address.

Inputs/outputs and side effects: takes a program session id, address, direction, a result cap, and an optional pseudo-disassembly scan range; returns references, source/confidence, coverage, and incomplete/truncated status; read-only, does not modify the listing.

When to use: call to trace callers, callees, or data cross-references; use functions_list when you need the complete set of functions.
""",
            references_list,
            contract_version=2,
        ),
        ToolDefinition(
            "strings_list",
            """List defined strings, paginated, optionally filtered by content.

Inputs/outputs and side effects: takes a program session id, an optional content fragment, and pagination parameters; returns address, length, data type, and displayed value; read-only.

When to use: call to locate behavior and references from textual clues; do not use this tool to search for arbitrary raw byte patterns.
""",
            strings_list,
        ),
    )
    for definition in definitions:
        registry.register(definition)
