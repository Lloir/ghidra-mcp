"""Decompilation and function-graph analysis tools."""

from itertools import islice
from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from .navigation import ToolInputError


def _new_decompiler() -> Any:
    from ghidra.app.decompiler import DecompInterface

    return DecompInterface()


def _function(api: Any, address: str) -> Any:
    resolved = api.toAddr(address)
    if resolved is None:
        raise ToolInputError(f"could not resolve address: {address}")
    function = api.getFunctionContaining(resolved)
    if function is None:
        raise ToolInputError(f"address is not contained in a function: {address}")
    return function


def _identity(function: Any) -> dict[str, str]:
    return {"name": str(function.getName()), "entry_point": str(function.getEntryPoint())}


def register_analysis_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def decompile_function(
        program_id: str,
        address: str,
        timeout_seconds: int = 30,
        max_chars: int = 50_000,
    ) -> dict[str, str | bool]:
        if not 1 <= timeout_seconds <= 300:
            raise ToolInputError("timeout_seconds must be between 1 and 300")
        if not 1 <= max_chars <= 200_000:
            raise ToolInputError("max_chars must be between 1 and 200000")
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        function = _function(api, address)
        decompiler = _new_decompiler()
        try:
            if not decompiler.openProgram(program):
                raise RuntimeError(f"decompiler could not open the program: {decompiler.getLastMessage()}")
            results = decompiler.decompileFunction(function, timeout_seconds, None)
            if not results.decompileCompleted():
                raise RuntimeError(f"decompilation failed: {decompiler.getLastMessage()}")
            decompiled = results.getDecompiledFunction()
            if decompiled is None:
                raise RuntimeError("decompilation completed but produced no C text")
            text = str(decompiled.getC())
            return {
                **_identity(function),
                "c": text[:max_chars],
                "truncated": len(text) > max_chars,
            }
        finally:
            decompiler.dispose()

    def call_graph(program_id: str, address: str, limit: int = 100) -> dict[str, object]:
        if not 1 <= limit <= 1000:
            raise ToolInputError("limit must be between 1 and 1000")
        api = workspace.get(program_id)
        function = _function(api, address)
        callers = list(islice(function.getCallingFunctions(None), limit + 1))
        callees = list(islice(function.getCalledFunctions(None), limit + 1))
        callers_truncated = len(callers) > limit
        callees_truncated = len(callees) > limit
        callers = sorted(callers[:limit], key=lambda item: str(item.getEntryPoint()))
        callees = sorted(callees[:limit], key=lambda item: str(item.getEntryPoint()))
        return {
            "function": _identity(function),
            "callers": [_identity(item) for item in callers],
            "callees": [_identity(item) for item in callees],
            "callers_truncated": callers_truncated,
            "callees_truncated": callees_truncated,
        }

    def control_flow_graph(program_id: str, address: str) -> dict[str, object]:
        api = workspace.get(program_id)
        function = _function(api, address)
        instructions = list(
            islice(
                api.getCurrentProgram().getListing().getInstructions(function.getBody(), True),
                10_001,
            )
        )
        if len(instructions) > 10_000:
            raise RuntimeError(
                "function has more than 10000 instructions; refusing to build an oversized control-flow graph"
            )
        nodes = [str(instruction.getAddress()) for instruction in instructions]
        edges: list[dict[str, str]] = []
        has_computed_flow = False
        has_inferred_flow = False
        for instruction in instructions:
            source = str(instruction.getAddress())
            fallthrough = instruction.getFallThrough()
            if fallthrough is not None:
                edges.append(
                    {
                        "from": source,
                        "to": str(fallthrough),
                        "kind": "fallthrough",
                        "provenance": "instruction_fallthrough",
                        "confidence": "high",
                    }
                )
            default_flows = {str(target) for target in instruction.getDefaultFlows() or ()}
            computed = bool(instruction.getFlowType().isComputed())
            has_computed_flow = has_computed_flow or computed
            for target in instruction.getFlows() or ():
                target_text = str(target)
                inferred = target_text not in default_flows
                has_inferred_flow = has_inferred_flow or inferred
                edges.append(
                    {
                        "from": source,
                        "to": target_text,
                        "kind": (
                            "computed_flow"
                            if inferred and computed
                            else "inferred_flow"
                            if inferred
                            else "direct_flow"
                        ),
                        "provenance": (
                            "ghidra_non_default_flow" if inferred else "instruction_default_flow"
                        ),
                        "confidence": "inferred" if inferred else "high",
                    }
                )
        return {
            "function": _identity(function),
            "nodes": nodes,
            "edges": edges,
            "coverage": {
                "scope": "ghidra_function_body",
                "defined_instructions": len(instructions),
            },
            "incomplete": True,
            "incomplete_reasons": [
                "ghidra_function_body_only",
                *(["non_default_flow_targets_are_inferred"] if has_inferred_flow else []),
                *(["computed_flow_targets_are_inferred"] if has_computed_flow else []),
            ],
        }

    definitions = (
        ToolDefinition(
            "decompile_function",
            """Decompile the function containing a given address to C-style text.

Inputs/outputs and side effects: takes a program session, an address inside a function, a timeout between 1 and 300 seconds, and a text character cap; returns the function's identity, bounded C text, and a truncation flag; read-only, and releases the decompiler after the call.

When to use: call to understand a function's high-level semantics; use instructions_list to check concrete machine instructions.
""",
            decompile_function,
        ),
        ToolDefinition(
            "call_graph",
            """Read a function's one-hop callers and callees.

Inputs/outputs and side effects: takes a program session, an address inside a function, and a per-direction result cap; returns the target function, bounded callers/callees, and truncation flags; read-only.

When to use: call to locate call relationships and blast radius; use control_flow_graph to analyze the jump structure inside a function.
""",
            call_graph,
        ),
        ToolDefinition(
            "control_flow_graph",
            """Build the instruction-level control-flow edge set for a function.

Inputs/outputs and side effects: takes a program session and an address inside a function; returns the defined instructions in the function body, edges with provenance/confidence, coverage, and incompleteness status; read-only, and refuses to build a graph for a function with more than 10000 instructions.

When to use: call to analyze branches, loops, or obfuscated control flow; use call_graph for cross-function call relationships.
""",
            control_flow_graph,
            contract_version=2,
        ),
    )
    for definition in definitions:
        registry.register(definition)
