"""Program session lifecycle tools."""

from pathlib import Path

from mcp.types import ToolAnnotations

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace


def register_program_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def program_open(binary_path: str, analyze: bool = True) -> dict[str, str]:
        program_id = workspace.open(Path(binary_path), analyze=analyze)
        return {"program_id": program_id, "path": str(Path(binary_path).resolve())}

    def program_list() -> list[dict[str, str]]:
        return workspace.list_open()

    def program_info(program_id: str) -> dict[str, str]:
        return workspace.describe(program_id)

    def program_close(program_id: str) -> dict[str, str]:
        workspace.close(program_id)
        return {"closed": program_id}

    def program_open_raw(
        binary_path: str,
        language_id: str,
        base_address: str,
        compiler_id: str = "default",
        analyze: bool = True,
    ) -> dict[str, str]:
        program_id = workspace.open_raw(
            Path(binary_path),
            language_id=language_id,
            base_address=base_address,
            compiler_id=compiler_id,
            analyze=analyze,
        )
        return {"program_id": program_id, "path": str(Path(binary_path).resolve())}

    definitions = (
        ToolDefinition(
            "program_open",
            """Open a binary and establish an independent program session.

Inputs/outputs and side effects: takes a local binary path and whether to analyze; returns the program session id and canonical path; creates or opens Ghidra project data.

When to use: call before analyzing any binary; if a session already exists, use program_list instead of opening again.
""",
            program_open,
        ),
        ToolDefinition(
            "program_list",
            """List the program sessions owned by the current process.

Inputs/outputs and side effects: no input; returns a list of program session ids and binary paths; read-only.

When to use: call to recover context or pick a target program; use program_info for architecture details on a specific program.
""",
            program_list,
        ),
        ToolDefinition(
            "program_info",
            """Read a program's format, language, and address range.

Inputs/outputs and side effects: takes a program session id; returns name, language, compiler, format, and address bounds; read-only.

When to use: call to establish program-level context at the start of analysis; use program_list if you only need to find an existing session.
""",
            program_info,
        ),
        ToolDefinition(
            "program_close",
            """Close a program session and release its Ghidra context.

Inputs/outputs and side effects: takes a program session id; returns the closed id; saves the project first, only closing and releasing resources after a successful save; the session is kept if saving fails and an error is returned.

When to use: call after finishing all work on a program; do not close while you still need to read or modify it.
""",
            program_close,
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        ),
        ToolDefinition(
            "program_open_raw",
            """Open a raw binary that program_open could not auto-detect (e.g. a firmware image or a headerless flash dump) with an explicit language, compiler, and base address.

Inputs/outputs and side effects: takes a local binary path, a Ghidra language id (e.g. ARM:LE:32:Cortex), a base address (hex string, e.g. 0x88000000), and an optional compiler id (default "default") and whether to analyze; returns the program session id and canonical path; creates or opens Ghidra project data, sharing the same persistent project naming as program_open, so the same file is only ever imported once.

When to use: call when program_open fails with "No load spec found" or similar auto-detection errors, and you already know the target architecture and load address (from documentation, a ROM header, or strings found in the file); if the architecture or base address is unknown, use file_strings/file_hexdump first to investigate rather than guessing.
""",
            program_open_raw,
        ),
    )
    for definition in definitions:
        registry.register(definition)
