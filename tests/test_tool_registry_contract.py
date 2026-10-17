import pytest


VALID_DESCRIPTION = """Read program summary information.

Inputs/outputs and side effects: takes the current program id; returns architecture, image base, and analysis status; read-only.

When to use: to establish context at the start of analysis; use functions_list instead when you need to enumerate functions.
"""


def test_default_registry_never_exposes_more_than_40_tools() -> None:
    from ghidra_mcp.registry import ToolRegistry

    registry = ToolRegistry()

    assert len(registry.enabled_tools()) <= 40


def test_tool_description_requires_three_sections() -> None:
    from ghidra_mcp.registry import DescriptionError, ToolDefinition

    with pytest.raises(DescriptionError, match="Inputs/outputs and side effects"):
        ToolDefinition(name="program_info", description="Reads program summary information.", handler=lambda: None)

    tool = ToolDefinition(name="program_info", description=VALID_DESCRIPTION, handler=lambda: None)
    assert tool.name == "program_info"


def test_duplicate_and_batch_alias_names_are_rejected() -> None:
    from ghidra_mcp.registry import RegistryError, ToolDefinition, ToolRegistry

    registry = ToolRegistry()
    registry.register(ToolDefinition("program_info", VALID_DESCRIPTION, lambda: None))

    with pytest.raises(RegistryError, match="already registered"):
        registry.register(ToolDefinition("program_info", VALID_DESCRIPTION, lambda: None))

    with pytest.raises(RegistryError, match="batch|bulk"):
        registry.register(ToolDefinition("program_info_batch", VALID_DESCRIPTION, lambda: None))
