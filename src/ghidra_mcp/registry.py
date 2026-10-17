"""The single registration point for task-oriented MCP tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from mcp.types import ToolAnnotations


class RegistryError(ValueError):
    """A tool registration violates the uniqueness or naming contract."""


class DescriptionError(ValueError):
    """A tool description is missing information needed to decide when to call it."""


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    handler: Callable[..., object]
    group: str = "default"
    contract_version: int = 1
    annotations: ToolAnnotations | None = None

    def __post_init__(self) -> None:
        if self.contract_version < 1:
            raise RegistryError("contract_version must be greater than or equal to 1")
        for required in ("Inputs/outputs and side effects:", "When to use:"):
            if required not in self.description:
                raise DescriptionError(
                    f"tool {self.name} description is missing the "
                    f"\"{required.rstrip(':')}\" section"
                )


class ToolRegistry:
    def __init__(self, enabled_groups: tuple[str, ...] = ()) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._enabled_groups = frozenset(("default", *enabled_groups))

    def register(self, tool: ToolDefinition) -> None:
        lowered = tool.name.lower()
        if lowered.endswith("_batch") or lowered.endswith("_bulk"):
            raise RegistryError(
                "batch/bulk aliases are not allowed; task tools accept arrays directly"
            )
        if tool.name in self._tools:
            raise RegistryError(f"tool {tool.name!r} already registered")
        self._tools[tool.name] = tool
        if len(self.enabled_tools()) > 40 and tool.group == "default":
            del self._tools[tool.name]
            raise RegistryError("default tools must not exceed 40")

    def enabled_tools(self) -> tuple[ToolDefinition, ...]:
        return tuple(tool for tool in self._tools.values() if tool.group in self._enabled_groups)
