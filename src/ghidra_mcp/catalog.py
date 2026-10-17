"""默认工具集的唯一装配入口。"""

from .registry import ToolRegistry
from .runtime import ProgramWorkspace
from .tools.analysis import register_analysis_tools
from .tools.inspection import register_inspection_tools
from .tools.listing import register_listing_tools
from .tools.navigation import register_navigation_tools
from .tools.operations import register_operation_tools
from .tools.programs import register_program_tools
from .tools.raw import register_raw_tools
from .tools.writes import register_write_tools


def build_default_registry(workspace: ProgramWorkspace) -> ToolRegistry:
    registry = ToolRegistry()
    register_program_tools(registry, workspace)
    register_navigation_tools(registry, workspace)
    register_listing_tools(registry, workspace)
    register_write_tools(registry, workspace)
    register_analysis_tools(registry, workspace)
    register_inspection_tools(registry, workspace)
    register_operation_tools(registry, workspace)
    register_raw_tools(registry, workspace)
    return registry
