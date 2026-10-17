"""Assembly and shutdown cleanup for the complete MCP service object."""

from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from .catalog import build_default_registry
from .config import (
    ConfigurationError,
    Settings,
    normalize_http_public_url,
    validate_http_auth_token,
)
from .runtime import GhidraRuntime, ProgramWorkspace
from .server import GhidraToolExecutor, create_mcp_app


@dataclass(slots=True)
class MCPService:
    settings: Settings
    app: FastMCP
    workspace: ProgramWorkspace
    tool_executor: GhidraToolExecutor

    def run(self) -> None:
        try:
            self.app.run(transport=self.settings.transport)  # type: ignore[arg-type]
        finally:
            try:
                self.tool_executor.run_sync(self.workspace.close_all)
            finally:
                self.tool_executor.shutdown()


def create_service(settings: Settings, *, pyghidra_module: Any | None = None) -> MCPService:
    if settings.install_dir is None:
        raise ConfigurationError(
            "the Ghidra installation directory must be configured via GHIDRA_INSTALL_DIR or TOML"
        )
    public_url = None
    if settings.transport == "streamable-http":
        validate_http_auth_token(settings.auth_token)
        public_url = normalize_http_public_url(settings.public_url)
    if settings.transport == "streamable-http" and settings.input_root is None:
        raise ConfigurationError("streamable-http requires GHIDRA_MCP_INPUT_ROOT to be set")
    runtime = GhidraRuntime(
        settings.install_dir,
        pyghidra_module=pyghidra_module,
        analysis_timeout_seconds=settings.analysis_timeout_seconds,
    )
    workspace = ProgramWorkspace(
        runtime,
        project_location=settings.storage_root,
        input_root=settings.input_root,
    )
    registry = build_default_registry(workspace)
    tool_executor = GhidraToolExecutor()
    app = create_mcp_app(
        registry,
        host=settings.host,
        port=settings.port,
        auth_token=settings.auth_token if settings.transport == "streamable-http" else None,
        public_url=public_url,
        tool_executor=tool_executor,
    )
    return MCPService(
        settings=settings,
        app=app,
        workspace=workspace,
        tool_executor=tool_executor,
    )
