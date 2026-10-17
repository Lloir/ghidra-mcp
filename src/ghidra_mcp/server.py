"""Bind the local tool registry to FastMCP."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from hashlib import sha256
import hmac
from importlib.metadata import PackageNotFoundError, version as package_version
import inspect
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .registry import ToolRegistry


class GhidraToolExecutor:
    """Keep JVM tool ownership on a single thread without blocking the async transport."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ghidra-mcp")

    async def run(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, partial(function, *args, **kwargs))

    def run_sync(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        return self._executor.submit(function, *args, **kwargs).result()

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True)


def _async_handler(function: Any, executor: GhidraToolExecutor) -> Any:
    @wraps(function)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        return await executor.run(function, *args, **kwargs)

    return wrapped


class StaticTokenVerifier(TokenVerifier):
    """Verify the single bearer token the deployer supplied via environment variables."""

    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token.encode("utf-8")

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token.encode("utf-8"), self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="ghidra-mcp",
            scopes=["mcp"],
            subject="configured-client",
        )


def _schema_version(registry: ToolRegistry) -> str:
    contracts = [
        {
            "name": tool.name,
            "description": tool.description,
            "signature": str(inspect.signature(tool.handler)),
            "contract_version": tool.contract_version,
            "annotations": (
                tool.annotations.model_dump(exclude_none=True)
                if tool.annotations is not None
                else None
            ),
        }
        for tool in registry.enabled_tools()
    ]
    encoded = json.dumps(contracts, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return sha256(encoded).hexdigest()[:16]


def _runtime_version() -> str:
    try:
        return package_version("ghidra-mcp")
    except PackageNotFoundError:
        return "unknown"


def _git_commit() -> str:
    configured = os.environ.get("GHIDRA_MCP_GIT_COMMIT", "").strip()
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def create_mcp_app(
    registry: ToolRegistry,
    *,
    host: str,
    port: int,
    auth_token: str | None = None,
    public_url: str | None = None,
    version: str | None = None,
    git_commit: str | None = None,
    tool_executor: GhidraToolExecutor | None = None,
) -> FastMCP:
    auth = None
    verifier = None
    if auth_token is not None:
        if public_url is None:
            raise ValueError("public_url must be provided when HTTP auth is enabled")
        base_url = public_url.rstrip("/")
        auth = AuthSettings(
            issuer_url=base_url,
            resource_server_url=f"{base_url}/mcp",
            required_scopes=["mcp"],
        )
        verifier = StaticTokenVerifier(auth_token)
    app = FastMCP(
        "ghidra-mcp",
        host=host,
        port=port,
        auth=auth,
        token_verifier=verifier,
    )
    executor = tool_executor or GhidraToolExecutor()
    for tool in registry.enabled_tools():
        app.tool(
            name=tool.name,
            description=tool.description,
            annotations=tool.annotations,
        )(_async_handler(tool.handler, executor))

    health_payload = {
        "status": "ok",
        "version": version or _runtime_version(),
        "git_commit": git_commit or _git_commit(),
        "schema_version": _schema_version(registry),
    }

    @app.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_request: Request) -> Response:
        return JSONResponse(health_payload)

    return app
