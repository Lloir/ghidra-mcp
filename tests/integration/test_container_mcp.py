import json
import os
from typing import Any

import anyio
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult


def _payload(result: CallToolResult) -> Any:
    assert not result.isError, result.content
    if result.structuredContent is not None:
        if set(result.structuredContent) == {"result"}:
            return result.structuredContent["result"]
        return result.structuredContent
    assert result.content and result.content[0].type == "text"
    return json.loads(result.content[0].text)


@pytest.mark.integration
def test_container_mcp_analyzes_and_persists_real_elf() -> None:
    url = os.environ.get("GHIDRA_MCP_CONTAINER_URL")
    token = os.environ.get("GHIDRA_MCP_CONTAINER_TOKEN")
    if not url or not token:
        pytest.skip("GHIDRA_MCP_CONTAINER_URL/TOKEN not configured")

    expected_name = os.environ.get("GHIDRA_MCP_CONTAINER_EXPECT_NAME", "fixture_symbolic")
    rename_to = os.environ.get("GHIDRA_MCP_CONTAINER_RENAME_TO")
    binary_path = os.environ.get("GHIDRA_MCP_CONTAINER_FIXTURE", "/data/input/libsymbolic.so")

    async def exercise() -> None:
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=120
        ) as client:
            async with streamable_http_client(url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    assert len(listed.tools) == 35
                    assert len(listed.tools) <= 40

                    opened = _payload(
                        await session.call_tool(
                            "program_open", {"binary_path": binary_path, "analyze": True}
                        )
                    )
                    program_id = opened["program_id"]
                    functions = _payload(
                        await session.call_tool(
                            "functions_list",
                            {"program_id": program_id, "offset": 0, "limit": 1000},
                        )
                    )
                    target = next(item for item in functions if item["name"] == expected_name)
                    entry = target["entry_point"]
                    decompiled = _payload(
                        await session.call_tool(
                            "decompile_function",
                            {"program_id": program_id, "address": entry, "timeout_seconds": 60},
                        )
                    )
                    assert expected_name in decompiled["c"]

                    if rename_to:
                        _payload(
                            await session.call_tool(
                                "function_rename",
                                {
                                    "program_id": program_id,
                                    "address": entry,
                                    "name": rename_to,
                                },
                            )
                        )
                        _payload(
                            await session.call_tool(
                                "comment_set",
                                {
                                    "program_id": program_id,
                                    "address": entry,
                                    "kind": "eol",
                                    "text": "container persistence verified",
                                },
                            )
                        )
                    _payload(await session.call_tool("program_close", {"program_id": program_id}))

                    reopened = _payload(
                        await session.call_tool(
                            "program_open", {"binary_path": binary_path, "analyze": False}
                        )
                    )
                    persisted = _payload(
                        await session.call_tool(
                            "function_get",
                            {"program_id": reopened["program_id"], "address": entry},
                        )
                    )
                    assert persisted["function"]["name"] == (rename_to or expected_name)
                    _payload(
                        await session.call_tool(
                            "program_close", {"program_id": reopened["program_id"]}
                        )
                    )

    anyio.run(exercise)
