import asyncio


def test_default_catalog_has_one_registration_path_and_no_placeholders() -> None:
    from ghidra_mcp.catalog import build_default_registry
    from ghidra_mcp.server import create_mcp_app

    registry = build_default_registry(workspace=object())
    definitions = registry.enabled_tools()

    assert [tool.name for tool in definitions] == [
        "program_open",
        "program_list",
        "program_info",
        "program_close",
        "program_open_raw",
        "memory_blocks_list",
        "memory_read",
        "functions_list",
        "function_get",
        "instructions_list",
        "symbols_list",
        "references_list",
        "strings_list",
        "function_rename",
        "symbol_rename",
        "comment_set",
        "function_create",
        "function_delete",
        "function_body_add",
        "decompile_function",
        "call_graph",
        "control_flow_graph",
        "data_list",
        "data_get",
        "comments_list",
        "variables_list",
        "pcode_list",
        "data_types_list",
        "function_tags",
        "bookmarks_list",
        "memory_search",
        "analysis_run",
        "data_type_get",
        "data_type_apply",
        "function_tag_update",
        "bookmark_set",
        "file_strings",
        "file_hexdump",
    ]
    assert all(callable(tool.handler) for tool in definitions)
    assert all("输入输出与副作用：" in tool.description for tool in definitions)
    assert all("何时使用：" in tool.description for tool in definitions)

    app = create_mcp_app(registry, host="127.0.0.1", port=8765)
    exposed = asyncio.run(app.list_tools())
    assert [tool.name for tool in exposed] == [tool.name for tool in definitions]
