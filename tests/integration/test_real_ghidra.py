import os
from pathlib import Path

import pytest

from ghidra_mcp.catalog import build_default_registry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace


FIXTURES = Path(__file__).parents[1] / "fixtures" / "generated"


@pytest.mark.integration
def test_real_elf_shared_libraries_cover_read_decompile_write_and_reopen(
    tmp_path: Path,
) -> None:
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR not configured")
    samples = (
        (FIXTURES / "libsymbolic.so", "fixture_symbolic"),
        (FIXTURES / "libstripped.so", "fixture_checksum"),
        (FIXTURES / "libcontrol_flow.so", "fixture_control_flow"),
    )
    if any(not sample.is_file() for sample, _ in samples):
        pytest.skip("run scripts/build_fixtures.py first")

    workspace = ProgramWorkspace(
        GhidraRuntime(Path(install_value)), project_location=tmp_path / "projects"
    )
    registry = build_default_registry(workspace)
    tools = {tool.name: tool.handler for tool in registry.enabled_tools()}

    for sample, expected_name in samples:
        opened = tools["program_open"](str(sample), analyze=True)
        program_id = opened["program_id"]
        info = tools["program_info"](program_id)
        assert "ELF" in info["format"]

        blocks = tools["memory_blocks_list"](program_id)
        assert blocks
        readable = next(block for block in blocks if block["initialized"])
        memory = tools["memory_read"](program_id, readable["start"], 16)
        assert memory["length"] == 16
        assert tools["memory_search"](program_id, memory["hex"][:8], max_results=5)

        functions = tools["functions_list"](program_id, offset=0, limit=1000)
        target = next(function for function in functions if function["name"] == expected_name)
        entry = target["entry_point"]
        assert tools["function_get"](program_id, entry)["function"]["entry_point"] == entry
        instructions = tools["instructions_list"](program_id, address=entry, limit=200)[
            "instructions"
        ]
        assert instructions
        tools["symbols_list"](program_id, contains=expected_name, limit=20)
        references = tools["references_list"](program_id, entry, direction="both", limit=20)
        assert references["requested_address"] == entry
        assert references["coverage"]["mode"] == "listing_only"
        tools["strings_list"](program_id, limit=20)
        assert expected_name in tools["decompile_function"](program_id, entry, 60)["c"]
        tools["call_graph"](program_id, entry)
        graph = tools["control_flow_graph"](program_id, entry)
        assert graph["nodes"]
        if expected_name == "fixture_control_flow":
            assert any(
                int(edge["to"], 16) < int(edge["from"], 16)
                for edge in graph["edges"]
                if edge["kind"] in {"direct_flow", "inferred_flow", "computed_flow"}
            ), "control-flow fixture must preserve the loop back-edge"
            assert any(
                instruction["mnemonic"].upper() == "CALL"
                and any("[" in operand for operand in instruction["operands"])
                for instruction in instructions
            ), "control-flow fixture must preserve the indirect call"
        data = tools["data_list"](program_id, limit=20)
        if data:
            assert (
                tools["data_get"](program_id, data[0]["address"])["address"] == data[0]["address"]
            )
        tools["variables_list"](program_id, entry)
        assert tools["pcode_list"](program_id, entry, limit=20)
        assert tools["data_types_list"](program_id, limit=20)
        first_type = tools["data_types_list"](program_id, limit=1)[0]
        assert tools["data_type_get"](program_id, first_type["path"])["path"] == first_type["path"]
        tools["function_tags"](program_id, entry)
        tools["bookmarks_list"](program_id, limit=20)
        assert tools["analysis_run"](program_id)["functions_after"] >= 1

        suffix = sample.stem.removeprefix("lib")
        if sample == samples[0][0]:
            real_save = workspace.save

            def fail_save(_program_id: str) -> None:
                raise RuntimeError("simulated persistence failure")

            workspace.save = fail_save  # type: ignore[method-assign]
            with pytest.raises(RuntimeError, match="simulated persistence failure"):
                tools["function_rename"](program_id, entry, "must_be_rolled_back")
            assert tools["function_get"](program_id, entry)["function"]["name"] == expected_name
            workspace.save = real_save  # type: ignore[method-assign]
        tools["function_rename"](program_id, entry, f"renamed_{suffix}")
        tools["symbol_rename"](program_id, entry, f"symbol_{suffix}")
        tools["function_delete"](program_id, entry)
        tools["function_create"](program_id, entry, f"verified_{suffix}")
        tools["comment_set"](program_id, entry, "eol", f"verified {suffix}")
        tools["function_tag_update"](program_id, entry, "add", f"reviewed_{suffix}")
        tools["bookmark_set"](program_id, entry, "Analysis", "Review", f"inspect {suffix}")

        current_program = workspace.get(program_id).getCurrentProgram()
        undefined = current_program.getListing().getFirstUndefinedData(
            current_program.getMemory(), workspace.runtime.pyghidra.task_monitor()
        )
        assert undefined is not None
        undefined_address = str(undefined.getAddress())
        byte_type = next(
            item
            for item in tools["data_types_list"](program_id, contains="byte", limit=100)
            if item["length"] == 1
        )
        tools["data_type_apply"](program_id, undefined_address, byte_type["path"])

        tools["program_close"](program_id)

        reopened = tools["program_open"](str(sample), analyze=False)
        reopened_id = reopened["program_id"]
        assert tools["function_get"](reopened_id, entry)["function"]["name"] == f"verified_{suffix}"
        assert any(
            item["address"] == entry and item["text"] == f"verified {suffix}"
            for item in tools["comments_list"](reopened_id)
        )
        assert any(
            item["name"] == f"reviewed_{suffix}"
            for item in tools["function_tags"](reopened_id, entry)
        )
        assert any(
            item["address"] == entry and item["comment"] == f"inspect {suffix}"
            for item in tools["bookmarks_list"](reopened_id)
        )
        assert tools["data_get"](reopened_id, undefined_address)["address"] == undefined_address
        tools["program_close"](reopened_id)

    workspace.close_all()
