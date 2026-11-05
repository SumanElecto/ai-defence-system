import pytest

from src.tool_security import (
    BUILTIN_TOOLS,
    ToolPolicyError,
    execute_approved_tool,
    get_authorized_tools,
    validate_mcp_server_url,
    validate_tool_arguments,
    validate_tool_schema,
)


def test_tool_catalog_is_empty_without_explicit_allowlists(monkeypatch):
    monkeypatch.delenv("BUILTIN_TOOL_ALLOWLIST", raising=False)
    monkeypatch.delenv("MCP_ALLOWED_TOOLS", raising=False)
    monkeypatch.setenv("MCP_SERVER_URL", "https://tools.example.test/mcp")

    assert get_authorized_tools() == []


def test_only_named_builtin_tools_are_authorized(monkeypatch):
    monkeypatch.setenv("BUILTIN_TOOL_ALLOWLIST", "calculator")
    monkeypatch.delenv("MCP_ALLOWED_TOOLS", raising=False)

    assert [tool.name for tool in get_authorized_tools()] == ["calculator"]


def test_builtin_tools_require_approval_and_validate_arguments():
    calculator = BUILTIN_TOOLS["calculator"]

    with pytest.raises(PermissionError):
        execute_approved_tool(
            calculator,
            {"expression": "2+2"},
            approved=False,
        )

    with pytest.raises(ToolPolicyError, match="authorized schema"):
        validate_tool_arguments(
            calculator,
            {"expression": "2+2", "shell": "echo unsafe"},
        )


def test_calculator_accepts_bounded_arithmetic_but_not_code():
    calculator = BUILTIN_TOOLS["calculator"]

    result = execute_approved_tool(
        calculator,
        {"expression": "2 * (3 + 4)"},
        approved=True,
    )

    assert result["text"] == "14"

    with pytest.raises(ToolPolicyError, match="arithmetic expressions only"):
        execute_approved_tool(
            calculator,
            {"expression": "__import__('os').system('id')"},
            approved=True,
        )


def test_sha256_builtin_returns_digest_after_approval():
    result = execute_approved_tool(
        BUILTIN_TOOLS["sha256_text"],
        {"text": "hello"},
        approved=True,
    )

    assert result["text"] == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_sensitive_arguments_are_rejected_before_tool_execution():
    with pytest.raises(ToolPolicyError, match="Sensitive values"):
        execute_approved_tool(
            BUILTIN_TOOLS["sha256_text"],
            {"text": "jane.doe@example.com"},
            approved=True,
        )


def test_mcp_schemas_reject_remote_refs_and_invalid_json_schema():
    with pytest.raises(ToolPolicyError, match=r"cannot use \$ref"):
        validate_tool_schema({"type": "object", "$ref": "https://schema.test/x"})

    with pytest.raises(ToolPolicyError, match="schema is invalid"):
        validate_tool_schema({"type": "not-a-schema-type"})


@pytest.mark.parametrize(
    "url",
    [
        "http://tools.example.test/mcp",
        "https://user:pass@tools.example.test/mcp",
        "https://tools.example.test/mcp?token=secret",
        "https://tools.example.test/mcp#fragment",
    ],
)
def test_mcp_endpoint_requires_credential_free_https_url(url):
    with pytest.raises(ToolPolicyError):
        validate_mcp_server_url(url)