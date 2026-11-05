import ast
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import anyio
import httpx2
from jsonschema.validators import validator_for
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from src.sensitive_data import find_sensitive_data, redact_sensitive_data


MAX_TOOL_COUNT = 32
MAX_SCHEMA_BYTES = 32_768
MAX_ARGUMENT_BYTES = 16_384
MAX_TOOL_RESULT_BYTES = 32_768
TOOL_TIMEOUT_SECONDS = 30
TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    source: Literal["builtin", "mcp"]
    remote_name: str | None = None
    server_url: str | None = None


@dataclass(frozen=True)
class ToolInvocation:
    name: str
    arguments: dict[str, Any]


class ToolPolicyError(ValueError):
    pass


class ToolOutputSecurityError(ValueError):
    pass


BUILTIN_TOOLS = {
    "calculator": ToolDefinition(
        name="calculator",
        description="Evaluate a bounded arithmetic expression. No code or names are allowed.",
        input_schema={
            "type": "object",
            "properties": {"expression": {"type": "string", "maxLength": 256}},
            "required": ["expression"],
            "additionalProperties": False,
        },
        source="builtin",
    ),
    "sha256_text": ToolDefinition(
        name="sha256_text",
        description="Return the SHA-256 digest of supplied text.",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 16384}},
            "required": ["text"],
            "additionalProperties": False,
        },
        source="builtin",
    ),
}


def _allowlist(environment_key: str) -> set[str]:
    return {
        entry.strip()
        for entry in os.environ.get(environment_key, "").split(",")
        if entry.strip()
    }


def validate_mcp_server_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ToolPolicyError("MCP endpoint must be an HTTPS URL without embedded credentials")
    return url


def _reject_schema_refs(value: Any) -> None:
    if isinstance(value, dict):
        if "$ref" in value:
            raise ToolPolicyError("MCP tool schemas cannot use $ref")
        for child in value.values():
            _reject_schema_refs(child)
    elif isinstance(value, list):
        for child in value:
            _reject_schema_refs(child)


def validate_tool_schema(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise ToolPolicyError("Tool input schema must be a JSON object")
    if len(json.dumps(schema, separators=(",", ":")).encode("utf-8")) > MAX_SCHEMA_BYTES:
        raise ToolPolicyError("Tool input schema exceeds the configured size limit")
    _reject_schema_refs(schema)
    try:
        validator = validator_for(schema)
        validator.check_schema(schema)
    except Exception:
        raise ToolPolicyError("Tool input schema is invalid") from None
    return schema


def validate_tool_arguments(
    tool: ToolDefinition,
    arguments: Any,
) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ToolPolicyError("Tool arguments must be a JSON object")
    try:
        serialized = json.dumps(arguments, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise ToolPolicyError("Tool arguments must contain JSON values only") from None
    if len(serialized.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ToolPolicyError("Tool arguments exceed the configured size limit")

    schema = validate_tool_schema(tool.input_schema)
    validator = validator_for(schema)(schema, format_checker=validator_for(schema).FORMAT_CHECKER)
    try:
        validator.validate(arguments)
    except Exception:
        raise ToolPolicyError("Tool arguments do not match the authorized schema") from None
    if find_sensitive_data(serialized):
        raise ToolPolicyError("Sensitive values are not allowed in tool arguments")
    return arguments


def _evaluate_arithmetic(expression: str) -> int | float:
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 256:
        raise ToolPolicyError("Calculator expression is empty or too long")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        raise ToolPolicyError("Calculator accepts arithmetic expressions only") from None

    allowed_operators = {
        ast.Add: lambda left, right: left + right,
        ast.Sub: lambda left, right: left - right,
        ast.Mult: lambda left, right: left * right,
        ast.Div: lambda left, right: left / right,
        ast.FloorDiv: lambda left, right: left // right,
        ast.Mod: lambda left, right: left % right,
        ast.Pow: lambda left, right: left ** right,
    }

    def evaluate(node: ast.AST) -> int | float:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if (
            isinstance(node, ast.Constant)
            and (type(node.value) is int or type(node.value) is float)
        ):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = evaluate(node.operand)
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and type(node.op) in allowed_operators:
            left = evaluate(node.left)
            right = evaluate(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 100:
                raise ToolPolicyError("Exponent exceeds the configured limit")
            try:
                result = allowed_operators[type(node.op)](left, right)
            except (ArithmeticError, OverflowError):
                raise ToolPolicyError("Calculator expression is not finite") from None
            if isinstance(result, complex) or not math.isfinite(result) or abs(result) > 1e100:
                raise ToolPolicyError("Calculator result exceeds the configured limit")
            return result
        raise ToolPolicyError("Calculator accepts arithmetic expressions only")

    if sum(1 for _ in ast.walk(tree)) > 64:
        raise ToolPolicyError("Calculator expression is too complex")
    return evaluate(tree)


def _clean_tool_result(value: str, canary: str | None) -> dict[str, Any]:
    if len(value.encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
        raise ToolPolicyError("Tool result exceeds the configured size limit")
    findings = find_sensitive_data(value, canary)
    categories = list(dict.fromkeys(item["category"] for item in findings))
    if "synthetic_canary" in categories:
        raise ToolOutputSecurityError("Tool result contained a synthetic canary")
    redacted, redacted_categories = redact_sensitive_data(value, canary)
    return {"text": redacted, "redacted_categories": redacted_categories}


async def _call_mcp_tool(
    url: str,
    bearer_token: str | None,
    remote_name: str,
    arguments: dict[str, Any],
) -> str:
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    timeout = httpx2.Timeout(TOOL_TIMEOUT_SECONDS, read=TOOL_TIMEOUT_SECONDS)
    async with httpx2.AsyncClient(headers=headers, timeout=timeout) as http_client:
        transport = streamable_http_client(
            url,
            http_client=http_client,
            max_sse_event_size=MAX_TOOL_RESULT_BYTES,
        )
        async with Client(transport, cache=None) as client:
            result = await client.call_tool(remote_name, arguments)

    if result.is_error:
        raise ToolPolicyError("MCP tool returned an error")
    if result.structured_content is not None:
        output = json.dumps(result.structured_content, ensure_ascii=False, allow_nan=False)
    else:
        text_blocks = []
        for block in result.content:
            if getattr(block, "type", None) != "text":
                continue
            text = getattr(block, "text", None)
            if not isinstance(text, str):
                raise ToolPolicyError("MCP tool returned unsupported content")
            text_blocks.append(text)
        if len(text_blocks) != len(result.content):
            raise ToolPolicyError("MCP tool returned unsupported content")
        output = "\n".join(text_blocks)
    return output


def get_authorized_tools() -> list[ToolDefinition]:
    allowed_builtins = _allowlist("BUILTIN_TOOL_ALLOWLIST")
    tools = [
        BUILTIN_TOOLS[name]
        for name in sorted(allowed_builtins)
        if name in BUILTIN_TOOLS
    ]

    allowed_mcp_tools = _allowlist("MCP_ALLOWED_TOOLS")
    server_url = os.environ.get("MCP_SERVER_URL", "").strip()
    if not allowed_mcp_tools:
        return tools
    if not server_url:
        raise ToolPolicyError("MCP_SERVER_URL is required for MCP_ALLOWED_TOOLS")
    validate_mcp_server_url(server_url)
    remote_tools = anyio.run(_list_mcp_tools, server_url, allowed_mcp_tools)
    names = {tool.name for tool in tools}
    for tool in remote_tools:
        if tool.name in names:
            raise ToolPolicyError("Built-in and MCP tool names must be unique")
        names.add(tool.name)
    return tools + remote_tools


async def _list_mcp_tools(
    server_url: str,
    allowed_tool_names: set[str],
) -> list[ToolDefinition]:
    bearer_token = os.environ.get("MCP_SERVER_BEARER_TOKEN", "").strip() or None
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    timeout = httpx2.Timeout(TOOL_TIMEOUT_SECONDS, read=TOOL_TIMEOUT_SECONDS)
    async with httpx2.AsyncClient(headers=headers, timeout=timeout) as http_client:
        transport = streamable_http_client(
            server_url,
            http_client=http_client,
            max_sse_event_size=MAX_SCHEMA_BYTES,
        )
        async with Client(transport, cache=None) as client:
            result = await client.list_tools()

    available = []
    for tool in result.tools:
        if tool.name not in allowed_tool_names:
            continue
        if not TOOL_NAME_PATTERN.fullmatch(tool.name):
            continue
        schema = validate_tool_schema(tool.input_schema)
        provider_name = f"mcp_{tool.name}"
        if not TOOL_NAME_PATTERN.fullmatch(provider_name):
            raise ToolPolicyError("MCP tool name cannot be safely exposed to the model")
        available.append(ToolDefinition(
            name=provider_name,
            description=(tool.description or tool.title or tool.name)[:1024],
            input_schema=schema,
            source="mcp",
            remote_name=tool.name,
            server_url=server_url,
        ))
        if len(available) >= MAX_TOOL_COUNT:
            break
    return available


def execute_approved_tool(
    tool: ToolDefinition,
    arguments: dict[str, Any],
    *,
    approved: bool,
    security_canary: str | None = None,
) -> dict[str, Any]:
    if approved is not True:
        raise PermissionError("Tool execution requires explicit approval")
    validated_arguments = validate_tool_arguments(tool, arguments)

    if tool.source == "builtin" and tool.name == "calculator":
        output = str(_evaluate_arithmetic(validated_arguments["expression"]))
    elif tool.source == "builtin" and tool.name == "sha256_text":
        output = hashlib.sha256(
            validated_arguments["text"].encode("utf-8")
        ).hexdigest()
    elif tool.source == "mcp" and tool.server_url and tool.remote_name:
        bearer_token = os.environ.get("MCP_SERVER_BEARER_TOKEN", "").strip() or None
        output = anyio.run(
            _call_mcp_tool,
            tool.server_url,
            bearer_token,
            tool.remote_name,
            validated_arguments,
        )
    else:
        raise ToolPolicyError("Tool is not registered")

    return _clean_tool_result(output, security_canary)