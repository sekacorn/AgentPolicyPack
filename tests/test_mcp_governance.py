"""The MCP governance example: server connect and tool call requests as AgentForge sends them.

No library code is specific to MCP. These tests prove the existing targets
(resource ids, types and attributes; tool names and namespaces) express the
policies an operator needs, and that requests in AgentForge's shape validate.
"""

from __future__ import annotations

from pathlib import Path

from agent_policy_pack import evaluate, load_bundle
from agent_policy_pack.models import DecisionRequest
from agent_policy_pack.testing import run_policy_tests
from agent_policy_pack.validation import lint_bundle, validate_bundle

EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "mcp_governance"
    / "mcp-servers-and-tools.yaml"
)


def test_the_example_validates_and_passes_its_own_tests() -> None:
    bundle = load_bundle(EXAMPLE)
    assert validate_bundle(bundle) == []
    assert [f.code for f in lint_bundle(bundle) if f.severity == "error"] == []
    report = run_policy_tests(bundle)
    assert report["failed"] == 0 and report["total"] == len(bundle.tests) == 7


def test_the_example_folder_holds_exactly_the_documented_example() -> None:
    assert {p.name for p in EXAMPLE.parent.glob("*.yaml")} == {EXAMPLE.name}


def test_a_connect_request_without_hosting_falls_to_deny() -> None:
    bundle = load_bundle(EXAMPLE)
    request = DecisionRequest.model_validate(
        {"action": "mcp.server.connect", "resource": {"id": "files", "type": "McpServer"}}
    )
    assert evaluate(bundle, request).decision == "deny"


def test_a_tool_call_without_a_tool_block_is_denied() -> None:
    bundle = load_bundle(EXAMPLE)
    request = DecisionRequest.model_validate(
        {"action": "tool.call", "resource": {"id": "files/search", "type": "McpTool"}}
    )
    assert evaluate(bundle, request).decision == "deny"
