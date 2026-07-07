from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_policy_pack import __version__, digest_value, evaluate, load_bundle
from agent_policy_pack.cli import app
from agent_policy_pack.conditions import evaluate_condition
from agent_policy_pack.diffing import diff_bundles
from agent_policy_pack.exceptions import PolicyParseError
from agent_policy_pack.field_path import MISSING, resolve_path
from agent_policy_pack.loader import load_bundle as load_bundle_file
from agent_policy_pack.models import DecisionRequest, PolicyBundle
from agent_policy_pack.reports import render_csv
from agent_policy_pack.serialization import canonical_json
from agent_policy_pack.simulation import compare, load_requests, simulate
from agent_policy_pack.testing import coverage_report, run_policy_tests
from agent_policy_pack.validation import lint_bundle, validate_bundle

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "tool_governance" / "policy.yaml"
REQUEST = ROOT / "examples" / "tool_governance" / "allow-search-request.yaml"


def test_version_and_public_imports() -> None:
    assert __version__ == "0.1.0a1"
    assert load_bundle(EXAMPLE).bundle.id == "tool-governance"


def test_example_validate_lint_digest_and_test_runner() -> None:
    bundle = load_bundle(EXAMPLE)
    assert validate_bundle(bundle) == []
    assert [f.code for f in lint_bundle(bundle) if f.severity == "error"] == []
    assert len(digest_value(bundle)) == 64
    report = run_policy_tests(bundle)
    assert report["passed"] == 2
    assert coverage_report(bundle)["matched_percent"] > 0


def test_evaluate_allow_and_deny() -> None:
    bundle = load_bundle(EXAMPLE)
    request = DecisionRequest.model_validate(
        load_requests(ROOT / "examples" / "tool_governance" / "requests.yaml")[0]
    )
    decision = evaluate(bundle, request)
    assert decision.decision == "allow"
    assert decision.allowed
    assert decision.obligations[0].source_policy_id == "allow-research-search"
    assert any(
        limit.name == "max_cost_usd" and limit.limit == Decimal("0.05") for limit in decision.limits
    )

    deny = evaluate(
        bundle, load_requests(ROOT / "examples" / "tool_governance" / "requests.yaml")[1]
    )
    assert deny.decision == "deny"
    assert deny.controlling_policy_id == "deny-shell"


@pytest.mark.parametrize(
    ("operator", "left", "right", "expected"),
    [
        ("equals", "a", "a", True),
        ("not_equals", "a", "b", True),
        ("in", "a", ["a", "b"], True),
        ("not_in", "c", ["a"], True),
        ("contains", ["x"], "x", True),
        ("not_contains", ["x"], "y", True),
        ("exists", "x", None, True),
        ("not_exists", None, None, True),
        ("starts_with", "abc", "ab", True),
        ("ends_with", "abc", "bc", True),
        ("less_than", 1, 2, True),
        ("less_than_or_equal", 2, 2, True),
        ("greater_than", 3, 2, True),
        ("greater_than_or_equal", 3, 3, True),
        ("between", 2, [1, 3], True),
        ("matches_safe_pattern", "tool.read", "tool.*", True),
    ],
)
def test_condition_operators(operator: str, left: object, right: object, expected: bool) -> None:
    request = {"subject": {"value": left}}
    cond: dict[str, object] = {"field": "subject.value", "operator": operator}
    if operator not in {"exists", "not_exists"}:
        cond["value"] = right
    if operator == "not_exists":
        cond["field"] = "subject.missing"
    assert evaluate_condition(cond, request) is expected


def test_value_from_and_nested_conditions() -> None:
    request = {"subject": {"id": "a"}, "resource": {"owner": "a"}}
    condition = {
        "all": [{"field": "resource.owner", "operator": "equals", "value_from": "subject.id"}]
    }
    assert evaluate_condition(condition, request)
    assert not evaluate_condition({"not": condition}, request)


def test_field_path_and_missing_condition_branches() -> None:
    request = {"a": [{"b": 2}], "subject": {"value": "abc"}}
    assert resolve_path(request, "a.0.b") == 2
    assert resolve_path(request, ".bad") is MISSING
    assert not evaluate_condition(
        {"field": "subject.value", "operator": "matches_safe_pattern", "value": "(bad)+"}, request
    )
    assert not evaluate_condition(
        {"field": "subject.value", "operator": "equals", "value_from": "missing.path"}, request
    )
    assert not evaluate_condition({"all": []}, request)
    assert evaluate_condition(
        {"any": [{"field": "subject.value", "operator": "equals", "value": "abc"}]}, request
    )
    assert not evaluate_condition({"field": "subject.value", "operator": "not_in"}, request)
    assert not evaluate_condition({"field": "subject.value", "operator": "not_contains"}, request)


def test_conflict_strategies() -> None:
    raw = {
        "schema_version": "1.0",
        "bundle": {
            "id": "b",
            "name": "B",
            "version": "1.0.0",
            "namespace": "example.b",
            "default_decision": "deny",
            "conflict_strategy": "allow_overrides",
        },
        "policies": [
            {"id": "deny", "effect": "deny", "priority": 1, "targets": {"actions": ["x"]}},
            {"id": "allow", "effect": "allow", "priority": 2, "targets": {"actions": ["x"]}},
        ],
    }
    request = DecisionRequest(action="x")
    assert evaluate(PolicyBundle.model_validate(raw), request).decision == "allow"
    raw["bundle"]["conflict_strategy"] = "deny_overrides"
    assert evaluate(PolicyBundle.model_validate(raw), request).decision == "deny"
    raw["bundle"]["conflict_strategy"] = "only_one_applicable"
    assert evaluate(PolicyBundle.model_validate(raw), request).decision == "indeterminate"
    raw["bundle"]["conflict_strategy"] = "highest_priority"
    assert evaluate(PolicyBundle.model_validate(raw), request).decision == "allow"
    raw["bundle"]["conflict_strategy"] = "first_applicable"
    assert evaluate(PolicyBundle.model_validate(raw), request).decision == "allow"


def test_determinism_equivalent_yaml_json_and_reports(tmp_path: Path) -> None:
    bundle = load_bundle(EXAMPLE)
    json_path = tmp_path / "policy.json"
    json_path.write_text(canonical_json(bundle), encoding="utf-8")
    assert digest_value(load_bundle(json_path)) == digest_value(bundle)
    request = DecisionRequest.model_validate(
        load_requests(ROOT / "examples" / "tool_governance" / "requests.yaml")[0]
    )
    first = evaluate(bundle, request)
    second = evaluate(bundle, request)
    assert first.decision_id == second.decision_id
    assert canonical_json(first) == canonical_json(second)


def test_simulation_compare_and_diff() -> None:
    bundle = load_bundle(EXAMPLE)
    requests = load_requests(ROOT / "examples" / "tool_governance" / "requests.yaml")
    report = simulate(bundle, requests)
    assert report["summary"]["allow"] == 1  # type: ignore[index]
    old = load_bundle(ROOT / "tests" / "fixtures" / "diff" / "policy-v1.yaml")
    new = load_bundle(ROOT / "tests" / "fixtures" / "diff" / "policy-v2.yaml")
    assert diff_bundles(old, new)["summary"]["security_relaxation"] >= 1  # type: ignore[index]
    assert (
        compare(old, new, load_requests(ROOT / "tests" / "fixtures" / "diff" / "requests.yaml"))[
            "changed"
        ]
        >= 1
    )


def test_loader_rejects_unsafe_and_duplicate_yaml(tmp_path: Path) -> None:
    dup = tmp_path / "dup.yaml"
    dup.write_text("schema_version: '1.0'\nschema_version: '1.0'\n", encoding="utf-8")
    with pytest.raises(PolicyParseError):
        load_bundle_file(dup)
    unsafe = tmp_path / "unsafe.yaml"
    unsafe.write_text("!!python/object/apply:os.system ['echo bad']", encoding="utf-8")
    with pytest.raises(PolicyParseError):
        load_bundle_file(unsafe)
    dup_json = tmp_path / "dup.json"
    dup_json.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(PolicyParseError):
        load_bundle_file(dup_json)
    with pytest.raises(PolicyParseError):
        load_bundle_file(tmp_path / "missing.yaml")


def test_csv_formula_escape() -> None:
    assert "'=cmd" in render_csv([{"value": "=cmd"}])
    heterogeneous = render_csv([{"b": "2"}, {"a": "1"}])
    assert heterogeneous.splitlines()[0] == "a,b"
    assert render_csv([]) == ""


def test_invalid_bundle_fails_closed_and_validation_branches() -> None:
    raw = {
        "schema_version": "2.0",
        "bundle": {
            "id": "bad id",
            "name": "B",
            "version": "nope",
            "namespace": "bad namespace",
            "default_decision": "deny",
            "conflict_strategy": "allow_overrides",
        },
        "policies": [
            {
                "id": "p",
                "effect": "allow",
                "priority": -1,
                "targets": {},
                "conditions": {
                    "field": "bad..path",
                    "operator": "similar_to",
                    "value": "x",
                    "value_from": "also.bad",
                },
                "obligations": [{"type": "custom"}],
                "limits": {"max_tool_calls": -1},
            },
            {"id": "p", "effect": "deny", "priority": 0, "targets": {"actions": ["x"]}},
        ],
        "tests": [
            {"id": "t", "request": {"action": "x"}, "expect_decision": "allow"},
            {"id": "t", "request": {"action": "x"}, "expect_decision": "deny"},
        ],
    }
    bundle = PolicyBundle.model_validate(raw)
    findings = validate_bundle(bundle)
    assert any(item.code == "UNSUPPORTED_SCHEMA_VERSION" for item in findings)
    decision = evaluate(bundle, DecisionRequest(action="x"))
    assert decision.decision == "indeterminate"
    assert decision.effective_decision == "deny"


def test_missing_condition_value_is_validation_error() -> None:
    raw = {
        "schema_version": "1.0",
        "bundle": {
            "id": "missing-condition-value",
            "name": "Missing Condition Value",
            "version": "1.0.0",
            "namespace": "example.missing_condition_value",
            "default_decision": "deny",
            "conflict_strategy": "deny_overrides",
        },
        "policies": [
            {
                "id": "bad-condition",
                "effect": "allow",
                "priority": 1,
                "targets": {"actions": ["x"]},
                "conditions": {"field": "action", "operator": "not_in"},
            }
        ],
    }
    bundle = PolicyBundle.model_validate(raw)
    assert any(finding.code == "MISSING_CONDITION_VALUE" for finding in validate_bundle(bundle))
    assert evaluate(bundle, DecisionRequest(action="x")).decision == "indeterminate"


def test_missing_target_object_does_not_match_allow_policy() -> None:
    raw = {
        "schema_version": "1.0",
        "bundle": {
            "id": "target-bug",
            "name": "Target Bug",
            "version": "1.0.0",
            "namespace": "example.target_bug",
            "default_decision": "deny",
            "conflict_strategy": "deny_overrides",
        },
        "policies": [
            {
                "id": "allow-search-tool",
                "effect": "allow",
                "priority": 10,
                "targets": {"tools": {"names": ["search"]}, "actions": ["tool.call"]},
            }
        ],
    }
    decision = evaluate(PolicyBundle.model_validate(raw), DecisionRequest(action="tool.call"))
    assert decision.decision == "deny"
    assert decision.matched_policy_ids == ()


def test_invalid_limit_context_fails_closed() -> None:
    bundle = load_bundle(EXAMPLE)
    request = DecisionRequest.model_validate(
        load_requests(ROOT / "examples" / "tool_governance" / "requests.yaml")[0]
    )
    bad_request = request.model_copy(
        update={"context": {"estimated_cost_usd": "0.01", "tool_calls": "many"}}
    )
    decision = evaluate(bundle, bad_request)
    assert decision.decision == "indeterminate"
    assert decision.effective_decision == "deny"
    assert any(finding.code == "INVALID_LIMIT_CONTEXT" for finding in decision.findings)


def test_unsafe_action_target_pattern_fails_closed() -> None:
    raw = {
        "schema_version": "1.0",
        "bundle": {
            "id": "unsafe-target",
            "name": "Unsafe Target",
            "version": "1.0.0",
            "namespace": "example.unsafe_target",
            "default_decision": "deny",
            "conflict_strategy": "deny_overrides",
        },
        "policies": [
            {
                "id": "bad-pattern",
                "effect": "allow",
                "priority": 1,
                "targets": {"actions": ["tool.(call)+"]},
            }
        ],
    }
    bundle = PolicyBundle.model_validate(raw)
    assert any(finding.code == "UNSAFE_TARGET_PATTERN" for finding in validate_bundle(bundle))
    decision = evaluate(bundle, DecisionRequest(action="tool.call"))
    assert decision.decision == "indeterminate"


def test_cli_acceptance_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    commands = [
        ["validate", str(EXAMPLE)],
        ["lint", str(EXAMPLE)],
        ["inspect", str(EXAMPLE)],
        ["normalize", str(EXAMPLE)],
        ["digest", str(EXAMPLE)],
        ["evaluate", str(EXAMPLE), "--request", str(REQUEST)],
        ["test", str(EXAMPLE)],
        ["coverage", str(EXAMPLE)],
        [
            "simulate",
            str(EXAMPLE),
            "--requests",
            str(ROOT / "examples" / "tool_governance" / "requests.yaml"),
        ],
        [
            "diff",
            str(ROOT / "tests" / "fixtures" / "diff" / "policy-v1.yaml"),
            str(ROOT / "tests" / "fixtures" / "diff" / "policy-v2.yaml"),
        ],
        [
            "compare",
            str(ROOT / "tests" / "fixtures" / "diff" / "policy-v1.yaml"),
            str(ROOT / "tests" / "fixtures" / "diff" / "policy-v2.yaml"),
            "--requests",
            str(ROOT / "tests" / "fixtures" / "diff" / "requests.yaml"),
        ],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.output
    out = tmp_path / "report.json"
    assert runner.invoke(app, ["test", str(EXAMPLE), "--output", str(out)]).exit_code == 0
    assert out.read_text(encoding="utf-8").startswith("{")
    bad_requests = tmp_path / "bad-requests.yaml"
    bad_requests.write_text("requests: nope\n", encoding="utf-8")
    bad_result = runner.invoke(app, ["simulate", str(EXAMPLE), "--requests", str(bad_requests)])
    assert bad_result.exit_code == 2
    assert "Request batch must contain a requests list" in bad_result.output
