"""Structural, semantic, and lint validation."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from .conditions import is_safe_pattern
from .constants import (
    CONFLICT_STRATEGIES,
    EFFECTS,
    MAX_CONDITION_DEPTH,
    OBLIGATION_TYPES,
    OPERATORS,
    SCHEMA_VERSION,
)
from .models import Finding, PolicyBundle

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_NS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$")
_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$")


def _finding(
    severity: Literal["error", "warning", "information"],
    code: str,
    message: str,
    path: str,
    suggestion: str = "",
) -> Finding:
    return Finding(severity=severity, code=code, message=message, path=path, suggestion=suggestion)


def _validate_condition(value: Any, path: str, depth: int = 0) -> list[Finding]:
    findings: list[Finding] = []
    if depth > MAX_CONDITION_DEPTH:
        return [
            _finding("error", "CONDITION_DEPTH_EXCEEDED", "Condition nesting is too deep.", path)
        ]
    if not isinstance(value, dict):
        return [_finding("error", "INVALID_CONDITION", "Condition must be a mapping.", path)]
    group_keys = [key for key in ("all", "any", "not") if key in value]
    if group_keys:
        if len(group_keys) > 1 or any(
            key in value for key in ("field", "operator", "value", "value_from")
        ):
            findings.append(
                _finding(
                    "error",
                    "INVALID_CONDITION_SHAPE",
                    "Condition mixes group and leaf forms.",
                    path,
                )
            )
        for key in ("all", "any"):
            if key in value:
                children = value[key]
                if not isinstance(children, list) or not children:
                    findings.append(
                        _finding(
                            "error",
                            "INVALID_CONDITION_GROUP",
                            f"{key} must be a non-empty list.",
                            f"{path}.{key}",
                        )
                    )
                else:
                    for index, child in enumerate(children):
                        findings.extend(
                            _validate_condition(child, f"{path}.{key}[{index}]", depth + 1)
                        )
        if "not" in value:
            findings.extend(_validate_condition(value["not"], f"{path}.not", depth + 1))
        return findings
    field = value.get("field")
    op = value.get("operator")
    if not isinstance(field, str) or not _FIELD_RE.match(field):
        findings.append(
            _finding(
                "error", "INVALID_FIELD_PATH", "Condition field path is invalid.", f"{path}.field"
            )
        )
    if op not in OPERATORS:
        findings.append(
            _finding(
                "error",
                "UNKNOWN_CONDITION_OPERATOR",
                f"Unsupported operator {op!r}.",
                f"{path}.operator",
            )
        )
    if "value" in value and "value_from" in value:
        findings.append(
            _finding(
                "error",
                "AMBIGUOUS_CONDITION_VALUE",
                "Use either value or value_from, not both.",
                path,
            )
        )
    if op not in {"exists", "not_exists"} and "value" not in value and "value_from" not in value:
        findings.append(
            _finding(
                "error",
                "MISSING_CONDITION_VALUE",
                "Condition operator requires value or value_from.",
                path,
            )
        )
    if "value_from" in value and (
        not isinstance(value["value_from"], str) or not _FIELD_RE.match(value["value_from"])
    ):
        findings.append(
            _finding(
                "error",
                "INVALID_VALUE_FROM_PATH",
                "value_from path is invalid.",
                f"{path}.value_from",
            )
        )
    if op == "between":
        numbers = value.get("value")
        if not isinstance(numbers, list) or len(numbers) != 2:
            findings.append(
                _finding(
                    "error",
                    "INVALID_NUMERIC_RANGE",
                    "between requires two values.",
                    f"{path}.value",
                )
            )
        else:
            try:
                if Decimal(str(numbers[0])) > Decimal(str(numbers[1])):
                    findings.append(
                        _finding(
                            "error",
                            "IMPOSSIBLE_NUMERIC_RANGE",
                            "Range lower bound exceeds upper bound.",
                            f"{path}.value",
                        )
                    )
            except InvalidOperation:
                findings.append(
                    _finding(
                        "error",
                        "INVALID_DECIMAL",
                        "Range values must be decimals.",
                        f"{path}.value",
                    )
                )
    if (
        op == "matches_safe_pattern"
        and isinstance(value.get("value"), str)
        and not is_safe_pattern(value["value"])
    ):
        findings.append(
            _finding(
                "error",
                "UNSAFE_PATTERN",
                "Pattern is outside the supported safe glob subset.",
                f"{path}.value",
            )
        )
    return findings


def _validate_target_patterns(targets: dict[str, Any], path: str) -> list[Finding]:
    findings: list[Finding] = []
    actions = targets.get("actions")
    if actions is None:
        return findings
    patterns = actions if isinstance(actions, list) else [actions]
    for index, pattern in enumerate(patterns):
        if isinstance(pattern, str) and not is_safe_pattern(pattern):
            findings.append(
                _finding(
                    "error",
                    "UNSAFE_TARGET_PATTERN",
                    "Action target pattern is outside the supported safe glob subset.",
                    f"{path}.actions[{index}]",
                )
            )
    return findings


def validate_bundle(bundle: PolicyBundle) -> list[Finding]:
    """Return validation findings for a bundle."""

    findings: list[Finding] = []
    if bundle.schema_version != SCHEMA_VERSION:
        findings.append(
            _finding(
                "error",
                "UNSUPPORTED_SCHEMA_VERSION",
                "Unsupported schema version.",
                "schema_version",
            )
        )
    if not bundle.bundle.id or not _ID_RE.match(bundle.bundle.id):
        findings.append(
            _finding("error", "INVALID_BUNDLE_ID", "Bundle id is invalid.", "bundle.id")
        )
    try:
        Version(bundle.bundle.version)
    except InvalidVersion:
        findings.append(
            _finding(
                "error", "INVALID_SEMANTIC_VERSION", "Bundle version is invalid.", "bundle.version"
            )
        )
    if not _NS_RE.match(bundle.bundle.namespace):
        findings.append(
            _finding(
                "error", "INVALID_NAMESPACE", "Bundle namespace is invalid.", "bundle.namespace"
            )
        )
    if bundle.bundle.conflict_strategy not in CONFLICT_STRATEGIES:
        findings.append(
            _finding(
                "error",
                "INVALID_CONFLICT_STRATEGY",
                "Conflict strategy is unsupported.",
                "bundle.conflict_strategy",
            )
        )
    if bundle.bundle.conflict_strategy == "allow_overrides":
        findings.append(
            _finding(
                "warning",
                "DANGEROUS_ALLOW_OVERRIDES",
                "allow_overrides can relax denies.",
                "bundle.conflict_strategy",
            )
        )
    seen: set[str] = set()
    for index, policy in enumerate(bundle.policies):
        ppath = f"policies[{index}]"
        if not policy.id or not _ID_RE.match(policy.id):
            findings.append(
                _finding("error", "INVALID_POLICY_ID", "Policy id is invalid.", f"{ppath}.id")
            )
        if policy.id in seen:
            findings.append(
                _finding(
                    "error",
                    "DUPLICATE_POLICY_ID",
                    f"Duplicate policy id {policy.id!r}.",
                    f"{ppath}.id",
                )
            )
        seen.add(policy.id)
        if policy.effect not in EFFECTS:
            findings.append(
                _finding(
                    "error", "INVALID_EFFECT", "Policy effect is unsupported.", f"{ppath}.effect"
                )
            )
        if policy.priority < 0:
            findings.append(
                _finding(
                    "error",
                    "INVALID_PRIORITY",
                    "Priority must be non-negative.",
                    f"{ppath}.priority",
                )
            )
        if not policy.targets:
            findings.append(
                _finding(
                    "warning",
                    "POLICY_WITH_NO_TARGETS",
                    "Policy has no targets and may be broad.",
                    f"{ppath}.targets",
                )
            )
        findings.extend(_validate_target_patterns(policy.targets, f"{ppath}.targets"))
        if policy.conditions is not None:
            findings.extend(_validate_condition(policy.conditions, f"{ppath}.conditions"))
        for oindex, obligation in enumerate(policy.obligations):
            if obligation.type not in OBLIGATION_TYPES and "." not in obligation.type:
                findings.append(
                    _finding(
                        "error",
                        "UNKNOWN_OBLIGATION_TYPE",
                        "Unknown obligation type needs an extension namespace.",
                        f"{ppath}.obligations[{oindex}].type",
                    )
                )
        if policy.limits is not None:
            for key, value in policy.limits.model_dump().items():
                if value is not None and value < 0:
                    findings.append(
                        _finding(
                            "error",
                            "INVALID_LIMIT",
                            "Limits must be non-negative.",
                            f"{ppath}.limits.{key}",
                        )
                    )
    seen_tests: set[str] = set()
    for index, test in enumerate(bundle.tests):
        if test.id in seen_tests:
            findings.append(
                _finding(
                    "error", "DUPLICATE_TEST_ID", "Duplicate policy test id.", f"tests[{index}].id"
                )
            )
        seen_tests.add(test.id)
    return sorted(findings, key=lambda f: (f.severity, f.path, f.code, f.message))


def lint_bundle(bundle: PolicyBundle) -> list[Finding]:
    """Return advisory lint findings."""

    findings = validate_bundle(bundle)
    targeted = [policy for policy in bundle.policies if policy.targets]
    if not targeted:
        findings.append(
            _finding(
                "warning", "NO_TARGETED_POLICIES", "Bundle has no targeted policies.", "policies"
            )
        )
    if not bundle.tests:
        findings.append(
            _finding("warning", "NO_POLICY_TESTS", "Bundle contains no policy tests.", "tests")
        )
    return sorted(findings, key=lambda f: (f.severity, f.path, f.code, f.message))


def has_errors(findings: list[Finding]) -> bool:
    """Return whether findings contain errors."""

    return any(finding.severity == "error" for finding in findings)
