"""Safe structured condition evaluation."""

from __future__ import annotations

import fnmatch
from decimal import Decimal, InvalidOperation
from typing import Any

from .constants import MAX_CONDITION_DEPTH, MAX_PATTERN_INPUT_LENGTH, MAX_PATTERN_LENGTH, OPERATORS
from .field_path import MISSING, resolve_path


def is_safe_pattern(pattern: str) -> bool:
    """Return whether a glob pattern is within the supported safe subset."""

    if len(pattern) > MAX_PATTERN_LENGTH:
        return False
    return all(ch not in pattern for ch in "{}()|+\\")


def _decimal(value: Any) -> Decimal | None:
    try:
        if isinstance(value, bool):
            return None
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == "equals":
        return bool(left == right)
    if op == "not_equals":
        return bool(left != right)
    if op == "in":
        return bool(isinstance(right, (list, tuple, set, str)) and left in right)
    if op == "not_in":
        # Negative operators still fail closed when the operand shape is invalid.
        return bool(isinstance(right, (list, tuple, set, str)) and left not in right)
    if op == "contains":
        return bool(isinstance(left, (list, tuple, set, str, dict)) and right in left)
    if op == "not_contains":
        return bool(isinstance(left, (list, tuple, set, str, dict)) and right not in left)
    if op == "starts_with":
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    if op == "ends_with":
        return isinstance(left, str) and isinstance(right, str) and left.endswith(right)
    if op == "matches_safe_pattern":
        return (
            isinstance(left, str)
            and isinstance(right, str)
            and len(left) <= MAX_PATTERN_INPUT_LENGTH
            and is_safe_pattern(right)
            and fnmatch.fnmatchcase(left, right)
        )
    if op == "between":
        if not isinstance(right, (list, tuple)) or len(right) != 2:
            return False
        left_d, low, high = _decimal(left), _decimal(right[0]), _decimal(right[1])
        return left_d is not None and low is not None and high is not None and low <= left_d <= high
    if op in {"less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"}:
        left_d, right_d = _decimal(left), _decimal(right)
        if left_d is None or right_d is None:
            return False
        if op == "less_than":
            return left_d < right_d
        if op == "less_than_or_equal":
            return left_d <= right_d
        if op == "greater_than":
            return left_d > right_d
        return left_d >= right_d
    return False


def evaluate_condition(
    condition: dict[str, Any] | None, request: dict[str, Any], depth: int = 0
) -> bool:
    """Evaluate a condition tree without dynamic code execution."""

    if condition is None or condition == {}:
        return True
    if depth > MAX_CONDITION_DEPTH:
        return False
    if "all" in condition:
        values = condition.get("all")
        return (
            isinstance(values, list)
            and bool(values)
            and all(evaluate_condition(item, request, depth + 1) for item in values)
        )
    if "any" in condition:
        values = condition.get("any")
        return isinstance(values, list) and any(
            evaluate_condition(item, request, depth + 1) for item in values
        )
    if "not" in condition:
        value = condition.get("not")
        return isinstance(value, dict) and not evaluate_condition(value, request, depth + 1)

    field = condition.get("field")
    op = condition.get("operator")
    if not isinstance(field, str) or op not in OPERATORS:
        return False
    left = resolve_path(request, field)
    if op == "exists":
        return left is not MISSING and left is not None
    if op == "not_exists":
        return left is MISSING or left is None
    if left is MISSING:
        return False
    if "value" not in condition and "value_from" not in condition:
        return False
    right = (
        resolve_path(request, condition["value_from"])
        if isinstance(condition.get("value_from"), str)
        else condition.get("value")
    )
    if right is MISSING:
        return False
    return _compare(left, op, right)
