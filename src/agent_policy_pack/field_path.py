"""Safe field-path resolution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

MISSING = object()


def resolve_path(root: Mapping[str, Any], path: str) -> Any:
    """Resolve a dotted field path against a request mapping."""

    if not path or ".." in path or path.startswith(".") or path.endswith("."):
        return MISSING
    current: Any = root
    for part in path.split("."):
        if not part.replace("_", "").replace("-", "").isalnum():
            return MISSING
        if isinstance(current, Mapping):
            current = current.get(part, MISSING)
        elif isinstance(current, Sequence) and not isinstance(current, str) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else MISSING
        else:
            return MISSING
        if current is MISSING:
            return MISSING
    return current
