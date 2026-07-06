"""Deterministic target matching."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import Any

from .conditions import is_safe_pattern


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _match_patterns(value: str, patterns: list[Any]) -> bool:
    return not patterns or any(
        isinstance(p, str) and is_safe_pattern(p) and fnmatch.fnmatchcase(value, p)
        for p in patterns
    )


def _match_any(actual: Any, expected: Any) -> bool:
    values = _as_list(actual)
    expected_values = _as_list(expected)
    return not expected_values or any(item in values for item in expected_values)


def _match_attributes(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def matches_targets(targets: dict[str, Any], request: dict[str, Any]) -> bool:
    """Return whether a request matches policy targets."""

    subject = _mapping_or_empty(request.get("subject"))
    resource = _mapping_or_empty(request.get("resource"))
    tool = _mapping_or_empty(request.get("tool"))
    model = _mapping_or_empty(request.get("model"))
    provider = _mapping_or_empty(request.get("provider")) or model
    environment = _mapping_or_empty(request.get("environment"))

    st = targets.get("subjects") or targets.get("subject") or {}
    if st:
        if st.get("ids") and subject.get("id") not in st["ids"]:
            return False
        if st.get("types") and subject.get("type") not in st["types"]:
            return False
        if st.get("roles") and not _match_any(subject.get("roles"), st["roles"]):
            return False
        if st.get("groups") and not _match_any(subject.get("groups"), st["groups"]):
            return False
        if st.get("trust_levels") and subject.get("trust_level") not in st["trust_levels"]:
            return False
        if st.get("attributes") and not _match_attributes(
            subject.get("attributes") or {}, st["attributes"]
        ):
            return False

    actions = targets.get("actions")
    if actions and not _match_patterns(str(request.get("action", "")), _as_list(actions)):
        return False

    rt = targets.get("resources") or targets.get("resource") or {}
    if rt:
        if rt.get("ids") and resource.get("id") not in rt["ids"]:
            return False
        if rt.get("types") and resource.get("type") not in rt["types"]:
            return False
        if rt.get("namespaces") and resource.get("namespace") not in rt["namespaces"]:
            return False
        if (
            rt.get("classifications")
            and (
                resource.get("classification")
                or (resource.get("attributes") or {}).get("classification")
            )
            not in rt["classifications"]
        ):
            return False
        if rt.get("attributes") and not _match_attributes(
            resource.get("attributes") or {}, rt["attributes"]
        ):
            return False

    tt = targets.get("tools") or targets.get("tool") or {}
    if tt:
        if not tool:
            return False
        if tt.get("names") and tool.get("name") not in tt["names"]:
            return False
        if tt.get("namespaces") and tool.get("namespace") not in tt["namespaces"]:
            return False
        if tt.get("capabilities") and not _match_any(tool.get("capabilities"), tt["capabilities"]):
            return False
        if (
            tt.get("risks")
            and (tool.get("risk") or tool.get("risk_classification")) not in tt["risks"]
        ):
            return False

    mt = targets.get("models") or targets.get("model") or {}
    if mt:
        if not model:
            return False
        if mt.get("providers") and model.get("provider") not in mt["providers"]:
            return False
        if mt.get("names") and model.get("name") not in mt["names"]:
            return False
        if mt.get("families") and model.get("family") not in mt["families"]:
            return False
        if mt.get("hosting") and model.get("hosting") not in mt["hosting"]:
            return False

    pt = targets.get("providers") or targets.get("provider") or {}
    if pt:
        if not provider:
            return False
        if pt.get("names") and provider.get("name", provider.get("provider")) not in pt["names"]:
            return False
        if pt.get("trust_levels") and provider.get("trust_level") not in pt["trust_levels"]:
            return False
        if pt.get("localities") and provider.get("locality") not in pt["localities"]:
            return False

    et = targets.get("environments") or targets.get("environment") or {}
    if et:
        names = et if isinstance(et, list) else et.get("names", [])
        if names and environment.get("name") not in names:
            return False
    return True
