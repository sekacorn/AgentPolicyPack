"""Safe YAML and JSON loading."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .constants import MAX_BUNDLE_BYTES, MAX_INPUT_DEPTH, MAX_INPUT_NODES
from .exceptions import PolicyParseError, UnsafeInputError
from .models import PolicyBundle


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise PolicyParseError("YAML mapping keys must be strings.")
        if key in mapping:
            raise PolicyParseError(f"Duplicate key {key!r} in YAML mapping.")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def read_text(path: Path, max_bytes: int = MAX_BUNDLE_BYTES) -> str:
    """Read a local UTF-8 policy input under the size limit."""

    if str(path).startswith(("http://", "https://")):
        raise UnsafeInputError("Remote URLs are not supported for policy input.")
    try:
        if path.stat().st_size > max_bytes:
            raise UnsafeInputError(f"Input exceeds size limit of {max_bytes} bytes.")
        text = path.read_text(encoding="utf-8")
    except UnsafeInputError:
        raise
    except OSError as exc:
        raise PolicyParseError(f"Could not read input file: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyParseError("Input must be valid UTF-8.") from exc
    if not text.strip():
        raise PolicyParseError("Input file is empty.")
    if any((ord(ch) < 32 and ch not in "\n\r\t") for ch in text):
        raise UnsafeInputError("Input contains unsafe control characters.")
    return text


def _reject_duplicate_json_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise PolicyParseError(f"Duplicate key {key!r} in JSON object.")
        data[key] = value
    return data


def _check_json_depth(text: str) -> None:
    """Reject overly nested JSON before handing it to the recursive decoder."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_INPUT_DEPTH:
                raise UnsafeInputError("Input nesting exceeds the supported limit.")
        elif character in "]}":
            depth -= 1


def _check_yaml_events(text: str) -> None:
    """Reject YAML graph features and bound nesting before object construction."""

    depth = 0
    nodes = 0
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.NodeEvent) and getattr(event, "anchor", None):
                raise UnsafeInputError("YAML anchors and aliases are not supported.")
            if isinstance(event, yaml.events.NodeEvent) and getattr(event, "tag", None):
                raise UnsafeInputError("Explicit YAML tags are not supported.")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                nodes += 1
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            elif isinstance(event, yaml.events.ScalarEvent):
                nodes += 1
            if depth > MAX_INPUT_DEPTH:
                raise UnsafeInputError("Input nesting exceeds the supported limit.")
            if nodes > MAX_INPUT_NODES:
                raise UnsafeInputError("Input contains too many values.")
    except UnsafeInputError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"Could not parse policy input: {exc}") from exc


def _validate_plain_structure(data: object) -> None:
    """Bound parsed JSON-shaped data and reject non-finite numbers."""

    stack: list[tuple[object, int]] = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_INPUT_NODES:
            raise UnsafeInputError("Input contains too many values.")
        if depth > MAX_INPUT_DEPTH:
            raise UnsafeInputError("Input nesting exceeds the supported limit.")
        if isinstance(value, float) and not math.isfinite(value):
            raise UnsafeInputError("Input contains a non-finite numeric value.")
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise PolicyParseError("Input mapping keys must be strings.")
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def load_raw(path: str | Path) -> dict[str, Any]:
    """Load YAML or JSON into plain Python data without executing code."""

    if isinstance(path, str) and path.startswith(("http://", "https://")):
        raise UnsafeInputError("Remote URLs are not supported for policy input.")
    policy_path = Path(path)
    suffix = policy_path.suffix.lower()
    text = read_text(policy_path)
    try:
        if suffix in {".yaml", ".yml"}:
            # UniqueKeyLoader subclasses SafeLoader and adds duplicate-key rejection.
            _check_yaml_events(text)
            data = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506  # nosec B506
        elif suffix == ".json":
            _check_json_depth(text)
            data = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    UnsafeInputError(f"Unsupported JSON numeric constant {value!r}.")
                ),
            )
        else:
            raise PolicyParseError(f"Unsupported file extension {suffix!r}.")
    except PolicyParseError:
        raise
    except (yaml.YAMLError, json.JSONDecodeError, RecursionError) as exc:
        raise PolicyParseError(f"Could not parse policy input: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyParseError("Policy input must be a mapping/object.")
    _validate_plain_structure(data)
    return data


def load_bundle(path: str | Path) -> PolicyBundle:
    """Load a policy bundle file into the typed internal representation."""

    try:
        return PolicyBundle.model_validate(load_raw(path))
    except ValidationError as exc:
        raise PolicyParseError(str(exc)) from exc
