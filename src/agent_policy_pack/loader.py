"""Safe YAML and JSON loading."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .constants import MAX_BUNDLE_BYTES
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
            data = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506  # nosec B506
        elif suffix == ".json":
            data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
        else:
            raise PolicyParseError(f"Unsupported file extension {suffix!r}.")
    except PolicyParseError:
        raise
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise PolicyParseError(f"Could not parse policy input: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyParseError("Policy input must be a mapping/object.")
    return data


def load_bundle(path: str | Path) -> PolicyBundle:
    """Load a policy bundle file into the typed internal representation."""

    try:
        return PolicyBundle.model_validate(load_raw(path))
    except ValidationError as exc:
        raise PolicyParseError(str(exc)) from exc
