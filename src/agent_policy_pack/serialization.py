"""Deterministic serialization, normalization, and digests."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

from pydantic import BaseModel


def to_plain(value: Any) -> Any:
    """Convert models and Decimals into canonical JSON-compatible values."""

    if isinstance(value, BaseModel):
        return to_plain(value.model_dump(mode="python", exclude_none=True))
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, dict):
        return {str(key): to_plain(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Serialize a value as stable canonical JSON."""

    return json.dumps(to_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_value(value: Any) -> str:
    """Return a SHA-256 digest for canonical JSON."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
