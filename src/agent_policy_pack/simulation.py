"""Batch simulation and bundle comparison."""

from __future__ import annotations

from pathlib import Path

from .evaluator import evaluate
from .loader import load_raw
from .models import DecisionRequest, PolicyBundle


def load_requests(path: str | Path) -> list[DecisionRequest]:
    """Load a request list from YAML or JSON."""

    data = load_raw(path)
    items = data.get("requests", data.get("items", []))
    if not isinstance(items, list):
        raise ValueError("Request batch must contain a requests list.")
    if len(items) > 1_000:
        raise ValueError("Request batch exceeds the maximum supported size.")
    return [DecisionRequest.model_validate(item) for item in items]


def simulate(bundle: PolicyBundle, requests: list[DecisionRequest]) -> dict[str, object]:
    """Evaluate a batch of requests and summarize decisions."""

    results = [evaluate(bundle, request) for request in requests]
    counts = {
        name: sum(1 for result in results if result.decision == name)
        for name in ("allow", "deny", "require_review", "indeterminate")
    }
    return {
        "total": len(results),
        "summary": counts,
        "results": [result.model_dump(mode="json", exclude_none=True) for result in results],
    }


def compare(
    old: PolicyBundle, new: PolicyBundle, requests: list[DecisionRequest]
) -> dict[str, object]:
    """Compare decisions between two bundles for the same request batch."""

    changes: list[dict[str, object]] = []
    for index, request in enumerate(requests):
        before = evaluate(old, request)
        after = evaluate(new, request)
        if (
            before.decision != after.decision
            or before.obligations != after.obligations
            or before.limits != after.limits
        ):
            changes.append(
                {
                    "index": index,
                    "before": before.decision,
                    "after": after.decision,
                    "new_allow": before.decision != "allow" and after.decision == "allow",
                    "new_deny": before.decision != "deny" and after.decision == "deny",
                    "changed_obligations": before.obligations != after.obligations,
                    "changed_limits": before.limits != after.limits,
                }
            )
    return {"total": len(requests), "changed": len(changes), "changes": changes}
