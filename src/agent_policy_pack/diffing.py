"""Conservative rule-based policy diffing."""

from __future__ import annotations

from .models import PolicyBundle
from .serialization import canonical_json


def diff_bundles(old: PolicyBundle, new: PolicyBundle) -> dict[str, object]:
    """Classify notable changes between two policy bundles."""

    old_policies = {policy.id: policy for policy in old.policies}
    new_policies = {policy.id: policy for policy in new.policies}
    changes: list[dict[str, str]] = []
    for policy_id in sorted(old_policies.keys() - new_policies.keys()):
        effect = old_policies[policy_id].effect
        category = "security_relaxation" if effect == "deny" else "potentially_breaking"
        changes.append({"category": category, "policy_id": policy_id, "message": "Policy removed."})
    for policy_id in sorted(new_policies.keys() - old_policies.keys()):
        effect = new_policies[policy_id].effect
        category = "tightening" if effect == "deny" else "informational"
        changes.append({"category": category, "policy_id": policy_id, "message": "Policy added."})
    for policy_id in sorted(old_policies.keys() & new_policies.keys()):
        before = old_policies[policy_id]
        after = new_policies[policy_id]
        if canonical_json(before) == canonical_json(after):
            continue
        if before.effect == "deny" and after.effect == "allow":
            category = "security_relaxation"
        elif before.effect == "allow" and after.effect == "deny":
            category = "tightening"
        elif before.priority != after.priority or before.targets != after.targets:
            category = "potentially_breaking"
        else:
            category = "informational"
        changes.append({"category": category, "policy_id": policy_id, "message": "Policy changed."})
    counts = {
        category: sum(1 for item in changes if item["category"] == category)
        for category in (
            "security_relaxation",
            "tightening",
            "potentially_breaking",
            "informational",
        )
    }
    return {"changes": changes, "summary": counts}
