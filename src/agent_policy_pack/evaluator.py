"""Policy evaluation and conflict resolution."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, cast

from .conditions import evaluate_condition
from .matching import matches_targets
from .models import (
    Decision,
    DecisionOutcome,
    DecisionRequest,
    Evidence,
    Finding,
    LimitResult,
    Obligation,
    Policy,
    PolicyBundle,
)
from .serialization import digest_value, to_plain
from .validation import has_errors, validate_bundle


def _request_map(request: DecisionRequest) -> dict[str, Any]:
    plain = to_plain(request)
    return cast(dict[str, Any], plain)


def _limit_current_name(limit_name: str) -> str:
    return {
        "max_cost_usd": "estimated_cost_usd",
        "max_daily_cost_usd": "current_daily_cost_usd",
        "max_monthly_cost_usd": "current_monthly_cost_usd",
        "max_input_tokens": "input_tokens",
        "max_output_tokens": "output_tokens",
        "max_total_tokens": "total_tokens",
        "max_tool_calls": "tool_calls",
        "max_agent_steps": "agent_steps",
        "max_retries": "retries",
    }[limit_name]


def _aggregate_limits(
    policies: list[Policy], request: DecisionRequest
) -> tuple[tuple[LimitResult, ...], tuple[Finding, ...]]:
    chosen: dict[str, tuple[int | Decimal, str]] = {}
    for policy in policies:
        if policy.limits is None:
            continue
        for key, value in policy.limits.model_dump().items():
            if value is None:
                continue
            if key not in chosen or value < chosen[key][0]:
                chosen[key] = (value, policy.id)
    results: list[LimitResult] = []
    findings: list[Finding] = []
    context = request.context
    for key, (limit, source) in sorted(chosen.items()):
        current_raw = context.get(_limit_current_name(key))
        current: Decimal | int | None = None
        invalid_current = False
        if current_raw is not None:
            try:
                current = (
                    Decimal(str(current_raw)) if isinstance(limit, Decimal) else int(current_raw)
                )
            except (InvalidOperation, TypeError, ValueError):
                invalid_current = True
                findings.append(
                    Finding(
                        severity="error",
                        code="INVALID_LIMIT_CONTEXT",
                        message=f"Context value for {_limit_current_name(key)!r} is invalid.",
                        path=f"context.{_limit_current_name(key)}",
                    )
                )
        remaining = None if current is None else limit - current
        results.append(
            LimitResult(
                name=key,
                limit=limit,
                current=current,
                remaining=remaining,
                exceeded=invalid_current or (current is not None and current > limit),
                source_policy_id=source,
            )
        )
    return tuple(results), tuple(findings)


def _aggregate_obligations(policies: list[Policy]) -> tuple[Obligation, ...]:
    seen: set[str] = set()
    obligations: list[Obligation] = []
    for policy in sorted(policies, key=lambda p: (p.priority, p.id), reverse=True):
        for obligation in policy.obligations:
            data = obligation.model_copy(
                update={
                    "source_policy_id": obligation.source_policy_id or policy.id,
                    "reason": obligation.reason or policy.reason,
                }
            )
            key = f"{data.type}:{data.source_policy_id}:{data.parameters}"
            if key not in seen:
                obligations.append(data)
                seen.add(key)
    return tuple(obligations)


def _control(
    strategy: str, applicable: list[Policy]
) -> tuple[DecisionOutcome, Policy | None, list[Finding]]:
    findings: list[Finding] = []
    if not applicable:
        return "deny", None, findings
    denies = [p for p in applicable if p.effect == "deny"]
    reviews = [p for p in applicable if p.effect == "require_review"]
    allows = [p for p in applicable if p.effect in {"allow", "limit", "redact", "log_only"}]
    if strategy == "only_one_applicable" and len(applicable) != 1:
        findings.append(
            Finding(
                severity="error",
                code="MULTIPLE_APPLICABLE_POLICIES",
                message="More than one policy applies.",
                path="policies",
            )
        )
        return "indeterminate", None, findings
    ordered = sorted(applicable, key=lambda p: (-p.priority, p.id))
    if strategy == "first_applicable":
        chosen = ordered[0]
    elif strategy == "highest_priority":
        top_priority = ordered[0].priority
        top = [p for p in ordered if p.priority == top_priority]
        if len({p.effect for p in top}) > 1:
            chosen = sorted(top, key=lambda p: (p.effect != "deny", p.id))[0]
        else:
            chosen = top[0]
    elif strategy == "allow_overrides":
        chosen = sorted(
            allows or reviews or denies or applicable, key=lambda p: (-p.priority, p.id)
        )[0]
    else:
        chosen = sorted(
            denies or reviews or allows or applicable, key=lambda p: (-p.priority, p.id)
        )[0]
    decision: DecisionOutcome = (
        "deny"
        if chosen.effect == "deny"
        else "require_review"
        if chosen.effect == "require_review"
        else "allow"
    )
    return decision, chosen, findings


def evaluate(
    bundle: PolicyBundle, request: DecisionRequest, *, indeterminate_as: str = "deny"
) -> Decision:
    """Evaluate a request against a policy bundle."""

    validation = validate_bundle(bundle)
    if has_errors(validation):
        request_digest = digest_value(request)
        bundle_digest = digest_value(bundle)
        return Decision(
            decision="indeterminate",
            effective_decision="deny" if indeterminate_as == "deny" else "indeterminate",
            decision_id=digest_value(
                {"bundle": bundle_digest, "request": request_digest, "decision": "indeterminate"}
            ),
            bundle_digest=bundle_digest,
            request_digest=request_digest,
            findings=tuple(validation),
        )
    req_map = _request_map(request)
    evidence: list[Evidence] = []
    applicable: list[Policy] = []
    for policy in sorted(bundle.policies, key=lambda p: (-p.priority, p.id)):
        if not policy.enabled:
            evidence.append(
                Evidence(
                    policy_id=policy.id,
                    effect=policy.effect,
                    matched=False,
                    reason="Policy disabled.",
                )
            )
            continue
        targets_match = matches_targets(policy.targets, req_map)
        # Conditions may be comparatively expensive; non-targeted policies cannot apply.
        conditions_match = (
            evaluate_condition(policy.conditions, req_map) if targets_match else False
        )
        matched = targets_match and conditions_match
        evidence.append(
            Evidence(
                policy_id=policy.id,
                effect=policy.effect,
                matched=matched,
                reason=policy.reason,
                details={"targets": targets_match, "conditions": conditions_match},
            )
        )
        if matched:
            applicable.append(policy)
    decision, chosen, findings = _control(bundle.bundle.conflict_strategy, applicable)
    if decision == "deny" and chosen is None and bundle.bundle.default_decision == "allow":
        decision = "allow"
    effective: DecisionOutcome = (
        "deny" if decision == "indeterminate" and indeterminate_as == "deny" else decision
    )
    limits, limit_findings = _aggregate_limits(applicable, request)
    findings.extend(limit_findings)
    if limit_findings and decision == "allow":
        decision = "indeterminate"
        effective = "deny" if indeterminate_as == "deny" else "indeterminate"
    elif any(limit.exceeded for limit in limits) and decision == "allow":
        effective = "deny"
    obligations = _aggregate_obligations(applicable)
    request_digest = digest_value(request)
    bundle_digest = digest_value(bundle)
    return Decision(
        decision=decision,
        effective_decision=effective,
        decision_id=digest_value(
            {
                "bundle": bundle_digest,
                "request": request_digest,
                "decision": decision,
                "matched": [p.id for p in applicable],
            }
        ),
        bundle_digest=bundle_digest,
        request_digest=request_digest,
        matched_policy_ids=tuple(p.id for p in applicable),
        controlling_policy_id=chosen.id if chosen else None,
        obligations=obligations,
        limits=limits,
        evidence=tuple(evidence),
        findings=tuple(findings),
    )
