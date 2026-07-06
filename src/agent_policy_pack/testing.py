"""Policy test runner and policy-test coverage."""

from __future__ import annotations

from typing import cast

from .evaluator import evaluate
from .models import DecisionRequest, Finding, PolicyBundle


def run_policy_tests(bundle: PolicyBundle) -> dict[str, object]:
    """Run bundle-embedded policy tests."""

    results: list[dict[str, object]] = []
    passed = 0
    for test in bundle.tests:
        decision = evaluate(bundle, DecisionRequest.model_validate(test.request))
        failures: list[str] = []
        if decision.decision != test.expect_decision:
            failures.append(f"expected decision {test.expect_decision}, got {decision.decision}")
        for obligation in test.expect_obligations:
            if obligation not in {item.type for item in decision.obligations}:
                failures.append(f"missing obligation {obligation}")
        for policy_id in test.expect_matched_policies:
            if policy_id not in decision.matched_policy_ids:
                failures.append(f"missing matched policy {policy_id}")
        if not failures:
            passed += 1
        results.append(
            {
                "id": test.id,
                "passed": not failures,
                "failures": failures,
                "decision": decision.decision,
            }
        )
    return {
        "passed": passed,
        "failed": len(results) - passed,
        "total": len(results),
        "results": results,
    }


def policy_test_findings(bundle: PolicyBundle) -> list[Finding]:
    """Convert test failures to findings."""

    report = run_policy_tests(bundle)
    result_items = cast(list[dict[str, object]], report["results"])
    findings: list[Finding] = []
    for result in result_items:
        if not result["passed"]:
            failures = cast(list[str], result["failures"])
            findings.append(
                Finding(
                    severity="error",
                    code="POLICY_TEST_FAILED",
                    message="; ".join(failures),
                    path=f"tests.{result['id']}",
                )
            )
    return findings


def coverage_report(bundle: PolicyBundle) -> dict[str, object]:
    """Return policy-test coverage across evaluated and controlling policies."""

    evaluated = {policy.id for policy in bundle.policies}
    matched: set[str] = set()
    controlling: set[str] = set()
    for test in bundle.tests:
        decision = evaluate(bundle, DecisionRequest.model_validate(test.request))
        matched.update(decision.matched_policy_ids)
        if decision.controlling_policy_id:
            controlling.add(decision.controlling_policy_id)
    total = len(evaluated)
    return {
        "total_policies": total,
        "evaluated": sorted(evaluated),
        "matched": sorted(matched),
        "controlling": sorted(controlling),
        "unmatched": sorted(evaluated - matched),
        "matched_percent": 100.0 if total == 0 else round(len(matched) / total * 100, 2),
        "controlling_percent": 100.0 if total == 0 else round(len(controlling) / total * 100, 2),
    }
