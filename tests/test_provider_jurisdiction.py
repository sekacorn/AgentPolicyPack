"""Provider jurisdiction targeting and the provider governance examples."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_policy_pack import evaluate, load_bundle
from agent_policy_pack.matching import matches_targets
from agent_policy_pack.models import DecisionRequest, PolicyBundle
from agent_policy_pack.testing import run_policy_tests
from agent_policy_pack.validation import lint_bundle, validate_bundle

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "provider_governance"
EXAMPLE_FILES = (
    "local-only.yaml",
    "block-vendors-and-jurisdictions.yaml",
    "deny-unknown-jurisdiction.yaml",
)


def _targets(*jurisdictions: str) -> dict[str, Any]:
    return {"providers": {"jurisdictions": list(jurisdictions)}}


def _request(provider: Any = None, model: Any = None) -> dict[str, Any]:
    request: dict[str, Any] = {"action": "model.call"}
    if provider is not None:
        request["provider"] = provider
    if model is not None:
        request["model"] = model
    return request


def test_a_declared_jurisdiction_matches_exactly() -> None:
    request = _request({"name": "vendor_b", "jurisdiction": "XA"})

    assert matches_targets(_targets("XA", "XB"), request)
    assert not matches_targets(_targets("XB"), request)
    # No normalization: the comparison is exact.
    assert not matches_targets(_targets("xa"), request)


@pytest.mark.parametrize("value", [None, "", 7, ["XA"], {"code": "XA"}])
def test_a_missing_or_malformed_jurisdiction_is_unknown(value: Any) -> None:
    provider: dict[str, Any] = {"name": "vendor_b"}
    if value is not None:
        provider["jurisdiction"] = value
    request = _request(provider)

    assert matches_targets(_targets("unknown"), request)
    assert not matches_targets(_targets("XA"), request)


def test_a_request_with_only_a_model_block_has_an_unknown_jurisdiction() -> None:
    # The provider block falls back to the model block, which carries none.
    request = _request(model={"provider": "openai_compatible", "hosting": "hosted"})

    assert matches_targets(_targets("unknown"), request)


def test_a_request_with_no_provider_or_model_never_matches_a_provider_target() -> None:
    # Same rule as every other provider target: nothing to match against.
    assert not matches_targets(_targets("unknown"), _request())


def test_jurisdiction_combines_with_the_other_provider_targets() -> None:
    targets = {"providers": {"names": ["vendor_a"], "jurisdictions": ["XA"]}}

    assert matches_targets(targets, _request({"name": "vendor_a", "jurisdiction": "XA"}))
    assert not matches_targets(targets, _request({"name": "vendor_b", "jurisdiction": "XA"}))
    assert not matches_targets(targets, _request({"name": "vendor_a", "jurisdiction": "XB"}))


def test_locality_is_untouched_and_independent_of_jurisdiction() -> None:
    request = _request({"name": "vendor_a", "locality": "on_prem", "jurisdiction": "XA"})

    assert matches_targets({"providers": {"localities": ["on_prem"]}}, request)
    assert not matches_targets({"providers": {"localities": ["XA"]}}, request)
    assert not matches_targets(_targets("on_prem"), request)


def test_a_policy_without_a_jurisdiction_target_ignores_the_field() -> None:
    targets = {"providers": {"names": ["vendor_a"]}}

    assert matches_targets(targets, _request({"name": "vendor_a"}))
    assert matches_targets(targets, _request({"name": "vendor_a", "jurisdiction": "XA"}))


def test_jurisdiction_verification_is_carried_but_never_changes_a_decision() -> None:
    bundle = load_bundle(EXAMPLES / "block-vendors-and-jurisdictions.yaml")

    def decide(verification: str | None) -> str:
        provider = {"name": "vendor_b", "hosting": "hosted", "jurisdiction": "XB"}
        if verification is not None:
            provider["jurisdiction_verification"] = verification
        request = DecisionRequest(
            action="model.call",
            model={"provider": "openai_compatible", "name": "m", "hosting": "hosted"},
            provider=provider,
        )
        return evaluate(bundle, request).effective_decision

    # A caller cannot talk its way past a block by calling the value verified.
    assert {decide(v) for v in (None, "attested", "verified", "unknown")} == {"deny"}


@pytest.mark.parametrize("name", EXAMPLE_FILES)
def test_each_example_validates_and_passes_its_own_tests(name: str) -> None:
    bundle: PolicyBundle = load_bundle(EXAMPLES / name)

    assert validate_bundle(bundle) == []
    assert [f.code for f in lint_bundle(bundle) if f.severity == "error"] == []
    report = run_policy_tests(bundle)
    assert report["failed"] == 0
    assert report["total"] == len(bundle.tests) >= 3


def test_the_example_folder_holds_exactly_the_documented_examples() -> None:
    assert {p.name for p in EXAMPLES.glob("*.yaml")} == set(EXAMPLE_FILES)


@pytest.mark.parametrize(
    ("name", "provider", "expected"),
    [
        ("deny-unknown-jurisdiction.yaml", {"jurisdiction": "unknown"}, "deny"),
        ("deny-unknown-jurisdiction.yaml", {}, "deny"),
        ("deny-unknown-jurisdiction.yaml", {"jurisdiction": "XC"}, "allow"),
        ("deny-unknown-jurisdiction.yaml", {"jurisdiction": "not_applicable"}, "allow"),
        ("block-vendors-and-jurisdictions.yaml", {"jurisdiction": "XA"}, "deny"),
        ("block-vendors-and-jurisdictions.yaml", {"jurisdiction": "XC"}, "allow"),
        # The block list alone does not stop an undescribed provider.
        ("block-vendors-and-jurisdictions.yaml", {"jurisdiction": "unknown"}, "allow"),
    ],
)
def test_example_decisions(name: str, provider: dict[str, str], expected: str) -> None:
    bundle = load_bundle(EXAMPLES / name)
    request = DecisionRequest(
        action="model.call",
        model={"provider": "openai_compatible", "name": "m", "hosting": "hosted"},
        provider={"name": "vendor_b", "hosting": "hosted", **provider},
    )

    assert evaluate(bundle, request).effective_decision == expected


def test_the_local_only_example_denies_a_hosted_endpoint_in_any_jurisdiction() -> None:
    bundle = load_bundle(EXAMPLES / "local-only.yaml")

    def decide(hosting: str) -> str:
        request = DecisionRequest(
            action="model.call",
            model={"provider": "openai_compatible", "name": "m", "hosting": hosting},
            provider={"name": "vendor_b", "hosting": hosting, "jurisdiction": "XC"},
        )
        return evaluate(bundle, request).effective_decision

    assert (decide("local"), decide("hosted"), decide("elsewhere")) == ("allow", "deny", "deny")
