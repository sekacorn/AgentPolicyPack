"""Public data models for policy bundles, requests, decisions, and reports."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Json = dict[str, Any]
DecisionOutcome = Literal["allow", "deny", "require_review", "indeterminate"]


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Finding(StrictModel):
    """Validation, lint, or test finding."""

    severity: Literal["error", "warning", "information"]
    code: str
    message: str
    path: str = ""
    suggestion: str = ""
    context: Json = Field(default_factory=dict)


class BundleMetadata(StrictModel):
    """Bundle metadata."""

    id: str
    name: str
    version: str
    namespace: str
    description: str = ""
    default_decision: DecisionOutcome = "deny"
    conflict_strategy: str = "deny_overrides"
    tags: tuple[str, ...] = ()
    metadata: Json = Field(default_factory=dict)


class Obligation(StrictModel):
    """An action required by policy."""

    type: str
    parameters: Json = Field(default_factory=dict)
    source_policy_id: str | None = None
    reason: str = ""
    required: bool = True


class Limits(StrictModel):
    """Quantitative policy limits."""

    max_cost_usd: Decimal | None = None
    max_daily_cost_usd: Decimal | None = None
    max_monthly_cost_usd: Decimal | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_total_tokens: int | None = None
    max_tool_calls: int | None = None
    max_agent_steps: int | None = None
    max_retries: int | None = None

    @field_validator("*", mode="before")
    @classmethod
    def parse_decimal_strings(cls, value: object) -> object:
        """Accept string decimals without binary floating-point conversion."""

        return Decimal(value) if isinstance(value, str) else value


class Policy(StrictModel):
    """A single governance policy."""

    id: str
    name: str = ""
    description: str = ""
    enabled: bool = True
    effect: str
    priority: int = 0
    targets: Json = Field(default_factory=dict)
    conditions: Json | None = None
    obligations: tuple[Obligation, ...] = ()
    limits: Limits | None = None
    reason: str = ""
    tags: tuple[str, ...] = ()
    metadata: Json = Field(default_factory=dict)


class PolicyTest(StrictModel):
    """A declarative policy test case."""

    id: str
    name: str = ""
    request: Json
    expect_decision: DecisionOutcome
    expect_obligations: tuple[str, ...] = ()
    expect_limits: Json = Field(default_factory=dict)
    expect_matched_policies: tuple[str, ...] = ()


class PolicyBundle(StrictModel):
    """A normalized policy bundle."""

    schema_version: str
    bundle: BundleMetadata
    data_classifications: tuple[str, ...] = ("public", "internal", "confidential", "restricted")
    policies: tuple[Policy, ...] = ()
    tests: tuple[PolicyTest, ...] = ()


class DecisionRequest(StrictModel):
    """A request to evaluate against a policy bundle."""

    subject: Json = Field(default_factory=dict)
    action: str = ""
    resource: Json = Field(default_factory=dict)
    tool: Json | None = None
    model: Json | None = None
    provider: Json | None = None
    environment: Json = Field(default_factory=dict)
    context: Json = Field(default_factory=dict)


class Evidence(StrictModel):
    """Explainability evidence for a policy decision."""

    policy_id: str
    effect: str
    matched: bool
    reason: str = ""
    details: Json = Field(default_factory=dict)


class LimitResult(StrictModel):
    """A concrete applicable limit and request status."""

    name: str
    limit: Decimal | int
    current: Decimal | int | None = None
    remaining: Decimal | int | None = None
    exceeded: bool = False
    source_policy_id: str


class Decision(StrictModel):
    """The result of policy evaluation."""

    decision: DecisionOutcome
    effective_decision: DecisionOutcome
    decision_id: str
    bundle_digest: str
    request_digest: str
    matched_policy_ids: tuple[str, ...] = ()
    controlling_policy_id: str | None = None
    obligations: tuple[Obligation, ...] = ()
    limits: tuple[LimitResult, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[Finding, ...] = ()

    @property
    def allowed(self) -> bool:
        """Return whether the effective result permits immediate execution."""

        return self.effective_decision == "allow"
