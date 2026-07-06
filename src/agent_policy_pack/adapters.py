"""Optional adapter protocols prepared for ecosystem integrations."""

from __future__ import annotations

from typing import Protocol

from .models import Decision, DecisionRequest, PolicyBundle


class PolicyDecisionAdapter(Protocol):
    """Protocol for frameworks that want delegated policy decisions."""

    def evaluate(self, bundle: PolicyBundle, request: DecisionRequest) -> Decision:
        """Evaluate a policy request."""


class AuditSink(Protocol):
    """Protocol for future audit-log integrations."""

    def record_decision(self, decision: Decision) -> None:
        """Record a policy decision in an external audit system."""
