"""Exception hierarchy for AgentPolicyPack."""

from __future__ import annotations


class AgentPolicyPackError(Exception):
    """Base exception for AgentPolicyPack."""


class PolicyLoadError(AgentPolicyPackError):
    """A policy file could not be loaded."""


class PolicyParseError(PolicyLoadError):
    """A policy file could not be parsed safely."""


class PolicyValidationError(AgentPolicyPackError):
    """A policy bundle failed validation."""


class PolicyEvaluationError(AgentPolicyPackError):
    """Policy evaluation failed."""


class PolicyIndeterminateError(PolicyEvaluationError):
    """A policy decision was indeterminate."""


class PolicyTestError(AgentPolicyPackError):
    """Policy tests failed."""


class PolicySimulationError(AgentPolicyPackError):
    """Policy simulation failed."""


class PolicyDiffError(AgentPolicyPackError):
    """Policy diffing failed."""


class PolicyExportError(AgentPolicyPackError):
    """A report could not be exported."""


class UnsafeInputError(PolicyLoadError):
    """Input was unsafe or outside supported limits."""


class UnsupportedSchemaVersionError(PolicyValidationError):
    """The policy schema version is not supported."""


class AdapterError(AgentPolicyPackError):
    """An optional adapter failed."""
