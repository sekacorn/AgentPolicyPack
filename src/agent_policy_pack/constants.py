"""Constants for AgentPolicyPack."""

from __future__ import annotations

VERSION = "0.1.0a1"
SCHEMA_VERSION = "1.0"
MAX_BUNDLE_BYTES = 1_000_000
MAX_BATCH_REQUESTS = 1_000
MAX_CONDITION_DEPTH = 8
MAX_PATTERN_LENGTH = 200
MAX_PATTERN_INPUT_LENGTH = 2_000

EFFECTS = {"allow", "deny", "require_review", "limit", "redact", "log_only"}
DECISIONS = {"allow", "deny", "require_review", "indeterminate"}
CONFLICT_STRATEGIES = {
    "deny_overrides",
    "allow_overrides",
    "first_applicable",
    "highest_priority",
    "only_one_applicable",
}
OPERATORS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "exists",
    "not_exists",
    "starts_with",
    "ends_with",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "between",
    "matches_safe_pattern",
}
OBLIGATION_TYPES = {
    "audit",
    "redact",
    "mask",
    "require_review",
    "enforce_limit",
    "notify",
    "retain_evidence",
    "attach_policy_context",
}
