# AgentPolicyPack

AgentPolicyPack lets organizations define, test, and carry AI-agent governance rules across models, frameworks, providers, and deployment environments.

AgentPolicyPack is an alpha project. Version `0.1.0a1` is ready for public alpha release with documented limitations, not production certification.

## Motivation

AI-agent governance should be portable, deterministic, auditable, version-controlled, and testable in CI. AgentPolicyPack provides a vendor-neutral policy bundle format, a fail-closed evaluator, policy tests, simulation, diffing, and a Python API plus CLI.

## Problem Statement

Organizations often encode agent rules inside one model provider, framework, runtime, or deployment stack. That creates lock-in and makes policy behavior hard to test. AgentPolicyPack separates governance intent from enforcement systems so the same rules can be validated, compared, and evaluated offline.

## Core Capabilities

- YAML and JSON policy bundles loaded with safe parsers.
- Strict schema models that reject unknown fields.
- Structural and semantic validation with stable finding codes.
- Safe structured condition language with bounded nesting.
- Target matching for subjects, actions, resources, tools, models, providers, and environments.
- Conflict strategies: `deny_overrides`, `allow_overrides`, `first_applicable`, `highest_priority`, and `only_one_applicable`.
- Effects: `allow`, `deny`, `require_review`, `limit`, `redact`, and `log_only`.
- Obligations and most-restrictive limit aggregation.
- Deterministic normalization, digests, decision IDs, and reports.
- Embedded policy tests, policy-test coverage, simulation, comparison, and conservative diffing.

## Architecture

Policy bundles load into typed Pydantic models. Validation runs before evaluation. Invalid bundles fail closed as `indeterminate` with a deny-equivalent effective decision. The evaluator performs deterministic target matching, structured condition evaluation, conflict resolution, obligation aggregation, limit aggregation, and evidence generation. External systems remain responsible for enforcing the returned decision.

## Installation

```powershell
python -m pip install agentpolicypack
```

For development:

```powershell
python -m pip install -e ".[dev]"
```

## Quick Start Policy

```yaml
schema_version: "1.0"
bundle:
  id: customer-support-governance
  name: Customer Support Agent Governance
  version: "1.0.0"
  namespace: example.customer_support
  default_decision: deny
  conflict_strategy: deny_overrides
policies:
  - id: allow-ticket-read
    effect: allow
    priority: 100
    targets:
      subjects:
        roles: [support_agent]
      actions: [ticket.read]
      resources:
        types: [SupportTicket]
    conditions:
      all:
        - field: resource.attributes.assigned_agent_id
          operator: equals
          value_from: subject.id
```

## Evaluation Example

```powershell
agentpolicy evaluate examples/tool_governance/policy.yaml --request examples/tool_governance/allow-search-request.yaml
```

## Policy-Test Example

```powershell
agentpolicy test examples/tool_governance/policy.yaml
agentpolicy coverage examples/tool_governance/policy.yaml
```

## CLI Examples

```powershell
agentpolicy validate examples/tool_governance/policy.yaml
agentpolicy lint examples/tool_governance/policy.yaml
agentpolicy inspect examples/tool_governance/policy.yaml
agentpolicy normalize examples/tool_governance/policy.yaml
agentpolicy digest examples/tool_governance/policy.yaml
agentpolicy simulate examples/tool_governance/policy.yaml --requests examples/tool_governance/requests.yaml
agentpolicy diff tests/fixtures/diff/policy-v1.yaml tests/fixtures/diff/policy-v2.yaml
agentpolicy compare tests/fixtures/diff/policy-v1.yaml tests/fixtures/diff/policy-v2.yaml --requests tests/fixtures/diff/requests.yaml
```

## Python API Example

```python
from agent_policy_pack import DecisionRequest, evaluate, load_bundle

bundle = load_bundle("examples/tool_governance/policy.yaml")
request = DecisionRequest(action="tool.call", subject={"roles": ["research_agent"]})
decision = evaluate(bundle, request)
print(decision.decision, decision.effective_decision)
```

## Conflict Strategies

`deny_overrides` is the default. Any matching deny controls before review or allow. `allow_overrides` is supported but dangerous because it may relax denies. `first_applicable` uses deterministic priority-descending, ID-ascending order. `highest_priority` selects the highest priority and resolves equal-priority mixed effects conservatively. `only_one_applicable` returns `indeterminate` when multiple policies match.

## Effects, Obligations, and Limits

Policy effects express governance intent. Decisions expose a primary outcome plus structured obligations such as `audit`, `redact`, `mask`, `require_review`, `enforce_limit`, `notify`, `retain_evidence`, and `attach_policy_context`. Custom obligations must use an extension namespace and are preserved, not executed. Limits use exact `Decimal` handling for costs.

## Simulation and Diffing

Simulation evaluates request batches offline. Comparison evaluates two bundles against the same requests. Diffing classifies changes conservatively as security relaxation, tightening, potentially breaking, or informational.

## Integration Roadmap

The package includes protocol types for future adapters. Version `0.1.0a1` works independently and offline. Forge, PrivateAIStack, ModelSwapBench, OpenOntologyLite, AIAuditLog, and OpenAIMeter integrations are deferred unless optional adapters are installed and tested in later releases.

## Security Model

AgentPolicyPack uses safe YAML loading, strict unknown-field rejection, bounded condition nesting, safe glob-style patterns, deterministic serialization, and fail-closed defaults. It never uses Python `eval` or `exec`, never imports modules named by policy files, and never follows remote URLs.

## Limitations

- External systems must enforce policy decisions.
- No identity-provider integration.
- No secrets management.
- No network firewall.
- No operating-system sandbox.
- No hosted policy server.
- No graphical editor.
- No general-purpose expression language.
- No arbitrary code execution.
- No legal or regulatory certification.
- Custom obligations are preserved but not executed.
- PII obligations do not provide automatic perfect PII discovery.
- Policies cannot guarantee model behavior.
- Optional framework adapters may cover only documented integration points.
- Policy diff classification is conservative and rule-based.
- Policy-test coverage is not software-code coverage.
- Bundle format may evolve before version 1.0.

## Contributing

Use the development commands in `docs/development.md`. Keep behavior deterministic, typed, local-first, and fail-closed.

## License

MIT.

## Author

sekacorn

