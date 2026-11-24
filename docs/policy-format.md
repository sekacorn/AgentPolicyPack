# Policy Format Reference

Bundles support YAML and JSON with `schema_version: "1.0"`. Top-level fields are `schema_version`, `bundle`, `data_classifications`, `policies`, and `tests`.

`bundle` contains `id`, `name`, `version`, `namespace`, `description`, `default_decision`, `conflict_strategy`, `tags`, and explicit `metadata`.

Policies contain `id`, `name`, `description`, `enabled`, `effect`, `priority`, `targets`, `conditions`, `obligations`, `limits`, `reason`, `tags`, and `metadata`.

Targets may match subjects, actions, resources, tools, models, providers, and environments. Wildcards are glob-style and intentionally limited.

### Model and provider targets

`targets.models` matches the request's `model` block on `providers`, `names`, `families`, and `hosting`. `targets.providers` matches the request's `provider` block on `names`, `trust_levels`, and `jurisdictions`. When a request has no `provider` block, the `model` block is used in its place. A request with neither never matches a model or provider target.

`jurisdictions` compares against `provider.jurisdiction` exactly, with no case folding or normalization. The values are the caller's: this library does not define a list. AgentForge reports an ISO 3166 country code, `not_applicable` for a local endpoint, or `unknown`.

- **A missing jurisdiction is `unknown`.** An absent, empty, or non-string `provider.jurisdiction` is treated as the string `unknown`, so a policy targeting `jurisdictions: [unknown]` also catches a request that declares nothing.
- **A jurisdiction is a declaration, not a finding.** The value is attested by whoever built the request. This library evaluates it and never checks it, and it says nothing about where a request is routed or stored. A request may carry `provider.jurisdiction_verification` for audit; no target reads it, so it cannot change a decision.

#### Failing closed

**A jurisdiction target only matches a request that declares a `provider` or `model` block.** A request with neither matches no jurisdiction target, not even `jurisdictions: [unknown]`, so a deny rule on its own does not stop it. To fail closed you must also set `default_decision: deny`, and make sure no allow rule matches a request that describes no model; the examples do this by having their allow rule require a model block.

AgentForge always populates both blocks on a model call, so its requests are always matched. Other callers must do the same or rely on the default decision.

`examples/provider_governance/` has three bundles with embedded tests: `local-only.yaml` (local endpoints only), `block-vendors-and-jurisdictions.yaml` (deny listed provider names and jurisdictions), and `deny-unknown-jurisdiction.yaml` (deny providers that declare no jurisdiction). Their vendor names and jurisdiction codes are placeholders.

Conditions are structured with `all`, `any`, `not`, or leaf conditions using `field`, `operator`, and either `value` or `value_from`. Operators are `equals`, `not_equals`, `in`, `not_in`, `contains`, `not_contains`, `exists`, `not_exists`, `starts_with`, `ends_with`, numeric comparisons, `between`, and `matches_safe_pattern`.

Missing fields make ordinary conditions non-matching. Invalid bundles or unsafe ambiguity produce validation errors and evaluation fails closed.

Decisions are `allow`, `deny`, `require_review`, or `indeterminate`. `decision` records the controlling policy result. Consumers must use `effective_decision` (or `Decision.allowed`) before execution: an otherwise allowed request becomes effectively denied when an applicable limit is exceeded. Indeterminate defaults to deny-equivalent behavior. Embedded tests may set `expect_effective_decision` to assert that enforcement-safe result.

Obligations include `audit`, `redact`, `mask`, `require_review`, `enforce_limit`, `notify`, `retain_evidence`, and `attach_policy_context`. Extension obligations must contain a namespace such as `example.custom_obligation`.

Limits include cost, token, tool-call, retry, and agent-step limits. Cost values are handled with `Decimal`, not binary floating point.
