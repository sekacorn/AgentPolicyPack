# Policy Format Reference

Bundles support YAML and JSON with `schema_version: "1.0"`. Top-level fields are `schema_version`, `bundle`, `data_classifications`, `policies`, and `tests`.

`bundle` contains `id`, `name`, `version`, `namespace`, `description`, `default_decision`, `conflict_strategy`, `tags`, and explicit `metadata`.

Policies contain `id`, `name`, `description`, `enabled`, `effect`, `priority`, `targets`, `conditions`, `obligations`, `limits`, `reason`, `tags`, and `metadata`.

Targets may match subjects, actions, resources, tools, models, providers, and environments. Wildcards are glob-style and intentionally limited.

Conditions are structured with `all`, `any`, `not`, or leaf conditions using `field`, `operator`, and either `value` or `value_from`. Operators are `equals`, `not_equals`, `in`, `not_in`, `contains`, `not_contains`, `exists`, `not_exists`, `starts_with`, `ends_with`, numeric comparisons, `between`, and `matches_safe_pattern`.

Missing fields make ordinary conditions non-matching. Invalid bundles or unsafe ambiguity produce validation errors and evaluation fails closed.

Decisions are `allow`, `deny`, `require_review`, or `indeterminate`. Indeterminate defaults to deny-equivalent behavior.

Obligations include `audit`, `redact`, `mask`, `require_review`, `enforce_limit`, `notify`, `retain_evidence`, and `attach_policy_context`. Extension obligations must contain a namespace such as `example.custom_obligation`.

Limits include cost, token, tool-call, retry, and agent-step limits. Cost values are handled with `Decimal`, not binary floating point.

