# Security and Threat Model

AgentPolicyPack treats policy files as untrusted input. It uses safe YAML loading, duplicate-key checks, JSON parsing, UTF-8 validation, file-size limits, strict models, bounded condition nesting, and restricted safe glob patterns.

The evaluator does not execute code, does not import policy-named modules, does not use `eval` or `exec`, and does not make network calls during evaluation.

Security decision failures are fail-closed. Invalid bundles evaluate to `indeterminate` with a deny-equivalent effective decision by default.

Out of scope: identity provider behavior, secrets management, network firewalling, operating-system sandboxing, hosted policy serving, legal certification, and perfect PII discovery.

