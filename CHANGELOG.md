# Changelog

## Unreleased

- Add an optional `jurisdictions` provider target, matched exactly against `provider.jurisdiction`. A missing, empty, or non-string jurisdiction is treated as `unknown`, so a policy can deny providers that declare nothing. The value is the caller's declaration and is never checked. A jurisdiction target only matches a request that declares a `provider` or `model` block, so failing closed also needs `default_decision: deny`. Existing bundles and requests are unaffected.
- Add `examples/provider_governance/` with three tested bundles: local endpoints only, block listed vendors and jurisdictions, and deny unknown jurisdictions.
- Document model and provider targets in `docs/policy-format.md`.

## 0.2.0b1 - 2026-08-11

- First Beta release candidate.
- Harden untrusted YAML and JSON parsing with bounded structure and explicit rejection of YAML graph features.
- Let embedded policy tests and bundle comparisons report effective enforcement outcomes, including limit-based execution denials.
- Update release tooling for current package metadata validation.

## 0.1.0a2 - 2026-08-06

- Publish corrected Apache-2.0 package metadata under the public maintainer identity `sekacorn`.
- Preserve the existing offline policy evaluation behavior and documented limitations.

## 0.1.0a1

- Initial public alpha release.
