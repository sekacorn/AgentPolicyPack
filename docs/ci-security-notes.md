# CI Security Notes

Workflows use official stable action versions because exact verified commit SHAs were not established during local preparation. Human release review should pin each action to a verified commit SHA before enforcing a stricter supply-chain policy.

The release workflow is prepared for PyPI Trusted Publishing through OIDC and the protected `pypi` environment. It does not use a PyPI API token.

