# Development

Use PowerShell-compatible commands:

```powershell
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy --strict src
python -m pytest
python -m pytest --cov=agent_policy_pack --cov-branch
python -m bandit -r src
python -m pip_audit
python -m build
python -m twine check dist/*
```

Release publishing is intentionally manual and must use the future GitHub release workflow. Do not commit, tag, publish, or create a GitHub release as part of local verification.

