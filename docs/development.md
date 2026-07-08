# Development

Use PowerShell-compatible commands:

```powershell
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m mypy --strict src
python -m pytest
python -m pytest --cov=agent_policy_pack --cov-branch
python -m bandit -r src
python -m pip_audit
python -m build
python -m twine check dist/*
```

Release publishing must use the GitHub release workflow with PyPI Trusted Publishing. Do not create a release tag until metadata, checks, artifacts, clean installs, CI, and the PyPI trusted publisher configuration are verified.
