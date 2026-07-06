"""Command-line interface for AgentPolicyPack."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer

from .constants import VERSION
from .diffing import diff_bundles
from .evaluator import evaluate
from .exceptions import AgentPolicyPackError
from .loader import load_bundle
from .models import DecisionRequest
from .reports import render_json, render_markdown
from .serialization import digest_value
from .simulation import compare as compare_bundles
from .simulation import load_requests, simulate
from .testing import coverage_report, run_policy_tests
from .validation import has_errors, lint_bundle, validate_bundle

app = typer.Typer(no_args_is_help=True, add_completion=False)


def _emit(
    value: Any, output: Path | None = None, fmt: str = "json", title: str = "AgentPolicyPack Report"
) -> None:
    text = render_markdown(title, value) if fmt == "markdown" else render_json(value)
    if output:
        output.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
    else:
        typer.echo(text)


def _load(path: Path) -> Any:
    try:
        return load_bundle(path)
    except AgentPolicyPackError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
) -> None:
    """AgentPolicyPack policy-as-code toolkit."""

    if version:
        typer.echo(VERSION)
        raise typer.Exit()


@app.command()
def validate(
    policy: Path,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    """Validate a policy bundle."""

    bundle = _load(policy)
    findings = validate_bundle(bundle)
    _emit({"findings": [f.model_dump(mode="json") for f in findings]}, output, fmt, "Validation")
    if has_errors(findings):
        raise typer.Exit(1)


@app.command()
def lint(
    policy: Path,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    """Lint a policy bundle."""

    bundle = _load(policy)
    findings = lint_bundle(bundle)
    _emit({"findings": [f.model_dump(mode="json") for f in findings]}, output, fmt, "Lint")
    if has_errors(findings):
        raise typer.Exit(1)


@app.command()
def inspect(
    policy: Path, output: Annotated[Path | None, typer.Option("--output", "-o")] = None
) -> None:
    """Inspect bundle summary."""

    bundle = _load(policy)
    _emit(
        {
            "id": bundle.bundle.id,
            "version": bundle.bundle.version,
            "policies": len(bundle.policies),
            "tests": len(bundle.tests),
            "conflict_strategy": bundle.bundle.conflict_strategy,
        },
        output,
    )


@app.command()
def normalize(
    policy: Path, output: Annotated[Path | None, typer.Option("--output", "-o")] = None
) -> None:
    """Print canonical normalized JSON."""

    _emit(_load(policy), output)


@app.command()
def digest(policy: Path) -> None:
    """Print bundle digest."""

    typer.echo(digest_value(_load(policy)))


@app.command(name="evaluate")
def evaluate_cmd(
    policy: Annotated[Path, typer.Argument()],
    request: Annotated[Path, typer.Option("--request", "-r")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Evaluate a request."""

    bundle = _load(policy)
    req = DecisionRequest.model_validate(load_requests_file(request))
    decision = evaluate(bundle, req)
    _emit(decision, output)
    if decision.effective_decision != "allow":
        raise typer.Exit(1)


def load_requests_file(path: Path) -> dict[str, Any]:
    """Load one request object from YAML or JSON."""

    from .loader import load_raw

    data = load_raw(path)
    if "request" in data and isinstance(data["request"], dict):
        return data["request"]
    return data


@app.command(name="test")
def test_cmd(
    policy: Path, output: Annotated[Path | None, typer.Option("--output", "-o")] = None
) -> None:
    """Run embedded policy tests."""

    report = run_policy_tests(_load(policy))
    _emit(report, output)
    if report["failed"]:
        raise typer.Exit(1)


@app.command()
def coverage(
    policy: Path, output: Annotated[Path | None, typer.Option("--output", "-o")] = None
) -> None:
    """Report policy-test coverage."""

    _emit(coverage_report(_load(policy)), output)


@app.command(name="simulate")
def simulate_cmd(
    policy: Annotated[Path, typer.Argument()],
    requests: Annotated[Path, typer.Option("--requests")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Evaluate a batch of requests."""

    _emit(simulate(_load(policy), load_requests(requests)), output)


@app.command()
def diff(
    old: Path, new: Path, output: Annotated[Path | None, typer.Option("--output", "-o")] = None
) -> None:
    """Diff two policy bundles."""

    _emit(diff_bundles(_load(old), _load(new)), output)


@app.command()
def compare(
    old: Annotated[Path, typer.Argument()],
    new: Annotated[Path, typer.Argument()],
    requests: Annotated[Path, typer.Option("--requests")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Compare two bundles against a request batch."""

    _emit(compare_bundles(_load(old), _load(new), load_requests(requests)), output)
