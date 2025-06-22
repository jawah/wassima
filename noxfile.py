from __future__ import annotations

import os

import nox


@nox.session(python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "pypy"])
def test(session: nox.Session) -> None:
    # Install deps and the package itself.
    session.install("-r", "requirements-dev.txt")
    session.install(".")

    # Show the pip version.
    session.run("pip", "--version")
    session.run("python", "--version")

    session.run(
        "python",
        "-m",
        "coverage",
        "run",
        "--parallel-mode",
        "-m",
        "pytest",
        "-v",
        "-ra",
        f"--color={'yes' if 'GITHUB_ACTIONS' in os.environ else 'auto'}",
        "--tb=native",
        "--durations=10",
        "--strict-config",
        "--strict-markers",
        *(session.posargs or ("tests/",)),
        env={
            "PYTHONWARNINGS": "always::DeprecationWarning",
        },
    )


@nox.session
def lint(session: nox.Session) -> None:
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


@nox.session
def sync(session: nox.Session) -> None:
    session.install("-r", "requirements-dev.txt")

    session.run(
        "python",
        "bin/update.py",
    )

    session.install("pre-commit")

    session.run("pre-commit", "run", "--all-files", success_codes=[1, 0], silent=True)
