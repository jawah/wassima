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


def git_clone(session: nox.Session, git_url: str) -> None:
    """We either clone the target repository or if already exist
    simply reset the state and pull.
    """
    expected_directory = git_url.split("/")[-1]

    if expected_directory.endswith(".git"):
        expected_directory = expected_directory[:-4]

    if not os.path.isdir(expected_directory):
        session.run("git", "clone", "--depth", "1", git_url, external=True)
    else:
        session.run("git", "-C", expected_directory, "reset", "--hard", "HEAD", external=True)
        session.run("git", "-C", expected_directory, "pull", external=True)


@nox.session()
def downstream_niquests(session: nox.Session) -> None:
    root = os.getcwd()
    tmp_dir = session.create_tmp()

    session.cd(tmp_dir)
    git_clone(session, "https://github.com/jawah/niquests")
    session.chdir("niquests")

    session.run("git", "rev-parse", "HEAD", external=True)
    session.install(".[socks]", silent=False)
    session.install("-r", "requirements-dev.txt", silent=False)

    session.cd(root)
    session.install(".", silent=False)
    session.cd(f"{tmp_dir}/niquests")

    session.run("python", "-c", "import wassima; print(wassima.__version__)")
    session.run(
        "python",
        "-m",
        "pytest",
        "-v",
        f"--color={'yes' if 'GITHUB_ACTIONS' in os.environ else 'auto'}",
        *(session.posargs or ("tests/",)),
        env={"NIQUESTS_STRICT_OCSP": "1"},
    )
