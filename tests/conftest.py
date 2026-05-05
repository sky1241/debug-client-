"""Helpers pytest pour la stack pentest claude-tooling.

Fixtures et utilitaires partagés par tous les `test_*.py`. Pas de mock —
chaque test appelle le vrai wrapper bash via subprocess et asserte sur
le comportement réel.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent  # ~/.claude-tooling
BIN_DIR = REPO_ROOT / "bin"


def run_wrapper(
    name: str,
    *args: str,
    env_extra: dict[str, str] | None = None,
    cwd: Path | str | None = None,
    timeout: int = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """Lance un wrapper bash de `bin/` et retourne le CompletedProcess.

    `name` peut être un nom court (`audit-fingerprint`) ou un path complet.
    On utilise toujours le binaire du repo, pas celui de /usr/local/bin/
    (= teste le code local avant qu'il ne soit installé).
    """
    if "/" in name:
        cmd_path = name
    else:
        cmd_path = str(BIN_DIR / name)
    env = os.environ.copy()
    if env_extra:
        env.update({k: str(v) for k, v in env_extra.items()})
    return subprocess.run(
        [cmd_path, *map(str, args)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
        input=input_text,
    )


# Map nom-paquet (tool-versions.lock) → nom-binaire CLI quand ils diffèrent
_PKG_TO_BIN: dict[str, str] = {
    "clamav": "clamscan",  # paquet apt = clamav, binaire CLI = clamscan
}


def tool_available(tool: str) -> bool:
    """True si le binaire est trouvable dans PATH (ou dans les paths classiques)."""
    binary = _PKG_TO_BIN.get(tool, tool)
    if shutil.which(binary):
        return True
    for cand in (
        f"{Path.home()}/go/bin/{binary}",
        f"{Path.home()}/.cargo/bin/{binary}",
        f"{Path.home()}/.local/bin/{binary}",
        f"{Path.home()}/.config/composer/vendor/bin/{binary}",
    ):
        if Path(cand).is_file() and os.access(cand, os.X_OK):
            return True
    return False


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Crée un repo factice minimal (1 fichier .py innocent)."""
    (tmp_path / "main.py").write_text("print('hello')\n")
    return tmp_path


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    """Repo factice strictement vide."""
    return tmp_path


@pytest.fixture
def repo_with(tmp_path: Path):
    """Factory : retourne une fonction qui crée un repo avec les fichiers donnés.

    Usage::

        def test_xxx(repo_with):
            repo = repo_with({'app.py': 'eval(x)\\n', 'README': 'hi'})
    """

    def _builder(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return tmp_path

    return _builder


@pytest.fixture(scope="session")
def kali_tools() -> list[str]:
    """Liste des outils SAST attendus (selon `tool-versions.lock`)."""
    lock = REPO_ROOT / "tool-versions.lock"
    out: list[str] = []
    if not lock.is_file():
        return out
    for line in lock.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        out.append(line.split("=", 1)[0])
    return out


def assert_contains(text: str, *needles: str) -> None:
    """Asserte que toutes les `needles` sont dans `text` (avec message clair)."""
    for n in needles:
        assert n in text, f"manque {n!r} dans:\n{text[:500]}"


def assert_exits_clean(p: subprocess.CompletedProcess) -> None:
    """Asserte exit 0 avec message d'erreur incluant stderr."""
    assert p.returncode == 0, (
        f"exit {p.returncode}\nstdout: {p.stdout[-400:]}\nstderr: {p.stderr[-400:]}"
    )
