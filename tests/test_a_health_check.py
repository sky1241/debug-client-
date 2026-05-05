"""Section A — Health-check de l'environnement (tests #1-10 de TESTS.md).

Chaque test correspond à 1 ligne numérotée de TESTS.md. On valide que
l'environnement Kali est dans l'état attendu et que les wrappers maison
sont installés/fonctionnels.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import (
    BIN_DIR,
    REPO_ROOT,
    assert_exits_clean,
    run_wrapper,
    tool_available,
)


def test_001_kali_tools_installed(kali_tools: list[str]) -> None:
    """TESTS.md #1 — Les 24 outils SAST listés dans tool-versions.lock sont présents."""
    assert kali_tools, "tool-versions.lock vide ou absent (lance `audit-doctor --bump`)"
    missing = [t for t in kali_tools if not tool_available(t)]
    assert not missing, f"outils absents: {missing}"


def test_002_repo_wrappers_present() -> None:
    """TESTS.md #2 — Les 8 wrappers principaux du repo bin/ sont présents et exécutables."""
    expected = [
        "audit-fingerprint",
        "client-audit-code",
        "client-audit-web",
        "client-audit-net",
        "client-audit-test",
        "client-audit-diff",
        "audit-doctor",
        "audit-history",
    ]
    issues: list[str] = []
    for name in expected:
        path = BIN_DIR / name
        if not path.is_file():
            issues.append(f"{name}: absent")
        elif not os.access(path, os.X_OK):
            issues.append(f"{name}: non-exécutable")
    assert not issues, f"wrappers en problème: {issues}"


def test_003_nmap_localhost_top1000() -> None:
    """TESTS.md #3 — `nmap` sait scanner localhost et trouve au moins 1 port ouvert.

    On ne hardcode pas un port précis (3000/8081 dépendent de l'env xmrig + dashboard).
    Le test valide juste : nmap exit 0 + au moins une ligne 'XXX/tcp open' dans la sortie.
    """
    import subprocess

    p = subprocess.run(
        ["nmap", "-p", "1-1000", "-T4", "127.0.0.1"],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 0, f"nmap exit {p.returncode}, stderr={p.stderr[-300:]}"
    open_ports = [l for l in p.stdout.splitlines() if "/tcp" in l and "open" in l]
    assert open_ports, f"aucun port ouvert détecté sur localhost (nmap output:\n{p.stdout[-500:]})"
