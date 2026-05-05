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
