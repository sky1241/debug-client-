"""Section A — Health-check de l'environnement (tests #1-10 de TESTS.md).

Chaque test correspond à 1 ligne numérotée de TESTS.md. On valide que
l'environnement Kali est dans l'état attendu et que les wrappers maison
sont installés/fonctionnels.
"""
from __future__ import annotations

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
