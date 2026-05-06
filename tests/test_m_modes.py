"""Section M — Validation 5 modes opérationnels (tests #165-169 de TESTS.md).

Tests rapides : chaque mode est lancé sur un mini-repo Python (~5-15s
par audit). Validations : audit termine + exit code OK + comportement
spécifique du mode (sandbox bloque dirs sensibles, offline skippe outils
réseau, etc.).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


def _make_mini_repo(tmp_path: Path) -> Path:
    """Mini-repo pour test rapide (juste 1 .py innocent)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("def hi(): print('hi')\n")
    (repo / "README.md").write_text("# safe\n")
    return repo


@pytest.fixture(scope="session")
def audit_default(tmp_path_factory) -> dict:
    """Audit en mode default (AUDIT_PARALLEL=1, pas sandbox, pas offline)."""
    repo = _make_mini_repo(tmp_path_factory.mktemp("M-default"))
    p = run_wrapper("client-audit-code", str(repo), timeout=120)
    return {"out": p.stdout + p.stderr, "rc": p.returncode}


@pytest.fixture(scope="session")
def audit_parallel0(tmp_path_factory) -> dict:
    """Audit en mode serial (AUDIT_PARALLEL=0)."""
    repo = _make_mini_repo(tmp_path_factory.mktemp("M-serial"))
    p = run_wrapper(
        "client-audit-code", str(repo),
        env_extra={"AUDIT_PARALLEL": "0"},
        timeout=180,
    )
    return {"out": p.stdout + p.stderr, "rc": p.returncode}


@pytest.fixture(scope="session")
def audit_offline(tmp_path_factory) -> dict:
    """Audit en mode offline (AUDIT_OFFLINE=1)."""
    repo = _make_mini_repo(tmp_path_factory.mktemp("M-offline"))
    p = run_wrapper(
        "client-audit-code", str(repo),
        env_extra={"AUDIT_OFFLINE": "1"},
        timeout=180,
    )
    return {"out": p.stdout + p.stderr, "rc": p.returncode}


def test_165_mode_default_completes(audit_default: dict) -> None:
    """TESTS.md #165 — mode default termine sans crash."""
    assert "AUDIT TERMINÉ" in audit_default["out"], \
        f"audit default pas terminé:\n{audit_default['out'][-500:]}"
    assert audit_default["rc"] in (0, 1), \
        f"default rc inattendu: {audit_default['rc']}"


def test_166_mode_parallel_0_serial(audit_parallel0: dict) -> None:
    """TESTS.md #166 — AUDIT_PARALLEL=0 (serial) termine sans crash."""
    assert "AUDIT TERMINÉ" in audit_parallel0["out"], \
        f"audit serial pas terminé:\n{audit_parallel0['out'][-500:]}"
    assert audit_parallel0["rc"] in (0, 1), \
        f"serial rc inattendu: {audit_parallel0['rc']}"
    # Pas de crash 'TOOL_PIDS unbound' (anti-régression bug #117)
    assert "variable sans liaison" not in audit_parallel0["out"], \
        "régression bug #117 : 'variable sans liaison' en AUDIT_PARALLEL=0"


def test_167_mode_sandbox_supported_by_wrapper() -> None:
    """TESTS.md #167 — AUDIT_SANDBOX=1 supporté (firejail intégré).

    Test statique : on évite de lancer l'audit sandboxé (peut nécessiter
    config firejail spécifique). On valide la présence des branches code.
    """
    src = (BIN_DIR / "client-audit-code").read_text()
    # Pattern strict : `if [ "$AUDIT_SANDBOX" = "1" ]; then ... firejail ... --profile ...`
    has_branch = bool(re.search(
        r'if\s+\[\s+"\$AUDIT_SANDBOX"\s*=\s*"1"\s+\][^{]*?firejail',
        src, re.DOTALL,
    ))
    has_profile = bool(re.search(r"firejail[^\n]*--profile=", src))
    assert has_branch, "pas de branche conditionnelle 'if AUDIT_SANDBOX=1 then firejail'"
    assert has_profile, "firejail invoqué sans --profile= (config sandbox absente)"


def test_168_mode_offline_skips_online_tools(audit_offline: dict) -> None:
    """TESTS.md #168 — AUDIT_OFFLINE=1 termine et skippe les outils réseau."""
    out = audit_offline["out"]
    assert "AUDIT TERMINÉ" in out, f"audit offline pas terminé:\n{out[-500:]}"
    # Au moins un outil doit être marqué SKIPPED ou similaire (mode offline)
    assert re.search(r"SKIP|skipped|offline", out, re.IGNORECASE), \
        f"aucun outil skippé en mode offline:\n{out[-500:]}"


def test_169_combo_modes_supported() -> None:
    """TESTS.md #169 — combo PARALLEL=0+SANDBOX=1+OFFLINE=1 supporté (statique).

    Test statique : on évite de lancer le combo (firejail peut demander
    root et trop ralentir). On valide juste que les 3 vars sont reconnues
    indépendamment dans le wrapper.
    """
    src = (BIN_DIR / "client-audit-code").read_text()
    for var in ("AUDIT_PARALLEL", "AUDIT_SANDBOX", "AUDIT_OFFLINE"):
        # Doit être déclaré avec valeur par défaut explicite (pas juste mentionné)
        assert re.search(rf'{var}="\$\{{?{var}:?-[01]', src), \
            f"{var} sans valeur par défaut explicite (var orpheline)"
    # OFFLINE=1 doit déclencher SANDBOX=1 (ligne d'assignation à proximité immédiate du test)
    pattern = r'if\s+\[\s+"\$AUDIT_OFFLINE"\s*=\s*"1"[^{]*?AUDIT_SANDBOX=1'
    assert re.search(pattern, src, re.DOTALL), \
        "AUDIT_OFFLINE=1 ne force PAS explicitement AUDIT_SANDBOX=1 (fix #93/#169)"
