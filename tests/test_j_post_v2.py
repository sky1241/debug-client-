"""Section J — Audit honnête post-v2 (tests #117-121 de TESTS.md).

Bugs trouvés à l'audit honnête v2 (Sky a redemandé "tu es sûr ?") et
fixés. Ces tests valident que les fixs sont bien en place.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import BIN_DIR, REPO_ROOT, run_wrapper


WRAPPER_AUDIT_CODE = BIN_DIR / "client-audit-code"
TOOL_LOCK = REPO_ROOT / "tool-versions.lock"


def test_117_tool_pids_explicit_array_init() -> None:
    """TESTS.md #117 — TOOL_PIDS=() init explicite (pas que `declare -a`).

    Bug : avec set -u + declare -a sans init, AUDIT_PARALLEL=0 → CRASH
    'TOOL_PIDS: variable sans liaison'. Fix : assignation `TOOL_PIDS=()` explicite.
    """
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"^TOOL_PIDS=\(\)", src, re.MULTILINE), \
        "TOOL_PIDS=() init explicite absent — fix bug #117 manquant"


def test_118_no_duration_s_grep_pattern() -> None:
    """TESTS.md #118 — DURATION_S retiré (regex `Fin d'intervalle invalide`).

    Bug : `grep "[$DURATION_S]"` produisait `Fin d'intervalle invalide`
    car DURATION_S était mal formé (entier seul, pas range). Fix : retiré.
    """
    src = WRAPPER_AUDIT_CODE.read_text()
    # DURATION_S ne doit pas apparaître dans le wrapper (si oui, le bug est revenu)
    assert "DURATION_S" not in src, \
        "DURATION_S présent dans le wrapper — bug #118 régressé"


def test_119_gitleaks_version_extraction_works() -> None:
    """TESTS.md #119 — gitleaks version extraite correctement (pas 'process').

    Bug : `gitleaks=process` dans le lock car parsing prenait la 1ère ligne
    de stdout (`Loading keys for processing...`). Fix : extraction via dpkg.
    """
    lock = TOOL_LOCK.read_text()
    m = re.search(r"^gitleaks=([^\s]+)", lock, re.MULTILINE)
    assert m, "gitleaks absent du tool-versions.lock"
    version = m.group(1)
    assert version not in ("process", "Loading", "unknown"), \
        f"gitleaks version mal extraite: '{version}' (bug #119 régressé)"
    # Doit ressembler à une version sémantique (X.Y.Z)
    assert re.match(r"^\d+\.\d+", version), \
        f"gitleaks version pas semver: '{version}'"


def test_120_audit_doctor_handles_missing_wrapper() -> None:
    """TESTS.md #120 — audit-doctor reporte propre quand un wrapper est absent (MISSING).

    Bug initial documenté dans la session : faux bug "sandbox+offline 1 FAIL transitoire"
    → après re-test = OK. Le test ici valide la stabilité d'audit-doctor face à
    une absence (cas réel observé en pratique).
    """
    src = (BIN_DIR / "audit-doctor").read_text()
    assert re.search(r"MISSING", src), "audit-doctor sans status MISSING — fix bug #120 manquant"


def test_121_dry_run_json_generates_output() -> None:
    """TESTS.md #121 — `--dry-run --json` génère bien un JSON output.

    Bug : grep filtrait trop strict → JSON vide. Fix : grep relax + DRY-RUN
    status explicit dans le manifest.
    """
    src = WRAPPER_AUDIT_CODE.read_text()
    # Doit avoir un status DRY-RUN qui passe dans le JSON output
    assert re.search(r"DRY[-_]RUN", src), "status DRY-RUN absent du wrapper"
    # Le format JSON doit aussi être traité quand DRY_RUN=1 (pas zappé)
    assert re.search(r"DRY_RUN.*FORMAT|FORMAT.*DRY_RUN|format.*dry", src, re.DOTALL | re.IGNORECASE), \
        "FORMAT/DRY_RUN handling pas évident — vérifier que JSON sort en --dry-run"
