"""Section H — Audit pro v1 / fixs hardening (tests #65-69 de TESTS.md).

Ces tests valident que les fixs identifiés à l'audit pro v1 sont bien
présents dans le source des wrappers. Tests statiques (regex) — branchage
par construction : sed du fix dans le source → test FAIL.
"""
from __future__ import annotations

import re
from pathlib import Path

from conftest import BIN_DIR


WRAPPER_AUDIT_CODE = BIN_DIR / "client-audit-code"
WRAPPER_AUDIT_TEST = BIN_DIR / "client-audit-test"

def test_065_dockle_uses_input_flag() -> None:
    """TESTS.md #65 — dockle est lancé avec `--input <file>` (pas path positionnel)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"dockle[^\n]*--input", src), \
        "dockle doit utiliser --input (pas path positionnel) — fix bug #65"


def test_066_bash_c_uses_pipefail() -> None:
    """TESTS.md #66 — wrappers bash internes utilisent `set -o pipefail`."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Le wrapper génère des scripts avec pipefail explicite (run_tool helper)
    assert re.search(r"set -o pipefail", src), \
        "set -o pipefail absent — fix bug #66 (SIGPIPE masqué)"
    # Le set -euo pipefail global doit aussi être présent (fail fast)
    assert re.search(r"^set -[a-z]*o pipefail", src, re.MULTILINE) or \
        "set -euo pipefail" in src, "set -euo pipefail global absent"


def test_067_wait_iterates_per_pid() -> None:
    """TESTS.md #67 — `wait` est appelé par PID, pas `wait || true` aveugle."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Doit avoir un array TOOL_PIDS et une boucle for sur chaque PID
    assert "TOOL_PIDS=()" in src, "TOOL_PIDS=() absent (init array vide obligatoire)"
    assert re.search(r"TOOL_PIDS\+=\(\$!\)", src), \
        "TOOL_PIDS+=($!) absent (collecte des PIDs de jobs en arrière-plan)"
    assert re.search(r"for\s+\w+\s+in\s+\"\$\{TOOL_PIDS\[@\]\}\"", src), \
        "boucle `for pid in TOOL_PIDS[@]` absente — fix bug #67"
    # Anti-pattern strict : pas de `wait || true` aveugle
    assert not re.search(r"^\s*wait\s*\|\|\s*true\s*$", src, re.MULTILINE), \
        "anti-pattern `wait || true` détecté (masque les crashs workers)"
