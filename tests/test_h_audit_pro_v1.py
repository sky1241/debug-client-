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
