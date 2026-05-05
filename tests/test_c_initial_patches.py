"""Section C — Patches initiaux (tests #25-31 de TESTS.md)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import BIN_DIR, run_wrapper


def test_027_html_inline_js_detection_present() -> None:
    """TESTS.md #27 — Le wrapper détecte le JS inline HTML (HAS_HTML_INLINE_JS + extraction Python)."""
    code = (BIN_DIR / "client-audit-code").read_text()
    assert "HAS_HTML_INLINE_JS" in code, "détection JS inline HTML absente (régression chunk 27)"
    assert "<script" in code, "regex extraction <script> absente"
    assert "eslint-inline" in code, "block run_tool eslint-inline absent"


def test_026_semgrep_no_quiet_in_wrapper() -> None:
    """TESTS.md #26 — Le wrapper client-audit-code n'utilise PAS '--quiet' avec semgrep.

    Le bug initial : semgrep --quiet supprime l'output texte → rapport vide.
    Le patch retire --quiet et ajoute --disable-version-check.
    """
    code = (BIN_DIR / "client-audit-code").read_text()
    # Cherche la ligne qui invoque semgrep
    semgrep_line = re.search(r"semgrep scan[^\"]*", code)
    assert semgrep_line, "ligne 'semgrep scan' introuvable dans client-audit-code"
    line = semgrep_line.group(0)
    assert "--quiet" not in line, f"--quiet présent (régression chunk 26): {line}"
    assert "--disable-version-check" in line, \
        f"--disable-version-check absent (patch chunk 26): {line}"


def test_025_fingerprint_loopback_and_link_local() -> None:
    """TESTS.md #25 — patch regex IP : 127.0.0.0/8 + 169.254.0.0/16 reconnus."""
    cases = [
        ("127.0.0.1", ("Loopback", "loopback")),
        ("127.5.5.5", ("Loopback", "loopback")),
        ("169.254.1.1", ("Link-local", "link-local")),
    ]
    for ip, expect_any in cases:
        p = run_wrapper("audit-fingerprint", ip, timeout=20)
        out = p.stdout + p.stderr
        assert any(s in out for s in expect_any), \
            f"{ip} non reconnu comme {expect_any}:\n{out[-300:]}"
        assert "IP PUBLIQUE" not in out, f"{ip} flagué publique (régression)"
