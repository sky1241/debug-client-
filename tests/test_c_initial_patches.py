"""Section C — Patches initiaux (tests #25-31 de TESTS.md)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import BIN_DIR, run_wrapper


def test_029_has_bin_excludes_git_and_images() -> None:
    """TESTS.md #29 — HAS_BIN exclut .git/* + extensions images (sshfs marque tout exécutable)."""
    code = (BIN_DIR / "client-audit-code").read_text()
    # On cherche le bloc HAS_BIN=$(find ... avec ses exclusions
    has_bin = re.search(r"HAS_BIN=\$\(find.*?\| head -1\)", code, re.DOTALL)
    assert has_bin, "définition HAS_BIN introuvable"
    block = has_bin.group(0)
    for excl in ("*/.git/*", "*.jpg", "*.png", "*.gif"):
        assert excl in block, f"exclusion {excl!r} absente de HAS_BIN (régression chunk 29)"


def test_028_eslint_flat_config_with_ts_parser() -> None:
    """TESTS.md #28 — Le wrapper utilise eslint flat config + parser TS via require absolu."""
    code = (BIN_DIR / "client-audit-code").read_text()
    assert "eslint.config.cjs" in code, "config flat ESLint absente"
    assert "@typescript-eslint/parser" in code, "parser TypeScript absent"
    assert "/usr/local/lib/node_modules" in code, "chemin absolu parser absent"


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
