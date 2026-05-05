"""Section G — CI rosetta-stone `client-audit-test` (tests #58-64 de TESTS.md)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


def test_058_no_lax_patterns_left() -> None:
    """TESTS.md #58 — Plus de patterns laxes type 'findings:|Findings:' tout court."""
    code = (BIN_DIR / "client-audit-test").read_text()
    # Pattern lax = matcherait Findings: 0
    assert "Findings: [1-9]" in code, "pattern semgrep strict absent"
    # Pas de pattern qui matche tout
    assert not re.search(r'CHECKS\+=.*"semgrep@@findings:\|Findings:@@', code), \
        "pattern lax semgrep encore présent"


def test_059_patterns_audit_done() -> None:
    """TESTS.md #59 — L'audit a effectivement supprimé les patterns laxes."""
    code = (BIN_DIR / "client-audit-test").read_text()
    # On vérifie quelques patterns stricts mis à la place
    expected_strict = [
        ("trivy-deps", "Total: [1-9]"),
        ("trivy-config", "FAILURES: [1-9]"),
        ("osv-scanner", "affected by [1-9]"),
    ]
    missing = []
    for tool, expected in expected_strict:
        if expected not in code:
            missing.append(f"{tool} → {expected}")
    assert not missing, f"patterns stricts manquants: {missing}"


def test_060_strict_patterns_present() -> None:
    """TESTS.md #60 — Les patterns stricts (counters non-zéro) sont en place."""
    code = (BIN_DIR / "client-audit-test").read_text()
    # Ces patterns doivent matcher 1+ findings non-zéro
    for pat in ("Findings: [1-9]", "Total: [1-9]", "FAILURES: [1-9]"):
        assert pat in code, f"pattern strict {pat!r} absent"


def test_061_findings_zero_rejected() -> None:
    """TESTS.md #61 — Le pattern 'Findings: [1-9]' rejette 'Findings: 0'."""
    pat = re.compile(r"Findings:\s*[1-9]|[1-9][0-9]*\s*findings\.")
    assert not pat.search("Findings: 0 (0 blocking)\nRan 66 rules: 0 findings."), \
        "pattern strict accepterait à tort Findings: 0"
    assert pat.search("Findings: 8 (8 blocking)"), \
        "pattern strict ne matche pas Findings: 8"


def test_062_trivy_total_zero_rejected() -> None:
    """TESTS.md #62 — Le pattern 'Total: [1-9]|CVE-[0-9]' rejette 'Total: 0'."""
    pat = re.compile(r"Total:\s*[1-9]|CVE-[0-9]")
    assert not pat.search("Total: 0 (UNKNOWN: 0, LOW: 0)"), \
        "pattern accepterait Total: 0 (faux positif)"
    assert pat.search("Total: 1 (MEDIUM: 1)"), "pattern rejette Total: 1"
    assert pat.search("CVE-2024-12345 found"), "pattern rejette CVE-..."


def test_063_osv_scanner_zero_rejected() -> None:
    """TESTS.md #63 — Le pattern 'affected by [1-9]' rejette osv-scanner 0 vulns."""
    pat = re.compile(r"affected by [1-9][0-9]* known|FIXED VERSION")
    assert not pat.search("Total 0 packages affected by 0 known vulnerabilities"), \
        "pattern accepterait 0 vulns"
    assert pat.search("Total 4 packages affected by 16 known vulnerabilities"), \
        "pattern rejette le cas avec vulns"


@pytest.mark.slow
def test_064_audit_test_full_run() -> None:
    """TESTS.md #64 — `client-audit-test` complet retourne 23/0/0."""
    p = subprocess.run(
        [str(BIN_DIR / "client-audit-test")],
        capture_output=True, text=True, timeout=300,
    )
    out = p.stdout + p.stderr
    assert p.returncode == 0, f"audit-test exit {p.returncode}:\n{out[-500:]}"
    # Doit afficher RÉSULTAT avec >= 20 PASS, 0 FAIL
    m = re.search(r"RÉSULTAT\s*:\s*([0-9]+)\s*PASS\s*/\s*([0-9]+)\s*FAIL", out)
    assert m, f"ligne RÉSULTAT absente:\n{out[-500:]}"
    passed, failed = int(m.group(1)), int(m.group(2))
    assert failed == 0, f"{failed} FAIL — détails dans output"
    assert passed >= 20, f"{passed} PASS — attendu >=20"
