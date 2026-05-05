"""Section E — gitleaks / retire / pip-audit (tests #50-53 de TESTS.md)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


def test_050_gitleaks_whitelists_example_keys(tmp_path: Path) -> None:
    """TESTS.md #50 — gitleaks ne flag PAS les keys 'EXAMPLE' (whitelistées)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text(
        'aws_id = "AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    )
    p = subprocess.run(
        ["gitleaks", "dir", "--no-banner", str(repo)],
        capture_output=True, text=True, timeout=30,
    )
    out = p.stdout + p.stderr
    assert "no leaks found" in out.lower(), \
        f"gitleaks aurait flag des EXAMPLE keys (faux positif):\n{out[-300:]}"


def test_051_gitleaks_detects_real_keys(tmp_path: Path) -> None:
    """TESTS.md #51 — gitleaks détecte AWS access token + GitHub PAT au format valide."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "leaks.py").write_text(
        'aws_id = "AKIAQ27Y4PNJ4PYG2XYZ"\n'
        'github_pat = "ghp_abc123XYZ456abc123XYZ456abc123XYZ4567"\n'
        'slack = "xoxb-1234567890-1234567890-AbCdEfGh_IjKlMnOpQrStUvWx"\n'
    )
    p = subprocess.run(
        ["gitleaks", "dir", "--no-banner", str(repo)],
        capture_output=True, text=True, timeout=30,
    )
    out = p.stdout + p.stderr
    m = re.search(r"leaks found:\s*([0-9]+)", out)
    assert m, f"gitleaks ne dit pas 'leaks found':\n{out[-300:]}"
    n = int(m.group(1))
    assert n >= 1, f"gitleaks a trouvé {n} leak(s) — attendu >=1 (3 keys plantées)"


def test_052_retire_finds_jquery_cves(tmp_path: Path) -> None:
    """TESTS.md #52 — retire détecte les CVE multiples sur jQuery 1.6.1."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "jquery-1.6.1.min.js").write_text("/*! jQuery v1.6.1 | (c) 2011 John Resig */\n")
    p = subprocess.run(
        ["retire", "--path", str(repo), "--outputformat", "text",
         "--severity", "medium", "--colors", "never"],
        capture_output=True, text=True, timeout=60,
    )
    out = p.stdout + p.stderr
    assert "jquery" in out.lower(), f"retire n'a pas vu jQuery:\n{out[-400:]}"
    cve_count = len(re.findall(r"CVE-[0-9]+-[0-9]+", out))
    assert cve_count >= 1, f"retire 0 CVE alors que jQuery 1.6.1 en a 9+:\n{out[-400:]}"


def test_053_pip_audit_finds_requests_vulns(tmp_path: Path) -> None:
    """TESTS.md #53 — pip-audit détecte vulns sur requests==2.6.0."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.6.0\n")
    pipaudit = Path.home() / ".local" / "bin" / "pip-audit"
    if not pipaudit.is_file():
        pipaudit = "pip-audit"  # fallback PATH
    p = subprocess.run(
        [str(pipaudit), "--disable-pip", "--no-deps", "-r", str(repo / "requirements.txt")],
        capture_output=True, text=True, timeout=60,
    )
    out = p.stdout + p.stderr
    assert "requests" in out.lower(), f"pip-audit n'a pas analysé requests:\n{out[-400:]}"
    vulns_match = re.search(r"Found ([0-9]+) known vulnerabilit", out)
    assert vulns_match and int(vulns_match.group(1)) >= 1, \
        f"pip-audit 0 vuln (attendu plusieurs):\n{out[-400:]}"
