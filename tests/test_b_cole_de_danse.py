"""Section B — Audit du repo réel `sky1241/-cole-de-danse` (tests #11-24).

Pas de skip pytest sur fail réseau : si le réseau est down, le test FAIL
(c'est bien — il signale que l'env n'est pas dans l'état attendu).
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


COLE_REPO_URL = "https://github.com/sky1241/-cole-de-danse.git"


def test_011_repo_findable_via_github_api() -> None:
    """TESTS.md #11 — Le repo `sky1241/-cole-de-danse` est trouvable via API GitHub."""
    with urllib.request.urlopen(
        "https://api.github.com/repos/sky1241/-cole-de-danse", timeout=10
    ) as resp:
        data = json.loads(resp.read())
    assert data.get("name") == "-cole-de-danse"
    assert data.get("private") is False, "repo doit être public"


def test_014_cole_de_danse_cname_haoyanwuying(tmp_path: Path) -> None:
    """TESTS.md #14 — Le CNAME du repo cloné = `haoyanwuying.com`."""
    target = tmp_path / "clone"
    p = subprocess.run(
        ["git", "clone", "--depth=1", COLE_REPO_URL, str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 0, f"clone failed: {p.stderr[-200:]}"
    cname = (target / "CNAME").read_text().strip()
    assert cname == "haoyanwuying.com", f"CNAME inattendu: {cname!r}"


def test_013_audit_fingerprint_on_html_repo(tmp_path: Path) -> None:
    """TESTS.md #13 — `audit-fingerprint` sur un dossier HTML détecte 'DOSSIER' + 'HTML'."""
    repo = tmp_path / "site"
    repo.mkdir()
    (repo / "index.html").write_text("<!DOCTYPE html><html><body>x</body></html>")
    p = run_wrapper("audit-fingerprint", str(repo), timeout=20)
    out = p.stdout + p.stderr
    assert "DOSSIER" in out, f"section DOSSIER manquante:\n{out[-300:]}"
    assert "HTML" in out, f"HTML non détecté:\n{out[-300:]}"


def test_012_git_clone_works(tmp_path: Path) -> None:
    """TESTS.md #12 — `git clone` récupère le repo (index.html + .git/ présents)."""
    target = tmp_path / "clone"
    p = subprocess.run(
        ["git", "clone", "--depth=1", COLE_REPO_URL, str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 0, f"clone failed: {p.stderr[-300:]}"
    assert (target / "index.html").is_file()
    assert (target / ".git").is_dir()
