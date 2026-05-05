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


@pytest.fixture(scope="session")
def cole_clone(tmp_path_factory) -> Path:
    """Clone une seule fois cole-de-danse pour toute la session.

    En cas d'échec : assert (pas pytest.skip) — l'env DOIT avoir le réseau pour B.
    """
    target = tmp_path_factory.mktemp("cole-de-danse-clone") / "repo"
    p = subprocess.run(
        ["git", "clone", "--depth=1", COLE_REPO_URL, str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 0, f"clone cole-de-danse failed (réseau ?): {p.stderr[-300:]}"
    return target


def test_011_repo_findable_via_github_api() -> None:
    """TESTS.md #11 — Le repo `sky1241/-cole-de-danse` est trouvable via API GitHub."""
    with urllib.request.urlopen(
        "https://api.github.com/repos/sky1241/-cole-de-danse", timeout=10
    ) as resp:
        data = json.loads(resp.read())
    assert data.get("name") == "-cole-de-danse"
    assert data.get("private") is False, "repo doit être public"


@pytest.fixture(scope="session")
def http_server(cole_clone: Path):
    """Lance python -m http.server sur un port libre, sert le clone cole-de-danse."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=str(cole_clone),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    yield port
    proc.terminate()
    proc.wait(timeout=5)


def test_016_http_server_serves_repo(http_server: int) -> None:
    """TESTS.md #16 — Le serveur HTTP local sert le repo (200 + HTML body)."""
    with urllib.request.urlopen(f"http://127.0.0.1:{http_server}/", timeout=5) as resp:
        assert resp.status == 200, f"status {resp.status}"
        body = resp.read().decode(errors="ignore")
    assert "<html" in body.lower() or "<!DOCTYPE" in body, f"pas de HTML servi:\n{body[:200]}"


def test_015_no_real_secret_in_html(cole_clone: Path) -> None:
    """TESTS.md #15 — Pas de pattern AWS/GitHub/Stripe réel dans index.html."""
    html = (cole_clone / "index.html").read_text(errors="ignore")
    forbidden = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT classic"),
        (r"sk_live_[A-Za-z0-9]{20,}", "Stripe live key"),
        (r"xoxb-[0-9]+-[0-9]+-", "Slack bot token"),
    ]
    found: list[str] = []
    for pat, label in forbidden:
        m = re.search(pat, html)
        if m:
            found.append(f"{label}: {m.group(0)[:30]}...")
    assert not found, f"secrets réels détectés: {found}"


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
