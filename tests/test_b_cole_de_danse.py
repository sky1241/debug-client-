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


def test_017_whatweb_detects_python(http_server: int) -> None:
    """TESTS.md #17 — `whatweb -a 3` détecte Python/SimpleHTTP."""
    p = subprocess.run(
        ["whatweb", "-a", "3", f"http://127.0.0.1:{http_server}/"],
        capture_output=True, text=True, timeout=30,
    )
    out = p.stdout + p.stderr
    assert any(s in out for s in ("Python", "SimpleHTTP", "BaseHTTP")), \
        f"techno python non détectée:\n{out[-300:]}"


def test_018_nikto_runs(http_server: int) -> None:
    """TESTS.md #18 — `nikto` tourne et produit un rapport non-vide."""
    p = subprocess.run(
        ["nikto", "-h", f"http://127.0.0.1:{http_server}",
         "-nointeractive", "-ask", "no", "-maxtime", "20s"],
        capture_output=True, text=True, timeout=60,
    )
    out = p.stdout + p.stderr
    assert "Nikto" in out, f"nikto non lancé:\n{out[-300:]}"
    assert "Server:" in out, f"output incomplet:\n{out[-300:]}"


def test_019_gobuster_finds_index(http_server: int, tmp_path: Path) -> None:
    """TESTS.md #19 — `gobuster dir` trouve `index.html` sur le HTTP server."""
    wl = tmp_path / "wl.txt"
    wl.write_text("index.html\nrobots.txt\nfoo\nbar\n")
    p = subprocess.run(
        ["gobuster", "dir", "-u", f"http://127.0.0.1:{http_server}",
         "-w", str(wl), "-q", "-t", "20", "--no-error"],
        capture_output=True, text=True, timeout=30,
    )
    assert "index.html" in p.stdout, f"gobuster n'a pas trouvé index.html:\n{p.stdout[-300:]}"


def test_020_prod_headers_github_pages() -> None:
    """TESTS.md #20 — `curl -I haoyanwuying.com` retourne 200 + signature GitHub Pages/Fastly."""
    p = subprocess.run(
        ["curl", "-sI", "-L", "--max-time", "10", "https://haoyanwuying.com/"],
        capture_output=True, text=True, timeout=15,
    )
    assert p.returncode == 0, f"curl exit {p.returncode}: {p.stderr[-200:]}"
    out = p.stdout
    assert "200" in out, f"pas de 200 OK:\n{out[:300]}"
    assert any(s in out.lower() for s in ("github.com", "fastly", "varnish")), \
        f"signature GitHub Pages absente:\n{out[:400]}"


def test_021_prod_blocks_git_head() -> None:
    """TESTS.md #21 — `haoyanwuying.com/.git/HEAD` retourne 404 (prod safe)."""
    p = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-L", "--max-time", "10", "https://haoyanwuying.com/.git/HEAD"],
        capture_output=True, text=True, timeout=15,
    )
    assert p.returncode == 0, f"curl exit {p.returncode}"
    assert p.stdout.strip() == "404", f"prod expose .git/HEAD ! code={p.stdout!r}"


def test_022_prod_blocks_git_config() -> None:
    """TESTS.md #22 — `haoyanwuying.com/.git/config` retourne 404."""
    p = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10", "https://haoyanwuying.com/.git/config"],
        capture_output=True, text=True, timeout=15,
    )
    assert p.returncode == 0
    assert p.stdout.strip() == "404", f"prod expose .git/config ! code={p.stdout!r}"


def test_023_inline_js_no_dangerous_patterns(cole_clone: Path) -> None:
    """TESTS.md #23 — Le JS inline d'index.html ne contient pas eval/Function/innerHTML."""
    html = (cole_clone / "index.html").read_text(errors="ignore")
    blocks = re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
        html, re.DOTALL | re.IGNORECASE,
    )
    js = "\n".join(blocks)
    forbidden = ("eval(", "new Function(", "document.write(", ".innerHTML =")
    found = [p for p in forbidden if p in js]
    assert not found, f"patterns dangereux dans JS inline: {found}"


@pytest.mark.slow
def test_024_client_audit_code_produces_report(cole_clone: Path) -> None:
    """TESTS.md #24 — `client-audit-code` produit un rapport markdown sur cole-de-danse."""
    p = run_wrapper("client-audit-code", str(cole_clone), timeout=180)
    out = p.stdout + p.stderr
    assert "AUDIT TERMINÉ" in out, f"audit pas terminé:\n{out[-400:]}"
    rapports = list(cole_clone.glob("audit-claude-*.md"))
    assert rapports, f"aucun rapport généré dans {cole_clone}"




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
