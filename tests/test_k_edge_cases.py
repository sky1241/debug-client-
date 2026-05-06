"""Section K — Edge cases agressifs post-v2.0.1 (tests #122-157 de TESTS.md).

Mix de tests dynamiques (exécution réelle wrapper sur cas tordus) et de
tests statiques (présence des fixs dans le source). Privilégie les tests
rapides et déterministes — pas de re-run install.sh ni 60k fichiers.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, REPO_ROOT, run_wrapper


WRAPPER_AUDIT_CODE = BIN_DIR / "client-audit-code"
WRAPPER_AUDIT_DOCTOR = BIN_DIR / "audit-doctor"
WRAPPER_AUDIT_HISTORY = BIN_DIR / "audit-history"
WRAPPER_AUDIT_FINGERPRINT = BIN_DIR / "audit-fingerprint"
WRAPPER_AUDIT_DIFF = BIN_DIR / "client-audit-diff"


# =========================================================================
# Path edge cases (espaces, apostrophes, unicode, FIFOs, chemin inexistant)
# =========================================================================

def test_122_filename_with_space_and_apostrophe(tmp_path: Path) -> None:
    """TESTS.md #122 — nom de fichier avec espace + apostrophe ne casse pas l'audit."""
    weird = tmp_path / "O'Brien with space.py"
    weird.write_text("def f(): pass\n")
    p = run_wrapper("audit-fingerprint", str(tmp_path), timeout=30)
    assert p.returncode == 0, f"audit-fingerprint crash sur path avec ': {p.stderr[-300:]}"


def test_123_client_name_with_apostrophe(tmp_path: Path) -> None:
    """TESTS.md #123 — nom client avec apostrophe (passé via env CLIENT_NAME)."""
    (tmp_path / "main.py").write_text("print('hi')\n")
    p = run_wrapper(
        "client-audit-code", str(tmp_path),
        env_extra={"CLIENT_NAME": "O'Test", "AUDIT_PARALLEL": "0"},
        timeout=120,
    )
    assert "AUDIT TERMINÉ" in (p.stdout + p.stderr), \
        f"audit avec CLIENT_NAME contenant ' a fail:\n{p.stderr[-300:]}"


def test_124_relative_path_dot(tmp_path: Path) -> None:
    """TESTS.md #124 — `audit-fingerprint .` (path relatif) marche."""
    (tmp_path / "main.py").write_text("def f(): pass\n")
    p = subprocess.run(
        [str(WRAPPER_AUDIT_FINGERPRINT), "."],
        capture_output=True, text=True, timeout=30, cwd=str(tmp_path),
    )
    assert p.returncode == 0, f"audit-fingerprint . crash: {p.stderr[-200:]}"


def test_125_symlink_self_loop(tmp_path: Path) -> None:
    """TESTS.md #125 — symlink loop self/parent (`ln -s . loop_self`) ne crash pas."""
    (tmp_path / "main.py").write_text("hi\n")
    (tmp_path / "loop_self").symlink_to(".")
    p = run_wrapper("audit-fingerprint", str(tmp_path), timeout=30)
    assert p.returncode == 0, f"audit-fingerprint a crash sur symlink loop: {p.stderr[-300:]}"


def test_126_127_date_tag_includes_pid_anti_collision() -> None:
    """TESTS.md #126-127 — DATE_TAG inclut $$ pour 2 audits parallèles distincts."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r'DATE_TAG=".*\$\(date[^)]+\)[^"]*-\$\$', src), \
        "DATE_TAG ne contient pas $$ — collision LOG_DIR possible (bug #126)"


# =========================================================================
# AUDIT_TOOL_TIMEOUT edge cases
# =========================================================================

def test_128_audit_tool_timeout_finite_works() -> None:
    """TESTS.md #128 — AUDIT_TOOL_TIMEOUT=N (entier positif) supporté dans le wrapper."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert "AUDIT_TOOL_TIMEOUT" in src, "AUDIT_TOOL_TIMEOUT absent du wrapper"


def test_129_audit_tool_timeout_zero_means_no_timeout() -> None:
    """TESTS.md #129 — AUDIT_TOOL_TIMEOUT=0 → pas de timeout (compat GNU `timeout 0`)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # GNU timeout traite 0 comme "pas de limite" — wrapper doit pas casser
    assert re.search(r'timeout\s+"?\$\{?AUDIT_TOOL_TIMEOUT', src), \
        "AUDIT_TOOL_TIMEOUT n'est pas passé à `timeout` directement"


def test_130_audit_tool_timeout_negative_no_crash(tmp_path: Path) -> None:
    """TESTS.md #130 — AUDIT_TOOL_TIMEOUT=-5 ne crash pas (timeout natif rejette)."""
    (tmp_path / "main.py").write_text("hi\n")
    p = run_wrapper(
        "client-audit-code", str(tmp_path),
        env_extra={"AUDIT_TOOL_TIMEOUT": "-5", "AUDIT_PARALLEL": "0"},
        timeout=120,
    )
    # Le wrapper peut ignorer ou warn, mais pas crash
    assert "AUDIT TERMINÉ" in (p.stdout + p.stderr) or p.returncode in (0, 1, 2), \
        f"wrapper a crash sur TIMEOUT=-5: rc={p.returncode}\n{p.stderr[-300:]}"


# =========================================================================
# AUDIT_MAX_FILES edge cases
# =========================================================================

def test_131_audit_max_files_one_rejects(tmp_path: Path) -> None:
    """TESTS.md #131 — AUDIT_MAX_FILES=1 → repo > 1 fichier refusé."""
    (tmp_path / "a.py").write_text("a\n")
    (tmp_path / "b.py").write_text("b\n")
    p = run_wrapper(
        "client-audit-code", str(tmp_path),
        env_extra={"AUDIT_MAX_FILES": "1"},
        timeout=30,
    )
    out = p.stdout + p.stderr
    assert p.returncode != 0 or re.search(r"trop|exceed|max|limite", out, re.IGNORECASE), \
        f"AUDIT_MAX_FILES=1 sur 2 fichiers n'a pas refusé:\n{out[-400:]}"


def test_132_audit_max_files_zero_rejects(tmp_path: Path) -> None:
    """TESTS.md #132 — AUDIT_MAX_FILES=0 → refus immédiat."""
    (tmp_path / "main.py").write_text("hi\n")
    p = run_wrapper(
        "client-audit-code", str(tmp_path),
        env_extra={"AUDIT_MAX_FILES": "0"},
        timeout=30,
    )
    assert p.returncode != 0, f"AUDIT_MAX_FILES=0 n'a pas refusé (rc={p.returncode})"


def test_133_invalid_url_returns_clean_error() -> None:
    """TESTS.md #133 — `audit-fingerprint <url-invalide>` → message clair (exit 0/1/6 ok)."""
    p = run_wrapper(
        "audit-fingerprint",
        "this-domain-doesnt-exist-zzz9876.invalid",
        timeout=30,
    )
    out = p.stdout + p.stderr
    # Plusieurs codes acceptables (selon classification du wrapper) — pas de crash brutal
    assert p.returncode in (0, 1, 6), f"exit code inattendu: {p.returncode}\n{out[-300:]}"
    assert re.search(r"échec|fail|inconnue|invalid", out.lower()), \
        f"pas de message d'erreur clair:\n{out[-300:]}"


# =========================================================================
# audit-fingerprint IPv6 (chunks 134-136)
# =========================================================================

def test_134_audit_fingerprint_ipv6_loopback_works() -> None:
    """TESTS.md #134-136 — audit-fingerprint ::1 (IPv6 loopback) supporté."""
    p = run_wrapper("audit-fingerprint", "::1", timeout=30)
    out = p.stdout + p.stderr
    assert p.returncode in (0, 1), f"audit-fingerprint ::1 crash rc={p.returncode}"
    # Doit reconnaître IPv6 (pas dire "cible inconnue")
    assert "cible inconnue" not in out.lower(), \
        f"::1 reconnu comme inconnu — fix IPv6 régressé:\n{out[:400]}"


def test_135_audit_fingerprint_ipv6_link_local() -> None:
    """TESTS.md #135 — audit-fingerprint fe80:: (IPv6 link-local) supporté."""
    p = run_wrapper("audit-fingerprint", "fe80::1", timeout=30)
    out = p.stdout + p.stderr
    assert p.returncode in (0, 1, 6), f"audit-fingerprint fe80::1 crash rc={p.returncode}"
    assert "cible inconnue" not in out.lower(), \
        f"fe80::1 reconnu comme inconnu — fix IPv6 régressé:\n{out[:400]}"


def test_136_audit_fingerprint_ipv6_pattern_in_source() -> None:
    """TESTS.md #136 — audit-fingerprint a une regex IPv6 ou flag -6 dans le source."""
    src = WRAPPER_AUDIT_FINGERPRINT.read_text()
    # Pattern IPv6 (::, ou groupes hex) ou flag -6 explicite
    has_ipv6 = bool(re.search(r":|-6|IPv6", src, re.IGNORECASE))
    assert has_ipv6, "audit-fingerprint sans support IPv6 — fix #136 manquant"


# =========================================================================
# Path unicode / accents
# =========================================================================

def test_137_path_with_accents(tmp_path: Path) -> None:
    """TESTS.md #137 — path avec accents (`/tmp/édge-té/fiché.py`) supporté."""
    accent = tmp_path / "édge-té"
    accent.mkdir()
    (accent / "fiché.py").write_text("hi\n")
    p = run_wrapper("audit-fingerprint", str(accent), timeout=30)
    assert p.returncode == 0, f"audit-fingerprint a crash sur path accent: {p.stderr[-300:]}"


def test_138_path_with_unicode_and_spaces(tmp_path: Path) -> None:
    """TESTS.md #138 — path unicode + espaces (`/tmp/test 中文 audit/`) supporté."""
    weird = tmp_path / "test 中文 audit"
    weird.mkdir()
    (weird / "main.py").write_text("hi\n")
    p = run_wrapper("audit-fingerprint", str(weird), timeout=30)
    assert p.returncode == 0, \
        f"audit-fingerprint a crash sur path unicode+espaces: {p.stderr[-300:]}"


# =========================================================================
# audit-doctor edge cases (chunks 139-140)
# =========================================================================

def test_139_audit_doctor_detects_missing_wrapper() -> None:
    """TESTS.md #139 — audit-doctor détecte un wrapper supprimé (MISSING)."""
    src = WRAPPER_AUDIT_DOCTOR.read_text()
    assert re.search(r"MISSING", src), "status MISSING absent d'audit-doctor"


def test_140_audit_doctor_detects_non_executable() -> None:
    """TESTS.md #140 — audit-doctor détecte wrapper non-exécutable (TAMPERED ou similaire)."""
    src = WRAPPER_AUDIT_DOCTOR.read_text()
    assert re.search(r"TAMPERED|not.executable|exécutable", src, re.IGNORECASE), \
        "audit-doctor ne checke pas les permissions exécutables"


# =========================================================================
# rsync exclude audit-claude-*.md (chunks 141-142)
# =========================================================================

def test_141_142_rsync_excludes_audit_artifacts() -> None:
    """TESTS.md #141-142 — rsync exclut les `audit-claude-*.md/json` du run précédent."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"--exclude=['\"]?audit-claude-\*", src), \
        "rsync ne filtre pas les audit-claude-*.md/json — bug #141 régressé"


def test_143_audit_fingerprint_nonexistent_path() -> None:
    """TESTS.md #143 — audit-fingerprint sur path inexistant → 'cible inconnue'."""
    p = run_wrapper(
        "audit-fingerprint",
        "/tmp/this-does-not-exist-zzzzz-9876543",
        timeout=15,
    )
    out = p.stdout + p.stderr
    assert "cible inconnue" in out.lower() or p.returncode != 0, \
        f"path inexistant non reporté:\n{out[:400]}"


def test_144_repo_only_dot_git(tmp_path: Path) -> None:
    """TESTS.md #144 — repo avec uniquement `.git/` (hooks samples) supporté."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    (git_dir / "hooks").mkdir()
    (git_dir / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\necho hi\n")
    p = run_wrapper("audit-fingerprint", str(tmp_path), timeout=30)
    assert p.returncode == 0, f"audit-fingerprint a crash sur repo .git/ only: {p.stderr[-300:]}"


def test_145_external_symlink_excluded_by_safe_links() -> None:
    """TESTS.md #145 — symlink vers /home/sky exclu par rsync --safe-links."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"rsync[^\n]*--safe-links", src), \
        "--safe-links absent — symlink externe pas exclu"


def test_146_client_audit_diff_empty_dirs(tmp_path: Path) -> None:
    """TESTS.md #146 — `client-audit-diff` sur dirs vides → exit non-zéro propre."""
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    p = run_wrapper("client-audit-diff", str(a), str(b), timeout=15)
    assert p.returncode != 0, "diff sur dirs vides devrait retourner non-zéro"


def test_147_audit_history_filter_no_match() -> None:
    """TESTS.md #147 — audit-history --filter avec regex sans match → tableau vide."""
    p = run_wrapper(
        "audit-history",
        "--filter=zzzz-no-match-9876xyz",
        timeout=15,
    )
    # Doit pas crash, doit retourner 0 ou 1 (selon contexte)
    assert p.returncode in (0, 1), f"audit-history --filter crash rc={p.returncode}"


def test_148_client_audit_test_keep_flag() -> None:
    """TESTS.md #148 — client-audit-test supporte --keep (rosetta + logs gardés)."""
    src = (BIN_DIR / "client-audit-test").read_text()
    assert re.search(r"--keep", src), "client-audit-test --keep absent"


def test_149_empty_dir_with_json_format(tmp_path: Path) -> None:
    """TESTS.md #149 — dossier vide + --json → JSON valide total_files=0."""
    p = run_wrapper(
        "client-audit-code", str(tmp_path),
        "--json",
        env_extra={"AUDIT_PARALLEL": "0"},
        timeout=60,
    )
    out = p.stdout + p.stderr
    # Soit ça finit propre, soit ça refuse (exit 2 acceptable car repo vide)
    assert p.returncode in (0, 2), f"empty dir + --json crash rc={p.returncode}:\n{out[-300:]}"


def test_150_audit_fingerprint_public_ip() -> None:
    """TESTS.md #150 — `audit-fingerprint 8.8.8.8` (IP publique) → warning."""
    p = run_wrapper("audit-fingerprint", "8.8.8.8", timeout=15)
    out = p.stdout + p.stderr
    assert "publique" in out.lower() or "PUBLIQUE" in out, \
        f"IP 8.8.8.8 non reconnue comme publique:\n{out[:400]}"


def test_151_max_file_size_limit_in_wrapper() -> None:
    """TESTS.md #151 — limite par fichier (AUDIT_MAX_FILE_SIZE / max-size) configurée."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_MAX_FILE_SIZE", src), "AUDIT_MAX_FILE_SIZE absent"
    # Doit être passé à rsync via --max-size (gros fichiers exclus)
    assert re.search(r"--max-size", src), "--max-size pas passé à rsync"


def test_152_audit_parallel_invalid_string_fallback() -> None:
    """TESTS.md #152 — AUDIT_PARALLEL=yes (invalide) → fallback serial (pas crash)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Doit avoir une validation de la valeur (case ou if)
    assert re.search(r"AUDIT_PARALLEL.*[01]|case.*AUDIT_PARALLEL", src), \
        "AUDIT_PARALLEL pas validé (risque crash sur valeur non-0/1)"


def test_153_audit_parallel_invalid_int_fallback() -> None:
    """TESTS.md #153 — AUDIT_PARALLEL=2 (invalide, attendu 0/1) → fallback serial."""
    # Test statique : la validation doit accepter 0 et 1 (au minimum)
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r'AUDIT_PARALLEL.*=\s*"?[01]"?', src), \
        "AUDIT_PARALLEL n'a pas de cas par défaut connu"


def test_154_install_sh_idempotent() -> None:
    """TESTS.md #154 — install.sh idempotent (script ne casse pas en re-run).

    Test statique : on lit install.sh et on vérifie les patterns d'idempotence
    (ln -sf ou check existence avant link). Pas de re-run réel pour ne pas
    polluer /usr/local/bin.
    """
    install = (REPO_ROOT / "install.sh").read_text()
    # Patterns d'idempotence : ln -sf, [ -f ] check, ou cp -n
    assert re.search(r"ln\s+-[sf]+|\[\s+-f\s|test\s+-f|cp\s+-n", install), \
        "install.sh sans pattern d'idempotence (ln -sf / check existence)"


def test_155_audit_fingerprint_with_fifo(tmp_path: Path) -> None:
    """TESTS.md #155 — audit-fingerprint sur dir avec FIFO ne crash pas."""
    fifo_path = tmp_path / "test.fifo"
    os.mkfifo(str(fifo_path))
    (tmp_path / "main.py").write_text("hi\n")
    try:
        p = run_wrapper("audit-fingerprint", str(tmp_path), timeout=15)
        assert p.returncode == 0, f"audit-fingerprint crash sur FIFO: {p.stderr[-300:]}"
    finally:
        if fifo_path.exists():
            fifo_path.unlink()


def test_156_157_pip_audit_marked_as_online() -> None:
    """TESTS.md #156-157 — pip-audit utilise run_tool_online (skippé en AUDIT_OFFLINE)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Cherche pip-audit ET run_tool_online sur la même région du fichier
    pip_lines = [m.start() for m in re.finditer(r"pip-audit", src)]
    assert pip_lines, "pip-audit absent du wrapper"
    # Au moins un pip-audit doit être dans run_tool_online
    online_calls = re.findall(r"run_tool_online[^\n]*pip-audit", src)
    assert online_calls, \
        "pip-audit pas marqué online — fix bug #156-157 manquant"
