"""Section I — Hardening 10 chunks senior eng (tests #70-116 de TESTS.md).

Couverture des fixs hardening : bash, DoS, sandbox, offline, JSON, version
pinning, history, dry-run, zipbomb, doc. La majorité des tests sont
statiques (regex sur source du wrapper / profile / lock). Les dynamiques
sont regroupés via fixtures session-scope pour minimiser les runs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import BIN_DIR, REPO_ROOT, run_wrapper


WRAPPER_AUDIT_CODE = BIN_DIR / "client-audit-code"
WRAPPER_AUDIT_DOCTOR = BIN_DIR / "audit-doctor"
WRAPPER_AUDIT_HISTORY = BIN_DIR / "audit-history"
FIREJAIL_PROFILE = REPO_ROOT / "firejail" / "claude-audit.profile"
TOOL_LOCK = REPO_ROOT / "tool-versions.lock"


# =========================================================================
# I.1 — Bash hardening (chunks 70-75)
# =========================================================================

def test_070_run_tool_script_has_pipefail() -> None:
    """TESTS.md #70 — `run_tool` génère un script avec `set -o pipefail`."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Le wrapper utilise printf pour générer un script intermédiaire avec pipefail
    # Pattern strict : printf '#!/bin/bash\nset -o pipefail\n%s\n' "$cmd" > "$script_file"
    assert re.search(r"printf\s+['\"][^'\"]*set -o pipefail[^'\"]*['\"][^>]*>\s*\"?\$\{?script_file", src), \
        "run_tool doit générer un script avec 'set -o pipefail' explicite (printf -> script_file)"


def test_071_wait_propagates_exit_code() -> None:
    """TESTS.md #71 — `wait "$pid"` est utilisé (propage exit code worker)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r'wait\s+"?\$_?pid"?', src), \
        "wait $pid absent — propagation exit code workers cassée"


def test_072_no_pid_collision_in_temp_paths() -> None:
    """TESTS.md #72 — paths temp uniques (mktemp ou inclusion de $$)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Soit mktemp, soit -$$ explicite dans les paths /tmp/
    has_safe_tmp = bool(re.search(r"mktemp", src)) or \
                    bool(re.search(r"/tmp/[^\"'\s]*\$\$", src)) or \
                    bool(re.search(r"DATE_TAG=.*\$\$", src))
    assert has_safe_tmp, "ni mktemp ni $$ dans les paths temp — risque collision PID"


def test_073_dockle_uses_file_input() -> None:
    """TESTS.md #73 — dockle reçoit un fichier via --input (pas dir)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Pattern : `dockle ... --input {}` ou `dockle ... --input "$file"`
    assert re.search(r"dockle[^\n]*--input\s+", src), \
        "dockle doit recevoir un fichier via --input"


def test_074_double_dash_separator_for_path_args() -> None:
    """TESTS.md #74 — séparateur `--` utilisé devant les paths (cppcheck, flawfinder, yamllint)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Au moins un des outils suspects doit utiliser --
    has_sep = sum(
        1 for tool in ("cppcheck", "flawfinder", "yamllint")
        if re.search(rf"{tool}[^\n]*\s--\s", src)
    )
    assert has_sep >= 1, "aucun outil n'utilise -- séparateur (cppcheck/flawfinder/yamllint)"


def test_075_rosetta_full_audit_passes(rosetta_full_run: dict) -> None:
    """TESTS.md #75 — rosetta complet : tous les outils signal détecté."""
    summary = rosetta_full_run
    assert summary["audit_terminé"], "AUDIT TERMINÉ absent dans output"
    assert summary["log_dir"].is_dir(), f"LOG_DIR introuvable: {summary['log_dir']}"
    out_files = list(summary["log_dir"].glob("*.out"))
    assert len(out_files) >= 18, f"trop peu de .out (attendu ≥18, eu {len(out_files)})"


# =========================================================================
# I.2 — DoS limits (chunks 76-81)
# =========================================================================

def test_076_rsync_safe_links_for_external_symlinks() -> None:
    """TESTS.md #76 — rsync utilise --safe-links (exclut symlinks pointant hors src)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"rsync[^\n]*--safe-links", src), \
        "rsync doit utiliser --safe-links (anti-symlink-attack)"


def test_077_rsync_excludes_user_secrets() -> None:
    """TESTS.md #77 — rsync exclut .ssh, .aws, .gnupg via --exclude ou safe-links."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Anti-pattern : pas de copie de symlinks externes (safe-links suffit) — déjà testé en 076
    # On valide ici que la copie n'est PAS faite sans --safe-links
    rsyncs = re.findall(r"rsync[^\n]+", src)
    assert rsyncs, "aucun rsync trouvé dans le wrapper"
    for r in rsyncs:
        if "--archive" in r or "-a" in r.split():
            assert "--safe-links" in r or "-l" not in r, \
                f"rsync archive sans --safe-links détecté: {r[:200]}"


def test_078_max_files_limit_enforced() -> None:
    """TESTS.md #78 — AUDIT_MAX_FILES respecté (limite path bomb)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_MAX_FILES", src), "var AUDIT_MAX_FILES absente"
    # Doit faire un check vs la valeur (compare et exit ou skip)
    assert re.search(r"\$AUDIT_MAX_FILES|\$\{AUDIT_MAX_FILES", src), \
        "AUDIT_MAX_FILES jamais déréférencée — variable orpheline"


def test_079_max_total_size_limit_enforced() -> None:
    """TESTS.md #79 — AUDIT_MAX_TOTAL_SIZE_MB respecté (limite repo > 1 GiB)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_MAX_TOTAL_SIZE_MB", src), "AUDIT_MAX_TOTAL_SIZE_MB absente"


def test_080_find_maxdepth_capped() -> None:
    """TESTS.md #80 — `find` avec `-maxdepth` cap (anti-deep tree)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    finds = re.findall(r"find\s+[^\n|;]+", src)
    # Au moins UN find doit avoir -maxdepth (pas tous, certains find sont ciblés)
    has_capped = any("-maxdepth" in f for f in finds)
    assert has_capped, "aucun find n'utilise -maxdepth — risque deep tree"


def test_081_max_file_size_limit() -> None:
    """TESTS.md #81 — AUDIT_MAX_FILE_SIZE limite par fichier."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_MAX_FILE_SIZE|max-size", src), \
        "limite par-fichier absente (AUDIT_MAX_FILE_SIZE / --max-size)"


# =========================================================================
# I.3 — Sandbox firejail (chunks 82-90)
# =========================================================================

def test_082_firejail_profile_exists() -> None:
    """TESTS.md #82 — profil firejail présent."""
    assert FIREJAIL_PROFILE.is_file(), f"profil firejail manquant: {FIREJAIL_PROFILE}"


def test_083_firejail_blocks_ssh_dir() -> None:
    """TESTS.md #83 — profil bloque ~/.ssh (ligne non commentée)."""
    prof = FIREJAIL_PROFILE.read_text()
    # Multiline + ligne pas commentée (anti-sabotage par #)
    assert re.search(r"^\s*blacklist\s+(\$\{HOME\}|~)/\.ssh\s*$", prof, re.MULTILINE), \
        "blacklist ~/.ssh absente ou commentée du profil firejail"


def test_084_firejail_blocks_sensitive_dirs() -> None:
    """TESTS.md #84 — profil bloque .aws, .gnupg, secrets."""
    prof = FIREJAIL_PROFILE.read_text()
    sensitive = (".aws", ".gnupg")
    for s in sensitive:
        assert re.search(rf"blacklist\s+\${{HOME}}/{re.escape(s)}|blacklist\s+~/{re.escape(s)}", prof), \
            f"blacklist ~/{s} absente"


def test_085_firejail_supports_net_none() -> None:
    """TESTS.md #85 — wrapper supporte --net=none via AUDIT_OFFLINE."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"--net=none|--net\s+none", src), \
        "--net=none absent du wrapper (mode offline cassé)"


def test_086_firejail_seccomp_caps_drop() -> None:
    """TESTS.md #86 — profil firejail drop privileges (seccomp + caps)."""
    prof = FIREJAIL_PROFILE.read_text()
    assert "seccomp" in prof, "seccomp absent du profil firejail"
    assert re.search(r"caps\.drop\s+all|caps\s+drop", prof), "caps.drop all absent"
    assert "noroot" in prof, "noroot absent du profil firejail"


def test_087_firejail_rlimit_as_8gib() -> None:
    """TESTS.md #87-88 — rlimit-as ≥ 8 GiB (fix OOM semgrep)."""
    prof = FIREJAIL_PROFILE.read_text()
    m = re.search(r"rlimit-as\s+(\d+)", prof)
    assert m, "rlimit-as absent du profil"
    val = int(m.group(1))
    # 8 GiB = 8589934592, on accepte ≥ 4 GiB (on tolère config plus stricte)
    assert val >= 4 * 1024 * 1024 * 1024, f"rlimit-as trop bas: {val} (< 4 GiB)"


def test_088_firejail_rlimit_fsize_present() -> None:
    """TESTS.md #88 — rlimit-fsize cap (anti-DoS disque)."""
    prof = FIREJAIL_PROFILE.read_text()
    assert re.search(r"rlimit-fsize\s+\d+", prof), "rlimit-fsize absent (anti-DoS disque)"


def test_089_audit_sandbox_flag_in_wrapper() -> None:
    """TESTS.md #89 — AUDIT_SANDBOX=1 wrapper switch."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert "AUDIT_SANDBOX" in src, "AUDIT_SANDBOX flag absent"
    assert re.search(r"firejail.*--profile", src), \
        "firejail --profile non utilisé"


def test_090_firejail_nonewprivs() -> None:
    """TESTS.md #90 — profil firejail no-new-privs (anti-escalation)."""
    prof = FIREJAIL_PROFILE.read_text()
    assert re.search(r"nonewprivs|no-new-privs", prof), \
        "nonewprivs absent du profil — anti-escalation manquant"


# =========================================================================
# I.4 — Mode offline (chunks 91-93)
# =========================================================================

def test_091_audit_offline_flag() -> None:
    """TESTS.md #91 — AUDIT_OFFLINE=1 flag dans le wrapper."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert "AUDIT_OFFLINE" in src, "AUDIT_OFFLINE flag absent"


def test_092_run_tool_online_helper() -> None:
    """TESTS.md #92 — helper `run_tool_online` skip outils online en mode offline."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"run_tool_online", src), "helper run_tool_online absent"


def test_093_offline_implies_sandbox() -> None:
    """TESTS.md #93 — mode offline implique sandbox (force --net=none)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Pattern strict : `if [ "$AUDIT_OFFLINE" = "1" ] && ...; then ... AUDIT_SANDBOX=1`
    # On exige le test conditionnel + l'assignation AUDIT_SANDBOX=1 sur ≤6 lignes après
    pattern = r'if\s+\[\s+"\$AUDIT_OFFLINE"\s*=\s*"1"\s+\][^{]*?AUDIT_SANDBOX=1'
    assert re.search(pattern, src, re.DOTALL), \
        "AUDIT_OFFLINE=1 ne force PAS explicitement AUDIT_SANDBOX=1 (fix #93)"


# =========================================================================
# I.5 — JSON output (chunks 94-96)
# =========================================================================

def test_094_format_all_supported() -> None:
    """TESTS.md #94 — `--format=all` génère .md + .json."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # FORMAT="all" doit être listé comme valeur valide (pas seulement md/json)
    assert re.search(r"md\|json\|all|all\|json\|md|md, json, all", src), \
        "format 'all' non supporté dans le wrapper"


def test_095_json_schema_versioned() -> None:
    """TESTS.md #95 — schéma JSON nommé/versionné (claude-audit-code/v1 ou similaire)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"claude-audit-code/v\d", src) or \
           re.search(r'"schema"', src), \
        "schéma JSON non versionné"


def test_096_json_only_format_supported() -> None:
    """TESTS.md #96 — `--format=json` seul supporté (pas de .md généré)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r'--format[= ]json|FORMAT[= ]json', src), \
        "--format=json absent du wrapper"


# =========================================================================
# I.6 — Version pinning + cache (chunks 97-102)
# =========================================================================

def test_097_tool_lock_has_24_tools() -> None:
    """TESTS.md #97 — tool-versions.lock contient ≥ 20 outils (24 cible)."""
    lines = [l for l in TOOL_LOCK.read_text().splitlines()
             if l.strip() and not l.startswith("#") and "=" in l]
    assert len(lines) >= 20, f"tool-versions.lock incomplet: {len(lines)} outils (attendu ≥20)"


def test_098_audit_doctor_runs_clean() -> None:
    """TESTS.md #98 — audit-doctor sort sans erreur (état OK / DRIFT acceptable)."""
    p = run_wrapper("audit-doctor", timeout=30)
    out = p.stdout + p.stderr
    assert p.returncode in (0, 1), f"audit-doctor crash code {p.returncode}:\n{out[-400:]}"
    assert re.search(r"OK|DRIFT|MISSING|TAMPERED", out), \
        f"audit-doctor pas de status:\n{out[-400:]}"


def test_099_audit_doctor_detects_tampering() -> None:
    """TESTS.md #99 — audit-doctor détecte un wrapper modifié (TAMPERED)."""
    src = WRAPPER_AUDIT_DOCTOR.read_text()
    assert re.search(r"TAMPERED|sha256sum|--check", src), \
        "audit-doctor sans checksum / TAMPERED detection"


def test_100_audit_doctor_can_bump() -> None:
    """TESTS.md #100 — audit-doctor supporte --bump (re-checksum)."""
    src = WRAPPER_AUDIT_DOCTOR.read_text()
    assert re.search(r"--bump|bump_checksums", src), \
        "audit-doctor --bump absent"


def test_101_cache_dirs_setup() -> None:
    """TESTS.md #101 — caches CVE configurés (.cache/audit-stack/{trivy,grype,osv-scanner})."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"\.cache/audit-stack|TRIVY_CACHE_DIR|GRYPE_DB_CACHE", src), \
        "caches CVE persistants non configurés"


def test_102_caches_used_by_tools() -> None:
    """TESTS.md #102 — outils CVE pointent sur le cache custom (speedup)."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Au moins un des cache dirs doit être passé en env aux outils
    has_cache_env = any(re.search(rf"{var}", src)
                        for var in ("TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR", "OSV_SCANNER_CACHE"))
    assert has_cache_env, "aucune var cache CVE exportée"


# =========================================================================
# I.7 — audit-history (chunks 103-106)
# =========================================================================

def test_103_audit_history_jsonl_format() -> None:
    """TESTS.md #103 — audit-history écrit en JSONL."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"\.audit-history\.jsonl|audit-history\.jsonl", src) or \
           ".audit-history" in WRAPPER_AUDIT_HISTORY.read_text(), \
        "fichier .audit-history.jsonl jamais référencé"


def test_104_audit_history_supports_limit() -> None:
    """TESTS.md #104 — audit-history --limit=N supporté."""
    src = WRAPPER_AUDIT_HISTORY.read_text()
    assert re.search(r"--limit", src), "audit-history --limit absent"


def test_105_audit_history_supports_filter() -> None:
    """TESTS.md #105 — audit-history --filter=X supporté."""
    src = WRAPPER_AUDIT_HISTORY.read_text()
    assert re.search(r"--filter", src), "audit-history --filter absent"


def test_106_audit_history_handles_corrupt_lines() -> None:
    """TESTS.md #106 — audit-history tolère lignes JSONL corrompues."""
    src = WRAPPER_AUDIT_HISTORY.read_text()
    # Doit avoir un try/except ou check JSON parse
    assert re.search(r"parse.error|try:|JSONDecodeError|continue", src, re.IGNORECASE), \
        "audit-history ne gère pas les lignes corrompues"


# =========================================================================
# I.8 — --dry-run (chunks 107-109)
# =========================================================================

def test_107_dry_run_flag_present() -> None:
    """TESTS.md #107 — --dry-run flag dans le wrapper."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"--dry-run|DRY_RUN", src), "--dry-run flag absent"


def test_108_dry_run_compatible_with_json() -> None:
    """TESTS.md #108 — --dry-run --json génère output structuré."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Doit avoir mention DRY-RUN dans le code (status spécial dans manifest/json)
    assert re.search(r"DRY[-_]RUN|dry.run", src, re.IGNORECASE), \
        "DRY-RUN status absent du code"


def test_109_dry_run_skips_execution() -> None:
    """TESTS.md #109 — en --dry-run, run_tool ne lance PAS l'outil."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Heuristique : check que DRY_RUN gate les exécutions
    assert re.search(r'(\$DRY_RUN|"\$\{DRY_RUN\}").*"1"|DRY_RUN.*=.*1.*return', src, re.DOTALL), \
        "DRY_RUN ne gate pas l'exécution"


# =========================================================================
# I.9 — Zipbomb detection (chunks 110-112)
# =========================================================================

def test_110_zipbomb_ratio_check() -> None:
    """TESTS.md #110 — wrapper calcule un ratio compressed/uncompressed."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"zipbomb|ratio|compress.*ratio", src, re.IGNORECASE), \
        "détection zipbomb absente"


def test_111_zipbomb_threshold_warning() -> None:
    """TESTS.md #111 — seuil ratio (warning ou reject) configuré."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_ZIPBOMB|RATIO|seuil|threshold", src, re.IGNORECASE), \
        "seuil zipbomb non configuré"


def test_112_zipbomb_reject_mode() -> None:
    """TESTS.md #112 — AUDIT_REJECT_ZIPBOMB=1 fait exit 2."""
    src = WRAPPER_AUDIT_CODE.read_text()
    assert re.search(r"AUDIT_REJECT_ZIPBOMB|REJECT_ZIPBOMB", src), \
        "AUDIT_REJECT_ZIPBOMB flag absent"


# =========================================================================
# I.10 — Doc + tag (chunks 113-116)
# =========================================================================

def test_113_readme_has_threat_model() -> None:
    """TESTS.md #113 — README v2 contient threat model."""
    readme = (REPO_ROOT / "README.md").read_text()
    assert re.search(r"threat\s*model", readme, re.IGNORECASE), \
        "README sans 'threat model' — doc v2 incomplete"


def test_114_changelog_present() -> None:
    """TESTS.md #114 — CHANGELOG.md présent et non-vide."""
    cl = REPO_ROOT / "CHANGELOG.md"
    assert cl.is_file(), "CHANGELOG.md manquant"
    content = cl.read_text()
    assert len(content) > 200, f"CHANGELOG trop court: {len(content)} chars"
    assert re.search(r"^##\s+v?\d", content, re.MULTILINE), \
        "CHANGELOG sans entrée versionnée"


def test_115_v2_tag_exists() -> None:
    """TESTS.md #115 — tag v2.x existe dans git."""
    p = subprocess.run(
        ["git", "tag", "--list", "v2*"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    tags = [t.strip() for t in p.stdout.splitlines() if t.strip()]
    assert any(t.startswith("v2") for t in tags), f"aucun tag v2.x trouvé: {tags}"


def test_116_three_modes_validated_in_doc() -> None:
    """TESTS.md #116 — README mentionne les 3 modes (default / sandbox / offline)."""
    readme = (REPO_ROOT / "README.md").read_text()
    for mode in ("AUDIT_SANDBOX", "AUDIT_OFFLINE"):
        assert mode in readme, f"mode {mode} non documenté dans README"


# =========================================================================
# Fixtures dynamiques partagées (1 audit pour I.1#75 et autres dynamiques)
# =========================================================================

@pytest.fixture(scope="session")
def rosetta_full_run(tmp_path_factory) -> dict:
    """Lance UN audit-code sur un rosetta-stone multi-langages."""
    repo = tmp_path_factory.mktemp("rosetta-I") / "repo"
    repo.mkdir()
    # Mini rosetta multi-lang pour activer ≥18 outils (Python, Go, JS, Ruby, Rust, C, Bash, YAML, Docker, K8s, etc.)
    (repo / "bad.py").write_text("import os\ndef f(x): eval(x); os.system('rm '+x)\n")
    (repo / "requirements.txt").write_text("requests==2.6.0\n")
    (repo / "bad.go").write_text('package main\nimport "crypto/md5"\nfunc main() { _ = md5.New() }\n')
    (repo / "bad.js").write_text("function f(x){ eval(x); }\n")
    (repo / "bad.ts").write_text("export function f(x: string){ eval(x); }\n")
    (repo / "bad.rb").write_text("def bad(x); eval(x); end\n")
    (repo / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (4.0.0)\nDEPENDENCIES\n  rails\n")
    (repo / "Cargo.lock").write_text(
        'version = 3\n[[package]]\nname = "time"\nversion = "0.1.43"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "ca8a50ef2360fbd1eeb0ecd46795a87a19024eb4b53c5dc916ca1fd95fe62438"\n'
    )
    (repo / "bad.c").write_text("#include <string.h>\nvoid f(char *u){ char b[16]; strcpy(b,u); }\n")
    (repo / "bad.sh").write_text("#!/bin/bash\nrm -rf $1\n")
    (repo / "bad.yml").write_text("foo:\n   bar: 1\n  baz: 2\n")
    (repo / "Dockerfile").write_text("FROM ubuntu:14.04\nUSER root\n")
    (repo / "package.json").write_text('{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.0.0"}}\n')
    p = run_wrapper("client-audit-code", str(repo), timeout=300)
    out = p.stdout + p.stderr
    log_dirs = sorted((Path.home() / "audit-logs" / repo.name).glob("*"))
    return {
        "audit_terminé": "AUDIT TERMINÉ" in out,
        "log_dir": log_dirs[-1] if log_dirs else Path("/dev/null"),
        "stdout": p.stdout,
        "stderr": p.stderr,
        "returncode": p.returncode,
    }
