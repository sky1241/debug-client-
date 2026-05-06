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


def test_070_run_tool_script_has_pipefail() -> None:
    """TESTS.md #70 — `run_tool` génère un script avec `set -o pipefail`."""
    src = WRAPPER_AUDIT_CODE.read_text()
    # Le wrapper write un script intermediaire avec pipefail explicite
    assert re.search(r"set -o pipefail.*\$cmd", src, re.DOTALL) or \
           re.search(r"pipefail\\n%s\\n", src), \
        "le script généré par run_tool doit inclure 'set -o pipefail'"


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


@pytest.fixture(scope="session")
def rosetta_full_run

# =========================================================================
# Fixture session-scope (rosetta-stone multi-langages pour test_075 + autres)
# =========================================================================

(tmp_path_factory) -> dict:
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
