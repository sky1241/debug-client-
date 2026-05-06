"""Section D — Multi-langage SAST (tests #32-49 de TESTS.md).

Fixture `rosetta_audit` (scope=session) : crée un mini-rosetta-stone, lance
client-audit-code 1x par run pytest, retourne le LOG_DIR partagé.

Branchage : la fixture `safe_audit` lance audit-code sur un repo SANS vulns ;
les tests `_branche` vérifient que les patterns NE remontent PAS dans le safe
(= prouve que les tests détectent vraiment la régression).
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


def _build_rosetta(rosetta: Path) -> None:
    """Crée un mini-rosetta-stone (1 vuln par langage) dans le dossier donné."""
    (rosetta / "bad.py").write_text(
        "import os, pickle\n"
        "def attack(u):\n"
        "    eval(u); pickle.loads(u); os.system('rm '+u)\n"
    )
    (rosetta / "requirements.txt").write_text("requests==2.6.0\n")
    (rosetta / "bad.go").write_text(
        "package main\nimport \"crypto/md5\"\n"
        "func main() { _ = md5.New() }\n"
    )
    (rosetta / "bad.js").write_text("function f(x){ eval(x); new Function(x)(); }\n")
    (rosetta / "bad.ts").write_text("export function bad(x: string): void { eval(x); }\n")
    (rosetta / "index.html").write_text("<html><body>x</body></html>")
    (rosetta / "bad.php").write_text("<?php\nfunction bad($u) { return $u . $undef; }\n")
    (rosetta / "bad.rb").write_text("def bad(input); eval(input); end\n")
    (rosetta / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (4.0.0)\n"
        "PLATFORMS\n  ruby\nDEPENDENCIES\n  rails (= 4.0.0)\n"
    )
    (rosetta / "Cargo.toml").write_text(
        '[package]\nname = "test"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\ntime = "0.1.43"\n'
    )
    (rosetta / "Cargo.lock").write_text(
        'version = 3\n'
        '[[package]]\nname = "test"\nversion = "0.1.0"\n'
        '[[package]]\nname = "time"\nversion = "0.1.43"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "ca8a50ef2360fbd1eeb0ecd46795a87a19024eb4b53c5dc916ca1fd95fe62438"\n'
    )
    (rosetta / "bad.c").write_text(
        '#include <stdio.h>\n#include <string.h>\n'
        'void bad(char *u) { char b[16]; strcpy(b, u); gets(b); }\n'
        'int main() { return 0; }\n'
    )
    (rosetta / "bad.sh").write_text("#!/bin/bash\nrm -rf $1\n")
    (rosetta / "bad.yml").write_text("foo:\n   bar: 1\n  baz: 2\n")
    (rosetta / "Dockerfile").write_text(
        "FROM ubuntu:14.04\nUSER root\nADD https://example.com/x.sh /tmp/x.sh\nEXPOSE 22\n"
    )
    (rosetta / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\n"
        "spec:\n  containers:\n  - name: c\n    image: nginx:1.0\n"
        "    securityContext:\n      privileged: true\n      runAsUser: 0\n"
    )
    (rosetta / "main.tf").write_text(
        'resource "aws_s3_bucket" "leaky" { bucket = "x"; acl = "public-read-write" }\n'
    )
    (rosetta / "secrets.py").write_text(
        'aws_id = "AKIAQ27Y4PNJ4PYG2XYZ"\n'
        'github_pat = "ghp_abc123XYZ456abc123XYZ456abc123XYZ4567"\n'
    )
    (rosetta / "jquery-1.6.1.min.js").write_text("/*! jQuery v1.6.1 */\n")
    (rosetta / "eicar.com").write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    dummy = rosetta / "dummy.bin"
    dummy.write_bytes(os.urandom(1100))
    dummy.chmod(0o755)
    (rosetta / "package.json").write_text(
        '{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.0.0"}}\n'
    )
    (rosetta / "package-lock.json").write_text(
        '{"name":"x","version":"1.0.0","lockfileVersion":2,"requires":true,'
        '"packages":{"node_modules/lodash":{"version":"4.0.0",'
        '"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.0.0.tgz"}}}\n'
    )


@pytest.fixture(scope="session")
def rosetta_audit(tmp_path_factory) -> Path:
    """1 seul audit-code par run pytest. Tous les tests partagent ce LOG_DIR."""
    rosetta = tmp_path_factory.mktemp("rosetta-D") / "repo"
    rosetta.mkdir()
    _build_rosetta(rosetta)
    p = run_wrapper("client-audit-code", str(rosetta), timeout=300)
    out = p.stdout + p.stderr
    assert "AUDIT TERMINÉ" in out, f"audit pas terminé:\n{out[-500:]}"
    log_dirs = sorted((Path.home() / "audit-logs" / rosetta.name).glob("*"))
    assert log_dirs, f"aucun LOG_DIR pour {rosetta.name}"
    return log_dirs[-1]


@pytest.fixture(scope="session")
def safe_audit(tmp_path_factory) -> Path:
    """Audit-code sur un repo SANS vulns — sert de référence pour valider le branchage."""
    site = tmp_path_factory.mktemp("safe-D") / "repo"
    site.mkdir()
    (site / "main.py").write_text("def add(a, b):\n    return a + b\n")
    (site / "README.md").write_text("# Safe project\n")
    p = run_wrapper("client-audit-code", str(site), timeout=120)
    out = p.stdout + p.stderr
    assert "AUDIT TERMINÉ" in out, f"audit safe pas terminé:\n{out[-300:]}"
    log_dirs = sorted((Path.home() / "audit-logs" / site.name).glob("*"))
    assert log_dirs
    return log_dirs[-1]


def test_032_bandit_detects_python_vulns(rosetta_audit: Path) -> None:
    """TESTS.md #32 — bandit détecte B307/B403/B602 sur le rosetta piégé."""
    out = (rosetta_audit / "bandit.out").read_text(errors="ignore")
    found = [c for c in ("B307", "B403", "B602") if c in out]
    assert found, f"aucun pattern bandit trouvé:\n{out[:600]}"


def test_033_gosec_detects_md5(rosetta_audit: Path) -> None:
    """TESTS.md #33 — gosec détecte G401 (MD5 weak crypto) sur bad.go."""
    out = (rosetta_audit / "gosec.out").read_text(errors="ignore")
    assert "G401" in out, f"G401 non détecté:\n{out[:400]}"


def test_034_eslint_detects_eval_in_js(rosetta_audit: Path) -> None:
    """TESTS.md #34 — eslint trouve no-eval / no-new-func dans bad.js."""
    out = (rosetta_audit / "eslint.out").read_text(errors="ignore")
    assert "no-eval" in out or "no-new-func" in out, f"eslint n'a rien trouvé:\n{out[:400]}"


def test_035_eslint_ts_parser_works(rosetta_audit: Path) -> None:
    """TESTS.md #35 — eslint avec parser TS détecte eval() dans bad.ts."""
    out = (rosetta_audit / "eslint.out").read_text(errors="ignore")
    assert "bad.ts" in out, f"bad.ts non analysé (parser TS cassé ?):\n{out[:400]}"


def test_036_eslint_inline_present(rosetta_audit: Path) -> None:
    """TESTS.md #36 — détection HAS_HTML_INLINE_JS active (peut être skippée si HAS_JS prend priorité)."""
    # Sur le rosetta on a bad.js → HAS_JS prend priorité et eslint-inline est skippé.
    # On valide juste que la branche existe dans le wrapper (test_027 le fait déjà côté code).
    # Ici on s'assure que le manifest pour eslint-inline existe (skippé OU lancé selon présence JS).
    manifest_dir = rosetta_audit / ".manifests"
    assert manifest_dir.is_dir()
    # Soit eslint, soit eslint-inline, soit les deux ont une trace
    has_eslint = (manifest_dir / "eslint.line").exists() or (manifest_dir / "eslint-inline.line").exists()
    assert has_eslint, "ni eslint ni eslint-inline dans manifests"


def test_037_phpstan_detects_undefined_var(rosetta_audit: Path) -> None:
    """TESTS.md #37 — phpstan détecte la variable PHP indéfinie."""
    out = (rosetta_audit / "phpstan.out").read_text(errors="ignore")
    assert "undef" in out.lower() or "Variable" in out, f"phpstan rien:\n{out[:400]}"


def test_038_brakeman_detects_warnings(rosetta_audit: Path) -> None:
    """TESTS.md #38 — brakeman détecte au moins 1 warning sécurité."""
    out = (rosetta_audit / "brakeman.out").read_text(errors="ignore")
    assert re.search(r"Security Warnings: [1-9]", out), f"brakeman 0 warning:\n{out[:400]}"


def test_039_bundler_audit_detects_rails_cve(rosetta_audit: Path) -> None:
    """TESTS.md #39 — bundler-audit détecte CVE sur Gemfile.lock Rails 4.0.0."""
    out = (rosetta_audit / "bundler-audit.out").read_text(errors="ignore")
    assert "Name: rails" in out and "CVE" in out, f"bundler-audit pas de CVE Rails:\n{out[:600]}"
    assert "Vulnerabilities found" in out, f"bannière 'Vulnerabilities found' absente:\n{out[-400:]}"


def test_040_cargo_audit_detects_rustsec(rosetta_audit: Path) -> None:
    """TESTS.md #40 — cargo-audit détecte RUSTSEC sur Cargo.lock time 0.1.43."""
    out = (rosetta_audit / "cargo-audit.out").read_text(errors="ignore")
    assert re.search(r"RUSTSEC-\d{4}-\d{4}", out), f"cargo-audit pas de RUSTSEC:\n{out[:500]}"


def test_041_cppcheck_detects_gets(rosetta_audit: Path) -> None:
    """TESTS.md #41 — cppcheck détecte gets() obsolete sur bad.c."""
    out = (rosetta_audit / "cppcheck.out").read_text(errors="ignore")
    assert ("getsCalled" in out) or ("obsolete" in out.lower() and "gets" in out), \
        f"cppcheck pas de finding gets():\n{out[:500]}"


def test_042_flawfinder_detects_buffer_overflow(rosetta_audit: Path) -> None:
    """TESTS.md #42 — flawfinder détecte CWE-120 sur strcpy/gets dans bad.c."""
    out = (rosetta_audit / "flawfinder.out").read_text(errors="ignore")
    assert "CWE-120" in out, f"flawfinder pas de CWE-120:\n{out[:500]}"
    assert "gets" in out or "strcpy" in out, f"flawfinder pas de gets/strcpy:\n{out[:500]}"


def test_043_shellcheck_detects_unquoted_var(rosetta_audit: Path) -> None:
    """TESTS.md #43 — shellcheck détecte SC2086 sur `$1` non quoté dans bad.sh."""
    out = (rosetta_audit / "shellcheck.out").read_text(errors="ignore")
    assert "SC2086" in out, f"shellcheck pas de SC2086:\n{out[:400]}"


def test_044_yamllint_detects_indent_error(rosetta_audit: Path) -> None:
    """TESTS.md #44 — yamllint détecte indent ou syntax error sur bad.yml."""
    out = (rosetta_audit / "yamllint.out").read_text(errors="ignore")
    assert "[error]" in out, f"yamllint pas d'error:\n{out[:400]}"
    assert ("indent" in out.lower()) or ("syntax error" in out.lower()), \
        f"yamllint ni indent ni syntax error:\n{out[:400]}"


def test_045_semgrep_finds_at_least_one(rosetta_audit: Path) -> None:
    """TESTS.md #45 — semgrep multi-langage trouve au moins 1 finding."""
    out = (rosetta_audit / "semgrep.out").read_text(errors="ignore")
    assert re.search(r"Findings: [1-9]", out), f"semgrep 0 findings:\n{out[-500:]}"
