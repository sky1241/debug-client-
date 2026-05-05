"""Section D — Multi-langage SAST (tests #32-49 de TESTS.md).

Helper `audit_rosetta(tmp_path)` : crée un mini-rosetta-stone, lance
client-audit-code dessus, retourne le LOG_DIR. Appelé par chaque test.

Pas de fixture session-scope pour permettre un branchage RÉEL (vider un .out
puis relancer le test → FAIL, alors qu'avec scope=session pytest re-loaderait
la fixture et masquerait le branchage).
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


def audit_rosetta(tmp_path: Path) -> Path:
    """Crée un mini-rosetta dans tmp_path, lance client-audit-code, retourne LOG_DIR."""
    rosetta = tmp_path / "rosetta"
    rosetta.mkdir()
    _build_rosetta(rosetta)
    p = run_wrapper("client-audit-code", str(rosetta), timeout=300)
    out = p.stdout + p.stderr
    assert "AUDIT TERMINÉ" in out, f"audit pas terminé:\n{out[-500:]}"
    log_dirs = sorted((Path.home() / "audit-logs" / rosetta.name).glob("*"))
    assert log_dirs, f"aucun LOG_DIR pour {rosetta.name}"
    return log_dirs[-1]


def test_032_bandit_detects_python_vulns(tmp_path: Path) -> None:
    """TESTS.md #32 — bandit détecte B307 (eval) ou B403 (pickle) ou B602 (shell)."""
    log_dir = audit_rosetta(tmp_path)
    out = (log_dir / "bandit.out").read_text(errors="ignore")
    found = [c for c in ("B307", "B403", "B602") if c in out]
    assert found, f"aucun pattern bandit trouvé:\n{out[:600]}"
