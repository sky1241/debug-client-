"""Section D — Multi-langage SAST (tests #32-49 de TESTS.md).

Une fixture session-scope `rosetta_audit` lance client-audit-code une seule fois
sur un mini-rosetta (1 vuln par langage) et chaque test vérifie son outil.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from conftest import BIN_DIR, run_wrapper


@pytest.fixture(scope="session")
def rosetta_audit(tmp_path_factory) -> Path:
    """Crée un rosetta-stone, lance client-audit-code, retourne le LOG_DIR.

    Tous les tests #32-49 partagent ce LOG_DIR pour gagner du temps.
    """
    rosetta = tmp_path_factory.mktemp("rosetta-D")
    # Python — bandit
    (rosetta / "bad.py").write_text(
        "import os, pickle\n"
        "def attack(u):\n"
        "    eval(u); pickle.loads(u); os.system('rm '+u)\n"
    )
    # Python deps vulnérables — pip-audit
    (rosetta / "requirements.txt").write_text("requests==2.6.0\n")
    # Go — gosec G401
    (rosetta / "bad.go").write_text(
        "package main\nimport \"crypto/md5\"\n"
        "func main() { _ = md5.New() }\n"
    )
    # JS — eslint
    (rosetta / "bad.js").write_text("function f(x){ eval(x); new Function(x)(); }\n")
    # TS — eslint avec parser
    (rosetta / "bad.ts").write_text("export function bad(x: string): void { eval(x); }\n")
    # Inline JS in HTML — eslint-inline (mais HAS_JS prend priorité si bad.js present !)
    # Pour tester eslint-inline indépendamment, on le fait dans un sous-dir séparé
    # → ici on vérifie que eslint trouve les vulns du JS standalone
    (rosetta / "index.html").write_text(
        "<html><head><script type='application/ld+json'>{}</script></head>"
        "<body><script>var x=1;</script></body></html>"
    )
    # PHP — phpstan
    (rosetta / "bad.php").write_text("<?php\nfunction bad($u) { return $u . $undef; }\n")
    # Ruby — brakeman + bundler-audit
    (rosetta / "bad.rb").write_text("def bad(input); eval(input); end\n")
    (rosetta / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (4.0.0)\n"
        "PLATFORMS\n  ruby\nDEPENDENCIES\n  rails (= 4.0.0)\n"
    )
    # Rust — cargo-audit (RUSTSEC-2020-0071)
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
    # C — cppcheck + flawfinder
    (rosetta / "bad.c").write_text(
        '#include <stdio.h>\n#include <string.h>\n'
        'void bad(char *u) { char b[16]; strcpy(b, u); gets(b); }\n'
        'int main() { return 0; }\n'
    )
    # Shell — shellcheck SC2086
    (rosetta / "bad.sh").write_text("#!/bin/bash\nrm -rf $1\n")
    # YAML — yamllint
    (rosetta / "bad.yml").write_text("foo:\n   bar: 1\n  baz: 2\n")
    # Dockerfile vulnérable — trivy-config + dockle
    (rosetta / "Dockerfile").write_text(
        "FROM ubuntu:14.04\nUSER root\nADD https://example.com/x.sh /tmp/x.sh\nEXPOSE 22\n"
    )
    # K8s manifest vulnérable — trivy-config
    (rosetta / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\n"
        "spec:\n  containers:\n  - name: c\n    image: nginx:1.0\n"
        "    securityContext:\n      privileged: true\n      runAsUser: 0\n"
    )
    # Terraform vulnérable
    (rosetta / "main.tf").write_text(
        'resource "aws_s3_bucket" "leaky" { bucket = "x"; acl = "public-read-write" }\n'
    )
    # gitleaks — AWS key + GitHub PAT
    (rosetta / "secrets.py").write_text(
        'aws_id = "AKIAQ27Y4PNJ4PYG2XYZ"\n'
        'github_pat = "ghp_abc123XYZ456abc123XYZ456abc123XYZ4567"\n'
    )
    # retire — jQuery vulnérable
    (rosetta / "jquery-1.6.1.min.js").write_text("/*! jQuery v1.6.1 */\n")
    # EICAR pour clamav
    eicar = rosetta / "eicar.com"
    eicar.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    # Dummy bin > 1k pour HAS_BIN
    dummy = rosetta / "dummy.bin"
    dummy.write_bytes(os.urandom(1100))
    dummy.chmod(0o755)
    # package.json + lock pour osv-scanner / trivy-deps
    (rosetta / "package.json").write_text(
        '{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.0.0"}}\n'
    )
    (rosetta / "package-lock.json").write_text(
        '{"name":"x","version":"1.0.0","lockfileVersion":2,"requires":true,'
        '"packages":{"node_modules/lodash":{"version":"4.0.0",'
        '"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.0.0.tgz"}}}\n'
    )

    # Lance client-audit-code
    p = run_wrapper("client-audit-code", str(rosetta), timeout=300)
    assert "AUDIT TERMINÉ" in (p.stdout + p.stderr), f"audit pas terminé:\n{(p.stdout+p.stderr)[-500:]}"

    # Localise le LOG_DIR
    rosetta_name = rosetta.name
    log_root = Path.home() / "audit-logs" / rosetta_name
    log_dirs = sorted(log_root.glob("*"))
    assert log_dirs, f"aucun LOG_DIR trouvé dans {log_root}"
    return log_dirs[-1]


def test_032_bandit_detects_python_vulns(rosetta_audit: Path) -> None:
    """TESTS.md #32 — bandit détecte B307 (eval) ou B403 (pickle) ou B602 (shell)."""
    out = (rosetta_audit / "bandit.out").read_text(errors="ignore")
    found = [c for c in ("B307", "B403", "B602") if c in out]
    assert found, f"aucun pattern bandit trouvé:\n{out[:600]}"
