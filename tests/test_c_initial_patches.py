"""Section C — Patches initiaux (tests #25-31 de TESTS.md)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import BIN_DIR, run_wrapper


def test_025_fingerprint_loopback_and_link_local() -> None:
    """TESTS.md #25 — patch regex IP : 127.0.0.0/8 + 169.254.0.0/16 reconnus."""
    cases = [
        ("127.0.0.1", ("Loopback", "loopback")),
        ("127.5.5.5", ("Loopback", "loopback")),
        ("169.254.1.1", ("Link-local", "link-local")),
    ]
    for ip, expect_any in cases:
        p = run_wrapper("audit-fingerprint", ip, timeout=20)
        out = p.stdout + p.stderr
        assert any(s in out for s in expect_any), \
            f"{ip} non reconnu comme {expect_any}:\n{out[-300:]}"
        assert "IP PUBLIQUE" not in out, f"{ip} flagué publique (régression)"
