"""Sabotage runner — branchage RÉEL de 15 tests statiques.

Pour chaque test :
1. Backup le fichier source (cp -p)
2. Apply sabotage (sed-like substitution Python)
3. Run le test ciblé via pytest
4. Verify FAIL (returncode != 0)
5. Restore (cp -p backup)
6. Run le test à nouveau
7. Verify PASS (returncode == 0)
8. Report PASS/FAIL du sabotage
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path("/home/sky/.claude-tooling")
BIN = REPO / "bin"

# Tests à sabotager : (test_id, file_path, sabotage_fn, restore_check)
SABOTAGES = [
    # H — Audit pro v1
    ("test_065_dockle_uses_input_flag",
     BIN / "client-audit-code",
     lambda s: s.replace("dockle --no-color -f list --exit-level fatal --input {}",
                          "dockle --no-color -f list --exit-level fatal {}")),
    ("test_066_bash_c_uses_pipefail",
     BIN / "client-audit-code",
     lambda s: s.replace("set -o pipefail\\n", "")),
    ("test_067_wait_iterates_per_pid",
     BIN / "client-audit-code",
     lambda s: s.replace("TOOL_PIDS=()", "TOOL_PIDS_OFF=()")),
    ("test_068_date_tag_includes_pid",
     BIN / "client-audit-code",
     lambda s: s.replace('DATE_TAG="$(date +%Y-%m-%d-%H%M%S)-$$"',
                          'DATE_TAG="$(date +%Y-%m-%d-%H%M%S)"')),
    ("test_069_strict_patterns_in_audit_test",
     BIN / "client-audit-test",
     lambda s: s.replace("Findings: [1-9]", "Findings: ")),

    # I — Hardening
    ("test_076_rsync_safe_links_for_external_symlinks",
     BIN / "client-audit-code",
     lambda s: s.replace("--safe-links", "--copy-links")),
    ("test_082_firejail_profile_exists",
     REPO / "firejail" / "claude-audit.profile",
     "RENAME"),  # special : on renomme le fichier
    ("test_083_firejail_blocks_ssh_dir",
     REPO / "firejail" / "claude-audit.profile",
     lambda s: s.replace("blacklist ${HOME}/.ssh", "# blacklist ${HOME}/.ssh")),
    ("test_085_firejail_supports_net_none",
     BIN / "client-audit-code",
     lambda s: s.replace("--net=none", "--net=foo")),
    ("test_094_format_all_supported",
     BIN / "client-audit-code",
     lambda s: s.replace("md|json|all", "md|json")),

    # J — post-v2
    ("test_117_tool_pids_explicit_array_init",
     BIN / "client-audit-code",
     lambda s: s.replace("TOOL_PIDS=()", "declare -a TOOL_PIDS")),
    ("test_119_gitleaks_version_extraction_works",
     REPO / "tool-versions.lock",
     lambda s: s.replace("gitleaks=8.26.0", "gitleaks=process")),

    # K — edge cases
    ("test_141_142_rsync_excludes_audit_artifacts",
     BIN / "client-audit-code",
     lambda s: s.replace("--exclude='audit-claude-", "--exclude='not-touched-")),
    ("test_148_client_audit_test_keep_flag",
     BIN / "client-audit-test",
     lambda s: s.replace("--keep", "--XXkeep")),

    # H bonus
    ("test_117_tool_pids_explicit_array_init_v2",
     BIN / "client-audit-code",
     lambda s: s.replace("TOOL_PIDS=()", "")),
]


def run_test(test_id: str) -> int:
    """Run un test pytest, retourne le returncode (0 = PASS, !=0 = FAIL)."""
    # Match all files containing this test
    p = subprocess.run(
        ["python3", "-m", "pytest", f"tests/", "-k", test_id, "-x", "-q",
         "--timeout=30", "--tb=no", "--no-header"],
        capture_output=True, text=True, cwd=str(REPO), timeout=60,
    )
    return p.returncode


def main() -> None:
    results: list[tuple[str, bool, str]] = []  # (test_id, branched_ok, note)

    for entry in SABOTAGES:
        test_id, target, op = entry[0], entry[1], entry[2]
        if not target.exists() and op != "RENAME":
            results.append((test_id, False, f"target absent: {target}"))
            continue

        # Backup
        backup = Path(f"/tmp/sabotage_backup_{target.name}")
        if op == "RENAME":
            renamed = target.parent / (target.name + ".saboted")
            shutil.move(str(target), str(renamed))
        else:
            shutil.copy2(str(target), str(backup))
            original = target.read_text()
            mutated = op(original)
            if mutated == original:
                results.append((test_id, False, "sabotage = no-op (pattern absent)"))
                shutil.copy2(str(backup), str(target))
                continue
            target.write_text(mutated)

        # Run test → must FAIL
        rc_after_sabotage = run_test(test_id)

        # Restore
        if op == "RENAME":
            shutil.move(str(renamed), str(target))
        else:
            shutil.copy2(str(backup), str(target))
            backup.unlink()

        # Run test → must PASS
        rc_after_restore = run_test(test_id)

        if rc_after_sabotage != 0 and rc_after_restore == 0:
            results.append((test_id, True, f"sabotage→FAIL ({rc_after_sabotage}), restore→PASS"))
        elif rc_after_sabotage == 0:
            results.append((test_id, False, f"sabotage→PASS (test pas branché !) rc={rc_after_sabotage}"))
        else:
            results.append((test_id, False, f"restore→FAIL (cleanup raté) rc={rc_after_restore}"))

    # Report
    print("=" * 80)
    print(f"  SABOTAGE REPORT — {sum(1 for _, ok, _ in results if ok)}/{len(results)}")
    print("=" * 80)
    for test_id, ok, note in results:
        flag = "✓ BRANCHÉ" if ok else "✗ NON BRANCHÉ"
        print(f"  [{flag}] {test_id}")
        print(f"             → {note}")
    print("=" * 80)


if __name__ == "__main__":
    main()
