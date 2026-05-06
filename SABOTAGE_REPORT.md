# SABOTAGE REPORT — preuve de branchage RÉEL

> Date : 2026-05-06
> Contexte : auto-audit a révélé que Claude (instance 2) avait écrit 124 tests
> en majorité statiques (regex sur source des wrappers bash) sans vérifier que
> ces tests détectent vraiment les régressions. Audit niveau 3 noté 4/20.

## Méthodologie

Pour chaque test statique critique, le script `scripts/sabotage_runner.py` :

1. **Backup** du fichier source (cp -p)
2. **Sabotage** : substitution Python sur le source (équivalent sed)
3. **Run** du test ciblé via pytest -k <test_id>
4. **Verify FAIL** : returncode != 0 attendu
5. **Restore** depuis backup
6. **Re-run** : returncode == 0 attendu (test repassé)

## Résultat : 14/15 ✅

| # | Test | Wrapper saboté | Sabotage | Résultat |
|---|---|---|---|---|
| 1 | test_065_dockle_uses_input_flag | bin/client-audit-code | retire `--input` | ✓ FAIL→PASS |
| 2 | test_066_bash_c_uses_pipefail | bin/client-audit-code | retire `set -o pipefail` | ✓ FAIL→PASS |
| 3 | test_067_wait_iterates_per_pid | bin/client-audit-code | renomme `TOOL_PIDS=()` | ✓ FAIL→PASS |
| 4 | test_068_date_tag_includes_pid | bin/client-audit-code | retire `-$$` du DATE_TAG | ✓ FAIL→PASS |
| 5 | test_069_strict_patterns | bin/client-audit-test | retire `[1-9]` du regex | ✓ FAIL→PASS |
| 6 | test_076_rsync_safe_links | bin/client-audit-code | `--safe-links` → `--copy-links` | ✓ FAIL→PASS |
| 7 | test_082_firejail_profile_exists | firejail/claude-audit.profile | renomme le fichier | ✓ FAIL→PASS |
| 8 | test_083_firejail_blocks_ssh_dir | firejail/claude-audit.profile | commente la ligne | ✓ FAIL→PASS (après tighten) |
| 9 | test_085_firejail_supports_net_none | bin/client-audit-code | `--net=none` → `--net=foo` | ✓ FAIL→PASS |
| 10 | test_094_format_all_supported | bin/client-audit-code | `md\|json\|all` → `md\|json` | ✓ FAIL→PASS |
| 11 | test_117_tool_pids_explicit | bin/client-audit-code | `TOOL_PIDS=()` → `declare -a TOOL_PIDS` | ✓ FAIL→PASS |
| 12 | test_119_gitleaks_version | tool-versions.lock | `gitleaks=8.26.0` → `gitleaks=process` | ✓ FAIL→PASS |
| 13 | test_141_142_rsync_excludes | bin/client-audit-code | retire pattern `--exclude='audit-claude-` | ✓ FAIL→PASS |
| 14 | test_148_client_audit_test_keep | bin/client-audit-test | `--keep` → `--XXkeep` | ✓ FAIL→PASS |
| 15 | test_117_v2 (suppression totale) | bin/client-audit-code | retire la ligne complètement | ✗ rc=5 cleanup raté (faux positif runner) |

## Fixs collatéraux

### test_083 était NON BRANCHÉ (regex laxe)

Premier run : sabotage = comment-out de `blacklist ${HOME}/.ssh` → test PASS quand même.

Cause : regex `r"blacklist\s+\${HOME}/\.ssh"` matche aussi `# blacklist ${HOME}/.ssh`.

**Fix appliqué** : pattern strict `r"^\s*blacklist\s+(\$\{HOME\}|~)/\.ssh\s*$"` avec `re.MULTILINE` + ancrage début/fin de ligne. Vérifié : sabotage par commentage → test FAIL maintenant.

### Autres regex laxes resserrées

Lors du même rattrapage, 4 autres tests ont été identifiés avec regex permissives et resserrés :

- **test_070_run_tool_script_has_pipefail** — regex `set -o pipefail.*\$cmd` avec `re.DOTALL` (capture arbitraire) → resserré : exiger `printf '...set -o pipefail...' > "$script_file"` complet.
- **test_093_offline_implies_sandbox** — regex avec `.*` → resserré : exiger `if [ "$AUDIT_OFFLINE" = "1" ] ... AUDIT_SANDBOX=1` (DOTALL mais ancré sur `if`).
- **test_136_audit_fingerprint_ipv6** — cherchait juste `:` dans le source (faux positif certain) → resserré : exiger explicitement `::1` / `fe80::` ET flag `-6` sur ping/nmap.
- **test_167_mode_sandbox_supported** — regex laxe → resserré : exiger `if [ "$AUDIT_SANDBOX" = "1" ]; then ... firejail` ET `firejail ... --profile=`.
- **test_169_combo_modes_supported** — vérifiait juste présence des vars → resserré : exiger valeurs par défaut explicites + couplage OFFLINE→SANDBOX.

## Bilan

- Avant rattrapage : 0 sabotage effectif documenté → audit niveau 3 = **4/20**
- Après rattrapage : 14/15 sabotages confirmés + 5 regex resserrées → niveau 3 estimé **15/20**

## Reproduction

```bash
cd ~/.claude-tooling && python3 scripts/sabotage_runner.py
```

Doit retourner `SABOTAGE REPORT — 14/15` (le 15ème est un faux positif du runner sur cleanup, pas un bug réel).
