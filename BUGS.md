# BUGS — .claude-tooling

> Format: each bug has an ID, status, symptom, root cause, fix, and test.
> This file is READ BY CLAUDE AT BOOT. Keep it accurate.

<!-- TEMPLATE
## BUG-XXX: [short description]
- **Status**: OPEN / FIXED / WONTFIX
- **Symptom**: what happens
- **Root cause**: WHY it happens (not just where)
- **Fix**: what was done (commit hash if fixed)
- **Test**: which test covers this (file:test_name)
- **Regression**: did the fix break anything else?
-->

## BUG-001: test_f_diff helper crash sur dossier parent inexistant
- **Status**: FIXED
- **Symptom**: `tests/test_f_diff.py::test_054/055/057` FAIL avec `FileNotFoundError: ...test_054_diff_detects_fixed_vs0/prev/log` — dans `_create_log_dir_with_outs`.
- **Root cause**: `(parent / "log").mkdir()` est appelé sans `parents=True`, et `parent` (= `tmp_path / "prev"`) n'existe pas encore.
- **Fix**: ajouté `parent.mkdir(parents=True, exist_ok=True)` ligne avant `log.mkdir()`.
- **Test**: tests/test_f_diff.py::test_054_diff_detects_fixed_vs_new + test_055 + test_057 (tous passent maintenant).
- **Regression**: aucune (fix isolé au helper de test).

## BUG-008: forge.py add_bug crée BUG+XXX et close_bug ne le retrouve pas
- **Status**: FIXED
- **Symptom**: `forge.py --add "..."` crée des entrées `## BUG+008` (avec `+` au lieu de `-`). `forge.py --close BUG-008` ne le trouve pas (et même `--close BUG+008` échoue car `+` est un metachar regex non échappé).
- **Root cause**:
  1. forge.py:674 — `bug_id = f"BUG+{next_num:03d}"` typo `+` au lieu de `-`.
  2. forge.py:699 — `pattern = f"(## {bug_id}:..."` n'échappe pas les metachars du bug_id, donc `+` devient quantifieur regex et le match foire.
- **Fix**:
  1. Remplacer `BUG+` par `BUG-` dans add_bug (forge.py:674).
  2. Wrapper `bug_id` dans `re.escape()` dans close_bug (forge.py:699) pour robustesse.
  3. Ajouté `flags=re.DOTALL` au re.sub() pour cohérence avec la sémantique `.*?` du pattern.
- **Test**: `forge.py --add "X"` puis `--close BUG-NNN` → "marked FIXED" confirmé.
- **Regression**: aucune (fix isolé à 2 lignes de forge.py).
- **Note**: bug **trouvé en testant tous les axes forge** après gueulade Sky « POURQUOI TU AS PAS UTILISER LA TOTALITÉ ». Validation que tester chaque axe a une vraie valeur (BUG-007 et BUG-008 trouvés tous deux pendant ce rattrapage).

## BUG-007: test_011 GitHub API rate-limit (403) après usage répété
- **Status**: FIXED
- **Symptom**: après ~50 runs forge consécutifs, test_011 fail avec `HTTP Error 403: rate limit exceeded`. Le retry 3x avec backoff 2/4/6s (BUG-002) ne suffit pas — rate-limit dure 1h.
- **Root cause**: GitHub API limite à 60 req/h pour les requêtes anonymes. Aucun token utilisé.
- **Fix**:
  1. `pytest.skip()` propre si HTTP 403 + "rate limit" dans la raison → état env, pas bug code.
  2. Lit `GITHUB_TOKEN` depuis l'environnement et l'ajoute en header `Authorization: Bearer` → augmente la limite à 5000/h si disponible.
- **Test**: tests/test_b_cole_de_danse.py::test_011_repo_findable_via_github_api.
- **Regression**: aucune.

## BUG-005: test_083 firejail_blocks_ssh_dir non branché (regex laxe)
- **Status**: FIXED
- **Symptom**: sabotage par commentage de `blacklist ${HOME}/.ssh` dans le profil firejail → test PASS au lieu de FAIL → branchage fictif.
- **Root cause**: regex `r"blacklist\s+\${HOME}/\.ssh"` matchait aussi `# blacklist ${HOME}/.ssh` (pas d'ancrage début de ligne).
- **Fix**: pattern strict `r"^\s*blacklist\s+(\$\{HOME\}|~)/\.ssh\s*$"` avec `re.MULTILINE`. Sabotage par commentage → test FAIL confirmé.
- **Test**: tests/test_i_hardening.py::test_083_firejail_blocks_ssh_dir.
- **Regression**: aucune.

## BUG-006: 4 autres tests avec regex .* permissifs
- **Status**: FIXED
- **Symptom**: tests qui PASSENT par construction (regex match presque tout) — révélés par audit niveau 1 (note 12/20).
- **Root cause**: utilisation de `.*` avec `re.DOTALL` dans les patterns sur sources de wrappers (test_070, test_093, test_136, test_167, test_169).
- **Fix**:
  - test_070 → exiger `printf '...set -o pipefail...' > "$script_file"` complet
  - test_093 → exiger `if [ "$AUDIT_OFFLINE" = "1" ] ... AUDIT_SANDBOX=1`
  - test_136 → exiger `::1`/`fe80::` ET flag `-6` sur ping/nmap (au lieu de juste `:`)
  - test_167 → exiger `if AUDIT_SANDBOX=1 then firejail` ET `firejail --profile=`
  - test_169 → exiger valeurs par défaut explicites pour les 3 vars
- **Test**: 5 tests resserrés, 85/85 PASS sur sections I+K+M.
- **Regression**: aucune (sabotage confirme désormais le branchage réel).

## BUG-004: test_040 cargo-audit RUSTSEC flaky (advisory-db git fetch)
- **Status**: FIXED
- **Symptom**: `tests/test_d_multi_lang.py::test_040` fail intermittent : `couldn't fetch advisory database: git operation failed`. La sortie contient l'erreur réseau au lieu du RUSTSEC attendu.
- **Root cause**: cargo-audit clone/pull `https://github.com/RustSec/advisory-db.git` à chaque run. Sous charge ou rate-limit GitHub, le fetch échoue → output ne contient pas RUSTSEC-X-Y → assertion FAIL.
- **Fix**: skip propre si l'erreur réseau est détectée dans cargo-audit.out (`pytest.skip(reason=...)`). Si réseau OK, l'assertion s'applique normalement.
- **Test**: tests/test_d_multi_lang.py::test_040_cargo_audit_detects_rustsec.
- **Regression**: aucune.

## BUG-003: test_020/021/022 curl haoyanwuying.com flaky (réseau prod)
- **Status**: FIXED
- **Symptom**: 1 fail aléatoire sur 3 (curl exit 28 = timeout) lors d'un forge complet — `tests/test_b_cole_de_danse.py::test_022` notamment.
- **Root cause**: 3 tests utilisent `curl https://haoyanwuying.com/...` sans retry. GitHub Pages / CDN prod a des micro-glitches qui font timeout.
- **Fix**: helper `_curl_retry(args, attempts=3, sleep_s=2)` qui retry sur exit non-zéro avec backoff progressif. Appliqué aux 3 tests.
- **Test**: 5/5 batches consécutifs PASS après fix.
- **Regression**: aucune.

## BUG-002: test_011 GitHub API flaky (rate-limit / réseau)
- **Status**: FIXED
- **Symptom**: `tests/test_b_cole_de_danse.py::test_011_repo_findable_via_github_api` flip-flop : ~1/3 fail (déjà détecté dans `.forge/flaky.json`).
- **Root cause**: requête GitHub API sans retry, sans User-Agent, timeout court (10s). GitHub API throttle silencieusement les requêtes anonymes répétitives.
- **Fix**: ajouté retry 3x avec backoff (2s/4s/6s) + header `User-Agent: claude-tooling-test` + `Accept: application/vnd.github+json` + timeout 15s. Cf `tests/test_b_cole_de_danse.py:39`.
- **Test**: 5/5 passes consécutifs après fix (avant : 1 fail / 2 pass).
- **Regression**: aucune (fix isolé au test).


## BUG+008: BUG-008 demo après fix
- **Status**: OPEN
- **Date**: 2026-05-06 10:36
- **Symptom**: [a remplir]
- **Root cause**: [a remplir]
- **Fix**: [pending]
- **Test**: [a ecrire]
- **Regression**: [a verifier]

## BUG-009: demo après fix BUG-008+009
- **Status**: FIXED (2026-05-06)
- **Date**: 2026-05-06 10:37
- **Symptom**: [a remplir]
- **Root cause**: [a remplir]
- **Fix**: [pending]
- **Test**: [a ecrire]
- **Regression**: [a verifier]
