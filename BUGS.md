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

## BUG-002: test_011 GitHub API flaky (rate-limit / réseau)
- **Status**: FIXED
- **Symptom**: `tests/test_b_cole_de_danse.py::test_011_repo_findable_via_github_api` flip-flop : ~1/3 fail (déjà détecté dans `.forge/flaky.json`).
- **Root cause**: requête GitHub API sans retry, sans User-Agent, timeout court (10s). GitHub API throttle silencieusement les requêtes anonymes répétitives.
- **Fix**: ajouté retry 3x avec backoff (2s/4s/6s) + header `User-Agent: claude-tooling-test` + `Accept: application/vnd.github+json` + timeout 15s. Cf `tests/test_b_cole_de_danse.py:39`.
- **Test**: 5/5 passes consécutifs après fix (avant : 1 fail / 2 pass).
- **Regression**: aucune (fix isolé au test).

