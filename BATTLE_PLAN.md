# BATTLE PLAN — anti-drift Claude

> Ce document est mon prompt de référence. Je le relis avant CHAQUE chunk.
> Si je dévie, Sky a le droit de me coller mon nez dedans.

---

## La règle absolue (3 étapes par chunk)

Pour chacun des 180 tests de `TESTS.md`, je fais dans l'ordre **strict** :

### 1. **JE DOIS CODER** le test en Python
- 1 fichier `tests/test_<section>.py`, 1 fonction `def test_NNN_<nom>():` par chunk
- Code propre : docstring courte, asserts précis, pas de mock à la con
- Le test doit appeler le **vrai wrapper** via `subprocess.run` (pas faker)
- Pas de hardcoded merde : paths via `tempfile`/`tmp_path`, env via `os.environ`

### 2. **LE FAIRE PASSER À L'AUDIT FORGE**
```bash
cd ~/.claude-tooling
python3 forge.py                      # run tous les tests, doit dire 0 fail
python3 forge.py --diff               # vs baseline → 0 régression
```
- Si forge dit FAIL ou régression : **STOP**
- Debug via `forge.py --bisect TEST_NAME` ou `forge.py --locate` (Ochiai SBFL)
- Pas de fix à l'aveugle : forge me dit où, je fix là, forge re-valide
- Si vraiment bloqué : WebSearch autorisé pour le contexte

### 3. **BRANCHER** (vérifier que ça tourne et détecte vraiment)
- Le test doit RÉELLEMENT exécuter le wrapper bash, pas juste exister
- Cassez le wrapper exprès → le test doit FAIL (= il est branché)
- Re-réparez → le test doit PASS
- Mettre à jour baseline forge : `python3 forge.py --baseline`

### 4. (post-3) Commit + push GitHub
```bash
git add tests/ .forge/
git commit -m "test(chunk N/180): <description>"
git remote set-url origin "https://sky1241:${PAT}@github.com/sky1241/debug-client-.git"
git push origin main
git remote set-url origin git@github.com:sky1241/debug-client-.git
```

---

## Garantie 0 régression à chaque chunk

À chunk N :
- forge.py **doit** dire 0 fail sur l'intégralité (chunks 1..N)
- Si un test de chunk passé fail → c'est une régression, **STOP avant push**
- forge `--bisect` pour identifier le commit cassé
- Fix → re-run forge → push uniquement si tout vert

---

## Découpage des 180 chunks (référence TESTS.md)

| Section | Range | Fichier | Nb |
|---|---|---|---|
| A. Health-check | 1-10 | `test_a_health_check.py` | 10 |
| B. Cole-de-danse | 11-24 | `test_b_cole_de_danse.py` | 14 |
| C. Patches initiaux | 25-31 | `test_c_initial_patches.py` | 7 |
| D. Multi-langage SAST | 32-49 | `test_d_multi_lang.py` | 18 |
| E. gitleaks/retire/pip-audit | 50-53 | `test_e_extra_tools.py` | 4 |
| F. Mode delta | 54-57 | `test_f_diff.py` | 4 |
| G. CI rosetta | 58-64 | `test_g_rosetta.py` | 7 |
| H. Audit pro v1 | 65-69 | (intégrés dans D/G) | 5 |
| I. Hardening 10 chunks | 70-116 | `test_i_hardening.py` | 47 |
| J. Audit honnête v2 | 117-121 | `test_j_post_v2.py` | 5 |
| K. Edge cases | 122-157 | `test_k_edge_cases.py` | 36 |
| L. Attack resistance | 158-164 | `test_l_attack.py` | 7 |
| M. Modes 5 | 165-169 | `test_m_modes.py` | 5 |
| N. Forge self | 170-180 | `test_n_forge_self.py` | 11 |
| **TOTAL** | | | **180** |

---

## Choses à NE PAS FAIRE (anti-drift)

- ❌ Sauter "brancher" pour gagner du temps (= test mort)
- ❌ Coder 10 tests d'un coup avant forge audit (= je perds le bénéfice de la détection précoce)
- ❌ Push sans avoir fait forge `--diff` (= je propage potentiellement des régressions)
- ❌ Mocker un wrapper si "ça marche pareil" (= je teste le mock, pas le wrapper)
- ❌ Ignorer un test flaky en disant "il passera tout seul" (= dette technique)
- ❌ Fix un wrapper sans test qui prouve la régression (= je bidouille)
- ❌ Inventer des tests qui ne sont pas dans TESTS.md (= drift de scope)

## Choses à FAIRE (anti-drift)

- ✅ Avant chaque chunk : relire ce BATTLE_PLAN.md
- ✅ Après chaque chunk : `forge.py --diff` obligatoire
- ✅ Si forge dit régression : `--bisect` AVANT de toucher au code
- ✅ Commit message format strict : `test(chunk N/180): <description>`
- ✅ Push après chaque chunk (= état réplicable côté Sky GitHub)
- ✅ Mode silencieux mais vérifiable : Sky doit pouvoir voir l'historique forge + git

---

## Setup (chunk 0 avant tout)

1. `cd ~/.claude-tooling/`
2. Créer `tests/` (vide) + `tests/conftest.py` (helpers : `run_wrapper(name, *args, **env)`)
3. `python3 forge.py --init` (crée BUGS.md + structure si pas déjà là)
4. `python3 forge.py --baseline` (snapshot vide initial)
5. Commit setup + push
6. **Puis** chunk 1 (test #1 health-check)

---

## Mantra

> *Code → forge audit → branche (détection réelle) → diff 0 régression → commit → push.*
> *180 fois. Pas une de moins.*
> *Si je dévie, je relis ce fichier.*
