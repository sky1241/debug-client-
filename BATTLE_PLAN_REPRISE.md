# BATTLE PLAN — REPRISE après chunk 037

> Repris par Claude (instance 2) le 2026-05-06.
> Prédécesseur arrêté à 53 commits / 180 chunks (29%) avec 3 fails non résolus.
> Doc de référence : ce fichier + `BATTLE_PLAN.md` (protocole original).

---

## État réel hérité (vérifié à la reprise)

| Section | Plan | Committés | Tests OK | Tests cassés |
|---|---|---|---|---|
| A. Health-check | 10 | 10 | 10 | 0 |
| B. Cole-de-danse | 14 | 14 | 12 | 2 flaky réseau |
| C. Patches initiaux | 7 | 7 | 7 | 0 |
| **D. Multi-lang SAST** | **18** | **7** | **7** | **0** (mais 11 manquants) |
| E. Extra tools | 4 | 4 | 4 | 0 |
| **F. Mode delta** | **4** | **4** | **1** | **3 cassés** (FileNotFoundError) |
| G. CI rosetta | 7 | 7 | 7 | 0 |
| H-N | 116 | 0 | 0 | 0 (à écrire) |

**Bug bloquant trouvé** : `tests/test_f_diff.py` ligne 13 — `_create_log_dir_with_outs()` fait `(parent / "log").mkdir()` sans créer `parent` d'abord.

**Non-committé** : `tests/test_d_multi_lang.py` contient le test_038 (brakeman) prêt mais pas committé.

**Baseline forge polluée** : `.forge/baseline.json` = 40 passed / 5 failed (interdit par BATTLE_PLAN).

**Push GitHub** : cassé depuis le début (`debug-client-` repo unreachable).

---

## Stratégie

Garder le protocole rigoureux du prédécesseur (CODE → forge audit → BRANCHE → commit) mais ajouter :

1. **0 fail dans baseline** = règle dure. Si fail → fix avant continue.
2. **Tester en lot raisonnable** : 5-10 tests, pas 1 par 1 (rythme), mais commit chunk par chunk.
3. **Push GitHub** : à régler en phase 0, sinon abandonner et travailler en local seul.
4. **BUGS.md** : remplir au fur et à mesure (template vide actuellement).

---

## Phases ordonnées

### PHASE 0 — Ménage (priorité absolue, ~30 min)

1. Fix `test_f_diff.py::_create_log_dir_with_outs` → ajouter `parent.mkdir(parents=True, exist_ok=True)` ligne avant `log.mkdir()`
2. Vérifier `client-audit-diff` répond bien avec `--out=<file>` (le wrapper existe : `bin/client-audit-diff` 6043 octets)
3. Re-run forge : vérifier 53/53 PASS
4. Re-baseline propre : `python3 forge.py --baseline` → 0 fail attendu
5. Commit fix + test_038 brakeman uncommitted
6. Tester push GitHub (avec PAT user) → si échec, continuer en local

### PHASE 1 — Compléter section D (chunks 39-49, 11 tests, ~1h)

Outils restants pour le rosetta-stone :
- 39. bundler-audit (Gemfile.lock Rails 4.0.0 → CVE)
- 40. cargo-audit (Cargo.lock time 0.1.43 → RUSTSEC)
- 41. cppcheck (bad.c → gets/strcpy)
- 42. flawfinder (bad.c → CWE-120)
- 43. shellcheck (bad.sh → SC2086)
- 44. yamllint (bad.yml → indent error)
- 45. semgrep multi-lang (rosetta → Findings: ≥1)
- 46. trufflehog3 (rosetta → secrets HIGH)
- 47. clamav (eicar.com → Eicar-Test-Signature)
- 48. trivy-deps (lockfiles → CVE)
- 49. trivy-config (Dockerfile + K8s → FAILURES ≥1)

Pattern fixe : test lit `<rosetta_audit>/<tool>.out` et asserte un pattern.

### PHASE 2 — Section H (chunks 65-69, 5 tests, ~30 min)

Tests qui valident des **fixs** (pas des outils) :
- 65. dockle utilise `--input` (regex sur source du wrapper)
- 66. `bash -c "set -o pipefail; ..."` présent (regex)
- 67. `wait` par PID (pas `wait || true`)
- 68. `mktemp -d` au lieu de `$$`
- 69. patterns stricts présents (`Findings: [1-9]`, etc.)

### PHASE 3 — Section I (chunks 70-116, 47 tests, ~3-4h)

Le plus gros morceau, en 10 sous-fichiers :

| Sous-section | Range | Sujet | Nb |
|---|---|---|---|
| I.1 | 70-75 | Bash hardening | 6 |
| I.2 | 76-81 | DoS limits | 6 |
| I.3 | 82-90 | Sandbox firejail | 9 |
| I.4 | 91-93 | Offline mode | 3 |
| I.5 | 94-96 | JSON output | 3 |
| I.6 | 97-102 | Version pinning + cache | 6 |
| I.7 | 103-106 | audit-history | 4 |
| I.8 | 107-109 | --dry-run | 3 |
| I.9 | 110-112 | Zipbomb detection | 3 |
| I.10 | 113-116 | Doc + tag | 4 |

Création de `tests/test_i_hardening.py` (47 tests) — le brouillon `/tmp/test_i_hardening.py` du prédécesseur a peut-être été perdu au reboot, à recréer.

### PHASE 4 — Section J (chunks 117-121, 5 tests, ~30 min)

Tests post-v2 (les bugs trouvés à l'audit honnête) :
- 117. `AUDIT_PARALLEL=0` ne crash plus (TOOL_PIDS=())
- 118. plus de `grep: Fin d'intervalle invalide` (DURATION_S retiré)
- 119. gitleaks version via dpkg, pas "process"
- 120. Re-test sandbox+offline (transitoire fixé)
- 121. `--dry-run --json` génère bien JSON

### PHASE 5 — Section K (chunks 122-157, 36 tests, ~2-3h)

Edge cases agressifs. Création `tests/test_k_edge_cases.py`. Patterns :
- Path unicode/espaces/apostrophes
- Symlinks (loop, /etc/passwd, /home/sky/.ssh)
- Limites (AUDIT_MAX_FILES=0/1, TOOL_TIMEOUT=0/-5/1)
- IPv6 (::1, fe80::)
- Tampering audit-doctor

### PHASE 6 — Section L (chunks 158-164, 7 tests, ~1h)

Attaque réelle : créer fichiers Cargo.toml avec `build.rs` malveillant + Gemfile + setup.py + symlinks dangereux. Asserter 0 PWN, fichiers /tmp/PWNED-*.txt absents.

### PHASE 7 — Section M (chunks 165-169, 5 tests, ~30 min)

Validation 5 modes : default, AUDIT_PARALLEL=0, AUDIT_SANDBOX=1, AUDIT_OFFLINE=1, combo. Tests de bout en bout avec rosetta.

### PHASE 8 — Section N (chunks 170-180, 11 tests, ~1h)

Self-audit de forge.py : ast.parse, bandit, semgrep, grep eval/exec, comptage fonctions/classes/subprocess.

### PHASE 9 — Push GitHub final

Tag stable + push avec PAT. Cleanup.

---

## Estimation totale

| Phase | Durée |
|---|---|
| PHASE 0 (ménage) | 30 min |
| PHASE 1 (D 39-49) | 1h |
| PHASE 2 (H) | 30 min |
| PHASE 3 (I, 47 tests) | 3-4h |
| PHASE 4 (J) | 30 min |
| PHASE 5 (K, 36 tests) | 2-3h |
| PHASE 6 (L) | 1h |
| PHASE 7 (M) | 30 min |
| PHASE 8 (N) | 1h |
| PHASE 9 (push) | 15 min |
| **TOTAL** | **~10-12h** |

À ce rythme : nuit complète si lancé en background avec auto-progress.

---

## Règles dures (anti-drift)

1. **Jamais `--baseline` avec un fail actif** → fix d'abord.
2. **Branchage RÉEL obligatoire** : sabotage du wrapper → test FAIL → restore → test PASS, documenté en commit.
3. **Commit message format** : `test(chunk N/180): #N <description>` strictement.
4. **0 régression à chaque chunk** : `forge.py --diff` doit dire 0 fail.
5. **Pas d'invention** : si un test du TESTS.md ne peut pas être écrit (outil manquant), MARQUER avec `pytest.skip(reason="...")` explicite, jamais `assert True`.
6. **BUGS.md** : remplir au fur et à mesure des bugs trouvés (le template est vide).

## Anti-pattern à NE PAS répéter

- ❌ Le prédécesseur a fait `--baseline` malgré 5 fails actifs → baseline polluée
- ❌ Il a sauté de D-037 directement à E/F/G en bloc sans terminer D
- ❌ Il a ignoré le push GitHub cassé pendant 9h
- ❌ Il a laissé un test (test_038) uncommitted

## Mantra (du prédécesseur, à respecter)

> *Code → forge audit → branche (détection réelle) → diff 0 régression → commit → push.*
> *180 fois. Pas une de moins.*
> *Si je dévie, je relis ce fichier.*
