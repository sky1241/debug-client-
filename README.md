# claude-tooling — stack pentest ludo-PC-1 (v2.0)

Wrappers d'audit sécurité pour le workflow client de Sky.
Stack : 24+ outils SAST/secrets/IaC/SBOM/malware, sandboxé, parallélisé, modes online/offline, sortie markdown + JSON.

---

## Wrappers fournis (`bin/`)

| Wrapper | Rôle |
|---|---|
| `audit-fingerprint` | Recon passive (chemin / URL / IP) — dispatch outils en pass 2 |
| `client-audit-code` | Audit code statique multi-langage (24+ outils, parallèle, timeout, sandbox, offline) |
| `client-audit-web` | Pentest web (whatweb / nikto / nuclei / wpscan) avec ordre de mission obligatoire |
| `client-audit-net` | Recon réseau (nmap services + NSE vuln + OS detect) avec ordre de mission |
| `client-audit-diff` | Compare 2 audits successifs (FIXÉ / NOUVEAU / INCHANGÉ) |
| `client-audit-test` | CI rosetta-stone — vérifie que chaque outil détecte sa vuln signature |
| `audit-doctor` | Vérif env (versions vs lock + checksums wrappers + caches CVE) |
| `audit-history` | Affiche l'historique des runs (~/audit-logs/.audit-history.jsonl) |

## Installation / mise à jour

```bash
cd ~/.claude-tooling
./install.sh
audit-doctor       # vérifie l'environnement
client-audit-test  # CI complète (~22s)
```

`install.sh` est idempotent : sauvegarde la version actuelle de `/usr/local/bin/X` si c'est un fichier régulier (pas déjà un symlink).

---

## Threat model

La stack est conçue pour auditer du **code potentiellement hostile** (clients, CTF, repos publics).

### Protections actives

| # | Vecteur attaque | Protection |
|---|---|---|
| 1 | RCE via `build.rs` / `setup.py` / `Gemfile` lors de cargo-audit / pip-audit / bundler-audit | **firejail** sandbox (`AUDIT_SANDBOX=1`) — drop privs, blacklist secrets, rlimits |
| 2 | Symlink piégé `secrets → /home/sky/.ssh/id_rsa` | rsync `--safe-links` + détection préalable + warn (exclus du snapshot) |
| 3 | Path bomb (65k fichiers) | `AUDIT_MAX_FILES=50000` (configurable) avec exit 2 |
| 4 | Repo géant (DoS disque) | `AUDIT_MAX_TOTAL_SIZE_MB=1024` |
| 5 | Fichier énorme (DoS mémoire) | rsync `--max-size=$AUDIT_MAX_FILE_SIZE` (default 50M) |
| 6 | Symlink circulaire | rsync `--safe-links` (refuse les targets inattendus) |
| 7 | Zipbomb (.zip 10kb → 10MB) | Détection ratio > `AUDIT_MAX_ZIP_RATIO` (default 100x) ; refus avec `AUDIT_REJECT_ZIPBOMB=1` |
| 8 | Injection args via `--config=/etc/passwd` filename | `--` séparateur sur cppcheck/flawfinder/yamllint |
| 9 | Phone-home des outils (gitleaks → API, grype → vuln DB) | `AUDIT_OFFLINE=1` → firejail `--net=none` + skip outils online |
| 10 | Wrapper modifié (tampering) | `audit-doctor` vérifie `bin/.checksums` (sha256) |
| 11 | Outil cassé (régression silencieuse) | `client-audit-test` → 23 vulns signature, FAIL = régression |

### Threats résiduels (assumés)

- **Compromission de l'utilisateur Sky** : si attacker a write sur `~/.claude-tooling/bin/`, il peut altérer les wrappers. Mitigation : `audit-doctor` détecte le tampering, mais ne le bloque pas.
- **Vulnérabilité dans un outil SAST** : si bandit/semgrep/etc. ont une RCE via input piégé, le sandbox réduit l'impact mais ne le supprime pas.
- **Outils ignorés en mode offline** : 4 outils dégradés (semgrep registry, retire jsrepo, bundler-audit advisory-db, osv-scanner API). Cache local (Trivy/Grype) compense partiellement.

---

## Modes d'usage

| Mode | Commande | Quand |
|---|---|---|
| **Standard** (default) | `client-audit-code ~/clients/X/` | Code client connu, légitime. Confiance haute. |
| **Sandbox** | `AUDIT_SANDBOX=1 client-audit-code ~/clients/X/` | Code non-confiance (CTF, repo public, code suspect). RCE bloquée. |
| **Strict offline** | `AUDIT_OFFLINE=1 client-audit-code ~/clients/X/` | Air-gap, secret-cleared, pas de phone-home. Implique sandbox. |
| **Dry-run** | `client-audit-code --dry-run ~/clients/X/` | Voir ce qui serait lancé sans exécuter. |
| **JSON pour CI** | `client-audit-code --json ~/clients/X/` | Rapport machine-readable pour intégration pipeline. |

## Workflow recommandé

```bash
# 0. Vérifier la stack avant audit critique
audit-doctor                                  # 24 OK / 0 DRIFT / 0 MISSING / 0 TAMPERED
client-audit-test                             # 23 PASS / 0 FAIL / 0 WARN

# 1. Récupérer le code client
client-mount
cp -r /chemin/vers/zip-client ~/clients/CLIENT_X/

# 2. Auditer (mode standard pour un client de confiance)
client-audit-code ~/clients/CLIENT_X/

# 2bis. Si code public/non-confiance/CTF
AUDIT_SANDBOX=1 client-audit-code ~/clients/CLIENT_X/

# 3. Renvoyer le rapport. Le client corrige.

# 4. Re-auditer
client-audit-code ~/clients/CLIENT_X/

# 5. Diff entre les 2 runs
client-audit-diff \
  ~/audit-logs/CLIENT_X/2026-XX-XX-AAAAAA/ \
  ~/audit-logs/CLIENT_X/2026-XX-XX-BBBBBB/ \
  --out=~/clients/CLIENT_X/delta.md

# 6. Voir l'historique
audit-history --filter=CLIENT_X
```

---

## Variables d'environnement

| Variable | Default | Effet |
|---|---|---|
| `AUDIT_PARALLEL` | `1` | Parallélisation des outils (×2 perf). `0` = serial. |
| `AUDIT_TOOL_TIMEOUT` | `300` | Timeout par outil (secondes). |
| `AUDIT_SANDBOX` | `0` | Active firejail (recommandé pour code non-confiance). |
| `AUDIT_OFFLINE` | `0` | Mode air-gap : --net=none + skip outils online. Force `SANDBOX=1`. |
| `AUDIT_MAX_FILES` | `50000` | Anti path bomb. Exit 2 si dépassé. |
| `AUDIT_MAX_TOTAL_SIZE_MB` | `1024` | Anti repo géant. |
| `AUDIT_MAX_FILE_SIZE` | `50M` | rsync `--max-size`. |
| `AUDIT_MAX_ZIP_RATIO` | `100` | Seuil détection zipbomb (uncompressed/compressed). |
| `AUDIT_REJECT_ZIPBOMB` | `0` | Si `1` : refus avec exit 2 au lieu de warn. |
| `SANDBOX_PROFILE` | `~/.claude-tooling/firejail/claude-audit.profile` | Profil firejail à utiliser. |
| `TRIVY_CACHE_DIR` | `~/.cache/audit-stack/trivy` | Cache CVE local persistant. |
| `GRYPE_DB_CACHE_DIR` | `~/.cache/audit-stack/grype` | Idem grype. |

## Options CLI

| Option | Effet |
|---|---|
| `--replay` | Mode reproductible (pas de yield mining, log verbeux). |
| `--keep` / `--keep-snapshot` | Garde la copie `/tmp/audit-*` après l'audit (debug). |
| `--dry-run` | Affiche les outils qui seraient lancés sans rien exécuter. |
| `--format=md\|json\|all` | Format du rapport (default md). |
| `--json` | Alias `--format=json`. |

---

## Outils SAST supportés (24 outils, validés en CI)

**Code statique par langage** : Python (bandit) · Go (gosec) · JS/TS (eslint flat config + parser TS) · JS inline HTML (extraction Python) · PHP (phpstan) · Ruby (brakeman) · Java (semgrep p/java) · C/C++ (cppcheck + flawfinder) · Shell (shellcheck) · YAML (yamllint)

**Multi-langage** : semgrep (`p/security-audit` + `p/secrets`)

**Secrets** : trufflehog3 + gitleaks

**Dépendances vulnérables** :
- pip-audit (Python), bundler-audit (Ruby), cargo-audit (Rust), retire.js (libs JS legacy)
- **osv-scanner v2** (multi-écosystèmes unifié — Google/OpenSSF base OSV)
- trivy fs (manifests) + grype (CVE matching deps)

**SBOM** : syft (CycloneDX)

**IaC scan** :
- **checkov** (Terraform / K8s / Helm / Dockerfile / CloudFormation)
- trivy config (Dockerfile + K8s)
- **dockle** (Dockerfile CIS Benchmark)

**Malware** : clamav (signatures + EICAR validé)

**Sandbox** : firejail (drop privs, blacklist secrets, rlimits)

---

## Tester la stack — `client-audit-test`

CI reproductible. Crée un repo "rosetta-stone" piégé avec 1 vuln signature par outil, lance `client-audit-code` dessus, et vérifie que chaque outil a bien trouvé sa vuln.

```bash
client-audit-test           # CI complète, ~22s, cleanup automatique
client-audit-test --keep    # garde le rosetta + les logs (debug)
```

Exit codes : `0` = stack saine · `1` = au moins un FAIL · `2` = WARN seulement · `3` = client-audit-code a crashé.

### Quand le lancer

- **Avant le 1er audit d'un client important**
- **Après chaque modif des wrappers** (régression)
- **Après `apt upgrade` / `cargo install` / `npm -g`** (versions cassées)
- **Avant un audit en mode offline** (les 4 outils online passeront en WARN — vérification que les 19 outils locaux marchent)

---

## Stack hardening (v2.0)

Tous les chunks de hardening implémentés :

| Chunk | Objet |
|---|---|
| 1 | Bash hardening : pipefail interne, wait propagation, mktemp, dockle --input |
| 2 | DoS limits + path canonicalization + reject symlinks externes |
| 3 | Sandboxing firejail (`AUDIT_SANDBOX=1`) — anti-RCE code client |
| 4 | Mode `AUDIT_OFFLINE=1` (--net=none + skip outils online) |
| 5 | Sortie JSON (`--format=json`/`--json`/`--format=all`) + usage enrichi |
| 6 | Version pinning (`tool-versions.lock`) + `audit-doctor` + caches CVE |
| 7 | Audit log JSONL + `audit-history` |
| 8 | `--dry-run` + `--keep-snapshot` |
| 9 | Détection zipbomb (`AUDIT_MAX_ZIP_RATIO`, `AUDIT_REJECT_ZIPBOMB`) |
| 10 | Documentation finale + tag v2.0 |

---

## Limitations connues

- **Pas de DAST** : la stack ne fait pas de scan dynamique d'applications web tournantes. Pour ça : OWASP ZAP via `client-audit-web` (à intégrer en chunk futur).
- **SARIF natif** : sortie JSON est custom (`claude-audit-code/v1`), pas SARIF OASIS. Conversion possible mais chaque outil a son propre format.
- **Cache CVE/NVD** : ~3 GiB sur disque après 1er run. À nettoyer manuellement si besoin (`rm -rf ~/.cache/audit-stack/*`).
- **Mode offline** : 4 outils sont skippés (semgrep, retire, bundler-audit, osv-scanner). Trivy/grype/pip-audit/cargo-audit fonctionnent en offline grâce aux caches.
