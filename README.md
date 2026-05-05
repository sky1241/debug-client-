# claude-tooling — stack pentest ludo-PC-1

Wrappers d'audit pour le workflow client de Sky.
Versionnage Git de ce que je modifie en `/usr/local/bin/` pour ne pas perdre l'état si le disque crame.

## Wrappers fournis (`bin/`)

| Wrapper | Rôle |
|---|---|
| `audit-fingerprint` | Recon passive (chemin / URL / IP) — dispatch outils en pass 2 |
| `client-audit-code` | Audit code statique multi-langage (12 langages, parallèle, timeout) |
| `client-audit-web` | Pentest web (whatweb / nikto / nuclei / wpscan) avec ordre de mission obligatoire |
| `client-audit-net` | Recon réseau (nmap services + NSE vuln + OS detect) avec ordre de mission |
| `client-audit-diff` | Compare 2 audits successifs (FIXÉ / NOUVEAU / INCHANGÉ) |
| `client-audit-test` | CI rosetta-stone — vérifie que chaque outil détecte sa vuln signature |

## Installation / mise à jour

```bash
cd ~/.claude-tooling
./install.sh
```

Idempotent. Sauvegarde la version `/usr/local/bin/X` actuelle si c'est un fichier régulier (pas déjà un symlink).

## Workflow recommandé

```bash
# 0. (avant tout) Vérifier que la stack est saine
client-audit-test                            # exit 0 = OK

# 1. Récupérer le code client sur le 1TB
client-mount
cp -r /chemin/vers/zip-client ~/clients/CLIENT_X/

# 2. Auditer
client-audit-code ~/clients/CLIENT_X/

# 3. Renvoyer le rapport. Le client corrige.

# 4. Re-auditer
client-audit-code ~/clients/CLIENT_X/

# 5. Diff entre les 2 runs
client-audit-diff \
  ~/audit-logs/CLIENT_X/2026-XX-XX-AAAAAA/ \
  ~/audit-logs/CLIENT_X/2026-XX-XX-BBBBBB/ \
  --out=~/clients/CLIENT_X/delta.md
```

## Variables d'environnement

| Variable | Défaut | Effet |
|---|---|---|
| `AUDIT_PARALLEL` | `1` | Lance les outils en parallèle (×2 plus rapide). Mettre à `0` pour serial. |
| `AUDIT_TOOL_TIMEOUT` | `300` (code) / `600` (web) / `1800` (net) | Timeout en secondes par outil. |

## Tester la stack — `client-audit-test`

CI reproductible de la stack pentest. Crée un repo "rosetta-stone" piégé avec 1 vuln signature par outil, lance `client-audit-code` dessus, et vérifie que chaque outil a bien trouvé sa vuln.

```bash
client-audit-test           # CI complète, ~6s, cleanup automatique
client-audit-test --keep    # garde le rosetta + les logs (debug)
```

### Exit codes

| Code | Signification |
|:---:|---|
| `0` | Tous les outils détectent leur vuln signature → stack saine |
| `1` | Au moins un FAIL — un outil n'a pas trouvé sa vuln (régression) |
| `2` | Aucun FAIL mais des WARN — outil pas installé ou pas lancé |

### Vulns plantées par outil

| Outil | Vuln signature attendue |
|---|---|
| bandit | `eval()` Python (B307) + `pickle.loads` (B403) |
| gosec | `crypto/md5` (G401) |
| eslint | `eval()` + `new Function()` dans `.js` ET `.ts` |
| phpstan | variable PHP indéfinie |
| brakeman | warnings sécu Ruby (≥1) |
| bundler-audit | CVE Rails 4.0.0 (Gemfile.lock) |
| cargo-audit | RUSTSEC-2020-0071 (`time 0.1.43`) |
| cppcheck | `gets()` obsolète |
| flawfinder | `gets()` CWE-120 buffer overflow |
| shellcheck | variable non quotée (SC2086) |
| yamllint | YAML mal indenté |
| retire | jQuery 1.6.1 (multiples CVE) |
| gitleaks | AWS access token + GitHub PAT |
| pip-audit | `requests==2.6.0` (PYSEC + CVE) |

### Quand le lancer

- **Avant le 1er audit d'un client important** — preuve que la stack répond
- **Après chaque modif des wrappers** — détecte régressions immédiatement
- **Après chaque mise à jour système** (apt upgrade, cargo install, npm -g) — vérifie qu'aucun outil n'a cassé son CLI

Si un FAIL apparaît, regarde le `.out` de l'outil concerné dans `~/audit-logs/rosetta-stone-test-*/` (lance avec `--keep` pour garder les artefacts).

## Outils SAST supportés

Python (bandit) · Go (gosec) · JS/TS (eslint flat config + parser TS) · JS inline HTML (extraction Python) ·
PHP (phpstan) · Ruby (brakeman + bundler-audit) · Rust (cargo-audit) · Java (semgrep p/java) ·
C/C++ (cppcheck + flawfinder) · Shell (shellcheck) · YAML (yamllint) ·
Multi-langage (semgrep) · Secrets (trufflehog3 + gitleaks) · Deps (trivy + pip-audit) ·
Libs JS legacy (retire.js) · Malware (clamav)
