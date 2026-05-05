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

## Tester la stack

```bash
client-audit-test
```

Crée un repo "rosetta-stone" piégé avec 1 vuln signature par outil, lance audit-code, vérifie que chaque outil l'a bien trouvé. Exit 0 = stack saine.

## Outils SAST supportés

Python (bandit) · Go (gosec) · JS/TS (eslint flat config + parser TS) · JS inline HTML (extraction Python) ·
PHP (phpstan) · Ruby (brakeman + bundler-audit) · Rust (cargo-audit) · Java (semgrep p/java) ·
C/C++ (cppcheck + flawfinder) · Shell (shellcheck) · YAML (yamllint) ·
Multi-langage (semgrep) · Secrets (trufflehog3 + gitleaks) · Deps (trivy + pip-audit) ·
Libs JS legacy (retire.js) · Malware (clamav)
