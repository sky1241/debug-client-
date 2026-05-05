# Changelog

## v2.0 — 2026-05-05

Hardening complet en 10 chunks (audit propre senior eng + recherche outils 2025).

### Nouvelles capacités

- **Sandbox firejail** (`AUDIT_SANDBOX=1`) — anti-RCE code client (build.rs / Cargo.toml / setup.py)
- **Mode offline** (`AUDIT_OFFLINE=1`) — air-gap strict (--net=none + skip outils online)
- **Sortie JSON** (`--format=json`/`all`) — schéma `claude-audit-code/v1`
- **`audit-doctor`** — vérif env (versions vs lock + checksums wrappers + caches CVE)
- **`audit-history`** — historique JSONL des runs
- **`--dry-run`** — voir les outils sans lancer
- **Détection zipbomb** (`AUDIT_MAX_ZIP_RATIO`, `AUDIT_REJECT_ZIPBOMB`)

### Nouveaux outils intégrés

- **osv-scanner v2** (deps multi-écosystèmes unifié)
- **checkov** (IaC scan)
- **syft + grype** (SBOM + CVE matching)
- **dockle** (Dockerfile CIS)
- **firejail** (sandbox)

### DoS protection

- `AUDIT_MAX_FILES` (default 50000) — anti path bomb
- `AUDIT_MAX_TOTAL_SIZE_MB` (default 1024) — anti repo géant
- `AUDIT_MAX_FILE_SIZE` (default 50M) — rsync --max-size
- find -maxdepth 30 partout

### Sécurité

- rsync `--safe-links` + détection symlinks externes
- `--` séparateur args (cppcheck/flawfinder/yamllint/dockle)
- `bash -c "set -o pipefail; $cmd"` (vraie capture erreurs)
- `mktemp -d` (anti-collision PID wrap-around)
- `bin/.checksums` (sha256 wrappers, anti-tampering)

### Fixes

- dockle invocation cassée (path en argument positionnel → 'invalid image') → `--input`
- semgrep/trivy-deps/trivy-config/osv-scanner patterns trop laxes (faux PASS) → patterns stricts
- semgrep `--quiet` masquait les findings → retiré
- eslint v10 flat config (parser TS via require absolu)
- HAS_BIN matchait `.git/index` et images sshfs → exclusions étendues

### Cache

- Trivy + Grype : cache persistant `~/.cache/audit-stack/` — speedup 5× sur runs successifs (102s → 21s)

### Tests

- Rosetta-stone v2 : 23 outils testés avec patterns stricts (rejet faux positifs sur 0 finding)
- `client-audit-test` : 23/23 PASS / 0 FAIL / 0 WARN en 22s

---

## v1.0 — 2026-05-05 (initial)

- 6 wrappers : audit-fingerprint, client-audit-code/web/net/test/diff
- 18 outils SAST/secrets/deps/malware
- Parallélisation outils (×2 perf)
- Mode delta `client-audit-diff`
- Garde-fous légaux (PDF ordre de mission Suisse art. 143bis CP)
