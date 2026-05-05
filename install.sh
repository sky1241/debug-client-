#!/bin/bash
# install.sh — installe les wrappers de la stack pentest dans /usr/local/bin/ via symlinks.
# Idempotent : ré-exécutable sans risque, écrase les liens existants.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="$REPO/bin"
TARGET="/usr/local/bin"

if [ ! -d "$BIN_SRC" ]; then
  echo "ERREUR: $BIN_SRC introuvable" >&2; exit 1
fi

echo "Installation depuis $BIN_SRC → $TARGET (symlinks)"
echo ""

INSTALLED=0
for src in "$BIN_SRC"/*; do
  name="$(basename "$src")"
  dst="$TARGET/$name"
  # Backup version actuelle si fichier régulier (pas un symlink existant vers nous)
  if [ -f "$dst" ] && [ ! -L "$dst" ]; then
    sudo cp "$dst" "${dst}.bak.preinstall.$(date +%s)"
    echo "  [backup] $dst → ${dst}.bak.preinstall.*"
  fi
  sudo ln -sf "$src" "$dst"
  sudo chmod +x "$src"
  echo "  ✓ $name"
  INSTALLED=$((INSTALLED+1))
done

echo ""
echo "✓ $INSTALLED wrappers installés (symlinks vers $BIN_SRC)"
echo ""
echo "Lance la CI pour valider :"
echo "  client-audit-test"
