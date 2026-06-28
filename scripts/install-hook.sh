#!/bin/sh
# Install MORTIS pre-commit hook into this repository.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cp "$ROOT/hooks/pre-commit" "$ROOT/.git/hooks/pre-commit"
chmod +x "$ROOT/.git/hooks/pre-commit"
echo "MORTIS pre-commit hook installed."
