#!/usr/bin/env bash
# Install the security-fence skill into your Claude Code skills directory.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/skill/security-fence"
DEST="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}/security-fence"

mkdir -p "$(dirname "$DEST")"

if [ -e "$DEST" ] && [ ! -L "$DEST" ]; then
  echo "✗ $DEST already exists and is not a symlink. Move/remove it first." >&2
  exit 1
fi

ln -sfn "$SRC" "$DEST"
echo "✓ Linked skill -> $DEST"
echo "  Use it in Claude Code with:  /security-fence"
echo

echo "Optional engines for deeper coverage (Fence auto-detects them):"
for t in gitleaks trufflehog semgrep grype pip-audit; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "  ✓ $t"
  else
    echo "  ○ $t  (not installed)"
  fi
done
echo
echo "Install missing ones, e.g.:  brew install gitleaks trufflehog grype  &&  pipx install semgrep pip-audit"
