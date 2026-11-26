#!/usr/bin/env bash
# 把 PeasRea 安装成 agent 技能（默认 ~/.agents/skills/peasrea）
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-$HOME/.agents/skills/peasrea}"

mkdir -p "$DEST"
for d in SKILL.md README.md LICENSE peasrea.py pyproject.toml references scripts assets kb; do
  [ -e "$SRC/$d" ] && cp -R "$SRC/$d" "$DEST/"
done
find "$DEST" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

echo "installed -> $DEST"
echo "query:  python \"$DEST/scripts/kb_query.py\" --stats"
