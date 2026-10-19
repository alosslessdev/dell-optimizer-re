#!/usr/bin/env bash
# Bulk-decompile every unique managed binary under extract/ with ilspycmd.
# Unique by SHA-256; output dir = decompiled_all/<stem>__<hash8>.
set -u
export PATH="$PATH:$HOME/.dotnet/tools"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
mkdir -p decompiled_all work/hashes
STAMP=work/decompile_status.txt
[ -f "$STAMP" ] || : > "$STAMP"
while IFS= read -r rel; do
  p="extract/$rel"
  [ -f "$p" ] || continue
  h=$(sha256sum "$p" | cut -d' ' -f1)
  mark="work/hashes/$h"
  if [ -e "$mark" ]; then
    continue
  fi
  name=$(basename "$p"); name="${name%.*}"
  out="decompiled_all/${name}__${h:0:8}"
  if ilspycmd -p -o "$out" "$p" >> "$STAMP" 2>&1; then
    echo "ok   $rel -> $out" >> "$STAMP"
  else
    echo "FAIL $rel" >> "$STAMP"
    rm -rf "$out"
  fi
  touch "$mark"
done < work/managed.txt
echo DONE >> "$STAMP"
