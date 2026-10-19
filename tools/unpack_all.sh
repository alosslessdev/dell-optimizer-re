#!/usr/bin/env bash
# End-to-end reproduction of the Dell Optimizer unpacking + decompilation pipeline.
# Prereqs: python3 (+numpy for iss_stream_extract), bsdtar or the bundled 7zz,
#          file(1), .NET SDK + `dotnet tool install --global ilspycmd`.
# Usage: work/unpack_all.sh [--no-decompile] [--no-catalog]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY=${PY:-python3}
if [ -z "${SEVEN:-}" ]; then
  if [ -x "$ROOT/work/7zz/7zz" ]; then SEVEN="$ROOT/work/7zz/7zz"
  elif command -v 7zz >/dev/null 2>&1; then SEVEN=$(command -v 7zz)
  elif command -v 7z  >/dev/null 2>&1; then SEVEN=$(command -v 7z)
  else echo "7-Zip required: install 7zip or set SEVEN=/path/to/7zz"; exit 1; fi
fi
EX="$ROOT/extract"
INPUT="$ROOT/input/Dell-Optimizer-Application_GJ7NN_WIN64_6.3.5.0_A00.exe"
DO_DECOMPILE=1
DO_CATALOG=1
for a in "$@"; do
  case "$a" in
    --no-decompile) DO_DECOMPILE=0 ;;
    --no-catalog) DO_CATALOG=0 ;;
  esac
done
mkdir -p "$EX"

echo "== 1/6 DUP overlay -> payload.7z"
if [ ! -f "$ROOT/work/payload.7z" ]; then
  "$PY" "$ROOT/work/dup_split.py" "$INPUT" "$ROOT/work/payload.7z"
fi

echo "== 2/6 payload.7z -> extract/"
if [ ! -f "$EX/DellOptimizer.exe" ]; then
  if command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$ROOT/work/payload.7z" -C "$EX"
  else
    "$SEVEN" x -y -o"$EX" "$ROOT/work/payload.7z" >/dev/null
  fi
fi

echo "== 3/6 InstallShield ISSetupStream -> extract/is_payload"
if [ ! -d "$EX/is_payload" ]; then
  "$PY" "$ROOT/work/iss_stream_extract.py" "$EX/DellOptimizer.exe" "$EX/is_payload"
fi

echo "== 4/6 MSIs -> extract/{app,pkg_*}"
unpack_msi() {
  local msi="$1"
  local tag="$2"
  local raw="$EX/raw_$tag"
  local cab="$EX/cab_$tag"
  local out="$EX/$tag"
  if [ -d "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
    echo "   $tag: already present"; return
  fi
  rm -rf "$raw" "$cab" "$out"; mkdir -p "$raw"
  "$SEVEN" x -y -tCompound -o"$raw" "$msi" >/dev/null
  "$PY" "$ROOT/work/msi_extract.py" "$raw" "$cab" "$out" "$SEVEN"
}
IS="$EX/is_payload"
unpack_msi "$IS/{A861556A-7676-4F68-8CA9-992EECE14211}/Dell Optimizer.msi"            app
unpack_msi "$IS/{8BDD9DC3-633E-4B66-BD72-54836432D82B}/Dell.Core.Services.Installer_64bit.msi" pkg_coreservices
unpack_msi "$IS/{3674DF8F-4910-46FC-9AB1-B7E043C7C673}/Dell AppCore.msi"             pkg_appcore
unpack_msi "$IS/{F51A237C-7889-4B50-8960-65126B1BEAE8}/Dell UserSubAgent.msi"        pkg_usersubagent

echo "== 5/6 managed/native inventory"
"$PY" "$ROOT/work/make_inventory.py" "$EX" "$ROOT/work"

if [ "$DO_DECOMPILE" = 1 ]; then
  echo "== 6/6 ilspycmd decompilation (long; needs ilspycmd on PATH)"
  bash "$ROOT/work/decompile_all.sh"
  if [ "$DO_CATALOG" = 1 ]; then "$PY" "$ROOT/work/gen_catalog.py"; fi
else
  echo "== 6/6 decompilation skipped"
fi
echo "done"
