#!/usr/bin/env bash
set -euo pipefail

# Build RANVDS with Nuitka into a single binary.
# Outputs to dist/nuitka/ranvds
# Env overrides:
#   PYTHON_BIN   - python interpreter to use (default: python3)
#   OUT_DIR      - output directory (default: dist/nuitka)

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Ensure local user bin is on PATH for --user installs
export PATH="$HOME/.local/bin:$PATH"

if ! command -v python3 >/dev/null; then
  echo "python3 is required on PATH" >&2
  exit 1
fi

PYTHON_BIN=${PYTHON_BIN:-python3}

# Ensure Nuitka present (user-level install to avoid system perms)
if ! "$PYTHON_BIN" -m nuitka --version >/dev/null 2>&1; then
  echo "Installing Nuitka locally..."
  "$PYTHON_BIN" -m pip install --user -U pip wheel setuptools nuitka orderedset zstandard patchelf
fi

# Ensure patchelf is available (required by Nuitka standalone on Linux)
if ! command -v patchelf >/dev/null 2>&1; then
  echo "Installing patchelf (user)..."
  if ! "$PYTHON_BIN" -m pip install --user -U patchelf; then
    echo "ERROR: Failed to install patchelf via pip. Please install 'patchelf' system-wide and re-run." >&2
    exit 2
  fi
fi

# Try to locate Kivy data dir so images/fonts get bundled
KIVY_DATA_DIR="$($PYTHON_BIN - <<'PY'
try:
    import kivy, pathlib
    print(pathlib.Path(kivy.__file__).parent / "data")
except Exception:
    print("")
PY
)"

INCLUDE_KIVY=""
if [ -n "$KIVY_DATA_DIR" ] && [ -d "$KIVY_DATA_DIR" ]; then
  INCLUDE_KIVY=(--include-data-dir="${KIVY_DATA_DIR}=kivy/data")
else
  INCLUDE_KIVY=()
fi

OUT_DIR=${OUT_DIR:-dist/nuitka}
mkdir -p "$OUT_DIR"

set -x
"$PYTHON_BIN" -m nuitka \
  --onefile \
  --standalone \
  --assume-yes-for-downloads \
  --enable-plugin=multiprocessing \
  --enable-plugin=kivy \
  --follow-imports \
  --remove-output \
  --output-dir="$OUT_DIR" \
  --output-filename="ranvds" \
  --include-data-files="config/fields.cfg=fields.cfg" \
  --include-data-files="config/translations.cfg=translations.cfg" \
  --include-data-files="config/mcc-mnc.csv=mcc-mnc.csv" \
  --include-module=ranvds \
  --include-module=pcap_analyzer \
  --include-module=table_builder \
  --include-module=security_evaluator \
  --include-package=scat \
  --include-package-data=scat \
  --include-package=kivy \
  --include-package-data=kivy \
  "${INCLUDE_KIVY[@]}" \
  ranvds_gui.py

set +x
printf '\nBuilt %s/ranvds\n' "$OUT_DIR"
