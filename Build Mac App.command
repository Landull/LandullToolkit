#!/bin/bash
# Double-click to build "Landull Toolkit.app" (first run downloads Qt, ~2-4 minutes).
cd "$(dirname "$0")" || exit 1
exec > >(tee build.log) 2>&1
echo "== Landull Toolkit: macOS build =="
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "Python 3.9+ is required: https://www.python.org/downloads/"; read -r -p "Press Enter to close"; exit 1; fi
echo "Using $($PY --version) at $(command -v $PY)"
[ -d .venv ] || "$PY" -m venv .venv || exit 1
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt || { echo "pip install failed"; read -r -p "Press Enter"; exit 1; }
HIDDEN=""
for t in tools/*.py; do HIDDEN="$HIDDEN --hidden-import $(basename "$t" .py)"; done
.venv/bin/pyinstaller --noconfirm --clean --log-level WARN --windowed \
  --name "Landull Toolkit" --icon assets/icon.icns --osx-bundle-identifier com.landull.toolkit \
  --add-data "assets:assets" --paths tools --paths . --hidden-import toolspecs $HIDDEN \
  landull_toolkit.py || { echo "BUILD FAILED"; read -r -p "Press Enter to close"; exit 1; }
rm -rf build "Landull Toolkit.spec"
echo
echo "BUILD OK -> $(pwd)/dist/Landull Toolkit.app"
echo "Drag it into your Applications folder to install."
open -R "dist/Landull Toolkit.app"
