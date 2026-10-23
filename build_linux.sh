#!/bin/bash
# Build a Linux executable: dist/LandullToolkit/LandullToolkit
cd "$(dirname "$0")" || exit 1
set -e
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
HIDDEN=""; for t in tools/*.py; do HIDDEN="$HIDDEN --hidden-import $(basename "$t" .py)"; done
.venv/bin/pyinstaller --noconfirm --clean --log-level WARN --windowed --name LandullToolkit \
  --icon assets/icon.png --add-data "assets:assets" --paths tools --paths . --hidden-import toolspecs $HIDDEN \
  landull_toolkit.py
rm -rf build LandullToolkit.spec
echo "BUILD OK -> dist/LandullToolkit/LandullToolkit"
