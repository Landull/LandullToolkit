@echo off
rem Double-click to build dist\LandullToolkit\LandullToolkit.exe
cd /d "%~dp0"
if not exist .venv ( py -3 -m venv .venv || python -m venv .venv )
.venv\Scripts\python -m pip install -q --upgrade pip
.venv\Scripts\python -m pip install -q -r requirements.txt || goto :fail
set HIDDEN=
for %%f in (tools\*.py) do call set HIDDEN=%%HIDDEN%% --hidden-import %%~nf
.venv\Scripts\pyinstaller --noconfirm --clean --log-level WARN --windowed --name LandullToolkit ^
  --icon assets\icon.ico --add-data "assets;assets" --paths tools --paths . --hidden-import toolspecs %HIDDEN% ^
  landull_toolkit.py || goto :fail
rmdir /s /q build & del LandullToolkit.spec
echo BUILD OK -^> dist\LandullToolkit\LandullToolkit.exe
pause
exit /b 0
:fail
echo BUILD FAILED
pause
exit /b 1
