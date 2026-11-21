@echo off
REM Construit dist\SHADOWSCAN.exe (un seul fichier, sans console, avec icône).
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller customtkinter
python -m PyInstaller --noconfirm --clean --onefile --windowed --name SHADOWSCAN ^
  --icon assets\shadowscan.ico --add-data "assets\shadowscan.ico;assets" ^
  --collect-all customtkinter shadowscan_app.py
echo.
if exist dist\SHADOWSCAN.exe (
  echo Termine : %cd%\dist\SHADOWSCAN.exe
) else (
  echo ECHEC : voir les messages ci-dessus.
)
pause
