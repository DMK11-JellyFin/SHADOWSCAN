# SHADOWSCAN v4 — lancement comme un logiciel

Fichiers à copier dans le dépôt (en gardant les dossiers) :
- `src/gui.py` (interface remaniée, plus sobre)
- `shadowscan_app.py` (point d'entrée : ouvre directement la fenêtre)
- `build_exe.bat` (fabrique l'exécutable)
- `assets/shadowscan.ico` (icône)

## Fabriquer le .exe
Double-clic sur `build_exe.bat` (ou `.\build_exe.bat` dans PowerShell). Résultat : `dist\SHADOWSCAN.exe`.
Copie-le où tu veux (Bureau, etc.) ; clic droit > « Épingler à la barre des tâches » possible.

## Sans .exe
`pythonw shadowscan_app.py` ouvre la fenêtre sans console.

## Où vont les fichiers
Rapports et journaux d'annulation : `Documents\SHADOWSCAN\reports\`. En cas de plantage au démarrage : `Documents\SHADOWSCAN\erreur.log`.
