# SHADOWSCAN

Outil Windows d'inventaire et de rangement de fichiers : scan d'un dossier, détection des doublons et des noms suspects, classement assisté par une IA locale (Ollama).

## Installation

Python 3.10+ requis.

    pip install -r requirements-gui.txt

## Lancement

| Besoin | Commande |
|---|---|
| Interface graphique | `python main.py --gui` |
| Interface + scan immédiat | `python main.py --gui --scan --folder "C:\Users\HvKDMK11\Documents"` |
| Interface sans console | `pythonw shadowscan_app.py` |
| Ligne de commande (rapports CSV/JSON) | `python main.py --folder <dossier> --output <dossier de rapports>` |

Options de la CLI : `--no-hash` désactive le SHA-256 (donc la détection de doublons).

## Fabriquer le logiciel (.exe)

Double-clic sur `build_exe.bat` (ou `.\build_exe.bat` dans PowerShell). Résultat : `dist\SHADOWSCAN.exe`, un seul fichier, sans console, avec son icône (`assets\shadowscan.ico`).
Le fichier peut être copié où l'on veut (Bureau, barre des tâches…). Windows SmartScreen ou un antivirus peut le signaler, car il n'est pas signé.

Les rapports et journaux d'annulation de l'exécutable sont écrits dans `Documents\SHADOWSCAN\`. En cas de plantage au démarrage : `Documents\SHADOWSCAN\erreur.log`.

## Fonctions de l'interface

- **Tableau de bord** : scan en direct (compteurs, répartition par catégorie, plus gros fichiers), bouton Annuler, F5 pour lancer.
- **Fichiers** : recherche (Ctrl+F), filtre par catégorie, tri.
- **Doublons**, **Suspects**, **Erreurs** : listes détaillées. Double-clic ou clic droit : afficher dans l'Explorateur, copier le chemin.
- **Rangement** : voir ci-dessous.
- **Rapports** : `inventory.csv`, `duplicates.csv`, `suspicious_files.csv`, `scan_errors.csv`, `summary.json`, exportés à la fin de chaque scan.
- Thème sombre ou clair.

Le scan est en lecture seule : il ne supprime et ne déplace rien.

## Rangement avec une IA locale (Ollama)

1. Lance Ollama (`ollama serve` si besoin) et vérifie qu'un modèle est installé (`ollama list`).
2. Onglet **Rangement** : choisis le dossier et le modèle, puis **Générer le plan**.
3. Décoche les lignes à laisser en place, utilise **Changer le dossier…** pour corriger une proposition.
4. **Appliquer** déplace les fichiers cochés après confirmation. **Annuler le rangement** remet tout à sa place grâce au journal enregistré dans `reports\journals\`.

Garanties :

- Aucune suppression et aucun écrasement : en cas de nom identique, le fichier devient `nom (1).ext`.
- L'IA ne voit que les noms, tailles et extensions (jamais le contenu), et uniquement en local.
- Par défaut, seuls les fichiers placés directement dans le dossier sont classés. Les sous-dossiers, `.git`, `node_modules`, fichiers cachés et téléchargements en cours sont ignorés.
- Les faux doubles extensions (`facture.pdf.exe`) vont dans « À vérifier » sans passer par l'IA.
- Si Ollama est injoignable ou répond mal, SHADOWSCAN classe par extension (colonne « Source » : Règle au lieu de IA).
- Les racines de disque et les dossiers système (Windows, Program Files…) sont refusés.

## Structure

    main.py              CLI et option --gui
    shadowscan_app.py    point d'entrée du logiciel (.exe)
    build_exe.bat        fabrication de SHADOWSCAN.exe
    assets/              icône
    src/scanner.py       inventaire des fichiers
    src/analyzer.py      doublons et noms suspects
    src/reporter.py      export des rapports
    src/gui.py           interface (CustomTkinter)
    src/organizer.py     plan de rangement, Ollama, application et annulation
