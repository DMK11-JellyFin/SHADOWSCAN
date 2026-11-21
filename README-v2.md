# SHADOWSCAN v2 — mise à jour interface graphique

## Installation
Copie dans ton dépôt (en écrasant `main.py`) :
- `main.py`  → racine du projet
- `src/gui.py` → dossier `src/`
Les modules `scanner.py`, `analyzer.py`, `reporter.py` ne changent pas. Aucune dépendance externe (Tkinter est inclus avec Python sous Windows).

## Utilisation
    python main.py --gui
    python main.py --gui --folder "C:\Users\HvKDMK11\Documents" --output reports
    python main.py                    # ligne de commande, comme avant (v1)

## Onglets
- Tableau de bord : totaux et répartition par catégorie
- Fichiers : recherche (nom, chemin, SHA-256), filtre par catégorie, tri par colonne
- Doublons : groupes triés par espace récupérable
- Fichiers suspects : doubles extensions trompeuses (ex. facture.pdf.exe)
- Erreurs : fichiers illisibles
- Rapports : ouvrir le dossier ou chaque CSV/JSON, réexporter
Clic droit sur une ligne : afficher dans l'Explorateur / copier le chemin.

## Sécurité
L'interface est en lecture seule : aucune suppression, aucun déplacement. Les rapports sont écrits automatiquement à la fin de chaque scan.

## Limite connue
Le scan s'exécute dans un thread avec une barre de progression indéterminée (le scanner v1 n'expose pas de compteur). Les 20 000 premières lignes max sont affichées dans l'onglet Fichiers ; les rapports CSV contiennent tout.
