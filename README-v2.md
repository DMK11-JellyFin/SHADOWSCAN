# SHADOWSCAN v2 — interface graphique

## Installation
    pip install customtkinter
Copie dans le dépôt : `main.py`, `src/gui.py`, `src/scanner.py` (progression + annulation, la CLI reste identique), `requirements-gui.txt`.

## Lancement
    python main.py --gui
    python main.py --gui --scan --folder "C:\Users\HvKDMK11\Documents"   # scan immédiat
    python main.py                                                        # CLI comme avant

## Fonctions
- Scan en direct : compteurs, camembert par catégorie et plus gros fichiers se mettent à jour pendant l'analyse ; bouton Annuler ; F5 = lancer
- Pages : Tableau de bord, Fichiers (recherche Ctrl+F, filtre, tri), Doublons (détail des chemins), Suspects, Erreurs, Rapports
- Thème sombre / clair
- Clic droit ou double-clic sur une ligne : afficher dans l'Explorateur / copier le chemin
- Lecture seule : aucune suppression, aucun déplacement
