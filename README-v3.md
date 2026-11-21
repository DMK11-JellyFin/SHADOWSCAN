# SHADOWSCAN v3 — rangement assisté par IA locale

## Installation
Copie `src/gui.py` et `src/organizer.py` dans le dépôt (aucune nouvelle dépendance : Ollama est appelé via urllib).

## Utilisation
    ollama serve            # si Ollama n'est pas déjà lancé
    python main.py --gui
Onglet **Rangement** : choisis le dossier, le modèle Ollama, puis **Générer le plan**.
Décoche ce que tu ne veux pas bouger, **Changer le dossier…** pour corriger une ligne, puis **Appliquer**.
**Annuler le rangement** remet tout en place (journal dans `reports/journals/`).

## Garanties
- Jamais de suppression, jamais d'écrasement (collision : `fichier (1).ext`).
- L'IA ne voit que les noms, tailles et extensions (pas le contenu), et seulement en local.
- Par défaut, seuls les fichiers directement dans le dossier sont rangés ; les sous-dossiers, `.git`, `node_modules`, fichiers cachés et téléchargements en cours sont ignorés.
- Les faux doubles extensions (`facture.pdf.exe`) vont dans « À vérifier » sans passer par l'IA.
- Si Ollama est injoignable ou répond mal, SHADOWSCAN retombe sur des règles par extension (colonne « Source »).
