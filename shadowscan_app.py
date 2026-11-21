# Point d'entrée « logiciel » : double-clic sur SHADOWSCAN.exe (ou sur ce fichier) ouvre directement la fenêtre.
# Les rapports et journaux sont écrits dans Documents\SHADOWSCAN (un .exe n'a pas toujours le droit d'écrire à côté de lui).
import sys
import traceback
from pathlib import Path


def main():
    home = Path.home()
    data_dir = home / "Documents" / "SHADOWSCAN"
    try:
        if sys.platform.startswith("win"):
            import ctypes
            # Pour que la barre des tâches utilise l'icône de SHADOWSCAN et non celle de Python.
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("DMK11.SHADOWSCAN")
        from src.gui import launch_gui
        start = home / "Downloads"
        launch_gui(str(start if start.is_dir() else home), str(data_dir / "reports"), True, False)
    except Exception:  # noqa: BLE001 - en mode fenêtré, sans ceci l'erreur serait invisible
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "erreur.log").write_text(traceback.format_exc(), encoding="utf-8")
        try:
            from tkinter import messagebox
            messagebox.showerror("SHADOWSCAN", f"Erreur au démarrage. Détails dans :\n{data_dir / 'erreur.log'}")
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    main()
