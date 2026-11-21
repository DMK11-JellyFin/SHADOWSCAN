# Python 3.10+ | SHADOWSCAN GUI (Tkinter) - lecture seule : aucune suppression / aucun déplacement.
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from src.analyzer import analyze_files
from src.reporter import write_reports
from src.scanner import scan_directory

REPORT_FILES = ["inventory.csv", "duplicates.csv", "suspicious_files.csv", "scan_errors.csv", "summary.json"]


# ---------- Logique pure (testable sans interface) ----------
def format_size(num: int) -> str:
    size = float(num)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1024 or unit == "To":
            return f"{int(size)} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} o"


def filter_records(records, query: str = "", category: str = "Toutes"):
    query = query.strip().lower()
    result = []
    for rec in records:
        if category != "Toutes" and rec["category"] != category:
            continue
        if query and query not in rec["name"].lower() and query not in rec["path"].lower() \
                and query not in rec["sha256"].lower():
            continue
        result.append(rec)
    return result


def duplicate_waste(group, size_by_path) -> int:
    """Espace récupérable théorique : (n-1) copies."""
    sizes = [size_by_path.get(p, 0) for p in group["paths"]]
    return sum(sizes) - (max(sizes) if sizes else 0)


def open_in_system(path: Path) -> None:
    """Ouvre un fichier/dossier avec l'application par défaut (lecture seule)."""
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def reveal_in_explorer(path: Path) -> None:
    if sys.platform.startswith("win"):
        subprocess.Popen(["explorer", "/select,", str(path)])
    else:
        open_in_system(path.parent)


# ---------- Interface ----------
class ShadowScanApp(tk.Tk):
    def __init__(self, folder: str, output: str, calculate_hash: bool = True):
        super().__init__()
        self.title("SHADOWSCAN")
        self.geometry("1100x680")
        self.minsize(900, 560)

        self.folder_var = tk.StringVar(value=str(Path(folder).expanduser()))
        self.output_var = tk.StringVar(value=str(Path(output).expanduser()))
        self.hash_var = tk.BooleanVar(value=calculate_hash)
        self.status_var = tk.StringVar(value="Prêt.")
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="Toutes")

        self.records, self.errors, self.analysis = [], [], None
        self._queue: queue.Queue = queue.Queue()
        self._scanning = False
        self._sort_state = {}

        self._build_top()
        self._build_tabs()
        ttk.Label(self, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill="x", side="bottom")
        self.search_var.trace_add("write", lambda *_: self._refresh_files())

    # --- construction ---
    def _build_top(self):
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Label(bar, text="Dossier :").grid(row=0, column=0, sticky="w")
        ttk.Entry(bar, textvariable=self.folder_var, width=70).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(bar, text="Parcourir…", command=self._choose_folder).grid(row=0, column=2)
        ttk.Label(bar, text="Rapports :").grid(row=1, column=0, sticky="w")
        ttk.Entry(bar, textvariable=self.output_var, width=70).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Button(bar, text="Parcourir…", command=self._choose_output).grid(row=1, column=2)
        ttk.Checkbutton(bar, text="Calculer SHA-256 (nécessaire aux doublons)",
                        variable=self.hash_var).grid(row=2, column=1, sticky="w", pady=4)
        self.scan_btn = ttk.Button(bar, text="Lancer le scan", command=self._start_scan)
        self.scan_btn.grid(row=2, column=2)
        self.progress = ttk.Progressbar(bar, mode="indeterminate")
        self.progress.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        bar.columnconfigure(1, weight=1)

    def _build_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=8)

        # Tableau de bord
        self.dash = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.dash, text="Tableau de bord")
        self.stats_label = ttk.Label(self.dash, text="Aucun scan effectué.", justify="left", font=("Segoe UI", 11))
        self.stats_label.pack(anchor="w")
        self.cat_tree = self._make_tree(self.dash, ("category", "size", "share"),
                                        ("Catégorie", "Taille", "Part"), (200, 140, 100), height=10)

        # Fichiers
        files = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(files, text="Fichiers")
        flt = ttk.Frame(files)
        flt.pack(fill="x", pady=(0, 6))
        ttk.Label(flt, text="Recherche :").pack(side="left")
        ttk.Entry(flt, textvariable=self.search_var, width=40).pack(side="left", padx=4)
        ttk.Label(flt, text="Catégorie :").pack(side="left", padx=(12, 0))
        self.cat_combo = ttk.Combobox(flt, textvariable=self.category_var, state="readonly", width=16,
                                      values=["Toutes"])
        self.cat_combo.pack(side="left", padx=4)
        self.cat_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_files())
        self.count_label = ttk.Label(flt, text="")
        self.count_label.pack(side="right")
        self.files_tree = self._make_tree(
            files, ("name", "category", "size", "modified", "path"),
            ("Nom", "Catégorie", "Taille", "Modifié (UTC)", "Chemin"), (220, 100, 90, 160, 480), sortable=True)
        self._attach_open_menu(self.files_tree, path_col=4)

        # Doublons
        dup = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(dup, text="Doublons")
        self.dup_tree = self._make_tree(dup, ("copies", "waste", "sha", "paths"),
                                        ("Copies", "Espace récupérable", "SHA-256", "Chemins"),
                                        (70, 130, 160, 640), sortable=True)
        self._attach_open_menu(self.dup_tree, path_col=3, multi=True)

        # Suspects
        sus = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(sus, text="Fichiers suspects")
        ttk.Label(sus, text="Double extension trompeuse (ex. facture.pdf.exe). Aucune action destructive proposée.",
                  foreground="#a33").pack(anchor="w", pady=(0, 6))
        self.sus_tree = self._make_tree(sus, ("name", "size", "modified", "path"),
                                        ("Nom", "Taille", "Modifié (UTC)", "Chemin"), (260, 90, 160, 520),
                                        sortable=True)
        self._attach_open_menu(self.sus_tree, path_col=3)

        # Erreurs
        err = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(err, text="Erreurs")
        self.err_tree = self._make_tree(err, ("path", "error"), ("Chemin", "Erreur"), (500, 500), sortable=True)

        # Rapports
        rep = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(rep, text="Rapports")
        ttk.Button(rep, text="Ouvrir le dossier des rapports", command=self._open_report_dir).pack(anchor="w")
        ttk.Separator(rep).pack(fill="x", pady=8)
        for name in REPORT_FILES:
            ttk.Button(rep, text=f"Ouvrir {name}", command=lambda n=name: self._open_report(n)).pack(
                anchor="w", pady=2)
        ttk.Button(rep, text="Réexporter les rapports maintenant", command=self._export_reports).pack(
            anchor="w", pady=(12, 0))

    def _make_tree(self, parent, cols, headings, widths, height=None, sortable=False):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(8, 0) if height else 0)
        kwargs = {"height": height} if height else {}
        tree = ttk.Treeview(frame, columns=cols, show="headings", **kwargs)
        for col, head, width in zip(cols, headings, widths):
            if sortable:
                tree.heading(col, text=head, command=lambda c=col, t=tree: self._sort_by(t, c))
            else:
                tree.heading(col, text=head)
            tree.column(col, width=width, anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def _attach_open_menu(self, tree, path_col, multi=False):
        menu = tk.Menu(self, tearoff=0)

        def paths():
            sel = tree.selection()
            if not sel:
                return []
            value = tree.item(sel[0], "values")[path_col]
            return [p.strip() for p in str(value).split(" | ")] if multi else [str(value)]

        def copy_path():
            p = paths()
            if p:
                self.clipboard_clear()
                self.clipboard_append("\n".join(p))

        def reveal():
            p = paths()
            if p:
                self._safe(lambda: reveal_in_explorer(Path(p[0])))

        menu.add_command(label="Afficher dans l'Explorateur", command=reveal)
        menu.add_command(label="Copier le chemin", command=copy_path)

        def popup(event):
            row = tree.identify_row(event.y)
            if row:
                tree.selection_set(row)
                menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", popup)

    # --- actions ---
    def _safe(self, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("SHADOWSCAN", str(exc))

    def _choose_folder(self):
        d = filedialog.askdirectory(initialdir=self.folder_var.get() or str(Path.home()))
        if d:
            self.folder_var.set(d)

    def _choose_output(self):
        d = filedialog.askdirectory(initialdir=self.output_var.get() or str(Path.cwd()))
        if d:
            self.output_var.set(d)

    def _start_scan(self):
        if self._scanning:
            return
        root = Path(self.folder_var.get()).expanduser()
        if not root.is_dir():
            messagebox.showerror("SHADOWSCAN", f"Dossier invalide :\n{root}")
            return
        self._scanning = True
        self.scan_btn.state(["disabled"])
        self.progress.start(12)
        self.status_var.set(f"Scan en cours : {root}")
        calc = self.hash_var.get()

        def worker():
            try:
                records, errors = scan_directory(root, calculate_hash=calc)
                analysis = analyze_files(records)
                self._queue.put(("ok", records, errors, analysis))
            except Exception as exc:  # noqa: BLE001
                self._queue.put(("err", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(150, self._poll)

    def _poll(self):
        try:
            msg = self._queue.get_nowait()
        except queue.Empty:
            self.after(150, self._poll)
            return
        self._scanning = False
        self.progress.stop()
        self.scan_btn.state(["!disabled"])
        if msg[0] == "err":
            self.status_var.set("Échec du scan.")
            messagebox.showerror("SHADOWSCAN", msg[1])
            return
        _, self.records, self.errors, self.analysis = msg
        self._refresh_all()
        self._export_reports(silent=True)

    def _refresh_all(self):
        a = self.analysis
        cats = ["Toutes"] + sorted({r["category"] for r in self.records})
        self.cat_combo.configure(values=cats)
        self.category_var.set("Toutes")
        self.stats_label.configure(text=(
            f"Fichiers analysés : {len(self.records):,}\n"
            f"Taille totale : {format_size(a['total_size'])}  ({a['total_size']:,} octets)\n"
            f"Groupes de doublons : {len(a['duplicate_groups'])}\n"
            f"Noms suspects : {len(a['suspicious_files'])}\n"
            f"Erreurs de scan : {len(self.errors)}"))
        self.cat_tree.delete(*self.cat_tree.get_children())
        total = a["total_size"] or 1
        for cat, size in sorted(a["category_sizes"].items(), key=lambda kv: -kv[1]):
            self.cat_tree.insert("", "end", values=(cat, format_size(size), f"{100 * size / total:.1f} %"))
        self._refresh_files()

        size_by_path = {r["path"]: r["size_bytes"] for r in self.records}
        self.dup_tree.delete(*self.dup_tree.get_children())
        for g in sorted(a["duplicate_groups"], key=lambda g: -duplicate_waste(g, size_by_path)):
            self.dup_tree.insert("", "end", values=(
                len(g["paths"]), format_size(duplicate_waste(g, size_by_path)),
                g["sha256"][:16] + "…", " | ".join(g["paths"])))
        self.sus_tree.delete(*self.sus_tree.get_children())
        for r in a["suspicious_files"]:
            self.sus_tree.insert("", "end", values=(r["name"], format_size(r["size_bytes"]),
                                                    r["modified_utc"][:19], r["path"]))
        self.err_tree.delete(*self.err_tree.get_children())
        for e in self.errors:
            self.err_tree.insert("", "end", values=(e["path"], e["error"]))
        self.status_var.set(f"Scan terminé : {len(self.records):,} fichiers, "
                            f"{len(a['duplicate_groups'])} groupes de doublons.")

    def _refresh_files(self):
        self.files_tree.delete(*self.files_tree.get_children())
        shown = filter_records(self.records, self.search_var.get(), self.category_var.get())
        for r in shown[:20000]:
            self.files_tree.insert("", "end", values=(
                r["name"], r["category"], format_size(r["size_bytes"]), r["modified_utc"][:19], r["path"]),
                tags=(str(r["size_bytes"]),))
        extra = " (affichage limité à 20 000)" if len(shown) > 20000 else ""
        self.count_label.configure(text=f"{len(shown):,} / {len(self.records):,} fichiers{extra}")

    def _sort_by(self, tree, col):
        reverse = self._sort_state.get((id(tree), col), False)
        rows = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(item):
            v = item[0]
            digits = v.replace("…", "").split(" ")[0].replace(",", ".")
            try:
                num = float(digits)
                mult = {"Ko": 1024, "Mo": 1024**2, "Go": 1024**3, "To": 1024**4}.get(v.split(" ")[-1], 1)
                return (0, num * mult, v.lower())
            except ValueError:
                return (1, 0, v.lower())

        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            tree.move(k, "", i)
        self._sort_state[(id(tree), col)] = not reverse

    # --- rapports ---
    def _export_reports(self, silent=False):
        if not self.analysis:
            messagebox.showinfo("SHADOWSCAN", "Lance d'abord un scan.")
            return
        out = Path(self.output_var.get()).expanduser().resolve()
        try:
            write_reports(self.records, self.analysis, self.errors, out)
            self.status_var.set(f"Rapports écrits dans {out}")
            if not silent:
                messagebox.showinfo("SHADOWSCAN", f"Rapports exportés dans :\n{out}")
        except OSError as exc:
            messagebox.showerror("SHADOWSCAN", f"Impossible d'écrire les rapports :\n{exc}")

    def _open_report_dir(self):
        out = Path(self.output_var.get()).expanduser().resolve()
        if not out.is_dir():
            messagebox.showinfo("SHADOWSCAN", "Aucun rapport pour l'instant. Lance un scan.")
            return
        self._safe(lambda: open_in_system(out))

    def _open_report(self, name):
        p = Path(self.output_var.get()).expanduser().resolve() / name
        if not p.is_file():
            messagebox.showinfo("SHADOWSCAN", f"{name} n'existe pas encore. Lance un scan.")
            return
        self._safe(lambda: open_in_system(p))


def launch_gui(folder: str, output: str, calculate_hash: bool = True) -> None:
    app = ShadowScanApp(folder, output, calculate_hash)
    app.mainloop()
