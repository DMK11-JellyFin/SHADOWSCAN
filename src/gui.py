# Python 3.10+ | SHADOWSCAN GUI (CustomTkinter). Scan en lecture seule ; le rangement (page « Rangement »)
# déplace seulement après validation, sans jamais supprimer ni écraser, et reste annulable.
# Dépendance : pip install customtkinter
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import defaultdict
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import customtkinter as ctk

from src import organizer
from src.analyzer import analyze_files
from src.reporter import write_reports
from src.scanner import scan_directory

FONT = "Segoe UI" if sys.platform.startswith("win") else "DejaVu Sans"
MONO = "Consolas" if sys.platform.startswith("win") else "DejaVu Sans Mono"
REPORT_FILES = ["inventory.csv", "duplicates.csv", "suspicious_files.csv", "scan_errors.csv", "summary.json"]
CAT_LABELS = {"Documents": "Documents", "Images": "Images", "Videos": "Vidéos", "Audio": "Audio",
              "Archives": "Archives", "Executables": "Exécutables", "Code": "Code",
              "Spreadsheets": "Tableurs", "Other": "Autres"}
DONUT_COLORS = ["#4e79a7", "#f28e2b", "#59a14f", "#e15759", "#76b7b2", "#edc948", "#b07aa1", "#9c755f", "#bab0ac"]

# (clair, sombre)
PAL = {
    "bg": ("#f3f3f3", "#1f2023"),
    "side": ("#ebebeb", "#272a2e"),
    "card": ("#ffffff", "#2b2e33"),
    "card2": ("#eaeaea", "#363a40"),
    "border": ("#dcdcdc", "#41454c"),
    "text": ("#1f1f1f", "#e8e8e8"),
    "muted": ("#666666", "#a0a4ab"),
    "accent": ("#0067c0", "#0f78d4"),
    "accent_h": ("#005aa8", "#2b88dc"),
    "danger": ("#c42b1c", "#c9392c"),
    "danger_h": ("#a82418", "#b02e22"),
    "ok": ("#107c41", "#1e8a4c"),
    "warn": ("#9d5d00", "#d9a032"),
}


def col(name):
    return PAL[name]


def cur(name):
    return PAL[name][1 if ctk.get_appearance_mode() == "Dark" else 0]


# ---------- Logique pure (testable sans interface) ----------
def format_size(num: int) -> str:
    size = float(num)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1024 or unit == "To":
            return f"{int(size)} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} o"


def format_duration(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60:02d}:{s % 60:02d}"


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


# ---------- Widgets ----------
class Card(ctk.CTkFrame):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", col("card"))
        kw.setdefault("corner_radius", 6)
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", col("border"))
        super().__init__(master, **kw)


class StatCard(Card):
    def __init__(self, master, title, color):
        super().__init__(master)
        self.var = tk.StringVar(value="—")
        box = ctk.CTkFrame(self, fg_color="transparent")
        box.pack(side="left", fill="both", expand=True, padx=14, pady=10)
        ctk.CTkLabel(box, text=title, font=ctk.CTkFont(size=12), text_color=col("muted")).pack(anchor="w")
        ctk.CTkLabel(box, textvariable=self.var, font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=col("text")).pack(anchor="w")


class TablePage(ctk.CTkFrame):
    """Page avec titre, barre d'outils optionnelle et tableau stylé."""

    def __init__(self, master, app, title, subtitle, columns, widths, path_col=None, multi=False,
                 filters=False, sortable=True, empty_text="Aucune donnée. Lance un scan.", on_select=None):
        super().__init__(master, fg_color="transparent")
        self.app, self.path_col, self.multi, self.empty_text = app, path_col, multi, empty_text
        self.on_select_cb = on_select
        self._sort_state = {}
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="Toutes")
        self.on_filter = None

        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(head, text=title, font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        self.subtitle = ctk.CTkLabel(head, text=subtitle, text_color=col("muted"), justify="left")
        self.subtitle.pack(anchor="w")

        if filters:
            bar = ctk.CTkFrame(self, fg_color="transparent")
            bar.pack(fill="x", pady=(0, 10))
            self.search = ctk.CTkEntry(bar, textvariable=self.search_var, width=360, height=36, corner_radius=5,
                                       placeholder_text="Rechercher un nom, un chemin ou un SHA-256…")
            self.search.pack(side="left")
            self.cat_menu = ctk.CTkOptionMenu(bar, variable=self.category_var, values=["Toutes"], width=170,
                                              height=36, corner_radius=5, fg_color=col("card2"),
                                              button_color=col("card2"), button_hover_color=col("border"),
                                              text_color=col("text"),
                                              command=lambda _v: self.on_filter and self.on_filter())
            self.cat_menu.pack(side="left", padx=10)
            self.count_label = ctk.CTkLabel(bar, text="", text_color=col("muted"))
            self.count_label.pack(side="right")
            self._debounce = None
            self.search_var.trace_add("write", self._on_search)

        card = Card(self)
        card.pack(fill="both", expand=True)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree = ttk.Treeview(inner, columns=[c[0] for c in columns], show="headings", style="SS.Treeview")
        for (cid, head_text), width in zip(columns, widths):
            self.tree.heading(cid, text=head_text, anchor="w", command=(lambda c=cid: self._sort_by(c)) if sortable else None)
            self.tree.column(cid, width=width, anchor="w")
        vsb = ctk.CTkScrollbar(inner, command=self.tree.yview)
        hsb = ctk.CTkScrollbar(inner, orientation="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        inner.rowconfigure(0, weight=1)
        inner.columnconfigure(0, weight=1)
        self.empty_label = ctk.CTkLabel(inner, text=empty_text, text_color=col("muted"),
                                        font=ctk.CTkFont(size=14))
        self.empty_label.place(relx=0.5, rely=0.45, anchor="center")

        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Afficher dans l'Explorateur", command=self._reveal)
        self.menu.add_command(label="Copier le chemin", command=self._copy)
        self.tree.bind("<Button-3>", self._popup)
        self.tree.bind("<Double-1>", lambda _e: self._reveal())
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.on_select_cb and self.on_select_cb(self))
        self.row_data = {}

    def _on_search(self, *_):
        if self._debounce:
            self.after_cancel(self._debounce)
        self._debounce = self.after(250, lambda: self.on_filter and self.on_filter())

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.row_data = {}

    def add(self, values, data=None):
        n = len(self.tree.get_children(""))
        iid = self.tree.insert("", "end", values=values, tags=("odd" if n % 2 else "even",))
        if data is not None:
            self.row_data[iid] = data

    def finish(self, empty_text=None):
        if self.tree.get_children(""):
            self.empty_label.place_forget()
        else:
            self.empty_label.configure(text=empty_text or self.empty_text)
            self.empty_label.place(relx=0.5, rely=0.45, anchor="center")

    def selected_paths(self):
        sel = self.tree.selection()
        if not sel or self.path_col is None:
            return []
        value = str(self.tree.item(sel[0], "values")[self.path_col])
        return [p.strip() for p in value.split(" | ")] if self.multi else [value]

    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row and self.path_col is not None:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _reveal(self):
        p = self.selected_paths()
        if p:
            self.app.safe(lambda: reveal_in_explorer(Path(p[0])))

    def _copy(self):
        p = self.selected_paths()
        if p:
            self.clipboard_clear()
            self.clipboard_append("\n".join(p))
            self.app.toast("Chemin copié")

    def _sort_by(self, col_id):
        reverse = self._sort_state.get(col_id, False)
        rows = [(self.tree.set(k, col_id), k) for k in self.tree.get_children("")]

        def key(item):
            v = item[0]
            head = v.replace("…", "").split(" ")[0].replace(",", ".")
            try:
                mult = {"Ko": 1024, "Mo": 1024 ** 2, "Go": 1024 ** 3, "To": 1024 ** 4}.get(v.split(" ")[-1], 1)
                return (0, float(head) * mult, v.lower())
            except ValueError:
                return (1, 0, v.lower())

        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)
            self.tree.item(k, tags=("odd" if i % 2 else "even",))
        self._sort_state[col_id] = not reverse


# ---------- Application ----------
class ShadowScanApp(ctk.CTk):
    PAGES = [("dashboard", "Tableau de bord"), ("files", "Fichiers"), ("dups", "Doublons"),
             ("sus", "Suspects"), ("errs", "Erreurs"), ("org", "Rangement"), ("reports", "Rapports")]

    def __init__(self, folder, output, calculate_hash=True, autoscan=False):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        super().__init__(fg_color=col("bg"))
        self.title("SHADOWSCAN")
        self.geometry("1240x760")
        self.minsize(1020, 640)
        self._set_icon()

        self.folder_var = tk.StringVar(value=str(Path(folder).expanduser()))
        self.output_var = tk.StringVar(value=str(Path(output).expanduser()))
        self.hash_var = tk.BooleanVar(value=calculate_hash)

        self.records, self.errors, self.analysis = [], [], None
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.scanning = False
        self.result = None
        self.donut_progress = 1.0
        self._toast_job = None
        self.live = self._new_live()

        # rangement (IA locale)
        self.org_url_var = tk.StringVar(value=organizer.DEFAULT_URL)
        self.org_model_var = tk.StringVar(value="")
        self.org_ai_var = tk.BooleanVar(value=True)
        self.org_sub_var = tk.BooleanVar(value=False)
        self.org_moves, self.org_root, self.org_state = [], None, None
        self.org_stop = threading.Event()
        self.org_busy = False
        self._models_loaded = False

        self._style_tree()
        self._build_layout()
        self.show("dashboard")
        self.bind("<F5>", lambda _e: self.toggle_scan())
        self.bind("<Control-f>", lambda _e: (self.show("files"), self.files_page.search.focus_set()))
        if autoscan:
            self.after(300, self.start_scan)

    def _set_icon(self):
        base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
        ico = base / "assets" / "shadowscan.ico"
        if sys.platform.startswith("win") and ico.is_file():
            # CustomTkinter remet son icône par défaut après ~200 ms : on pose la nôtre après.
            self.after(300, lambda: self.iconbitmap(str(ico)))

    # --- état ---
    @staticmethod
    def _new_live():
        return {"count": 0, "size": 0, "errors": 0, "cats": defaultdict(int), "path": "", "top": [],
                "start": time.monotonic()}

    # --- style des tableaux (ttk) ---
    def _style_tree(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("SS.Treeview", background=cur("card"), fieldbackground=cur("card"), foreground=cur("text"),
                     rowheight=30, borderwidth=0, font=(FONT, 10))
        st.map("SS.Treeview", background=[("selected", cur("accent"))], foreground=[("selected", "#ffffff")])
        st.configure("SS.Treeview.Heading", background=cur("card2"), foreground=cur("muted"), relief="flat",
                     font=(FONT, 9, "bold"), padding=(8, 8), borderwidth=0)
        st.map("SS.Treeview.Heading", background=[("active", cur("border"))])
        st.layout("SS.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _tag_trees(self):
        for page in (self.files_page, self.dups_page, self.sus_page, self.errs_page, self.org_page):
            page.tree.tag_configure("odd", background=cur("card2") if False else cur("card"))
            page.tree.tag_configure("even", background=cur("card"))
            alt = "#30333a" if ctk.get_appearance_mode() == "Dark" else "#f6f6f6"
            page.tree.tag_configure("odd", background=alt)

    # --- layout ---
    def _build_layout(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        side = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=col("side"))
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)
        logo = ctk.CTkFrame(side, fg_color="transparent")
        logo.pack(fill="x", padx=20, pady=(26, 22))
        ctk.CTkLabel(logo, text="SHADOWSCAN", font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")

        self.nav = {}
        for key, label in self.PAGES:
            btn = ctk.CTkButton(side, text=label, anchor="w", height=36, corner_radius=5,
                                fg_color="transparent", hover_color=col("card2"), text_color=col("muted"),
                                font=ctk.CTkFont(size=13), command=lambda k=key: self.show(k))
            btn.pack(fill="x", padx=12, pady=2)
            self.nav[key] = btn

        bottom = ctk.CTkFrame(side, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=20)
        ctk.CTkLabel(bottom, text="Aucun fichier n'est supprimé", text_color=col("muted"),
                     font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(0, 10))
        self.theme_switch = ctk.CTkSwitch(bottom, text="Mode clair", command=self._toggle_theme,
                                          progress_color=col("accent"))
        self.theme_switch.pack(anchor="w")

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=26, pady=22)
        self.content.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)

        self.pages = {}
        self._build_dashboard()
        self.files_page = TablePage(
            self.content, self, "Fichiers", "Double-clic : afficher dans l'Explorateur.",
            [("name", "Nom"), ("cat", "Catégorie"), ("size", "Taille"), ("mod", "Modifié (UTC)"), ("path", "Chemin")],
            [250, 110, 90, 150, 560], path_col=4, filters=True)
        self.files_page.on_filter = self.refresh_files
        self.dups_page = TablePage(
            self.content, self, "Doublons", "Fichiers au contenu identique (SHA-256), triés par espace récupérable.",
            [("copies", "Copies"), ("waste", "Récupérable"), ("sha", "SHA-256"), ("paths", "Chemins")],
            [70, 120, 160, 700], path_col=3, multi=True, empty_text="Aucun doublon détecté.",
            on_select=self._show_dup_detail)
        self.sus_page = TablePage(
            self.content, self, "Fichiers suspects",
            "Double extension trompeuse (ex. facture.pdf.exe). Ne les ouvre pas.",
            [("name", "Nom"), ("size", "Taille"), ("mod", "Modifié (UTC)"), ("path", "Chemin")],
            [280, 90, 150, 600], path_col=3, empty_text="Aucun nom suspect.")
        self.errs_page = TablePage(
            self.content, self, "Erreurs de scan", "Fichiers illisibles (droits, fichiers verrouillés…).",
            [("path", "Chemin"), ("error", "Erreur")], [520, 520], empty_text="Aucune erreur.")
        self._build_dup_detail()
        self._build_organizer()
        self._build_reports()
        for key, page in (("files", self.files_page), ("dups", self.dups_page), ("sus", self.sus_page),
                          ("errs", self.errs_page), ("org", self.org_page)):
            self.pages[key] = page
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        self._tag_trees()

        self.toast_label = ctk.CTkLabel(self, text="", fg_color=col("accent"), text_color="#ffffff",
                                        corner_radius=5, font=ctk.CTkFont(size=12, weight="bold"),
                                        padx=14, pady=6)

    def _build_dashboard(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["dashboard"] = page
        page.columnconfigure(0, weight=1)
        page.rowconfigure(3, weight=1)

        head = ctk.CTkFrame(page, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        ctk.CTkLabel(head, text="Tableau de bord", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        self.dash_sub = ctk.CTkLabel(head, text="Inventaire d'un dossier, doublons et noms suspects.",
                                     text_color=col("muted"))
        self.dash_sub.pack(anchor="w")

        # Zone de scan
        hero = Card(page)
        hero.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        r1 = ctk.CTkFrame(hero, fg_color="transparent")
        r1.pack(fill="x", padx=18, pady=(16, 6))
        self.folder_entry = ctk.CTkEntry(r1, textvariable=self.folder_var, height=40, corner_radius=5,
                                         placeholder_text="Dossier à analyser")
        self.folder_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(r1, text="Parcourir…", width=110, height=40, corner_radius=5, fg_color=col("card2"),
                      hover_color=col("border"), text_color=col("text"), command=self._choose_folder
                      ).pack(side="left", padx=(10, 0))
        self.scan_btn = ctk.CTkButton(r1, text="Lancer le scan", width=170, height=40, corner_radius=5,
                                      font=ctk.CTkFont(size=14, weight="bold"), fg_color=col("accent"),
                                      hover_color=col("accent_h"), command=self.toggle_scan)
        self.scan_btn.pack(side="left", padx=(10, 0))

        r2 = ctk.CTkFrame(hero, fg_color="transparent")
        r2.pack(fill="x", padx=18, pady=(0, 8))
        ctk.CTkLabel(r2, text="Accès rapide :", text_color=col("muted")).pack(side="left", padx=(0, 8))
        for label, sub in (("Téléchargements", "Downloads"), ("Documents", "Documents"), ("Bureau", "Desktop"),
                           ("Dossier personnel", "")):
            ctk.CTkButton(r2, text=label, height=28, corner_radius=5, width=10, fg_color="transparent",
                          border_width=1, border_color=col("border"), hover_color=col("card2"),
                          text_color=col("text"), font=ctk.CTkFont(size=12),
                          command=lambda s=sub: self.folder_var.set(str(Path.home() / s) if s else str(Path.home()))
                          ).pack(side="left", padx=3)
        ctk.CTkCheckBox(r2, text="Calculer SHA-256 (doublons)", variable=self.hash_var, checkbox_height=20,
                        checkbox_width=20, fg_color=col("accent"), hover_color=col("accent_h")
                        ).pack(side="right")

        r3 = ctk.CTkFrame(hero, fg_color="transparent")
        r3.pack(fill="x", padx=18, pady=(2, 16))
        self.progress = ctk.CTkProgressBar(r3, height=6, progress_color=col("accent"), fg_color=col("card2"),
                                           mode="determinate")
        self.progress.set(0)
        self.progress.pack(fill="x")
        self.ticker = ctk.CTkLabel(r3, text="Prêt. F5 pour lancer le scan.",
                                   text_color=col("muted"), anchor="w", font=ctk.CTkFont(size=12))
        self.ticker.pack(fill="x", pady=(6, 0))

        # Cartes
        cards = ctk.CTkFrame(page, fg_color="transparent")
        cards.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self.stats = {}
        for i, (key, title, color) in enumerate([
                ("files", "Fichiers", "#7c6cff"), ("size", "Taille totale", "#22d3ee"),
                ("dups", "Groupes de doublons", "#f59e0b"), ("sus", "Noms suspects", "#ef4444"),
                ("errs", "Erreurs", "#94a3b8")]):
            card = StatCard(cards, title, color)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            cards.columnconfigure(i, weight=1, uniform="stat")
            self.stats[key] = card

        # Graphiques
        charts = ctk.CTkFrame(page, fg_color="transparent")
        charts.grid(row=3, column=0, sticky="nsew")
        charts.columnconfigure(0, weight=3, uniform="ch")
        charts.columnconfigure(1, weight=2, uniform="ch")
        charts.rowconfigure(0, weight=1)
        c1 = Card(charts)
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        ctk.CTkLabel(c1, text="Répartition par catégorie", font=ctk.CTkFont(size=14, weight="bold")
                     ).pack(anchor="w", padx=18, pady=(14, 0))
        self.donut = tk.Canvas(c1, highlightthickness=0, bg=cur("card"))
        self.donut.pack(fill="both", expand=True, padx=10, pady=8)
        self.donut.bind("<Configure>", lambda _e: self.draw_donut())
        c2 = Card(charts)
        c2.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        ctk.CTkLabel(c2, text="Plus gros fichiers", font=ctk.CTkFont(size=14, weight="bold")
                     ).pack(anchor="w", padx=18, pady=(14, 0))
        self.topc = tk.Canvas(c2, highlightthickness=0, bg=cur("card"))
        self.topc.pack(fill="both", expand=True, padx=10, pady=8)
        self.topc.bind("<Configure>", lambda _e: self.draw_top())

    def _build_dup_detail(self):
        # panneau de détail sous le tableau des doublons
        self.dups_page.pack_propagate(True)
        self.dup_detail = ctk.CTkTextbox(self.dups_page, height=110, corner_radius=5, fg_color=col("card"),
                                         border_width=1, border_color=col("border"), text_color=col("text"),
                                         font=ctk.CTkFont(family=MONO, size=12))
        self.dup_detail.pack(fill="x", pady=(10, 0))
        self.dup_detail.insert("1.0", "Sélectionne un groupe pour voir tous ses chemins.")
        self.dup_detail.configure(state="disabled")

    def _show_dup_detail(self, page):
        paths = page.selected_paths()
        self.dup_detail.configure(state="normal")
        self.dup_detail.delete("1.0", "end")
        self.dup_detail.insert("1.0", "\n".join(paths) if paths else "")
        self.dup_detail.configure(state="disabled")

    def _build_reports(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self.pages["reports"] = page
        ctk.CTkLabel(page, text="Rapports", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(page, text="Exportés automatiquement à la fin de chaque scan.", text_color=col("muted")
                     ).pack(anchor="w", pady=(0, 14))
        card = Card(page)
        card.pack(fill="x")
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=16)
        ctk.CTkEntry(row, textvariable=self.output_var, height=40, corner_radius=5).pack(side="left", fill="x",
                                                                                         expand=True)
        for text, cmd in (("Parcourir…", self._choose_output), ("Ouvrir le dossier", self._open_report_dir),
                          ("Réexporter", lambda: self.export_reports())):
            ctk.CTkButton(row, text=text, height=40, corner_radius=5, fg_color=col("card2"),
                          hover_color=col("border"), text_color=col("text"), command=cmd).pack(side="left",
                                                                                              padx=(10, 0))
        self.report_rows = {}
        lst = Card(page)
        lst.pack(fill="x", pady=(14, 0))
        for name in REPORT_FILES:
            r = ctk.CTkFrame(lst, fg_color="transparent")
            r.pack(fill="x", padx=18, pady=6)
            ctk.CTkLabel(r, text=name, font=ctk.CTkFont(size=13, weight="bold"), width=200, anchor="w"
                         ).pack(side="left")
            info = ctk.CTkLabel(r, text="—", text_color=col("muted"), anchor="w")
            info.pack(side="left", fill="x", expand=True)
            ctk.CTkButton(r, text="Ouvrir", width=90, height=30, corner_radius=5, fg_color=col("accent"),
                          hover_color=col("accent_h"), command=lambda n=name: self._open_report(n)
                          ).pack(side="right")
            self.report_rows[name] = info

    # --- navigation ---
    def show(self, key):
        self.pages[key].tkraise()
        for k, btn in self.nav.items():
            active = k == key
            btn.configure(fg_color=col("card2") if active else "transparent",
                          text_color=col("accent") if active else col("muted"))
        if key == "reports":
            self.refresh_report_rows()
        if key == "org" and not self._models_loaded:
            self.refresh_models()

    def _toggle_theme(self):
        ctk.set_appearance_mode("light" if self.theme_switch.get() else "dark")
        self._style_tree()
        self._tag_trees()
        self.donut.configure(bg=cur("card"))
        self.topc.configure(bg=cur("card"))
        self.draw_donut()
        self.draw_top()

    def toast(self, text, ms=2200):
        self.toast_label.configure(text=text)
        self.toast_label.place(relx=1.0, rely=1.0, x=-26, y=-22, anchor="se")
        if self._toast_job:
            self.after_cancel(self._toast_job)
        self._toast_job = self.after(ms, self.toast_label.place_forget)

    def safe(self, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("SHADOWSCAN", str(exc))

    # --- scan ---
    def _choose_folder(self):
        d = filedialog.askdirectory(initialdir=self.folder_var.get() or str(Path.home()))
        if d:
            self.folder_var.set(d)

    def _choose_output(self):
        d = filedialog.askdirectory(initialdir=self.output_var.get() or str(Path.cwd()))
        if d:
            self.output_var.set(d)

    def toggle_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.scan_btn.configure(text="Arrêt…", state="disabled")
        else:
            self.start_scan()

    def start_scan(self):
        if self.scanning:
            return
        root = Path(self.folder_var.get()).expanduser()
        if not root.is_dir():
            messagebox.showerror("SHADOWSCAN", f"Dossier invalide :\n{root}")
            return
        self.show("dashboard")
        self.scanning = True
        self.result = None
        self.stop_event.clear()
        self.live = self._new_live()
        self.donut_progress = 1.0
        self.scan_btn.configure(text="Annuler", fg_color=col("danger"), hover_color=col("danger_h"))
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        calc = self.hash_var.get()
        live = self.live

        def on_progress(rec, path):
            with self.lock:
                live["path"] = path
                if rec is None:
                    live["errors"] += 1
                    return
                live["count"] += 1
                live["size"] += rec["size_bytes"]
                live["cats"][rec["category"]] += rec["size_bytes"]
                top = live["top"]
                if len(top) < 8 or rec["size_bytes"] > top[-1][1]:
                    top.append((rec["name"], rec["size_bytes"], rec["path"]))
                    top.sort(key=lambda t: -t[1])
                    del top[8:]

        def worker():
            try:
                records, errors = scan_directory(root, calculate_hash=calc, progress=on_progress,
                                                 stop_event=self.stop_event)
                self.result = ("ok", records, errors, analyze_files(records))
            except Exception as exc:  # noqa: BLE001
                self.result = ("err", str(exc))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self._tick)

    def _tick(self):
        with self.lock:
            live = self.live
            count, size, errs, path = live["count"], live["size"], live["errors"], live["path"]
        elapsed = time.monotonic() - live["start"]
        self.stats["files"].var.set(f"{count:,}".replace(",", " "))
        self.stats["size"].var.set(format_size(size))
        self.stats["errs"].var.set(str(errs))
        short = path if len(path) < 95 else "…" + path[-92:]
        rate = count / elapsed if elapsed > 0 else 0
        self.ticker.configure(text=f"{short}\n{format_duration(elapsed)}  ·  {rate:,.0f} fichiers/s".replace(",", " "))
        self.draw_donut()
        self.draw_top()
        if self.result is None:
            self.after(120, self._tick)
        else:
            self._finish_scan()

    def _finish_scan(self):
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1)
        self.scanning = False
        self.scan_btn.configure(text="Lancer le scan", state="normal", fg_color=col("accent"),
                                hover_color=col("accent_h"))
        if self.result[0] == "err":
            self.ticker.configure(text="Échec du scan.")
            messagebox.showerror("SHADOWSCAN", self.result[1])
            return
        _, self.records, self.errors, self.analysis = self.result
        cancelled = self.stop_event.is_set()
        a = self.analysis
        self.stats["files"].var.set(f"{len(self.records):,}".replace(",", " "))
        self.stats["size"].var.set(format_size(a["total_size"]))
        self.stats["dups"].var.set(str(len(a["duplicate_groups"])))
        self.stats["sus"].var.set(str(len(a["suspicious_files"])))
        self.stats["errs"].var.set(str(len(self.errors)))
        elapsed = time.monotonic() - self.live["start"]
        self.ticker.configure(text=("Scan interrompu (résultats partiels)" if cancelled else "Scan terminé")
                              + f" en {format_duration(elapsed)} · {len(self.records):,} fichiers".replace(",", " "))
        self.dash_sub.configure(text=f"Dernier scan : {self.folder_var.get()}")
        self._refresh_tables()
        self.export_reports(silent=True)
        self._animate_donut(0.0)
        self.toast("Scan interrompu" if cancelled else "Scan terminé · rapports exportés")

    def _animate_donut(self, p):
        self.donut_progress = min(1.0, p)
        self.draw_donut()
        if p < 1.0:
            self.after(16, lambda: self._animate_donut(p + 0.045))

    # --- dessin ---
    def _cats(self):
        if self.scanning or self.analysis is None:
            with self.lock:
                return dict(self.live["cats"])
        return dict(self.analysis["category_sizes"])

    def draw_donut(self):
        c = self.donut
        c.delete("all")
        c.configure(bg=cur("card"))
        w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 160)
        cats = sorted(self._cats().items(), key=lambda kv: -kv[1])
        total = sum(v for _, v in cats)
        size = min(h - 20, w * 0.48)
        t = max(18, size * 0.16)
        cx, cy = 20 + size / 2, h / 2
        box = (cx - size / 2 + t / 2, cy - size / 2 + t / 2, cx + size / 2 - t / 2, cy + size / 2 - t / 2)
        c.create_oval(*box, outline=cur("card2"), width=t)
        if total <= 0:
            c.create_text(cx, cy - 8, text="Aucune donnée", fill=cur("muted"), font=(FONT, 12, "bold"))
            c.create_text(cx, cy + 12, text="Lance un scan", fill=cur("muted"), font=(FONT, 10))
            return
        angle = 90.0
        for i, (cat, sz) in enumerate(cats):
            ext = -360.0 * sz / total * self.donut_progress
            if abs(ext) > 0.3:
                c.create_arc(*box, start=angle, extent=max(ext, -359.9), style="arc", width=t,
                             outline=DONUT_COLORS[i % len(DONUT_COLORS)])
            angle += ext
        c.create_text(cx, cy - 10, text=format_size(total), fill=cur("text"), font=(FONT, 17, "bold"))
        c.create_text(cx, cy + 14, text="analysés", fill=cur("muted"), font=(FONT, 10))
        lx, y = cx + size / 2 + 36, max(14, cy - min(len(cats), 9) * 15)
        for i, (cat, sz) in enumerate(cats[:9]):
            colr = DONUT_COLORS[i % len(DONUT_COLORS)]
            c.create_oval(lx, y + 4, lx + 10, y + 14, fill=colr, outline=colr)
            c.create_text(lx + 18, y + 9, text=CAT_LABELS.get(cat, cat), anchor="w", fill=cur("text"),
                          font=(FONT, 10, "bold"))
            c.create_text(w - 12, y + 9, text=f"{format_size(sz)}  {100 * sz / total:.0f} %", anchor="e",
                          fill=cur("muted"), font=(FONT, 9))
            y += 30

    def draw_top(self):
        c = self.topc
        c.delete("all")
        c.configure(bg=cur("card"))
        w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 160)
        if self.scanning or self.analysis is None:
            with self.lock:
                items = list(self.live["top"])
        else:
            items = sorted(((r["name"], r["size_bytes"], r["path"]) for r in self.records),
                           key=lambda t: -t[1])[:8]
        if not items:
            c.create_text(w / 2, h / 2, text="Aucune donnée", fill=cur("muted"), font=(FONT, 12, "bold"))
            return
        biggest = items[0][1] or 1
        y = 6
        for name, sz, _p in items:
            label = name if len(name) < 30 else name[:27] + "…"
            c.create_text(8, y + 8, text=label, anchor="w", fill=cur("text"), font=(FONT, 10))
            c.create_text(w - 8, y + 8, text=format_size(sz), anchor="e", fill=cur("muted"), font=(FONT, 9))
            c.create_rectangle(8, y + 20, w - 8, y + 25, fill=cur("card2"), width=0)
            c.create_rectangle(8, y + 20, 8 + max(3, (w - 16) * sz / biggest), y + 25, fill=cur("accent"), width=0)
            y += 38

    # --- tableaux ---
    def _refresh_tables(self):
        a = self.analysis
        cats = ["Toutes"] + sorted({r["category"] for r in self.records})
        self.files_page.cat_menu.configure(values=cats)
        self.files_page.category_var.set("Toutes")
        self.refresh_files()

        size_by_path = {r["path"]: r["size_bytes"] for r in self.records}
        self.dups_page.clear()
        for g in sorted(a["duplicate_groups"], key=lambda g: -duplicate_waste(g, size_by_path)):
            self.dups_page.add((len(g["paths"]), format_size(duplicate_waste(g, size_by_path)),
                                g["sha256"][:16] + "…", " | ".join(g["paths"])))
        empty = "Hachage désactivé : pas de détection de doublons." if not self.hash_var.get() else None
        self.dups_page.finish(empty)
        self.sus_page.clear()
        for r in a["suspicious_files"]:
            self.sus_page.add((r["name"], format_size(r["size_bytes"]), r["modified_utc"][:19], r["path"]))
        self.sus_page.finish()
        self.errs_page.clear()
        for e in self.errors:
            self.errs_page.add((e["path"], e["error"]))
        self.errs_page.finish()
        for key, n in (("dups", len(a["duplicate_groups"])), ("sus", len(a["suspicious_files"])),
                       ("errs", len(self.errors))):
            label = dict(self.PAGES)[key]
            self.nav[key].configure(text=f"{label}   ({n})" if n else label)

    def refresh_files(self):
        p = self.files_page
        p.clear()
        shown = filter_records(self.records, p.search_var.get(), p.category_var.get())
        for r in shown[:20000]:
            p.add((r["name"], CAT_LABELS.get(r["category"], r["category"]), format_size(r["size_bytes"]),
                   r["modified_utc"][:19], r["path"]))
        p.finish("Aucun fichier ne correspond." if self.records else None)
        extra = " (affichage limité à 20 000)" if len(shown) > 20000 else ""
        p.count_label.configure(text=f"{len(shown):,} / {len(self.records):,} fichiers{extra}".replace(",", " "))

    # --- rangement (IA locale) ---
    def _build_organizer(self):
        p = TablePage(
            self.content, self, "Rangement",
            "Classe les fichiers d'un dossier. Rien n'est déplacé avant ta validation.",
            [("sel", ""), ("name", "Fichier"), ("size", "Taille"), ("dest", "Dossier proposé"),
             ("src", "Source"), ("path", "Chemin")],
            [36, 280, 90, 240, 80, 520], path_col=5,
            empty_text="Aucun plan. Choisis un dossier puis clique sur « Générer le plan ».")
        self.org_page = p
        head = p.winfo_children()[0]

        ctrl = Card(p)
        ctrl.pack(fill="x", pady=(0, 10), after=head)
        r1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        r1.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkEntry(r1, textvariable=self.folder_var, height=36, corner_radius=5,
                     placeholder_text="Dossier à ranger").pack(side="left", fill="x", expand=True)
        ctk.CTkButton(r1, text="Parcourir…", width=100, height=36, corner_radius=5, fg_color=col("card2"),
                      hover_color=col("border"), text_color=col("text"), command=self._choose_folder
                      ).pack(side="left", padx=(10, 0))

        r2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        r2.pack(fill="x", padx=16, pady=(0, 6))
        ctk.CTkCheckBox(r2, text="Classer avec Ollama (IA locale)", variable=self.org_ai_var, checkbox_height=20,
                        checkbox_width=20, fg_color=col("accent"), hover_color=col("accent_h")
                        ).pack(side="left")
        self.model_menu = ctk.CTkOptionMenu(r2, variable=self.org_model_var, values=["(aucun modèle)"], width=230,
                                            height=32, corner_radius=5, fg_color=col("card2"),
                                            button_color=col("card2"), button_hover_color=col("border"),
                                            text_color=col("text"))
        self.model_menu.pack(side="left", padx=(12, 0))
        ctk.CTkButton(r2, text="Actualiser", width=90, height=32, corner_radius=5, fg_color=col("card2"),
                      hover_color=col("border"), text_color=col("text"), command=self.refresh_models
                      ).pack(side="left", padx=(6, 0))
        ctk.CTkEntry(r2, textvariable=self.org_url_var, width=200, height=32, corner_radius=5
                     ).pack(side="left", padx=(10, 0))
        ctk.CTkCheckBox(r2, text="Inclure les sous-dossiers", variable=self.org_sub_var,
                        checkbox_height=20, checkbox_width=20, fg_color=col("accent"),
                        hover_color=col("accent_h")).pack(side="right")

        r3 = ctk.CTkFrame(ctrl, fg_color="transparent")
        r3.pack(fill="x", padx=16, pady=(0, 14))
        self.org_gen_btn = ctk.CTkButton(r3, text="Générer le plan", width=170, height=38, corner_radius=5,
                                         font=ctk.CTkFont(size=14, weight="bold"), fg_color=col("accent"),
                                         hover_color=col("accent_h"), command=self.toggle_plan)
        self.org_gen_btn.pack(side="left")
        box = ctk.CTkFrame(r3, fg_color="transparent")
        box.pack(side="left", fill="x", expand=True, padx=(14, 0))
        self.org_progress = ctk.CTkProgressBar(box, height=6, progress_color=col("accent"), fg_color=col("card2"))
        self.org_progress.set(0)
        self.org_progress.pack(fill="x", pady=(6, 0))
        self.org_status = ctk.CTkLabel(box, text="Seuls les fichiers placés directement dans le dossier sont classés.",
                                       text_color=col("muted"), anchor="w", font=ctk.CTkFont(size=12))
        self.org_status.pack(fill="x", pady=(4, 0))

        bar = ctk.CTkFrame(p, fg_color="transparent")
        bar.pack(fill="x", pady=(10, 0))
        self.org_summary = ctk.CTkLabel(bar, text="", text_color=col("muted"))
        self.org_summary.pack(side="left")
        self.org_apply_btn = ctk.CTkButton(bar, text="Appliquer le plan", width=160, height=38, corner_radius=5,
                                           font=ctk.CTkFont(size=14, weight="bold"), fg_color=col("ok"),
                                           hover_color=col("ok"), state="disabled", command=self.apply_plan)
        self.org_apply_btn.pack(side="right")
        for text, width, cmd in (("Annuler le rangement", 170, self.undo_last),
                                 ("Changer le dossier…", 150, self.change_folder),
                                 ("Tout décocher", 110, lambda: self._org_set_all(False)),
                                 ("Tout cocher", 100, lambda: self._org_set_all(True))):
            ctk.CTkButton(bar, text=text, width=width, height=38, corner_radius=5, fg_color=col("card2"),
                          hover_color=col("border"), text_color=col("text"), command=cmd
                          ).pack(side="right", padx=(0, 8))

        p.tree.bind("<Button-1>", self._org_click)
        p.tree.bind("<Double-1>", self._org_double_click)

    def refresh_models(self):
        url = self.org_url_var.get().strip() or organizer.DEFAULT_URL
        self._models_loaded = True
        self.org_status.configure(text="Recherche d'Ollama…", text_color=col("muted"))
        out = {}

        def worker():
            try:
                out["models"] = organizer.list_models(url)
            except (OSError, ValueError) as exc:
                out["error"] = str(getattr(exc, "reason", exc))

        def poll():
            if not out:
                self.after(100, poll)
                return
            if "models" in out and out["models"]:
                self.model_menu.configure(values=out["models"])
                if self.org_model_var.get() not in out["models"]:
                    self.org_model_var.set(out["models"][0])
                self.org_status.configure(text=f"Ollama : {len(out['models'])} modèle(s) disponible(s).",
                                          text_color=col("ok"))
            elif "models" in out:
                self.model_menu.configure(values=["(aucun modèle)"])
                self.org_model_var.set("(aucun modèle)")
                self.org_status.configure(text="Ollama répond mais aucun modèle n'est installé (ollama pull …).",
                                          text_color=col("warn"))
            else:
                self.org_status.configure(
                    text=f"Ollama injoignable ({out['error']}). Lance-le, ou décoche l'IA pour utiliser les règles.",
                    text_color=col("warn"))

        threading.Thread(target=worker, daemon=True).start()
        poll()

    def toggle_plan(self):
        if self.org_busy:
            self.org_stop.set()
            self.org_gen_btn.configure(text="Arrêt…", state="disabled")
        else:
            self.generate_plan()

    def generate_plan(self):
        root = Path(self.folder_var.get()).expanduser()
        if not root.is_dir():
            messagebox.showerror("SHADOWSCAN", f"Dossier invalide :\n{root}")
            return
        reason = organizer.is_protected_root(root)
        if reason:
            messagebox.showerror("SHADOWSCAN", f"Rangement refusé : {reason}\n{root}")
            return
        use_ai = self.org_ai_var.get()
        model = self.org_model_var.get()
        if use_ai and model in ("", "(aucun modèle)"):
            messagebox.showinfo("SHADOWSCAN", "Aucun modèle Ollama sélectionné. Clique sur Actualiser ou décoche l'IA.")
            return
        recursive = self.org_sub_var.get()
        if recursive and not messagebox.askyesno(
                "SHADOWSCAN", "Inclure les sous-dossiers va sortir les fichiers de leur arborescence "
                              "(projets, albums…) pour les ranger à la racine choisie.\n\nContinuer ?"):
            return
        url = self.org_url_var.get().strip() or organizer.DEFAULT_URL
        self.org_root = root.resolve()
        self.org_busy = True
        self.org_stop.clear()
        self.org_state = {"done": 0, "total": 0, "result": None}
        state = self.org_state
        self.org_gen_btn.configure(text="Annuler", fg_color=col("danger"), hover_color=col("danger_h"))
        self.org_apply_btn.configure(state="disabled")
        self.org_progress.configure(mode="indeterminate")
        self.org_progress.start()
        self.org_status.configure(text="Lecture du dossier…", text_color=col("muted"))

        def on_progress(done, total):
            state["done"], state["total"] = done, total

        def worker():
            try:
                out = Path(self.output_var.get()).expanduser()
                records = organizer.list_files(root, recursive, exclude=[out])
                state["total"] = len(records)
                moves, warnings = organizer.build_plan(root, records, use_ai, model, url, self.org_stop, on_progress)
                state["result"] = ("ok", moves, warnings, len(records))
            except Exception as exc:  # noqa: BLE001
                state["result"] = ("err", str(exc))

        threading.Thread(target=worker, daemon=True).start()
        self.after(150, self._poll_plan)

    def _poll_plan(self):
        st = self.org_state
        if st["result"] is None:
            if st["total"] and st["done"]:
                if str(self.org_progress.cget("mode")) != "determinate":
                    self.org_progress.stop()
                    self.org_progress.configure(mode="determinate")
                self.org_progress.set(st["done"] / st["total"])
                self.org_status.configure(text=f"L'IA analyse les noms : {st['done']} / {st['total']}",
                                          text_color=col("muted"))
            self.after(150, self._poll_plan)
            return
        self.org_progress.stop()
        self.org_progress.configure(mode="determinate")
        self.org_progress.set(1)
        self.org_busy = False
        self.org_gen_btn.configure(text="Générer le plan", state="normal", fg_color=col("accent"),
                                   hover_color=col("accent_h"))
        if st["result"][0] == "err":
            self.org_status.configure(text="Échec de la génération du plan.", text_color=col("danger"))
            messagebox.showerror("SHADOWSCAN", st["result"][1])
            return
        _, self.org_moves, warnings, n_files = st["result"]
        cancelled = self.org_stop.is_set()
        self._org_fill()
        if warnings:
            self.org_status.configure(text=warnings[0], text_color=col("warn"))
        else:
            ai = sum(1 for m in self.org_moves if m["source"] == "IA")
            self.org_status.configure(
                text=("Plan interrompu (règles pour le reste). " if cancelled else "Plan prêt. ")
                     + f"{n_files} fichier(s) analysé(s), {ai} dossier(s) choisi(s) par l'IA.",
                text_color=col("ok"))

    def _org_fill(self):
        p = self.org_page
        p.clear()
        for m in self.org_moves:
            p.add(("✓" if m["checked"] else "", m["name"], format_size(m["size"]), m["folder"], m["source"],
                   m["src"]), data=m)
        p.finish("Rien à ranger : tout est déjà à sa place." if self.org_root else None)
        self._org_update_summary()

    def _org_update_summary(self):
        chosen = [m for m in self.org_moves if m["checked"]]
        folders = {m["folder"] for m in chosen}
        self.org_summary.configure(text=f"{len(chosen)}/{len(self.org_moves)} fichiers · "
                                        f"{len(folders)} dossiers" if self.org_moves else "")
        self.org_apply_btn.configure(state="normal" if chosen and not self.org_busy else "disabled",
                                     text=f"Appliquer ({len(chosen)})" if chosen else "Appliquer le plan")

    def _org_set_row(self, iid):
        m = self.org_page.row_data[iid]
        self.org_page.tree.item(iid, values=("✓" if m["checked"] else "", m["name"], format_size(m["size"]),
                                             m["folder"], m["source"], m["src"]))

    def _org_set_all(self, value):
        for iid in self.org_page.tree.get_children(""):
            self.org_page.row_data[iid]["checked"] = value
            self._org_set_row(iid)
        self._org_update_summary()

    def _org_click(self, event):
        t = self.org_page.tree
        if t.identify_region(event.x, event.y) == "cell" and t.identify_column(event.x) == "#1":
            iid = t.identify_row(event.y)
            if iid in self.org_page.row_data:
                m = self.org_page.row_data[iid]
                m["checked"] = not m["checked"]
                self._org_set_row(iid)
                self._org_update_summary()
            return "break"
        return None

    def _org_double_click(self, event):
        if self.org_page.tree.identify_column(event.x) == "#1":
            return "break"
        self.org_page._reveal()
        return None

    def change_folder(self):
        sel = self.org_page.tree.selection()
        if not sel:
            self.toast("Sélectionne d'abord des lignes")
            return
        answer = simpledialog.askstring("Changer le dossier", "Nouveau dossier (ex. Cours/Réseaux) :", parent=self)
        if answer is None:
            return
        folder = organizer.sanitize_folder(answer)
        if not folder:
            messagebox.showerror("SHADOWSCAN", "Nom de dossier invalide.")
            return
        for iid in sel:
            m = self.org_page.row_data[iid]
            m["folder"], m["source"], m["checked"] = folder, "Manuel", True
            self._org_set_row(iid)
        self._org_update_summary()

    def apply_plan(self):
        chosen = [m for m in self.org_moves if m["checked"]]
        if not chosen or self.org_busy or self.org_root is None:
            return
        n_dirs = len({m["folder"] for m in chosen})
        if not messagebox.askyesno(
                "SHADOWSCAN", f"Déplacer {len(chosen)} fichier(s) vers {n_dirs} dossier(s) dans :\n{self.org_root}\n\n"
                              "Aucun fichier ne sera supprimé ni écrasé. Tu pourras annuler ensuite."):
            return
        self.org_busy = True
        self.org_stop.clear()
        self.org_state = {"done": 0, "total": len(chosen), "result": None}
        state, root = self.org_state, self.org_root
        journal_dir = Path(self.output_var.get()).expanduser().resolve() / "journals"
        self.org_apply_btn.configure(state="disabled")
        self.org_gen_btn.configure(state="disabled")
        self.org_status.configure(text="Déplacement en cours…", text_color=col("muted"))

        def on_progress(done, total):
            state["done"] = done

        def worker():
            try:
                state["result"] = ("ok", organizer.apply_moves(root, self.org_moves, journal_dir, None, on_progress))
            except Exception as exc:  # noqa: BLE001
                state["result"] = ("err", str(exc))

        threading.Thread(target=worker, daemon=True).start()
        self.after(150, self._poll_apply)

    def _poll_apply(self):
        st = self.org_state
        if st["result"] is None:
            self.org_progress.set(st["done"] / max(1, st["total"]))
            self.after(150, self._poll_apply)
            return
        self.org_busy = False
        self.org_gen_btn.configure(state="normal")
        if st["result"][0] == "err":
            self.org_status.configure(text="Échec du rangement.", text_color=col("danger"))
            messagebox.showerror("SHADOWSCAN", st["result"][1])
            self._org_update_summary()
            return
        res = st["result"][1]
        self.org_progress.set(1)
        self.org_moves = [m for m in self.org_moves if m["src"] not in res["moved_paths"]]
        self._org_fill()
        self.org_status.configure(text=f"{res['moved']} fichier(s) rangé(s). Journal : {res['journal']}",
                                  text_color=col("ok"))
        self.toast(f"{res['moved']} fichier(s) rangé(s)")
        if res["skipped"]:
            lines = "\n".join(f"{Path(p).name} : {why}" for p, why in res["skipped"][:12])
            messagebox.showwarning("SHADOWSCAN", f"{len(res['skipped'])} fichier(s) non déplacé(s) :\n{lines}")

    def undo_last(self):
        if self.org_busy:
            return
        journal_dir = Path(self.output_var.get()).expanduser().resolve() / "journals"
        path = organizer.latest_journal(journal_dir) if journal_dir.is_dir() else None
        if path is None:
            messagebox.showinfo("SHADOWSCAN", "Aucun rangement à annuler.")
            return
        if not messagebox.askyesno("SHADOWSCAN", f"Remettre les fichiers à leur place d'origine ?\n{path.name}"):
            return

        def run():
            res = organizer.undo_journal(path)
            self.org_moves = []
            self._org_fill()
            self.org_status.configure(text=f"{res['restored']} fichier(s) remis en place.", text_color=col("ok"))
            self.toast(f"{res['restored']} fichier(s) restauré(s)")
            if res["failed"]:
                lines = "\n".join(f"{Path(p).name} : {why}" for p, why in res["failed"][:12])
                messagebox.showwarning("SHADOWSCAN", f"{len(res['failed'])} fichier(s) non restauré(s) :\n{lines}")

        self.safe(run)

    # --- rapports ---
    def export_reports(self, silent=False):
        if not self.analysis:
            messagebox.showinfo("SHADOWSCAN", "Lance d'abord un scan.")
            return
        out = Path(self.output_var.get()).expanduser().resolve()
        try:
            write_reports(self.records, self.analysis, self.errors, out)
            self.refresh_report_rows()
            if not silent:
                self.toast("Rapports exportés")
        except OSError as exc:
            messagebox.showerror("SHADOWSCAN", f"Impossible d'écrire les rapports :\n{exc}")

    def refresh_report_rows(self):
        out = Path(self.output_var.get()).expanduser().resolve()
        for name, label in self.report_rows.items():
            f = out / name
            label.configure(text=f"{format_size(f.stat().st_size)}  ·  {f}" if f.is_file()
                            else "pas encore généré")

    def _open_report_dir(self):
        out = Path(self.output_var.get()).expanduser().resolve()
        if not out.is_dir():
            messagebox.showinfo("SHADOWSCAN", "Aucun rapport pour l'instant. Lance un scan.")
            return
        self.safe(lambda: open_in_system(out))

    def _open_report(self, name):
        p = Path(self.output_var.get()).expanduser().resolve() / name
        if not p.is_file():
            messagebox.showinfo("SHADOWSCAN", f"{name} n'existe pas encore. Lance un scan.")
            return
        self.safe(lambda: open_in_system(p))


def launch_gui(folder: str, output: str, calculate_hash: bool = True, autoscan: bool = False) -> None:
    app = ShadowScanApp(folder, output, calculate_hash, autoscan)
    app.mainloop()
