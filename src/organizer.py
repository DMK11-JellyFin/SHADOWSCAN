# Python 3.10+ | SHADOWSCAN - rangement assisté par une IA locale (Ollama).
# Garanties : aucune suppression, aucun écrasement, tout rangement est journalisé et annulable.
# Aucune dépendance externe (urllib uniquement). L'IA ne reçoit que les noms, tailles et extensions.
from __future__ import annotations

import json
import os
import re
import shutil
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from src.scanner import classify_file

DEFAULT_URL = "http://localhost:11434"
SUSPECT_FOLDER = "À vérifier"
JOURNAL_PREFIX = "move_journal_"

# Dossiers de projets / environnements : on n'y touche jamais.
PROTECTED_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", "venv", ".venv", "site-packages",
                  ".idea", ".vscode", "$recycle.bin", "system volume information"}
SKIP_NAMES = {"desktop.ini", "thumbs.db", ".ds_store"}
SKIP_PREFIXES = ("ntuser", "~$")
PARTIAL_EXT = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload"}
EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".msi", ".com", ".vbs"}
DOC_LIKE_EXT = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".xls", ".xlsx", ".zip", ".mp3", ".mp4"}

# Dossiers par défaut (règles), utilisés seuls ou comme suggestion donnée à l'IA.
CATEGORY_FOLDERS = {"Documents": "Documents", "Images": "Images", "Videos": "Vidéos", "Audio": "Musique",
                    "Archives": "Archives", "Executables": "Programmes", "Code": "Code",
                    "Spreadsheets": "Tableurs", "Other": "Divers"}
EXTRA_EXT_FOLDERS = {".pptx": "Présentations", ".ppt": "Présentations", ".odp": "Présentations",
                     ".iso": "Archives", ".apk": "Programmes", ".ipynb": "Code", ".sql": "Code",
                     ".ttf": "Polices", ".otf": "Polices", ".lnk": "Raccourcis", ".torrent": "Divers",
                     ".epub": "Documents", ".md": "Documents"}
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
PROTECTED_ROOT_NAMES = {"windows", "program files", "program files (x86)", "programdata", "appdata", "system32"}


# ---------- Utilitaires purs ----------
def sanitize_folder(name: str, max_levels: int = 2) -> str | None:
    """Nettoie un nom de dossier proposé (par l'IA ou l'utilisateur). Renvoie un chemin relatif sûr ou None."""
    if not isinstance(name, str):
        return None
    parts = []
    for raw in re.split(r"[\\/]+", name.strip()):
        part = re.sub(r'[<>:"|?*\x00-\x1f]', "", raw).strip().rstrip(". ")
        if not part or part in {".", ".."}:
            continue
        if part.lower() in WINDOWS_RESERVED:
            part = part + "_"
        parts.append(part[:40])
    if not parts:
        return None
    return "/".join(parts[:max_levels])


def is_protected_root(root: Path) -> str | None:
    """Renvoie une raison si le dossier ne doit pas être rangé automatiquement."""
    root = root.resolve()
    if root.parent == root:
        return "C'est la racine d'un disque."
    if any(part.lower() in PROTECTED_ROOT_NAMES for part in root.parts[1:]):
        return "C'est un dossier système."
    return None


def is_suspect(name: str) -> bool:
    suffixes = [s.lower() for s in Path(name).suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in EXEC_EXT and suffixes[-2] in DOC_LIKE_EXT


def skip_reason(name: str) -> str | None:
    low = name.lower()
    if name.startswith(".") or low in SKIP_NAMES or low.startswith(SKIP_PREFIXES):
        return "fichier caché ou système"
    if Path(low).suffix in PARTIAL_EXT:
        return "téléchargement en cours"
    return None


def rule_folder(rec: dict) -> str:
    ext = rec.get("extension", "")
    if ext in EXTRA_EXT_FOLDERS:
        return EXTRA_EXT_FOLDERS[ext]
    return CATEGORY_FOLDERS.get(rec.get("category", "Other"), "Divers")


def list_files(root: Path, recursive: bool = False, exclude=()) -> list[dict]:
    """Liste les fichiers à ranger (niveau 1 par défaut). Ignore liens, fichiers cachés et dossiers protégés."""
    root = root.resolve()
    excluded = [Path(e).resolve() for e in exclude]
    out = []

    def add(path: Path):
        try:
            if path.is_symlink() or not path.is_file() or skip_reason(path.name):
                return
            out.append({"path": str(path), "name": path.name, "extension": path.suffix.lower(),
                        "size_bytes": path.stat().st_size, "category": classify_file(path)})
        except OSError:
            pass

    if not recursive:
        try:
            for entry in os.scandir(root):
                add(Path(entry.path))
        except OSError:
            pass
        return sorted(out, key=lambda r: r["name"].lower())

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in PROTECTED_DIRS and not d.startswith(".")
                       and not any((here / d).resolve() == e or e in (here / d).resolve().parents for e in excluded)]
        for fn in filenames:
            add(here / fn)
    return sorted(out, key=lambda r: r["path"].lower())


def unique_path(directory: Path, name: str, reserved: set | None = None) -> Path:
    """Chemin libre dans `directory` : ajoute (1), (2)… au besoin. N'écrase jamais."""
    reserved = reserved if reserved is not None else set()
    stem, suffix = Path(name).stem, Path(name).suffix
    candidate, n = directory / name, 1
    while candidate.exists() or str(candidate).lower() in reserved:
        candidate = directory / f"{stem} ({n}){suffix}"
        n += 1
    reserved.add(str(candidate).lower())
    return candidate


# ---------- Ollama ----------
def _http_json(url: str, payload: dict | None, timeout: float):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL locale choisie par l'utilisateur)
        return json.loads(resp.read().decode("utf-8"))


def list_models(base_url: str = DEFAULT_URL, timeout: float = 3.0) -> list[str]:
    """Noms des modèles installés dans Ollama. Lève OSError / ValueError si Ollama est injoignable."""
    data = _http_json(base_url.rstrip("/") + "/api/tags", None, timeout)
    return sorted(m["name"] for m in data.get("models", []))


SYSTEM_PROMPT = (
    "Tu ranges des fichiers dans des dossiers. Pour chaque fichier tu reçois un id, son nom, sa taille et un "
    "dossier par défaut.\n"
    'Réponds UNIQUEMENT avec un objet JSON : {"moves":[{"id":0,"folder":"Cours/Réseaux"}]} avec une entrée par id.\n'
    "Règles :\n"
    "- Garde le dossier par défaut, sauf si le nom indique clairement un meilleur dossier "
    "(facture, CV, TP de réseaux, photos de voyage, etc.).\n"
    '- 1 ou 2 niveaux maximum séparés par "/". Noms courts, en français, sans caractères spéciaux.\n'
    "- Réutilise en priorité les dossiers déjà utilisés.\n"
    "- Ne renomme jamais un fichier et ne propose jamais de supprimer quoi que ce soit."
)


def _parse_moves(content: str) -> dict[int, str]:
    content = re.sub(r"<think>.*?</think>", "", content or "", flags=re.S)
    match = re.search(r"\{.*\}|\[.*\]", content, flags=re.S)
    if not match:
        raise ValueError("réponse sans JSON")
    data = json.loads(match.group(0))
    items = data.get("moves", data) if isinstance(data, dict) else data
    result: dict[int, str] = {}
    if isinstance(items, dict):  # forme {"0": "Docs", ...}
        for k, v in items.items():
            if str(k).lstrip("-").isdigit() and isinstance(v, str):
                result[int(k)] = v
    elif isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and "id" in it and isinstance(it.get("folder"), str):
                try:
                    result[int(it["id"])] = it["folder"]
                except (TypeError, ValueError):
                    pass
    return result


def ai_assign(records: list[dict], defaults: dict[str, str], model: str, base_url: str = DEFAULT_URL,
              stop_event=None, progress=None, batch_size: int = 20, timeout: float = 240.0):
    """Demande à Ollama un dossier par fichier. Renvoie ({path: dossier}, [avertissements])."""
    assigned: dict[str, str] = {}
    warnings: list[str] = []
    used: dict[str, str] = {}  # minuscule -> forme canonique, pour des noms de dossiers cohérents
    for d in defaults.values():
        used.setdefault(d.lower(), d)
    url = base_url.rstrip("/") + "/api/chat"
    bad_batches = 0
    for start in range(0, len(records), batch_size):
        if stop_event is not None and stop_event.is_set():
            break
        batch = records[start:start + batch_size]
        items = [{"id": i, "name": r["name"], "size_ko": r["size_bytes"] // 1024, "default": defaults[r["path"]]}
                 for i, r in enumerate(batch)]
        user = ("Dossiers déjà utilisés : " + json.dumps(sorted(set(used.values())), ensure_ascii=False)
                + "\nFichiers :\n" + "\n".join(json.dumps(it, ensure_ascii=False) for it in items))
        payload = {"model": model, "stream": False, "format": "json", "keep_alive": "10m",
                   "options": {"temperature": 0, "num_ctx": 4096},
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]}
        try:
            reply = _http_json(url, payload, timeout)
            moves = _parse_moves(reply.get("message", {}).get("content", ""))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            warnings.append(f"IA injoignable ({getattr(exc, 'reason', exc)}). Règles utilisées pour la suite.")
            break
        except (ValueError, KeyError, AttributeError) as exc:
            bad_batches += 1
            warnings.append(f"Réponse inexploitable de l'IA pour un lot ({exc}). Règles utilisées pour ce lot.")
            moves = {}
        for i, folder in moves.items():
            if 0 <= i < len(batch):
                clean = sanitize_folder(folder)
                if clean:
                    clean = "/".join(used.setdefault(p.lower(), p) for p in clean.split("/"))
                    assigned[batch[i]["path"]] = clean
        if progress:
            progress(min(start + batch_size, len(records)), len(records))
        if bad_batches >= 3:
            warnings.append("Trop de réponses inexploitables : essaie un modèle plus gros.")
            break
    return assigned, warnings


# ---------- Plan ----------
def build_plan(root: Path, records: list[dict], use_ai: bool = True, model: str = "", base_url: str = DEFAULT_URL,
               stop_event=None, progress=None):
    """Construit la liste des déplacements proposés. Renvoie (moves, warnings)."""
    root = root.resolve()
    defaults, ai_targets = {}, []
    for rec in records:
        if is_suspect(rec["name"]):
            defaults[rec["path"]] = SUSPECT_FOLDER  # jamais envoyé à l'IA
        else:
            defaults[rec["path"]] = rule_folder(rec)
            ai_targets.append(rec)
    assigned, warnings = {}, []
    if use_ai and model and ai_targets:
        assigned, warnings = ai_assign(ai_targets, defaults, model, base_url, stop_event, progress)
    moves = []
    for rec in records:
        folder = assigned.get(rec["path"], defaults[rec["path"]])
        source = "IA" if rec["path"] in assigned else "Règle"
        if Path(rec["path"]).parent.resolve() == (root / folder).resolve():
            continue  # déjà au bon endroit
        moves.append({"src": rec["path"], "name": rec["name"], "size": rec["size_bytes"], "folder": folder,
                      "source": source, "checked": True})
    return moves, warnings


# ---------- Application et annulation ----------
def _write_journal(path: Path, journal: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(journal, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def apply_moves(root: Path, moves: list[dict], journal_dir: Path, stop_event=None, progress=None) -> dict:
    """Déplace les fichiers cochés. Ne supprime ni n'écrase rien. Écrit un journal pour l'annulation."""
    root = root.resolve()
    journal_dir.mkdir(parents=True, exist_ok=True)
    jpath = journal_dir / f"{JOURNAL_PREFIX}{datetime.now():%Y%m%d_%H%M%S}.json"
    journal = {"version": 1, "root": str(root), "created_at": datetime.now().isoformat(timespec="seconds"),
               "moves": [], "created_dirs": [], "undone": False}
    skipped, reserved = [], set()
    todo = [m for m in moves if m.get("checked")]
    try:
        for i, m in enumerate(todo, 1):
            if stop_event is not None and stop_event.is_set():
                break
            src = Path(m["src"])
            try:
                folder = sanitize_folder(m["folder"])
                if not folder:
                    raise OSError("nom de dossier invalide")
                dest_dir = (root / folder).resolve()
                if root != dest_dir and root not in dest_dir.parents:
                    raise OSError("destination hors du dossier choisi")
                if src.is_symlink() or not src.is_file():
                    raise OSError("fichier introuvable")
                for d in reversed([dest_dir, *dest_dir.parents][: len(dest_dir.parts) - len(root.parts)]):
                    if not d.exists():
                        d.mkdir()
                        journal["created_dirs"].append(str(d))
                dest = unique_path(dest_dir, src.name, reserved)
                shutil.move(str(src), str(dest))
                journal["moves"].append({"from": str(src), "to": str(dest)})
            except OSError as exc:
                skipped.append((str(src), str(exc)))
            if progress:
                progress(i, len(todo))
            if i % 25 == 0:
                _write_journal(jpath, journal)
    finally:
        _write_journal(jpath, journal)
    return {"moved": len(journal["moves"]), "skipped": skipped, "journal": str(jpath),
            "moved_paths": {e["from"] for e in journal["moves"]}}


def latest_journal(journal_dir: Path) -> Path | None:
    for p in sorted(journal_dir.glob(f"{JOURNAL_PREFIX}*.json"), reverse=True):
        try:
            if not json.loads(p.read_text(encoding="utf-8")).get("undone"):
                return p
        except (OSError, ValueError):
            continue
    return None


def undo_journal(path: Path) -> dict:
    """Remet chaque fichier à son emplacement d'origine (ordre inverse) puis retire les dossiers vides créés."""
    journal = json.loads(path.read_text(encoding="utf-8"))
    restored, remaining = 0, []
    for entry in reversed(journal["moves"]):
        src, dest = Path(entry["from"]), Path(entry["to"])
        try:
            if not dest.is_file():
                raise OSError("fichier déplacé ou renommé depuis")
            if src.exists():
                raise OSError("l'emplacement d'origine est occupé")
            src.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(dest), str(src))
            restored += 1
        except OSError as exc:
            remaining.append({**entry, "reason": str(exc)})
    for d in reversed(journal.get("created_dirs", [])):
        try:
            os.rmdir(d)  # ne réussit que si le dossier est vide
        except OSError:
            pass
    journal["moves"] = list(reversed([{k: v for k, v in e.items() if k != "reason"} for e in remaining]))
    journal["undone"] = not remaining
    _write_journal(path, journal)
    return {"restored": restored, "failed": [(e["to"], e["reason"]) for e in remaining]}
