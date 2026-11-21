from pathlib import Path
from datetime import datetime, timezone
import hashlib

CHUNK_SIZE = 1024 * 1024

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()

def classify_file(path: Path) -> str:
    extension = path.suffix.lower()
    categories = {
        "Documents": {".pdf", ".doc", ".docx", ".txt", ".odt", ".rtf"},
        "Images": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"},
        "Videos": {".mp4", ".mkv", ".avi", ".mov", ".webm"},
        "Audio": {".mp3", ".wav", ".flac", ".ogg", ".m4a"},
        "Archives": {".zip", ".rar", ".7z", ".tar", ".gz"},
        "Executables": {".exe", ".msi", ".bat", ".cmd", ".ps1", ".scr"},
        "Code": {".py", ".cpp", ".c", ".h", ".hpp", ".js", ".ts", ".html", ".css", ".java"},
        "Spreadsheets": {".xlsx", ".xls", ".csv", ".ods"},
    }
    for category, extensions in categories.items():
        if extension in extensions:
            return category
    return "Other"

def scan_directory(root: Path, calculate_hash: bool = True, progress=None, stop_event=None):
    """progress(record_or_None, path) est appelé après chaque fichier (None = erreur).
    stop_event (threading.Event) permet d'annuler. Les deux sont optionnels (CLI inchangée)."""
    records = []
    errors = []
    root = root.resolve()
    for path in root.rglob("*"):
        if stop_event is not None and stop_event.is_set():
            break
        try:
            if path.is_symlink() or not path.is_file():
                continue
            stat = path.stat()
            record = {
                "path": str(path.resolve()),
                "name": path.name,
                "extension": path.suffix.lower(),
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "category": classify_file(path),
                "sha256": sha256_file(path) if calculate_hash else "",
            }
            records.append(record)
            if progress:
                progress(record, str(path))
        except (OSError, PermissionError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
            if progress:
                progress(None, str(path))
    return records, errors
