# Python 3.10+ | SHADOWSCAN file analysis
from collections import defaultdict

SUSPICIOUS_INNER_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".txt", ".xls", ".xlsx"
}
DANGEROUS_OUTER_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js"}

def is_suspicious_filename(filename: str) -> bool:
    from pathlib import Path
    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
    return (
        len(suffixes) >= 2
        and suffixes[-2] in SUSPICIOUS_INNER_EXTENSIONS
        and suffixes[-1] in DANGEROUS_OUTER_EXTENSIONS
    )

def analyze_files(records):
    category_sizes = defaultdict(int)
    duplicate_index = defaultdict(list)
    suspicious_files = []
    total_size = 0

    for record in records:
        size = record["size_bytes"]
        total_size += size
        category_sizes[record["category"]] += size

        digest = record.get("sha256")
        if digest:
            duplicate_index[digest].append(record["path"])

        if is_suspicious_filename(record["name"]):
            suspicious_files.append(record)

    duplicate_groups = [
        {"sha256": digest, "paths": paths}
        for digest, paths in duplicate_index.items()
        if len(paths) > 1
    ]

    return {
        "total_size": total_size,
        "category_sizes": dict(sorted(category_sizes.items())),
        "duplicate_groups": duplicate_groups,
        "suspicious_files": suspicious_files,
    }
