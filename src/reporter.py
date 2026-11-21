# Python 3.10+ | SHADOWSCAN report writer
from pathlib import Path
import csv
import json

def _write_csv(path: Path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def write_reports(records, analysis, errors, output: Path):
    output.mkdir(parents=True, exist_ok=True)

    inventory_fields = [
        "path", "name", "extension", "size_bytes",
        "modified_utc", "category", "sha256"
    ]
    _write_csv(output / "inventory.csv", inventory_fields, records)

    duplicate_rows = [
        {"sha256": group["sha256"], "paths": " | ".join(group["paths"])}
        for group in analysis["duplicate_groups"]
    ]
    _write_csv(output / "duplicates.csv", ["sha256", "paths"], duplicate_rows)

    suspicious_rows = [
        {key: record[key] for key in inventory_fields}
        for record in analysis["suspicious_files"]
    ]
    _write_csv(output / "suspicious_files.csv", inventory_fields, suspicious_rows)

    _write_csv(output / "scan_errors.csv", ["path", "error"], errors)

    summary = {
        "files_scanned": len(records),
        "total_size_bytes": analysis["total_size"],
        "category_sizes_bytes": analysis["category_sizes"],
        "duplicate_group_count": len(analysis["duplicate_groups"]),
        "suspicious_file_count": len(analysis["suspicious_files"]),
        "scan_error_count": len(errors),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
