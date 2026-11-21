# Python 3.10+ | Windows 11 | SHADOWSCAN CLI
from pathlib import Path
import argparse
from src.scanner import scan_directory
from src.analyzer import analyze_files
from src.reporter import write_reports

def main():
    parser = argparse.ArgumentParser(
        prog="SHADOWSCAN",
        description="Local filesystem inventory, duplicate detection and anomaly reporting."
    )
    parser.add_argument("--folder", default=str(Path.home() / "Downloads"),
                        help="Directory to scan (default: Downloads).")
    parser.add_argument("--output", default="reports",
                        help="Report directory (default: ./reports).")
    parser.add_argument("--no-hash", action="store_true",
                        help="Skip SHA-256 hashing; duplicate detection will be unavailable.")
    args = parser.parse_args()

    root = Path(args.folder).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        parser.error(f"Directory does not exist or is not a directory: {root}")

    print(f"Scanning: {root}")
    records, errors = scan_directory(root, calculate_hash=not args.no_hash)
    analysis = analyze_files(records)
    output = Path(args.output).expanduser().resolve()
    write_reports(records, analysis, errors, output)

    print("\nSHADOWSCAN completed")
    print(f"Files scanned: {len(records)}")
    print(f"Total size: {analysis['total_size']:,} bytes")
    print(f"Duplicate groups: {len(analysis['duplicate_groups'])}")
    print(f"Suspicious filenames: {len(analysis['suspicious_files'])}")
    print(f"Scan errors: {len(errors)}")
    print(f"Reports: {output}")

if __name__ == "__main__":
    main()
