# SHADOWSCAN

Local filesystem inventory and analysis tool written in Python. SHADOWSCAN scans a directory, classifies files, calculates SHA-256 hashes, detects byte-identical files, flags selected double-extension filenames, and exports CSV/JSON reports.

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Usage

```powershell
py main.py
py main.py --folder "D:\"
py main.py --folder "C:\Users\YourName\Downloads" --output "reports"
py main.py --folder "D:\Archive" --no-hash
```

`--no-hash` skips SHA-256 calculation and therefore disables duplicate detection.

## Reports

The output directory contains:

- `inventory.csv`: one row per scanned file
- `duplicates.csv`: groups of files with identical SHA-256 hashes
- `suspicious_files.csv`: selected double-extension filenames
- `scan_errors.csv`: files that could not be inspected
- `summary.json`: aggregate counts and storage by category

## Tests

```powershell
py -m unittest discover -s tests -v
```

## Notes

- The scanner does not modify, move, rename, or delete scanned files.
- Symlinks are skipped.
- A suspicious filename is a heuristic, not proof that a file is malicious.
- SHA-256 duplicate detection compares file contents, not filenames.
