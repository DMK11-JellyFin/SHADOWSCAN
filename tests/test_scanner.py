# Python 3.10+ | SHADOWSCAN unit tests
import tempfile
import unittest
from pathlib import Path

from src.scanner import scan_directory, classify_file
from src.analyzer import analyze_files, is_suspicious_filename

class ScannerTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_file(Path("report.PDF")), "Documents")
        self.assertEqual(classify_file(Path("script.py")), "Code")
        self.assertEqual(classify_file(Path("unknown.xyz")), "Other")

    def test_scan_and_duplicate_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("same content", encoding="utf-8")
            (root / "b.txt").write_text("same content", encoding="utf-8")
            records, errors = scan_directory(root)
            result = analyze_files(records)
            self.assertEqual(len(records), 2)
            self.assertEqual(errors, [])
            self.assertEqual(len(result["duplicate_groups"]), 1)

    def test_suspicious_double_extension(self):
        self.assertTrue(is_suspicious_filename("invoice.pdf.exe"))
        self.assertFalse(is_suspicious_filename("invoice.pdf"))

if __name__ == "__main__":
    unittest.main()
