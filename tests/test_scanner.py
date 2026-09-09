import tempfile
import unittest
from pathlib import Path

from securitydiag_core.scanner import bounded_text_status


class ScannerCoverageTests(unittest.TestCase):
    def test_large_obvious_binary_is_not_reported_as_oversized_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asset.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00" + b"A" * 4096)
            text, reason = bounded_text_status(path, max_bytes=128)
            self.assertIsNone(text)
            self.assertEqual(reason, "binary")

    def test_large_text_remains_coverage_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.env.txt"
            path.write_text("DJANGO_SECRET_KEY=" + "A" * 4096, encoding="utf-8")
            text, reason = bounded_text_status(path, max_bytes=128)
            self.assertIsNone(text)
            self.assertEqual(reason, "too_large")

    def test_small_text_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.txt"
            path.write_text("hello world", encoding="utf-8")
            text, reason = bounded_text_status(path, max_bytes=128)
            self.assertEqual(text, "hello world")
            self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
