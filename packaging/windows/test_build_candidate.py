"""Pinned Tauri NSIS payload provenance contracts, without Windows tools."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from build_candidate import file_record, packaged_desktop_record


class DesktopPayloadTests(unittest.TestCase):
    def test_nsis_hash_matches_installed_marker_and_keeps_compiler_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "desktop.exe"
            compiled = b"MZfixture\x00__TAURI_BUNDLE_TYPE_VAR_UNK\x00fixture-end"
            installed = b"MZfixture\x00__TAURI_BUNDLE_TYPE_VAR_NSS\x00fixture-end"
            path.write_bytes(compiled)
            record = packaged_desktop_record(path)
            self.assertEqual(record["sha256"], hashlib.sha256(installed).hexdigest())
            self.assertEqual(record["size"], len(installed))
            self.assertNotEqual(record["sha256"], file_record(path)["sha256"])
            self.assertEqual(path.read_bytes(), compiled)

    def test_changed_or_ambiguous_bundler_contract_cannot_publish_a_prediction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "desktop.exe"
            for payload in (b"MZ__TAURI_BUNDLE_TYPE_VAR_NSS", b"MZunknown-bundler",
                            b"__TAURI_BUNDLE_TYPE_VAR_UNK" * 2):
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    with self.assertRaises(ValueError):
                        packaged_desktop_record(path)


if __name__ == "__main__":
    unittest.main()
