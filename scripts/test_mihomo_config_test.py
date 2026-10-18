import gzip
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("parser_gate", Path(__file__).with_name("test-mihomo-config.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ArchiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.original = gate.MAX_BINARY
        gate.MAX_BINARY = 32

    def tearDown(self):
        gate.MAX_BINARY = self.original

    def archive(self, entries):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            for name, value in entries:
                archive.writestr(name, value)
        return data.getvalue()

    def test_gzip_size_boundary(self):
        self.assertEqual(gate.unpack(gzip.compress(b"x" * 32), "linux"), b"x" * 32)
        for value in [b"", b"x" * 33]:
            with self.assertRaises(ValueError):
                gate.unpack(gzip.compress(value), "linux")

    def test_zip_accepts_one_flat_executable(self):
        self.assertEqual(gate.unpack(self.archive([("mihomo.exe", b"fixture")]), "windows"), b"fixture")

    def test_zip_rejects_traversal_or_nested_paths(self):
        for name in ["../mihomo.exe", "nested/mihomo.exe", "nested\\mihomo.exe"]:
            with self.assertRaises(ValueError):
                gate.unpack(self.archive([(name, b"fixture")]), "windows")

    def test_zip_rejects_zero_multiple_and_oversize_executables(self):
        for entries in [[], [("a.exe", b"a"), ("b.exe", b"b")], [("a.exe", b"x" * 33)]]:
            with self.assertRaises(ValueError):
                gate.unpack(self.archive(entries), "windows")

    def test_corrupt_archives_are_not_executed(self):
        for kind in ["windows", "linux"]:
            with self.assertRaises((ValueError, OSError, zipfile.BadZipFile)):
                gate.unpack(b"not an archive", kind)


class LifecycleDiagnosticsTests(unittest.TestCase):
    def test_failure_exposes_mode_and_bounded_stderr_only(self):
        failure = gate.subprocess.CalledProcessError(
            101, ["synthetic"], output=b"discarded stdout",
            stderr=b"discarded-prefix" + b"x" * 9000 + b"startup: Deadline")
        with patch.object(gate.subprocess, "run", side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                gate.run_lifecycle(Path("fixture"), Path("binary"), ["--occupy-mixed"], {})
        message = str(caught.exception)
        self.assertIn("--occupy-mixed failed", message)
        self.assertIn("startup: Deadline", message)
        self.assertNotIn("discarded", message)
        self.assertLess(len(message), 8300)

    def test_timeout_and_missing_stderr_remain_failures(self):
        for stderr in (None, b"fixture timeout"):
            failure = gate.subprocess.TimeoutExpired(["synthetic"], 50, stderr=stderr)
            with patch.object(gate.subprocess, "run", side_effect=failure):
                with self.assertRaisesRegex(RuntimeError, "synthetic lifecycle normal failed"):
                    gate.run_lifecycle(Path("fixture"), Path("binary"), [], {})


if __name__ == "__main__":
    unittest.main()
