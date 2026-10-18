"""Offline contract tests for the Windows runtime stager."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).with_name("stage_runtime.py")
SPEC = importlib.util.spec_from_file_location("stage_runtime_under_test", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
stage_runtime_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_runtime_module)


def make_pe(machine: int = 0x8664) -> bytes:
    """Create a small PE header sufficient to test architecture validation."""
    image = bytearray(128)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 64)
    image[64:68] = b"PE\0\0"
    struct.pack_into("<H", image, 68, machine)
    return bytes(image)


class StageRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="runtime-stager-test-")
        self.root = Path(self.temp.name)
        self.output_root = self.root / "out"
        self.adapter_path = self.root / "adapter-agent.exe"
        self.adapter_path.write_bytes(make_pe())
        self.manifest_path = self.root / "mihomo-compatibility.json"
        self.archive_path = self.root / "mihomo.zip"
        self.asset_name = "mihomo-windows-amd64-compatible-v0.0.1.zip"
        self.member_name = "mihomo-windows-amd64-compatible.exe"
        self.engine = make_pe()
        self._write_archive([(self.member_name, self.engine, None)])
        self._write_compatibility_manifest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _zip_bytes(self, entries: list[tuple[str, bytes, int | None]]) -> bytes:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data, unix_mode in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                if unix_mode is not None:
                    info.create_system = 3
                    info.external_attr = unix_mode << 16
                archive.writestr(info, data)
        return stream.getvalue()

    def _write_archive(self, entries: list[tuple[str, bytes, int | None]]) -> bytes:
        content = self._zip_bytes(entries)
        self.archive_path.write_bytes(content)
        return content

    def _write_compatibility_manifest(self, *, digest: str | None = None) -> None:
        archive_bytes = self.archive_path.read_bytes()
        data = {
            "schema": 1,
            "version": "v0.0.1",
            "repository": "https://github.com/MetaCubeX/mihomo",
            "source_tag": "https://github.com/MetaCubeX/mihomo/tree/v0.0.1",
            "license": "GPL-3.0",
            "license_url": "https://github.com/MetaCubeX/mihomo/blob/v0.0.1/LICENSE",
            "assets": {
                "windows": {
                    "name": self.asset_name,
                    "bytes": len(archive_bytes),
                    "sha256": digest or hashlib.sha256(archive_bytes).hexdigest(),
                }
            },
        }
        self.manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def _stage(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "adapter_agent": self.adapter_path,
            "output_root": self.output_root,
            "source_sha": "a" * 40,
            "version": "0.1.0",
            "mihomo_archive": self.archive_path,
            "compatibility_manifest": self.manifest_path,
        }
        arguments.update(overrides)
        return stage_runtime_module.stage_runtime(**arguments)

    def _assert_failed_cleanly(self, message_fragment: str, **overrides: object) -> None:
        with self.assertRaises(stage_runtime_module.StageRuntimeError) as error:
            self._stage(**overrides)
        self.assertIn(message_fragment, str(error.exception))
        self.assertFalse((self.output_root / "runtime").exists())
        if self.output_root.exists():
            self.assertEqual(list(self.output_root.glob(".runtime-stage-*")), [])

    def test_offline_stage_publishes_verified_complete_runtime(self) -> None:
        source_manifest_bytes = self.manifest_path.read_bytes()
        result = self._stage()
        runtime = self.output_root / "runtime"

        self.assertEqual(
            {path.name for path in runtime.iterdir()},
            {
                "adapter-agent.exe",
                "mihomo.exe",
                "mihomo-compatibility.json",
                "THIRD_PARTY_NOTICES.txt",
                "manifest.json",
            },
        )
        self.assertEqual((runtime / "mihomo-compatibility.json").read_bytes(), source_manifest_bytes)
        self.assertEqual(result["source_sha"], "a" * 40)
        self.assertEqual(result["version"], "0.1.0")
        self.assertEqual(result["platform"], "windows")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertEqual(result["signature"], "NOT_RUN")

        file_records = result["files"]
        self.assertEqual(set(file_records), {
            "adapter-agent.exe",
            "mihomo.exe",
            "mihomo-compatibility.json",
            "THIRD_PARTY_NOTICES.txt",
        })
        for name, record in file_records.items():
            content = (runtime / name).read_bytes()
            self.assertEqual(record["size_bytes"], len(content))
            self.assertEqual(record["sha256"], hashlib.sha256(content).hexdigest())

        notices = (runtime / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn("Version: v0.0.1", notices)
        self.assertIn("License: GPL-3.0", notices)
        self.assertIn("https://github.com/MetaCubeX/mihomo/tree/v0.0.1", notices)
        manifest_text = (runtime / "manifest.json").read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), manifest_text)

    def test_bad_pinned_digest_rejects_archive_without_publishing(self) -> None:
        self._write_compatibility_manifest(digest="0" * 64)
        self._assert_failed_cleanly("SHA256 does not match")

    def test_published_runtime_is_not_failed_by_cleanup_of_its_old_name(self) -> None:
        # Reproduce the Windows missing-path cleanup failure after atomic rename.
        # Once publication succeeds, deleting the original name is unnecessary.
        with mock.patch.object(
            stage_runtime_module.shutil,
            "rmtree",
            side_effect=FileNotFoundError(2, "staging name was renamed"),
        ):
            result = self._stage()
        runtime = self.output_root / "runtime"
        self.assertEqual(result["source_sha"], "a" * 40)
        self.assertTrue((runtime / "adapter-agent.exe").is_file())
        self.assertTrue((runtime / "mihomo.exe").is_file())
        self.assertEqual(list(self.output_root.glob(".runtime-stage-*")), [])

    def test_traversal_zip_entry_is_rejected_after_archive_verification(self) -> None:
        self._write_archive([("../mihomo-windows-amd64-compatible.exe", self.engine, None)])
        self._write_compatibility_manifest()
        self._assert_failed_cleanly("entry name is not the expected flat executable")

    def test_extra_zip_entry_is_rejected(self) -> None:
        self._write_archive(
            [
                (self.member_name, self.engine, None),
                ("README.txt", b"extra", None),
            ]
        )
        self._write_compatibility_manifest()
        self._assert_failed_cleanly("exactly one file")

    def test_symlink_zip_entry_is_rejected(self) -> None:
        self._write_archive([(self.member_name, self.engine, 0o120777)])
        self._write_compatibility_manifest()
        self._assert_failed_cleanly("not a regular file")

    def test_non_amd64_adapter_pe_is_rejected(self) -> None:
        self.adapter_path.write_bytes(make_pe(machine=0x014C))
        self._assert_failed_cleanly("Adapter agent is not an x64")

    def test_non_amd64_engine_pe_is_rejected(self) -> None:
        self._write_archive([(self.member_name, make_pe(machine=0x014C), None)])
        self._write_compatibility_manifest()
        self._assert_failed_cleanly("Mihomo engine is not an x64")

    def test_invalid_source_sha_is_rejected(self) -> None:
        self._assert_failed_cleanly("40-character", source_sha="abc")

    def test_existing_runtime_destination_is_never_overwritten(self) -> None:
        runtime = self.output_root / "runtime"
        runtime.mkdir(parents=True)
        sentinel = runtime / "keep.txt"
        sentinel.write_text("existing", encoding="utf-8")
        with self.assertRaises(stage_runtime_module.StageRuntimeError) as error:
            self._stage()
        self.assertIn("already exists", str(error.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output_root.glob(".runtime-stage-*")), [])

    def test_destination_created_at_publish_time_is_not_replaced(self) -> None:
        original_publish = stage_runtime_module._rename_noreplace
        sentinel = self.output_root / "runtime" / "keep.txt"

        def race_with_existing_destination(source: Path, destination: Path) -> None:
            destination.mkdir()
            (destination / "keep.txt").write_text("existing", encoding="utf-8")
            original_publish(source, destination)

        with mock.patch.object(
            stage_runtime_module,
            "_rename_noreplace",
            side_effect=race_with_existing_destination,
        ):
            with self.assertRaises(stage_runtime_module.StageRuntimeError) as error:
                self._stage()
        self.assertIn("already exists", str(error.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output_root.glob(".runtime-stage-*")), [])

    def test_archive_byte_count_is_checked_even_when_digest_matches(self) -> None:
        self._write_compatibility_manifest()
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        data["assets"]["windows"]["bytes"] += 1
        self.manifest_path.write_text(json.dumps(data), encoding="utf-8")
        self._assert_failed_cleanly("size does not match the pinned size")

    def test_download_redirect_policy_rejects_http(self) -> None:
        handler = stage_runtime_module._HttpsOnlyRedirectHandler()
        request = stage_runtime_module.urllib.request.Request(
            "https://github.com/MetaCubeX/mihomo/releases/download/v0.0.1/asset.zip"
        )
        with self.assertRaises(stage_runtime_module.StageRuntimeError) as error:
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.test/asset.zip")
        self.assertIn("did not use HTTPS", str(error.exception))


if __name__ == "__main__":
    unittest.main()
