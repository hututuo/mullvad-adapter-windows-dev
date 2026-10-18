#!/usr/bin/env python3
"""Stage a verified Windows x64 runtime payload for a later installer build.

This script only assembles files. It does not build or validate a Tauri/NSIS
installer, install anything, or establish runtime compatibility.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


DEFAULT_COMPATIBILITY_MANIFEST = (
    Path(__file__).resolve().parents[2] / "engines" / "mihomo-compatibility.json"
)

MAX_COMPATIBILITY_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ADAPTER_BYTES = 256 * 1024 * 1024
MAX_ENGINE_BYTES = 128 * 1024 * 1024
MAX_PE_HEADER_OFFSET = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 10
DOWNLOAD_DEADLINE_SECONDS = 90
COPY_CHUNK_BYTES = 64 * 1024
AMD64_PE_MACHINE = 0x8664

_HEX_256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SAFE_ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.zip$")


class StageRuntimeError(Exception):
    """Expected staging failure with a path- and credential-free message."""


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        target = urllib.parse.urljoin(request.full_url, new_url)
        if urllib.parse.urlsplit(target).scheme.lower() != "https":
            raise StageRuntimeError("Mihomo download redirect did not use HTTPS")
        return super().redirect_request(request, response, code, message, headers, target)


def _safe_regular_file(path: Path, *, max_bytes: int, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise StageRuntimeError(f"Cannot inspect {label} input") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise StageRuntimeError(f"{label} input must be a regular non-symlink file")
    if info.st_size < 0 or info.st_size > max_bytes:
        raise StageRuntimeError(f"{label} input exceeds the configured size limit")
    return info


def _copy_limited(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[int, str]:
    before = _safe_regular_file(source, max_bytes=max_bytes, label=label)
    digest = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as reader, destination.open("xb") as writer:
            while True:
                chunk = reader.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise StageRuntimeError(f"{label} input exceeds the configured size limit")
                digest.update(chunk)
                writer.write(chunk)
    except StageRuntimeError:
        raise
    except OSError as exc:
        raise StageRuntimeError(f"Cannot copy {label} input") from exc
    if total != before.st_size:
        raise StageRuntimeError(f"{label} input changed while it was being staged")
    return total, digest.hexdigest()


def _hash_file(path: Path, *, max_bytes: int, label: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise StageRuntimeError(f"{label} exceeds the configured size limit")
                digest.update(chunk)
    except StageRuntimeError:
        raise
    except OSError as exc:
        raise StageRuntimeError(f"Cannot read {label}") from exc
    return total, digest.hexdigest()


def _validate_https_url(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise StageRuntimeError(f"Pinned compatibility metadata has no valid {label}")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise StageRuntimeError(f"Pinned compatibility metadata has no valid {label}")
    return value


def _load_compatibility_manifest(path: Path, staged_copy: Path) -> tuple[dict[str, Any], int, str]:
    size, digest = _copy_limited(
        path,
        staged_copy,
        max_bytes=MAX_COMPATIBILITY_MANIFEST_BYTES,
        label="Mihomo compatibility manifest",
    )
    try:
        content = staged_copy.read_text(encoding="utf-8")
        manifest = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageRuntimeError("Pinned Mihomo compatibility manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise StageRuntimeError("Pinned Mihomo compatibility manifest schema is unsupported")

    version = manifest.get("version")
    if not isinstance(version, str) or not _SAFE_VERSION.fullmatch(version):
        raise StageRuntimeError("Pinned Mihomo version is invalid")
    repository = _validate_https_url(manifest.get("repository"), "repository URL")
    source_tag = _validate_https_url(manifest.get("source_tag"), "source tag URL")
    license_url = _validate_https_url(manifest.get("license_url"), "license URL")
    license_name = manifest.get("license")
    if not isinstance(license_name, str) or not license_name or len(license_name) > 80:
        raise StageRuntimeError("Pinned Mihomo license identifier is invalid")

    parsed_repo = urllib.parse.urlsplit(repository)
    if parsed_repo.hostname != "github.com" or not re.fullmatch(
        r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed_repo.path
    ):
        raise StageRuntimeError("Pinned Mihomo repository must be an official GitHub project URL")
    assets = manifest.get("assets")
    windows_asset = assets.get("windows") if isinstance(assets, dict) else None
    if not isinstance(windows_asset, dict):
        raise StageRuntimeError("Pinned compatibility metadata has no Windows asset")
    asset_name = windows_asset.get("name")
    asset_bytes = windows_asset.get("bytes")
    asset_sha256 = windows_asset.get("sha256")
    if not isinstance(asset_name, str) or not _SAFE_ASSET_NAME.fullmatch(asset_name):
        raise StageRuntimeError("Pinned Windows asset name is invalid")
    if isinstance(asset_bytes, bool) or not isinstance(asset_bytes, int):
        raise StageRuntimeError("Pinned Windows asset size is invalid")
    if asset_bytes <= 0 or asset_bytes > MAX_ARCHIVE_BYTES:
        raise StageRuntimeError("Pinned Windows asset size exceeds the configured limit")
    if not isinstance(asset_sha256, str) or not _HEX_256.fullmatch(asset_sha256):
        raise StageRuntimeError("Pinned Windows asset SHA256 is invalid")
    _validate_https_url(source_tag, "source tag URL")
    _validate_https_url(license_url, "license URL")

    return manifest, size, digest


def _expected_engine_member(asset_name: str, version: str) -> str:
    suffix = f"-{version}.zip"
    if not asset_name.endswith(suffix):
        raise StageRuntimeError("Pinned Windows asset name does not match its version")
    stem = asset_name[: -len(suffix)]
    if not stem or "/" in stem or "\\" in stem:
        raise StageRuntimeError("Pinned Windows asset name is invalid")
    return f"{stem}.exe"


def _download_archive(url: str, destination: Path, expected_size: int) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "MullvadAdapter-Windows-Runtime-Stager/1", "Accept": "application/octet-stream"},
    )
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    digest = hashlib.sha256()
    total = 0
    try:
        opener = urllib.request.build_opener(_HttpsOnlyRedirectHandler())
        with opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            if time.monotonic() > deadline:
                raise StageRuntimeError("Mihomo download exceeded the time limit")
            final_url = urllib.parse.urlsplit(response.geturl())
            if final_url.scheme != "https":
                raise StageRuntimeError("Mihomo download redirected away from HTTPS")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) != expected_size:
                        raise StageRuntimeError("Mihomo download size does not match the pinned size")
                except ValueError as exc:
                    raise StageRuntimeError("Mihomo download returned an invalid size") from exc
            with destination.open("xb") as writer:
                while True:
                    if time.monotonic() > deadline:
                        raise StageRuntimeError("Mihomo download exceeded the time limit")
                    chunk = response.read(min(COPY_CHUNK_BYTES, expected_size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected_size:
                        raise StageRuntimeError("Mihomo download exceeds the pinned size")
                    digest.update(chunk)
                    writer.write(chunk)
    except StageRuntimeError:
        raise
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise StageRuntimeError("Mihomo download failed within the configured network limits") from exc
    if total != expected_size:
        raise StageRuntimeError("Mihomo download size does not match the pinned size")
    if time.monotonic() > deadline:
        raise StageRuntimeError("Mihomo download exceeded the time limit")
    return total, digest.hexdigest()


def _extract_engine(archive_path: Path, output_path: Path, expected_member: str) -> tuple[int, str]:
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if len(infos) != 1:
                raise StageRuntimeError("Mihomo archive must contain exactly one file")
            info = infos[0]
            if info.filename != expected_member or getattr(info, "orig_filename", info.filename) != info.filename:
                raise StageRuntimeError("Mihomo archive entry name is not the expected flat executable")
            if info.is_dir() or "/" in info.filename or "\\" in info.filename or ":" in info.filename:
                raise StageRuntimeError("Mihomo archive contains a path entry")
            if info.flag_bits & 0x1:
                raise StageRuntimeError("Encrypted Mihomo archive entries are not supported")
            file_type = stat.S_IFMT(info.external_attr >> 16)
            if file_type not in (0, stat.S_IFREG):
                raise StageRuntimeError("Mihomo archive entry is not a regular file")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise StageRuntimeError("Mihomo archive compression type is not supported")
            if info.file_size <= 0 or info.file_size > MAX_ENGINE_BYTES:
                raise StageRuntimeError("Mihomo executable exceeds the extraction size limit")

            total = 0
            digest = hashlib.sha256()
            with archive.open(info, "r") as reader, output_path.open("xb") as writer:
                while True:
                    chunk = reader.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ENGINE_BYTES or total > info.file_size:
                        raise StageRuntimeError("Mihomo executable exceeds the extraction size limit")
                    digest.update(chunk)
                    writer.write(chunk)
            if total != info.file_size:
                raise StageRuntimeError("Mihomo executable size is inconsistent with its ZIP metadata")
            return total, digest.hexdigest()
    except StageRuntimeError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise StageRuntimeError("Mihomo archive is corrupt or cannot be safely extracted") from exc


def _validate_amd64_pe(path: Path, *, label: str, file_size: int) -> None:
    if file_size < 70:
        raise StageRuntimeError(f"{label} is not a valid Windows PE executable")
    try:
        with path.open("rb") as stream:
            dos_header = stream.read(64)
            if len(dos_header) != 64 or dos_header[:2] != b"MZ":
                raise StageRuntimeError(f"{label} is not a valid Windows PE executable")
            pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
            if pe_offset < 64 or pe_offset > MAX_PE_HEADER_OFFSET or pe_offset + 6 > file_size:
                raise StageRuntimeError(f"{label} has an invalid PE header offset")
            stream.seek(pe_offset)
            pe_header = stream.read(6)
    except OSError as exc:
        raise StageRuntimeError(f"Cannot read {label} PE header") from exc
    if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
        raise StageRuntimeError(f"{label} is not a valid Windows PE executable")
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    if machine != AMD64_PE_MACHINE:
        raise StageRuntimeError(f"{label} is not an x64 Windows executable")


def _notices(manifest: dict[str, Any]) -> bytes:
    version = manifest["version"]
    repository = manifest["repository"].rstrip("/")
    source_tag = manifest["source_tag"]
    license_name = manifest["license"]
    license_url = manifest["license_url"]
    asset_name = manifest["assets"]["windows"]["name"]
    asset_url = f"{repository}/releases/download/{version}/{asset_name}"
    lines = [
        "Third-party runtime notices",
        "",
        "Mihomo (MetaCubeX)",
        f"Version: {version}",
        "Platform: Windows x86_64",
        f"Project: {repository}",
        f"Source tag: {source_tag}",
        f"Binary asset: {asset_url}",
        f"License: {license_name}",
        f"License text: {license_url}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory while refusing to replace any target."""
    if os.name == "nt":
        try:
            os.rename(source, destination)
            return
        except FileExistsError:
            raise
        except OSError as exc:
            if destination.exists() or destination.is_symlink():
                raise FileExistsError("staging destination already exists") from exc
            raise StageRuntimeError("Cannot atomically publish staged runtime") from exc

    libc = ctypes.CDLL(None, use_errno=True)
    source_b = os.fsencode(source)
    destination_b = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(source_b, destination_b, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(-100, source_b, -100, destination_b, 0x1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise StageRuntimeError("This platform lacks atomic no-overwrite directory publication")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (17, 80, 183):  # EEXIST on POSIX, ERROR_ALREADY_EXISTS on Windows
        raise FileExistsError("staging destination already exists")
    raise StageRuntimeError("Cannot atomically publish staged runtime")


def _ensure_output_root(path: Path) -> Path:
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise StageRuntimeError("Output staging root must be a directory and not a symlink")
        else:
            path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
    except StageRuntimeError:
        raise
    except OSError as exc:
        raise StageRuntimeError("Cannot prepare output staging root") from exc
    destination = resolved / "runtime"
    if destination.exists() or destination.is_symlink():
        raise StageRuntimeError("Staging destination already exists; choose a fresh output root")
    return resolved


class _RuntimeStagingDirectory:
    """Clean failed assembly; ownership transfers with the atomic publication.

    TemporaryDirectory's Windows cleanup can fail on a path that was renamed
    successfully. Do not ask it to delete the old name after publication, and
    never clean the published directory on a later context-manager exit.
    """

    def __init__(self, root: Path) -> None:
        self.path = Path(tempfile.mkdtemp(prefix=".runtime-stage-", dir=root))
        self.published = False

    def __enter__(self) -> _RuntimeStagingDirectory:
        return self

    def publish(self, destination: Path) -> None:
        _rename_noreplace(self.path, destination)
        self.published = True

    def __exit__(self, *_: object) -> None:
        if not self.published:
            shutil.rmtree(self.path)


def stage_runtime(
    adapter_agent: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    source_sha: str,
    version: str,
    *,
    mihomo_archive: str | os.PathLike[str] | None = None,
    compatibility_manifest: str | os.PathLike[str] = DEFAULT_COMPATIBILITY_MANIFEST,
) -> dict[str, Any]:
    """Build and atomically publish ``output_root/runtime``.

    ``mihomo_archive`` exists for offline packaging and tests; it is subjected
    to the same pinned byte-count and SHA256 checks as a network download.
    """
    if not isinstance(source_sha, str) or not _SOURCE_SHA.fullmatch(source_sha):
        raise StageRuntimeError("SOURCE_SHA must be a full 40-character hexadecimal commit SHA")
    source_sha = source_sha.lower()
    if not isinstance(version, str) or not _SAFE_VERSION.fullmatch(version):
        raise StageRuntimeError("Version must be a short path-safe version string")

    root = _ensure_output_root(Path(output_root).expanduser())
    destination = root / "runtime"
    if destination.exists() or destination.is_symlink():
        raise StageRuntimeError("Staging destination already exists; choose a fresh output root")

    adapter_source = Path(adapter_agent).expanduser()
    manifest_source = Path(compatibility_manifest).expanduser()
    adapter_info = _safe_regular_file(
        adapter_source,
        max_bytes=MAX_ADAPTER_BYTES,
        label="Adapter agent",
    )
    if adapter_info.st_size == 0:
        raise StageRuntimeError("Adapter agent input is empty")
    if mihomo_archive is not None:
        _safe_regular_file(Path(mihomo_archive).expanduser(), max_bytes=MAX_ARCHIVE_BYTES, label="Mihomo archive")

    try:
        with _RuntimeStagingDirectory(root) as staging_lease:
            staging = staging_lease.path
            adapter_out = staging / "adapter-agent.exe"
            adapter_size, adapter_hash = _copy_limited(
                adapter_source,
                adapter_out,
                max_bytes=MAX_ADAPTER_BYTES,
                label="Adapter agent",
            )
            _validate_amd64_pe(adapter_out, label="Adapter agent", file_size=adapter_size)

            compatibility_out = staging / "mihomo-compatibility.json"
            compatibility, compatibility_size, compatibility_hash = _load_compatibility_manifest(
                manifest_source,
                compatibility_out,
            )
            windows_asset = compatibility["assets"]["windows"]
            expected_member = _expected_engine_member(windows_asset["name"], compatibility["version"])

            archive_out = staging / ".mihomo-verified.zip"
            if mihomo_archive is None:
                repository = compatibility["repository"].rstrip("/")
                download_url = (
                    f"{repository}/releases/download/{compatibility['version']}/"
                    f"{windows_asset['name']}"
                )
                archive_size, archive_hash = _download_archive(
                    download_url,
                    archive_out,
                    windows_asset["bytes"],
                )
            else:
                archive_size, archive_hash = _copy_limited(
                    Path(mihomo_archive).expanduser(),
                    archive_out,
                    max_bytes=MAX_ARCHIVE_BYTES,
                    label="Mihomo archive",
                )
            if archive_size != windows_asset["bytes"]:
                raise StageRuntimeError("Mihomo archive size does not match the pinned size")
            if archive_hash.lower() != windows_asset["sha256"].lower():
                raise StageRuntimeError("Mihomo archive SHA256 does not match the pinned digest")

            mihomo_out = staging / "mihomo.exe"
            mihomo_size, mihomo_hash = _extract_engine(archive_out, mihomo_out, expected_member)
            _validate_amd64_pe(mihomo_out, label="Mihomo engine", file_size=mihomo_size)
            archive_out.unlink()

            notices_out = staging / "THIRD_PARTY_NOTICES.txt"
            notices_out.write_bytes(_notices(compatibility))
            notices_size, notices_hash = _hash_file(
                notices_out,
                max_bytes=MAX_COMPATIBILITY_MANIFEST_BYTES,
                label="Third-party notices",
            )

            files = {
                "adapter-agent.exe": {"size_bytes": adapter_size, "sha256": adapter_hash},
                "mihomo.exe": {"size_bytes": mihomo_size, "sha256": mihomo_hash},
                "mihomo-compatibility.json": {
                    "size_bytes": compatibility_size,
                    "sha256": compatibility_hash,
                },
                "THIRD_PARTY_NOTICES.txt": {"size_bytes": notices_size, "sha256": notices_hash},
            }
            payload_manifest = {
                "schema": 1,
                "source_sha": source_sha,
                "version": version,
                "platform": "windows",
                "architecture": "x86_64",
                "signature": "NOT_RUN",
                "files": files,
            }
            manifest_out = staging / "manifest.json"
            manifest_out.write_text(
                json.dumps(payload_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            # Catch a destination created while payload validation was in progress.
            if destination.exists() or destination.is_symlink():
                raise StageRuntimeError("Staging destination appeared during assembly; nothing was replaced")
            staging_lease.publish(destination)
            return payload_manifest
    except FileExistsError as exc:
        raise StageRuntimeError("Staging destination already exists; choose a fresh output root") from exc
    except StageRuntimeError:
        raise
    except OSError as exc:
        raise StageRuntimeError("Runtime staging failed before publication") from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-agent", required=True, help="Path to the built adapter-agent.exe")
    parser.add_argument("--output-root", required=True, help="Fresh staging root; runtime/ is created beneath it")
    parser.add_argument("--source-sha", required=True, help="Full 40-character source commit SHA")
    parser.add_argument("--version", required=True, help="Adapter package version")
    parser.add_argument(
        "--mihomo-archive",
        help="Optional already-downloaded pinned Mihomo ZIP for offline staging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = stage_runtime(
            args.adapter_agent,
            args.output_root,
            args.source_sha,
            args.version,
            mihomo_archive=args.mihomo_archive,
        )
    except StageRuntimeError as exc:
        print(f"runtime staging failed: {exc}", file=sys.stderr)
        return 1
    print(
        "runtime staged: Windows x86_64, "
        f"{len(result['files'])} verified files, signature {result['signature']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
