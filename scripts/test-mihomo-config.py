#!/usr/bin/env python3
"""Pinned official parser, with an explicit Windows-only front/REJECT lifecycle gate."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tempfile
import time
import urllib.request
import zipfile

MAX_BINARY = 128 * 1024 * 1024


def run_lifecycle(fixture, binary, mode, clean_env):
    """Expose bounded diagnostics from this public, synthetic-only fixture."""
    try:
        subprocess.run([str(fixture.resolve()), str(binary), *mode], check=True,
                       capture_output=True, timeout=50, env=clean_env)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Never use this helper for production/config/credential commands. The
        # fixture has only public synthetic inputs; discard stdout and bound stderr.
        stderr = error.stderr or b""
        if isinstance(stderr, bytes):
            stderr = stderr[-8192:].decode("utf-8", errors="replace")
        else:
            stderr = stderr[-8192:]
        label = mode[0] if mode else "normal"
        raise RuntimeError(f"synthetic lifecycle {label} failed: {stderr}") from error


def unpack(data, os_name):
    if os_name == "linux":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            result = compressed.read(MAX_BINARY + 1)
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [item for item in archive.infolist() if item.filename.endswith(".exe")]
            if len(files) != 1:
                raise ValueError("expected exactly one official executable")
            item = files[0]
            if PurePosixPath(item.filename).name != item.filename or "\\" in item.filename or item.file_size > MAX_BINARY:
                raise ValueError("invalid executable archive entry")
            with archive.open(item) as compressed:
                result = compressed.read(MAX_BINARY + 1)
    if not result or len(result) > MAX_BINARY:
        raise ValueError("invalid executable size")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-generator", type=Path, required=True)
    parser.add_argument("--lifecycle-fixture", type=Path, help="Windows-only synthetic owned front gate")
    args = parser.parse_args()
    os_name = platform.system().lower()
    if os_name not in {"windows", "linux"} or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("parser gate supports Windows/Linux x64 only")
    if args.lifecycle_fixture is not None and os_name != "windows":
        raise RuntimeError("owned front lifecycle gate requires Windows")
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / "engines/mihomo-compatibility.json").read_text())
    asset = manifest["assets"][os_name]
    url = f'https://github.com/MetaCubeX/mihomo/releases/download/{manifest["version"]}/{asset["name"]}'
    start = time.monotonic()
    data = bytearray()
    with urllib.request.urlopen(url, timeout=30) as response:
        while block := response.read(1024 * 1024):
            data.extend(block)
            if len(data) > asset["bytes"] or time.monotonic() - start > 180:
                raise RuntimeError("download exceeded pinned size/time bound")
    if len(data) != asset["bytes"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
        raise RuntimeError("official artifact size/hash mismatch")
    clean_env = {k: v for k, v in os.environ.items() if not k.upper().startswith("CLASH_")}
    with tempfile.TemporaryDirectory(prefix="adapter-mihomo-parser-") as directory:
        work = Path(directory)
        binary = work / ("mihomo.exe" if os_name == "windows" else "mihomo")
        binary.write_bytes(unpack(data, os_name))
        if os_name == "linux":
            binary.chmod(0o700)
        version = subprocess.run([str(binary), "-v"], check=True, capture_output=True, timeout=10, env=clean_env)
        if f'Mihomo Meta {manifest["version"]} '.encode() not in version.stdout:
            raise RuntimeError("engine version mismatch")
        for mode in ("ipv4", "ipv6", "ss", "front"):
            fixture = subprocess.run([str(args.fixture_generator.resolve()), mode], check=True, capture_output=True, timeout=10, env=clean_env).stdout
            if not 0 < len(fixture) <= 16384:
                raise RuntimeError("invalid synthetic fixture size")
            home = work / mode
            home.mkdir()
            # -f - bypasses config.Init and uses only synthetic stdin; -t returns
            # after parser validation, before hub startup or listener creation.
            parsed = subprocess.run([str(binary), "-t", "-f", "-", "-d", str(home)], input=fixture, capture_output=True, timeout=30, env=clean_env)
            if parsed.returncode:
                raise RuntimeError(f"synthetic {mode} parser failed (exit {parsed.returncode})")
            print(f"{os_name} {manifest['version']} {mode}: parser PASS", flush=True)
            if mode == "ipv4":
                malformed = json.loads(fixture)
                malformed["proxies"][0]["private-key"] = "invalid-synthetic-key"
                rejected = subprocess.run([str(binary), "-t", "-f", "-", "-d", str(home)], input=json.dumps(malformed).encode(), capture_output=True, timeout=30, env=clean_env)
                if rejected.returncode == 0:
                    raise RuntimeError("engine parser accepted the malformed-key negative control")
                print(f"{os_name} {manifest['version']} malformed-key: correctly rejected", flush=True)

        if args.lifecycle_fixture is not None:
            # Archive size/hash and -v were verified above. This fixture runs only
            # a loopback front whose sole initial choice is REJECT, no VPN workers.
            run_lifecycle(args.lifecycle_fixture, binary, [], clean_env)
            run_lifecycle(args.lifecycle_fixture, binary, ["--occupy-mixed"], clean_env)
            run_lifecycle(args.lifecycle_fixture, binary, ["--cancel-before-ready"], clean_env)
            for phase in ("before-input", "before-spawn", "after-spawn", "ready-checkpoint"):
                run_lifecycle(args.lifecycle_fixture, binary, ["--cancel-" + phase], clean_env)
            print("Windows official front lifecycle: mixed/controller ownership/readiness/auth/REJECT/stop/cleanup and occupied-mixed/late-start/four cleaned startup cancellation controls PASS", flush=True)

    print("Synthetic engine gates complete; no tunnel/route/egress acceptance", flush=True)


if __name__ == "__main__":
    main()
