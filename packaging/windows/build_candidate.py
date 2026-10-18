#!/usr/bin/env python3
"""Build an unsigned Windows x64 installer; never install or publish it.

Python, Rust and Node are build-machine tools only. The installer embeds the
verified agent/Mihomo runtime and Microsoft's offline WebView2 installer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from stage_runtime import stage_runtime, _validate_amd64_pe, StageRuntimeError

TARGET = "x86_64-pc-windows-msvc"


def file_record(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"file": path.name, "size": path.stat().st_size, "sha256": digest.hexdigest()}


def packaged_desktop_record(path: Path) -> dict:
    """Describe the NSIS payload, separately from the restored compiler output.

    Pinned Tauri bundler 2.10.1 patches this equal-length marker for packaging
    and then restores the original executable. Keep both hashes: the installer
    contains NSS, while the build cache contains UNK.
    """
    marker = b"__TAURI_BUNDLE_TYPE_VAR_UNK"
    payload = path.read_bytes()
    if payload.count(marker) != 1:
        raise ValueError("Expected one unpatched Tauri bundle-type marker")
    payload = payload.replace(marker, b"__TAURI_BUNDLE_TYPE_VAR_NSS", 1)
    return {"file": path.name, "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(), "bundle_type": "nsis"}


def build(args: argparse.Namespace) -> dict:
    if sys.platform != "win32":
        raise ValueError("Windows x64 build host required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("Full lower-case source SHA required")
    source = Path(__file__).resolve().parents[2]
    output = Path(args.output).resolve()
    # Never replace a prior candidate or erase a user's directory.
    output.mkdir(parents=True, exist_ok=False)
    target = Path(args.target_dir).resolve()
    core_target = target / "core"
    ui_target = target / "desktop"
    desktop = source / "desktop"
    version = tomllib.loads((source / "core/Cargo.toml").read_text())["workspace"]["package"]["version"]
    if json.loads((desktop / "src-tauri/tauri.conf.json").read_text())["version"] != version:
        raise ValueError("Agent and desktop versions differ")
    env = os.environ.copy()
    env["ADAPTER_SOURCE_SHA"] = args.source_sha
    # Ship no dependency on a separately installed Visual C++ redistributable.
    # Keep other caller build flags rather than replacing them.
    if env.get("RUSTFLAGS"):
        raise ValueError("Use CARGO_ENCODED_RUSTFLAGS for unambiguous additional build flags")
    flags = env.get("CARGO_ENCODED_RUSTFLAGS", "")
    env.pop("RUSTFLAGS", None)
    env["CARGO_ENCODED_RUSTFLAGS"] = flags + ("\x1f" if flags else "") + "-C\x1ftarget-feature=+crt-static"
    if args.offline:
        env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_TARGET_DIR"] = str(core_target)
    subprocess.run(["cargo", "build", "--locked", "--release", "--target", TARGET,
                    "-p", "adapter-agent"], cwd=source / "core", env=env, check=True)
    runtime = output / "payload"
    stage_runtime(core_target / TARGET / "release/adapter-agent.exe", runtime,
                  args.source_sha, version, mihomo_archive=args.mihomo_archive)
    manifest = runtime / "runtime/manifest.json"
    env["ADAPTER_RUNTIME_MANIFEST_SHA256"] = file_record(manifest)["sha256"]
    env["CARGO_TARGET_DIR"] = str(ui_target)
    resources = {str(path): "runtime/" + path.name for path in (runtime / "runtime").iterdir()}
    config = output / "candidate-config.json"
    config.write_text(json.dumps({"bundle": {"active": True, "resources": resources,
        "targets": ["nsis"], "windows": {"nsis": {
            "installMode": "currentUser", "languages": ["SimpChinese", "English"],
            "displayLanguageSelector": True}, "webviewInstallMode": {"type": "offlineInstaller"}}}}, indent=2))
    npm = shutil.which("npm.cmd")
    if not npm:
        raise ValueError("Build host npm.cmd unavailable")
    subprocess.run([npm, "run", "tauri", "--", "build", "--ci", "--no-sign", "--target", TARGET,
                    "--config", str(config), "--", "--locked"], cwd=desktop, env=env, check=True)
    release = ui_target / TARGET / "release"
    executable = release / "mullvad-adapter-desktop.exe"
    _validate_amd64_pe(executable, label="Desktop", file_size=executable.stat().st_size)
    installers = sorted((release / "bundle/nsis").glob("*.exe"))
    if len(installers) != 1:
        raise ValueError("Expected exactly one NSIS installer")
    installer = output / installers[0].name
    shutil.copyfile(installers[0], installer)
    receipt = {"schema": 1, "source_sha": args.source_sha, "version": version,
        "platform": "windows", "architecture": "x86_64", "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "signature": "NOT_RUN", "publish": "NOT_RUN", "installer": file_record(installer),
        "desktop": file_record(executable), "runtime_manifest": file_record(manifest),
        "packaged_desktop": packaged_desktop_record(executable),
        "runtime_requirements": "Windows 11 x64; external Clash ingress for system traffic. WebView2 offline installer included.",
        "verification": {"build": "PASS", "installation": "NOT_RUN", "interaction": "NOT_RUN",
                         "upgrade": "NOT_RUN", "tunnel": "NOT_RUN", "recovery": "NOT_RUN"}}
    (output / "candidate.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, help="New candidate directory")
    parser.add_argument("--target-dir", required=True, help="Dedicated build cache; no simultaneous writers")
    parser.add_argument("--mihomo-archive", help="Previously verified pinned official ZIP")
    parser.add_argument("--offline", action="store_true", help="Use preloaded Cargo cache; WebView2/NSIS may still need downloads")
    args = parser.parse_args()
    try:
        result = build(args)
    except (OSError, ValueError, StageRuntimeError, subprocess.CalledProcessError) as error:
        print(f"candidate build failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
