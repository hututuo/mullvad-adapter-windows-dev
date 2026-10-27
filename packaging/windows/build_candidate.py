#!/usr/bin/env python3
"""Build an unsigned Windows x64 installer; never install or publish it.

Python, Rust and Node are build-machine tools only. The installer embeds the
verified agent/Mihomo runtime and Microsoft's offline WebView2 installer.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib

from stage_runtime import stage_runtime, _validate_amd64_pe, StageRuntimeError

TARGET = "x86_64-pc-windows-msvc"
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")

# These are the checked-out files consumed by the two builds and runtime
# staging. Build caches and generated output are handled separately below.
_BUILD_INPUT_PATHS = (
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".cargo",
    "core",
    "helpers/quic-carrier",
    "desktop",
    "packaging/windows/build_candidate.py",
    "packaging/windows/stage_runtime.py",
    "engines/mihomo-compatibility.json",
)

# These ignored trees are expected in the existing local and Actions flows.
# Unexpected ignored files in a build-input tree fail closed (for example,
# desktop/.env.local), because they can alter what Cargo or Tauri builds.
_BUILD_CACHE_PATHS = (
    "core/target",
    "helpers/quic-carrier/target",
    "helpers/quic-carrier/bin",
    "desktop/node_modules",
    "desktop/dist",
    "desktop/src-tauri/gen",
    "desktop/src-tauri/target",
    "packaging/windows/__pycache__",
)


class BuildSourceError(ValueError):
    """The requested source revision or its build inputs are not trustworthy."""


def _git_output(source: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise BuildSourceError("Unable to verify build inputs in the checked-out Git repository") from error
    return result.stdout


def _tracked_input_paths(source: Path) -> tuple[bytes, ...]:
    paths = _git_output(source, "ls-files", "-z", "--", *_BUILD_INPUT_PATHS).split(b"\0")
    return tuple(sorted(path for path in paths if path))


def _assert_no_hidden_index_state(source: Path) -> None:
    # Git status can intentionally omit files marked assume-unchanged or
    # skip-worktree. A candidate must not use those flags to hide changed code.
    entries = _git_output(source, "ls-files", "-v", "-z", "--", *_BUILD_INPUT_PATHS).split(b"\0")
    for entry in entries:
        if entry and (entry[:1].islower() or entry[:1] == b"S"):
            raise BuildSourceError("Git index hides a build input with assume-unchanged or skip-worktree")


def _is_within(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _status_changes(source: Path, transient_roots: tuple[Path, ...]) -> tuple[list[str], list[str]]:
    """Return tracked edits and non-cache untracked/ignored build inputs."""
    output = _git_output(
        source,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=normal",
        "--ignored=matching",
        "--",
        *_BUILD_INPUT_PATHS,
    )
    tracked: list[str] = []
    untracked: list[str] = []
    for entry in output.split(b"\0"):
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            # Malformed or rename continuation records still fail closed.
            tracked.append("<unrecognized Git status>")
            continue
        state = entry[:2].decode("ascii", errors="replace")
        relative = os.fsdecode(entry[3:]).rstrip("/\\")
        path = (source / relative).resolve(strict=False)
        if state == "??" or state == "!!":
            # Only untracked/ignored data may be excluded. A modified tracked
            # file remains an error even if the user points a cache there.
            if _is_within(path, transient_roots):
                continue
            if state == "!!":
                untracked.append(relative)
            else:
                untracked.append(relative)
        else:
            tracked.append(relative)
    return tracked, untracked


def _input_fingerprint(source: Path) -> str:
    digest = hashlib.sha256()
    for encoded_path in _tracked_input_paths(source):
        relative = os.fsdecode(encoded_path)
        path = source / relative
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                kind = b"symlink"
                contents = os.fsencode(os.readlink(path))
                content_digest = hashlib.sha256(contents).digest()
            elif stat.S_ISREG(info.st_mode):
                kind = b"file"
                content = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        content.update(chunk)
                content_digest = content.digest()
            else:
                raise BuildSourceError("A tracked build input is missing or is not a regular file")
        except OSError as error:
            raise BuildSourceError("A tracked build input cannot be read") from error
        digest.update(encoded_path)
        digest.update(b"\0")
        digest.update(kind)
        digest.update(b"\0")
        digest.update(str(stat.S_IMODE(info.st_mode) & 0o111).encode("ascii"))
        digest.update(b"\0")
        digest.update(content_digest)
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True)
class BuildSourceSnapshot:
    source: Path
    head: str
    fingerprint: str
    transient_roots: tuple[Path, ...]

    def assert_unchanged(self) -> None:
        current_head = _git_output(self.source, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
        if current_head != self.head:
            raise BuildSourceError("The checked-out Git HEAD changed during the candidate build")
        _assert_no_hidden_index_state(self.source)
        tracked, untracked = _status_changes(self.source, self.transient_roots)
        if tracked:
            raise BuildSourceError("Tracked build inputs changed during the candidate build")
        if untracked:
            raise BuildSourceError("Untracked or ignored build inputs appeared during the candidate build")
        if _input_fingerprint(self.source) != self.fingerprint:
            raise BuildSourceError("Build input contents changed during the candidate build")
        tracked, untracked = _status_changes(self.source, self.transient_roots)
        _assert_no_hidden_index_state(self.source)
        if tracked:
            raise BuildSourceError("Tracked build inputs changed during candidate input verification")
        if untracked:
            raise BuildSourceError("Untracked or ignored build inputs appeared during candidate input verification")


def _capture_build_source(
    source: Path,
    requested_sha: str,
    *,
    output: Path,
    target: Path,
) -> BuildSourceSnapshot:
    if not _SOURCE_SHA.fullmatch(requested_sha):
        raise BuildSourceError("Full lower-case source SHA required")
    source = source.resolve()
    git_root = Path(os.fsdecode(_git_output(source, "rev-parse", "--show-toplevel")).strip()).resolve()
    if git_root != source:
        raise BuildSourceError("Candidate source directory must be the root of its Git checkout")
    head = _git_output(source, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    if requested_sha != head:
        raise BuildSourceError(
            f"--source-sha does not match checked-out Git HEAD (requested {requested_sha}, HEAD {head})"
        )

    _assert_no_hidden_index_state(source)
    tracked_paths = _tracked_input_paths(source)
    scratch_paths: list[Path] = []
    for path in (output, target):
        scratch = path.resolve(strict=False)
        if scratch == source or scratch in source.parents:
            raise BuildSourceError("Candidate output/cache path cannot contain or replace the source checkout")
        if source in scratch.parents:
            scratch_paths.append(scratch)
    for scratch in scratch_paths:
        if any(
            tracked_path.resolve(strict=False) == scratch
            or scratch in tracked_path.resolve(strict=False).parents
            for tracked_path in (source / os.fsdecode(path) for path in tracked_paths)
        ):
            raise BuildSourceError("Candidate output/cache path overlaps tracked build inputs")

    transient_roots = tuple(
        (source / relative).resolve(strict=False) for relative in _BUILD_CACHE_PATHS
    ) + tuple(
        path.resolve(strict=False)
        for path in (output, target)
        if path.resolve(strict=False) == source
        or source in path.resolve(strict=False).parents
    )
    tracked, untracked = _status_changes(source, transient_roots)
    if tracked:
        raise BuildSourceError("Tracked build inputs are dirty; commit them before building this source SHA")
    if untracked:
        raise BuildSourceError(
            "Untracked or ignored files are present in build inputs; remove them or move them outside the checkout"
        )
    fingerprint = _input_fingerprint(source)
    # Close the race between the initial status check and hashing the source.
    tracked, untracked = _status_changes(source, transient_roots)
    if tracked:
        raise BuildSourceError("Tracked build inputs changed while the source snapshot was captured")
    if untracked:
        raise BuildSourceError("Untracked or ignored build inputs appeared while the source snapshot was captured")
    _assert_no_hidden_index_state(source)
    return BuildSourceSnapshot(source, head, fingerprint, transient_roots)


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


def require_upstream_long_paths(source: Path) -> None:
    # A CLI fetch alone does not change Cargo's libgit2 checkout settings. Only
    # inspect the host configuration; never rewrite a developer's global file.
    result = subprocess.run(
        ["git", "config", "--global", "--bool", "--get", "core.longpaths"],
        cwd=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise ValueError("Windows build host requires git config --global core.longpaths true "
                         "for the pinned official QUIC repository; no host setting was changed")


def build(
    args: argparse.Namespace,
    *,
    source_root: Path | None = None,
    command_runner=subprocess.run,
) -> dict:
    if sys.platform != "win32":
        raise ValueError("Windows x64 build host required")
    source = (source_root or Path(__file__).resolve().parents[2]).resolve()
    output = Path(args.output).resolve()
    target = Path(args.target_dir).resolve()
    source_snapshot = _capture_build_source(source, args.source_sha, output=output, target=target)
    core_target = target / "core"
    ui_target = target / "desktop"
    desktop = source / "desktop"
    version = tomllib.loads((source / "core/Cargo.toml").read_text())["workspace"]["package"]["version"]
    if json.loads((desktop / "src-tauri/tauri.conf.json").read_text())["version"] != version:
        raise ValueError("Agent and desktop versions differ")

    require_upstream_long_paths(source)

    # Never replace a prior candidate or erase a user's directory. Source
    # verification completes first so invalid provenance has no output side effect.
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env["ADAPTER_SOURCE_SHA"] = args.source_sha
    # Upstream contains paths beyond legacy MAX_PATH. Keep the fix scoped to
    # child Git/Cargo processes; never modify the build host's global config.
    env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"
    git_config_count = int(env.get("GIT_CONFIG_COUNT", "0"))
    if not 0 <= git_config_count <= 64:
        raise ValueError("Invalid inherited Git config count")
    env[f"GIT_CONFIG_KEY_{git_config_count}"] = "core.longpaths"
    env[f"GIT_CONFIG_VALUE_{git_config_count}"] = "true"
    env["GIT_CONFIG_COUNT"] = str(git_config_count + 1)
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
    source_snapshot.assert_unchanged()
    command_runner(["cargo", "build", "--locked", "--release", "--target", TARGET,
                    "-p", "adapter-agent"], cwd=source / "core", env=env, check=True)
    source_snapshot.assert_unchanged()
    command_runner(["cargo", "build", "--locked", "--release", "--target", TARGET],
                   cwd=source / "helpers/quic-carrier", env=env, check=True)
    source_snapshot.assert_unchanged()
    runtime = output / "payload"
    stage_runtime(core_target / TARGET / "release/adapter-agent.exe", runtime,
                  args.source_sha, version, mihomo_archive=args.mihomo_archive,
                  quic_helper=core_target / TARGET / "release/mullvad-quic-carrier.exe")
    source_snapshot.assert_unchanged()
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
    source_snapshot.assert_unchanged()
    command_runner([npm, "run", "tauri", "--", "build", "--ci", "--no-sign", "--target", TARGET,
                    "--config", str(config), "--", "--locked"], cwd=desktop, env=env, check=True)
    source_snapshot.assert_unchanged()
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
    source_snapshot.assert_unchanged()
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
