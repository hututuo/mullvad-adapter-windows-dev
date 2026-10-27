"""Pinned Tauri NSIS payload provenance contracts, without Windows tools."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import build_candidate
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


class BuildSourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "checkout with spaces"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, relative, payload):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload if isinstance(payload, bytes) else payload.encode("utf-8"))
        return path

    def _git(self, *arguments):
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def _init_repo(self):
        self._write(
            ".gitignore",
            "core/target/\ndesktop/node_modules/\ndesktop/dist/\n"
            "desktop/src-tauri/target/\ndesktop/src-tauri/gen/\n"
            "packaging/windows/__pycache__/\n.env.*\n",
        )
        self._write(
            "core/Cargo.toml",
            '[workspace]\nmembers = ["crates/agent"]\nresolver = "2"\n\n'
            '[workspace.package]\nversion = "0.1.0"\n',
        )
        self._write("core/Cargo.lock", "version = 4\n")
        self._write("core/crates/agent/Cargo.toml", "[package]\nname='adapter-agent'\n")
        self._write("core/crates/agent/src/main.rs", "fn main() {}\n")
        self._write("helpers/quic-carrier/Cargo.toml", "[package]\nname='mullvad-quic-carrier'\n")
        self._write("helpers/quic-carrier/Cargo.lock", "version = 4\n")
        self._write("helpers/quic-carrier/src/main.rs", "fn main() {}\n")
        self._write("desktop/package.json", '{"scripts":{"build":"vite build"}}\n')
        self._write("desktop/package-lock.json", '{"lockfileVersion":3}\n')
        self._write("desktop/src/main.ts", "console.log('desktop');\n")
        self._write("desktop/src-tauri/Cargo.toml", "[package]\nname='desktop'\n")
        self._write("desktop/src-tauri/Cargo.lock", "version = 4\n")
        self._write("desktop/src-tauri/build.rs", "fn main() {}\n")
        self._write("desktop/src-tauri/tauri.conf.json", json.dumps({"version": "0.1.0"}))
        self._write("desktop/src-tauri/src/main.rs", "fn main() {}\n")
        self._write("engines/mihomo-compatibility.json", '{"schema":1}\n')
        self._write("packaging/windows/build_candidate.py", "# candidate builder\n")
        self._write("packaging/windows/stage_runtime.py", "# runtime stager\n")
        self._write("packaging/windows/README.md", "candidate build contract\n")
        self._git("init", "-q")
        self._git("config", "user.name", "Candidate Test")
        self._git("config", "user.email", "candidate-test@example.invalid")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "clean build inputs")
        return self._git("rev-parse", "HEAD")

    def _args(self, source_sha):
        return type("Args", (), {
            "source_sha": source_sha,
            "output": str(Path(self.temporary.name) / "candidate output"),
            "target_dir": str(Path(self.temporary.name) / "build cache"),
            "offline": False,
            "mihomo_archive": None,
        })()

    def _run_build(self, source_sha, *, mutate_during=None, output=None, target=None):
        commands = []

        def run_command(command, **kwargs):
            commands.append(command)
            if command[0] == "cargo":
                env = kwargs["env"]
                self.assertEqual(env["CARGO_NET_GIT_FETCH_WITH_CLI"], "true")
                slot = int(env["GIT_CONFIG_COUNT"]) - 1
                self.assertEqual(env[f"GIT_CONFIG_KEY_{slot}"], "core.longpaths")
                self.assertEqual(env[f"GIT_CONFIG_VALUE_{slot}"], "true")
                artifact = Path(kwargs["env"]["CARGO_TARGET_DIR"]) / build_candidate.TARGET / "release/adapter-agent.exe"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b"mock agent")
            else:
                target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                release = target / build_candidate.TARGET / "release"
                release.mkdir(parents=True, exist_ok=True)
                (release / "mullvad-adapter-desktop.exe").write_bytes(
                    b"MZ__TAURI_BUNDLE_TYPE_VAR_UNK\x00fixture"
                )
                installer = release / "bundle/nsis/MullvadAdapter-test.exe"
                installer.parent.mkdir(parents=True, exist_ok=True)
                installer.write_bytes(b"mock installer")
            if mutate_during == "cargo" and command[0] == "cargo":
                self._write("core/crates/agent/src/main.rs", "fn main() { println!(\"changed\"); }\n")
            if mutate_during == "npm" and command[0] != "cargo":
                self._write("desktop/src/main.ts", "console.log('changed');\n")

        def fake_stage_runtime(_adapter, output_root, source_sha, _version, **_kwargs):
            runtime = Path(output_root) / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "manifest.json").write_text('{"schema":1}\n', encoding="utf-8")
            (runtime / "mihomo.exe").write_bytes(b"mock mihomo")
            return {"source_sha": source_sha}

        with (
            mock.patch.object(build_candidate.sys, "platform", "win32"),
            mock.patch.object(build_candidate.shutil, "which", return_value="npm.cmd"),
            mock.patch.object(build_candidate, "stage_runtime", side_effect=fake_stage_runtime),
            mock.patch.object(build_candidate, "require_upstream_long_paths"),
            mock.patch.object(build_candidate, "_validate_amd64_pe"),
        ):
            args = self._args(source_sha)
            if output is not None:
                args.output = str(output)
            if target is not None:
                args.target_dir = str(target)
            result = build_candidate.build(
                args, source_root=self.root, command_runner=run_command
            )
        return result, commands

    def _assert_rejected_before_build(self, source_sha, message):
        commands = []
        args = self._args(source_sha)
        with mock.patch.object(build_candidate.sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, message):
                build_candidate.build(
                    args,
                    source_root=self.root,
                    command_runner=lambda command, **_kwargs: commands.append(command),
                )
        self.assertEqual(commands, [])
        self.assertFalse(Path(args.output).exists())

    def test_wrong_source_sha_is_rejected_before_output_or_build(self):
        actual_sha = self._init_repo()
        wrong_sha = "0" * 40 if actual_sha != "0" * 40 else "1" * 40
        self._assert_rejected_before_build(wrong_sha, "does not match checked-out Git HEAD")

    def test_dirty_tracked_input_is_rejected_before_build(self):
        source_sha = self._init_repo()
        self._write("core/crates/agent/src/main.rs", "fn main() { /* dirty */ }\n")
        self._assert_rejected_before_build(source_sha, "Tracked build inputs are dirty")

    def test_assume_unchanged_cannot_hide_a_dirty_build_input(self):
        source_sha = self._init_repo()
        self._git("update-index", "--assume-unchanged", "core/crates/agent/src/main.rs")
        self._write("core/crates/agent/src/main.rs", "fn main() { /* hidden dirty */ }\n")
        self._assert_rejected_before_build(source_sha, "Git index hides a build input")

    def test_untracked_input_that_could_affect_cargo_is_rejected(self):
        source_sha = self._init_repo()
        self._write("core/crates/agent/build.rs", "fn main() {}\n")
        self._assert_rejected_before_build(source_sha, "Untracked or ignored files are present")

    def test_unexpected_ignored_build_input_is_rejected(self):
        source_sha = self._init_repo()
        self._write("desktop/.env.local", "VITE_FEATURE_FLAG=on\n")
        self._assert_rejected_before_build(source_sha, "Untracked or ignored files are present")

    def test_clean_head_builds_and_keeps_expected_ignored_caches(self):
        source_sha = self._init_repo()
        self._write("core/target/previous-build.bin", b"cache")
        self._write("desktop/node_modules/.package-lock.json", b"cache")
        self._write("desktop/src-tauri/gen/schemas/generated.json", b"generated")
        self._write("packaging/windows/local-note.txt", b"not a build input")
        output = self.root / "desktop/candidate output"
        target = self.root / "desktop/build cache"
        result, commands = self._run_build(source_sha, output=output, target=target)
        self.assertEqual(result["source_sha"], source_sha)
        self.assertEqual([command[0] for command in commands], ["cargo", "cargo", "npm.cmd"])
        self.assertTrue((output / "candidate.json").is_file())

    def test_input_changes_during_either_build_stage_fail_before_receipt(self):
        cases = (("cargo", "tracked"), ("npm", "tracked"), ("cargo", "untracked"))
        for changed_stage, change_kind in cases:
            with self.subTest(stage=changed_stage, kind=change_kind):
                case_name = f"{changed_stage}-{change_kind}"
                self.root = Path(self.temporary.name) / f"checkout {case_name}"
                self.root.mkdir()
                source_sha = self._init_repo()
                args = self._args(source_sha)
                args.output = str(Path(self.temporary.name) / f"candidate {case_name}")
                args.target_dir = str(Path(self.temporary.name) / f"cache {case_name}")
                commands = []

                def run_command(command, **kwargs):
                    commands.append(command)
                    if command[0] == "cargo":
                        artifact = Path(kwargs["env"]["CARGO_TARGET_DIR"]) / build_candidate.TARGET / "release/adapter-agent.exe"
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        artifact.write_bytes(b"mock agent")
                    else:
                        target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                        release = target / build_candidate.TARGET / "release"
                        release.mkdir(parents=True, exist_ok=True)
                        (release / "mullvad-adapter-desktop.exe").write_bytes(
                            b"MZ__TAURI_BUNDLE_TYPE_VAR_UNK\x00fixture"
                        )
                        installer = release / "bundle/nsis/MullvadAdapter-test.exe"
                        installer.parent.mkdir(parents=True, exist_ok=True)
                        installer.write_bytes(b"mock installer")
                    mutates_now = (
                        changed_stage == "cargo" and command[0] == "cargo"
                    ) or (changed_stage == "npm" and command[0] != "cargo")
                    if mutates_now:
                        if change_kind == "tracked":
                            changed_path = (
                                "core/crates/agent/src/main.rs"
                                if command[0] == "cargo"
                                else "desktop/src/main.ts"
                            )
                            self._write(changed_path, f"changed in {command[0]}\n")
                        else:
                            self._write("core/crates/agent/build.rs", "untracked during cargo\n")

                def fake_stage_runtime(_adapter, output_root, source_sha, _version, **_kwargs):
                    runtime = Path(output_root) / "runtime"
                    runtime.mkdir(parents=True)
                    (runtime / "manifest.json").write_text('{"schema":1}\n', encoding="utf-8")
                    (runtime / "mihomo.exe").write_bytes(b"mock mihomo")
                    return {"source_sha": source_sha}

                with (
                    mock.patch.object(build_candidate.sys, "platform", "win32"),
                    mock.patch.object(build_candidate.shutil, "which", return_value="npm.cmd"),
                    mock.patch.object(build_candidate, "stage_runtime", side_effect=fake_stage_runtime),
                    mock.patch.object(build_candidate, "require_upstream_long_paths"),                    mock.patch.object(build_candidate, "_validate_amd64_pe"),
                ):
                    with self.assertRaisesRegex(ValueError, "during the candidate build"):
                        build_candidate.build(args, source_root=self.root, command_runner=run_command)
                self.assertTrue(commands)
                self.assertFalse((Path(args.output) / "candidate.json").exists())


class UpstreamLongPathTests(unittest.TestCase):
    def test_requires_real_global_file_not_command_override_and_never_mutates_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "host.gitconfig"
            config.write_text("[core]\nlongpaths = false\n")
            with mock.patch.dict(os.environ, {
                "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.longpaths", "GIT_CONFIG_VALUE_0": "true",
            }):
                before = config.read_bytes()
                with self.assertRaisesRegex(ValueError, "no host setting was changed"):
                    build_candidate.require_upstream_long_paths(root)
                self.assertEqual(before, config.read_bytes())
                config.write_text("[core]\nlongpaths = true\n")
                before = config.read_bytes()
                build_candidate.require_upstream_long_paths(root)
                self.assertEqual(before, config.read_bytes())


if __name__ == "__main__":
    unittest.main()
