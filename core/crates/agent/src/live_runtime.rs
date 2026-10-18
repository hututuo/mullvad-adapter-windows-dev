//! Resolve and verify the packaged Windows runtime before any sidecar is launched.
//!
//! `PrivateRuntime` is a separate, private scratch/secret-input lease. This module
//! only reads the immutable install resource directory and never reads settings,
//! credentials, or transient input files.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

const MAX_RUNTIME_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_COMPATIBILITY_BYTES: u64 = 1024 * 1024;
const MAX_NOTICES_BYTES: u64 = 1024 * 1024;
const MAX_AGENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MIHOMO_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PE_HEADER_OFFSET: u64 = 1024 * 1024;
const PE_AMD64: u16 = 0x8664;
const PE32_PLUS: u16 = 0x020b;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const CHUNK_BYTES: usize = 64 * 1024;

const COMPONENTS: [&str; 4] = [
    "adapter-agent.exe",
    "mihomo.exe",
    "mihomo-compatibility.json",
    "THIRD_PARTY_NOTICES.txt",
];
const RUNTIME_ENTRIES: [&str; 5] = [
    "THIRD_PARTY_NOTICES.txt",
    "adapter-agent.exe",
    "manifest.json",
    "mihomo-compatibility.json",
    "mihomo.exe",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRuntime {
    pub runtime_dir: PathBuf,
    pub adapter_agent: PathBuf,
    pub mihomo: PathBuf,
    pub source_sha: String,
    pub version: String,
    pub mihomo_version: String,
}

#[derive(Clone, Debug)]
struct FileRecord {
    size: u64,
    sha256: String,
}

/// Use compiled identity and the directory containing the launched agent.
/// `ADAPTER_SOURCE_SHA` must be set by the build; absence fails closed.
pub fn resolve_process() -> io::Result<VerifiedRuntime> {
    let source_sha = option_env!("ADAPTER_SOURCE_SHA")
        .ok_or_else(|| invalid("runtime_build_source_sha_missing"))?;
    let verified = resolve_for_current_process(source_sha, env!("CARGO_PKG_VERSION"))?;
    // Independent compile-time pin of the exact officially verified x64 engine.
    // The unsigned manifest alone only establishes self-consistency.
    let record = FileRecord {
        size: 61_105_152,
        sha256: "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b".into(),
    };
    verify_hashed_file(&verified.mihomo, &record, MAX_MIHOMO_BYTES, Some("pe-x64"))?;
    Ok(verified)
}

/// Resolve runtime files for the current process using immutable build identity.
/// In debug builds, one explicit `--runtime-dir PATH` is accepted and goes through
/// the same verifier. Release builds reject that override.
pub fn resolve_for_current_process(
    expected_source_sha: &str,
    expected_version: &str,
) -> io::Result<VerifiedRuntime> {
    let executable =
        std::env::current_exe().map_err(|_| invalid("runtime_executable_unavailable"))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    resolve_from_args(&executable, &args, expected_source_sha, expected_version)
}

fn resolve_from_args(
    executable: &Path,
    args: &[OsString],
    expected_source_sha: &str,
    expected_version: &str,
) -> io::Result<VerifiedRuntime> {
    validate_expected_identity(expected_source_sha, expected_version)?;
    #[cfg(debug_assertions)]
    let mut runtime_override: Option<PathBuf> = None;
    #[cfg(not(debug_assertions))]
    let runtime_override: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == OsStr::new("--runtime-dir") {
            #[cfg(not(debug_assertions))]
            return Err(invalid("runtime_override_release_disabled"));

            #[cfg(debug_assertions)]
            {
                if runtime_override.is_some() {
                    return Err(invalid("runtime_override_duplicate"));
                }
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| invalid("runtime_override_path_missing"))?;
                let path = PathBuf::from(value);
                if !path.is_absolute() || has_parent_component(&path) {
                    return Err(invalid("runtime_override_path_invalid"));
                }
                runtime_override = Some(path);
                index += 1;
            }
        }
        index += 1;
    }

    let runtime_dir = match runtime_override {
        Some(path) => path,
        None => executable
            .parent()
            .ok_or_else(|| invalid("runtime_executable_parent_missing"))?
            .to_owned(),
    };
    verify_runtime_dir(&runtime_dir, expected_source_sha, expected_version)
}

/// Verify a directory produced by the runtime stager before returning launch paths.
/// The Tauri host may call this for `<install-root>/runtime`; the agent calls it on
/// its own executable directory. `PrivateRuntime` remains separate scratch state.
pub fn verify_runtime_dir(
    runtime_dir: &Path,
    expected_source_sha: &str,
    expected_version: &str,
) -> io::Result<VerifiedRuntime> {
    validate_expected_identity(expected_source_sha, expected_version)?;
    validate_existing_path(runtime_dir, false)?;
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(runtime_dir).map_err(|_| invalid("runtime_directory_unavailable"))? {
        let entry = entry.map_err(|_| invalid("runtime_directory_unreadable"))?;
        if names.len() >= RUNTIME_ENTRIES.len() {
            return Err(invalid("runtime_entries_mismatch"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("runtime_entry_name_invalid"))?;
        validate_existing_path(&entry.path(), true)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| invalid("runtime_entry_metadata_unavailable"))?;
        if is_reparse_or_symlink(&metadata) || !metadata.is_file() {
            return Err(invalid("runtime_entry_not_regular_file"));
        }
        names.insert(name);
    }
    let expected_names: BTreeSet<_> = RUNTIME_ENTRIES.into_iter().map(str::to_owned).collect();
    if names != expected_names {
        return Err(invalid("runtime_entries_mismatch"));
    }

    let manifest_path = runtime_dir.join("manifest.json");
    let manifest_bytes = read_bounded_file(&manifest_path, MAX_RUNTIME_MANIFEST_BYTES)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invalid("runtime_manifest_invalid_json"))?;
    let files = validate_runtime_manifest(&manifest, expected_source_sha, expected_version)?;

    let mut compatibility_bytes = None;
    for name in COMPONENTS {
        let record = files
            .get(name)
            .ok_or_else(|| invalid("runtime_manifest_file_missing"))?;
        let max = match name {
            "adapter-agent.exe" => MAX_AGENT_BYTES,
            "mihomo.exe" => MAX_MIHOMO_BYTES,
            "mihomo-compatibility.json" => MAX_COMPATIBILITY_BYTES,
            "THIRD_PARTY_NOTICES.txt" => MAX_NOTICES_BYTES,
            _ => return Err(invalid("runtime_manifest_file_unknown")),
        };
        let path = runtime_dir.join(name);
        match name {
            "adapter-agent.exe" | "mihomo.exe" => {
                verify_hashed_file(&path, record, max, Some("pe-x64"))?;
            }
            "mihomo-compatibility.json" => {
                compatibility_bytes = Some(read_verified_file(&path, record, max)?);
            }
            "THIRD_PARTY_NOTICES.txt" => {
                let _ = read_verified_file(&path, record, max)?;
            }
            _ => unreachable!("component list is static"),
        }
    }
    let mihomo_version = validate_compatibility_manifest(
        compatibility_bytes
            .as_deref()
            .ok_or_else(|| invalid("runtime_compatibility_missing"))?,
    )?;

    Ok(VerifiedRuntime {
        runtime_dir: runtime_dir.to_owned(),
        adapter_agent: runtime_dir.join("adapter-agent.exe"),
        mihomo: runtime_dir.join("mihomo.exe"),
        source_sha: expected_source_sha.to_ascii_lowercase(),
        version: expected_version.to_owned(),
        mihomo_version,
    })
}

fn validate_runtime_manifest(
    manifest: &Value,
    expected_source_sha: &str,
    expected_version: &str,
) -> io::Result<std::collections::BTreeMap<String, FileRecord>> {
    let root = object(Some(manifest), "runtime_manifest_not_object")?;
    require_keys(
        root,
        &[
            "schema",
            "source_sha",
            "version",
            "platform",
            "architecture",
            "signature",
            "files",
        ],
        "runtime_manifest_fields_invalid",
    )?;
    if number(root.get("schema"), "runtime_manifest_schema_invalid")? != 1 {
        return Err(invalid("runtime_manifest_schema_unsupported"));
    }
    let source_sha = string(root.get("source_sha"), "runtime_manifest_source_invalid")?;
    if !is_sha256_source(source_sha) || !source_sha.eq_ignore_ascii_case(expected_source_sha) {
        return Err(invalid("runtime_manifest_source_mismatch"));
    }
    if string(root.get("version"), "runtime_manifest_version_invalid")? != expected_version {
        return Err(invalid("runtime_manifest_version_mismatch"));
    }
    if string(root.get("platform"), "runtime_manifest_platform_invalid")? != "windows"
        || string(
            root.get("architecture"),
            "runtime_manifest_architecture_invalid",
        )? != "x86_64"
        || string(root.get("signature"), "runtime_manifest_signature_invalid")? != "NOT_RUN"
    {
        return Err(invalid("runtime_manifest_target_mismatch"));
    }

    let files = object(root.get("files"), "runtime_manifest_files_invalid")?;
    let expected: BTreeSet<_> = COMPONENTS.into_iter().map(str::to_owned).collect();
    let actual: BTreeSet<_> = files.keys().cloned().collect();
    if actual != expected {
        return Err(invalid("runtime_manifest_file_set_mismatch"));
    }
    let mut records = std::collections::BTreeMap::new();
    for (name, value) in files {
        let fields = object(Some(value), "runtime_manifest_file_invalid")?;
        require_keys(
            fields,
            &["size_bytes", "sha256"],
            "runtime_manifest_record_invalid",
        )?;
        let size = number(fields.get("size_bytes"), "runtime_manifest_size_invalid")?;
        let maximum = match name.as_str() {
            "adapter-agent.exe" => MAX_AGENT_BYTES,
            "mihomo.exe" => MAX_MIHOMO_BYTES,
            "mihomo-compatibility.json" => MAX_COMPATIBILITY_BYTES,
            "THIRD_PARTY_NOTICES.txt" => MAX_NOTICES_BYTES,
            _ => return Err(invalid("runtime_manifest_file_unknown")),
        };
        if size == 0 || size > maximum {
            return Err(invalid("runtime_manifest_size_out_of_bounds"));
        }
        let sha256 = string(fields.get("sha256"), "runtime_manifest_hash_invalid")?;
        if !is_sha256(sha256) {
            return Err(invalid("runtime_manifest_hash_invalid"));
        }
        records.insert(
            name.clone(),
            FileRecord {
                size,
                sha256: sha256.to_ascii_lowercase(),
            },
        );
    }
    Ok(records)
}

fn validate_compatibility_manifest(bytes: &[u8]) -> io::Result<String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("mihomo_compatibility_invalid_json"))?;
    let root = object(Some(&value), "mihomo_compatibility_not_object")?;
    if number(root.get("schema"), "mihomo_compatibility_schema_invalid")? != 1 {
        return Err(invalid("mihomo_compatibility_schema_unsupported"));
    }
    let version = string(root.get("version"), "mihomo_version_invalid")?;
    if !valid_version(version) {
        return Err(invalid("mihomo_version_invalid"));
    }
    let repository = string(root.get("repository"), "mihomo_repository_invalid")?;
    let source_tag = string(root.get("source_tag"), "mihomo_source_tag_invalid")?;
    let license = string(root.get("license"), "mihomo_license_invalid")?;
    let license_url = string(root.get("license_url"), "mihomo_license_url_invalid")?;
    if repository != "https://github.com/MetaCubeX/mihomo"
        || source_tag != format!("{repository}/tree/{version}")
        || license != "GPL-3.0"
        || license_url != format!("{repository}/blob/{version}/LICENSE")
    {
        return Err(invalid("mihomo_upstream_identity_mismatch"));
    }
    let assets = object(root.get("assets"), "mihomo_assets_invalid")?;
    let windows = object(assets.get("windows"), "mihomo_windows_asset_invalid")?;
    let expected_name = format!("mihomo-windows-amd64-compatible-{version}.zip");
    if string(windows.get("name"), "mihomo_windows_asset_name_invalid")? != expected_name {
        return Err(invalid("mihomo_windows_asset_name_mismatch"));
    }
    let bytes = number(windows.get("bytes"), "mihomo_windows_asset_size_invalid")?;
    let digest = string(windows.get("sha256"), "mihomo_windows_asset_hash_invalid")?;
    if bytes == 0 || bytes > MAX_ARCHIVE_BYTES || !is_sha256(digest) {
        return Err(invalid("mihomo_windows_asset_metadata_invalid"));
    }
    Ok(version.to_owned())
}

fn read_verified_file(path: &Path, record: &FileRecord, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path, maximum)?;
    let size = file
        .metadata()
        .map_err(|_| invalid("runtime_file_metadata_unavailable"))?
        .len();
    if size != record.size {
        return Err(invalid("runtime_file_size_mismatch"));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("runtime_file_read_failed"))?;
    if bytes.len() as u64 != size || !sha256_bytes(&bytes).eq_ignore_ascii_case(&record.sha256) {
        return Err(invalid("runtime_file_hash_mismatch"));
    }
    Ok(bytes)
}

fn verify_hashed_file(
    path: &Path,
    record: &FileRecord,
    maximum: u64,
    format: Option<&str>,
) -> io::Result<()> {
    let mut file = open_regular_file(path, maximum)?;
    let initial_metadata = file
        .metadata()
        .map_err(|_| invalid("runtime_file_metadata_unavailable"))?;
    if initial_metadata.len() != record.size {
        return Err(invalid("runtime_file_size_mismatch"));
    }
    if format == Some("pe-x64") {
        verify_pe_x64(&mut file, record.size)?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| invalid("runtime_file_seek_failed"))?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; CHUNK_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| invalid("runtime_file_read_failed"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > maximum || total > record.size {
            return Err(invalid("runtime_file_size_out_of_bounds"));
        }
        digest.update(&buffer[..count]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|_| invalid("runtime_file_metadata_unavailable"))?;
    if total != record.size || final_metadata.len() != initial_metadata.len() {
        return Err(invalid("runtime_file_size_mismatch"));
    }
    let actual = hex_lower(&digest.finalize());
    if !actual.eq_ignore_ascii_case(&record.sha256) {
        return Err(invalid("runtime_file_hash_mismatch"));
    }
    Ok(())
}

fn verify_pe_x64(file: &mut (impl Read + Seek), file_size: u64) -> io::Result<()> {
    if file_size < 90 {
        return Err(invalid("runtime_pe_too_small"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| invalid("runtime_pe_seek_failed"))?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos)
        .map_err(|_| invalid("runtime_pe_header_truncated"))?;
    if &dos[..2] != b"MZ" {
        return Err(invalid("runtime_pe_dos_signature_invalid"));
    }
    let offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    if !(64..=MAX_PE_HEADER_OFFSET).contains(&offset) || offset + 26 > file_size {
        return Err(invalid("runtime_pe_offset_invalid"));
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| invalid("runtime_pe_seek_failed"))?;
    let mut header = [0u8; 26];
    file.read_exact(&mut header)
        .map_err(|_| invalid("runtime_pe_header_truncated"))?;
    let machine = u16::from_le_bytes([header[4], header[5]]);
    let optional_size = u16::from_le_bytes([header[20], header[21]]);
    let optional_magic = u16::from_le_bytes([header[24], header[25]]);
    if &header[..4] != b"PE\0\0"
        || machine != PE_AMD64
        || optional_size < 2
        || optional_magic != PE32_PLUS
    {
        return Err(invalid("runtime_pe_not_amd64"));
    }
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path, maximum)?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid("runtime_file_metadata_unavailable"))?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(invalid("runtime_metadata_size_out_of_bounds"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("runtime_file_read_failed"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid("runtime_file_size_mismatch"));
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, maximum: u64) -> io::Result<File> {
    validate_existing_path(path, true)?;
    let before = fs::symlink_metadata(path).map_err(|_| invalid("runtime_file_unavailable"))?;
    if is_reparse_or_symlink(&before) || !before.is_file() || before.len() > maximum {
        return Err(invalid("runtime_file_not_regular"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself, never its target, then inspect the handle.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| invalid("runtime_file_open_failed"))?;
    let opened = file
        .metadata()
        .map_err(|_| invalid("runtime_file_metadata_unavailable"))?;
    if is_reparse_or_symlink(&opened) || !opened.is_file() || opened.len() > maximum {
        return Err(invalid("runtime_file_not_regular"));
    }
    Ok(file)
}

fn validate_existing_path(path: &Path, final_is_file: bool) -> io::Result<()> {
    if !path.is_absolute() || has_parent_component(path) {
        return Err(invalid("runtime_path_not_absolute"));
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| invalid("runtime_path_component_unavailable"))?;
        if is_reparse_or_symlink(&metadata) {
            return Err(invalid("runtime_path_reparse_component"));
        }
        if index == 0 {
            let expected_type = if final_is_file {
                metadata.is_file()
            } else {
                metadata.is_dir()
            };
            if !expected_type {
                return Err(invalid("runtime_path_final_type_invalid"));
            }
        }
    }
    Ok(())
}

fn is_reparse_or_symlink(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_expected_identity(source_sha: &str, version: &str) -> io::Result<()> {
    if !is_sha256_source(source_sha) || !valid_version(version) {
        return Err(invalid("runtime_expected_identity_invalid"));
    }
    Ok(())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|part| matches!(part, Component::ParentDir))
        || path
            .as_os_str()
            .to_string_lossy()
            .split(['/', '\\'])
            .any(|part| part == "..")
}

fn is_sha256_source(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn object<'a>(value: Option<&'a Value>, code: &'static str) -> io::Result<&'a Map<String, Value>> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(code))
}

fn require_keys(
    object: &Map<String, Value>,
    expected: &[&str],
    code: &'static str,
) -> io::Result<()> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid(code));
    }
    Ok(())
}

fn string<'a>(value: Option<&'a Value>, code: &'static str) -> io::Result<&'a str> {
    value.and_then(Value::as_str).ok_or_else(|| invalid(code))
}

fn number(value: Option<&Value>, code: &'static str) -> io::Result<u64> {
    value.and_then(Value::as_u64).ok_or_else(|| invalid(code))
}

fn invalid(code: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        io::Cursor,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let ticks = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "adapter-live-runtime-{}-{ticks}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&PE_AMD64.to_le_bytes());
        bytes[84..86].copy_from_slice(&2u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&PE32_PLUS.to_le_bytes());
        bytes
    }

    fn record(bytes: &[u8]) -> Value {
        json!({
            "size_bytes": bytes.len(),
            "sha256": sha256_bytes(bytes),
        })
    }

    fn compatibility() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": 1,
            "version": "v1.19.31",
            "repository": "https://github.com/MetaCubeX/mihomo",
            "source_tag": "https://github.com/MetaCubeX/mihomo/tree/v1.19.31",
            "license": "GPL-3.0",
            "license_url": "https://github.com/MetaCubeX/mihomo/blob/v1.19.31/LICENSE",
            "purpose": "synthetic configuration parser CI only; not bundled or installed",
            "assets": {"windows": {
                "name": "mihomo-windows-amd64-compatible-v1.19.31.zip",
                "bytes": 22_460_803,
                "sha256": "93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218"
            }}
        }))
        .unwrap()
    }

    fn write_fixture(root: &Path) -> String {
        let agent = make_pe();
        let mihomo = make_pe();
        let compat = compatibility();
        let notices = b"GPL-3.0 notice".to_vec();
        fs::write(root.join("adapter-agent.exe"), &agent).unwrap();
        fs::write(root.join("mihomo.exe"), &mihomo).unwrap();
        fs::write(root.join("mihomo-compatibility.json"), &compat).unwrap();
        fs::write(root.join("THIRD_PARTY_NOTICES.txt"), &notices).unwrap();
        let source = "a".repeat(40);
        let manifest = json!({
            "schema": 1,
            "source_sha": source,
            "version": "0.1.0",
            "platform": "windows",
            "architecture": "x86_64",
            "signature": "NOT_RUN",
            "files": {
                "adapter-agent.exe": record(&agent),
                "mihomo.exe": record(&mihomo),
                "mihomo-compatibility.json": record(&compat),
                "THIRD_PARTY_NOTICES.txt": record(&notices),
            }
        });
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        source
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pe_check_requires_amd64_and_pe32_plus_headers() {
        let bytes = make_pe();
        verify_pe_x64(&mut Cursor::new(bytes.clone()), bytes.len() as u64).unwrap();
        let mut x86 = bytes.clone();
        x86[68..70].copy_from_slice(&0x014cu16.to_le_bytes());
        assert_eq!(
            verify_pe_x64(&mut Cursor::new(x86.clone()), x86.len() as u64)
                .unwrap_err()
                .to_string(),
            "runtime_pe_not_amd64"
        );
        let mut pe32 = bytes;
        pe32[88..90].copy_from_slice(&0x010bu16.to_le_bytes());
        assert!(verify_pe_x64(&mut Cursor::new(pe32.clone()), pe32.len() as u64).is_err());
    }

    #[test]
    fn runtime_manifest_requires_matching_source_version_and_target() {
        let source = "b".repeat(40);
        let mut manifest = json!({
            "schema": 1,
            "source_sha": source,
            "version": "0.1.0",
            "platform": "windows",
            "architecture": "x86_64",
            "signature": "NOT_RUN",
            "files": {
                "adapter-agent.exe": {"size_bytes": 1, "sha256": "0".repeat(64)},
                "mihomo.exe": {"size_bytes": 1, "sha256": "0".repeat(64)},
                "mihomo-compatibility.json": {"size_bytes": 1, "sha256": "0".repeat(64)},
                "THIRD_PARTY_NOTICES.txt": {"size_bytes": 1, "sha256": "0".repeat(64)},
            }
        });
        assert!(validate_runtime_manifest(&manifest, &source, "0.1.0").is_ok());
        manifest["source_sha"] = json!("c".repeat(40));
        assert!(validate_runtime_manifest(&manifest, &source, "0.1.0").is_err());
        manifest["source_sha"] = json!(source);
        manifest["version"] = json!("0.1.1");
        assert!(validate_runtime_manifest(&manifest, &source, "0.1.0").is_err());
        manifest["version"] = json!("0.1.0");
        manifest["architecture"] = json!("aarch64");
        assert!(validate_runtime_manifest(&manifest, &source, "0.1.0").is_err());
        manifest["architecture"] = json!("x86_64");
        let traversing_record = manifest["files"]["mihomo.exe"].clone();
        manifest["files"]["../mihomo.exe"] = traversing_record;
        assert!(validate_runtime_manifest(&manifest, &source, "0.1.0").is_err());
    }

    #[test]
    fn complete_runtime_fixture_is_verified_before_returning_paths() {
        let temp = TempDir::new();
        let runtime = temp.0.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        let result = verify_runtime_dir(&runtime, &source, "0.1.0").unwrap();
        assert_eq!(result.adapter_agent, runtime.join("adapter-agent.exe"));
        assert_eq!(result.mihomo, runtime.join("mihomo.exe"));
        assert_eq!(result.source_sha, source);
        assert_eq!(result.version, "0.1.0");
        assert_eq!(result.mihomo_version, "v1.19.31");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn development_override_is_explicit_absolute_and_unique() {
        let temp = TempDir::new();
        let runtime = temp.0.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        let exe = temp.0.join("adapter-agent.exe");
        fs::write(&exe, make_pe()).unwrap();

        let args = vec![
            OsString::from("--runtime-dir"),
            runtime.as_os_str().to_owned(),
        ];
        let resolved = resolve_from_args(&exe, &args, &source, "0.1.0").unwrap();
        assert_eq!(resolved.runtime_dir, runtime);

        let relative = vec![OsString::from("--runtime-dir"), OsString::from("runtime")];
        assert_eq!(
            resolve_from_args(&exe, &relative, &source, "0.1.0")
                .unwrap_err()
                .to_string(),
            "runtime_override_path_invalid"
        );
        // PathBuf::join normalizes `..` for Windows verbatim prefixes. Build the
        // raw command argument so this tests traversal input on both platforms.
        let mut raw_traversal = runtime.as_os_str().to_owned();
        raw_traversal.push(std::path::MAIN_SEPARATOR_STR);
        raw_traversal.push("..");
        raw_traversal.push(std::path::MAIN_SEPARATOR_STR);
        raw_traversal.push("runtime");
        let traversal = vec![OsString::from("--runtime-dir"), raw_traversal];
        assert_eq!(
            resolve_from_args(&exe, &traversal, &source, "0.1.0")
                .unwrap_err()
                .to_string(),
            "runtime_override_path_invalid"
        );
        let duplicate = vec![
            OsString::from("--runtime-dir"),
            runtime.as_os_str().to_owned(),
            OsString::from("--runtime-dir"),
            runtime.as_os_str().to_owned(),
        ];
        assert_eq!(
            resolve_from_args(&exe, &duplicate, &source, "0.1.0")
                .unwrap_err()
                .to_string(),
            "runtime_override_duplicate"
        );
    }

    #[test]
    fn tampered_binary_wrong_architecture_and_unmanifested_files_fail_closed() {
        let temp = TempDir::new();
        let runtime = temp.0.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        fs::write(runtime.join("mihomo.exe"), b"changed").unwrap();
        assert!(verify_runtime_dir(&runtime, &source, "0.1.0").is_err());

        fs::remove_dir_all(&runtime).unwrap();
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        let mut x86 = make_pe();
        x86[68..70].copy_from_slice(&0x014cu16.to_le_bytes());
        fs::write(runtime.join("mihomo.exe"), &x86).unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(runtime.join("manifest.json")).unwrap()).unwrap();
        manifest["files"]["mihomo.exe"] = record(&x86);
        fs::write(
            runtime.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_runtime_dir(&runtime, &source, "0.1.0").is_err());

        fs::remove_dir_all(&runtime).unwrap();
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        fs::write(runtime.join("extra.exe"), make_pe()).unwrap();
        assert!(verify_runtime_dir(&runtime, &source, "0.1.0").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_runtime_component_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new();
        let runtime = temp.0.join("runtime");
        fs::create_dir(&runtime).unwrap();
        let source = write_fixture(&runtime);
        let target = temp.0.join("target.exe");
        fs::write(&target, make_pe()).unwrap();
        fs::remove_file(runtime.join("mihomo.exe")).unwrap();
        symlink(target, runtime.join("mihomo.exe")).unwrap();
        assert!(verify_runtime_dir(&runtime, &source, "0.1.0").is_err());
    }
}
