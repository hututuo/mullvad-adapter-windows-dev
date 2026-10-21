//! Per-user Windows login startup registration for this application only.
//!
//! Reads never create or repair the Run key. Mutations inspect the existing
//! value first and refuse to replace or remove a command owned by another exe.

#[cfg(any(windows, feature = "windows-api-check"))]
const STARTUP_VALUE_NAME: &str = "Mullvad Adapter";
#[cfg(any(windows, feature = "windows-api-check"))]
const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
#[cfg(any(windows, feature = "windows-api-check"))]
const WIDGET_KEY_PATH: &str = "Software\\MullvadAdapter\\Desktop";
#[cfg(any(windows, feature = "windows-api-check"))]
const WIDGET_VALUE_NAME: &str = "StatusWidget";
const REG_DWORD_KIND: u32 = 4;
const AUTOSTART_ARGUMENT: &[u16] = &[
    b' ' as u16,
    b'-' as u16,
    b'-' as u16,
    b'a' as u16,
    b'u' as u16,
    b't' as u16,
    b'o' as u16,
    b's' as u16,
    b't' as u16,
    b'a' as u16,
    b'r' as u16,
    b't' as u16,
];
const MAX_RUN_COMMAND_UTF16_UNITS: usize = 260;

/// Build the exact quoted Run command for an executable path, including its
/// terminating UTF-16 NUL. Kept platform-independent so command boundaries
/// can be tested on non-Windows hosts.
fn command_for_executable(executable: &[u16]) -> Result<Vec<u16>, &'static str> {
    if executable.is_empty()
        || executable
            .iter()
            .any(|unit| *unit == 0 || *unit == b'"' as u16)
    {
        return Err("startup_command_invalid");
    }

    let command_len = 1 + executable.len() + 1 + AUTOSTART_ARGUMENT.len();
    // The Run command limit is applied to the whole stored REG_SZ, including
    // its terminator, to stay within the documented 260 UTF-16 unit bound.
    if command_len + 1 > MAX_RUN_COMMAND_UTF16_UNITS {
        return Err("startup_command_too_long");
    }

    let mut command = Vec::with_capacity(command_len + 1);
    command.push(b'"' as u16);
    command.extend_from_slice(executable);
    command.push(b'"' as u16);
    command.extend_from_slice(AUTOSTART_ARGUMENT);
    command.push(0);
    Ok(command)
}

/// Check whether a Run command's executable token is this executable.
/// Command arguments are deliberately ignored for ownership: older versions
/// may have stored different arguments, but they are still this app's value.
fn command_belongs_to_executable(command: &[u16], executable: &[u16]) -> bool {
    if command.is_empty()
        || executable.is_empty()
        || command.iter().any(|unit| *unit == 0)
        || executable
            .iter()
            .any(|unit| *unit == 0 || *unit == b'"' as u16)
    {
        return false;
    }

    let token = if command[0] == b'"' as u16 {
        let Some(close_quote) = command[1..].iter().position(|unit| *unit == b'"' as u16) else {
            return false;
        };
        let token_end = close_quote + 1;
        let rest = &command[token_end + 1..];
        if !rest.is_empty() && rest[0] != b' ' as u16 && rest[0] != b'\t' as u16 {
            return false;
        }
        &command[1..token_end]
    } else {
        let token_end = command
            .iter()
            .position(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16)
            .unwrap_or(command.len());
        &command[..token_end]
    };
    token == executable
}

fn decode_widget_preference(kind: u32, bytes: &[u8]) -> Result<bool, &'static str> {
    if kind != REG_DWORD_KIND || bytes.len() != 4 {
        return Err("widget_preference_invalid");
    }
    match u32::from_le_bytes(bytes.try_into().expect("length checked")) {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("widget_preference_invalid"),
    }
}

#[cfg(windows)]
pub fn status() -> Result<bool, String> {
    registry::status()
}

#[cfg(not(windows))]
pub fn status() -> Result<bool, String> {
    Err("startup_unsupported".to_owned())
}

#[cfg(windows)]
pub fn set_enabled(enabled: bool) -> Result<bool, String> {
    registry::set_enabled(enabled)
}

#[cfg(not(windows))]
pub fn set_enabled(_enabled: bool) -> Result<bool, String> {
    Err("startup_unsupported".to_owned())
}

#[cfg(windows)]
pub fn widget_enabled() -> Result<bool, String> {
    registry::widget_enabled()
}

#[cfg(not(windows))]
pub fn widget_enabled() -> Result<bool, String> {
    Err("startup_unsupported".to_owned())
}

#[cfg(windows)]
pub fn set_widget_enabled(enabled: bool) -> Result<bool, String> {
    registry::set_widget_enabled(enabled)
}

#[cfg(not(windows))]
pub fn set_widget_enabled(_enabled: bool) -> Result<bool, String> {
    Err("startup_unsupported".to_owned())
}

#[cfg(any(windows, feature = "windows-api-check"))]
#[allow(dead_code)]
mod registry {
    use super::{
        command_belongs_to_executable, command_for_executable, decode_widget_preference,
        MAX_RUN_COMMAND_UTF16_UNITS, REG_DWORD_KIND, RUN_KEY_PATH, STARTUP_VALUE_NAME,
        WIDGET_KEY_PATH, WIDGET_VALUE_NAME,
    };
    use std::mem::size_of;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND},
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
            RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD,
            REG_OPTION_NON_VOLATILE, REG_SZ,
        },
    };

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    enum ValueRead {
        Missing,
        Present { kind: u32, units: Vec<u16> },
    }

    fn registry_error(code: u32) -> String {
        format!("startup_registry_error:{code}")
    }

    fn conflict() -> String {
        "startup_entry_conflict".to_owned()
    }

    fn verification_failed() -> String {
        "startup_verification_failed".to_owned()
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    #[cfg(windows)]
    fn current_executable() -> Result<Vec<u16>, String> {
        let path =
            std::env::current_exe().map_err(|_| "startup_executable_unavailable".to_owned())?;
        let executable: Vec<u16> = path.as_os_str().encode_wide().collect();
        if executable.is_empty() || executable.iter().any(|unit| *unit == 0) {
            return Err("startup_command_invalid".to_owned());
        }
        Ok(executable)
    }

    #[cfg(all(not(windows), feature = "windows-api-check"))]
    fn current_executable() -> Result<Vec<u16>, String> {
        Err("startup_unsupported".to_owned())
    }

    fn open_key(path: &str, access: u32, create: bool) -> Result<Option<RegistryKey>, String> {
        let path = wide_nul(path);
        let mut handle = std::ptr::null_mut();
        let result = unsafe {
            if create {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    access,
                    std::ptr::null(),
                    &mut handle,
                    std::ptr::null_mut(),
                )
            } else {
                RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut handle)
            }
        };
        if result == 0 {
            Ok(Some(RegistryKey(handle)))
        } else if !create && matches!(result, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            Ok(None)
        } else {
            Err(registry_error(result))
        }
    }

    fn read_value(key: &RegistryKey) -> Result<ValueRead, String> {
        let name = wide_nul(STARTUP_VALUE_NAME);
        let mut kind = 0u32;
        let mut bytes = 0u32;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(ValueRead::Missing);
        }
        if result != 0 {
            return Err(registry_error(result));
        }

        let max_bytes = (MAX_RUN_COMMAND_UTF16_UNITS * size_of::<u16>()) as u32;
        if bytes == 0 || bytes > max_bytes || bytes as usize % size_of::<u16>() != 0 {
            return Err(conflict());
        }

        let mut data = vec![0u16; bytes as usize / size_of::<u16>()];
        let mut read_kind = 0u32;
        let mut read_bytes = bytes;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut read_kind,
                data.as_mut_ptr().cast(),
                &mut read_bytes,
            )
        };
        if result == ERROR_MORE_DATA {
            return Err(conflict());
        }
        if result != 0 {
            return Err(registry_error(result));
        }
        if read_kind != kind
            || read_bytes != bytes
            || data.last().copied() != Some(0)
            || data[..data.len() - 1].iter().any(|unit| *unit == 0)
        {
            return Err(conflict());
        }
        data.pop();
        Ok(ValueRead::Present {
            kind: read_kind,
            units: data,
        })
    }

    fn present_is_owned<'a>(
        value: &'a ValueRead,
        executable: &[u16],
    ) -> Result<Option<&'a [u16]>, String> {
        match value {
            ValueRead::Missing => Ok(None),
            ValueRead::Present { kind, .. } if *kind != REG_SZ => Err(conflict()),
            ValueRead::Present { units, .. } => {
                if command_belongs_to_executable(units, executable) {
                    Ok(Some(units))
                } else {
                    Err(conflict())
                }
            }
        }
    }

    fn expected_command(executable: &[u16]) -> Result<Vec<u16>, String> {
        command_for_executable(executable).map_err(str::to_owned)
    }

    pub(super) fn status() -> Result<bool, String> {
        let Some(key) = open_key(RUN_KEY_PATH, KEY_QUERY_VALUE, false)? else {
            return Ok(false);
        };
        let value = read_value(&key)?;
        if matches!(value, ValueRead::Missing) {
            return Ok(false);
        }
        let executable = current_executable()?;
        Ok(present_is_owned(&value, &executable)?.is_some())
    }

    pub(super) fn set_enabled(enabled: bool) -> Result<bool, String> {
        if enabled {
            enable()
        } else {
            disable()
        }
    }

    fn enable() -> Result<bool, String> {
        let executable = current_executable()?;
        let expected = expected_command(&executable)?;
        let key = open_key(RUN_KEY_PATH, KEY_QUERY_VALUE | KEY_SET_VALUE, true)?
            .ok_or_else(|| "startup_registry_unavailable".to_owned())?;
        let value = read_value(&key)?;
        let existing = present_is_owned(&value, &executable)?;
        let expected_body = &expected[..expected.len() - 1];
        if existing == Some(expected_body) {
            return Ok(true);
        }

        let name = wide_nul(STARTUP_VALUE_NAME);
        let data_bytes = (expected.len() * size_of::<u16>()) as u32;
        let result = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                expected.as_ptr().cast(),
                data_bytes,
            )
        };
        if result != 0 {
            return Err(registry_error(result));
        }

        match read_value(&key)? {
            ValueRead::Present { kind, units }
                if kind == REG_SZ && units.as_slice() == expected_body =>
            {
                Ok(true)
            }
            ValueRead::Present { units, .. }
                if command_belongs_to_executable(&units, &executable) =>
            {
                Err(verification_failed())
            }
            ValueRead::Present { .. } => Err(conflict()),
            ValueRead::Missing => Err(verification_failed()),
        }
    }

    fn disable() -> Result<bool, String> {
        let Some(key) = open_key(RUN_KEY_PATH, KEY_QUERY_VALUE | KEY_SET_VALUE, false)? else {
            return Ok(false);
        };
        let value = read_value(&key)?;
        if matches!(value, ValueRead::Missing) {
            return Ok(false);
        }
        let executable = current_executable()?;
        present_is_owned(&value, &executable)?;

        let name = wide_nul(STARTUP_VALUE_NAME);
        let result = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        if result != 0 {
            return Err(registry_error(result));
        }

        match read_value(&key)? {
            ValueRead::Missing => Ok(false),
            ValueRead::Present { units, .. }
                if command_belongs_to_executable(&units, &executable) =>
            {
                Err(verification_failed())
            }
            ValueRead::Present { .. } => Err(conflict()),
        }
    }

    fn read_widget_preference(key: &RegistryKey) -> Result<Option<bool>, String> {
        let name = wide_nul(WIDGET_VALUE_NAME);
        let mut kind = 0u32;
        let mut bytes = 0u32;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if result != 0 {
            return Err(registry_error(result));
        }
        if kind != REG_DWORD || bytes != 4 {
            return Err("widget_preference_invalid".to_owned());
        }

        let mut data = [0u8; 4];
        let mut read_kind = 0u32;
        let mut read_bytes = data.len() as u32;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut read_kind,
                data.as_mut_ptr(),
                &mut read_bytes,
            )
        };
        if result == ERROR_MORE_DATA || read_kind != kind || read_bytes != bytes {
            return Err("widget_preference_invalid".to_owned());
        }
        if result != 0 {
            return Err(registry_error(result));
        }
        decode_widget_preference(REG_DWORD_KIND, &data)
            .map(Some)
            .map_err(str::to_owned)
    }

    pub(super) fn widget_enabled() -> Result<bool, String> {
        let Some(key) = open_key(WIDGET_KEY_PATH, KEY_QUERY_VALUE, false)? else {
            return Ok(false);
        };
        Ok(read_widget_preference(&key)?.unwrap_or(false))
    }

    pub(super) fn set_widget_enabled(enabled: bool) -> Result<bool, String> {
        let key = open_key(WIDGET_KEY_PATH, KEY_QUERY_VALUE | KEY_SET_VALUE, true)?
            .ok_or_else(|| "startup_registry_unavailable".to_owned())?;
        let current = read_widget_preference(&key)?;
        if current == Some(enabled) {
            return Ok(enabled);
        }

        let name = wide_nul(WIDGET_VALUE_NAME);
        let value = u32::from(enabled).to_le_bytes();
        let result = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_DWORD,
                value.as_ptr(),
                value.len() as u32,
            )
        };
        if result != 0 {
            return Err(registry_error(result));
        }
        match read_widget_preference(&key)? {
            Some(read_back) if read_back == enabled => Ok(enabled),
            Some(_) | None => Err(verification_failed()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        command_belongs_to_executable, command_for_executable, decode_widget_preference,
        REG_DWORD_KIND,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn command_is_exactly_quoted_and_terminated() {
        let command = command_for_executable(&wide(r"C:\Apps\Mullvad Adapter\adapter.exe"))
            .expect("command should fit the Run limit");
        let expected = wide(r#""C:\Apps\Mullvad Adapter\adapter.exe" --autostart"#);
        assert_eq!(&command[..command.len() - 1], expected);
        assert_eq!(command.last(), Some(&0));
    }

    #[test]
    fn command_rejects_nul_quotes_and_run_limit_overflow() {
        assert_eq!(
            command_for_executable(&[b'a' as u16, 0]),
            Err("startup_command_invalid")
        );
        assert_eq!(
            command_for_executable(&[b'a' as u16, b'"' as u16]),
            Err("startup_command_invalid")
        );

        // Prefix/suffix plus NUL consume 15 units, leaving 245 path units.
        let too_long = vec![b'x' as u16; 246];
        assert_eq!(
            command_for_executable(&too_long),
            Err("startup_command_too_long")
        );
    }

    #[test]
    fn ownership_uses_the_executable_token_and_not_arguments() {
        let executable = wide(r"C:\Apps\Mullvad Adapter\adapter.exe");
        let owned = wide(r#""C:\Apps\Mullvad Adapter\adapter.exe" --old-flag"#);
        let canonical = wide(r#""C:\Apps\Mullvad Adapter\adapter.exe" --autostart"#);
        let foreign = wide(r#""C:\Other\adapter.exe" --autostart"#);
        assert!(command_belongs_to_executable(&owned, &executable));
        assert!(command_belongs_to_executable(&canonical, &executable));
        assert!(!command_belongs_to_executable(&foreign, &executable));
    }

    #[test]
    fn ownership_rejects_malformed_commands() {
        let executable = wide(r"C:\Apps\adapter.exe");
        assert!(!command_belongs_to_executable(
            &wide(r#""C:\Apps\adapter.exe"x"#),
            &executable
        ));
        assert!(!command_belongs_to_executable(
            &[b'a' as u16, 0, b'b' as u16],
            &[b'a' as u16]
        ));
    }

    #[test]
    fn widget_preference_accepts_only_registry_dword_boolean_values() {
        assert_eq!(
            decode_widget_preference(REG_DWORD_KIND, &0u32.to_le_bytes()),
            Ok(false)
        );
        assert_eq!(
            decode_widget_preference(REG_DWORD_KIND, &1u32.to_le_bytes()),
            Ok(true)
        );
        assert_eq!(
            decode_widget_preference(REG_DWORD_KIND, &2u32.to_le_bytes()),
            Err("widget_preference_invalid")
        );
        assert_eq!(
            decode_widget_preference(3, &1u32.to_le_bytes()),
            Err("widget_preference_invalid")
        );
        assert_eq!(
            decode_widget_preference(REG_DWORD_KIND, &[1, 0, 0]),
            Err("widget_preference_invalid")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn registry_api_is_explicitly_unsupported_off_windows() {
        assert_eq!(super::status(), Err("startup_unsupported".to_owned()));
        assert_eq!(
            super::set_enabled(true),
            Err("startup_unsupported".to_owned())
        );
        assert_eq!(
            super::set_enabled(false),
            Err("startup_unsupported".to_owned())
        );
        assert_eq!(
            super::widget_enabled(),
            Err("startup_unsupported".to_owned())
        );
        assert_eq!(
            super::set_widget_enabled(true),
            Err("startup_unsupported".to_owned())
        );
    }
}
