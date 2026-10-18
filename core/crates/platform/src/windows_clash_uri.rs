//! Closed native protocol launch, no command shell or arbitrary URL support.
use std::io;
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn open(uri: &str) -> io::Result<()> {
    if uri.len() > 2048
        || !uri.starts_with("clash://install-config?url=http%3A%2F%2F127.0.0.1%3A")
        || uri.chars().any(|c| c.is_control() || c == '"' || c == '\'')
    {
        return Err(io::Error::other("clash_import_uri_invalid"));
    }
    launch(uri)
}

/// A closed, official download destination. Installation stays in the vendor's
/// installer, including elevation and prerequisites; no downloaded code is run
/// silently by this adapter.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn open_download_page() -> io::Result<()> {
    launch("https://github.com/clash-verge-rev/clash-verge-rev/releases/latest")
}

#[cfg(any(windows, feature = "windows-api-check"))]
fn launch(target: &str) -> io::Result<()> {
    let value: Vec<_> = target.encode_utf16().chain(Some(0)).collect();
    let verb: Vec<_> = "open".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            value.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };
    if result as isize <= 32 {
        Err(io::Error::other("clash_import_handler_missing"))
    } else {
        Ok(())
    }
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub fn installation() -> io::Result<(bool, bool)> {
    use windows_sys::Win32::{
        Foundation::LocalFree, System::Registry::*, UI::Shell::CommandLineToArgvW,
    };
    let key: Vec<_> = "clash\\shell\\open\\command"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut bytes = 0u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_CLASSES_ROOT,
            key.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    let mut protocol = false;
    let mut registered_app = false;
    if result == 0 && bytes > 2 && bytes <= 8192 && bytes % 2 == 0 {
        let mut command = vec![0u16; bytes as usize / 2];
        let result = unsafe {
            RegGetValueW(
                HKEY_CLASSES_ROOT,
                key.as_ptr(),
                std::ptr::null(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                std::ptr::null_mut(),
                command.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if result != 0 {
            return Err(io::Error::other("clash_detection_unavailable"));
        }
        protocol = command.first().copied().unwrap_or(0) != 0;
        let mut count = 0;
        let argv = unsafe { CommandLineToArgvW(command.as_ptr(), &mut count) };
        if !argv.is_null() {
            if count > 0 {
                let first = unsafe { *argv };
                let mut length = 0;
                while length < 4096 && unsafe { *first.add(length) } != 0 {
                    length += 1;
                }
                if length < 4096 {
                    let text = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(first, length)
                    });
                    let path = std::path::Path::new(&text);
                    registered_app = path.is_absolute()
                        && path.is_file()
                        && path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                            matches!(
                                s.to_ascii_lowercase().as_str(),
                                "clash-verge.exe" | "clash-verge-rev.exe"
                            )
                        });
                }
            }
            unsafe {
                LocalFree(argv.cast());
            }
        }
    } else if !matches!(result, 0 | 2 | 3) {
        return Err(io::Error::other("clash_detection_unavailable"));
    }
    let conventional = ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|root| {
            [
                "Clash Verge/clash-verge.exe",
                "Programs/Clash Verge/clash-verge.exe",
            ]
            .iter()
            .any(|suffix| std::path::Path::new(&root).join(suffix).is_file())
        });
    Ok((registered_app || conventional, protocol))
}
