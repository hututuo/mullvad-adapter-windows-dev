//! Per-user application root resolved by Windows, not an environment override.
//! No existing ACLs are changed. Relocated/reparse ancestors are unsupported.
use crate::{windows_private::*, windows_runtime::PrivateRuntime};
use std::{io, path::PathBuf, ptr::null_mut};
use windows_sys::Win32::{
    Storage::FileSystem::*,
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

pub struct AppRoot {
    private: PrivateRuntime,
    // Reject renames/reparse replacement while sensitive children are open.
    _ancestors: Vec<Handle>,
}
impl AppRoot {
    pub fn open(scope: &str) -> io::Result<Self> {
        if scope.is_empty()
            || scope.len() > 48
            || !scope
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid());
        }
        let mut value = null_mut();
        let status =
            unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, null_mut(), &mut value) };
        if status < 0 || value.is_null() {
            return Err(io::Error::other("local_app_data_unavailable"));
        }
        let path = unsafe {
            let mut count = 0;
            while count < 32768 && *value.add(count) != 0 {
                count += 1;
            }
            let result = if count == 32768 {
                None
            } else {
                String::from_utf16(std::slice::from_raw_parts(value, count)).ok()
            };
            CoTaskMemFree(value.cast());
            PathBuf::from(result.ok_or_else(invalid)?)
        };
        if !local_root(&path) {
            return Err(invalid());
        }
        let mut ancestors = Vec::new();
        for directory in path.ancestors().filter(|p| p.parent().is_some()) {
            let file = checked(unsafe {
                CreateFileW(
                    path_wide(directory)?.as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            })?;
            let mut info = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(file.0, &mut info) } == 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(invalid());
            }
            ancestors.push(file);
        }
        let private = PrivateRuntime::open(&path.join(format!("MullvadAdapter-{scope}")))?;
        Ok(Self {
            private,
            _ancestors: ancestors,
        })
    }
    pub fn path(&self) -> &std::path::Path {
        self.private.path()
    }
}
