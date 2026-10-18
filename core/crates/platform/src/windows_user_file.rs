//! Application data writers use the durable user SID, never a logon SID.
//! Caller must establish trusted parent directories. Existing ACLs are not repaired.
use super::{windows::Identity, windows_private::*};
use std::{fs::File, io, mem::zeroed, path::Path, ptr::null_mut};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

pub fn open_writer(path: &Path, append: bool, exclusive: bool) -> io::Result<File> {
    if !local_root(path) {
        return Err(invalid());
    }
    let identity = Identity::current()?;
    let sid = identity.sid_for_storage();
    let descriptor = Descriptor::new(sid)?;
    let attributes = descriptor.attributes();
    let handle = checked(unsafe {
        CreateFileW(
            path_wide(path)?.as_ptr(),
            if append {
                FILE_APPEND_DATA | FILE_READ_ATTRIBUTES
            } else {
                GENERIC_READ | GENERIC_WRITE
            },
            FILE_SHARE_READ,
            &attributes,
            if exclusive { CREATE_NEW } else { OPEN_ALWAYS },
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    })?;
    // OPEN_ALWAYS preserves existing bytes. Validate before any write/truncation.
    let mut info = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;
        let raw = handle.0;
        std::mem::forget(handle);
        Ok(unsafe { File::from_raw_handle(raw.cast()) })
    }
    #[cfg(not(windows))]
    Err(io::Error::other("windows_only"))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::{io::Write, os::windows::io::AsRawHandle};

    #[test]
    fn new_files_are_private_to_durable_user_and_existing_bytes_are_preserved() {
        let root = std::env::temp_dir().join(format!(
            "adapter-user-file-{}",
            super::super::windows::boot_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("events.jsonl");
        let sid = Identity::current().unwrap().sid_for_storage().to_owned();
        {
            let mut file = open_writer(&path, false, true).unwrap();
            require_private(file.as_raw_handle().cast(), &sid, false).unwrap();
            file.write_all(b"first\n").unwrap();
        }
        assert!(open_writer(&path, false, true).is_err());
        {
            let mut file = open_writer(&path, true, false).unwrap();
            file.write_all(b"second\n").unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
        let link = root.join("alias.jsonl");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(open_writer(&path, false, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
