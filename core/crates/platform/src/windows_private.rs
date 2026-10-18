//! Shared private-object ACL/type checks; caller must establish trusted ancestors.
use std::{
    ffi::c_void,
    io,
    mem::{size_of, zeroed},
    path::{Component, Path, Prefix},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
};
pub(crate) struct Handle(pub(crate) HANDLE);
// Public owners use directory/lock handles as lifetime guards; data handles have
// no public concurrent offset mutation. Mutable initialization is exclusive, and
// prepared stdin is consumed by a single launch.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub(crate) fn checked(h: HANDLE) -> io::Result<Handle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(h))
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub(crate) fn path_wide(p: &Path) -> io::Result<Vec<u16>> {
    let s = p.to_str().ok_or_else(invalid)?;
    if s.contains('\0') {
        return Err(invalid());
    }
    Ok(wide(s))
}
pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid private store")
}
pub(crate) struct Descriptor(Local);
impl Descriptor {
    pub(crate) fn new(sid: &str) -> io::Result<Self> {
        let text = wide(&format!("O:{sid}D:P(A;;FA;;;{sid})"));
        let mut p = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut p,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Local(p)))
    }
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: 0,
        }
    }
}
pub(crate) fn require_private(handle: HANDLE, sid: &str, directory: bool) -> io::Result<()> {
    unsafe {
        let mut metadata: BY_HANDLE_FILE_INFORMATION = zeroed();
        if GetFileInformationByHandle(handle, &mut metadata) == 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err(invalid());
        }
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        let status = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = Local(descriptor);
        let mut expected = null_mut();
        if ConvertStringSidToSidW(wide(sid).as_ptr(), &mut expected) == 0 {
            return Err(io::Error::last_os_error());
        }
        let _expected = Local(expected);
        let mut control = 0;
        let mut revision = 0;
        if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
            return Err(io::Error::last_os_error());
        }
        if owner.is_null()
            || EqualSid(owner, expected) == 0
            || acl.is_null()
            || (*acl).AceCount != 1
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(invalid());
        }
        let mut ace = null_mut();
        if GetAce(acl, 0, &mut ace) == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = &*(ace as *const ACE_HEADER);
        // Validate the variable-sized ACE before accessing its mask or SID.
        // An exact expected SID length also rejects trailing/short ACE payloads.
        if usize::from(header.AceSize) != 8 + GetLengthSid(expected) as usize {
            return Err(invalid());
        }
        let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
        if u32::from(ace.Header.AceType)
            != windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE
            || ace.Header.AceFlags != 0
            || ace.Mask != FILE_ALL_ACCESS
            || EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), expected) == 0
        {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn local_root(root: &Path) -> bool {
    root.is_absolute()
        && matches!(root.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
        && !root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}
