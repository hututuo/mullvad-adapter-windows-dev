//! Native Unicode clipboard output for a public report path, never key material.
//! No clipboard reads, history, arbitrary shell command or retry loop.
#[cfg(any(windows, feature = "windows-api-check", test))]
use std::io;

#[cfg(any(windows, feature = "windows-api-check", test))]
fn unicode_text(text: &str) -> io::Result<Vec<u16>> {
    if text.is_empty() || text.len() > 32768 || text.contains('\0') {
        return Err(io::Error::other("clipboard_text_invalid"));
    }
    let mut value: Vec<_> = text.encode_utf16().collect();
    value.push(0);
    Ok(value)
}

/// `owner` is the native window handle obtained by the trusted desktop bridge.
/// Allocate before opening the clipboard; OS owns the memory only on success.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn copy_public_text(owner: isize, text: &str) -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::{GlobalFree, HGLOBAL},
        System::{
            DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
            Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT},
        },
    };
    if owner == 0 {
        return Err(io::Error::other("clipboard_window_unavailable"));
    }
    let value = unicode_text(text)?;
    struct Memory(HGLOBAL);
    impl Drop for Memory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    GlobalFree(self.0);
                }
            }
        }
    }
    struct Clipboard;
    impl Drop for Clipboard {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }
    let mut memory = Memory(unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, value.len() * 2) });
    if memory.0.is_null() {
        return Err(io::Error::other("clipboard_allocation_failed"));
    }
    let pointer = unsafe { GlobalLock(memory.0) };
    if pointer.is_null() {
        return Err(io::Error::other("clipboard_allocation_failed"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), pointer.cast::<u16>(), value.len());
        GlobalUnlock(memory.0);
    }
    if unsafe { OpenClipboard(owner as _) } == 0 {
        return Err(io::Error::other("clipboard_busy"));
    }
    let _clipboard = Clipboard;
    if unsafe { EmptyClipboard() } == 0
        || unsafe {
            SetClipboardData(13 /* CF_UNICODETEXT */, memory.0)
        }
        .is_null()
    {
        return Err(io::Error::other("clipboard_write_failed"));
    }
    memory.0 = std::ptr::null_mut();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_paths_preserve_chinese_and_surrogate_pairs() {
        let text = "C:\\用户\\诊断📄.json";
        let value = unicode_text(text).unwrap();
        assert_eq!(value.last(), Some(&0));
        assert_eq!(String::from_utf16(&value[..value.len() - 1]).unwrap(), text);
        for invalid in ["", "path\0truncated", &"a".repeat(32769)] {
            assert!(unicode_text(invalid).is_err());
        }
    }
}
