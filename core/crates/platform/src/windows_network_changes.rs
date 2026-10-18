//! IP Helper notifications are invalidation hints, never connectivity evidence.
use std::{
    ffi::c_void,
    io, ptr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2,
        NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::AF_UNSPEC,
};

unsafe fn signal(context: *const c_void) {
    // Registration retains one Arc strong reference until callback rundown.
    let counter = unsafe { &*context.cast::<AtomicU64>() };
    let _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |n| n.checked_add(1));
}
unsafe extern "system" fn interface_changed(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    unsafe { signal(context) }
}
unsafe extern "system" fn address_changed(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    unsafe { signal(context) }
}
unsafe extern "system" fn route_changed(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    unsafe { signal(context) }
}
struct Registration {
    handle: HANDLE,
    context: *const AtomicU64,
}
// IP Helper registration/cancellation is not thread-affine. Callback state is
// only AtomicU64; cancellation holds no lock needed by a callback.
unsafe impl Send for Registration {}
impl Registration {
    fn new(counter: Arc<AtomicU64>, kind: u8) -> io::Result<Self> {
        let context = Arc::into_raw(counter);
        let mut handle = ptr::null_mut();
        let status = unsafe {
            if kind == 2 {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(route_changed),
                    context.cast(),
                    0,
                    &mut handle,
                )
            } else if kind == 1 {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(address_changed),
                    context.cast(),
                    0,
                    &mut handle,
                )
            } else {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface_changed),
                    context.cast(),
                    0,
                    &mut handle,
                )
            }
        };
        if status != 0 {
            // The documented failure path returns NULL and creates no registration.
            unsafe {
                drop(Arc::from_raw(context));
            }
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self { handle, context })
    }
    fn cancel(&mut self) -> io::Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        let status = unsafe { CancelMibChangeNotify2(self.handle) };
        if status != 0 {
            // Never release callback storage without successful deregistration.
            // A subsequent Drop retries; final failure retains the allocation
            // until process exit rather than risking a callback use-after-free.
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        self.handle = ptr::null_mut();
        unsafe {
            drop(Arc::from_raw(self.context));
        }
        Ok(())
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}
/// Own on the sampling worker, not on its responsive state-owner thread.
/// Drop synchronously cancels callbacks, never from inside a callback.
pub struct NetworkChanges {
    interface: Registration,
    address: Registration,
    route: Registration,
}
impl NetworkChanges {
    pub fn register(counter: Arc<AtomicU64>) -> io::Result<Self> {
        let interface = Registration::new(counter.clone(), 0)?;
        let address = Registration::new(counter.clone(), 1)?;
        let route = Registration::new(counter, 2)?;
        Ok(Self {
            interface,
            address,
            route,
        })
    }
    pub fn close(&mut self) -> io::Result<()> {
        // Attempt every registration even if an earlier cancellation fails.
        let interface = self.interface.cancel();
        let address = self.address.cancel();
        let route = self.route.cancel();
        interface.and(address).and(route)
    }
}
#[cfg(all(test, any(windows, feature = "windows-api-check")))]
mod tests {
    use super::*;
    #[test]
    fn callbacks_only_coalesce_and_saturate_without_reading_rows() {
        let counter = Arc::new(AtomicU64::new(0));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let counter = &counter;
                scope.spawn(move || {
                    for _ in 0..1000 {
                        unsafe {
                            interface_changed(Arc::as_ptr(counter).cast(), ptr::null(), 0);
                        }
                        unsafe {
                            address_changed(Arc::as_ptr(counter).cast(), ptr::null(), 0);
                            route_changed(Arc::as_ptr(counter).cast(), ptr::null(), 0);
                        }
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Acquire), 24000);
        counter.store(u64::MAX, Ordering::Release);
        unsafe {
            interface_changed(Arc::as_ptr(&counter).cast(), ptr::null(), 0);
        }
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
    }
    #[test]
    fn native_registration_close_releases_all_callback_contexts() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut changes = NetworkChanges::register(counter.clone()).unwrap();
        assert_eq!(Arc::strong_count(&counter), 4);
        changes.close().unwrap();
        assert_eq!(Arc::strong_count(&counter), 1);
        changes.close().unwrap();
        drop(changes);
        assert_eq!(Arc::strong_count(&counter), 1);
    }
    #[test]
    fn native_registration_can_move_to_worker_and_drop_there() {
        let counter = Arc::new(AtomicU64::new(0));
        let changes = NetworkChanges::register(counter.clone()).unwrap();
        std::thread::spawn(move || drop(changes)).join().unwrap();
        assert_eq!(Arc::strong_count(&counter), 1);
    }
}
