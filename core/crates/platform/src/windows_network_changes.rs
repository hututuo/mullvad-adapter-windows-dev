//! Classify interface-parameter hints off-callback before invalidating work.
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
        CancelMibChangeNotify2, FreeMibTable, GetIpInterfaceTable, MibParameterNotification,
        NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange,
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

struct Counters {
    invalidation: Arc<AtomicU64>,
    parameters: Arc<AtomicU64>,
    checked_parameters: Arc<AtomicU64>,
}
fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |n| n.checked_add(1));
}
unsafe fn signal(context: *const c_void) {
    let counters = unsafe { &*context.cast::<Counters>() };
    increment(&counters.invalidation);
}
unsafe extern "system" fn interface_changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    kind: MIB_NOTIFICATION_TYPE,
) {
    // Callback rows contain identity, not complete parameter values. Only a
    // valid parameter key can await classification; all other hints stay hard.
    if kind == MibParameterNotification && !row.is_null() {
        let row = unsafe { &*row };
        if matches!(row.Family, AF_INET | AF_INET6)
            && row.InterfaceIndex != 0
            && unsafe { row.InterfaceLuid.Value } != 0
        {
            let counters = unsafe { &*context.cast::<Counters>() };
            increment(&counters.parameters);
            return;
        }
    }
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
    context: *const Counters,
}
// IP Helper registration/cancellation is not thread-affine. Callback state is
// only atomic counters; cancellation holds no lock needed by a callback.
unsafe impl Send for Registration {}
impl Registration {
    fn new(counters: Arc<Counters>, kind: u8) -> io::Result<Self> {
        let context = Arc::into_raw(counters);
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
    counters: Arc<Counters>,
    baseline: Option<Vec<Parameters>>,
}
impl NetworkChanges {
    pub fn register(
        invalidation: Arc<AtomicU64>,
        parameters: Arc<AtomicU64>,
        checked_parameters: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        let counters = Arc::new(Counters {
            invalidation,
            parameters,
            checked_parameters,
        });
        let interface = Registration::new(counters.clone(), 0)?;
        let address = Registration::new(counters.clone(), 1)?;
        let route = Registration::new(counters.clone(), 2)?;
        Ok(Self {
            interface,
            address,
            route,
            counters,
            baseline: None,
        })
    }
    /// One bounded sampling worker owns this state. No I/O occurs in callbacks.
    /// Parameter hints gate publication, but do not cancel ongoing measurements.
    pub fn observe(&mut self) -> io::Result<crate::physical_attachment::Observation> {
        self.observe_with(parameters, crate::physical_attachment::windows::observe)
    }
    fn observe_with(
        &mut self,
        mut read: impl FnMut() -> io::Result<Vec<Parameters>>,
        mut sample: impl FnMut() -> io::Result<crate::physical_attachment::Observation>,
    ) -> io::Result<crate::physical_attachment::Observation> {
        let revision = self.counters.parameters.load(Ordering::Acquire);
        if revision == u64::MAX {
            increment(&self.counters.invalidation);
            return Err(io::Error::other("interface parameter counter exhausted"));
        }
        if self.baseline.is_some()
            && revision != u64::MAX
            && revision == self.counters.checked_parameters.load(Ordering::Acquire)
        {
            return sample();
        }
        let result = (|| {
            let first = read()?;
            let observation = sample()?;
            let last = read()?;
            if first != last || self.baseline.as_ref().is_some_and(|old| old != &last) {
                increment(&self.counters.invalidation);
            }
            self.baseline = (first == last).then_some(last);
            Ok(observation)
        })();
        if result.is_err() {
            self.baseline = None;
            increment(&self.counters.invalidation);
        }
        // Release only the batch read before sampling. A later callback remains
        // pending, and hard invalidation is published before classification.
        self.counters
            .checked_parameters
            .store(revision, Ordering::Release);
        result
    }
    pub fn close(&mut self) -> io::Result<()> {
        // Attempt every registration even if an earlier cancellation fails.
        let interface = self.interface.cancel();
        let address = self.address.cancel();
        let route = self.route.cancel();
        interface.and(address).and(route)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Parameters {
    key: (u16, u64, u32),
    values: Vec<u64>,
}
fn normalize(row: &MIB_IPINTERFACE_ROW) -> io::Result<Parameters> {
    let luid = unsafe { row.InterfaceLuid.Value };
    if !matches!(row.Family, AF_INET | AF_INET6) || luid == 0 || row.InterfaceIndex == 0 {
        return Err(io::Error::other("invalid interface parameter key"));
    }
    // Explicit fields, never struct padding or callback payload values. Only
    // interface Metric is exempt. Route Metric and route/socket witnesses keep
    // their existing strict checks for the explicitly bound physical carrier.
    let mut values = vec![
        row.MaxReassemblySize as u64,
        row.InterfaceIdentifier,
        row.MinRouterAdvertisementInterval as u64,
        row.MaxRouterAdvertisementInterval as u64,
        row.AdvertisingEnabled as u64,
        row.ForwardingEnabled as u64,
        row.WeakHostSend as u64,
        row.WeakHostReceive as u64,
        row.UseAutomaticMetric as u64,
        row.UseNeighborUnreachabilityDetection as u64,
        row.ManagedAddressConfigurationSupported as u64,
        row.OtherStatefulConfigurationSupported as u64,
        row.AdvertiseDefaultRoute as u64,
        row.RouterDiscoveryBehavior as u64,
        row.DadTransmits as u64,
        row.BaseReachableTime as u64,
        row.RetransmitTime as u64,
        row.PathMtuDiscoveryTimeout as u64,
        row.LinkLocalAddressBehavior as u64,
        row.LinkLocalAddressTimeout as u64,
        row.SitePrefixLength as u64,
        row.NlMtu as u64,
        row.Connected as u64,
        row.SupportsWakeUpPatterns as u64,
        row.SupportsNeighborDiscovery as u64,
        row.SupportsRouterDiscovery as u64,
        row.ReachableTime as u64,
        row.TransmitOffload._bitfield as u64,
        row.ReceiveOffload._bitfield as u64,
        row.DisableDefaultRoutes as u64,
    ];
    values.extend(row.ZoneIndices.into_iter().map(u64::from));
    Ok(Parameters {
        key: (row.Family, luid, row.InterfaceIndex),
        values,
    })
}
fn parameters() -> io::Result<Vec<Parameters>> {
    struct Table(*mut c_void);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0) };
        }
    }
    let mut pointer = ptr::null_mut();
    let status = unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut pointer) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if pointer.is_null() {
        return Err(io::Error::other("missing interface parameter table"));
    }
    let _table = Table(pointer.cast());
    let count = unsafe { (*pointer).NumEntries } as usize;
    if count == 0 || count > 8192 {
        return Err(io::Error::other("invalid interface parameter table"));
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*pointer).Table).cast::<MIB_IPINTERFACE_ROW>(),
            count,
        )
    };
    let mut result = rows.iter().map(normalize).collect::<io::Result<Vec<_>>>()?;
    result.sort_by_key(|row| row.key);
    if result.windows(2).any(|rows| rows[0].key == rows[1].key) {
        return Err(io::Error::other("duplicate interface parameter key"));
    }
    Ok(result)
}
#[cfg(all(test, any(windows, feature = "windows-api-check")))]
mod tests {
    use super::*;
    fn counters() -> Arc<Counters> {
        Arc::new(Counters {
            invalidation: Arc::new(AtomicU64::new(0)),
            parameters: Arc::new(AtomicU64::new(0)),
            checked_parameters: Arc::new(AtomicU64::new(0)),
        })
    }
    fn row(family: u16) -> MIB_IPINTERFACE_ROW {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.Family = family;
        row.InterfaceLuid.Value = 5;
        row.InterfaceIndex = 7;
        row.Connected = 1;
        row.NlMtu = 1500;
        row.UseAutomaticMetric = 1;
        row.Metric = 35;
        row
    }
    fn classifier() -> NetworkChanges {
        fn empty() -> Registration {
            Registration {
                handle: ptr::null_mut(),
                context: ptr::null(),
            }
        }
        NetworkChanges {
            interface: empty(),
            address: empty(),
            route: empty(),
            counters: counters(),
            baseline: None,
        }
    }
    fn sample() -> io::Result<crate::physical_attachment::Observation> {
        Ok(crate::physical_attachment::Observation {
            attachment: crate::physical_attachment::Attachment::Available,
            bindings: vec![crate::physical_attachment::PhysicalBinding {
                luid: 5,
                index: 7,
                ipv4: true,
                ipv6: false,
            }],
        })
    }
    #[test]
    fn classification_preserves_metric_only_but_invalidates_material_changes_and_errors() {
        let mut changes = classifier();
        let mut current = row(AF_INET);
        changes
            .observe_with(|| Ok(vec![normalize(&current).unwrap()]), sample)
            .unwrap();
        current.Metric = 30;
        increment(&changes.counters.parameters);
        changes
            .observe_with(|| Ok(vec![normalize(&current).unwrap()]), sample)
            .unwrap();
        assert_eq!(changes.counters.invalidation.load(Ordering::Acquire), 0);
        assert_eq!(
            changes.counters.checked_parameters.load(Ordering::Acquire),
            1
        );
        current.NlMtu = 1280;
        increment(&changes.counters.parameters);
        changes
            .observe_with(|| Ok(vec![normalize(&current).unwrap()]), sample)
            .unwrap();
        assert_eq!(changes.counters.invalidation.load(Ordering::Acquire), 1);
        assert_eq!(
            changes.counters.checked_parameters.load(Ordering::Acquire),
            2
        );
        increment(&changes.counters.parameters);
        assert!(changes
            .observe_with(|| Err(io::Error::other("synthetic read error")), sample)
            .is_err());
        assert_eq!(changes.counters.invalidation.load(Ordering::Acquire), 2);
        assert!(changes.baseline.is_none());
    }
    #[test]
    fn changing_parameters_and_late_batches_never_release_a_newer_hint() {
        let mut changes = classifier();
        let counter = changes.counters.parameters.clone();
        increment(&counter);
        let mut calls = 0;
        changes
            .observe_with(
                || {
                    calls += 1;
                    if calls == 1 {
                        increment(&counter);
                    }
                    Ok(vec![normalize(&row(AF_INET)).unwrap()])
                },
                sample,
            )
            .unwrap();
        assert_eq!(counter.load(Ordering::Acquire), 2);
        assert_eq!(
            changes.counters.checked_parameters.load(Ordering::Acquire),
            1
        );
        changes
            .observe_with(|| Ok(vec![normalize(&row(AF_INET)).unwrap()]), sample)
            .unwrap();
        assert_eq!(
            changes.counters.checked_parameters.load(Ordering::Acquire),
            2
        );
        increment(&counter);
        let mut calls = 0;
        changes
            .observe_with(
                || {
                    calls += 1;
                    let mut current = row(AF_INET);
                    if calls == 2 {
                        current.Connected = 0;
                    }
                    Ok(vec![normalize(&current).unwrap()])
                },
                sample,
            )
            .unwrap();
        assert_eq!(changes.counters.invalidation.load(Ordering::Acquire), 1);
        assert!(changes.baseline.is_none());
    }
    #[test]
    fn callbacks_only_coalesce_and_saturate_without_reading_parameters() {
        let counters = counters();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let counters = &counters;
                scope.spawn(move || {
                    for _ in 0..1000 {
                        unsafe {
                            interface_changed(Arc::as_ptr(counters).cast(), ptr::null(), 0);
                            address_changed(Arc::as_ptr(counters).cast(), ptr::null(), 0);
                            route_changed(Arc::as_ptr(counters).cast(), ptr::null(), 0);
                        }
                    }
                });
            }
        });
        assert_eq!(counters.invalidation.load(Ordering::Acquire), 24000);
        assert_eq!(counters.parameters.load(Ordering::Acquire), 0);
        counters.invalidation.store(u64::MAX, Ordering::Release);
        unsafe {
            interface_changed(Arc::as_ptr(&counters).cast(), ptr::null(), 0);
        }
        assert_eq!(counters.invalidation.load(Ordering::Acquire), u64::MAX);
    }
    #[test]
    fn valid_parameter_keys_wait_for_classification_other_notifications_invalidate() {
        let counters = counters();
        for family in [AF_INET, AF_INET6] {
            let row = row(family);
            unsafe {
                interface_changed(
                    Arc::as_ptr(&counters).cast(),
                    &row,
                    MibParameterNotification,
                );
            }
        }
        assert_eq!(counters.parameters.load(Ordering::Acquire), 2);
        assert_eq!(counters.checked_parameters.load(Ordering::Acquire), 0);
        assert_eq!(counters.invalidation.load(Ordering::Acquire), 0);
        for (kind, family, index) in [
            (1, AF_INET, 7),
            (2, AF_INET, 7),
            (0, AF_UNSPEC, 7),
            (0, AF_INET, 0),
        ] {
            let mut row = row(family);
            row.InterfaceIndex = index;
            unsafe {
                interface_changed(Arc::as_ptr(&counters).cast(), &row, kind);
            }
        }
        unsafe {
            address_changed(Arc::as_ptr(&counters).cast(), ptr::null(), 0);
            route_changed(Arc::as_ptr(&counters).cast(), ptr::null(), 0);
        }
        assert_eq!(counters.invalidation.load(Ordering::Acquire), 6);
        counters.parameters.store(u64::MAX, Ordering::Release);
        unsafe {
            interface_changed(Arc::as_ptr(&counters).cast(), &row(AF_INET), 0);
        }
        assert_eq!(counters.parameters.load(Ordering::Acquire), u64::MAX);
    }
    #[test]
    fn dual_stack_metric_oscillation_preserves_material_parameters() {
        for family in [AF_INET, AF_INET6] {
            let mut row = row(family);
            let baseline = normalize(&row).unwrap();
            for metric in [30, 35, 25, 35] {
                row.Metric = metric;
                assert_eq!(normalize(&row).unwrap(), baseline);
            }
            let mutations: &[fn(&mut MIB_IPINTERFACE_ROW)] = &[
                |r| r.Connected = 0,
                |r| r.NlMtu = 1280,
                |r| r.WeakHostSend = 1,
                |r| r.WeakHostReceive = 1,
                |r| r.UseAutomaticMetric = 0,
                |r| r.UseNeighborUnreachabilityDetection = 1,
                |r| r.InterfaceLuid.Value = 9,
                |r| r.InterfaceIndex = 9,
                |r| r.ZoneIndices[2] = 9,
                |r| r.ForwardingEnabled = 1,
                |r| r.TransmitOffload._bitfield = 1,
                |r| r.DisableDefaultRoutes = 1,
            ];
            for mutate in mutations {
                let mut changed = row;
                mutate(&mut changed);
                assert_ne!(normalize(&changed).unwrap(), baseline);
            }
        }
    }
    #[test]
    fn native_registration_close_releases_all_callback_contexts() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut changes = NetworkChanges::register(
            counter.clone(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        assert_eq!(Arc::strong_count(&changes.counters), 4);
        changes.close().unwrap();
        assert_eq!(Arc::strong_count(&changes.counters), 1);
        changes.close().unwrap();
        drop(changes);
        assert_eq!(Arc::strong_count(&counter), 1);
    }
    #[test]
    fn native_registration_can_move_to_worker_and_drop_there() {
        let counter = Arc::new(AtomicU64::new(0));
        let changes = NetworkChanges::register(
            counter.clone(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        std::thread::spawn(move || drop(changes)).join().unwrap();
        assert_eq!(Arc::strong_count(&counter), 1);
    }
    #[test]
    fn native_parameter_table_is_readable_without_packets_or_mutation() {
        assert!(!parameters().unwrap().is_empty());
    }
}
