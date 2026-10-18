//! One bounded IPv4 ICMP echo with an explicitly selected physical source.
//!
//! ICMP observations are low-cost latency evidence, never tunnel readiness,
//! relay quarantine or proof that DNS/HTTPS/data-plane service works. The owner
//! must still bind results to its operation/generation/network epoch.
//!
//! Win32 contract: IcmpSendEcho2Ex's source address is explicit and a null event
//! and APC select synchronous completion. This module uses one call, no DNS,
//! subprocess, route changes or retries.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
    IP_DEST_PROT_UNREACHABLE, IP_PACKET_TOO_BIG, IP_REQ_TIMED_OUT, IP_SOURCE_QUENCH, IP_SUCCESS,
    IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT,
};

pub const TIMEOUT_MS: u32 = 1200;
const NONCE_SIZE: usize = 32;
const REPLY_CAPACITY: usize = 256;
const REPLY32_HEADER_SIZE: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingResult {
    Reply {
        rtt_ms: u32,
    },
    /// No matching successful echo reply. Status preserves the timeout/error
    /// observation without treating it as failed tunnel or physical attachment.
    NoReply {
        status: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidPhysicalBinding,
    Cancelled,
    StaleRoute,
    RouteChanged,
    RouteUnavailable,
    InvalidReply,
    NonceUnavailable,
    Local { code: u32 },
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidAddress => "icmp_invalid_address",
            Self::InvalidPhysicalBinding => "icmp_invalid_physical_binding",
            Self::Cancelled => "icmp_cancelled",
            Self::StaleRoute => "icmp_stale_route",
            Self::RouteChanged => "icmp_route_changed",
            Self::RouteUnavailable => "icmp_route_unavailable",
            Self::InvalidReply => "icmp_invalid_reply",
            Self::NonceUnavailable => "icmp_nonce_unavailable",
            Self::Local { .. } => "icmp_local_error",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}

// Aligned for both native-pointer and POINTER_32 Win32 layouts. Capacity covers
// one reply, our nonce, maximum IPv4 options, ICMP error data and IO_STATUS_BLOCK.
#[repr(C, align(8))]
struct ReplyBuffer([u8; REPLY_CAPACITY]);

fn addresses(source: IpAddr, destination: IpAddr) -> Result<(Ipv4Addr, Ipv4Addr), Error> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, destination) else {
        return Err(Error::InvalidAddress);
    };
    let usable = |ip: Ipv4Addr| {
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && ip.octets()[0] != 0
            && ip.octets()[0] < 224
    };
    if !usable(source) || !usable(destination) || destination.is_private() {
        return Err(Error::InvalidAddress);
    }
    Ok((source, destination))
}

fn ipaddr(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

fn checkpoint(cancelled: bool, fresh: bool, same_path: bool) -> Result<(), Error> {
    if cancelled {
        return Err(Error::Cancelled);
    }
    if !fresh {
        return Err(Error::StaleRoute);
    }
    if !same_path {
        return Err(Error::RouteChanged);
    }
    Ok(())
}

fn guarded_exchange(
    cancel: impl Fn() -> bool,
    route_check: impl Fn() -> Result<(), Error>,
    exchange: impl FnOnce() -> Result<PingResult, Error>,
) -> Result<PingResult, Error> {
    checkpoint(cancel(), true, true)?;
    let before = route_check();
    checkpoint(cancel(), true, true)?;
    before?;
    let result = exchange();
    // Even a completed success/local error cannot escape a newer cancellation
    // or changed route. Synchronous cancellation latency is at most the API's
    // 1200ms timeout plus local scheduling/route-query overhead.
    checkpoint(cancel(), true, true)?;
    let after = route_check();
    checkpoint(cancel(), true, true)?;
    after?;
    result
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub fn probe_v4(
    route: &crate::egress::EgressSnapshot,
    cancel: impl Fn() -> bool,
) -> Result<PingResult, Error> {
    checkpoint(cancel(), route.is_fresh(), true)?;
    let binding = route.binding();
    if binding.luid == 0 || binding.index == 0 || !binding.ipv4 {
        return Err(Error::InvalidPhysicalBinding);
    }
    let (source, destination) = addresses(route.source(), route.destination())?;
    guarded_exchange(
        cancel,
        || {
            checkpoint(false, route.is_fresh(), true)?;
            let again = crate::egress::windows::snapshot(binding, route.destination())
                .map_err(|_| Error::RouteUnavailable)?;
            checkpoint(
                false,
                route.is_fresh() && again.is_fresh(),
                route.same_path(&again),
            )
        },
        || send_once(source, destination),
    )
}

#[cfg(any(windows, feature = "windows-api-check"))]
fn nonce() -> Result<[u8; NONCE_SIZE], Error> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut nonce = [0; NONCE_SIZE];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            nonce.as_mut_ptr(),
            NONCE_SIZE as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(Error::NonceUnavailable);
    }
    Ok(nonce)
}

#[cfg(any(windows, feature = "windows-api-check"))]
fn send_once(source: Ipv4Addr, destination: Ipv4Addr) -> Result<PingResult, Error> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex},
    };
    struct IcmpHandle(HANDLE);
    impl Drop for IcmpHandle {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(Error::Local {
            code: unsafe { GetLastError() },
        });
    }
    let handle = IcmpHandle(handle);
    let nonce = nonce()?;
    let mut reply = ReplyBuffer([0; REPLY_CAPACITY]);
    let count = unsafe {
        IcmpSendEcho2Ex(
            handle.0,
            null_mut(),
            None,
            null(),
            ipaddr(source),
            ipaddr(destination),
            nonce.as_ptr().cast(),
            NONCE_SIZE as u16,
            null(),
            reply.0.as_mut_ptr().cast(),
            REPLY_CAPACITY as u32,
            TIMEOUT_MS,
        )
    };
    // Read thread-local error immediately. Never format raw OS messages.
    let last_error = if count == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    decode_reply(
        &reply.0,
        reply.0.as_ptr() as usize,
        count,
        last_error,
        destination,
        &nonce,
    )
}

fn no_reply_status(status: u32) -> bool {
    matches!(
        status,
        IP_REQ_TIMED_OUT
            | IP_DEST_NET_UNREACHABLE
            | IP_DEST_HOST_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE
            | IP_TTL_EXPIRED_TRANSIT
            | IP_TTL_EXPIRED_REASSEM
            | IP_PACKET_TOO_BIG
            | IP_SOURCE_QUENCH
    )
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::InvalidReply)?
            .try_into()
            .map_err(|_| Error::InvalidReply)?,
    ))
}
fn short(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(Error::InvalidReply)?
            .try_into()
            .map_err(|_| Error::InvalidReply)?,
    ))
}

fn decode_reply(
    buffer: &[u8],
    base: usize,
    count: u32,
    last_error: u32,
    destination: Ipv4Addr,
    nonce: &[u8; NONCE_SIZE],
) -> Result<PingResult, Error> {
    if buffer.len() < REPLY32_HEADER_SIZE || buffer.len() > REPLY_CAPACITY {
        return Err(Error::InvalidReply);
    }
    if count == 0 {
        return if no_reply_status(last_error) {
            Ok(PingResult::NoReply { status: last_error })
        } else if last_error == 0 {
            Err(Error::InvalidReply)
        } else {
            Err(Error::Local { code: last_error })
        };
    }
    if count != 1 {
        return Err(Error::InvalidReply);
    }
    let status = word(buffer, 4)?;
    let size = usize::from(short(buffer, 12)?);
    if size > buffer.len() - REPLY32_HEADER_SIZE {
        return Err(Error::InvalidReply);
    }
    if status != IP_SUCCESS {
        return if no_reply_status(status) {
            Ok(PingResult::NoReply { status })
        } else {
            Err(Error::Local { code: status })
        };
    }
    if word(buffer, 0)? != ipaddr(destination) || size != NONCE_SIZE {
        return Err(Error::InvalidReply);
    }
    let rtt = word(buffer, 8)?;
    if rtt > TIMEOUT_MS {
        return Err(Error::InvalidReply);
    }
    // On x64 Microsoft's documented ICMP_ECHO_REPLY32 encodes Data as
    // POINTER_32. windows-sys 0.59 models it as a native pointer. Avoid casting
    // either generated structure or dereferencing an API-provided pointer.
    // The shared fields and the low 32 pointer bits have identical offsets in
    // both layouts. Convert those bits to a bounded offset into our OWN buffer;
    // wrapping subtraction also handles buffers straddling a 4GiB boundary.
    let data_offset = word(buffer, 16)?.wrapping_sub(base as u32) as usize;
    let end = data_offset.checked_add(size).ok_or(Error::InvalidReply)?;
    if data_offset < REPLY32_HEADER_SIZE
        || end > buffer.len()
        || buffer.get(data_offset..end) != Some(nonce.as_slice())
    {
        return Err(Error::InvalidReply);
    }
    Ok(PingResult::Reply { rtt_ms: rtt })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    const NONCE: [u8; NONCE_SIZE] = *b"synthetic-icmp-nonce-01234567890";
    const DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
    fn put_word(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    fn packet(base: usize, offset: usize) -> ReplyBuffer {
        let mut reply = ReplyBuffer([0; REPLY_CAPACITY]);
        put_word(&mut reply.0, 0, ipaddr(DESTINATION));
        put_word(&mut reply.0, 4, IP_SUCCESS);
        put_word(&mut reply.0, 8, 37);
        reply.0[12..14].copy_from_slice(&(NONCE_SIZE as u16).to_ne_bytes());
        put_word(&mut reply.0, 16, (base as u32).wrapping_add(offset as u32));
        reply.0[offset..offset + NONCE_SIZE].copy_from_slice(&NONCE);
        reply
    }
    fn decode(
        reply: &ReplyBuffer,
        base: usize,
        count: u32,
        error: u32,
    ) -> Result<PingResult, Error> {
        decode_reply(&reply.0, base, count, error, DESTINATION, &NONCE)
    }

    #[test]
    fn aligned_bounded_buffer_and_network_address_bytes_are_explicit() {
        assert!(std::mem::align_of::<ReplyBuffer>() >= 8);
        assert_eq!(std::mem::size_of::<ReplyBuffer>(), REPLY_CAPACITY);
        assert!(REPLY_CAPACITY >= 48 + NONCE_SIZE + 40 + 8 + 16);
        assert_eq!(
            ipaddr(Ipv4Addr::new(1, 2, 3, 4)).to_ne_bytes(),
            [1, 2, 3, 4]
        );
        assert_eq!(TIMEOUT_MS, 1200);
    }

    #[test]
    fn address_validation_requires_explicit_unicast_ipv4_source_and_public_target() {
        assert!(addresses("192.168.1.5".parse().unwrap(), IpAddr::V4(DESTINATION)).is_ok());
        for source in [
            "::1",
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.1.2.3",
        ] {
            assert_eq!(
                addresses(source.parse().unwrap(), IpAddr::V4(DESTINATION)),
                Err(Error::InvalidAddress)
            );
        }
        for target in [
            "2001:db8::1",
            "10.64.1.1",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.1",
            "224.0.0.1",
            "169.254.1.1",
        ] {
            assert_eq!(
                addresses("192.168.1.5".parse().unwrap(), target.parse().unwrap()),
                Err(Error::InvalidAddress)
            );
        }
    }

    #[test]
    fn actual_nonce_reply_has_rtt_and_both_documented_layout_offsets_work() {
        for offset in [REPLY32_HEADER_SIZE, 48, REPLY_CAPACITY - NONCE_SIZE] {
            let reply = packet(0x2000, offset);
            assert_eq!(
                decode(&reply, 0x2000, 1, 0),
                Ok(PingResult::Reply { rtt_ms: 37 })
            );
        }
        // RTT zero is valid local/low-latency evidence; it must not be replaced
        // by elapsed wall time or a made-up one-millisecond minimum.
        let mut reply = packet(0x2000, 48);
        put_word(&mut reply.0, 8, 0);
        assert_eq!(
            decode(&reply, 0x2000, 1, 0),
            Ok(PingResult::Reply { rtt_ms: 0 })
        );
    }

    #[test]
    fn pointer32_offset_is_bounded_even_at_address_space_wrap() {
        #[cfg(target_pointer_width = "64")]
        for base in [0x1_0000_2000usize, 0x7fff_1234_2000usize] {
            let reply = packet(base, 48);
            assert_eq!(
                decode(&reply, base, 1, 0),
                Ok(PingResult::Reply { rtt_ms: 37 })
            );
        }
        let base = 0xfffffff0usize;
        let reply = packet(base, 48);
        assert_eq!(
            decode(&reply, base, 1, 0),
            Ok(PingResult::Reply { rtt_ms: 37 })
        );
        for pointer in [
            0,
            0x1fff,
            0x2000,
            0x2010,
            0x2000 + REPLY_CAPACITY as u32,
            u32::MAX,
        ] {
            let mut reply = packet(0x2000, 48);
            put_word(&mut reply.0, 16, pointer);
            assert_eq!(decode(&reply, 0x2000, 1, 0), Err(Error::InvalidReply));
        }
    }

    #[test]
    fn address_status_count_data_and_rtt_cannot_fake_a_reply() {
        let base = 0x2000;
        for count in [2, u32::MAX] {
            assert_eq!(
                decode(&packet(base, 48), base, count, 0),
                Err(Error::InvalidReply)
            );
        }
        let mut reply = packet(base, 48);
        put_word(&mut reply.0, 0, ipaddr(Ipv4Addr::new(198, 51, 100, 2)));
        assert_eq!(decode(&reply, base, 1, 0), Err(Error::InvalidReply));
        for size in [0u16, 31, 33, u16::MAX] {
            let mut reply = packet(base, 48);
            reply.0[12..14].copy_from_slice(&size.to_ne_bytes());
            assert_eq!(decode(&reply, base, 1, 0), Err(Error::InvalidReply));
        }
        let mut reply = packet(base, 48);
        reply.0[48] ^= 1;
        assert_eq!(decode(&reply, base, 1, 0), Err(Error::InvalidReply));
        let mut reply = packet(base, 48);
        put_word(&mut reply.0, 8, TIMEOUT_MS + 1);
        assert_eq!(decode(&reply, base, 1, 0), Err(Error::InvalidReply));
        assert_eq!(
            decode_reply(&[0; 27], base, 1, 0, DESTINATION, &NONCE),
            Err(Error::InvalidReply)
        );
        assert_eq!(
            decode_reply(&[0; REPLY_CAPACITY + 1], base, 1, 0, DESTINATION, &NONCE),
            Err(Error::InvalidReply)
        );
    }

    #[test]
    fn timeout_and_remote_icmp_errors_are_not_rtt_or_local_success() {
        for status in [
            IP_REQ_TIMED_OUT,
            IP_DEST_HOST_UNREACHABLE,
            IP_DEST_NET_UNREACHABLE,
            IP_DEST_PROT_UNREACHABLE,
            IP_DEST_PORT_UNREACHABLE,
            IP_TTL_EXPIRED_TRANSIT,
            IP_TTL_EXPIRED_REASSEM,
            IP_PACKET_TOO_BIG,
            IP_SOURCE_QUENCH,
        ] {
            let mut reply = packet(0x2000, 48);
            put_word(&mut reply.0, 4, status);
            // An intermediate router's ICMP error may originate elsewhere.
            put_word(&mut reply.0, 0, ipaddr(Ipv4Addr::new(192, 0, 2, 2)));
            assert_eq!(
                decode(&reply, 0x2000, 1, 0),
                Ok(PingResult::NoReply { status })
            );
            assert_eq!(
                decode(&reply, 0x2000, 0, status),
                Ok(PingResult::NoReply { status })
            );
        }
        for code in [5, 87, 11001, 11006, 11008, 11012, 11050] {
            assert_eq!(
                decode(&packet(0x2000, 48), 0x2000, 0, code),
                Err(Error::Local { code })
            );
            let mut reply = packet(0x2000, 48);
            put_word(&mut reply.0, 4, code);
            assert_eq!(decode(&reply, 0x2000, 1, 0), Err(Error::Local { code }));
        }
        assert_eq!(
            decode(&packet(0x2000, 48), 0x2000, 0, 0),
            Err(Error::InvalidReply)
        );
    }

    #[test]
    fn cancelled_or_invalid_route_never_sends_and_one_echo_has_two_route_guards() {
        let sends = Cell::new(0);
        let checks = Cell::new(0);
        let result = guarded_exchange(
            || false,
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            || {
                sends.set(sends.get() + 1);
                Ok(PingResult::NoReply {
                    status: IP_REQ_TIMED_OUT,
                })
            },
        );
        assert_eq!(
            result,
            Ok(PingResult::NoReply {
                status: IP_REQ_TIMED_OUT
            })
        );
        assert_eq!(sends.get(), 1);
        assert_eq!(checks.get(), 2);
        sends.set(0);
        assert_eq!(
            guarded_exchange(
                || true,
                || Ok(()),
                || {
                    sends.set(sends.get() + 1);
                    unreachable!()
                }
            ),
            Err(Error::Cancelled)
        );
        assert_eq!(
            guarded_exchange(
                || false,
                || Err(Error::RouteChanged),
                || {
                    sends.set(sends.get() + 1);
                    unreachable!()
                }
            ),
            Err(Error::RouteChanged)
        );
        assert_eq!(sends.get(), 0);
    }

    #[test]
    fn late_cancellation_and_route_changes_discard_reply_and_local_errors() {
        for reply in [
            Ok(PingResult::Reply { rtt_ms: 37 }),
            Err(Error::Local { code: 5 }),
        ] {
            let cancelled = Cell::new(false);
            assert_eq!(
                guarded_exchange(
                    || cancelled.get(),
                    || Ok(()),
                    || {
                        cancelled.set(true);
                        reply
                    }
                ),
                Err(Error::Cancelled)
            );
            let checks = Cell::new(0);
            assert_eq!(
                guarded_exchange(
                    || false,
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == 2 {
                            Err(Error::RouteChanged)
                        } else {
                            Ok(())
                        }
                    },
                    || reply
                ),
                Err(Error::RouteChanged)
            );
        }
        assert_eq!(checkpoint(false, false, true), Err(Error::StaleRoute));
        assert_eq!(checkpoint(false, true, false), Err(Error::RouteChanged));
        assert_eq!(checkpoint(true, false, false), Err(Error::Cancelled));
    }

    #[test]
    fn cancellation_during_route_query_overrides_its_success_or_error() {
        for cancel_on_check in [1, 2] {
            for route_result in [Ok(()), Err(Error::RouteUnavailable)] {
                let cancelled = Cell::new(false);
                let checks = Cell::new(0);
                let sends = Cell::new(0);
                let result = guarded_exchange(
                    || cancelled.get(),
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == cancel_on_check {
                            cancelled.set(true);
                            route_result
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        sends.set(sends.get() + 1);
                        Ok(PingResult::Reply { rtt_ms: 37 })
                    },
                );
                assert_eq!(result, Err(Error::Cancelled));
                assert_eq!(sends.get(), cancel_on_check - 1);
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_single_loopback_echo_checks_nonce_without_external_traffic() {
        // Exercises native ABI and standard-user echo only. It bypasses the
        // production physical-route guard and does not prove physical egress.
        let result = send_once(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).unwrap();
        assert!(matches!(result, PingResult::Reply { .. }));
    }
}
