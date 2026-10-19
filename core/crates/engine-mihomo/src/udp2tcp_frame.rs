//! Mullvad UDP-over-TCP framing, independent of socket ownership or readiness.
//!
//! The wire format is a two-byte big-endian length followed by one datagram:
//! https://github.com/mullvad/udp-over-tcp/tree/5c6d8f44a5aa12ed9bb4ae51dd17e5e22e5ec303
//! This module alone does not enable a product transport. A cancelled/failed
//! partial frame requires retiring its TCP stream, never restarting the frame.
use std::{io, time::Instant};

pub const HEADER_LEN: usize = 2;
/// Match the existing IPv4-capable carrier's conservative datagram ceiling.
pub const MAX_DATAGRAM: usize = 65_507;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "udp2tcp_frame_invalid")
}
fn terminal() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "udp2tcp_frame_terminal")
}
fn checkpoint(deadline: Instant, cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "udp2tcp_cancelled",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(io::ErrorKind::TimedOut, "udp2tcp_deadline"))
    } else {
        Ok(())
    }
}

/// Holds at most one bounded datagram. Callers retain unconsumed input.
pub struct Decoder {
    header: [u8; HEADER_LEN],
    header_used: usize,
    payload: Vec<u8>,
    length: usize,
    ended: bool,
}
impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub fn new() -> Self {
        Self {
            header: [0; HEADER_LEN],
            header_used: 0,
            payload: Vec::new(),
            length: 0,
            ended: false,
        }
    }
    /// Consume only through the first complete datagram. The returned count is
    /// exact even when `input` contains several frames; feed its remainder again.
    /// Zero-length and over-limit frames permanently terminate this decoder.
    pub fn push(&mut self, input: &[u8]) -> io::Result<(usize, Option<Vec<u8>>)> {
        if self.ended {
            return Err(terminal());
        }
        let mut used = 0;
        if self.header_used < HEADER_LEN {
            let count = (HEADER_LEN - self.header_used).min(input.len());
            self.header[self.header_used..self.header_used + count]
                .copy_from_slice(&input[..count]);
            self.header_used += count;
            used += count;
            if self.header_used < HEADER_LEN {
                return Ok((used, None));
            }
            self.length = u16::from_be_bytes(self.header) as usize;
            if self.length == 0 || self.length > MAX_DATAGRAM {
                self.abort();
                return Err(invalid());
            }
            self.payload = Vec::with_capacity(self.length);
        }
        let count = (self.length - self.payload.len()).min(input.len() - used);
        self.payload.extend_from_slice(&input[used..used + count]);
        used += count;
        if self.payload.len() != self.length {
            return Ok((used, None));
        }
        self.header_used = 0;
        self.length = 0;
        Ok((used, Some(std::mem::take(&mut self.payload))))
    }
    /// A clean stream EOF is valid only between frames. It is always terminal.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.ended {
            return Err(terminal());
        }
        let complete = self.header_used == 0;
        self.abort();
        if complete {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "udp2tcp_truncated_frame",
            ))
        }
    }
    /// Cancellation discards this decoder. A caller must retire its stream too.
    pub fn abort(&mut self) {
        self.ended = true;
        self.payload.clear();
    }
    /// Bounded checked variant for a carrier's per-iteration operation guard.
    pub fn push_checked(
        &mut self,
        input: &[u8],
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<(usize, Option<Vec<u8>>)> {
        if let Err(error) = checkpoint(deadline, &cancelled) {
            self.abort();
            return Err(error);
        }
        let result = self.push(input);
        if let Err(error) = checkpoint(deadline, &cancelled) {
            self.abort();
            return Err(error);
        }
        result
    }
}

/// One frame with a retained partial-write offset. No automatic retry/replay.
pub struct PendingWrite {
    frame: Vec<u8>,
    offset: usize,
    failed: bool,
}
impl PendingWrite {
    pub fn new(datagram: &[u8]) -> io::Result<Self> {
        if datagram.is_empty() || datagram.len() > MAX_DATAGRAM {
            return Err(invalid());
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + datagram.len());
        frame.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
        frame.extend_from_slice(datagram);
        Ok(Self {
            frame,
            offset: 0,
            failed: false,
        })
    }
    pub fn is_complete(&self) -> bool {
        !self.failed && self.offset == self.frame.len()
    }
    pub fn written_bytes(&self) -> usize {
        self.offset
    }
    /// Calls `write` at most once. It MUST be nonblocking or independently
    /// bounded; this layer cannot interrupt an arbitrary blocking callback.
    /// `false` means retry the retained remainder later (including WouldBlock
    /// and a transient Interrupted). Zero-write, cancellation, deadline, invalid
    /// callback counts and all other errors poison this frame permanently.
    pub fn write_step(
        &mut self,
        mut write: impl FnMut(&[u8]) -> io::Result<usize>,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<bool> {
        if self.failed {
            return Err(terminal());
        }
        if let Err(error) = checkpoint(deadline, &cancelled) {
            self.failed = true;
            return Err(error);
        }
        if self.is_complete() {
            return Ok(true);
        }
        let result = match write(&self.frame[self.offset..]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "udp2tcp_write_zero",
            )),
            Ok(count) if count <= self.frame.len() - self.offset => {
                self.offset += count;
                Ok(self.is_complete())
            }
            Ok(_) => Err(invalid()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        };
        if let Err(error) = checkpoint(deadline, &cancelled) {
            self.failed = true;
            return Err(error);
        }
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, time::Duration};
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }
    #[test]
    fn bytewise_split_header_and_payload() {
        let mut decoder = Decoder::new();
        for byte in [0, 3, 10, 20] {
            assert_eq!(decoder.push(&[byte]).unwrap(), (1, None));
        }
        assert_eq!(decoder.push(&[30]).unwrap(), (1, Some(vec![10, 20, 30])));
        decoder.finish().unwrap();
        assert!(decoder.push(&[0, 1, 9]).is_err());
    }
    #[test]
    fn coalesced_frames_retain_exact_unconsumed_remainder() {
        let bytes = [0, 2, 1, 2, 0, 1, 3, 0];
        let mut decoder = Decoder::new();
        let (used, first) = decoder.push(&bytes).unwrap();
        assert_eq!((used, first), (4, Some(vec![1, 2])));
        let (next, second) = decoder.push(&bytes[used..]).unwrap();
        assert_eq!((next, second), (3, Some(vec![3])));
        assert_eq!(decoder.push(&bytes[used + next..]).unwrap(), (1, None));
        assert_eq!(
            decoder.finish().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[test]
    fn every_split_roundtrips_maximum_datagram() {
        let payload = vec![73; MAX_DATAGRAM];
        let frame = PendingWrite::new(&payload).unwrap().frame;
        for split in [0, 1, 2, 3, 513, frame.len() - 1, frame.len()] {
            let mut decoder = Decoder::new();
            let (used, first) = decoder.push(&frame[..split]).unwrap();
            assert_eq!(used, split);
            let result = if first.is_some() {
                first
            } else {
                decoder.push(&frame[split..]).unwrap().1
            };
            assert_eq!(result.as_deref(), Some(payload.as_slice()));
            decoder.finish().unwrap();
        }
    }
    #[test]
    fn eof_empty_and_between_frames_is_clean_but_truncation_is_terminal() {
        Decoder::new().finish().unwrap();
        for bytes in [&[0][..], &[0, 2][..], &[0, 2, 7][..]] {
            let mut decoder = Decoder::new();
            decoder.push(bytes).unwrap();
            assert_eq!(
                decoder.finish().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(decoder.push(&[8]).is_err());
        }
    }
    #[test]
    fn rejects_zero_and_oversize_before_allocating_payload() {
        for length in [0u16, (MAX_DATAGRAM + 1) as u16, u16::MAX] {
            let mut decoder = Decoder::new();
            assert!(decoder.push(&length.to_be_bytes()).is_err());
            assert_eq!(decoder.payload.capacity(), 0);
            assert!(decoder.push(&[0, 1, 1]).is_err());
        }
        assert!(PendingWrite::new(&[]).is_err());
        assert!(PendingWrite::new(&vec![0; MAX_DATAGRAM + 1]).is_err());
    }
    #[test]
    fn partial_writes_and_would_block_never_repeat_bytes() {
        let mut pending = PendingWrite::new(&[10, 20, 30]).unwrap();
        let mut bytes = vec![];
        for count in [1, 0, 2, 2] {
            let complete = pending
                .write_step(
                    |data| {
                        if count == 0 {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        bytes.extend_from_slice(&data[..count]);
                        Ok(count)
                    },
                    deadline(),
                    || false,
                )
                .unwrap();
            assert_eq!(complete, bytes.len() == 5);
        }
        assert_eq!(bytes, [0, 3, 10, 20, 30]);
        assert!(pending
            .write_step(|_| panic!("complete writer called"), deadline(), || false)
            .unwrap());
    }
    #[test]
    fn zero_write_invalid_count_and_io_failure_poison_frame() {
        for result in [Ok(0), Ok(99), Err(io::ErrorKind::ConnectionReset.into())] {
            let mut result = Some(result);
            let mut pending = PendingWrite::new(&[1]).unwrap();
            assert!(pending
                .write_step(|_| result.take().unwrap(), deadline(), || false)
                .is_err());
            assert!(pending
                .write_step(|_| panic!("poisoned writer called"), deadline(), || false)
                .is_err());
        }
    }
    #[test]
    fn cancellation_before_io_and_after_partial_io_is_terminal() {
        let cancelled = Cell::new(false);
        let mut pending = PendingWrite::new(&[9, 8]).unwrap();
        assert_eq!(
            pending
                .write_step(
                    |_| {
                        cancelled.set(true);
                        Ok(1)
                    },
                    deadline(),
                    || cancelled.get()
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(pending.written_bytes(), 1);
        cancelled.set(false);
        assert!(pending
            .write_step(|_| panic!("replayed partial frame"), deadline(), || false)
            .is_err());
        let mut decoder = Decoder::new();
        assert!(decoder
            .push_checked(&[0, 1, 8], deadline(), || true)
            .is_err());
        assert!(decoder.push(&[0, 1, 8]).is_err());
    }
    #[test]
    fn expired_deadline_never_invokes_writer() {
        let mut pending = PendingWrite::new(&[9]).unwrap();
        assert_eq!(
            pending
                .write_step(
                    |_| panic!("expired writer called"),
                    Instant::now(),
                    || false
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
