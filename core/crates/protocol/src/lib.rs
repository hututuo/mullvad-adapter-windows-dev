//! Versioned, bounded public IPC. Secret-returning operations are not part of the mock protocol.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
pub mod app;
pub const API_MAJOR: u16 = 1;
pub const API_MINOR: u16 = 0;
pub const MAX_FRAME: usize = 65_536;
/// Native pipe clients acknowledge a fully consumed response before server close.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResponseAck {
    pub request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub major: u16,
    pub boot_id: String,
    pub request_id: String,
    pub command: Command,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Snapshot,
    Operation { operation_id: String },
    SelectCity { city: String },
    Stop,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub major: u16,
    pub minor: u16,
    pub boot_id: String,
    pub build: String,
    pub mode: String,
    pub capabilities: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Snapshot {
    pub sequence: u64,
    pub generation: u64,
    pub network_epoch: u64,
    pub boot_id: String,
    pub mode: String,
    pub status: String,
    pub selected_city: Option<String>,
    pub capabilities: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Operation {
    pub id: String,
    pub boot_id: String,
    pub request_id: String,
    pub state: String,
    pub code: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello(Hello),
    Snapshot(Snapshot),
    Operation(Operation),
    Error { code: String },
}
impl Request {
    pub fn validate(&self, boot: &str) -> Result<(), &'static str> {
        if self.major != API_MAJOR {
            return Err("incompatible_protocol");
        }
        if self.boot_id != boot {
            return Err("boot_changed_reconcile");
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 64
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid_request_id");
        }
        match &self.command {
            Command::SelectCity { city } if !valid_city(city) => Err("invalid_city"),
            Command::Operation { operation_id }
                if operation_id.is_empty() || operation_id.len() > 128 =>
            {
                Err("invalid_operation_id")
            }
            _ => Ok(()),
        }
    }
}
fn valid_city(city: &str) -> bool {
    let b = city.as_bytes();
    b.len() == 6
        && b[2] == b'-'
        && b[..2].iter().all(u8::is_ascii_lowercase)
        && b[3..].iter().all(u8::is_ascii_alphanumeric)
}
pub fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> io::Result<T> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame_size"));
    }
    let mut body = zeroize::Zeroizing::new(vec![0; size]);
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid_message"))
}
pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let body = zeroize::Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid_message"))?,
    );
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame_size"));
    }
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}
