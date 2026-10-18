//! Durable loopback subscription, intentionally a remote profile in Verge.
//! It remains available while the desktop/tray process runs; Clash retains its
//! downloaded copy when this process exits. No one-shot/dead subscription URL.
use super::{create, err, hash, read, safe_path, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    port: u16,
    token: String,
}
pub struct Service {
    record: Record,
    store: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    _lock: std::fs::File,
}
impl Service {
    /// `random` is a cryptographic 256-bit lowercase hex value from native code.
    pub fn start(store: PathBuf, random: impl FnOnce() -> Result<String>) -> Result<Self> {
        safe_path(&store)?;
        let lock_path = store.join("profile-service.lock");
        safe_path(&lock_path)?;
        if !lock_path.exists() {
            match create(&lock_path, b"") {
                Ok(()) => {}
                Err(e) if lock_path.exists() => {
                    let _ = e;
                }
                Err(e) => return Err(e),
            }
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| err("file_access"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| err("profile_service_busy"))?;
        let record_path = store.join("profile-service.json");
        let (record, listener) = if record_path.exists() {
            let r: Record = serde_json::from_slice(&read(&record_path)?)
                .map_err(|_| err("profile_service_record"))?;
            if r.schema != 1 || r.port < 1024 || !digest(&r.token) {
                return Err(err("profile_service_record"));
            }
            let l = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, r.port))
                .map_err(|_| err("profile_service_port_busy"))?;
            (r, l)
        } else {
            let token = random()?;
            if !digest(&token) {
                return Err(err("profile_service_record"));
            }
            let l = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| err("profile_service_unavailable"))?;
            let r = Record {
                schema: 1,
                port: l
                    .local_addr()
                    .map_err(|_| err("profile_service_unavailable"))?
                    .port(),
                token,
            };
            create(
                &record_path,
                &serde_json::to_vec(&r).map_err(|_| err("profile_service_record"))?,
            )?;
            (r, l)
        };
        listener
            .set_nonblocking(true)
            .map_err(|_| err("profile_service_unavailable"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let root = store.clone();
        let token = record.token.clone();
        let port = record.port;
        let task = thread::Builder::new()
            .name("clash-profile-service".into())
            .spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, peer)) if peer.ip().is_loopback() => {
                            let _ = serve(&mut stream, &root, &token, port);
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25))
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| err("profile_service_unavailable"))?;
        Ok(Self {
            record,
            store,
            stop,
            thread: Some(task),
            _lock: lock,
        })
    }
    pub fn save(&self, bytes: &[u8]) -> Result<PathBuf> {
        if bytes.len() as u64 > super::MAX {
            return Err(err("file_too_large"));
        }
        let path = self.store.join(format!("profile-{}.yaml", hash(bytes)));
        if path.exists() {
            if read(&path)? != bytes {
                return Err(err("config_changed"));
            }
        } else {
            create(&path, bytes)?;
        }
        Ok(path)
    }
    /// Sensitive local capability URL. Native-only; never log/return to renderer.
    pub fn url(&self, fingerprint: &str) -> Result<String> {
        if !digest(fingerprint) {
            return Err(err("invalid_choice"));
        }
        Ok(format!(
            "http://127.0.0.1:{}/{}/{}.yaml",
            self.record.port, self.record.token, fingerprint
        ))
    }
    pub fn import_uri(&self, fingerprint: &str) -> Result<String> {
        let url = self.url(fingerprint)?;
        let encoded = url
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>();
        Ok(format!(
            "clash://install-config?url={encoded}&name=Mullvad%20Adapter"
        ))
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn request_path<'a>(header: &'a str, token: &str, port: u16) -> Option<&'a str> {
    let mut lines = header.split("\r\n");
    let line = lines.next()?;
    let mut parts = line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    let path = parts.next()?;
    if parts.next()? != "HTTP/1.1" || parts.next().is_some() {
        return None;
    }
    let expected = format!("127.0.0.1:{port}");
    let mut host = false;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            if host || value.trim() != expected {
                return None;
            }
            host = true;
        }
        if ["origin", "referer", "transfer-encoding", "content-length"]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
        {
            return None;
        }
    }
    let fingerprint = path
        .strip_prefix(&format!("/{token}/"))?
        .strip_suffix(".yaml")?;
    (host && digest(fingerprint)).then_some(fingerprint)
}
fn serve(stream: &mut TcpStream, store: &Path, token: &str, port: u16) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut header = Vec::new();
    let mut buf = [0u8; 512];
    while header.len() <= 4096 {
        let count = stream.read(&mut buf)?;
        if count == 0 {
            break;
        }
        header.extend_from_slice(&buf[..count]);
        if header.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let data = if header.len() <= 4096 {
        std::str::from_utf8(&header)
            .ok()
            .and_then(|s| request_path(s, token, port))
            .and_then(|id| {
                read(&store.join(format!("profile-{id}.yaml")))
                    .ok()
                    .filter(|b| hash(b) == id)
            })
    } else {
        None
    };
    if let Some(data) = data {
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/yaml; charset=utf-8\r\nContent-Disposition: attachment; filename=Mullvad-Adapter.yaml\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n",data.len())?;
        stream.write_all(&data)
    } else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_requires_exact_host_and_path_and_rejects_browser_origins() {
        let token = "a".repeat(64);
        let id = "b".repeat(64);
        let request = format!("GET /{token}/{id}.yaml HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n");
        assert_eq!(request_path(&request, &token, 12345), Some(id.as_str()));
        for bad in [
            request.replace("GET ", "POST "),
            request.replace("127.0.0.1:12345", "evil.example"),
            request.replace("\r\n\r\n", "\r\nOrigin: https://evil.example\r\n\r\n"),
            request.replace(&id, "../private"),
            request.replace(&token, &"c".repeat(64)),
            request.replace("\r\n\r\n", "\r\nHost: 127.0.0.1:12345\r\n\r\n"),
        ] {
            assert!(request_path(&bad, &token, 12345).is_none());
        }
    }
    #[test]
    fn service_survives_restart_and_serves_only_immutable_verified_files() {
        let root = std::env::temp_dir();
        // Windows canonicalize adds a verbatim/UNC prefix, deliberately outside
        // our local user-file policy. Production uses the OS AppRoot path.
        #[cfg(not(windows))]
        let root = root.canonicalize().unwrap();
        let root = root.join(format!(
            "adapter-profile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let s = Service::start(root.clone(), || Ok("a".repeat(64))).unwrap();
        let content = b"rules: [MATCH,DIRECT]";
        let path = s.save(content).unwrap();
        let url = s.url(&hash(content)).unwrap();
        let port = s.record.port;
        let get = |s: &Service| {
            let mut c = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, s.record.port)).unwrap();
            write!(
                c,
                "GET /{}/{}.yaml HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                s.record.token,
                hash(content),
                s.record.port
            )
            .unwrap();
            let mut b = Vec::new();
            c.read_to_end(&mut b).unwrap();
            b
        };
        let first = get(&s);
        assert!(first.ends_with(content));
        let headers = std::str::from_utf8(&first[..first.len() - content.len()]).unwrap();
        assert!(headers
            .contains("\r\nContent-Disposition: attachment; filename=Mullvad-Adapter.yaml\r\n"));
        drop(s);
        let s = Service::start(root.clone(), || panic!("must reuse durable identity")).unwrap();
        assert_eq!(s.record.port, port);
        assert_eq!(s.url(&hash(content)).unwrap(), url);
        assert!(get(&s).ends_with(content));
        std::fs::write(&path, b"changed").unwrap();
        assert!(get(&s).starts_with(b"HTTP/1.1 404"));
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
}
