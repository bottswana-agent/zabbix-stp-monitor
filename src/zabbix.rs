//! Minimal implementation of the Zabbix sender (trapper) protocol.
//!
//! See <https://www.zabbix.com/documentation/current/en/manual/appendix/protocols/zabbix_sender>
//! and <https://www.zabbix.com/documentation/current/en/manual/appendix/protocols/header_datalen>.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Value {
    pub key: String,
    pub value: String,
    pub clock: i64,
}

impl Value {
    pub fn new(key: impl Into<String>, value: impl ToString, clock: i64) -> Self {
        Value {
            key: key.into(),
            value: value.to_string(),
            clock,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SendResult {
    pub processed: u64,
    pub failed: u64,
    pub total: u64,
}

/// A Zabbix trapper endpoint.
type Endpoint = (String, u16);

/// Parse `host`, `host:port`, `[v6addr]:port` or a bare IPv6 address.
pub fn parse_endpoint(s: &str, default_port: u16) -> Endpoint {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']') {
            let port = p
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (h.to_string(), port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default_port)),
        _ => (s.to_string(), default_port),
    }
}

/// Sends values to Zabbix.
///
/// * Several servers can be configured (Zabbix HA cluster nodes, or a list of
///   proxies). They are tried in order until one accepts the data; the one
///   that worked is tried first next time. Only the active HA node accepts
///   data, so this follows a failover automatically.
/// * Zabbix 7.0 proxy groups: if the receiving proxy answers with a
///   `redirect` to the proxy currently responsible for the host, the data is
///   re-sent there and that proxy is used until it fails or Zabbix resets
///   the redirect.
pub struct Sender {
    endpoints: Vec<Endpoint>,
    preferred: Cell<usize>,
    redirect: RefCell<Option<Endpoint>>,
    host: String,
    timeout: Duration,
}

/// Outcome of one exchange with one endpoint.
#[derive(Debug, PartialEq)]
pub enum Reply {
    Accepted(SendResult),
    /// Zabbix 7.0 proxy-group redirect to another proxy.
    Redirect(String),
    /// Zabbix asked us to forget a previous redirect.
    ResetRedirect,
}

impl Sender {
    /// `servers` is a `,`/`;` separated list of `host[:port]`.
    pub fn new(servers: &str, port: u16, host: &str, timeout_secs: u64) -> Self {
        let endpoints = servers
            .split([',', ';'])
            .filter(|s| !s.trim().is_empty())
            .map(|s| parse_endpoint(s, port))
            .collect();
        Sender {
            endpoints,
            preferred: Cell::new(0),
            redirect: RefCell::new(None),
            host: host.to_string(),
            timeout: Duration::from_secs(timeout_secs.max(1)),
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn endpoints(&self) -> String {
        self.endpoints
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn send(&self, values: &[Value]) -> Result<SendResult> {
        let packet = encode(&self.host, values);

        // A redirect from a proxy group takes precedence while it works.
        let redirect = self.redirect.borrow().clone();
        if let Some(ep) = redirect {
            match self.exchange(&ep, &packet) {
                Ok(Reply::Accepted(r)) => return Ok(r),
                other => {
                    log::info!("dropping Zabbix redirect to {}:{} ({other:?})", ep.0, ep.1);
                    *self.redirect.borrow_mut() = None;
                }
            }
        }

        let n = self.endpoints.len();
        let mut errors = Vec::new();
        for i in 0..n {
            let idx = (self.preferred.get() + i) % n;
            let ep = &self.endpoints[idx];
            match self.send_following_redirect(ep, &packet) {
                Ok(r) => {
                    if idx != self.preferred.get() {
                        log::info!("Zabbix data now going to {}:{}", ep.0, ep.1);
                        self.preferred.set(idx);
                    }
                    return Ok(r);
                }
                Err(e) => errors.push(format!("{}:{}: {e:#}", ep.0, ep.1)),
            }
        }
        bail!("no Zabbix server accepted the data: {}", errors.join("; "))
    }

    fn send_following_redirect(&self, ep: &Endpoint, packet: &[u8]) -> Result<SendResult> {
        match self.exchange(ep, packet)? {
            Reply::Accepted(r) => Ok(r),
            Reply::ResetRedirect => bail!("Zabbix reset the redirect without accepting data"),
            Reply::Redirect(addr) => {
                let target = parse_endpoint(&addr, ep.1);
                log::info!(
                    "Zabbix {}:{} redirected us to {}:{}",
                    ep.0,
                    ep.1,
                    target.0,
                    target.1
                );
                match self.exchange(&target, packet)? {
                    Reply::Accepted(r) => {
                        *self.redirect.borrow_mut() = Some(target);
                        Ok(r)
                    }
                    other => bail!("unexpected reply after redirect: {other:?}"),
                }
            }
        }
    }

    fn exchange(&self, ep: &Endpoint, packet: &[u8]) -> Result<Reply> {
        let addr = (ep.0.as_str(), ep.1)
            .to_socket_addrs()
            .with_context(|| format!("resolving {}", ep.0))?
            .next()
            .with_context(|| format!("no address for {}", ep.0))?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout).context("connecting")?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(packet).context("sending")?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("reading response")?;
        decode_response(&response)
    }
}

/// Build a complete sender packet: `ZBXD\x01` + u32 LE length + u32 reserved + JSON.
pub fn encode(host: &str, values: &[Value]) -> Vec<u8> {
    let data: Vec<_> = values
        .iter()
        .map(|v| json!({"host": host, "key": v.key, "value": v.value, "clock": v.clock}))
        .collect();
    let body = json!({"request": "sender data", "data": data}).to_string();
    let mut packet = Vec::with_capacity(13 + body.len());
    packet.extend_from_slice(b"ZBXD\x01");
    packet.extend_from_slice(&(body.len() as u32).to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(body.as_bytes());
    packet
}

pub fn decode_response(buf: &[u8]) -> Result<Reply> {
    if buf.len() < 13 || &buf[..4] != b"ZBXD" {
        bail!("invalid response from Zabbix ({} bytes)", buf.len());
    }
    let flags = buf[4];
    if flags & 0x02 != 0 {
        bail!("compressed Zabbix responses are not supported");
    }
    let (len, start) = if flags & 0x04 != 0 {
        // "large packet" header: 8-byte lengths
        if buf.len() < 21 {
            bail!("truncated large-packet header");
        }
        (
            u64::from_le_bytes(buf[5..13].try_into().unwrap()) as usize,
            21,
        )
    } else {
        (
            u32::from_le_bytes(buf[5..9].try_into().unwrap()) as usize,
            13,
        )
    };
    let body = buf
        .get(start..start + len)
        .context("truncated Zabbix response")?;
    let v: serde_json::Value =
        serde_json::from_slice(body).context("Zabbix response is not JSON")?;

    // Zabbix 7.0 proxy groups. The redirect object carries the address of the
    // proxy that now owns the host; `reset` means "forget the redirect".
    if let Some(r) = v.get("redirect") {
        if r.get("reset").and_then(|x| x.as_bool()) == Some(true) {
            return Ok(Reply::ResetRedirect);
        }
        if let Some(addr) = r.get("address").and_then(|a| a.as_str()) {
            return Ok(Reply::Redirect(addr.to_string()));
        }
    }
    if v["response"] != "success" {
        bail!("Zabbix rejected the data: {v}");
    }
    let info = v["info"].as_str().unwrap_or_default();
    Ok(Reply::Accepted(parse_info(info)))
}

/// Parse `processed: 3; failed: 0; total: 3; seconds spent: 0.000055`.
fn parse_info(info: &str) -> SendResult {
    let mut r = SendResult::default();
    for part in info.split(';') {
        let mut kv = part.splitn(2, ':');
        let (Some(k), Some(v)) = (kv.next(), kv.next()) else {
            continue;
        };
        let n = v.trim().parse().unwrap_or(0);
        match k.trim() {
            "processed" => r.processed = n,
            "failed" => r.failed = n,
            "total" => r.total = n,
            _ => {}
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn encodes_header() {
        let p = encode("h", &[Value::new("k", 1, 5)]);
        assert_eq!(&p[..5], b"ZBXD\x01");
        let len = u32::from_le_bytes(p[5..9].try_into().unwrap()) as usize;
        assert_eq!(len, p.len() - 13);
        let v: serde_json::Value = serde_json::from_slice(&p[13..]).unwrap();
        assert_eq!(v["request"], "sender data");
        assert_eq!(v["data"][0]["host"], "h");
        assert_eq!(v["data"][0]["value"], "1");
        assert_eq!(v["data"][0]["clock"], 5);
    }

    #[test]
    fn round_trip_against_fake_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut hdr = [0u8; 13];
            s.read_exact(&mut hdr).unwrap();
            let len = u32::from_le_bytes(hdr[5..9].try_into().unwrap()) as usize;
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).unwrap();
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let n = req["data"].as_array().unwrap().len();
            let resp = format!(
                r#"{{"response":"success","info":"processed: {}; failed: 1; total: {n}; seconds spent: 0.0001"}}"#,
                n - 1
            );
            let mut out = b"ZBXD\x01".to_vec();
            out.extend_from_slice(&(resp.len() as u32).to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(resp.as_bytes());
            s.write_all(&out).unwrap();
        });
        let sender = Sender::new("127.0.0.1", port, "test", 2);
        let r = sender
            .send(&[Value::new("a", 1, 0), Value::new("b", "x", 0)])
            .unwrap();
        assert_eq!(
            r,
            SendResult {
                processed: 1,
                failed: 1,
                total: 2
            }
        );
        server.join().unwrap();
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut buf = b"ZBXD\x01".to_vec();
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(body);
        buf
    }

    /// Fake trapper: answers each connection with the next canned response.
    fn fake_server(responses: Vec<String>) -> (u16, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let n = responses.len();
            for resp in responses {
                let (mut s, _) = listener.accept().unwrap();
                let mut hdr = [0u8; 13];
                s.read_exact(&mut hdr).unwrap();
                let len = u32::from_le_bytes(hdr[5..9].try_into().unwrap()) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).unwrap();
                s.write_all(&frame(resp.as_bytes())).unwrap();
            }
            n
        });
        (port, h)
    }

    const OK: &str = r#"{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.0001"}"#;

    #[test]
    fn fails_over_to_next_server() {
        // Grab a free port and close it so the first server refuses connections
        // (like a Zabbix HA standby node).
        let dead = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (port, h) = fake_server(vec![OK.into(), OK.into()]);
        let sender = Sender::new(
            &format!("127.0.0.1:{dead}; 127.0.0.1:{port}"),
            10051,
            "h",
            2,
        );
        assert_eq!(sender.send(&[Value::new("a", 1, 0)]).unwrap().processed, 1);
        // Second send goes straight to the working node.
        assert_eq!(sender.send(&[Value::new("a", 1, 0)]).unwrap().processed, 1);
        assert_eq!(sender.preferred.get(), 1);
        h.join().unwrap();
    }

    #[test]
    fn follows_proxy_group_redirect() {
        let (p2, h2) = fake_server(vec![OK.into(), OK.into()]);
        let redirect = format!(
            r#"{{"response":"success","redirect":{{"revision":1,"address":"127.0.0.1:{p2}"}}}}"#
        );
        let (p1, h1) = fake_server(vec![redirect]);
        let sender = Sender::new(&format!("127.0.0.1:{p1}"), 10051, "h", 2);
        assert_eq!(sender.send(&[Value::new("a", 1, 0)]).unwrap().processed, 1);
        // Subsequent sends go to the redirected proxy directly.
        assert_eq!(sender.send(&[Value::new("a", 1, 0)]).unwrap().processed, 1);
        h1.join().unwrap();
        h2.join().unwrap();
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(parse_endpoint("zbx", 10051), ("zbx".into(), 10051));
        assert_eq!(parse_endpoint(" zbx:20051 ", 10051), ("zbx".into(), 20051));
        assert_eq!(
            parse_endpoint("[fd00::1]:20051", 10051),
            ("fd00::1".into(), 20051)
        );
        assert_eq!(parse_endpoint("fd00::1", 10051), ("fd00::1".into(), 10051));
    }

    #[test]
    fn rejects_failure_response() {
        let body = br#"{"response":"failed","info":"x"}"#;
        let mut buf = b"ZBXD\x01".to_vec();
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(body);
        assert!(decode_response(&buf).is_err());
        assert!(matches!(
            decode_response(&frame(br#"{"response":"success","redirect":{"revision":3,"address":"proxy2:10051"}}"#)),
            Ok(Reply::Redirect(a)) if a == "proxy2:10051"
        ));
        assert!(decode_response(b"junk").is_err());
    }
}
