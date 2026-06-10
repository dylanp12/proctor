//! Allowlist egress. Host side: a CONNECT proxy on a unix socket, enforcing
//! the allowlist and recording every decision. Sandbox side: a 127.0.0.1:3128
//! TCP listener that splices each connection to the bind-mounted unix socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct ProxyDecision {
    pub target: String,
    pub allowed: bool,
}

pub struct HostProxy {
    decisions: Arc<Mutex<Vec<ProxyDecision>>>,
    _sock_path: std::path::PathBuf,
}

impl HostProxy {
    /// Bind the unix socket and serve CONNECT requests on a background thread.
    pub fn start(sock: &Path, allow: Vec<String>) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        let decisions = Arc::new(Mutex::new(Vec::new()));
        let allow: Arc<Vec<String>> = Arc::new(allow);
        let dec = decisions.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let allow = allow.clone();
                let dec = dec.clone();
                std::thread::spawn(move || {
                    let _ = serve_connect(conn, &allow, &dec);
                });
            }
        });
        Ok(Self {
            decisions,
            _sock_path: sock.to_path_buf(),
        })
    }

    pub fn decisions(&self) -> Vec<ProxyDecision> {
        self.decisions.lock().unwrap().clone()
    }
}

fn serve_connect(
    mut client: UnixStream,
    allow: &[String],
    dec: &Mutex<Vec<ProxyDecision>>,
) -> std::io::Result<()> {
    // read the request line + headers (up to the blank line)
    let mut reader = BufReader::new(client.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        headers.push(h);
    }

    let mut tokens = request_line.split_whitespace();
    let method = tokens.next().unwrap_or("");
    let uri = tokens.next().unwrap_or("");
    let version = tokens.next().unwrap_or("HTTP/1.1");

    // CONNECT host:port (https tunnel) vs. absolute-form GET http://host/path
    let connect = method.eq_ignore_ascii_case("CONNECT");
    let target = if connect {
        uri.to_string()
    } else {
        host_port_from_url(uri)
    };

    let allowed = !target.is_empty() && allow.iter().any(|a| a == &target);
    dec.lock().unwrap().push(ProxyDecision {
        target: target.clone(),
        allowed,
    });
    if !allowed {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    }
    let upstream = match std::net::TcpStream::connect(&target) {
        Ok(u) => u,
        Err(_) => {
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
            return Ok(());
        }
    };
    if connect {
        // tunnel: confirm, then pipe bytes both ways
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        splice_bidir(client, upstream);
    } else {
        // forward proxy: replay the request in origin form, then pipe the rest
        let path = origin_form_path(uri);
        let mut up = upstream;
        let mut head = format!("{method} {path} {version}\r\n");
        for h in &headers {
            head.push_str(h);
        }
        head.push_str("\r\n");
        up.write_all(head.as_bytes())?;
        forward_bidir(reader, client, up);
    }
    Ok(())
}

/// Extract "host:port" from an absolute URL, defaulting the port by scheme.
fn host_port_from_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority); // strip userinfo
    if authority.is_empty() {
        return String::new();
    }
    if authority.contains(':') {
        authority.to_string()
    } else {
        let port = if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        format!("{authority}:{port}")
    }
}

/// Convert an absolute-form URI to origin form (path+query) for the upstream.
fn origin_form_path(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    match after_scheme.find('/') {
        Some(i) => after_scheme[i..].to_string(),
        None => "/".to_string(),
    }
}

/// Copy both directions until EOF (CONNECT tunnel: unix client <-> tcp origin).
fn splice_bidir(a: UnixStream, b: std::net::TcpStream) {
    let (mut a_r, mut a_w) = (a.try_clone().unwrap(), a);
    let (mut b_r, mut b_w) = (b.try_clone().unwrap(), b);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_r, &mut b_w);
        let _ = b_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut b_r, &mut a_w);
    let _ = a_w.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

/// Forward-proxy piping: `reader` is the buffered client read side (may hold a
/// request body), `client` the client write side, `up` the origin connection.
fn forward_bidir(mut reader: BufReader<UnixStream>, client: UnixStream, up: std::net::TcpStream) {
    let mut up_w = up.try_clone().unwrap();
    let mut up_r = up;
    let mut client_w = client;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut up_w);
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut up_r, &mut client_w);
    let _ = client_w.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

/// Sandbox side: listen on 127.0.0.1:3128 and splice each TCP connection to the
/// bind-mounted unix socket. Runs as a detached thread inside the netns.
pub fn start_in_ns_forwarder(sock: &Path) -> Result<(), String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:3128").map_err(|e| format!("bind 3128: {e}"))?;
    let sock = sock.to_path_buf();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut tcp) = conn else { continue };
            let sock = sock.clone();
            std::thread::spawn(move || {
                let Ok(unix) = UnixStream::connect(&sock) else {
                    return;
                };
                let mut tcp_r = tcp.try_clone().unwrap();
                let (mut u_r, mut u_w) = (unix.try_clone().unwrap(), unix);
                let t = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut tcp_r, &mut u_w);
                    let _ = u_w.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut u_r, &mut tcp);
                let _ = t.join();
            });
        }
    });
    Ok(())
}
