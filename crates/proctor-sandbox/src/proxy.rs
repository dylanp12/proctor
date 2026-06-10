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
    // read request line: "CONNECT host:port HTTP/1.1\r\n" then headers to blank
    let mut reader = BufReader::new(client.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }
    let allowed = allow.iter().any(|a| a == &target);
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
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    splice_bidir(client, upstream);
    Ok(())
}

/// Copy both directions until EOF.
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
