//! Multithreaded pure standard library HTTP server engine for NexShield.

use crate::http::{HttpRequest, HttpResponse};
use crate::router::{AppState, Router};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct HttpServer {
    router: Arc<Router>,
    running: Arc<AtomicBool>,
}

impl HttpServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            router: Arc::new(Router::new(state)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the multithreaded server on the specified address and port, automatically falling back if port is busy.
    pub fn start(&self, host: &str, start_port: u16, max_workers: usize) -> std::io::Result<()> {
        let mut port = start_port;
        let listener = loop {
            let bind_addr = format!("{}:{}", host, port);
            match TcpListener::bind(&bind_addr) {
                Ok(l) => break l,
                Err(e) if (e.kind() == std::io::ErrorKind::AddrInUse || e.raw_os_error() == Some(10048)) && port < start_port + 20 => {
                    println!("[!] Port {} is busy (AddrInUse). Trying next available port {}...", port, port + 1);
                    port += 1;
                }
                Err(e) => return Err(e),
            }
        };
        let bound_addr = format!("{}:{}", host, port);
        listener.set_nonblocking(true)?;

        self.running.store(true, Ordering::SeqCst);
        println!("\n[🚀] NexShield Pure Rust Mission Control Server is LIVE at: http://{}", bound_addr);
        println!("[+] Worker threads: {}, DSA-optimized sub-microsecond engines active.", max_workers);
        println!("[*] Press Ctrl+C to terminate.\n");

        let running = Arc::clone(&self.running);
        let router = Arc::clone(&self.router);

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _peer)) => {
                    let r = Arc::clone(&router);
                    thread::spawn(move || {
                        let _ = Self::handle_connection(stream, r);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => {
                    eprintln!("[-] Accept error: {}", e);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn handle_connection(mut stream: TcpStream, router: Arc<Router>) -> std::io::Result<()> {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let mut buffer = Vec::with_capacity(8192);
        let mut temp_buf = [0u8; 4096];
        let mut header_end = 0;
        let mut content_length = 0;

        loop {
            let bytes_read = match stream.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e),
            };
            buffer.extend_from_slice(&temp_buf[..bytes_read]);

            // Detect header boundary if not already found
            if header_end == 0 {
                for (i, w) in buffer.windows(4).enumerate() {
                    if w == b"\r\n\r\n" {
                        header_end = i + 4;
                        break;
                    }
                }
                if header_end == 0 {
                    for (i, w) in buffer.windows(2).enumerate() {
                        if w == b"\n\n" {
                            header_end = i + 2;
                            break;
                        }
                    }
                }

                if header_end > 0 {
                    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
                    for line in header_str.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                if let Ok(cl) = v.trim().parse::<usize>() {
                                    content_length = cl;
                                }
                            }
                        }
                    }
                }
            }

            if header_end > 0 {
                let body_len = buffer.len().saturating_sub(header_end);
                if body_len >= content_length {
                    break;
                }
            }

            if buffer.len() > 1024 * 1024 {
                break;
            }
        }

        if buffer.is_empty() {
            return Ok(());
        }

        if let Some(req) = HttpRequest::parse(&buffer) {
            let response = router.handle(&req);
            if req.path.starts_with("/api") || req.path == "/" || req.path == "/report" {
                println!("  [HTTP] {} {} -> {}", req.method, req.path, response.status);
            }
            let response_bytes = response.to_bytes();
            stream.write_all(&response_bytes)?;
            stream.flush()?;
        } else {
            let bad_req = HttpResponse::bad_request("Malformed HTTP request");
            stream.write_all(&bad_req.to_bytes())?;
            stream.flush()?;
        }

        Ok(())
    }
}
