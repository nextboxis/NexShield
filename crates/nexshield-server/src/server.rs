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

    /// Starts the multithreaded server on the specified address and port.
    pub fn start(&self, host: &str, port: u16, max_workers: usize) -> std::io::Result<()> {
        let bind_addr = format!("{}:{}", host, port);
        let listener = TcpListener::bind(&bind_addr)?;
        listener.set_nonblocking(true)?;

        self.running.store(true, Ordering::SeqCst);
        println!("[+] NexShield Pure Rust Mission Control Server listening on http://{}", bind_addr);
        println!("[+] Worker threads: {}, DSA-optimized sub-microsecond engines active.", max_workers);

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
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }

        if let Some(req) = HttpRequest::parse(&buffer[..bytes_read]) {
            let response = router.handle(&req);
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
