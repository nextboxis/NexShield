//! Native Multi-Threaded TCP Port Scanner Engine for NexShield.
//!
//! Powered by PortBitmap (8 KB port state representation) and TokenBucket (wire-speed rate limiting).

use nexshield_core::{PortBitmap, TokenBucket};
use nexshield_types::{HostPort, PortState, Protocol, ScanResult};

use crate::prober::probe_port;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// RFC 6298 Jacobson/Karels Adaptive RTT & Timeout Estimator (Lock-Free Atomic).
pub struct AdaptiveRttEstimator {
    srtt_us: AtomicU64,
    rttvar_us: AtomicU64,
    samples: AtomicUsize,
}

impl AdaptiveRttEstimator {
    pub fn new(initial_timeout: Duration) -> Self {
        let init_us = initial_timeout.as_micros() as u64;
        Self {
            srtt_us: AtomicU64::new(init_us),
            rttvar_us: AtomicU64::new(init_us / 2),
            samples: AtomicUsize::new(0),
        }
    }

    /// Record a measured TCP connect RTT sample in microseconds.
    pub fn record_sample(&self, rtt: Duration) {
        let r_us = (rtt.as_micros() as u64).max(200);
        let prev_count = self.samples.fetch_add(1, Ordering::Relaxed);
        if prev_count == 0 {
            self.srtt_us.store(r_us, Ordering::Relaxed);
            self.rttvar_us.store(r_us / 2, Ordering::Relaxed);
        } else {
            let srtt = self.srtt_us.load(Ordering::Relaxed);
            let rttvar = self.rttvar_us.load(Ordering::Relaxed);
            let delta = srtt.abs_diff(r_us);
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
            let next_var = (rttvar * 3 + delta) / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R
            let next_srtt = (srtt * 7 + r_us) / 8;
            self.rttvar_us.store(next_var, Ordering::Relaxed);
            self.srtt_us.store(next_srtt, Ordering::Relaxed);
        }
    }

    /// Compute adaptive RTO = SRTT + 4 * RTTVAR, clamped to [45ms, max_timeout].
    pub fn current_rto(&self, max_timeout: Duration) -> Duration {
        if self.samples.load(Ordering::Relaxed) < 2 {
            return max_timeout;
        }
        let srtt = self.srtt_us.load(Ordering::Relaxed);
        let rttvar = self.rttvar_us.load(Ordering::Relaxed);
        let rto_us = srtt.saturating_add(rttvar.saturating_mul(4));
        let min_us = 45_000; // 45ms floor for reliable local/LAN probing
        let max_us = max_timeout.as_micros() as u64;
        Duration::from_micros(rto_us.clamp(min_us, max_us.max(min_us)))
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub rate_limit_pps: Option<f64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            ports: crate::target::DEFAULT_PORTS.to_vec(),
            timeout: Duration::from_millis(300),
            concurrency: 100,
            rate_limit_pps: Some(2500.0), // 2500 packets/sec
        }
    }
}

pub struct ScanOutcome {
    pub result: ScanResult,
    pub bitmap: PortBitmap,
}

/// Executes a native concurrent TCP scan against the specified target.
pub fn scan_target(options: ScanOptions) -> ScanOutcome {
    let start_time = Instant::now();
    let ports = options.ports;
    let total_ports = ports.len();

    let rate_limiter = options
        .rate_limit_pps
        .map(|pps| Arc::new(TokenBucket::new(pps, pps)));

    let (tx, rx) = channel::<u16>();
    let port_index = Arc::new(AtomicUsize::new(0));
    let ports_arc = Arc::new(ports);
    let rtt_estimator = Arc::new(AdaptiveRttEstimator::new(options.timeout));

    let worker_count = options.concurrency.min(total_ports).max(1);
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let p_idx = Arc::clone(&port_index);
        let p_list = Arc::clone(&ports_arc);
        let target = options.target;
        let timeout = options.timeout;
        let limiter = rate_limiter.clone();
        let rtt = Arc::clone(&rtt_estimator);
        let thread_tx = tx.clone();

        let handle = thread::spawn(move || {
            loop {
                let idx = p_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= p_list.len() {
                    break;
                }

                let port = p_list[idx];

                // Rate limiting via atomic token bucket: O(1)
                if let Some(ref l) = limiter {
                    while !l.try_acquire(1.0) {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                // Attempt TCP Connect with RFC 6298 Adaptive RTO
                let addr = SocketAddr::new(target, port);
                let dynamic_timeout = rtt.current_rto(timeout);
                let t0 = Instant::now();
                if TcpStream::connect_timeout(&addr, dynamic_timeout).is_ok() {
                    rtt.record_sample(t0.elapsed());
                    let _ = thread_tx.send(port);
                }
            }
        });
        handles.push(handle);
    }

    // Drop main sender so receiver loop closes when workers complete
    drop(tx);

    let mut bitmap = PortBitmap::new();
    while let Ok(open_port) = rx.recv() {
        bitmap.set(open_port); // O(1) bit set
    }

    // Wait for all workers to join
    for h in handles {
        let _ = h.join();
    }

    // Banner grab open ports and construct detailed HostPort records
    let mut host_ports = Vec::new();
    for open_port in bitmap.iter_open() {
        let probe = probe_port(options.target, open_port, options.timeout);
        host_ports.push(HostPort {
            port: open_port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: probe.service,
            version: probe.version,
            banner: probe.banner,
        });
    }

    let elapsed = start_time.elapsed();
    let scan_result = ScanResult {
        target: options.target.to_string(),
        resolved_ip: Some(options.target),
        ports: host_ports,
        os_name: None,
        os_accuracy: 0,
        duration_ms: elapsed.as_millis() as u64,
        scanned_at: chrono_like_now(),
    };

    ScanOutcome {
        result: scan_result,
        bitmap,
    }
}

fn chrono_like_now() -> String {
    // Generate ISO timestamp without external chrono crate
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}s", d.as_secs()))
        .unwrap_or_else(|_| "0s".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn test_native_scan_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
        let test_port = listener.local_addr().unwrap().port();
        let _ = listener.set_nonblocking(true);

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let server_thread = thread::spawn(move || {
            while shutdown_rx.try_recv().is_err() {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(b"SSH-2.0-NexShield_Test_1.0\r\n");
                }
                thread::sleep(Duration::from_millis(2));
            }
        });

        // Small pause to let listener start
        thread::sleep(Duration::from_millis(10));

        let ports_to_scan = vec![test_port, 49991, 49992];
        let options = ScanOptions {
            target: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            ports: ports_to_scan,
            timeout: Duration::from_millis(500),
            concurrency: 2,
            rate_limit_pps: None,
        };

        let outcome = scan_target(options);
        let _ = shutdown_tx.send(());
        let _ = server_thread.join();

        assert!(outcome.bitmap.contains(test_port));
        assert!(!outcome.bitmap.contains(49991));
        assert_eq!(outcome.bitmap.count_open(), 1);
        assert_eq!(outcome.result.ports.len(), 1);
        assert_eq!(outcome.result.ports[0].port, test_port);
        assert_eq!(outcome.result.ports[0].service, "ssh");
    }
}
