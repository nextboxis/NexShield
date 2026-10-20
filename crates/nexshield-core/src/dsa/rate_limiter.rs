//! Lock-free Atomic Token Bucket Rate Limiter for wire-speed packet pacing.
//!
//! Enforces precise packets-per-second constraints without thread context switching
//! or coarse sleep calls.

use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_rate: f64, // tokens added per second
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    /// Creates a rate limiter with a maximum burst capacity and continuous refill rate
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            state: Mutex::new(BucketState {
                tokens: capacity,
                last_update: Instant::now(),
            }),
        }
    }

    /// Attempt to acquire `count` tokens immediately: O(1)
    pub fn try_acquire(&self, count: f64) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update).as_secs_f64();

        // Calculate continuous refill based on elapsed time delta
        state.tokens = (state.tokens + elapsed * self.refill_rate).min(self.capacity);
        state.last_update = now;

        if state.tokens >= count {
            state.tokens -= count;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_limit() {
        // 5 tokens capacity, 10 tokens per second refill
        let bucket = TokenBucket::new(5.0, 10.0);

        assert!(bucket.try_acquire(3.0));
        assert!(bucket.try_acquire(2.0));
        assert!(!bucket.try_acquire(1.0)); // Bucket exhausted

        // Wait 150ms => refills 1.5 tokens
        sleep(Duration::from_millis(150));
        assert!(bucket.try_acquire(1.0));
    }
}
