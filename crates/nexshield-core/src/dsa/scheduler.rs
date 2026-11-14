//! Min-Heap Priority Scheduler & Circular Ring-Buffer Event Bus.
//!
//! Provides O(log N) continuous Attack Surface Management (ASM) task scheduling
//! and an O(1) bounded Ring Buffer for real-time Server-Sent Events (SSE) telemetry.

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::RwLock;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScanScheduleEntry {
    pub id: String,
    pub target: String,
    pub profile: String,
    pub interval_secs: u64,
    pub next_run_epoch_secs: u64,
    pub runs_completed: u64,
}

impl Ord for ScanScheduleEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.next_run_epoch_secs
            .cmp(&other.next_run_epoch_secs)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for ScanScheduleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Binary Min-Heap Scheduler ordered by earliest `next_run_epoch_secs`: O(log N) push/pop.
#[derive(Debug, Default)]
pub struct MinHeapScheduler {
    heap: BinaryHeap<Reverse<ScanScheduleEntry>>,
}

impl MinHeapScheduler {
    pub fn new() -> Self {
        let mut sched = Self {
            heap: BinaryHeap::new(),
        };
        // Seed default continuous ASM baseline policy
        sched.schedule(ScanScheduleEntry {
            id: "ASM-BASELINE-01".to_string(),
            target: "127.0.0.1".to_string(),
            profile: "vuln".to_string(),
            interval_secs: 900,
            next_run_epoch_secs: 1_760_000_900,
            runs_completed: 1,
        });
        sched
    }

    /// Insert a scheduled scan job into the Min-Heap in O(log N) time.
    pub fn schedule(&mut self, entry: ScanScheduleEntry) {
        self.heap.push(Reverse(entry));
    }

    /// Return the number of active scheduled jobs.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Peek at the next scheduled job without removing it: O(1).
    pub fn peek_next(&self) -> Option<&ScanScheduleEntry> {
        self.heap.peek().map(|rev| &rev.0)
    }

    /// Pop all due jobs (`next_run_epoch_secs <= now_secs`), increment their counter,
    /// reschedule them at `now_secs + interval_secs`, and return the due snapshots.
    pub fn pop_due_and_reschedule(&mut self, now_secs: u64) -> Vec<ScanScheduleEntry> {
        let mut due = Vec::new();
        while let Some(Reverse(top)) = self.heap.peek() {
            if top.next_run_epoch_secs <= now_secs {
                let Reverse(mut job) = self.heap.pop().unwrap();
                due.push(job.clone());
                job.runs_completed += 1;
                job.next_run_epoch_secs = now_secs.saturating_add(job.interval_secs.max(10));
                self.heap.push(Reverse(job));
            } else {
                break;
            }
        }
        due
    }

    /// Return all scheduled entries sorted by `next_run_epoch_secs`.
    pub fn list_all(&self) -> Vec<ScanScheduleEntry> {
        let mut items: Vec<ScanScheduleEntry> = self.heap.iter().map(|r| r.0.clone()).collect();
        items.sort();
        items
    }
}

/// Real-Time Telemetry Event stored in the bounded Ring Buffer.
#[derive(Debug, Clone)]
pub struct StreamEvent {
    pub seq: u64,
    pub event_type: String,
    pub target: String,
    pub message: String,
    pub severity: String,
    pub timestamp_secs: u64,
}

/// Thread-safe bounded Circular Ring Buffer for real-time SSE telemetry streaming.
pub struct EventRingBuffer {
    capacity: usize,
    seq_counter: AtomicU64,
    ring: RwLock<VecDeque<StreamEvent>>,
}

impl EventRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16);
        let bus = Self {
            capacity: cap,
            seq_counter: AtomicU64::new(0),
            ring: RwLock::new(VecDeque::with_capacity(cap)),
        };
        bus.publish(
            "SYSTEM_BOOT",
            "127.0.0.1",
            "NexShield v7.0 Ring-Buffer Telemetry Bus & Sharded RwLock WAL initialized",
            "info",
            1_760_000_000,
        );
        bus
    }

    /// Publish an event to the ring buffer in O(1) amortized time.
    pub fn publish(
        &self,
        event_type: &str,
        target: &str,
        message: &str,
        severity: &str,
        timestamp_secs: u64,
    ) -> u64 {
        let seq = self.seq_counter.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        let ev = StreamEvent {
            seq,
            event_type: event_type.to_string(),
            target: target.to_string(),
            message: message.to_string(),
            severity: severity.to_string(),
            timestamp_secs,
        };
        if let Ok(mut guard) = self.ring.write() {
            if guard.len() >= self.capacity {
                guard.pop_front();
            }
            guard.push_back(ev);
        }
        seq
    }

    /// Read all events with `seq > since_seq` without blocking concurrent readers.
    pub fn read_since(&self, since_seq: u64) -> Vec<StreamEvent> {
        if let Ok(guard) = self.ring.read() {
            guard.iter().filter(|e| e.seq > since_seq).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Current highest sequence number published.
    pub fn head_seq(&self) -> u64 {
        self.seq_counter.load(AtomicOrdering::SeqCst)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_heap_scheduler_and_ring_buffer() {
        let mut sched = MinHeapScheduler::new();
        sched.schedule(ScanScheduleEntry {
            id: "JOB-FAST".to_string(),
            target: "10.0.0.1".to_string(),
            profile: "quick".to_string(),
            interval_secs: 60,
            next_run_epoch_secs: 100,
            runs_completed: 0,
        });

        let due = sched.pop_due_and_reschedule(150);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "JOB-FAST");

        let bus = EventRingBuffer::new(32);
        let s1 = bus.publish("PORT_DISCOVERED", "10.0.0.1", "Port 445/tcp OPEN", "high", 151);
        let events = bus.read_since(s1 - 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "PORT_DISCOVERED");
    }
}
