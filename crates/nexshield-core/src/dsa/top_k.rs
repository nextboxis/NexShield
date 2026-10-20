//! Bounded Min-Heap Priority Queue for live Top-K threat tracking.
//!
//! Provides O(log K) updates and O(1) discards, replacing O(N log N) sorting
//! on streaming security events.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Debug, Clone)]
pub struct TopKTracker<T: Ord> {
    k: usize,
    heap: BinaryHeap<Reverse<T>>,
}

impl<T: Ord> TopKTracker<T> {
    /// Creates a tracker that maintains at most `k` highest-ranked items
    pub fn new(k: usize) -> Self {
        assert!(k > 0, "Top-K capacity must be greater than zero");
        Self {
            k,
            heap: BinaryHeap::with_capacity(k),
        }
    }

    /// Number of items currently tracked
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns true if no items have been tracked
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Insert a candidate item:
    /// - Discard: O(1) if smaller than current top K
    /// - Insert/Replace: O(log K)
    pub fn insert(&mut self, item: T) {
        if self.heap.len() < self.k {
            self.heap.push(Reverse(item));
        } else if let Some(min) = self.heap.peek() {
            if item > min.0 {
                self.heap.pop();
                self.heap.push(Reverse(item));
            }
        }
    }

    /// Return items sorted in descending order (highest ranked first)
    pub fn into_sorted_vec(self) -> Vec<T> {
        let mut items: Vec<T> = self.heap.into_iter().map(|r| r.0).collect();
        items.sort();
        items.reverse();
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_k_tracking() {
        let mut tracker = TopKTracker::new(3);

        tracker.insert(10);
        tracker.insert(50);
        tracker.insert(20);
        tracker.insert(5);  // Should be ignored
        tracker.insert(100); // Should displace 10
        tracker.insert(75);  // Should displace 20

        let result = tracker.into_sorted_vec();
        assert_eq!(result, vec![100, 75, 50]);
    }
}
