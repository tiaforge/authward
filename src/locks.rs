//! Per-session async locks, keyed by session ID. Guards the refresh SQL +
//! IdP call together (Phase 2's locked-in concurrency decision) so
//! concurrent requests against one expiring session collapse into a
//! single refresh call, rather than racing — important with strict IdPs
//! that rotate (and invalidate) the refresh token on every use.
//!
//! Entries are cleaned up opportunistically after each use via
//! `DashMap::remove_if`, which holds the shard lock for the whole
//! check-and-remove, so it can't race with a concurrent `entry()` call on
//! the same key: either the remove fully precedes the next `entry()` (which
//! then creates a fresh lock, correct — the previous holder is long gone),
//! or `entry()` fully precedes the remove (which then observes the
//! now-higher strong count and correctly skips removal). Without this, the
//! map would grow by one entry per session for the life of the process.

use std::future::Future;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct SessionLocks {
    map: DashMap<String, Arc<Mutex<()>>>,
}

impl SessionLocks {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn with_lock<F, Fut, T>(&self, session_id: &str, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let mutex = self
            .map
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();

        let guard = mutex.lock().await;
        let result = f().await;
        drop(guard);

        // Only safe to drop our clone before the strong-count check below —
        // otherwise this reference alone would always keep the count above 1.
        drop(mutex);
        self.map
            .remove_if(session_id, |_, v| Arc::strong_count(v) == 1);

        result
    }
}
