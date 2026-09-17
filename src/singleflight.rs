// src/singleflight.rs
//
// Request coalescing for concurrent identical cache misses.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Clone)]
pub struct SingleFlight<T: Clone + Send + Sync + 'static> {
    inner: Arc<Inner<T>>,
}

struct Inner<T: Clone + Send + Sync + 'static> {
    flights: DashMap<String, Arc<OnceCell<T>>>,
}

impl<T: Clone + Send + Sync + 'static> SingleFlight<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                flights: DashMap::new(),
            }),
        }
    }

    /// Run `f` once for `key`. Concurrent callers with the same key
    /// share the result. Returns `(value, was_leader)` so callers can
    /// distinguish who actually did the work.
    pub async fn run<F, Fut>(&self, key: String, f: F) -> (T, bool)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let (cell, is_leader) = match self.inner.flights.entry(key.clone()) {
            Entry::Occupied(e) => (e.get().clone(), false),
            Entry::Vacant(e) => {
                let c = Arc::new(OnceCell::new());
                e.insert(c.clone());
                (c, true)
            }
        };

        let _guard = is_leader.then(|| FlightGuard {
            inner: self.inner.clone(),
            key: key.clone(),
        });

        let value = cell.get_or_init(f).await.clone();
        (value, is_leader)
    }
}

struct FlightGuard<T: Clone + Send + Sync + 'static> {
    inner: Arc<Inner<T>>,
    key: String,
}

impl<T: Clone + Send + Sync + 'static> Drop for FlightGuard<T> {
    fn drop(&mut self) {
        self.inner.flights.remove(&self.key);
    }
}
