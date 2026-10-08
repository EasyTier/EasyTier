//! Lifetime-bound, observable registry of live state claims.
//!
//! A [`Registry<T>`] holds the currently declared values of one or more
//! publishers. A publisher calls [`Registry::register`] and keeps the returned
//! [`Registration<T>`]; dropping that registration withdraws the claim.
//! Readers call [`Registry::snapshot`] and receive `Arc<T>` handles to the live
//! values, in registration order. Every accepted modification notifies
//! subscribers of the registry's [`watch`](tokio::sync::watch) signal, so a
//! consumer re-reads the current state instead of polling.
//!
//! The library owns three concerns only: registration, reading the current set,
//! and invalidation notification. Payload aggregation, conflict resolution,
//! retries, reconciliation loops, backend I/O, tasks and cancellation all stay
//! in the consumer.
//!
//! # Contracts
//!
//! - **Identity** — entries get monotonically increasing ids that are never
//!   reused, so a stale registration can never address a newer entry.
//! - **Readers are not holders** — reads return `Arc<T>`, never a slot or an
//!   ownership capability. Holding an old snapshot does not keep a withdrawn
//!   entry in later reads.
//! - **Withdrawal removes** — `Registration::drop` and [`Registry::close`]
//!   remove the authoritative record synchronously. Entry count does not grow
//!   with historical registrations.
//! - **Commit, unlock, notify, drop** — consumers that observe a notification
//!   always read the committed state, and retired payloads are destroyed after
//!   the internal lock is released, so `T::drop` may call back into the same
//!   registry.
//! - **No payload code under the lock** — comparisons, formatting,
//!   destructors and `T` methods never run while the internal mutex is held.
//! - **Notification is invalidation, not a version** — it means "the current
//!   state may have changed, re-read it"; it carries no content and does not
//!   prove that a consumer finished anything.
//! - **No tasks** — the library never spawns work and needs no Tokio runtime
//!   (`watch` is used with the `sync` feature only). Deadlines, retries and
//!   cancellation belong to the host.
//! - **Close is not channel disconnection** — [`Registry::close`] clears the
//!   entries, after which `register` and `replace` return `None`, but it does
//!   not destroy the change signal: senders shared with other producers keep
//!   working. Only when every sender is dropped and no change is pending does
//!   `changed()` report `Err`.
//!
//! # Consumer loop
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::sync::atomic::{AtomicBool, Ordering};
//! # use registry::Registry;
//! # async fn reconcile(_: Vec<Arc<u32>>) {}
//! # async fn example(registry: Registry<u32>, stop: Arc<AtomicBool>) {
//! let mut rx = registry.subscribe();
//! loop {
//!     if stop.load(Ordering::Relaxed) { break; } // host-owned stop condition
//!     rx.mark_unchanged();                // 1. confirm the notification baseline
//!     let inputs = registry.snapshot();   // 2. read the committed state
//!     reconcile(inputs).await;            // 3. do the work
//!     tokio::select! {                    // 4. wait for a change or a retry
//!         r = rx.changed() => if r.is_err() { break },
//!         _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
//!     }
//! }
//! registry.close();                       // normal path; host Drop covers the rest
//! # }
//! ```
//!
//! The host's cancellation future belongs in the same `select!` as `changed()`.
//! Confirming the baseline *before* reading means an update that lands during
//! `reconcile` is still pending when the loop reaches step 4, so it is never
//! acknowledged without being processed. Business failures are retried by a
//! host timer; they do not depend on the next registration change.

mod registry;

pub use registry::{Registration, Registry};
