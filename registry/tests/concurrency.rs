//! Deterministic concurrency scenarios for the consumer contract.
//!
//! Ordering is established with barriers and channels, never with sleeps; every
//! wait is bounded by a timeout so a lost notification fails the test instead
//! of hanging it.

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use registry::Registry;

const TIMEOUT: Duration = Duration::from_secs(5);

fn seen(registry: &Registry<u32>) -> BTreeSet<u32> {
    registry.snapshot().iter().map(|value| **value).collect()
}

/// An update landing after the baseline is confirmed but before the read must
/// be visible in that same read, and must stay pending for the next wait.
#[tokio::test]
async fn update_between_baseline_and_snapshot_is_observed() {
    let registry = Registry::<u32>::default();
    let mut rx = registry.subscribe();

    rx.mark_unchanged(); // 1. confirm the baseline
    let lease = registry.register(1).unwrap(); // update lands before the read
    assert_eq!(seen(&registry), BTreeSet::from([1])); // 2. read

    // The notification is still pending, so the next wait completes at once;
    // an extra wakeup is allowed and does not lose the update.
    tokio::time::timeout(TIMEOUT, rx.changed())
        .await
        .expect("consumer was not woken")
        .expect("signal disconnected");
    assert_eq!(seen(&registry), BTreeSet::from([1]));
    drop(lease);
}

/// An update landing after the read but before the wait must wake the consumer
/// in bounded time, and the next read must see it.
#[tokio::test]
async fn update_between_snapshot_and_wait_wakes_the_consumer() {
    let registry = Registry::<u32>::default();
    let mut rx = registry.subscribe();

    rx.mark_unchanged();
    assert!(seen(&registry).is_empty());

    let lease = registry.register(1).unwrap(); // between read and wait
    tokio::time::timeout(TIMEOUT, rx.changed())
        .await
        .expect("consumer was not woken")
        .expect("signal disconnected");

    // Next loop iteration: confirm, read, observe.
    rx.mark_unchanged();
    assert_eq!(seen(&registry), BTreeSet::from([1]));
    drop(lease);
}

/// A change committed while the consumer is processing the previous snapshot
/// must not be acknowledged; the following iteration has to see it.
#[test]
fn update_during_reconciliation_is_not_acknowledged() {
    let registry = Registry::<u32>::default();
    let mut rx = registry.subscribe();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();

    let producer = {
        let registry = registry.clone();
        std::thread::spawn(move || {
            release_rx
                .recv()
                .expect("consumer released the producer before processing");
            let lease = registry.register(1).unwrap();
            done_tx.send(()).unwrap();
            lease
        })
    };

    // Consumer iteration: baseline, read, then process while the producer updates.
    rx.mark_unchanged();
    assert!(seen(&registry).is_empty());
    release_tx.send(()).unwrap();
    done_rx.recv().unwrap();

    // The in-flight iteration did not acknowledge the change it never read.
    assert!(rx.has_changed().unwrap());

    let lease = producer.join().unwrap();
    rx.mark_unchanged();
    assert_eq!(seen(&registry), BTreeSet::from([1]));
    drop(lease);
}

/// Writes racing with close either commit before the close or fail; once the
/// dust settles the registry is empty and stays closed.
#[test]
fn close_races_with_writes_leave_an_empty_registry() {
    let registry = Registry::<u32>::default();
    let writers = 4;
    let barrier = Arc::new(Barrier::new(writers + 1));

    let mut handles = Vec::new();
    for _ in 0..writers {
        let registry = registry.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for i in 0..64u32 {
                match registry.register(i) {
                    // A write that committed before close may still return Ok
                    // and be cleared by it; a later write must fail.
                    Some(lease) => {
                        let _ = lease.replace(i + 1);
                    }
                    None => break,
                }
            }
        }));
    }
    barrier.wait();
    assert!(registry.close() || registry.is_empty());

    for handle in handles {
        handle.join().unwrap();
    }

    assert!(registry.is_empty());
    assert!(registry.snapshot().is_empty());
    assert!(
        registry.register(1).is_none(),
        "writes after close must fail"
    );
    assert!(!registry.close(), "close is irreversible");
}

/// A panicking producer still withdraws its registration and notifies.
#[test]
fn producer_panic_withdraws_the_registration() {
    let registry = Registry::<u32>::default();
    let mut rx = registry.subscribe();
    rx.mark_unchanged();

    let producer = {
        let registry = registry.clone();
        std::thread::spawn(move || {
            let _lease = registry.register(1).unwrap();
            panic!("producer failed");
        })
    };
    assert!(producer.join().is_err());

    assert!(registry.is_empty(), "the claim was withdrawn during unwind");
    assert!(rx.has_changed().unwrap(), "consumers were woken");
}

/// After the producers stop, a consumer must read the complete final set, and
/// then wait for a change instead of busy-looping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumer_converges_on_the_final_set_and_then_blocks() {
    let registry = Registry::<u32>::default();
    let mut rx = registry.subscribe();

    let producers: Vec<_> = (0..4u32)
        .map(|producer| {
            let registry = registry.clone();
            std::thread::spawn(move || {
                let mut sentinel = None;
                for i in 0..32u32 {
                    let lease = registry.register(producer * 100 + i).unwrap();
                    lease.replace(producer * 100 + i).unwrap();
                    sentinel = Some(lease); // withdraws the previous iteration
                }
                sentinel.unwrap()
            })
        })
        .collect();

    let sentinels: Vec<_> = producers
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let expected: BTreeSet<u32> = (0..4u32).map(|producer| producer * 100 + 31).collect();

    // Producers are joined, so only the sentinels are live.
    rx.mark_unchanged();
    assert_eq!(seen(&registry), expected);

    // With the final state consumed there is nothing left to acknowledge: the
    // consumer must block rather than spin.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.changed())
            .await
            .is_err(),
        "an idle consumer must wait for a change"
    );

    drop(sentinels);
    assert!(registry.close());
}

/// Supplemental pressure test: concurrent register / replace / drop on an open
/// registry must terminate with every claim withdrawn.
#[test]
fn concurrent_register_replace_drop_stays_consistent() {
    let registry = Registry::<u32>::default();
    let threads: u32 = 4;
    let barrier = Arc::new(Barrier::new(threads as usize + 1));

    let mut handles = Vec::new();
    for thread in 0..threads {
        let registry = registry.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for i in 0..500u32 {
                let lease = registry.register(thread * 1000 + i).unwrap();
                if i % 2 == 0 {
                    lease.replace(thread * 1000 + i + 1).unwrap();
                }
                drop(lease);
            }
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }

    assert!(registry.is_empty());
    assert!(registry.close());
    assert!(!registry.close());
}
