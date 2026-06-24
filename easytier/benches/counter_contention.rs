//! Compare counter implementations under tokio-task contention.
//!
//! Groups:
//!   - `contention_scaling` : N tokio tasks share one counter, total work fixed.
//!     Variants: `single_atomic`, `cas_saturating`, `sharded_atomic`,
//!     `thread_local_cell`, `unsafe_cell` (unsound, for reference only).
//!   - `single_thread_write`: per-`add` cost with no contention (floor cost).
//!   - `read_cost`          : per-`get()` cost.
//!   - `counter_handle`     : the REAL production hot path. Measures the actual
//!     `stats_manager::CounterHandle::add` (single-atomic `fetch_add` + lock-free
//!     fastant `touch`) against reconstructed baselines:
//!       * `prod` - real `CounterHandle` (this code's version)
//!       * `baseline_cas_mutex` - pre-optimization: single `AtomicU64` with `fetch_update` (CAS) + `Mutex<Instant>` touch
//!       * `baseline_fetchadd_mutex` - `fetch_add` + `Mutex<Instant>` touch (isolates the lock-free fastant touch)
//!
//! Run: `cargo bench -p easytier --bench counter_contention`

use std::cell::{Cell, UnsafeCell};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread::available_parallelism;
use std::time::Instant;

use criterion::{
    BenchmarkId, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use easytier::common::stats_manager::{CounterHandle, MetricName, StatsManager};
use parking_lot::Mutex;

const COUNTER_SHARDS: usize = 16;
const TOTAL_WORK: u64 = 8_000_000;
// The handle path calls `Instant::now()` per `add`, so it is far heavier per op
// than the counter-only groups; use a smaller total to keep the bench fast.
const HANDLE_TOTAL_WORK: u64 = 2_000_000;
const TASK_COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32];

trait Counter: Send + Sync {
    fn add(&self, delta: u64);
    fn get(&self) -> u64;
}

// ---------------------------------------------------------------------------
// 1. SingleAtomic: one atomic, fetch_add. Baseline; contends across cores.
// ---------------------------------------------------------------------------

struct SingleAtomic(AtomicU64);

impl Default for SingleAtomic {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl Counter for SingleAtomic {
    #[inline(always)]
    fn add(&self, delta: u64) {
        self.0.fetch_add(delta, Ordering::Relaxed);
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// 2. CasSaturating: fetch_update with saturating_add (the original PR `add`).
//    A CAS loop that can retry under contention.
// ---------------------------------------------------------------------------

struct CasSaturating(AtomicU64);

impl Default for CasSaturating {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl Counter for CasSaturating {
    #[inline(always)]
    fn add(&self, delta: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                Some(c.saturating_add(delta))
            });
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// 3. ShardedAtomic: 16 cache-aligned shards + per-thread shard index.
//    Mirrors production `stats_manager::UnsafeCounter`.
// ---------------------------------------------------------------------------

thread_local! {
    static SHARD_IDX: Cell<usize> = Cell::new({
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed) % COUNTER_SHARDS
    });
}

#[repr(align(64))]
struct Shard {
    value: AtomicU64,
}

struct ShardedAtomic {
    shards: Box<[Shard]>,
}

impl Default for ShardedAtomic {
    fn default() -> Self {
        let mut shards = Vec::with_capacity(COUNTER_SHARDS);
        for _ in 0..COUNTER_SHARDS {
            shards.push(Shard {
                value: AtomicU64::new(0),
            });
        }
        Self {
            shards: shards.into_boxed_slice(),
        }
    }
}

impl Counter for ShardedAtomic {
    #[inline(always)]
    fn add(&self, delta: u64) {
        let i = SHARD_IDX.with(|c| c.get());
        self.shards[i].value.fetch_add(delta, Ordering::Relaxed);
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.value.load(Ordering::Relaxed))
            .sum()
    }
}

// ---------------------------------------------------------------------------
// 4. ThreadLocalCell: per-thread Cell<u64> accumulation. Zero-atomic writes.
//    `get()` flushes the caller thread's local into a shared aggregate, so the
//    measured read cost reflects a flush-based read. Exact totals would require
//    flushing every thread (not modeled here).
// ---------------------------------------------------------------------------

thread_local! {
    static TLS_DELTA: Cell<u64> = const { Cell::new(0) };
}

struct ThreadLocalCell {
    shared: AtomicU64,
}

impl Default for ThreadLocalCell {
    fn default() -> Self {
        Self {
            shared: AtomicU64::new(0),
        }
    }
}

impl Counter for ThreadLocalCell {
    #[inline(always)]
    fn add(&self, delta: u64) {
        TLS_DELTA.with(|c| c.set(c.get() + delta));
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        let local = TLS_DELTA.with(|c| c.replace(0));
        self.shared.fetch_add(local, Ordering::Relaxed) + local
    }
}

// ---------------------------------------------------------------------------
// 5. UnsafeCellCounter: a plain u64 mutated through UnsafeCell with manual
//    `unsafe impl Send/Sync`. This is UNSOUND under concurrent access (data
//    race / UB) and is exactly what the original code did "for speed". It is
//    included only to measure the speed ceiling the author was chasing, and to
//    show that its `get()` returns wrong totals under contention (lost updates).
// ---------------------------------------------------------------------------

struct UnsafeCellCounter(UnsafeCell<u64>);

// SAFETY: deliberately unsound; see above.
unsafe impl Send for UnsafeCellCounter {}
unsafe impl Sync for UnsafeCellCounter {}

impl Default for UnsafeCellCounter {
    fn default() -> Self {
        Self(UnsafeCell::new(0))
    }
}

impl Counter for UnsafeCellCounter {
    #[inline(always)]
    fn add(&self, delta: u64) {
        // SAFETY: UNSOUND under concurrent access (data race).
        unsafe {
            *self.0.get() += delta;
        }
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        // SAFETY: UNSOUND under concurrent writers (data race).
        unsafe { *self.0.get() }
    }
}

// ---------------------------------------------------------------------------
// Production counter handle + reconstructed baselines for the `counter_handle`
// group. These measure the full hot path (`add` = counter update + `touch`
// timestamp), which is what actually runs per packet in `peer_manager`.
// ---------------------------------------------------------------------------

// The real production `CounterHandle`. `CounterHandle::add` does a sharded
// `fetch_add` then a lock-free atomic-millis `touch`.
impl Counter for CounterHandle {
    #[inline(always)]
    fn add(&self, delta: u64) {
        // Fully-qualified to avoid infinite recursion through the trait method.
        CounterHandle::add(self, delta);
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        CounterHandle::get(self)
    }
}

// A faithful replica of the pre-optimization design: a SINGLE `AtomicU64`
// (unsharded) plus a `Mutex<Instant>` timestamp. `use_cas` selects whether the
// counter write is a `fetch_update` saturating CAS (the original PR `add`) or a
// plain `fetch_add`.
struct BaselineHandle {
    counter: AtomicU64,
    last_updated: Mutex<Instant>,
    use_cas: bool,
}

impl Default for BaselineHandle {
    fn default() -> Self {
        Self {
            counter: AtomicU64::new(0),
            last_updated: Mutex::new(Instant::now()),
            use_cas: false,
        }
    }
}

impl Counter for BaselineHandle {
    #[inline(always)]
    fn add(&self, delta: u64) {
        if self.use_cas {
            let _ = self
                .counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                    Some(c.saturating_add(delta))
                });
        } else {
            self.counter.fetch_add(delta, Ordering::Relaxed);
        }
        *self.last_updated.lock() = Instant::now();
    }
    #[inline(always)]
    fn get(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Harness: a shared multi-thread tokio runtime sized to the host's parallelism.
// ---------------------------------------------------------------------------

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    let workers = available_parallelism().map(|n| n.get()).unwrap_or(1);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
});

fn bench_contention<C: Counter + Default + 'static>(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    name: &str,
    n_tasks: usize,
    per_task: u64,
) {
    let counter: Arc<C> = Arc::new(C::default());
    group.bench_with_input(BenchmarkId::new(name, n_tasks), &n_tasks, |b, &n| {
        b.iter(|| {
            let counter = counter.clone();
            RUNTIME.block_on(async move {
                let mut handles = Vec::with_capacity(n);
                for _ in 0..n {
                    let c = counter.clone();
                    handles.push(tokio::spawn(async move {
                        for _ in 0..per_task {
                            c.add(black_box(1));
                        }
                    }));
                }
                for handle in handles {
                    let _ = handle.await;
                }
                black_box(counter.get());
            });
        });
    });
}

fn contention_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention_scaling");
    group.throughput(Throughput::Elements(TOTAL_WORK));
    for &n in TASK_COUNTS {
        let per = TOTAL_WORK / n as u64;
        bench_contention::<SingleAtomic>(&mut group, "single_atomic", n, per);
        bench_contention::<CasSaturating>(&mut group, "cas_saturating", n, per);
        bench_contention::<ShardedAtomic>(&mut group, "sharded_atomic", n, per);
        bench_contention::<ThreadLocalCell>(&mut group, "thread_local_cell", n, per);
        bench_contention::<UnsafeCellCounter>(&mut group, "unsafe_cell", n, per);
    }
    group.finish();
}

fn single_thread_write<C: Counter + Default>(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    name: &str,
) {
    let counter = C::default();
    group.bench_function(name, |b| {
        b.iter(|| {
            counter.add(black_box(1));
        });
    });
}

fn single_thread_write_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_thread_write");
    group.throughput(Throughput::Elements(1));
    single_thread_write::<SingleAtomic>(&mut group, "single_atomic");
    single_thread_write::<CasSaturating>(&mut group, "cas_saturating");
    single_thread_write::<ShardedAtomic>(&mut group, "sharded_atomic");
    single_thread_write::<ThreadLocalCell>(&mut group, "thread_local_cell");
    single_thread_write::<UnsafeCellCounter>(&mut group, "unsafe_cell");
    group.finish();
}

fn read_cost<C: Counter + Default>(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    name: &str,
) {
    let counter = C::default();
    counter.add(1000);
    group.bench_function(name, |b| {
        b.iter(|| black_box(counter.get()));
    });
}

fn read_cost_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_cost");
    read_cost::<SingleAtomic>(&mut group, "single_atomic");
    read_cost::<CasSaturating>(&mut group, "cas_saturating");
    read_cost::<ShardedAtomic>(&mut group, "sharded_atomic");
    read_cost::<ThreadLocalCell>(&mut group, "thread_local_cell");
    read_cost::<UnsafeCellCounter>(&mut group, "unsafe_cell");
    group.finish();
}

fn bench_handle(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    name: &str,
    n_tasks: usize,
    per_task: u64,
    counter: Arc<dyn Counter>,
) {
    group.bench_with_input(BenchmarkId::new(name, n_tasks), &n_tasks, |b, &n| {
        b.iter(|| {
            let counter = counter.clone();
            RUNTIME.block_on(async move {
                let mut handles = Vec::with_capacity(n);
                for _ in 0..n {
                    let c = counter.clone();
                    handles.push(tokio::spawn(async move {
                        for _ in 0..per_task {
                            c.add(black_box(1));
                        }
                    }));
                }
                for handle in handles {
                    let _ = handle.await;
                }
                black_box(counter.get());
            });
        });
    });
}

fn counter_handle(c: &mut Criterion) {
    let mut group = c.benchmark_group("counter_handle");
    group.throughput(Throughput::Elements(HANDLE_TOTAL_WORK));

    // StatsManager::new() spawns a background cleanup task, which needs a tokio
    // runtime context; bind it to our shared RUNTIME for the lifetime of the
    // group.
    let _rt_guard = RUNTIME.enter();
    let stats = StatsManager::new();

    let prod: Arc<dyn Counter> = Arc::new(stats.get_simple_counter(MetricName::TrafficBytesTx));
    let cas: Arc<dyn Counter> = Arc::new(BaselineHandle {
        use_cas: true,
        ..Default::default()
    });
    let fam: Arc<dyn Counter> = Arc::new(BaselineHandle {
        use_cas: false,
        ..Default::default()
    });

    for &n in TASK_COUNTS {
        let per = HANDLE_TOTAL_WORK / n as u64;
        bench_handle(&mut group, "prod", n, per, prod.clone());
        bench_handle(&mut group, "baseline_cas_mutex", n, per, cas.clone());
        bench_handle(&mut group, "baseline_fetchadd_mutex", n, per, fam.clone());
    }
    group.finish();
}

// Keep the default measurement config; pass CLI flags to speed up a run, e.g.
// `-- --measurement-time 2 --sample-size 30 --warm-up-time 500`.
criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = contention_scaling, single_thread_write_group, read_cost_group, counter_handle
}
criterion_main!(benches);
