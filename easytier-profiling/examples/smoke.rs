//! Backend smoke workload; inspect actual reports/traces, not just successful exit.
use easytier_profiling as profiling;

#[cfg(feature = "hotpath-alloc")]
#[global_allocator]
static ALLOCATOR: profiling::CountingAllocator = profiling::CountingAllocator::new();

#[profiling::instrument("smoke::compute")]
fn compute(seed: u64) -> u64 {
    let bytes = std::hint::black_box(vec![seed as u8; 4096]);
    let mut value = seed;
    for index in 0..100_000 {
        value = std::hint::black_box(value)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(u64::from(bytes[index % bytes.len()]));
    }
    value
}

#[profiling::instrument("smoke::work")]
async fn work(rounds: u64) -> u64 {
    let (tx, mut rx) = profiling::channel!(tokio::sync::mpsc::channel(4));
    let lock = profiling::mutex!(tokio::sync::Mutex::new(0_u64));
    for value in 0..rounds {
        tx.send(compute(value)).await.unwrap();
        let mut sum = lock.lock().await;
        *sum = sum.wrapping_add(rx.recv().await.unwrap());
        drop(sum);
        tokio::task::yield_now().await;
    }
    let checksum = *lock.lock().await;
    profiling::event!("smoke", rounds = rounds, checksum = checksum);
    checksum
}

#[profiling::instrument("smoke::cancelled")]
async fn cancelled() {
    std::future::pending::<()>().await;
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(feature = "hotpath")]
    let _profiler = profiling::HotpathGuardBuilder::new("smoke").build();
    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::{fmt::format::FmtSpan, prelude::*};
        let subscriber = tracing_subscriber::registry();
        #[cfg(feature = "lttng")]
        let subscriber = subscriber.with(profiling::lttng::LttngLayer);
        subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::FULL)
                    .with_writer(std::io::stderr)
                    .with_ansi(false)
                    .without_time(),
            )
            .init();
    }
    let rounds = std::env::var("SMOKE_ROUNDS")
        .map(|s| s.parse::<u64>().expect("SMOKE_ROUNDS must be an integer"))
        .unwrap_or(32);
    let delay_ms = std::env::var("SMOKE_START_DELAY_MS")
        .map(|s| {
            s.parse::<u64>()
                .expect("SMOKE_START_DELAY_MS must be an integer")
        })
        .unwrap_or(0);
    if std::env::var_os("SMOKE_WARMUP").is_some() {
        std::hint::black_box(work(rounds).await);
        eprintln!("warmup complete");
    }
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    let checksum = work(rounds).await;
    tokio::select! {
        biased;
        _ = cancelled() => unreachable!(),
        _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {},
    }
    println!("rounds={rounds} checksum={checksum}");
}
