//! Backend smoke workload; also useful for capturing a small LTTng session.
use easytier_profiling as profiling;

#[cfg(feature = "hotpath-alloc")]
#[global_allocator]
static ALLOCATOR: profiling::CountingAllocator = profiling::CountingAllocator::new();

#[profiling::instrument("smoke::work")]
async fn work() {
    let (tx, mut rx) = profiling::channel!(tokio::sync::mpsc::channel(4));
    let lock = profiling::mutex!(tokio::sync::Mutex::new(Vec::new()));
    for value in 0..4 {
        tx.send(value).await.unwrap();
        lock.lock().await.push(rx.recv().await.unwrap());
        tokio::task::yield_now().await;
    }
    profiling::event!("smoke", values = lock.lock().await.len());
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(feature = "hotpath")]
    let _profiler = profiling::HotpathGuardBuilder::new("smoke").build();
    #[cfg(feature = "lttng")]
    {
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(profiling::lttng::LttngLayer)
            .init();
    }
    work().await;
}
