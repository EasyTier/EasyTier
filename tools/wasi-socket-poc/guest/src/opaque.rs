use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use easytier_core::socket::host::{HostSocketHandle, HostSocketRuntime, wasi::WasiHostTcpIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::{Builder, Runtime},
    time::sleep,
};

const TIMER_PROGRESS: u32 = 1 << 0;
const SECOND_SOCKET_PROGRESS: u32 = 1 << 1;
const PENDING_READ_COMPLETED: u32 = 1 << 2;
const PENDING_READ_ISOLATED: u32 = 1 << 3;
const DONE: u32 = 1 << 4;
const ERROR: u32 = 1 << 31;

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}

struct Probe {
    runtime: Runtime,
    status: Arc<AtomicU32>,
    sockets: HostSocketRuntime,
}

fn tcp_stream(
    sockets: &HostSocketRuntime,
    handle: u32,
) -> easytier_core::socket::host::HostTcpStream {
    sockets.tcp_stream(
        HostSocketHandle(u64::from(handle)),
        "192.0.2.1:10000".parse().unwrap(),
        "192.0.2.2:11013".parse().unwrap(),
        None,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn init_opaque_probe(pending_handle: u32, active_handle: u32) -> i32 {
    PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }

        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new(Arc::new(WasiHostTcpIo::default()));

        let pending_status = status.clone();
        let pending_stream = tcp_stream(&sockets, pending_handle);
        runtime.spawn(async move {
            let mut stream = pending_stream;
            let mut byte = [0_u8; 1];
            let _ = stream.read_exact(&mut byte).await;
            pending_status.fetch_or(PENDING_READ_COMPLETED, Ordering::SeqCst);
        });

        let active_status = status.clone();
        let active_stream = tcp_stream(&sockets, active_handle);
        runtime.spawn(async move {
            let mut stream = active_stream;
            let mut byte = [0_u8; 1];
            let result = async {
                stream.read_exact(&mut byte).await?;
                stream.write_all(&byte).await?;
                stream.flush().await
            }
            .await;
            match result {
                Ok(()) => {
                    active_status.fetch_or(SECOND_SOCKET_PROGRESS, Ordering::SeqCst);
                }
                Err(_) => {
                    active_status.fetch_or(ERROR | 1, Ordering::SeqCst);
                }
            }
        });

        let timer_status = status.clone();
        runtime.spawn(async move {
            sleep(Duration::from_millis(50)).await;
            timer_status.fetch_or(TIMER_PROGRESS, Ordering::SeqCst);
        });

        *slot = Some(Probe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_opaque_probe() -> u32 {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 2;
        };

        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });

        let status = probe.status.load(Ordering::SeqCst);
        if status & ERROR == 0
            && status & (TIMER_PROGRESS | SECOND_SOCKET_PROGRESS)
                == TIMER_PROGRESS | SECOND_SOCKET_PROGRESS
        {
            if status & PENDING_READ_COMPLETED == 0 {
                probe
                    .status
                    .fetch_or(PENDING_READ_ISOLATED | DONE, Ordering::SeqCst);
            } else {
                probe.status.fetch_or(ERROR | 3, Ordering::SeqCst);
            }
        }

        probe.status.load(Ordering::SeqCst)
    })
}
