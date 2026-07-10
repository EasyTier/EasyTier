use std::{
    cell::RefCell,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    runtime::{Builder, Runtime},
    time::sleep,
};

const TIMER_PROGRESS: u32 = 1 << 0;
const SECOND_SOCKET_PROGRESS: u32 = 1 << 1;
const PENDING_READ_COMPLETED: u32 = 1 << 2;
const PENDING_READ_ISOLATED: u32 = 1 << 3;
const DONE: u32 = 1 << 4;
const ERROR: u32 = 1 << 31;
const HOST_PENDING: i32 = -1;

static NEXT_OPERATION: AtomicU32 = AtomicU32::new(1);

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
    fn start_read(handle: u32, operation: u32, capacity: u32) -> i32;
    fn take_read(operation: u32, destination: u32, capacity: u32) -> i32;
    fn start_write(handle: u32, operation: u32, source: u32, length: u32) -> i32;
    fn take_write(operation: u32) -> i32;
}

struct Probe {
    runtime: Runtime,
    status: Arc<AtomicU32>,
    wakers: Arc<WakerRegistry>,
}

#[derive(Default)]
struct WakerRegistry {
    wakers: Mutex<Vec<Waker>>,
}

impl WakerRegistry {
    fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock().expect("waker registry poisoned");
        if !wakers.iter().any(|registered| registered.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    fn wake_all(&self) {
        let wakers = {
            let mut registered = self.wakers.lock().expect("waker registry poisoned");
            std::mem::take(&mut *registered)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

struct HostTcpStream {
    handle: u32,
    read_operation: Option<u32>,
    write_operation: Option<u32>,
    wakers: Arc<WakerRegistry>,
}

impl HostTcpStream {
    fn new(handle: u32, wakers: Arc<WakerRegistry>) -> Self {
        Self {
            handle,
            read_operation: None,
            write_operation: None,
            wakers,
        }
    }
}

impl AsyncRead for HostTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let operation = match self.read_operation {
            Some(operation) => operation,
            None => {
                let operation = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
                let result = unsafe {
                    start_read(
                        self.handle,
                        operation,
                        buffer.remaining().try_into().unwrap(),
                    )
                };
                if result != 0 {
                    return Poll::Ready(Err(host_error("start_read", result)));
                }
                self.read_operation = Some(operation);
                operation
            }
        };

        let destination = buffer.initialize_unfilled();
        let result = unsafe {
            take_read(
                operation,
                destination.as_mut_ptr() as u32,
                destination.len().try_into().unwrap(),
            )
        };
        if result == HOST_PENDING {
            self.wakers.register(cx.waker());
            return Poll::Pending;
        }
        self.read_operation = None;
        if result < 0 {
            return Poll::Ready(Err(host_error("take_read", result)));
        }

        buffer.advance(result as usize);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for HostTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let operation = match self.write_operation {
            Some(operation) => operation,
            None => {
                let operation = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
                let result = unsafe {
                    start_write(
                        self.handle,
                        operation,
                        buffer.as_ptr() as u32,
                        buffer.len().try_into().unwrap(),
                    )
                };
                if result != 0 {
                    return Poll::Ready(Err(host_error("start_write", result)));
                }
                self.write_operation = Some(operation);
                operation
            }
        };

        let result = unsafe { take_write(operation) };
        if result == HOST_PENDING {
            self.wakers.register(cx.waker());
            return Poll::Pending;
        }
        self.write_operation = None;
        if result < 0 {
            return Poll::Ready(Err(host_error("take_write", result)));
        }

        Poll::Ready(Ok(result as usize))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn host_error(operation: &str, code: i32) -> io::Error {
    io::Error::other(format!("host {operation} failed with code {code}"))
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
        let wakers = Arc::new(WakerRegistry::default());

        let pending_status = status.clone();
        let pending_wakers = wakers.clone();
        runtime.spawn(async move {
            let mut stream = HostTcpStream::new(pending_handle, pending_wakers);
            let mut byte = [0_u8; 1];
            let _ = stream.read_exact(&mut byte).await;
            pending_status.fetch_or(PENDING_READ_COMPLETED, Ordering::SeqCst);
        });

        let active_status = status.clone();
        let active_wakers = wakers.clone();
        runtime.spawn(async move {
            let mut stream = HostTcpStream::new(active_handle, active_wakers);
            let mut byte = [0_u8; 1];
            let result = async {
                stream.read_exact(&mut byte).await?;
                stream.write_all(&byte).await
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
            wakers,
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

        probe.wakers.wake_all();
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
