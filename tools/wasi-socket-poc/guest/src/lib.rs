use std::{os::fd::FromRawFd, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    runtime::Builder,
    time::{sleep, timeout},
};

const TIMER_PROGRESS: u32 = 1 << 0;
const SECOND_SOCKET_PROGRESS: u32 = 1 << 1;
const PENDING_READ_ISOLATED: u32 = 1 << 2;
const IDLE_TIMER_PROGRESS: u32 = 1 << 3;
const ERROR: u32 = 1 << 31;

#[unsafe(no_mangle)]
pub extern "C" fn run_probe(listener_fd: i32, idle_millis: u32) -> u32 {
    match run(listener_fd, idle_millis) {
        Ok(status) => status,
        Err(stage) => ERROR | stage,
    }
}

fn run(listener_fd: i32, idle_millis: u32) -> Result<u32, u32> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| 1_u32)?;

    runtime.block_on(async move {
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
        std_listener.set_nonblocking(true).map_err(|_| 2_u32)?;
        let listener = TcpListener::from_std(std_listener).map_err(|_| 3_u32)?;

        let (mut pending_stream, _) = timed_accept(&listener, 4).await?;
        let (mut active_stream, _) = timed_accept(&listener, 5).await?;

        let pending_read = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            pending_stream.read_exact(&mut byte).await
        });
        tokio::task::yield_now().await;

        let timer = tokio::spawn(async {
            sleep(Duration::from_millis(50)).await;
        });

        let mut byte = [0_u8; 1];
        timeout(Duration::from_secs(2), active_stream.read_exact(&mut byte))
            .await
            .map_err(|_| 6_u32)?
            .map_err(|_| 7_u32)?;
        timeout(Duration::from_secs(2), active_stream.write_all(&byte))
            .await
            .map_err(|_| 8_u32)?
            .map_err(|_| 9_u32)?;

        timeout(Duration::from_secs(2), timer)
            .await
            .map_err(|_| 10_u32)?
            .map_err(|_| 11_u32)?;

        let mut status = TIMER_PROGRESS | SECOND_SOCKET_PROGRESS;
        sleep(Duration::from_millis(idle_millis.into())).await;
        status |= IDLE_TIMER_PROGRESS;

        if !pending_read.is_finished() {
            status |= PENDING_READ_ISOLATED;
        }
        pending_read.abort();

        Ok(status)
    })
}

async fn timed_accept(
    listener: &TcpListener,
    timeout_stage: u32,
) -> Result<(tokio::net::TcpStream, std::net::SocketAddr), u32> {
    timeout(Duration::from_secs(2), listener.accept())
        .await
        .map_err(|_| timeout_stage)?
        .map_err(|_| timeout_stage + 100)
}
