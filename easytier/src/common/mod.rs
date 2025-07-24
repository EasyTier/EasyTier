use std::{
    fmt::Debug,
    future,
    io::Write as _,
    sync::{Arc, Mutex},
};
use time::util::refresh_tz;
use tokio::{task::JoinSet, time::timeout};
use tracing::Instrument;

use crate::{set_global_var, use_global_var};

pub mod acl_processor;
pub mod compressor;
pub mod config;
pub mod constants;
pub mod defer;
pub mod dns;
pub mod error;
pub mod global_ctx;
pub mod ifcfg;
pub mod netns;
pub mod network;
pub mod scoped_task;
pub mod stun;
pub mod stun_codec_ext;
pub mod token_bucket;

pub fn get_logger_timer<F: time::formatting::Formattable>(
    format: F,
) -> tracing_subscriber::fmt::time::OffsetTime<F> {
    refresh_tz();
    let local_offset = time::UtcOffset::current_local_offset()
        .unwrap_or(time::UtcOffset::from_whole_seconds(0).unwrap());
    tracing_subscriber::fmt::time::OffsetTime::new(local_offset, format)
}

pub fn get_logger_timer_rfc3339(
) -> tracing_subscriber::fmt::time::OffsetTime<time::format_description::well_known::Rfc3339> {
    get_logger_timer(time::format_description::well_known::Rfc3339)
}

pub type PeerId = u32;

pub fn new_peer_id() -> PeerId {
    rand::random()
}

pub fn join_joinset_background<T: Debug + Send + Sync + 'static>(
    js: Arc<Mutex<JoinSet<T>>>,
    origin: String,
) {
    let js = Arc::downgrade(&js);
    let o = origin.clone();
    tokio::spawn(
        async move {
            while js.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let fut = future::poll_fn(|cx| {
                    let Some(js) = js.upgrade() else {
                        return std::task::Poll::Ready(());
                    };

                    let mut js = js.lock().unwrap();
                    while !js.is_empty() {
                        let ret = js.poll_join_next(cx);
                        match ret {
                            std::task::Poll::Ready(Some(_)) => {
                                continue;
                            }
                            std::task::Poll::Ready(None) => {
                                break;
                            }
                            std::task::Poll::Pending => {
                                return std::task::Poll::Pending;
                            }
                        }
                    }
                    std::task::Poll::Ready(())
                });

                let _ = timeout(std::time::Duration::from_secs(5), fut).await;
            }
            tracing::debug!(?o, "joinset task exit");
        }
        .instrument(tracing::info_span!(
            "join_joinset_background",
            origin = origin
        )),
    );
}

pub fn set_default_machine_id(mid: Option<String>) {
    set_global_var!(MACHINE_UID, mid);
}

pub fn get_machine_id() -> uuid::Uuid {
    if let Some(default_mid) = use_global_var!(MACHINE_UID) {
        let mut b = [0u8; 16];
        crate::tunnel::generate_digest_from_str("", &default_mid, &mut b);
        return uuid::Uuid::from_bytes(b);
    }

    // a path same as the binary
    let machine_id_file = std::env::current_exe()
        .map(|x| x.with_file_name("et_machine_id"))
        .unwrap_or_else(|_| std::path::PathBuf::from("et_machine_id"));

    // try load from local file
    if let Ok(mid) = std::fs::read_to_string(&machine_id_file) {
        if let Ok(mid) = uuid::Uuid::parse_str(mid.trim()) {
            return mid;
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    ))]
    let gen_mid = machine_uid::get()
        .map(|x| {
            if x.is_empty() {
                return uuid::Uuid::new_v4();
            }
            let mut b = [0u8; 16];
            crate::tunnel::generate_digest_from_str("", x.as_str(), &mut b);
            uuid::Uuid::from_bytes(b)
        })
        .ok();

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    let gen_mid = None;

    if gen_mid.is_some() {
        return gen_mid.unwrap();
    }

    let gen_mid = uuid::Uuid::new_v4();

    // try save to local file
    if let Ok(mut file) = std::fs::File::create(machine_id_file) {
        let _ = file.write_all(gen_mid.to_string().as_bytes());
    }

    gen_mid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_join_joinset_backgroud() {
        let js = Arc::new(Mutex::new(JoinSet::<()>::new()));
        join_joinset_background(js.clone(), "TEST".to_owned());
        js.try_lock().unwrap().spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(js.try_lock().unwrap().is_empty());

        for _ in 0..5 {
            js.try_lock().unwrap().spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            });
            tokio::task::yield_now().await;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        for _ in 0..5 {
            js.try_lock().unwrap().spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            });
            tokio::task::yield_now().await;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(js.try_lock().unwrap().is_empty());

        let weak_js = Arc::downgrade(&js);
        drop(js);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert_eq!(weak_js.weak_count(), 0);
        assert_eq!(weak_js.strong_count(), 0);
    }
}
