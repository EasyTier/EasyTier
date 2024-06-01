use std::{
    fmt::Debug,
    future,
    sync::{Arc, Mutex},
};
use tokio::task::JoinSet;
use tracing::Instrument;

pub mod config;
pub mod constants;
pub mod defer;
pub mod error;
pub mod global_ctx;
pub mod ifcfg;
pub mod netns;
pub mod network;
pub mod stun;
pub mod stun_codec_ext;

pub fn get_logger_timer<F: time::formatting::Formattable>(
    format: F,
) -> tracing_subscriber::fmt::time::OffsetTime<F> {
    unsafe {
        time::util::local_offset::set_soundness(time::util::local_offset::Soundness::Unsound)
    };
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
    tokio::spawn(
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if js.weak_count() == 0 {
                    tracing::info!("joinset task exit");
                    break;
                }

                future::poll_fn(|cx| {
                    tracing::debug!("try join joinset tasks");
                    let Some(js) = js.upgrade() else {
                        return std::task::Poll::Ready(());
                    };

                    let mut js = js.lock().unwrap();
                    while !js.is_empty() {
                        let ret = js.poll_join_next(cx);
                        if ret.is_pending() {
                            return std::task::Poll::Pending;
                        }
                    }

                    std::task::Poll::Ready(())
                })
                .await;
            }
        }
        .instrument(tracing::info_span!(
            "join_joinset_background",
            origin = origin
        )),
    );
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
    }
}
