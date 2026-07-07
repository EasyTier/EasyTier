use std::{
    fmt::Debug,
    future::Future,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::Context as _;
use async_trait::async_trait;
use tokio::task::JoinSet;
use url::Url;

pub trait ListenerConnectionCounter: Debug + Send + Sync {
    fn get(&self) -> Option<u32>;
}

#[derive(Debug)]
struct EmptyConnectionCounter;

impl ListenerConnectionCounter for EmptyConnectionCounter {
    fn get(&self) -> Option<u32> {
        None
    }
}

#[async_trait]
pub trait SocketListener: Debug + Send {
    type Accepted: Send + 'static;

    async fn listen(&mut self) -> anyhow::Result<()>;

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted>;

    fn local_url(&self) -> Url;

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        Arc::new(EmptyConnectionCounter)
    }
}

#[async_trait]
pub trait AcceptedSocketHandler<Accepted>: Debug + Send + Sync {
    async fn handle_accepted_socket(&self, accepted: Accepted) -> anyhow::Result<()>;
}

#[async_trait]
impl<Accepted, F, Fut> AcceptedSocketHandler<Accepted> for F
where
    Accepted: Send + 'static,
    F: Fn(Accepted) -> Fut + Debug + Send + Sync,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    async fn handle_accepted_socket(&self, accepted: Accepted) -> anyhow::Result<()> {
        self(accepted).await
    }
}

#[derive(Clone, Debug)]
pub enum ListenerEvent {
    ListenerAdded {
        url: Url,
        connection_counter: Arc<dyn ListenerConnectionCounter>,
    },
    ListenerAddFailed {
        url: Url,
        error: String,
        retry_count: usize,
        will_retry: bool,
    },
    ListenerAcceptFailed {
        url: Url,
        error: String,
    },
    SocketAccepted {
        url: Url,
    },
    AcceptedSocketHandleFailed {
        url: Url,
        error: String,
    },
    AcceptedSocketHandlerDropped {
        url: Url,
    },
}

pub trait ListenerEventSink: Debug + Send + Sync {
    fn emit(&self, event: ListenerEvent);
}

#[derive(Debug)]
struct NoopListenerEventSink;

impl ListenerEventSink for NoopListenerEventSink {
    fn emit(&self, _event: ListenerEvent) {}
}

pub trait ListenerCreator<Accepted>:
    Fn() -> Box<dyn SocketListener<Accepted = Accepted>> + Send + Sync
{
}

impl<Accepted, T> ListenerCreator<Accepted> for T where
    T: Fn() -> Box<dyn SocketListener<Accepted = Accepted>> + Send + Sync
{
}

type ListenerCreatorArc<Accepted> = Arc<Box<dyn ListenerCreator<Accepted>>>;

#[derive(Clone)]
pub struct ListenerFactory<Accepted> {
    creator: ListenerCreatorArc<Accepted>,
    must_succeed: bool,
}

impl<Accepted> ListenerFactory<Accepted> {
    pub fn new<C>(creator: C, must_succeed: bool) -> Self
    where
        C: ListenerCreator<Accepted> + 'static,
    {
        Self {
            creator: Arc::new(Box::new(creator)),
            must_succeed,
        }
    }

    pub fn must_succeed(&self) -> bool {
        self.must_succeed
    }
}

#[derive(Debug, Clone)]
pub struct ListenerManagerOptions {
    pub max_listen_retries: usize,
    pub listen_retry_delay: Duration,
    pub accept_retry_delay: Duration,
}

impl Default for ListenerManagerOptions {
    fn default() -> Self {
        Self {
            max_listen_retries: 5,
            listen_retry_delay: Duration::from_secs(1),
            accept_retry_delay: Duration::from_secs(1),
        }
    }
}

pub struct ListenerManager<Accepted, H> {
    factories: Vec<ListenerFactory<Accepted>>,
    handler: Weak<H>,
    events: Arc<dyn ListenerEventSink>,
    options: ListenerManagerOptions,
    tasks: JoinSet<()>,
}

impl<Accepted, H> ListenerManager<Accepted, H>
where
    Accepted: Send + 'static,
    H: AcceptedSocketHandler<Accepted> + 'static,
{
    pub fn new(handler: Arc<H>) -> Self {
        Self::new_with_options(
            handler,
            Arc::new(NoopListenerEventSink),
            ListenerManagerOptions::default(),
        )
    }

    pub fn new_with_events(handler: Arc<H>, events: Arc<dyn ListenerEventSink>) -> Self {
        Self::new_with_options(handler, events, ListenerManagerOptions::default())
    }

    pub fn new_with_options(
        handler: Arc<H>,
        events: Arc<dyn ListenerEventSink>,
        options: ListenerManagerOptions,
    ) -> Self {
        Self {
            factories: Vec::new(),
            handler: Arc::downgrade(&handler),
            events,
            options,
            tasks: JoinSet::new(),
        }
    }

    pub fn add_listener<C>(&mut self, creator: C, must_succeed: bool)
    where
        C: ListenerCreator<Accepted> + 'static,
    {
        self.factories
            .push(ListenerFactory::new(creator, must_succeed));
    }

    pub fn listener_count(&self) -> usize {
        self.factories.len()
    }

    pub fn factories(&self) -> &[ListenerFactory<Accepted>] {
        &self.factories
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        for factory in &self.factories {
            let initial_listener = if factory.must_succeed {
                Some(
                    listen_once(factory.creator.clone(), self.events.clone())
                        .await
                        .with_context(|| "required listener failed to start")?,
                )
            } else {
                None
            };

            self.tasks.spawn(run_listener(
                factory.creator.clone(),
                self.handler.clone(),
                self.events.clone(),
                self.options.clone(),
                initial_listener,
            ));
        }

        Ok(())
    }
}

async fn listen_once<Accepted>(
    creator: ListenerCreatorArc<Accepted>,
    events: Arc<dyn ListenerEventSink>,
) -> anyhow::Result<Box<dyn SocketListener<Accepted = Accepted>>>
where
    Accepted: Send + 'static,
{
    let mut listener = creator();
    match listener.listen().await {
        Ok(()) => {
            emit_listener_added(&events, &*listener);
            Ok(listener)
        }
        Err(error) => {
            events.emit(ListenerEvent::ListenerAddFailed {
                url: listener.local_url(),
                error: format!("{error:?}"),
                retry_count: 1,
                will_retry: false,
            });
            Err(error)
        }
    }
}

async fn run_listener<Accepted, H>(
    creator: ListenerCreatorArc<Accepted>,
    handler: Weak<H>,
    events: Arc<dyn ListenerEventSink>,
    options: ListenerManagerOptions,
    mut initial_listener: Option<Box<dyn SocketListener<Accepted = Accepted>>>,
) where
    Accepted: Send + 'static,
    H: AcceptedSocketHandler<Accepted> + 'static,
{
    let mut listen_error_count = 0;
    loop {
        let mut listener = match initial_listener.take() {
            Some(listener) => listener,
            None => {
                let mut listener = creator();
                match listener.listen().await {
                    Ok(()) => {
                        listen_error_count = 0;
                        emit_listener_added(&events, &*listener);
                        listener
                    }
                    Err(error) => {
                        listen_error_count += 1;
                        let will_retry = listen_error_count <= options.max_listen_retries;
                        events.emit(ListenerEvent::ListenerAddFailed {
                            url: listener.local_url(),
                            error: format!("{error:?}"),
                            retry_count: listen_error_count,
                            will_retry,
                        });
                        tracing::error!(?error, ?listener, "listener listen error");
                        if !will_retry {
                            return;
                        }
                        tokio::time::sleep(options.listen_retry_delay).await;
                        continue;
                    }
                }
            }
        };

        loop {
            let listener_url = listener.local_url();
            let accepted = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    events.emit(ListenerEvent::ListenerAcceptFailed {
                        url: listener_url.clone(),
                        error: format!("{error:?}"),
                    });
                    tracing::error!(?error, ?listener, "listener accept error");
                    tokio::time::sleep(options.accept_retry_delay).await;
                    break;
                }
            };

            events.emit(ListenerEvent::SocketAccepted {
                url: listener_url.clone(),
            });
            let handler = handler.clone();
            let events = events.clone();
            tokio::spawn(async move {
                let Some(handler) = handler.upgrade() else {
                    events.emit(ListenerEvent::AcceptedSocketHandlerDropped { url: listener_url });
                    return;
                };
                if let Err(error) = handler.handle_accepted_socket(accepted).await {
                    events.emit(ListenerEvent::AcceptedSocketHandleFailed {
                        url: listener_url,
                        error: format!("{error:?}"),
                    });
                }
            });
        }
    }
}

fn emit_listener_added<Accepted>(
    events: &Arc<dyn ListenerEventSink>,
    listener: &dyn SocketListener<Accepted = Accepted>,
) where
    Accepted: Send + 'static,
{
    events.emit(ListenerEvent::ListenerAdded {
        url: listener.local_url(),
        connection_counter: listener.connection_counter(),
    });
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fmt,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    #[derive(Debug)]
    struct MockListener {
        url: Url,
        listen_results: Arc<Mutex<VecDeque<anyhow::Result<()>>>>,
        accepts: Arc<Mutex<VecDeque<anyhow::Result<usize>>>>,
        listen_count: Arc<AtomicUsize>,
        drop_count: Arc<AtomicUsize>,
    }

    impl Drop for MockListener {
        fn drop(&mut self) {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl SocketListener for MockListener {
        type Accepted = usize;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.listen_count.fetch_add(1, Ordering::Relaxed);
            self.listen_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(()))
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            let next_accept = self.accepts.lock().unwrap().pop_front();
            match next_accept {
                Some(ret) => ret,
                None => std::future::pending().await,
            }
        }

        fn local_url(&self) -> Url {
            self.url.clone()
        }
    }

    #[derive(Debug)]
    struct MockHandler {
        accepted: Mutex<Vec<usize>>,
    }

    #[async_trait]
    impl AcceptedSocketHandler<usize> for MockHandler {
        async fn handle_accepted_socket(&self, accepted: usize) -> anyhow::Result<()> {
            self.accepted.lock().unwrap().push(accepted);
            Ok(())
        }
    }

    #[derive(Default)]
    struct Events {
        events: Mutex<Vec<ListenerEvent>>,
    }

    impl Debug for Events {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Events").finish()
        }
    }

    impl ListenerEventSink for Events {
        fn emit(&self, event: ListenerEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[tokio::test]
    async fn required_listener_reuses_successful_initial_listen() {
        let handler = Arc::new(MockHandler {
            accepted: Mutex::new(Vec::new()),
        });
        let events = Arc::new(Events::default());
        let listen_count = Arc::new(AtomicUsize::new(0));
        let drop_count = Arc::new(AtomicUsize::new(0));
        let accepts = Arc::new(Mutex::new(VecDeque::from([Ok::<_, anyhow::Error>(7)])));
        let mut manager = ListenerManager::new_with_options(
            handler.clone(),
            events.clone(),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 0,
            },
        );

        let listener_accepts = accepts.clone();
        let listener_listen_count = listen_count.clone();
        let listener_drop_count = drop_count.clone();
        manager.add_listener(
            move || {
                Box::new(MockListener {
                    url: "mock://required".parse().unwrap(),
                    listen_results: Arc::new(Mutex::new(VecDeque::from([Ok(())]))),
                    accepts: listener_accepts.clone(),
                    listen_count: listener_listen_count.clone(),
                    drop_count: listener_drop_count.clone(),
                })
            },
            true,
        );

        manager.run().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(listen_count.load(Ordering::Relaxed), 1);
        assert_eq!(handler.accepted.lock().unwrap().as_slice(), &[7]);
        assert!(
            events
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, ListenerEvent::ListenerAdded { .. }))
        );
    }

    #[tokio::test]
    async fn optional_listener_retries_until_listen_succeeds() {
        let handler = Arc::new(MockHandler {
            accepted: Mutex::new(Vec::new()),
        });
        let events = Arc::new(Events::default());
        let listen_count = Arc::new(AtomicUsize::new(0));
        let listen_results = Arc::new(Mutex::new(VecDeque::from([
            Err(anyhow::anyhow!("not ready")),
            Ok(()),
        ])));
        let accepts = Arc::new(Mutex::new(VecDeque::from([Ok::<_, anyhow::Error>(3)])));
        let mut manager = ListenerManager::new_with_options(
            handler.clone(),
            events.clone(),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 2,
            },
        );

        let listener_results = listen_results.clone();
        let listener_accepts = accepts.clone();
        let listener_listen_count = listen_count.clone();
        manager.add_listener(
            move || {
                Box::new(MockListener {
                    url: "mock://optional".parse().unwrap(),
                    listen_results: listener_results.clone(),
                    accepts: listener_accepts.clone(),
                    listen_count: listener_listen_count.clone(),
                    drop_count: Arc::new(AtomicUsize::new(0)),
                })
            },
            false,
        );

        manager.run().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(listen_count.load(Ordering::Relaxed) >= 2);
        assert_eq!(handler.accepted.lock().unwrap().as_slice(), &[3]);
        assert!(events.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ListenerEvent::ListenerAddFailed {
                will_retry: true,
                ..
            }
        )));
    }
}
