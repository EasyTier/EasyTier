use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc, time::Duration};

use anyhow::Context as _;
use async_trait::async_trait;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use url::Url;

pub mod plan;
pub mod transport;

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
#[auto_impl::auto_impl(Box)]
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
pub trait AcceptedSocketHandler<Accepted>: Send + Sync {
    async fn handle_accepted_socket(&self, accepted: Accepted) -> anyhow::Result<()>;
}

#[async_trait]
impl<Accepted, F, Fut> AcceptedSocketHandler<Accepted> for F
where
    Accepted: Send + 'static,
    F: Fn(Accepted) -> Fut + Send + Sync,
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
    ListenerRemoved {
        url: Url,
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
}

pub trait ListenerEventSink: Debug + Send + Sync {
    fn emit(&self, event: ListenerEvent);
}

#[derive(Debug)]
pub struct ListenerEventSinkGroup {
    sinks: Vec<Arc<dyn ListenerEventSink>>,
}

impl ListenerEventSinkGroup {
    pub fn new(sinks: Vec<Arc<dyn ListenerEventSink>>) -> Arc<Self> {
        Arc::new(Self { sinks })
    }
}

impl ListenerEventSink for ListenerEventSinkGroup {
    fn emit(&self, event: ListenerEvent) {
        for sink in &self.sinks {
            sink.emit(event.clone());
        }
    }
}

pub trait RunningListenerProvider: Debug + Send + Sync + 'static {
    fn running_listeners(&self) -> Vec<Url>;
}

#[derive(Debug, Default)]
pub struct RunningListenerRegistry {
    listeners: std::sync::Mutex<Vec<(Url, usize)>>,
}

impl RunningListenerProvider for RunningListenerRegistry {
    fn running_listeners(&self) -> Vec<Url> {
        self.listeners
            .lock()
            .unwrap()
            .iter()
            .map(|(url, _)| url.clone())
            .collect()
    }
}

impl ListenerEventSink for RunningListenerRegistry {
    fn emit(&self, event: ListenerEvent) {
        let mut listeners = self.listeners.lock().unwrap();
        match event {
            ListenerEvent::ListenerAdded { url, .. } => {
                if let Some((_, count)) =
                    listeners.iter_mut().find(|(listener, _)| listener == &url)
                {
                    *count += 1;
                } else {
                    listeners.push((url, 1));
                }
            }
            ListenerEvent::ListenerRemoved { url } => {
                if let Some(index) = listeners.iter().position(|(listener, _)| listener == &url) {
                    if listeners[index].1 == 1 {
                        listeners.remove(index);
                    } else {
                        listeners[index].1 -= 1;
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct NoopListenerEventSink;

impl ListenerEventSink for NoopListenerEventSink {
    fn emit(&self, _event: ListenerEvent) {}
}

type ListenerCreatorArc<Accepted> =
    Arc<dyn Fn() -> Box<dyn SocketListener<Accepted = Accepted>> + Send + Sync>;

#[derive(Clone)]
pub struct ListenerFactory<Accepted> {
    creator: ListenerCreatorArc<Accepted>,
    must_succeed: bool,
}

impl<Accepted> ListenerFactory<Accepted> {
    pub fn new<C>(creator: C, must_succeed: bool) -> Self
    where
        C: Fn() -> Box<dyn SocketListener<Accepted = Accepted>> + Send + Sync + 'static,
    {
        Self {
            creator: Arc::new(creator),
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

pub struct ListenerManager<Accepted, H: ?Sized> {
    factories: Vec<ListenerFactory<Accepted>>,
    handler: Arc<H>,
    events: Arc<dyn ListenerEventSink>,
    options: ListenerManagerOptions,
    operation: Mutex<()>,
    cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
    handler_tasks: Arc<Mutex<JoinSet<()>>>,
    accepted_tasks: AcceptedTaskSpawner,
    accepted_task_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<AcceptedTask>>>,
}

type AcceptedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Clone)]
struct AcceptedTaskSpawner {
    tx: mpsc::UnboundedSender<AcceptedTask>,
}

impl AcceptedTaskSpawner {
    fn new() -> (Self, mpsc::UnboundedReceiver<AcceptedTask>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.tx.send(Box::pin(future)).is_err() {
            tracing::warn!("accepted socket handler task runner stopped");
        }
    }
}

impl<Accepted, H> ListenerManager<Accepted, H>
where
    Accepted: Send + 'static,
    H: AcceptedSocketHandler<Accepted> + ?Sized + 'static,
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
        let (accepted_tasks, accepted_task_rx) = AcceptedTaskSpawner::new();
        Self {
            factories: Vec::new(),
            handler,
            events,
            options,
            operation: Mutex::new(()),
            cancel: CancellationToken::new(),
            tasks: Mutex::new(JoinSet::new()),
            handler_tasks: Arc::new(Mutex::new(JoinSet::new())),
            accepted_tasks,
            accepted_task_rx: std::sync::Mutex::new(Some(accepted_task_rx)),
        }
    }

    pub fn add_listener<C>(&mut self, creator: C, must_succeed: bool)
    where
        C: Fn() -> Box<dyn SocketListener<Accepted = Accepted>> + Send + Sync + 'static,
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

    pub async fn run(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.cancel.is_cancelled() {
            anyhow::bail!("listener manager is stopped");
        }
        let accepted_task_rx = self
            .accepted_task_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("listener manager is one-shot and already ran"))?;
        let mut initial_listeners = Vec::with_capacity(self.factories.len());
        for factory in &self.factories {
            initial_listeners.push(if factory.must_succeed {
                let listener = tokio::select! {
                    _ = self.cancel.cancelled() => {
                        anyhow::bail!("listener manager stopped during startup")
                    }
                    result = listen_once(factory.creator.clone()) => {
                        result.with_context(|| "required listener failed to start")?
                    }
                };
                Some(listener)
            } else {
                None
            });
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("listener manager stopped during startup");
        }
        let initial_listeners = initial_listeners
            .into_iter()
            .map(|listener| {
                listener.map(|listener| RegisteredListener::new(listener, self.events.clone()))
            })
            .collect::<Vec<_>>();

        let mut tasks = self.tasks.lock().await;
        tasks.spawn(run_accepted_task_runner(
            accepted_task_rx,
            self.handler_tasks.clone(),
            self.cancel.clone(),
        ));

        for (factory, initial_listener) in self.factories.iter().zip(initial_listeners) {
            let cancel = self.cancel.clone();
            let listener = run_listener(
                factory.creator.clone(),
                self.handler.clone(),
                self.events.clone(),
                self.options.clone(),
                self.accepted_tasks.clone(),
                initial_listener,
            );
            tasks.spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = listener => {}
                }
            });
        }

        Ok(())
    }

    pub async fn stop(&self) {
        self.cancel.cancel();
        let _operation = self.operation.lock().await;
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(tasks);

        let mut handler_tasks = self.handler_tasks.lock().await;
        handler_tasks.abort_all();
        while handler_tasks.join_next().await.is_some() {}
    }
}

async fn listen_once<Accepted>(
    creator: ListenerCreatorArc<Accepted>,
) -> anyhow::Result<Box<dyn SocketListener<Accepted = Accepted>>>
where
    Accepted: Send + 'static,
{
    let mut listener = creator();
    match listener.listen().await {
        Ok(()) => Ok(listener),
        Err(error) => Err(error),
    }
}

async fn run_listener<Accepted, H>(
    creator: ListenerCreatorArc<Accepted>,
    handler: Arc<H>,
    events: Arc<dyn ListenerEventSink>,
    options: ListenerManagerOptions,
    accepted_tasks: AcceptedTaskSpawner,
    mut initial_listener: Option<RegisteredListener<Accepted>>,
) where
    Accepted: Send + 'static,
    H: AcceptedSocketHandler<Accepted> + ?Sized + 'static,
{
    let mut listen_error_count = 0;
    loop {
        let registered_listener = match initial_listener.take() {
            Some(listener) => listener,
            None => {
                let mut listener = creator();
                match listener.listen().await {
                    Ok(()) => {
                        listen_error_count = 0;
                        RegisteredListener::new(listener, events.clone())
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
                        crate::runtime_time::sleep(options.listen_retry_delay).await;
                        continue;
                    }
                }
            }
        };
        let mut listener = registered_listener.listener;
        let _registration = registered_listener.registration;

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
                    crate::runtime_time::sleep(options.accept_retry_delay).await;
                    break;
                }
            };

            events.emit(ListenerEvent::SocketAccepted {
                url: listener_url.clone(),
            });
            let handler = handler.clone();
            let events = events.clone();
            accepted_tasks.spawn(async move {
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

async fn run_accepted_task_runner(
    mut accepted_task_rx: mpsc::UnboundedReceiver<AcceptedTask>,
    handler_tasks: Arc<Mutex<JoinSet<()>>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            maybe_task = accepted_task_rx.recv() => {
                match maybe_task {
                    Some(task) => {
                        handler_tasks.lock().await.spawn(task);
                    }
                    None => break,
                }
            }
            _ = crate::runtime_time::sleep(Duration::from_secs(1)) => {
                let mut handler_tasks = handler_tasks.lock().await;
                while let Some(task) = handler_tasks.try_join_next() {
                    if let Err(error) = task {
                        tracing::error!(?error, "accepted socket handler task failed");
                    }
                }
            }
        }
    }

    let mut handler_tasks = handler_tasks.lock().await;
    if cancel.is_cancelled() {
        handler_tasks.abort_all();
    }
    while let Some(task) = handler_tasks.join_next().await {
        if let Err(error) = task {
            tracing::error!(?error, "accepted socket handler task failed");
        }
    }
}

struct RegisteredListener<Accepted>
where
    Accepted: Send + 'static,
{
    listener: Box<dyn SocketListener<Accepted = Accepted>>,
    registration: ListenerRegistration,
}

impl<Accepted> RegisteredListener<Accepted>
where
    Accepted: Send + 'static,
{
    fn new(
        listener: Box<dyn SocketListener<Accepted = Accepted>>,
        events: Arc<dyn ListenerEventSink>,
    ) -> Self {
        let url = listener.local_url();
        events.emit(ListenerEvent::ListenerAdded {
            url: url.clone(),
            connection_counter: listener.connection_counter(),
        });
        Self {
            listener,
            registration: ListenerRegistration { url, events },
        }
    }
}

struct ListenerRegistration {
    url: Url,
    events: Arc<dyn ListenerEventSink>,
}

impl Drop for ListenerRegistration {
    fn drop(&mut self) {
        self.events.emit(ListenerEvent::ListenerRemoved {
            url: self.url.clone(),
        });
    }
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
    struct BlockingListenListener {
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl SocketListener for BlockingListenListener {
        type Accepted = usize;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.started.notify_one();
            std::future::pending().await
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            "mock://blocking-start".parse().unwrap()
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

    #[test]
    fn running_listener_registry_reference_counts_duplicate_urls() {
        let registry = RunningListenerRegistry::default();
        let url: Url = "tcp://127.0.0.1:11010".parse().unwrap();
        for _ in 0..2 {
            registry.emit(ListenerEvent::ListenerAdded {
                url: url.clone(),
                connection_counter: Arc::new(EmptyConnectionCounter),
            });
        }
        assert_eq!(registry.running_listeners(), vec![url.clone()]);

        registry.emit(ListenerEvent::ListenerRemoved { url: url.clone() });
        assert_eq!(registry.running_listeners(), vec![url.clone()]);
        registry.emit(ListenerEvent::ListenerRemoved { url });
        assert!(registry.running_listeners().is_empty());
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
        crate::runtime_time::sleep(Duration::from_millis(20)).await;

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
        crate::runtime_time::sleep(Duration::from_millis(20)).await;

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

    #[tokio::test]
    async fn required_listener_failure_does_not_leave_partial_tasks_running() {
        let handler = Arc::new(MockHandler {
            accepted: Mutex::new(Vec::new()),
        });
        let events = Arc::new(Events::default());
        let first_accepts = Arc::new(Mutex::new(VecDeque::from([Ok::<_, anyhow::Error>(9)])));
        let mut manager = ListenerManager::new_with_options(
            handler.clone(),
            events.clone(),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 0,
            },
        );

        let first_accepts_clone = first_accepts.clone();
        manager.add_listener(
            move || {
                Box::new(MockListener {
                    url: "mock://first".parse().unwrap(),
                    listen_results: Arc::new(Mutex::new(VecDeque::from([Ok(())]))),
                    accepts: first_accepts_clone.clone(),
                    listen_count: Arc::new(AtomicUsize::new(0)),
                    drop_count: Arc::new(AtomicUsize::new(0)),
                })
            },
            true,
        );
        manager.add_listener(
            move || {
                Box::new(MockListener {
                    url: "mock://second".parse().unwrap(),
                    listen_results: Arc::new(Mutex::new(VecDeque::from([Err(anyhow::anyhow!(
                        "bind failed"
                    ))]))),
                    accepts: Arc::new(Mutex::new(VecDeque::new())),
                    listen_count: Arc::new(AtomicUsize::new(0)),
                    drop_count: Arc::new(AtomicUsize::new(0)),
                })
            },
            true,
        );

        assert!(manager.run().await.is_err());
        crate::runtime_time::sleep(Duration::from_millis(20)).await;
        assert!(handler.accepted.lock().unwrap().is_empty());
        assert!(
            events
                .events
                .lock()
                .unwrap()
                .iter()
                .all(|event| !matches!(event, ListenerEvent::ListenerAdded { .. }))
        );
    }

    #[tokio::test]
    async fn manager_owned_closure_handler_handles_accepted_socket() {
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let mut manager = ListenerManager::new_with_options(
            Arc::new({
                let accepted = accepted.clone();
                move |value| {
                    let accepted = accepted.clone();
                    async move {
                        accepted.lock().unwrap().push(value);
                        Ok(())
                    }
                }
            }),
            Arc::new(Events::default()),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 0,
            },
        );

        manager.add_listener(
            move || {
                Box::new(MockListener {
                    url: "mock://closure".parse().unwrap(),
                    listen_results: Arc::new(Mutex::new(VecDeque::from([Ok(())]))),
                    accepts: Arc::new(Mutex::new(VecDeque::from([Ok::<_, anyhow::Error>(11)]))),
                    listen_count: Arc::new(AtomicUsize::new(0)),
                    drop_count: Arc::new(AtomicUsize::new(0)),
                })
            },
            true,
        );

        manager.run().await.unwrap();
        crate::runtime_time::sleep(Duration::from_millis(20)).await;

        assert_eq!(accepted.lock().unwrap().as_slice(), &[11]);
    }

    #[derive(Debug)]
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    #[derive(Debug)]
    struct DropSignalListener {
        url: Url,
        listen_results: Arc<Mutex<VecDeque<anyhow::Result<()>>>>,
        accepts: Arc<Mutex<VecDeque<anyhow::Result<DropSignal>>>>,
    }

    #[async_trait]
    impl SocketListener for DropSignalListener {
        type Accepted = DropSignal;

        async fn listen(&mut self) -> anyhow::Result<()> {
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
    struct PendingHandler;

    #[async_trait]
    impl AcceptedSocketHandler<DropSignal> for PendingHandler {
        async fn handle_accepted_socket(&self, accepted: DropSignal) -> anyhow::Result<()> {
            let _accepted = accepted;
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn stop_joins_in_flight_handler_tasks_and_is_one_shot() {
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let mut manager = ListenerManager::new_with_options(
            Arc::new(PendingHandler),
            Arc::new(Events::default()),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 0,
            },
        );
        let accepts = Arc::new(Mutex::new(VecDeque::from([Ok::<_, anyhow::Error>(
            DropSignal(Some(drop_tx)),
        )])));
        let listener_accepts = accepts.clone();
        manager.add_listener(
            move || {
                Box::new(DropSignalListener {
                    url: "mock://drop".parse().unwrap(),
                    listen_results: Arc::new(Mutex::new(VecDeque::from([Ok(())]))),
                    accepts: listener_accepts.clone(),
                })
            },
            true,
        );

        manager.run().await.unwrap();
        crate::runtime_time::sleep(Duration::from_millis(20)).await;
        manager.stop().await;

        crate::runtime_time::timeout(Duration::from_secs(1), drop_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(manager.run().await.is_err());
    }

    #[tokio::test]
    async fn stop_interrupts_required_listener_startup() {
        let started = Arc::new(tokio::sync::Notify::new());
        let mut manager = ListenerManager::new(Arc::new(MockHandler {
            accepted: Mutex::new(Vec::new()),
        }));
        let listener_started = started.clone();
        manager.add_listener(
            move || {
                Box::new(BlockingListenListener {
                    started: listener_started.clone(),
                })
            },
            true,
        );
        let manager = Arc::new(manager);
        let run_task = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.run().await })
        };

        crate::runtime_time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        manager.stop().await;

        assert!(run_task.await.unwrap().is_err());
        assert!(manager.tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn listen_retry_exhaustion_keeps_in_flight_handler_tasks_until_manager_drop() {
        let (drop_tx, mut drop_rx) = tokio::sync::oneshot::channel();
        let listen_results = Arc::new(Mutex::new(VecDeque::from([
            Ok(()),
            Err(anyhow::anyhow!("bind failed")),
        ])));
        let accepts = Arc::new(Mutex::new(VecDeque::from([
            Ok::<_, anyhow::Error>(DropSignal(Some(drop_tx))),
            Err(anyhow::anyhow!("accept failed")),
        ])));
        let events = Arc::new(Events::default());
        let mut manager = ListenerManager::new_with_options(
            Arc::new(PendingHandler),
            events.clone(),
            ListenerManagerOptions {
                accept_retry_delay: Duration::from_millis(1),
                listen_retry_delay: Duration::from_millis(1),
                max_listen_retries: 0,
            },
        );
        let listener_results = listen_results.clone();
        let listener_accepts = accepts.clone();
        manager.add_listener(
            move || {
                Box::new(DropSignalListener {
                    url: "mock://retry-exhausted".parse().unwrap(),
                    listen_results: listener_results.clone(),
                    accepts: listener_accepts.clone(),
                })
            },
            true,
        );

        manager.run().await.unwrap();
        crate::runtime_time::timeout(Duration::from_secs(1), async {
            loop {
                if events.events.lock().unwrap().iter().any(|event| {
                    matches!(
                        event,
                        ListenerEvent::ListenerAddFailed {
                            will_retry: false,
                            ..
                        }
                    )
                }) {
                    break;
                }
                crate::runtime_time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        assert!(matches!(
            drop_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        drop(manager);
        crate::runtime_time::timeout(Duration::from_secs(1), drop_rx)
            .await
            .unwrap()
            .unwrap();
    }
}
