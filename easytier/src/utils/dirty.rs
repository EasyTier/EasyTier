use tokio::sync::watch;

#[derive(Debug)]
pub struct DirtyFlag {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl DirtyFlag {
    pub fn new(value: bool) -> Self {
        let (tx, rx) = watch::channel(value);
        Self { tx, rx }
    }

    pub fn mark(&self) {
        self.tx.send(true).ok();
    }

    pub fn peek(&self) -> bool {
        *self.tx.borrow()
    }

    pub fn reset(&self) -> bool {
        self.tx.send_replace(false)
    }

    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        let _ = rx.wait_for(|v| *v).await;
    }
}

impl Default for DirtyFlag {
    fn default() -> Self {
        Self::new(true)
    }
}
