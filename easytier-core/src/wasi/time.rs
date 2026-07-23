//! Deadline-tracking Tokio time implementation for externally driven WASI runtimes.

mod tracked {
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        future::{Future, IntoFuture},
        pin::Pin,
        task::{Context, Poll},
    };

    pub use tokio::time::{Duration, Instant, MissedTickBehavior, error};

    thread_local! {
        static CURRENT_DOMAIN: Cell<Option<u64>> = const { Cell::new(None) };
        static DEADLINES: RefCell<DeadlineRegistry> = RefCell::new(DeadlineRegistry::default());
    }

    #[derive(Default)]
    struct DeadlineRegistry {
        next_token: u64,
        entries: BTreeMap<u64, (u64, Instant)>,
    }

    impl DeadlineRegistry {
        fn insert(&mut self, domain: u64, deadline: Instant) -> u64 {
            loop {
                self.next_token = self.next_token.wrapping_add(1);
                if self.next_token != 0 && !self.entries.contains_key(&self.next_token) {
                    self.entries.insert(self.next_token, (domain, deadline));
                    return self.next_token;
                }
            }
        }
    }

    pub(crate) struct TimerDomainGuard(Option<u64>);

    impl Drop for TimerDomainGuard {
        fn drop(&mut self) {
            CURRENT_DOMAIN.set(self.0);
        }
    }

    pub(crate) fn enter_domain(domain: u64) -> TimerDomainGuard {
        TimerDomainGuard(CURRENT_DOMAIN.replace(Some(domain)))
    }

    pub(crate) fn clear_domain(domain: u64) {
        DEADLINES.with_borrow_mut(|registry| {
            registry
                .entries
                .retain(|_, (entry_domain, _)| *entry_domain != domain);
        });
    }

    pub(crate) fn next_deadline_millis(domain: u64) -> Option<u64> {
        let deadline = DEADLINES.with_borrow(|registry| {
            registry
                .entries
                .values()
                .filter_map(|(entry_domain, deadline)| {
                    (*entry_domain == domain).then_some(*deadline)
                })
                .min()
        })?;
        let duration = deadline.saturating_duration_since(Instant::now());
        let nanos = duration.as_nanos();
        Some(u64::try_from(nanos.div_ceil(1_000_000)).unwrap_or(u64::MAX))
    }

    struct Registration {
        token: Option<u64>,
        deadline: Instant,
    }

    impl Registration {
        fn new(deadline: Instant) -> Self {
            let mut registration = Self {
                token: None,
                deadline,
            };
            registration.ensure();
            registration
        }

        fn ensure(&mut self) {
            if self.token.is_some() {
                return;
            }
            let Some(domain) = CURRENT_DOMAIN.get() else {
                return;
            };
            self.token =
                Some(DEADLINES.with_borrow_mut(|registry| registry.insert(domain, self.deadline)));
        }

        fn reset(&mut self, deadline: Instant) {
            self.remove();
            self.deadline = deadline;
            self.ensure();
        }

        fn remove(&mut self) {
            if let Some(token) = self.token.take() {
                DEADLINES.with_borrow_mut(|registry| {
                    registry.entries.remove(&token);
                });
            }
        }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            self.remove();
        }
    }

    pub struct Sleep {
        inner: Pin<Box<tokio::time::Sleep>>,
        registration: Registration,
    }

    impl Sleep {
        pub fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
            let this = self.as_mut().get_mut();
            this.inner.as_mut().reset(deadline);
            this.registration.reset(deadline);
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.as_mut().get_mut();
            this.registration.ensure();
            let result = this.inner.as_mut().poll(context);
            if result.is_ready() {
                this.registration.remove();
            }
            result
        }
    }

    pub fn sleep(duration: Duration) -> Sleep {
        sleep_until(Instant::now() + duration)
    }

    pub fn sleep_until(deadline: Instant) -> Sleep {
        Sleep {
            inner: Box::pin(tokio::time::sleep_until(deadline)),
            registration: Registration::new(deadline),
        }
    }

    pub struct Interval {
        inner: Pin<Box<tokio::time::Sleep>>,
        period: Duration,
        next_deadline: Instant,
        missed_tick_behavior: MissedTickBehavior,
        registration: Registration,
    }

    impl Interval {
        pub async fn tick(&mut self) -> Instant {
            self.registration.ensure();
            let tick = self.next_deadline;
            self.inner.as_mut().await;
            let now = Instant::now();
            self.next_deadline = if now > tick + Duration::from_millis(5) {
                next_interval_deadline(self.missed_tick_behavior, tick, now, self.period)
            } else {
                tick + self.period
            };
            self.inner.as_mut().reset(self.next_deadline);
            self.registration.reset(self.next_deadline);
            tick
        }
    }

    pub(super) fn next_interval_deadline(
        behavior: MissedTickBehavior,
        tick: Instant,
        now: Instant,
        period: Duration,
    ) -> Instant {
        match behavior {
            MissedTickBehavior::Burst => tick + period,
            MissedTickBehavior::Delay => now + period,
            MissedTickBehavior::Skip => {
                now + period
                    - Duration::from_nanos(
                        ((now - tick).as_nanos() % period.as_nanos())
                            .try_into()
                            .expect("too much time has elapsed since the interval tick"),
                    )
            }
        }
    }

    pub fn interval(period: Duration) -> Interval {
        interval_at(Instant::now(), period)
    }

    pub fn interval_at(start: Instant, period: Duration) -> Interval {
        assert!(period > Duration::ZERO, "`period` must be non-zero.");
        Interval {
            inner: Box::pin(tokio::time::sleep_until(start)),
            period,
            next_deadline: start,
            missed_tick_behavior: MissedTickBehavior::Burst,
            registration: Registration::new(start),
        }
    }

    pub async fn timeout<F>(duration: Duration, future: F) -> Result<F::Output, error::Elapsed>
    where
        F: IntoFuture,
    {
        timeout_at(Instant::now() + duration, future).await
    }

    pub async fn timeout_at<F>(deadline: Instant, future: F) -> Result<F::Output, error::Elapsed>
    where
        F: IntoFuture,
    {
        let _registration = Registration::new(deadline);
        tokio::time::timeout_at(deadline, future).await
    }
}

pub use tracked::{Duration, Instant, Interval, error, interval, sleep, timeout};

pub(crate) use tracked::{clear_domain, enter_domain, next_deadline_millis};

#[cfg(test)]
mod tests {
    use super::tracked::MissedTickBehavior;
    use super::*;

    #[tokio::test]
    async fn tracks_reset_completion_and_drop_per_domain() {
        let _domain = enter_domain(7);
        {
            let sleep = sleep(Duration::from_millis(50));
            tokio::pin!(sleep);
            assert!(matches!(next_deadline_millis(7), Some(1..=50)));
            assert_eq!(next_deadline_millis(8), None);

            sleep
                .as_mut()
                .reset(Instant::now() + Duration::from_millis(20));
            assert!(matches!(next_deadline_millis(7), Some(1..=20)));
        }
        assert_eq!(next_deadline_millis(7), None);

        let pending = sleep(Duration::from_secs(1));
        assert!(matches!(next_deadline_millis(7), Some(999..=1000)));
        drop(pending);
        assert_eq!(next_deadline_millis(7), None);

        sleep(Duration::ZERO).await;
        assert_eq!(next_deadline_millis(7), None);
    }

    #[tokio::test]
    async fn tracks_interval_and_timeout_lifetimes() {
        let _domain = enter_domain(9);
        let mut ticker = interval(Duration::from_millis(40));
        assert_eq!(next_deadline_millis(9), Some(0));
        ticker.tick().await;
        assert!(matches!(next_deadline_millis(9), Some(1..=40)));
        drop(ticker);
        assert_eq!(next_deadline_millis(9), None);

        let timeout = tokio::spawn(timeout(
            Duration::from_millis(60),
            std::future::pending::<()>(),
        ));
        tokio::task::yield_now().await;
        assert!(matches!(next_deadline_millis(9), Some(1..=60)));
        timeout.abort();
        let _ = timeout.await;
        assert_eq!(next_deadline_millis(9), None);
    }

    #[tokio::test]
    async fn clears_all_deadlines_for_a_domain() {
        let _domain = enter_domain(11);
        let _timer = sleep(Duration::from_secs(1));
        assert!(next_deadline_millis(11).is_some());

        clear_domain(11);

        assert_eq!(next_deadline_millis(11), None);
    }

    #[test]
    fn computes_missed_interval_deadlines_like_tokio() {
        let tick = Instant::now();
        let now = tick + Duration::from_millis(250);
        let period = Duration::from_millis(100);

        assert_eq!(
            tracked::next_interval_deadline(MissedTickBehavior::Burst, tick, now, period),
            tick + period
        );
        assert_eq!(
            tracked::next_interval_deadline(MissedTickBehavior::Delay, tick, now, period),
            now + period
        );
        assert_eq!(
            tracked::next_interval_deadline(MissedTickBehavior::Skip, tick, now, period),
            tick + Duration::from_millis(300)
        );
    }
}
