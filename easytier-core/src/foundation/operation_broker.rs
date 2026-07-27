//! Domain-neutral lifecycle and completion storage for externally submitted
//! asynchronous operations.

use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
};

use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct OperationId(u64);

impl OperationId {
    pub(crate) fn from_raw(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionError {
    AtCapacity,
    IdExhausted,
}

pub(crate) struct Admission {
    pub(crate) id: OperationId,
    pub(crate) cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessError {
    Missing,
    NotDrained,
}

pub(crate) struct Completion<K, S> {
    pub(crate) operation_id: OperationId,
    pub(crate) kind: K,
    pub(crate) status: S,
}

pub(crate) struct ReleasedOperation<M, O> {
    pub(crate) metadata: M,
    pub(crate) outcome: Option<O>,
}

pub(crate) struct TakenOperation<M, T> {
    pub(crate) metadata: M,
    pub(crate) value: T,
}

enum OperationState<O> {
    Pending,
    Queued(O),
    Drained(O),
    Discarding,
}

struct Operation<K, O, M> {
    kind: K,
    metadata: Option<M>,
    cancellation: CancellationToken,
    state: OperationState<O>,
}

pub(crate) struct OperationBroker<K, O, M> {
    max_operations: usize,
    next_operation_id: u64,
    operations: HashMap<OperationId, Operation<K, O, M>>,
    completions: VecDeque<OperationId>,
    wake_generation: u64,
}

impl<K, O, M> OperationBroker<K, O, M>
where
    K: Copy,
{
    pub(crate) fn new(max_operations: usize) -> Self {
        Self {
            max_operations,
            next_operation_id: 1,
            operations: HashMap::new(),
            completions: VecDeque::new(),
            wake_generation: 0,
        }
    }

    pub(crate) fn admit(&mut self, kind: K, metadata: M) -> Result<Admission, AdmissionError> {
        if self.operations.len() >= self.max_operations {
            return Err(AdmissionError::AtCapacity);
        }
        let id =
            OperationId::from_raw(self.next_operation_id).ok_or(AdmissionError::IdExhausted)?;
        self.next_operation_id = self
            .next_operation_id
            .checked_add(1)
            .ok_or(AdmissionError::IdExhausted)?;
        let cancellation = CancellationToken::new();
        let replaced = self.operations.insert(
            id,
            Operation {
                kind,
                metadata: Some(metadata),
                cancellation: cancellation.clone(),
                state: OperationState::Pending,
            },
        );
        debug_assert!(replaced.is_none());
        Ok(Admission { id, cancellation })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.operations.len()
    }

    pub(crate) fn complete_with(
        &mut self,
        operation_id: OperationId,
        complete: impl FnOnce(K, &mut M) -> O,
    ) -> bool {
        self.resolve_pending_with(operation_id, false, complete)
    }

    pub(crate) fn cancel_with(
        &mut self,
        operation_id: OperationId,
        complete: impl FnOnce(K, &mut M) -> O,
    ) -> bool {
        self.resolve_pending_with(operation_id, true, complete)
    }

    fn resolve_pending_with(
        &mut self,
        operation_id: OperationId,
        cancel: bool,
        complete: impl FnOnce(K, &mut M) -> O,
    ) -> bool {
        let Some(mut operation) = self.operations.remove(&operation_id) else {
            return false;
        };
        match operation.state {
            OperationState::Pending => {
                if cancel {
                    operation.cancellation.cancel();
                }
                let outcome = complete(
                    operation.kind,
                    operation
                        .metadata
                        .as_mut()
                        .expect("pending operation metadata is present"),
                );
                let notify = self.completions.is_empty();
                operation.state = OperationState::Queued(outcome);
                self.operations.insert(operation_id, operation);
                self.completions.push_back(operation_id);
                notify
            }
            OperationState::Discarding => {
                if cancel {
                    self.operations.insert(operation_id, operation);
                }
                false
            }
            OperationState::Queued(_) | OperationState::Drained(_) => {
                self.operations.insert(operation_id, operation);
                false
            }
        }
    }

    pub(crate) fn free(&mut self, operation_id: OperationId) -> Option<ReleasedOperation<M, O>> {
        let mut operation = self.operations.remove(&operation_id)?;
        let state = std::mem::replace(&mut operation.state, OperationState::Discarding);
        match state {
            OperationState::Pending => {
                operation.cancellation.cancel();
                let released = ReleasedOperation {
                    metadata: operation
                        .metadata
                        .take()
                        .expect("pending operation metadata is present"),
                    outcome: None,
                };
                self.operations.insert(operation_id, operation);
                Some(released)
            }
            OperationState::Queued(outcome) => {
                self.completions
                    .retain(|completion| *completion != operation_id);
                Some(ReleasedOperation {
                    metadata: operation
                        .metadata
                        .take()
                        .expect("queued operation metadata is present"),
                    outcome: Some(outcome),
                })
            }
            OperationState::Drained(outcome) => Some(ReleasedOperation {
                metadata: operation
                    .metadata
                    .take()
                    .expect("drained operation metadata is present"),
                outcome: Some(outcome),
            }),
            OperationState::Discarding => {
                operation.state = OperationState::Discarding;
                self.operations.insert(operation_id, operation);
                None
            }
        }
    }

    pub(crate) fn drain<S>(
        &mut self,
        max_count: usize,
        mut status: impl FnMut(&O) -> S,
    ) -> Vec<Completion<K, S>> {
        let mut completions = Vec::with_capacity(max_count.min(self.completions.len()));
        while completions.len() < max_count {
            let Some(operation_id) = self.completions.pop_front() else {
                break;
            };
            let Some(operation) = self.operations.get_mut(&operation_id) else {
                continue;
            };
            let old_state = std::mem::replace(&mut operation.state, OperationState::Discarding);
            match old_state {
                OperationState::Queued(outcome) => {
                    completions.push(Completion {
                        operation_id,
                        kind: operation.kind,
                        status: status(&outcome),
                    });
                    operation.state = OperationState::Drained(outcome);
                }
                other => operation.state = other,
            }
        }
        completions
    }

    pub(crate) fn has_completions(&self) -> bool {
        !self.completions.is_empty()
    }

    pub(crate) fn pending_kind(&self, operation_id: OperationId) -> Option<K> {
        self.operations.get(&operation_id).and_then(|operation| {
            matches!(operation.state, OperationState::Pending).then_some(operation.kind)
        })
    }

    pub(crate) fn request_cancellation(&self, operation_id: OperationId) -> bool {
        let Some(operation) = self.operations.get(&operation_id) else {
            return false;
        };
        if !matches!(operation.state, OperationState::Pending) {
            return false;
        }
        operation.cancellation.cancel();
        true
    }

    pub(crate) fn with_drained<T>(
        &self,
        operation_id: OperationId,
        inspect: impl FnOnce(K, &M, &O) -> T,
    ) -> Result<T, AccessError> {
        let operation = self
            .operations
            .get(&operation_id)
            .ok_or(AccessError::Missing)?;
        match &operation.state {
            OperationState::Drained(outcome) => Ok(inspect(
                operation.kind,
                operation
                    .metadata
                    .as_ref()
                    .expect("drained operation metadata is present"),
                outcome,
            )),
            OperationState::Pending | OperationState::Queued(_) | OperationState::Discarding => {
                Err(AccessError::NotDrained)
            }
        }
    }

    pub(crate) fn take_with<T>(
        &mut self,
        operation_id: OperationId,
        take: impl FnOnce(&O) -> Option<T>,
    ) -> Result<Option<TakenOperation<M, T>>, AccessError> {
        let Some(mut operation) = self.operations.remove(&operation_id) else {
            return Err(AccessError::Missing);
        };
        let old_state = std::mem::replace(&mut operation.state, OperationState::Discarding);
        let outcome = match old_state {
            OperationState::Drained(outcome) => outcome,
            other => {
                operation.state = other;
                self.operations.insert(operation_id, operation);
                return Err(AccessError::NotDrained);
            }
        };
        let Some(value) = take(&outcome) else {
            operation.state = OperationState::Drained(outcome);
            self.operations.insert(operation_id, operation);
            return Ok(None);
        };
        Ok(Some(TakenOperation {
            metadata: operation
                .metadata
                .take()
                .expect("drained operation metadata is present"),
            value,
        }))
    }

    pub(crate) fn pending_ids(&self) -> Vec<OperationId> {
        self.operations
            .iter()
            .filter_map(|(operation_id, operation)| {
                matches!(operation.state, OperationState::Pending).then_some(*operation_id)
            })
            .collect()
    }

    pub(crate) fn wake_generation(&self) -> u64 {
        self.wake_generation
    }

    pub(crate) fn invalidate_waiters(&mut self) {
        self.wake_generation = self.wake_generation.wrapping_add(1);
    }

    pub(crate) fn discard_all(&mut self) {
        for operation in self.operations.values() {
            operation.cancellation.cancel();
        }
        self.operations.clear();
        self.completions.clear();
        self.invalidate_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Kind {
        Read,
        Write,
    }

    #[test]
    fn completion_is_drained_and_taken_once() {
        let mut broker = OperationBroker::new(4);
        let admission = broker.admit(Kind::Read, "metadata").unwrap();

        assert!(broker.complete_with(admission.id, |_, _| Ok::<_, u8>(7)));
        let completions = broker.drain(4, |outcome| outcome.is_ok());
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].operation_id, admission.id);
        assert_eq!(completions[0].kind, Kind::Read);
        assert!(completions[0].status);
        assert!(broker.drain(4, |_| true).is_empty());

        assert!(
            broker
                .take_with(admission.id, |_| None::<u8>)
                .unwrap()
                .is_none()
        );
        let taken = broker
            .take_with(admission.id, |outcome| outcome.as_ref().ok().copied())
            .unwrap()
            .unwrap();
        assert_eq!(taken.metadata, "metadata");
        assert_eq!(taken.value, 7);
        assert!(matches!(
            broker.take_with(admission.id, |_| Some(())),
            Err(AccessError::Missing)
        ));
    }

    #[test]
    fn free_pending_absorbs_late_completion() {
        let mut broker = OperationBroker::new(4);
        let admission = broker.admit(Kind::Write, 9).unwrap();

        let released = broker.free(admission.id).unwrap();
        assert_eq!(released.metadata, 9);
        assert!(released.outcome.is_none());
        assert!(admission.cancellation.is_cancelled());
        assert!(!broker.complete_with(admission.id, |_, _| 3));

        assert_eq!(broker.len(), 0);
        assert!(!broker.has_completions());
    }

    #[test]
    fn cancellation_and_completion_have_one_terminal_outcome() {
        let mut cancelled_first = OperationBroker::new(4);
        let cancelled = cancelled_first.admit(Kind::Read, ()).unwrap();
        assert!(cancelled_first.cancel_with(cancelled.id, |_, _| Err::<u8, _>("cancelled")));
        assert!(!cancelled_first.complete_with(cancelled.id, |_, _| Ok(1)));
        let completions = cancelled_first.drain(4, |outcome| outcome.is_ok());
        assert_eq!(completions.len(), 1);
        assert!(!completions[0].status);

        let mut completed_first = OperationBroker::new(4);
        let completed = completed_first.admit(Kind::Read, ()).unwrap();
        assert!(completed_first.complete_with(completed.id, |_, _| Ok::<_, &str>(1)));
        assert!(!completed_first.cancel_with(completed.id, |_, _| Err("cancelled")));
        let completions = completed_first.drain(4, |outcome| outcome.is_ok());
        assert_eq!(completions.len(), 1);
        assert!(completions[0].status);
    }

    #[test]
    fn requested_cancellation_stays_pending_until_operation_completes() {
        let mut broker = OperationBroker::new(4);
        let admission = broker.admit(Kind::Write, "metadata").unwrap();

        assert_eq!(broker.pending_kind(admission.id), Some(Kind::Write));
        assert!(broker.request_cancellation(admission.id));
        assert!(admission.cancellation.is_cancelled());
        assert!(!broker.has_completions());

        assert!(broker.complete_with(admission.id, |_, _| Ok::<_, &'static str>(7)));
        assert!(broker.has_completions());
        assert_eq!(broker.pending_kind(admission.id), None);
    }

    #[test]
    fn completion_notification_is_an_empty_to_nonempty_edge() {
        let mut broker = OperationBroker::new(4);
        let first = broker.admit(Kind::Read, ()).unwrap();
        let second = broker.admit(Kind::Write, ()).unwrap();

        assert!(broker.complete_with(first.id, |_, _| ()));
        assert!(!broker.complete_with(second.id, |_, _| ()));
        assert_eq!(broker.drain(2, |_| ()).len(), 2);
        assert!(!broker.has_completions());

        let third = broker.admit(Kind::Read, ()).unwrap();
        assert!(broker.complete_with(third.id, |_, _| ()));
    }

    #[test]
    fn admission_limit_counts_discarding_tombstones() {
        let mut broker = OperationBroker::new(1);
        let admission = broker.admit(Kind::Read, ()).unwrap();
        broker.free(admission.id);

        assert!(matches!(
            broker.admit(Kind::Write, ()),
            Err(AdmissionError::AtCapacity)
        ));

        broker.complete_with(admission.id, |_, _| ());
        broker.admit(Kind::Write, ()).unwrap();
    }

    #[test]
    fn cancellation_keeps_discarding_tombstone_until_completion() {
        let mut broker: OperationBroker<Kind, (), ()> = OperationBroker::new(1);
        let admission = broker.admit(Kind::Read, ()).unwrap();
        broker.free(admission.id);

        assert!(!broker.cancel_with(admission.id, |_, _| ()));
        assert_eq!(broker.len(), 1);
        assert!(matches!(
            broker.admit(Kind::Write, ()),
            Err(AdmissionError::AtCapacity)
        ));

        assert!(!broker.complete_with(admission.id, |_, _| ()));
        assert_eq!(broker.len(), 0);
        broker.admit(Kind::Write, ()).unwrap();
    }

    #[test]
    fn discard_invalidates_waiters_and_cancels_operations() {
        let mut broker: OperationBroker<Kind, (), ()> = OperationBroker::new(1);
        let admission = broker.admit(Kind::Read, ()).unwrap();
        let generation = broker.wake_generation();

        broker.discard_all();

        assert!(admission.cancellation.is_cancelled());
        assert_ne!(broker.wake_generation(), generation);
        assert_eq!(broker.len(), 0);
    }
}
