use std::{
    collections::{HashMap, VecDeque},
    io,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use easytier::socket_protector::{NativeSocketProtector, set_native_socket_protector};
use once_cell::sync::Lazy;
use tokio::sync::{Notify, oneshot};

const MAX_PENDING_SOCKET_PROTECTIONS: usize = 128;

#[derive(Debug, Clone)]
pub struct SocketProtectionRequest {
    pub request_id: u64,
    pub socket_fd: i32,
    pub purpose: String,
}

#[derive(Default)]
struct SocketProtectionState {
    enabled: bool,
    next_request_id: u64,
    queued: VecDeque<SocketProtectionRequest>,
    pending: HashMap<u64, PendingSocketProtection>,
}

struct PendingSocketProtection {
    completion: oneshot::Sender<io::Result<()>>,
    _socket: OwnedFd,
}

#[derive(Default)]
pub struct SocketProtectionManager {
    state: Mutex<SocketProtectionState>,
    request_ready: Notify,
}

pub static SOCKET_PROTECTION_MANAGER: Lazy<Arc<SocketProtectionManager>> =
    Lazy::new(|| Arc::new(SocketProtectionManager::default()));

impl SocketProtectionManager {
    fn enable(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.enabled = true;
    }

    fn disable(&self) {
        let queued = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.enabled = false;
            let queued_ids = state
                .queued
                .drain(..)
                .map(|request| request.request_id)
                .collect::<Vec<_>>();
            queued_ids
                .into_iter()
                .filter_map(|request_id| state.pending.remove(&request_id))
                .map(|pending| pending.completion)
                .collect::<Vec<_>>()
        };
        self.request_ready.notify_waiters();
        for sender in queued {
            let _ = sender.send(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native socket protection stopped",
            )));
        }
    }

    pub async fn next_request(&self) -> Option<SocketProtectionRequest> {
        loop {
            let notified = self.request_ready.notified();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(request) = state.queued.pop_front() {
                    return Some(request);
                }
                if !state.enabled {
                    return None;
                }
            }
            notified.await;
        }
    }

    pub fn complete_request(&self, request_id: u64, success: bool, error: Option<String>) -> bool {
        let pending = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&request_id);
        let Some(pending) = pending else {
            return false;
        };
        let result = if success {
            Ok(())
        } else {
            Err(io::Error::other(error.unwrap_or_else(|| {
                "native socket protection failed".to_string()
            })))
        };
        pending.completion.send(result).is_ok()
    }
}

#[async_trait]
impl NativeSocketProtector for SocketProtectionManager {
    async fn protect(&self, socket_handle: u64) -> io::Result<()> {
        let socket_fd = i32::try_from(socket_handle).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket handle {socket_handle} does not fit a HarmonyOS fd"),
            )
        })?;
        // Keep a duplicate alive across the ArkTS Promise. Socket options set
        // through it affect the same socket, while cancellation cannot turn the
        // request into a stale, reused descriptor.
        let protected_socket = unsafe { BorrowedFd::borrow_raw(socket_fd) }.try_clone_to_owned()?;
        let protected_fd = protected_socket.as_raw_fd();
        let (sender, receiver) = oneshot::channel();
        let request_id = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.enabled {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "native socket protection is not active",
                ));
            }
            if state.pending.len() >= MAX_PENDING_SOCKET_PROTECTIONS {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many pending native socket protection requests",
                ));
            }
            state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
            let request_id = state.next_request_id;
            state.queued.push_back(SocketProtectionRequest {
                request_id,
                socket_fd: protected_fd,
                // Keep the existing ArkTS request shape without native policy labels.
                purpose: "socket".to_owned(),
            });
            state.pending.insert(
                request_id,
                PendingSocketProtection {
                    completion: sender,
                    _socket: protected_socket,
                },
            );
            request_id
        };
        self.request_ready.notify_one();
        receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::Interrupted,
                format!("socket protection request {request_id} was cancelled"),
            )
        })?
    }
}

pub fn enable_socket_protection() -> bool {
    SOCKET_PROTECTION_MANAGER.enable();
    set_native_socket_protector(Some(SOCKET_PROTECTION_MANAGER.clone()));
    true
}

pub fn disable_socket_protection() -> bool {
    set_native_socket_protector(None);
    SOCKET_PROTECTION_MANAGER.disable();
    true
}

pub fn fail_socket_protection() -> bool {
    // Keep the disabled manager installed so an unexpected ArkTS pump failure
    // remains fail-closed for every subsequently created transport socket.
    SOCKET_PROTECTION_MANAGER.disable();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::socket_protector::NativeSocketProtector;
    use std::os::fd::AsRawFd;

    #[test]
    fn transport_socket_waits_for_platform_completion() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let manager = Arc::new(SocketProtectionManager::default());
            manager.enable();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let socket_fd = socket.as_raw_fd();
            let task = tokio::spawn({
                let manager = manager.clone();
                async move { manager.protect(socket_fd as u64).await }
            });
            let request = manager.next_request().await.unwrap();
            assert_ne!(request.socket_fd, socket_fd);
            assert!(manager.complete_request(request.request_id, true, None));
            task.await.unwrap().unwrap();
        });
    }

    #[test]
    fn dispatched_socket_is_retained_during_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let manager = Arc::new(SocketProtectionManager::default());
            manager.enable();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let socket_fd = socket.as_raw_fd();
            let task = tokio::spawn({
                let manager = manager.clone();
                async move { manager.protect(socket_fd as u64).await }
            });
            let request = manager.next_request().await.unwrap();

            manager.disable();
            tokio::task::yield_now().await;
            assert!(!task.is_finished());

            assert!(manager.complete_request(
                request.request_id,
                false,
                Some("shutdown".to_string()),
            ));
            assert!(task.await.unwrap().is_err());
        });
    }
}
