//! Serialized lifecycle ABI for a Go-driven WASI core instance.

use std::{cell::RefCell, collections::BTreeMap};

use tokio::{runtime::Builder, task::JoinHandle};

use crate::{
    instance::{
        CoreInstanceState,
        host::WasiCoreInstanceCreateConfig,
        runtime_driver::{RuntimeDriveOutcome, RuntimeDriver},
    },
    process_runtime::CoreProcessRuntime,
    runtime_time::{clear_domain, enter_domain, next_deadline_millis},
    socket::host::packet::HostPacketSinkHandle,
};

use super::{WasiCoreRuntime, new_wasi_core_runtime};

const MAX_CREATE_CONFIG_LEN: usize = 16 * 1024 * 1024;
const MAX_GUEST_BUFFER_LEN: usize = MAX_CREATE_CONFIG_LEN;
const INVALID_HANDLE: i32 = -1;
const INVALID_STATE: i32 = -2;
const INVALID_INPUT: i32 = -3;
const ASYNC_ERROR: i32 = -4;
const BUSY: i32 = -5;

thread_local! {
    static INSTANCES: RefCell<WasiInstanceRegistry> = RefCell::new(WasiInstanceRegistry::default());
}

struct WasiInstanceRegistry {
    next_handle: u64,
    entries: BTreeMap<u64, WasiInstanceEntry>,
    buffers: BTreeMap<u32, Box<[u8]>>,
    process_runtime: std::sync::Arc<CoreProcessRuntime>,
    active_entry: bool,
    error: String,
}

impl Default for WasiInstanceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 0,
            entries: BTreeMap::new(),
            buffers: BTreeMap::new(),
            process_runtime: CoreProcessRuntime::new(),
            active_entry: false,
            error: String::new(),
        }
    }
}

struct WasiInstanceEntry {
    runtime: tokio::runtime::Runtime,
    runtime_driver: RuntimeDriver,
    drive_again: bool,
    core: WasiCoreRuntime,
    start_task: Option<JoinHandle<anyhow::Result<()>>>,
    stop_task: Option<JoinHandle<()>>,
    error: String,
}

impl WasiInstanceRegistry {
    fn allocate_handle(&mut self) -> u64 {
        loop {
            self.next_handle = self.next_handle.wrapping_add(1);
            if self.next_handle != 0 && !self.entries.contains_key(&self.next_handle) {
                return self.next_handle;
            }
        }
    }

    fn set_error(&mut self, error: impl ToString) {
        self.error = error.to_string();
    }

    fn take_entry(&mut self, handle: u64) -> Result<WasiInstanceEntry, i32> {
        if self.active_entry {
            self.set_error("core instance lifecycle call is not reentrant");
            return Err(BUSY);
        }
        let Some(entry) = self.entries.remove(&handle) else {
            self.set_error(format!("unknown core instance handle: {handle}"));
            return Err(INVALID_HANDLE);
        };
        self.active_entry = true;
        Ok(entry)
    }

    fn restore_entry(&mut self, handle: u64, entry: WasiInstanceEntry) {
        debug_assert!(self.active_entry);
        let previous = self.entries.insert(handle, entry);
        debug_assert!(previous.is_none());
        self.active_entry = false;
    }

    fn finish_entry_call(&mut self) {
        debug_assert!(self.active_entry);
        self.active_entry = false;
    }

    fn read_buffer(&self, pointer: u32, length: usize) -> anyhow::Result<Vec<u8>> {
        let buffer = self
            .buffers
            .get(&pointer)
            .ok_or_else(|| anyhow::anyhow!("unknown guest buffer: {pointer}"))?;
        if length > buffer.len() {
            anyhow::bail!(
                "guest buffer length {length} exceeds allocation {}",
                buffer.len()
            );
        }
        Ok(buffer[..length].to_vec())
    }
}

impl WasiInstanceEntry {
    fn start(&mut self) -> anyhow::Result<()> {
        if self.start_task.is_some()
            || self.stop_task.is_some()
            || self.core.core().state() != CoreInstanceState::Created
        {
            anyhow::bail!("core instance cannot schedule start from its current state");
        }
        let instance = self.core.core().clone();
        self.start_task = Some(self.runtime.spawn(async move {
            instance.start().await?;
            instance.start_after_host_ready(None).await
        }));
        Ok(())
    }

    fn stop(&mut self) {
        if self.stop_task.is_some() || self.core.core().state() == CoreInstanceState::Stopped {
            return;
        }
        let instance = self.core.core().clone();
        self.stop_task = Some(self.runtime.spawn(async move {
            instance.stop().await;
        }));
    }

    fn drive(&mut self, domain: u64) -> anyhow::Result<()> {
        let _domain = enter_domain(domain);
        self.core.notify_host_completions();
        self.drive_again =
            self.runtime_driver.drive(&self.runtime) == RuntimeDriveOutcome::BudgetExhausted;

        if self
            .start_task
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let task = self.start_task.take().unwrap();
            match self.runtime.block_on(task) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => anyhow::bail!("core instance start task failed: {error}"),
            }
        }
        if self.stop_task.as_ref().is_some_and(JoinHandle::is_finished) {
            let task = self.stop_task.take().unwrap();
            if let Err(error) = self.runtime.block_on(task) {
                anyhow::bail!("core instance stop task failed: {error}");
            }
        }
        Ok(())
    }

    fn state_code(&self) -> i32 {
        if self.stop_task.is_some() {
            return 3;
        }
        if self.start_task.is_some() {
            return 1;
        }
        match self.core.core().state() {
            CoreInstanceState::Created => 0,
            CoreInstanceState::Starting => 1,
            CoreInstanceState::Running => 2,
            CoreInstanceState::Stopping => 3,
            CoreInstanceState::Stopped => 4,
        }
    }

    fn next_wait_millis(&self, domain: u64) -> Option<u64> {
        if self.drive_again {
            Some(0)
        } else {
            next_deadline_millis(domain)
        }
    }
}

fn decode_create_config(encoded: &[u8]) -> anyhow::Result<WasiCoreInstanceCreateConfig> {
    if encoded.is_empty() || encoded.len() > MAX_CREATE_CONFIG_LEN {
        anyhow::bail!("invalid host core instance config buffer");
    }
    let config: WasiCoreInstanceCreateConfig = serde_json::from_slice(encoded)?;
    config.validate()?;
    Ok(config)
}

fn with_entry(
    handle: u64,
    operation: impl FnOnce(&mut WasiInstanceEntry) -> anyhow::Result<i32>,
) -> i32 {
    let mut entry = match INSTANCES.with_borrow_mut(|registry| registry.take_entry(handle)) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let status = match operation(&mut entry) {
        Ok(status) => status,
        Err(error) => {
            entry.error = error.to_string();
            ASYNC_ERROR
        }
    };
    INSTANCES.with_borrow_mut(|registry| registry.restore_entry(handle, entry));
    status
}

fn read_guest_buffer(pointer: u32, length: u32, maximum: usize) -> anyhow::Result<Vec<u8>> {
    let length = usize::try_from(length).expect("u32 fits usize on wasm32");
    if pointer == 0 || length == 0 || length > maximum {
        anyhow::bail!("invalid guest buffer reference");
    }
    INSTANCES.with_borrow(|registry| registry.read_buffer(pointer, length))
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_buffer_alloc(length: u32) -> u32 {
    let length = usize::try_from(length).expect("u32 fits usize on wasm32");
    if length == 0 || length > MAX_GUEST_BUFFER_LEN {
        INSTANCES.with_borrow_mut(|registry| registry.set_error("invalid guest buffer length"));
        return 0;
    }
    let mut buffer = vec![0_u8; length].into_boxed_slice();
    let pointer = buffer.as_mut_ptr() as u32;
    if pointer == 0 {
        INSTANCES.with_borrow_mut(|registry| registry.set_error("guest buffer allocation failed"));
        return 0;
    }
    INSTANCES.with_borrow_mut(|registry| {
        if registry.buffers.contains_key(&pointer) {
            registry.set_error("guest buffer allocation collided with a live buffer");
            0
        } else {
            registry.buffers.insert(pointer, buffer);
            pointer
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_buffer_free(pointer: u32) -> i32 {
    INSTANCES.with_borrow_mut(|registry| {
        if registry.buffers.remove(&pointer).is_some() {
            0
        } else {
            registry.set_error(format!("unknown guest buffer: {pointer}"));
            INVALID_INPUT
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_create(
    config_pointer: u32,
    config_length: u32,
    packet_sink_handle: u64,
) -> u64 {
    let encoded = match read_guest_buffer(config_pointer, config_length, MAX_CREATE_CONFIG_LEN) {
        Ok(encoded) => encoded,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };
    let config = match decode_create_config(&encoded) {
        Ok(config) => config,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };
    let runtime_driver = RuntimeDriver::default();
    let park_driver = runtime_driver.clone();
    let runtime = match Builder::new_current_thread()
        .enable_time()
        .on_thread_park(move || park_driver.on_thread_park())
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };
    let handle = INSTANCES.with_borrow_mut(WasiInstanceRegistry::allocate_handle);
    let process_runtime = INSTANCES.with_borrow(|registry| registry.process_runtime.clone());
    let core = {
        let _domain = enter_domain(handle);
        let _runtime = runtime.enter();
        new_wasi_core_runtime(
            config.instance,
            process_runtime,
            config.environment,
            HostPacketSinkHandle(packet_sink_handle),
        )
    };
    let core = match core {
        Ok(core) => core,
        Err(error) => {
            clear_domain(handle);
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };

    INSTANCES.with_borrow_mut(|registry| {
        registry.entries.insert(
            handle,
            WasiInstanceEntry {
                runtime,
                runtime_driver,
                drive_again: false,
                core,
                start_task: None,
                stop_task: None,
                error: String::new(),
            },
        );
        handle
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_start(handle: u64) -> i32 {
    with_entry(handle, |entry| match entry.start() {
        Ok(()) => Ok(0),
        Err(error) => {
            entry.error = error.to_string();
            Ok(INVALID_STATE)
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_stop(handle: u64) -> i32 {
    with_entry(handle, |entry| {
        entry.stop();
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_drive(handle: u64) -> i32 {
    with_entry(handle, |entry| {
        entry.drive(handle)?;
        Ok(entry.state_code())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_notify_completions(handle: u64) -> i32 {
    with_entry(handle, |entry| {
        entry.core.notify_host_completions();
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_state(handle: u64) -> i32 {
    with_entry(handle, |entry| Ok(entry.state_code()))
}

/// Returns milliseconds until the next required drive, rounded up. A zero
/// means lifecycle work remains locally runnable. `i64::MAX` means core is
/// waiting only for a host completion; negative values are ABI status codes.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_next_deadline_millis(handle: u64) -> i64 {
    INSTANCES.with_borrow_mut(|registry| {
        if registry.active_entry {
            registry.set_error("core instance lifecycle call is not reentrant");
            return i64::from(BUSY);
        }
        let Some(entry) = registry.entries.get(&handle) else {
            registry.set_error(format!("unknown core instance handle: {handle}"));
            return i64::from(INVALID_HANDLE);
        };
        entry
            .next_wait_millis(handle)
            .map(|millis| i64::try_from(millis).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_send_packet(
    handle: u64,
    packet_pointer: u32,
    packet_length: u32,
) -> i32 {
    with_entry(handle, |entry| {
        let packet = match read_guest_buffer(packet_pointer, packet_length, 1024 * 1024) {
            Ok(packet) => packet,
            Err(error) => {
                entry.error = error.to_string();
                return Ok(INVALID_INPUT);
            }
        };
        let packet_plane = entry.core.core().packet_plane();
        entry.runtime.spawn(async move {
            if let Err(error) = packet_plane.send_ip_packet(packet).await {
                tracing::warn!(?error, "host packet ingress failed");
            }
        });
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_drop(handle: u64) -> i32 {
    let entry = match INSTANCES.with_borrow_mut(|registry| registry.take_entry(handle)) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    {
        let _domain = enter_domain(handle);
        drop(entry);
    }
    clear_domain(handle);
    INSTANCES.with_borrow_mut(WasiInstanceRegistry::finish_entry_call);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_error_len(handle: u64) -> u32 {
    INSTANCES.with_borrow(|registry| {
        let error = registry
            .entries
            .get(&handle)
            .map(|entry| entry.error.as_str())
            .unwrap_or(registry.error.as_str());
        u32::try_from(error.len()).unwrap_or(u32::MAX)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_error_copy(
    handle: u64,
    destination: u32,
    capacity: u32,
) -> i32 {
    INSTANCES.with_borrow_mut(|registry| {
        let error = registry
            .entries
            .get(&handle)
            .map(|entry| entry.error.as_bytes())
            .unwrap_or_else(|| registry.error.as_bytes())
            .to_vec();
        let capacity = usize::try_from(capacity).expect("u32 fits usize on wasm32");
        let Some(destination) = registry.buffers.get_mut(&destination) else {
            return INVALID_INPUT;
        };
        if capacity > destination.len() || capacity < error.len() {
            return INVALID_INPUT;
        }
        destination[..error.len()].copy_from_slice(&error);
        i32::try_from(error.len()).unwrap_or(INVALID_INPUT)
    })
}
