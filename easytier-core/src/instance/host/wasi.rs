//! Serialized lifecycle ABI for a Go-driven WASI core instance.

use std::{cell::RefCell, collections::BTreeMap, slice};

use tokio::{runtime::Builder, task::JoinHandle};

use crate::{
    instance::{CoreInstanceState, host::HostCoreInstanceCreateConfig},
    socket::host::packet::HostPacketSinkHandle,
};

use super::{WasiHostCoreInstance, new_wasi_host_core_instance};

const MAX_CREATE_CONFIG_LEN: usize = 16 * 1024 * 1024;
const INVALID_HANDLE: i32 = -1;
const INVALID_INPUT: i32 = -3;
const ASYNC_ERROR: i32 = -4;

thread_local! {
    static INSTANCES: RefCell<WasiInstanceRegistry> = RefCell::new(WasiInstanceRegistry::default());
}

#[derive(Default)]
struct WasiInstanceRegistry {
    next_handle: u64,
    entries: BTreeMap<u64, WasiInstanceEntry>,
    error: String,
}

struct WasiInstanceEntry {
    runtime: tokio::runtime::Runtime,
    instance: WasiHostCoreInstance,
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
}

impl WasiInstanceEntry {
    fn start(&mut self) -> anyhow::Result<()> {
        if self.start_task.is_some()
            || self.instance.instance().state() != CoreInstanceState::Created
        {
            anyhow::bail!("core instance cannot schedule start from its current state");
        }
        let instance = self.instance.instance().clone();
        self.start_task = Some(self.runtime.spawn(async move {
            instance.start().await?;
            if let Err(error) = instance.start_network_services(None).await {
                instance.stop().await;
                return Err(error);
            }
            Ok(())
        }));
        Ok(())
    }

    fn stop(&mut self) {
        if self.stop_task.is_some()
            || self.instance.instance().state() == CoreInstanceState::Stopped
        {
            return;
        }
        let instance = self.instance.instance().clone();
        self.stop_task = Some(self.runtime.spawn(async move {
            instance.stop().await;
        }));
    }

    fn drive(&mut self) -> anyhow::Result<()> {
        self.instance.notify_host_completions();
        self.runtime
            .block_on(async { tokio::task::yield_now().await });

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
        match self.instance.instance().state() {
            CoreInstanceState::Created => 0,
            CoreInstanceState::Starting => 1,
            CoreInstanceState::Running => 2,
            CoreInstanceState::Stopping => 3,
            CoreInstanceState::Stopped => 4,
        }
    }
}

fn decode_create_config(pointer: u32, length: u32) -> anyhow::Result<HostCoreInstanceCreateConfig> {
    let length = usize::try_from(length).expect("u32 fits usize on wasm32");
    if pointer == 0 || length == 0 || length > MAX_CREATE_CONFIG_LEN {
        anyhow::bail!("invalid host core instance config buffer");
    }
    let encoded = unsafe { slice::from_raw_parts(pointer as *const u8, length) };
    let config: HostCoreInstanceCreateConfig = serde_json::from_slice(encoded)?;
    config.validate()?;
    Ok(config)
}

fn with_entry(
    handle: u64,
    operation: impl FnOnce(&mut WasiInstanceEntry) -> anyhow::Result<i32>,
) -> i32 {
    INSTANCES.with_borrow_mut(|registry| {
        let Some(entry) = registry.entries.get_mut(&handle) else {
            registry.set_error(format!("unknown core instance handle: {handle}"));
            return INVALID_HANDLE;
        };
        match operation(entry) {
            Ok(status) => status,
            Err(error) => {
                entry.error = error.to_string();
                ASYNC_ERROR
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_create(
    config_pointer: u32,
    config_length: u32,
    packet_sink_handle: u64,
) -> u64 {
    let config = match decode_create_config(config_pointer, config_length) {
        Ok(config) => config,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };
    let runtime = match Builder::new_current_thread().enable_time().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };
    let instance = {
        let _runtime = runtime.enter();
        new_wasi_host_core_instance(
            config.instance,
            config.environment,
            HostPacketSinkHandle(packet_sink_handle),
        )
    };
    let instance = match instance {
        Ok(instance) => instance,
        Err(error) => {
            INSTANCES.with_borrow_mut(|registry| registry.set_error(error));
            return 0;
        }
    };

    INSTANCES.with_borrow_mut(|registry| {
        let handle = registry.allocate_handle();
        registry.entries.insert(
            handle,
            WasiInstanceEntry {
                runtime,
                instance,
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
    with_entry(handle, |entry| {
        entry.start()?;
        Ok(0)
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
        entry.drive()?;
        Ok(entry.state_code())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_notify_completions(handle: u64) -> i32 {
    with_entry(handle, |entry| {
        entry.instance.notify_host_completions();
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_state(handle: u64) -> i32 {
    with_entry(handle, |entry| Ok(entry.state_code()))
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_send_packet(
    handle: u64,
    packet_pointer: u32,
    packet_length: u32,
) -> i32 {
    with_entry(handle, |entry| {
        let length = usize::try_from(packet_length).expect("u32 fits usize on wasm32");
        if packet_pointer == 0 || length == 0 || length > 1024 * 1024 {
            return Ok(INVALID_INPUT);
        }
        let packet = unsafe { slice::from_raw_parts(packet_pointer as *const u8, length) }.to_vec();
        let instance = entry.instance.instance().clone();
        entry.runtime.spawn(async move {
            if let Err(error) = instance.send_ip_packet(packet).await {
                tracing::warn!(?error, "host packet ingress failed");
            }
        });
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_instance_drop(handle: u64) -> i32 {
    INSTANCES.with_borrow_mut(|registry| {
        if registry.entries.remove(&handle).is_none() {
            registry.set_error(format!("unknown core instance handle: {handle}"));
            INVALID_HANDLE
        } else {
            0
        }
    })
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
    INSTANCES.with_borrow(|registry| {
        let error = registry
            .entries
            .get(&handle)
            .map(|entry| entry.error.as_bytes())
            .unwrap_or_else(|| registry.error.as_bytes());
        let capacity = usize::try_from(capacity).expect("u32 fits usize on wasm32");
        if destination == 0 || capacity < error.len() {
            return INVALID_INPUT;
        }
        let destination = unsafe { slice::from_raw_parts_mut(destination as *mut u8, error.len()) };
        destination.copy_from_slice(error);
        i32::try_from(error.len()).unwrap_or(INVALID_INPUT)
    })
}
