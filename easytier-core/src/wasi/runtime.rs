//! Runtime implementation and lifecycle exports for a WASI core instance.

use crate::{
    config::toml::TomlConfig, connectivity::connector_host::HostConnectorEnvironmentSnapshot,
};

pub(super) type WasiCore = crate::instance::CoreInstance<
    crate::connectivity::connector_host::ConnectorHost<
        crate::wasi::adapter::socket::backend::WasiHostSocketBackend,
        crate::host::environment::HostConnectorEnvironmentServiceAdapter<
            crate::wasi::adapter::environment::WasiHostConnectorEnvironmentIo,
        >,
    >,
>;

pub(super) struct WasiCoreRuntime {
    socket_runtime: crate::host::socket::HostSocketRuntime,
    core: std::sync::Arc<WasiCore>,
}

impl WasiCoreRuntime {
    pub(super) fn core(&self) -> &std::sync::Arc<WasiCore> {
        &self.core
    }

    pub(super) fn notify_host_completions(&self) {
        self.socket_runtime.notify_completions();
    }
}

pub(super) fn new_wasi_core_runtime(
    config: TomlConfig,
    process_runtime: std::sync::Arc<crate::process_runtime::CoreProcessRuntime>,
    environment_snapshot: HostConnectorEnvironmentSnapshot,
    packet_sink: crate::host::packet::HostPacketSinkHandle,
) -> anyhow::Result<WasiCoreRuntime> {
    use std::sync::Arc;

    use crate::host::{
        dns::HostDnsResolver, environment::HostConnectorEnvironmentServiceAdapter,
        packet::HostPacketSink, socket::HostSocketRuntime,
    };
    use crate::{
        connectivity::connector_host::new_connector_host,
        instance::{CoreHostAdapters, CoreInstance},
        wasi::adapter::{
            dns::WasiHostDnsIo, environment::WasiHostConnectorEnvironmentIo,
            packet::WasiHostPacketIo, socket::backend::WasiHostSocketBackend,
        },
    };

    let socket_runtime = HostSocketRuntime::new();
    let environment_services = Arc::new(HostConnectorEnvironmentServiceAdapter::new(
        socket_runtime.clone(),
        Arc::new(WasiHostConnectorEnvironmentIo),
    ));
    let host = Arc::new(new_connector_host(
        socket_runtime.clone(),
        Arc::new(WasiHostSocketBackend::default()),
        environment_snapshot,
        environment_services,
    ));
    let dns = Arc::new(HostDnsResolver::new(
        socket_runtime.clone(),
        Arc::new(WasiHostDnsIo),
    ));
    let packet_sink = Arc::new(HostPacketSink::new(
        socket_runtime.clone(),
        Arc::new(WasiHostPacketIo),
        packet_sink,
    ));
    let adapters = CoreHostAdapters::new(host, dns, packet_sink, process_runtime);
    let core = CoreInstance::from_toml(config, adapters)?;

    Ok(WasiCoreRuntime {
        socket_runtime,
        core,
    })
}

mod abi {
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use tokio::{runtime::Builder, task::JoinHandle};

    use crate::{
        config::toml::{ConfigLoader as _, TomlConfig},
        foundation::time::{clear_domain, enter_domain, next_deadline_millis},
        host::packet::HostPacketSinkHandle,
        instance::{
            CoreInstanceState,
            manager::{InstanceFactory, InstanceManager, ManagedInstance},
        },
        process_runtime::{CoreProcessRuntime, ProtectedTcpPortLease},
        wasi::runtime_driver::{RuntimeDriveOutcome, RuntimeDriver},
    };

    use super::{WasiCoreRuntime, new_wasi_core_runtime};
    use crate::wasi::schema::WasiCoreInstanceCreateConfig;

    const MAX_CREATE_CONFIG_LEN: usize = 16 * 1024 * 1024;
    const MAX_GUEST_BUFFER_LEN: usize = MAX_CREATE_CONFIG_LEN;
    const INVALID_HANDLE: i32 = -1;
    const INVALID_STATE: i32 = -2;
    const INVALID_INPUT: i32 = -3;
    const ASYNC_ERROR: i32 = -4;
    const BUSY: i32 = -5;

    struct WasiAbiState {
        next_handle: u64,
        handles: BTreeMap<u64, WasiHandleState>,
        buffers: BTreeMap<u32, Box<[u8]>>,
        active_instance: bool,
        global_error: String,
    }

    struct WasiHandleState {
        instance_id: uuid::Uuid,
        error: String,
    }

    impl Default for WasiAbiState {
        fn default() -> Self {
            Self {
                next_handle: 0,
                handles: BTreeMap::new(),
                buffers: BTreeMap::new(),
                active_instance: false,
                global_error: String::new(),
            }
        }
    }

    struct WasiContext {
        manager: InstanceManager<WasiInstanceFactory>,
        abi: RefCell<WasiAbiState>,
    }

    impl Default for WasiContext {
        fn default() -> Self {
            Self {
                manager: InstanceManager::new(WasiInstanceFactory {
                    process_runtime: CoreProcessRuntime::new(),
                }),
                abi: RefCell::new(WasiAbiState::default()),
            }
        }
    }

    thread_local! {
        static CONTEXT: WasiContext = WasiContext::default();
    }

    struct WasiInstanceFactory {
        process_runtime: std::sync::Arc<CoreProcessRuntime>,
    }

    struct WasiCreateContext {
        domain: u64,
        environment: crate::connectivity::connector_host::HostConnectorEnvironmentSnapshot,
        packet_sink: HostPacketSinkHandle,
    }

    struct WasiInstance {
        instance_id: uuid::Uuid,
        domain: u64,
        core: WasiCoreRuntime,
        execution: Mutex<WasiExecution>,
        _protected_tcp_port_leases: Vec<ProtectedTcpPortLease>,
    }

    struct WasiExecution {
        runtime: tokio::runtime::Runtime,
        runtime_driver: RuntimeDriver,
        drive_again: bool,
        start_task: Option<JoinHandle<anyhow::Result<()>>>,
        stop_task: Option<JoinHandle<()>>,
    }

    impl ManagedInstance for WasiInstance {
        fn instance_id(&self) -> uuid::Uuid {
            self.instance_id
        }
    }

    impl InstanceFactory for WasiInstanceFactory {
        type Instance = WasiInstance;
        type CreateContext = WasiCreateContext;
        type Error = anyhow::Error;

        fn create(
            &self,
            config: TomlConfig,
            context: Self::CreateContext,
        ) -> Result<Arc<Self::Instance>, Self::Error> {
            let instance_id = config.get_id();
            let protected_tcp_ports = context
                .environment
                .protected_tcp_ports
                .iter()
                .copied()
                .map(|port| self.process_runtime.protect_tcp_port(port))
                .collect();
            let runtime_driver = RuntimeDriver::default();
            let park_driver = runtime_driver.clone();
            let runtime = Builder::new_current_thread()
                .enable_time()
                .on_thread_park(move || park_driver.on_thread_park())
                .build()?;
            let core = {
                let _domain = enter_domain(context.domain);
                let _runtime = runtime.enter();
                new_wasi_core_runtime(
                    config,
                    self.process_runtime.clone(),
                    context.environment,
                    context.packet_sink,
                )?
            };

            Ok(Arc::new(WasiInstance {
                instance_id,
                domain: context.domain,
                core,
                execution: Mutex::new(WasiExecution {
                    runtime,
                    runtime_driver,
                    drive_again: false,
                    start_task: None,
                    stop_task: None,
                }),
                _protected_tcp_port_leases: protected_tcp_ports,
            }))
        }
    }

    impl WasiAbiState {
        fn allocate_handle(&mut self) -> Result<u64, i32> {
            if self.active_instance {
                self.set_global_error("core instance lifecycle call is not reentrant");
                return Err(BUSY);
            }
            loop {
                self.next_handle = self.next_handle.wrapping_add(1);
                if self.next_handle != 0 && !self.handles.contains_key(&self.next_handle) {
                    return Ok(self.next_handle);
                }
            }
        }

        fn set_global_error(&mut self, error: impl ToString) {
            self.global_error = error.to_string();
        }

        fn set_handle_error(&mut self, handle: u64, error: impl ToString) {
            if let Some(state) = self.handles.get_mut(&handle) {
                state.error = error.to_string();
            } else {
                self.set_global_error(error);
            }
        }

        fn error_for_handle(&self, handle: u64) -> &str {
            self.handles
                .get(&handle)
                .map(|state| state.error.as_str())
                .unwrap_or(self.global_error.as_str())
        }

        fn begin_instance_call(&mut self, handle: u64) -> Result<uuid::Uuid, i32> {
            if self.active_instance {
                self.set_handle_error(handle, "core instance lifecycle call is not reentrant");
                return Err(BUSY);
            }
            let Some(instance_id) = self.handles.get(&handle).map(|state| state.instance_id) else {
                self.set_global_error(format!("unknown core instance handle: {handle}"));
                return Err(INVALID_HANDLE);
            };
            self.active_instance = true;
            Ok(instance_id)
        }

        fn begin_instance_drop(&mut self, handle: u64) -> Result<uuid::Uuid, i32> {
            self.begin_instance_call(handle)
        }

        fn finish_instance_call(&mut self) {
            debug_assert!(self.active_instance);
            self.active_instance = false;
        }

        fn finish_instance_drop(&mut self, handle: u64) {
            debug_assert!(self.active_instance);
            self.handles.remove(&handle);
            self.active_instance = false;
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

    impl WasiInstance {
        fn start(&self) -> anyhow::Result<()> {
            let mut execution = self.execution.lock().unwrap();
            if execution.start_task.is_some()
                || execution.stop_task.is_some()
                || self.core.core().state() != CoreInstanceState::Created
            {
                anyhow::bail!("core instance cannot schedule start from its current state");
            }
            let instance = self.core.core().clone();
            execution.start_task = Some(
                execution
                    .runtime
                    .spawn(async move { instance.start_managed().await }),
            );
            Ok(())
        }

        fn stop(&self) {
            let mut execution = self.execution.lock().unwrap();
            if execution.stop_task.is_some()
                || self.core.core().state() == CoreInstanceState::Stopped
            {
                return;
            }
            let instance = self.core.core().clone();
            execution.stop_task = Some(execution.runtime.spawn(async move {
                instance.stop().await;
            }));
        }

        fn drive(&self) -> anyhow::Result<()> {
            let _domain = enter_domain(self.domain);
            self.core.notify_host_completions();
            let mut execution = self.execution.lock().unwrap();
            execution.drive_again = execution.runtime_driver.drive(&execution.runtime)
                == RuntimeDriveOutcome::BudgetExhausted;

            if execution
                .start_task
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let task = execution.start_task.take().unwrap();
                match execution.runtime.block_on(task) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(error) => anyhow::bail!("core instance start task failed: {error}"),
                }
            }
            if execution
                .stop_task
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let task = execution.stop_task.take().unwrap();
                if let Err(error) = execution.runtime.block_on(task) {
                    anyhow::bail!("core instance stop task failed: {error}");
                }
            }
            Ok(())
        }

        fn state_code(&self) -> i32 {
            let execution = self.execution.lock().unwrap();
            if execution.stop_task.is_some() {
                return 3;
            }
            if execution.start_task.is_some() {
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

        fn next_wait_millis(&self) -> Option<u64> {
            let execution = self.execution.lock().unwrap();
            if execution.drive_again {
                Some(0)
            } else {
                next_deadline_millis(self.domain)
            }
        }

        fn send_packet(&self, packet: Vec<u8>) {
            let packet_plane = self.core.core().packet_plane();
            self.execution.lock().unwrap().runtime.spawn(async move {
                if let Err(error) = packet_plane.send_ip_packet(packet).await {
                    tracing::warn!(?error, "host packet ingress failed");
                }
            });
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

    fn with_instance(
        handle: u64,
        operation: impl FnOnce(&WasiInstance) -> anyhow::Result<i32>,
    ) -> i32 {
        let instance_id =
            match CONTEXT.with(|context| context.abi.borrow_mut().begin_instance_call(handle)) {
                Ok(instance_id) => instance_id,
                Err(status) => return status,
            };
        let instance = CONTEXT.with(|context| context.manager.get(instance_id));
        let status = match instance {
            Some(instance) => match operation(&instance) {
                Ok(status) => status,
                Err(error) => {
                    CONTEXT.with(|context| {
                        context.abi.borrow_mut().set_handle_error(handle, error);
                    });
                    ASYNC_ERROR
                }
            },
            None => {
                CONTEXT.with(|context| {
                    context.abi.borrow_mut().set_handle_error(
                        handle,
                        format!("core instance {instance_id} is not registered"),
                    );
                });
                INVALID_STATE
            }
        };
        CONTEXT.with(|context| context.abi.borrow_mut().finish_instance_call());
        status
    }

    fn with_abi_state<T>(operation: impl FnOnce(&WasiAbiState) -> T) -> T {
        CONTEXT.with(|context| operation(&context.abi.borrow()))
    }

    fn with_abi_state_mut<T>(operation: impl FnOnce(&mut WasiAbiState) -> T) -> T {
        CONTEXT.with(|context| operation(&mut context.abi.borrow_mut()))
    }

    fn set_abi_error(error: impl ToString) {
        with_abi_state_mut(|state| state.set_global_error(error));
    }

    fn set_instance_error(handle: u64, error: impl ToString) {
        with_abi_state_mut(|state| state.set_handle_error(handle, error));
    }

    fn manager_get(instance_id: uuid::Uuid) -> Option<std::sync::Arc<WasiInstance>> {
        CONTEXT.with(|context| context.manager.get(instance_id))
    }

    fn manager_remove(instance_id: uuid::Uuid) -> Option<std::sync::Arc<WasiInstance>> {
        CONTEXT.with(|context| context.manager.remove(instance_id))
    }

    fn manager_create(
        config: TomlConfig,
        context: WasiCreateContext,
    ) -> Result<
        std::sync::Arc<WasiInstance>,
        crate::instance::manager::InstanceCreateError<anyhow::Error>,
    > {
        CONTEXT.with(|wasi| wasi.manager.create(config, context))
    }

    fn read_guest_buffer(pointer: u32, length: u32, maximum: usize) -> anyhow::Result<Vec<u8>> {
        let length = usize::try_from(length).expect("u32 fits usize on wasm32");
        if pointer == 0 || length == 0 || length > maximum {
            anyhow::bail!("invalid guest buffer reference");
        }
        with_abi_state(|state| state.read_buffer(pointer, length))
    }

    #[unsafe(no_mangle)]
    /// Allocates a guest-owned ABI buffer and returns its linear-memory offset.
    ///
    /// The runtime may write at most `length` bytes through wasm memory, then
    /// pass the pointer to another lifecycle export and eventually free it.
    pub extern "C" fn easytier_buffer_alloc(length: u32) -> u32 {
        let length = usize::try_from(length).expect("u32 fits usize on wasm32");
        if length == 0 || length > MAX_GUEST_BUFFER_LEN {
            set_abi_error("invalid guest buffer length");
            return 0;
        }
        let mut buffer = vec![0_u8; length].into_boxed_slice();
        let pointer = buffer.as_mut_ptr() as u32;
        if pointer == 0 {
            set_abi_error("guest buffer allocation failed");
            return 0;
        }
        with_abi_state_mut(|state| {
            if state.buffers.contains_key(&pointer) {
                state.set_global_error("guest buffer allocation collided with a live buffer");
                0
            } else {
                state.buffers.insert(pointer, buffer);
                pointer
            }
        })
    }

    #[unsafe(no_mangle)]
    /// Releases a buffer previously returned by [`easytier_buffer_alloc`].
    pub extern "C" fn easytier_buffer_free(pointer: u32) -> i32 {
        with_abi_state_mut(|state| {
            if state.buffers.remove(&pointer).is_some() {
                0
            } else {
                state.set_global_error(format!("unknown guest buffer: {pointer}"));
                INVALID_INPUT
            }
        })
    }

    #[unsafe(no_mangle)]
    /// Creates one core instance from a versioned envelope containing TOML.
    ///
    /// `config_pointer` must name a live ABI buffer and `packet_sink_handle`
    /// identifies the host sink used for locally delivered raw IP packets.
    /// Returns zero on failure; retrieve the reason through the error exports.
    pub extern "C" fn easytier_instance_create(
        config_pointer: u32,
        config_length: u32,
        packet_sink_handle: u64,
    ) -> u64 {
        let encoded = match read_guest_buffer(config_pointer, config_length, MAX_CREATE_CONFIG_LEN)
        {
            Ok(encoded) => encoded,
            Err(error) => {
                set_abi_error(error);
                return 0;
            }
        };
        let create_config = match decode_create_config(&encoded) {
            Ok(config) => config,
            Err(error) => {
                set_abi_error(error);
                return 0;
            }
        };
        let config = match create_config.parse_config() {
            Ok(config) => config,
            Err(error) => {
                set_abi_error(error);
                return 0;
            }
        };
        let handle = match with_abi_state_mut(WasiAbiState::allocate_handle) {
            Ok(handle) => handle,
            Err(_) => return 0,
        };
        let instance = manager_create(
            config,
            WasiCreateContext {
                domain: handle,
                environment: create_config.environment,
                packet_sink: HostPacketSinkHandle(packet_sink_handle),
            },
        );
        let instance = match instance {
            Ok(instance) => instance,
            Err(error) => {
                clear_domain(handle);
                set_abi_error(error);
                return 0;
            }
        };

        with_abi_state_mut(|state| {
            let previous = state.handles.insert(
                handle,
                WasiHandleState {
                    instance_id: instance.instance_id(),
                    error: String::new(),
                },
            );
            debug_assert!(previous.is_none());
            handle
        })
    }

    #[unsafe(no_mangle)]
    /// Schedules instance startup. Completion is advanced by subsequent drive calls.
    pub extern "C" fn easytier_instance_start(handle: u64) -> i32 {
        with_instance(handle, |instance| match instance.start() {
            Ok(()) => Ok(0),
            Err(error) => {
                set_instance_error(handle, error);
                Ok(INVALID_STATE)
            }
        })
    }

    #[unsafe(no_mangle)]
    /// Requests graceful instance shutdown. Completion is advanced by drive calls.
    pub extern "C" fn easytier_instance_stop(handle: u64) -> i32 {
        with_instance(handle, |instance| {
            instance.stop();
            Ok(0)
        })
    }

    #[unsafe(no_mangle)]
    /// Runs one bounded turn of the instance's externally driven Tokio runtime.
    ///
    /// The return value is the current lifecycle state code, or a negative ABI
    /// status on failure. Call after a timer deadline or host completion.
    pub extern "C" fn easytier_instance_drive(handle: u64) -> i32 {
        with_instance(handle, |instance| {
            instance.drive()?;
            Ok(instance.state_code())
        })
    }

    #[unsafe(no_mangle)]
    /// Wakes tasks whose host I/O operation may have completed.
    ///
    /// The runtime calls this after finishing one or more `easytier_host`
    /// operations; it does not itself consume a host completion.
    pub extern "C" fn easytier_instance_notify_completions(handle: u64) -> i32 {
        with_instance(handle, |instance| {
            instance.core.notify_host_completions();
            Ok(0)
        })
    }

    #[unsafe(no_mangle)]
    /// Returns the current lifecycle state code without running the instance.
    pub extern "C" fn easytier_instance_state(handle: u64) -> i32 {
        with_instance(handle, |instance| Ok(instance.state_code()))
    }

    /// Returns milliseconds until the next required drive, rounded up. A zero
    /// means lifecycle work remains locally runnable. `i64::MAX` means core is
    /// waiting only for a host completion; negative values are ABI status codes.
    #[unsafe(no_mangle)]
    pub extern "C" fn easytier_instance_next_deadline_millis(handle: u64) -> i64 {
        let instance_id = match with_abi_state_mut(|state| state.begin_instance_call(handle)) {
            Ok(instance_id) => instance_id,
            Err(status) => return i64::from(status),
        };
        let result = match manager_get(instance_id) {
            Some(instance) => instance
                .next_wait_millis()
                .map(|millis| i64::try_from(millis).unwrap_or(i64::MAX))
                .unwrap_or(i64::MAX),
            None => {
                set_instance_error(
                    handle,
                    format!("core instance {instance_id} is not registered"),
                );
                i64::from(INVALID_STATE)
            }
        };
        with_abi_state_mut(WasiAbiState::finish_instance_call);
        result
    }

    #[unsafe(no_mangle)]
    /// Copies a raw IP packet from a guest ABI buffer into EasyTier ingress.
    ///
    /// Packet processing is asynchronous; success only means the ingress task
    /// was scheduled. The caller retains and may free the source buffer once
    /// this function returns.
    pub extern "C" fn easytier_instance_send_packet(
        handle: u64,
        packet_pointer: u32,
        packet_length: u32,
    ) -> i32 {
        with_instance(handle, |instance| {
            let packet = match read_guest_buffer(packet_pointer, packet_length, 1024 * 1024) {
                Ok(packet) => packet,
                Err(error) => {
                    set_instance_error(handle, error);
                    return Ok(INVALID_INPUT);
                }
            };
            instance.send_packet(packet);
            Ok(0)
        })
    }

    #[unsafe(no_mangle)]
    /// Destroys an instance and releases its lifecycle, timer, and runtime state.
    pub extern "C" fn easytier_instance_drop(handle: u64) -> i32 {
        let instance_id = match with_abi_state_mut(|state| state.begin_instance_drop(handle)) {
            Ok(instance_id) => instance_id,
            Err(status) => return status,
        };
        let Some(instance) = manager_remove(instance_id) else {
            set_instance_error(
                handle,
                format!("core instance {instance_id} is not registered"),
            );
            with_abi_state_mut(WasiAbiState::finish_instance_call);
            return INVALID_STATE;
        };
        let domain = instance.domain;
        {
            let _domain = enter_domain(domain);
            drop(instance);
        }
        clear_domain(domain);
        with_abi_state_mut(|state| state.finish_instance_drop(handle));
        0
    }

    #[unsafe(no_mangle)]
    /// Returns the byte length of the most recent lifecycle error for `handle`.
    pub extern "C" fn easytier_instance_error_len(handle: u64) -> u32 {
        with_abi_state(|state| {
            u32::try_from(state.error_for_handle(handle).len()).unwrap_or(u32::MAX)
        })
    }

    #[unsafe(no_mangle)]
    /// Copies the most recent lifecycle error into a caller-owned ABI buffer.
    ///
    /// `capacity` must contain the whole error; on success returns the copied
    /// byte count, otherwise a negative ABI status code.
    pub extern "C" fn easytier_instance_error_copy(
        handle: u64,
        destination: u32,
        capacity: u32,
    ) -> i32 {
        with_abi_state_mut(|state| {
            let error = state.error_for_handle(handle).as_bytes().to_vec();
            let capacity = usize::try_from(capacity).expect("u32 fits usize on wasm32");
            let Some(destination) = state.buffers.get_mut(&destination) else {
                return INVALID_INPUT;
            };
            if capacity > destination.len() || capacity < error.len() {
                return INVALID_INPUT;
            }
            destination[..error.len()].copy_from_slice(&error);
            i32::try_from(error.len()).unwrap_or(INVALID_INPUT)
        })
    }
}
