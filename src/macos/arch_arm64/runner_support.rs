//! Shared setup helpers for the legacy arm64 no-dyld runner.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::macos::plugin_events::import_event;
use crate::macos::{
    emit_runner_trace_event, io_event, kqueue_event, memory_event, process_event,
    push_recent_trace, runtime_process_metadata, thread_event, AppleRuntime,
    Arm64SyntheticOsRuntime, Arm64ThreadRuntime, Emulator, GuestFileTable, GuestProcessBootstrap,
    SharedTraceBus, StubRegion, SyntheticProcess, TraceEvent, TraceMetadata,
    ARM64_SYNTHETIC_THREAD_STACK_BASE,
};
use crate::UnicornEmulator;

#[derive(Clone, Debug)]
pub struct Arm64ImportTracker {
    pub last_stub: Arc<Mutex<Option<String>>>,
    pub import_count: Arc<AtomicUsize>,
    pub recent_imports: Arc<Mutex<VecDeque<String>>>,
}

#[derive(Clone, Debug)]
pub struct Arm64SharedState {
    pub process_bootstrap: GuestProcessBootstrap,
    pub tls_next_key: Arc<Mutex<u64>>,
    pub tls_values: Arc<Mutex<HashMap<u64, u64>>>,
    pub tlv_next_addr: Arc<Mutex<u64>>,
    pub tlv_storage: Arc<Mutex<HashMap<(u64, u64), u64>>>,
    pub malloc_next_addr: Arc<Mutex<u64>>,
    pub malloc_allocations: Arc<Mutex<HashMap<u64, u64>>>,
    pub dispatch_semaphore_next: Arc<Mutex<u64>>,
    pub dispatch_semaphores: Arc<Mutex<HashMap<u64, i64>>>,
    pub thread_runtime: Arc<Mutex<Arm64ThreadRuntime>>,
    pub os_runtime: Arc<Mutex<Arm64SyntheticOsRuntime>>,
    pub apple_runtime: Arc<Mutex<AppleRuntime>>,
    pub child_trace_budget: Arc<AtomicUsize>,
}

pub fn arm64_metadata(pid: Option<u64>, tid: u64) -> TraceMetadata {
    let metadata = runtime_process_metadata("arm64-guest").tid(tid);
    if let Some(pid) = pid {
        metadata.pid(pid).ppid(1)
    } else {
        metadata
    }
}

pub fn emit_arm64_event(bus: &Option<SharedTraceBus>, event: TraceEvent) {
    emit_runner_trace_event(bus, &TraceMetadata::new(), event);
}

pub fn record_arm64_import(tracker: &Arm64ImportTracker, summary: impl Into<String>) {
    tracker.import_count.fetch_add(1, Ordering::Relaxed);
    push_recent_trace(&tracker.recent_imports, summary.into());
}

pub fn arm64_process_event(
    pid: u64,
    tid: u64,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    process_event(&arm64_metadata(Some(pid), tid), name, call)
}

pub fn arm64_thread_event(
    tid: u64,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    thread_event(&arm64_metadata(None, tid), name, call)
}

pub fn arm64_io_event(pid: u64, tid: u64, call: impl Into<String>) -> TraceEvent {
    io_event(&arm64_metadata(Some(pid), tid), call)
}

pub fn arm64_kqueue_event(pid: u64, tid: u64, call: impl Into<String>) -> TraceEvent {
    kqueue_event(&arm64_metadata(Some(pid), tid), call)
}

pub fn arm64_memory_event(call: impl Into<String>) -> TraceEvent {
    memory_event(&TraceMetadata::new(), call)
}

pub fn initialize_arm64_import_tracker() -> Arm64ImportTracker {
    Arm64ImportTracker {
        last_stub: Arc::new(Mutex::new(None)),
        import_count: Arc::new(AtomicUsize::new(0)),
        recent_imports: Arc::new(Mutex::new(VecDeque::new())),
    }
}

pub fn initialize_arm64_shared_state(
    guest_fs_base: std::path::PathBuf,
    process_bootstrap: GuestProcessBootstrap,
) -> Arm64SharedState {
    let guest_files = GuestFileTable::new(guest_fs_base.clone());
    Arm64SharedState {
        process_bootstrap,
        tls_next_key: Arc::new(Mutex::new(1)),
        tls_values: Arc::new(Mutex::new(HashMap::new())),
        tlv_next_addr: Arc::new(Mutex::new(0x5100_0000)),
        tlv_storage: Arc::new(Mutex::new(HashMap::new())),
        malloc_next_addr: Arc::new(Mutex::new(0x5200_0000)),
        malloc_allocations: Arc::new(Mutex::new(HashMap::new())),
        dispatch_semaphore_next: Arc::new(Mutex::new(0x6D15_0000_0000)),
        dispatch_semaphores: Arc::new(Mutex::new(HashMap::new())),
        thread_runtime: Arc::new(Mutex::new(Arm64ThreadRuntime {
            next_thread_id: 2,
            current_thread_id: 1,
            next_stack_base: ARM64_SYNTHETIC_THREAD_STACK_BASE,
            ..Default::default()
        })),
        os_runtime: Arc::new(Mutex::new(Arm64SyntheticOsRuntime {
            next_process_id: 2,
            next_fd: 0x10_000,
            next_kqueue_fd: 0x20_000,
            guest_fs_base,
            guest_files,
            processes: HashMap::from([(
                1,
                SyntheticProcess {
                    pid: 1,
                    parent_pid: 0,
                    exit_status: 0,
                    running: true,
                    reaped: false,
                    exec_path: None,
                },
            )]),
            thread_processes: HashMap::from([(1, 1)]),
            process_fds: HashMap::from([(1, HashSet::from([0, 1, 2]))]),
            ..Default::default()
        })),
        apple_runtime: Arc::new(Mutex::new(AppleRuntime::default())),
        child_trace_budget: Arc::new(AtomicUsize::new(80)),
    }
}

pub fn install_arm64_return_stubs(
    emulator: &mut UnicornEmulator,
    stub_region: StubRegion,
    undefs: &[(String, u8)],
    tracker: &Arm64ImportTracker,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(HashMap<String, u64>, Arc<HashMap<u64, String>>), Box<dyn std::error::Error>> {
    let arm64_ret0_stub = [0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6];
    let mut stub_addr = stub_region.base;
    let mut stub_map = HashMap::new();
    for (name, _) in undefs {
        while stub_addr == stub_region.done_addr || Some(stub_addr) == stub_region.thread_exit_stub
        {
            stub_addr += 0x100;
        }
        let _ = emulator.write_memory(stub_addr, &arm64_ret0_stub);
        stub_map.insert(name.clone(), stub_addr);
        emit_arm64_event(
            trace_bus,
            process_event(
                &runtime_process_metadata(process_name.to_string()),
                "import-stub",
                "install_import_stub",
            )
            .arg("Symbol", name.clone())
            .arg("StubAddr", format!("0x{:X}", stub_addr)),
        );
        stub_addr += 0x100;
    }

    let stub_name_map = Arc::new(
        stub_map
            .iter()
            .map(|(name, addr)| (*addr, name.clone()))
            .collect::<HashMap<u64, String>>(),
    );
    let last_stub_for_hook = tracker.last_stub.clone();
    let import_count_for_hook = tracker.import_count.clone();
    let recent_imports_for_hook = tracker.recent_imports.clone();
    let stub_name_map_for_hook = stub_name_map.clone();
    let trace_bus_for_hook = trace_bus.clone();
    let process_name_for_hook = process_name.to_string();
    emulator.add_code_hook(
        stub_region.base,
        stub_region.base + stub_region.size,
        move |_emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
            let bucket = stub_region.bucket(address);
            if let Some(name) = stub_name_map_for_hook.get(&bucket) {
                import_count_for_hook.fetch_add(1, Ordering::Relaxed);
                push_recent_trace(
                    &recent_imports_for_hook,
                    format!("{} @ 0x{:X}", name, address),
                );
                emit_arm64_event(
                    &trace_bus_for_hook,
                    import_event(
                        &runtime_process_metadata(process_name_for_hook.clone()),
                        name.clone(),
                        "import-hit",
                    )
                    .arg("Address", format!("0x{:X}", address))
                    .arg("lr", format!("0x{:X}", _emu.read_reg("lr").unwrap())),
                );
                //println!("IMPORT HIT");
                if let Ok(mut slot) = last_stub_for_hook.lock() {
                    *slot = Some(format!("{} @ 0x{:X}", name, address));
                }
            } else {
                emit_arm64_event(
                    &trace_bus_for_hook,
                    process_event(
                        &runtime_process_metadata(process_name_for_hook.clone()),
                        "<unknown>",
                        "import-hit",
                    )
                    .arg("Address", format!("0x{:X}", address))
                    .arg("lr", format!("0x{:X}", _emu.read_reg("lr").unwrap())),
                );
            }
        },
    )?;

    Ok((stub_map, stub_name_map))
}
