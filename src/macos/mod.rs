#[path = "platform_apple/imports.rs"]
pub mod apple_imports;
#[path = "platform_apple/runtime.rs"]
pub mod apple_runtime;
pub mod arch_arm64;
#[path = "arch_arm64/binary_setup.rs"]
pub mod arm64_binary_setup;
#[path = "arch_arm64/bootstrap.rs"]
pub mod arm64_bootstrap;
#[path = "arch_arm64/diagnostics.rs"]
pub mod arm64_diagnostics;
#[path = "arch_arm64/io_imports.rs"]
pub mod arm64_io_imports;
#[path = "arch_arm64/process_imports.rs"]
pub mod arm64_process_imports;
#[path = "arch_arm64/pthread_imports.rs"]
pub mod arm64_pthread_imports;
#[path = "arch_arm64/runner.rs"]
pub mod arm64_runner;
#[path = "arch_arm64/runner_support.rs"]
pub mod arm64_runner_support;
#[path = "arch_arm64/runtime.rs"]
pub mod arm64_runtime;
#[path = "arch_arm64/runtime_hooks.rs"]
pub mod arm64_runtime_hooks;
#[path = "arch_arm64/time_imports.rs"]
pub mod arm64_time_imports;
#[path = "core/binary_bootstrap.rs"]
pub mod binary_bootstrap;
#[path = "core/binary_setup.rs"]
pub mod binary_setup;
#[path = "core/bootstrap.rs"]
pub mod bootstrap;
#[path = "core/capture.rs"]
pub mod capture;
pub mod core;
#[path = "core/diagnostics.rs"]
pub mod diagnostics;
#[path = "core/emulation.rs"]
pub mod emulation;
pub mod events;
#[path = "guest_model/files.rs"]
pub mod guest_files;
#[path = "guest_model/memory.rs"]
pub mod guest_memory;
pub mod guest_model;
pub mod imports;
#[path = "core/io_imports.rs"]
pub mod io_imports;
pub mod loader;
pub mod macho_utils;
pub mod memory_arena;
pub mod os;
pub mod platform_apple;
#[path = "core/plugin_events.rs"]
pub mod plugin_events;
#[path = "core/plugins.rs"]
pub mod plugins;
pub mod policy;
#[path = "core/process_imports.rs"]
pub mod process_imports;
#[path = "core/pthread_imports.rs"]
pub mod pthread_imports;
#[path = "core/runner.rs"]
pub mod runner;
#[path = "core/runner_plugins.rs"]
pub mod runner_plugins;
#[path = "core/runner_support.rs"]
pub mod runner_support;
#[path = "core/runtime.rs"]
pub mod runtime;
#[path = "core/runtime_hooks.rs"]
pub mod runtime_hooks;
#[path = "core/runtime_plugins.rs"]
pub mod runtime_plugins;
pub mod structs;
pub mod stubs;
pub mod syscall;
pub mod syscall_plugins;
#[path = "core/time_imports.rs"]
pub mod time_imports;
#[path = "core/trace.rs"]
pub mod trace;

pub fn debug_stdout_enabled() -> bool {
    std::env::var("MACHINA_DEBUG_STDOUT")
        .ok()
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

pub use apple_runtime::{AppleObject, AppleRuntime};
pub use arm64_runtime::{
    restore_arm64_context, save_arm64_context, wake_arm64_cond_waiters, wake_one_arm64_cond_waiter,
    Arm64SyntheticOsRuntime, Arm64ThreadContext,
};
pub use bootstrap::{setup_arm64_stack_bootstrap, GuestProcessBootstrap};
pub use capture::{
    extract_ascii_indicators, fnv1a64_hex, lossy_data_preview, sanitize_capture_label,
    shannon_entropy, CaptureSummary,
};
pub use emulation::{
    collect_targets, cpu_type_name, ensure_macho_cpu, macho_cputype, run_target_batch,
    targets_from_args, BatchSummary, EmulationOptions, EmulationReport, EmulationStatus, MacosCpu,
    MacosEmulator, CPU_TYPE_ARM64, DEFAULT_SAMPLE_PATH,
};
pub use guest_files::{
    fstat_guest_file as generic_fstat_guest_file, materialize_synthetic_file_bytes,
    open_guest_path as generic_open_guest_path,
    read_guest_directory_entry as generic_read_guest_directory_entry,
    read_guest_file as generic_read_guest_file, resolve_guest_path,
    stat_guest_path as generic_stat_guest_path, GuestDirectoryEntry, GuestFileTable,
    GuestOpenTarget, SyntheticGuestDirectory, SyntheticGuestFile, SyntheticGuestFileKind,
};
pub use guest_memory::{
    align_up, alloc_bytes, alloc_cstr, push_recent_trace, read_arm64_argv, read_cstring,
    stack_push_u32, stack_push_u64,
};
pub use macho_utils::{
    file_backed_slice_for_vmaddr, find_symbol_address, get_dysymtab_cmd, get_symtab_cmd,
    patch_section64_u64_slots, reload_file_backed_range, section32_indirect_symbol_name,
    section_indirect_symbol_name, symbol_name_by_index, trim_name,
};
pub use memory_arena::{setup_guest_memory_arena, GuestMemoryArena, GuestMemoryArenaConfig};
pub use os::{ArchType, Emulator, Heap, LogLevel, MacOsError};
pub use plugin_events::{
    capture_event, detect_event, io_event, kqueue_event, memory_event, process_event,
    syscall_event, thread_event, TraceMetadata,
};
pub use plugins::register_plugins;
pub use runner::{emulate_macos_arm64_binary, emulate_macos_binary};
pub use runner_plugins::{
    emit_event as emit_runner_trace_event, shared_trace_bus_from_env, SharedTraceBus,
};
pub use runtime::{
    bind_process_fd_target, block_active_arm64_thread_on_cond, block_current_arm64_thread_on_cond,
    close_directory_stream, close_synthetic_fd, dispatch_pending_arm64_thread,
    dispatch_pending_arm64_thread_by_id, fstat_guest_file, has_pipe_endpoint_ref,
    open_directory_stream, open_guest_file, read_guest_directory_entry, read_guest_file,
    register_process_fd, resolve_directory_stream_fd, resolve_process_fd_target, restore_context,
    save_context, stat_guest_path, terminate_synthetic_process, wake_cond_waiters,
    wake_one_cond_waiter, yield_active_arm64_thread, ActiveArm64Thread, Arm64ThreadRuntime,
    ForkParentResume, PendingArm64Thread, SyntheticFdTarget, SyntheticKeventRegistration,
    SyntheticOsRuntime, SyntheticPipe, SyntheticProcess, ThreadContext, WaitingArm64Thread,
    ARM64_SYNTHETIC_THREAD_STACK_BASE, ARM64_SYNTHETIC_THREAD_STACK_SIZE, MAX_SYNTHETIC_THREADS,
};
pub use runtime_plugins::{
    install_arm64_runtime_plugins, install_runtime_plugins, runtime_process_metadata,
    Arm64RuntimeContext, Arm64RuntimePlugin, Arm64SyscallRuntimePlugin, RuntimeContext,
    RuntimeContextCore, RuntimePlugin, SyscallRuntimePlugin,
};
pub use structs::{KmodInfo, MacPolicyList, Pointer64};
pub use stubs::{install_stub_region, StubIsa, StubRegion};
pub use syscall_plugins::{
    default_guest_fs_base, default_syscall_name, handle_basic_macos_syscall, SyscallInvocation,
    SyscallOutcome, SyscallRuntimeState,
};
pub use trace::{
    CallTracePlugin, PluginRegistry, StdoutTraceSink, StdoutTracer, TraceCategory, TraceConfig,
    TraceEvent, TraceFormat, TracePlugin, TraceProfile, TraceSink, Tracer, WriterTraceSink,
};
