//! Legacy arm64 Mach-O runner used by the no-dyld binary entrypoint.

use crate::macos::apple_imports::install_apple_imports;
use crate::macos::binary_bootstrap::{map_binary_segments, setup_bootstrap_state};
use crate::macos::binary_setup::{
    find_runtime_symbols, install_arm64_indirect_branch_hooks, install_arm64_lse_atomic_hooks,
    log_runtime_symbols, patch_symbol_pointers, resolve_entry,
};
use crate::macos::diagnostics::{install_diagnostic_hooks, run_with_diagnostics, RunReport};
use crate::macos::io_imports::install_io_imports;
use crate::macos::process_imports::install_process_imports;
use crate::macos::pthread_imports::install_pthread_imports;
use crate::macos::runner_support::{
    initialize_import_tracker, initialize_shared_state, install_return_stubs,
};
use crate::macos::runtime_hooks::install_runtime_hooks;
use crate::macos::time_imports::install_time_imports;
use crate::macos::{
    default_guest_fs_base, ensure_macho_cpu, install_runtime_plugins, process_event,
    shared_trace_bus_from_env, MacosCpu, RuntimeContext, SyscallRuntimePlugin, TraceMetadata,
};
use crate::{ArchType, Emulator, MachoBinary, UnicornEmulator};

pub fn emulate_macos_arm64_binary(binary_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let raw_data = std::fs::read(binary_path)?;
    let binary = MachoBinary::parse(&raw_data)?;
    let process_name = "main";
    let trace_bus = shared_trace_bus_from_env();
    let metadata = TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name);
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "binary-load", "binary-load")
                .arg("Path", binary_path.to_string())
                .arg("Size", raw_data.len().to_string()),
        );
    }

    if let Some(dyld_path) = binary.get_dyld_path() {
        if let Some(bus) = &trace_bus {
            let _ = bus.send(process_event(&metadata, "dyld", "dyld").arg("Path", dyld_path));
        }
    }
    for lib in binary.get_dylib_paths() {
        if let Some(bus) = &trace_bus {
            let _ = bus.send(process_event(&metadata, "load_dylib", "load_dylib").arg("Path", lib));
        }
    }

    let cputype = ensure_macho_cpu(&binary, MacosCpu::Arm64)
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "cpu-detect", "cpu-detect")
                .arg("CpuType", format!("0x{:X}", cputype))
                .arg("CpuName", "arm64"),
        );
    }

    let mut emulator = UnicornEmulator::new(ArchType::Arm64)?;
    emulator.set_automap_low_page(true);
    let _ = emulator.install_unmapped_memory_debug_hook(&trace_bus);

    let stack_base: u64 = 0x7FFF_FFFC_0000;
    let stack_size: u64 = 0x40000;
    emulator.map_code_memory(stack_base, stack_size)?;
    let sp = (stack_base + stack_size - 16) & !0xF;
    emulator.write_reg("sp", sp)?;

    let max_addr = map_binary_segments(&mut emulator, &binary, &trace_bus, process_name)?;
    let bootstrap_state = setup_bootstrap_state(
        &mut emulator,
        &binary,
        binary_path,
        max_addr,
        sp,
        &trace_bus,
        process_name,
    )?;
    let heap_base = bootstrap_state.heap_base;
    let mmap_base = bootstrap_state.mmap_base;
    let mmap_end = bootstrap_state.mmap_end;
    let mmap_next = bootstrap_state.mmap_next.clone();
    let errno_ptr = bootstrap_state.errno_ptr;
    let stub_region = bootstrap_state.stub_region;
    let process_bootstrap = bootstrap_state.process_bootstrap;
    let stub_base = stub_region.base;
    let stub_size = stub_region.size;
    let done_addr = stub_region.done_addr;
    let thread_exit_stub = stub_region.thread_exit_stub.unwrap_or(done_addr);

    let undefs = binary.get_undefined_symbols();
    if let Some(bus) = &trace_bus {
        let preview = undefs
            .iter()
            .take(10)
            .map(|(name, n_type)| format!("{name}:0x{n_type:X}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = bus.send(
            process_event(&metadata, "undefined-symbols", "undefined-symbols")
                .arg("Count", undefs.len().to_string())
                .arg("Preview", preview),
        );
    }

    let import_tracker = initialize_import_tracker();
    let (stub_map, _stub_name_map) = install_return_stubs(
        &mut emulator,
        stub_region,
        &undefs,
        &import_tracker,
        &trace_bus,
        &process_name,
    )?;
    let last_stub = import_tracker.last_stub.clone();
    let import_count = import_tracker.import_count.clone();
    let recent_imports = import_tracker.recent_imports.clone();

    let shared_state = initialize_shared_state(
        default_guest_fs_base(std::path::Path::new(binary_path), "arm64_ios"),
        process_bootstrap,
    );
    let usleep_streaks = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        (u64, u64),
        u32,
    >::new()));
    let saw_exit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime_symbols = find_runtime_symbols(&binary);
    log_runtime_symbols(runtime_symbols, &trace_bus, &process_name);

    install_runtime_hooks(
        &mut emulator,
        thread_exit_stub,
        done_addr,
        runtime_symbols.libc_close_trampoline,
        runtime_symbols.libc_dup2_trampoline,
        runtime_symbols.libc_execve_trampoline,
        &trace_bus,
        &shared_state,
    )?;

    install_pthread_imports(
        &mut emulator,
        &stub_map,
        errno_ptr,
        thread_exit_stub,
        &trace_bus,
        &shared_state,
        &import_tracker,
    )?;

    install_time_imports(
        &mut emulator,
        &stub_map,
        &shared_state,
        &import_tracker,
        &usleep_streaks,
    )?;

    install_apple_imports(
        &mut emulator,
        &stub_map,
        &trace_bus,
        &shared_state,
        &import_tracker,
        &process_name,
    )?;

    install_io_imports(
        &mut emulator,
        &stub_map,
        errno_ptr,
        mmap_end,
        &mmap_next,
        &trace_bus,
        &shared_state,
        &import_tracker,
    )?;

    install_process_imports(
        &mut emulator,
        &stub_map,
        done_addr,
        errno_ptr,
        &trace_bus,
        &saw_exit,
        &shared_state,
        &import_tracker,
    )?;
    patch_symbol_pointers(
        &mut emulator,
        &binary,
        &undefs,
        &stub_map,
        done_addr,
        &trace_bus,
        &process_name,
    )?;
    install_arm64_lse_atomic_hooks(&mut emulator, &binary, &trace_bus, process_name)?;
    install_arm64_indirect_branch_hooks(&mut emulator, &binary, &trace_bus, process_name)?;

    let runtime_context = RuntimeContext::new(
        process_name,
        binary_path,
        done_addr,
        heap_base,
        mmap_base,
        mmap_end,
        mmap_next.clone(),
        saw_exit.clone(),
        trace_bus.clone(),
    );
    let syscall_count = runtime_context.core.runtime.syscall_count.clone();
    install_runtime_plugins(&mut emulator, &runtime_context, &[&SyscallRuntimePlugin])?;

    let actual_entry = resolve_entry(&binary);
    if let Some(bus) = &trace_bus {
        let _ = bus.send(
            process_event(&metadata, "entry", "entry")
                .arg("Pc", format!("0x{:X}", actual_entry))
                .arg("DoneAddr", format!("0x{:X}", done_addr)),
        );
    }
    emulator.write_reg("pc", actual_entry)?;
    emulator.write_reg("lr", done_addr)?;

    install_diagnostic_hooks(
        &mut emulator,
        &binary,
        runtime_symbols.firstmoduledata,
        actual_entry,
        done_addr,
        &trace_bus,
        process_name,
    )?;

    let result = run_with_diagnostics(
        &mut emulator,
        RunReport {
            actual_entry,
            done_addr,
            stack_base,
            stack_size,
            stub_base,
            stub_size,
            saw_exit,
            syscall_count,
            import_count,
            last_stub,
            recent_imports,
            trace_bus: trace_bus.clone(),
            process_name: process_name.to_string(),
        },
    );

    if let Some(bus) = &trace_bus {
        let recent_preview = import_tracker
            .recent_imports
            .lock()
            .ok()
            .map(|items| items.iter().cloned().collect::<Vec<_>>().join(" | "))
            .unwrap_or_default();
        let _ = bus.send(
            process_event(&metadata, "trace-summary", "trace-summary")
                .arg(
                    "Syscalls",
                    runtime_context
                        .core
                        .runtime
                        .syscall_count
                        .load(std::sync::atomic::Ordering::Relaxed)
                        .to_string(),
                )
                .arg(
                    "Imports",
                    import_tracker
                        .import_count
                        .load(std::sync::atomic::Ordering::Relaxed)
                        .to_string(),
                )
                .arg("RecentImports", recent_preview),
        );
    }

    result
}
