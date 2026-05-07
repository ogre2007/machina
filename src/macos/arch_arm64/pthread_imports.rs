//! Pthread and TLS-related synthetic imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;

use crate::macos::arm64_runner_support::{
    arm64_metadata, arm64_thread_event, emit_arm64_event, record_arm64_import, Arm64ImportTracker,
    Arm64SharedState,
};
use crate::macos::{
    block_active_arm64_thread_on_cond, block_current_arm64_thread_on_cond,
    dispatch_pending_arm64_thread, thread_event, yield_active_arm64_thread, Emulator,
    PendingArm64Thread, SharedTraceBus, ARM64_SYNTHETIC_THREAD_STACK_SIZE, MAX_SYNTHETIC_THREADS,
};
use crate::UnicornEmulator;

pub fn install_arm64_pthread_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    errno_ptr: u64,
    thread_exit_stub: u64,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(&addr) = stub_map.get("_pthread_get_stackaddr_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let requested_thread = emu.read_reg("x0").unwrap_or(0);
                let (tid, stackaddr) = {
                    let runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    let tid = if requested_thread == 0 {
                        runtime.current_thread_id.max(1)
                    } else {
                        requested_thread
                    };
                    let stackaddr = if tid == 1 {
                        0x8000_0000_0000
                    } else {
                        runtime
                            .next_stack_base
                            .saturating_sub(crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE)
                            .saturating_add(crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE)
                    };
                    (tid, stackaddr)
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", stackaddr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_get_stackaddr_np(thread={}) -> 0x{:X}",
                        tid, stackaddr
                    ),
                );
                let event =
                    arm64_thread_event(tid, "pthread_get_stackaddr_np", "pthread_get_stackaddr_np")
                        .arg("Thread", tid.to_string())
                        .arg("Result", format!("0x{:X}", stackaddr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_get_stacksize_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let requested_thread = emu.read_reg("x0").unwrap_or(0);
                let tid = {
                    let runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if requested_thread == 0 {
                        runtime.current_thread_id.max(1)
                    } else {
                        requested_thread
                    }
                };
                let stacksize = if tid == 1 {
                    0x20_0000
                } else {
                    crate::macos::ARM64_SYNTHETIC_THREAD_STACK_SIZE
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", stacksize);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_get_stacksize_np(thread={}) -> 0x{:X}",
                        tid, stacksize
                    ),
                );
                let event =
                    arm64_thread_event(tid, "pthread_get_stacksize_np", "pthread_get_stacksize_np")
                        .arg("Thread", tid.to_string())
                        .arg("Result", format!("0x{:X}", stacksize));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__tlv_bootstrap") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let tlv_next_addr = shared_state.tlv_next_addr.clone();
        let tlv_storage = shared_state.tlv_storage.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let descriptor = emu.read_reg("x0").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let value_addr = {
                    let mut storage = match tlv_storage.lock() {
                        Ok(storage) => storage,
                        Err(_) => return,
                    };
                    if let Some(existing) = storage.get(&(thread_id, descriptor)).copied() {
                        existing
                    } else {
                        let addr = {
                            let mut next = match tlv_next_addr.lock() {
                                Ok(next) => next,
                                Err(_) => return,
                            };
                            let addr = *next;
                            *next = next.saturating_add(0x1000);
                            addr
                        };
                        let _ = emu.map_data_memory(addr, 0x1000);
                        let _ = emu.write_memory(addr, &[0u8; 16]);
                        storage.insert((thread_id, descriptor), addr);
                        addr
                    }
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x8", value_addr);
                let _ = emu.write_reg("x0", value_addr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "__tlv_bootstrap(desc=0x{:X}, tid={}) -> 0x{:X}",
                        descriptor, thread_id, value_addr
                    ),
                );
                let event = arm64_thread_event(thread_id, "tlv-bootstrap", "__tlv_bootstrap")
                    .arg("Descriptor", format!("0x{:X}", descriptor))
                    .arg("Result", format!("0x{:X}", value_addr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__tlv_atexit") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dtor = emu.read_reg("x0").unwrap_or(0);
                let object = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "__tlv_atexit(dtor=0x{:X}, object=0x{:X}) -> 0",
                        dtor, object
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "tlv-atexit",
                    "__tlv_atexit",
                )
                .arg("Dtor", format!("0x{:X}", dtor))
                .arg("Object", format!("0x{:X}", object));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_key_create") {
        let tls_next_key = shared_state.tls_next_key.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let key_ptr = emu.read_reg("x0").unwrap_or(0);
                let key = {
                    let mut next = tls_next_key.lock().unwrap();
                    let key = *next;
                    *next = next.saturating_add(1);
                    key
                };
                if key_ptr != 0 {
                    let _ = emu.write_memory(key_ptr, &(key as u32).to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_key_create(key_ptr=0x{:X}) -> key={}",
                        key_ptr, key
                    ),
                );
                println!("[IMPORT][arm64] _pthread_key_create -> key={}", key);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("___error") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", errno_ptr);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("___error() -> 0x{:X}", errno_ptr));
                println!("[IMPORT][arm64] ___error -> 0x{:X}", errno_ptr);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_setspecific") {
        let tls_values = shared_state.tls_values.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let key = emu.read_reg("x0").unwrap_or(0);
                let value = emu.read_reg("x1").unwrap_or(0);
                if let Ok(mut map) = tls_values.lock() {
                    map.insert(key, value);
                }
                let tls_base = emu.read_reg("tpidrro_el0").unwrap_or(0);
                if tls_base != 0 {
                    let slot_addr = tls_base.saturating_add(key.saturating_mul(8));
                    let _ = emu.write_memory(slot_addr, &value.to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_setspecific(key={}, value=0x{:X}, tls_slot=0x{:X})",
                        key,
                        value,
                        tls_base.saturating_add(key.saturating_mul(8))
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_setspecific key={} value=0x{:X} tls_slot=0x{:X}",
                    key,
                    value,
                    tls_base.saturating_add(key.saturating_mul(8))
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_getspecific") {
        let tls_values = shared_state.tls_values.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let key = emu.read_reg("x0").unwrap_or(0);
                let value = tls_values
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&key).copied())
                    .unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", value);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_pthread_getspecific(key={}) -> 0x{:X}", key, value),
                );
                println!(
                    "[IMPORT][arm64] _pthread_getspecific key={} -> 0x{:X}",
                    key, value
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_self") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", thread_id);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("_pthread_self() -> {}", thread_id));
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-self",
                    "pthread_self",
                )
                .arg("ThreadId", thread_id.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_setname_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let name_ptr = emu.read_reg("x0").unwrap_or(0);
                let name = if name_ptr != 0 {
                    crate::macos::read_cstring(emu, name_ptr, 256).unwrap_or_default()
                } else {
                    String::new()
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_setname_np(tid={}, name={:?}) -> 0",
                        thread_id, name
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-setname",
                    "pthread_setname_np",
                )
                .arg("ThreadId", thread_id.to_string())
                .arg("Name", name);
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_create") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let next_handle = shared_state.dispatch_semaphore_next.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let initial = emu.read_reg("x0").unwrap_or(0) as i64;
                let handle = {
                    let mut next = match next_handle.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let handle = *next;
                    *next = next.saturating_add(0x100);
                    handle
                };
                if let Ok(mut map) = semaphores.lock() {
                    map.insert(handle, initial);
                }
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", handle);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_create(value={}) -> 0x{:X}",
                        initial, handle
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-create",
                    "dispatch_semaphore_create",
                )
                .arg("Initial", initial.to_string())
                .arg("Handle", format!("0x{:X}", handle));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_signal") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let value = {
                    let mut map = match semaphores.lock() {
                        Ok(map) => map,
                        Err(_) => return,
                    };
                    let slot = map.entry(handle).or_insert(0);
                    *slot = slot.saturating_add(1);
                    *slot
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_signal(handle=0x{:X}) -> {}",
                        handle, value
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-signal",
                    "dispatch_semaphore_signal",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Value", value.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_semaphore_wait") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let timeout = emu.read_reg("x1").unwrap_or(0);
                let (value, result) = {
                    let mut map = match semaphores.lock() {
                        Ok(map) => map,
                        Err(_) => return,
                    };
                    let slot = map.entry(handle).or_insert(0);
                    if *slot > 0 {
                        *slot -= 1;
                        (*slot, 0u64)
                    } else {
                        (*slot, 0u64)
                    }
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_semaphore_wait(handle=0x{:X}, timeout=0x{:X}) -> {} value={}",
                        handle, timeout, result, value
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-semaphore-wait",
                    "dispatch_semaphore_wait",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Timeout", format!("0x{:X}", timeout))
                .arg("Result", result.to_string())
                .arg("Value", value.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dispatch_release") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let semaphores = shared_state.dispatch_semaphores.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let handle = emu.read_reg("x0").unwrap_or(0);
                let existed = semaphores
                    .lock()
                    .ok()
                    .and_then(|mut map| map.remove(&handle))
                    .is_some();
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dispatch_release(handle=0x{:X}) -> existed={}",
                        handle, existed
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "dispatch-release",
                    "dispatch_release",
                )
                .arg("Handle", format!("0x{:X}", handle))
                .arg("Existed", existed.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_create") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let thread_ptr = emu.read_reg("x0").unwrap_or(0);
                let _attr = emu.read_reg("x1").unwrap_or(0);
                let start_routine = emu.read_reg("x2").unwrap_or(0);
                let arg = emu.read_reg("x3").unwrap_or(0);
                let parent_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let parent_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&parent_tid).copied())
                    .unwrap_or(1);

                let (result, thread_id) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if runtime.next_thread_id > MAX_SYNTHETIC_THREADS + 1 {
                        (11u64, 0u64)
                    } else {
                        let thread_id = runtime.next_thread_id;
                        runtime.next_thread_id = runtime.next_thread_id.saturating_add(1);
                        let stack_base = runtime.next_stack_base;
                        runtime.next_stack_base = runtime
                            .next_stack_base
                            .saturating_add(ARM64_SYNTHETIC_THREAD_STACK_SIZE);
                        let _ = emu.map_data_memory(stack_base, ARM64_SYNTHETIC_THREAD_STACK_SIZE);
                        runtime.pending_threads.push_back(PendingArm64Thread {
                            thread_id,
                            entry: start_routine,
                            arg,
                            stack_top: stack_base + ARM64_SYNTHETIC_THREAD_STACK_SIZE - 0x100,
                            exit_pc: thread_exit_stub,
                            resume: None,
                        });
                        (0u64, thread_id)
                    }
                };
                if result == 0 {
                    if let Ok(mut os) = os_runtime.lock() {
                        os.process_thread_ids.insert(thread_id);
                        os.thread_processes.insert(thread_id, parent_pid);
                    }
                }

                if result == 0 && thread_ptr != 0 {
                    let _ = emu.write_memory(thread_ptr, &thread_id.to_le_bytes());
                }

                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }

                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_create(thread_ptr=0x{:X}, start=0x{:X}, arg=0x{:X}) -> {}",
                        thread_ptr, start_routine, arg, result
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(Some(parent_pid), parent_tid),
                    "pthread-create",
                    "pthread_create",
                )
                .arg("ThreadPtr", format!("0x{:X}", thread_ptr))
                .arg("StartRoutine", format!("0x{:X}", start_routine))
                .arg("Arg", format!("0x{:X}", arg))
                .arg("Result", result.to_string())
                .arg("ChildTid", thread_id.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_init") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let attr = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        rt.mutex_owners.remove(&mutex);
                        rt.current_thread_id.max(1)
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_init(mutex=0x{:X}, attr=0x{:X}, tid={}) -> 0",
                        mutex, attr, thread_id
                    ),
                );

                println!(
                    "[IMPORT][arm64] _pthread_mutex_init mutex=0x{:X} attr=0x{:X} tid={} -> 0",
                    mutex, attr, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_lock") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, owner_before) = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        let owner = rt.mutex_owners.get(&mutex).copied().unwrap_or(0);
                        rt.mutex_owners.insert(mutex, tid);
                        (tid, owner)
                    })
                    .unwrap_or((1, 0));
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_lock(mutex=0x{:X}, tid={}, prev_owner={}) -> 0",
                        mutex, thread_id, owner_before
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_mutex_lock mutex=0x{:X} tid={} prev_owner={} -> 0",
                    mutex, thread_id, owner_before
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_mutex_unlock") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let mutex = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, owner_before) = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        let owner = rt.mutex_owners.remove(&mutex).unwrap_or(0);
                        (tid, owner)
                    })
                    .unwrap_or((1, 0));
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_mutex_unlock(mutex=0x{:X}, tid={}, prev_owner={}) -> 0",
                        mutex, thread_id, owner_before
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_mutex_unlock mutex=0x{:X} tid={} prev_owner={} -> 0",
                    mutex, thread_id, owner_before
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_init") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let attr = emu.read_reg("x1").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        rt.cond_signal_counts.remove(&cond);
                        rt.cond_waiters.remove(&cond);
                        rt.current_thread_id.max(1)
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_init(cond=0x{:X}, attr=0x{:X}, tid={}) -> 0",
                        cond, attr, thread_id
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_init cond=0x{:X} attr=0x{:X} tid={} -> 0",
                    cond, attr, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_wait") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let mutex = emu.read_reg("x1").unwrap_or(0);
                let mut dispatched = false;
                let mut synthetic_wake = false;
                let mut consumed_signal = false;
                let mut blocked_to = None;
                let mut blocked_current = false;
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if let Some(count) = runtime.cond_signal_counts.get_mut(&cond) {
                        if *count > 0 {
                            *count -= 1;
                            consumed_signal = true;
                            runtime.mutex_owners.insert(mutex, thread_id);
                        }
                    }
                    if consumed_signal {
                        runtime.cond_wait_streaks.remove(&(cond, mutex));
                    } else {
                        runtime.mutex_owners.remove(&mutex);
                    }
                    if !consumed_signal
                        && runtime.active_thread.is_none()
                        && !runtime.pending_threads.is_empty()
                    {
                        if let Ok(did_block) = block_current_arm64_thread_on_cond(
                            emu,
                            &mut runtime,
                            cond,
                            mutex,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            blocked_current = did_block;
                        }
                    }
                    if blocked_current {
                        dispatched = true;
                    }
                    if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                        if !blocked_current
                            && did_dispatch
                            && runtime.active_thread.as_ref().map(|a| a.thread_id)
                                != Some(thread_id)
                        {
                            dispatched = true;
                        }
                    }
                    if !consumed_signal
                        && !dispatched
                        && runtime.active_thread.is_some()
                        && !runtime.pending_threads.is_empty()
                    {
                        if let Ok(result) = block_active_arm64_thread_on_cond(
                            emu,
                            &mut runtime,
                            cond,
                            mutex,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            blocked_to = result;
                        }
                    }
                    if !consumed_signal && !dispatched && blocked_to.is_none() {
                        let streak = runtime
                            .cond_wait_streaks
                            .entry((cond, mutex))
                            .and_modify(|v| *v = v.saturating_add(1))
                            .or_insert(1);
                        if *streak >= 8 {
                            *streak = 0;
                            synthetic_wake = true;
                        }
                    }
                }
                if dispatched {
                    println!(
                        "[THREAD][arm64] dispatch from pthread_cond_wait cond=0x{:X} mutex=0x{:X}",
                        cond, mutex
                    );
                    return;
                }
                if let Some((from_tid, to_tid)) = blocked_to {
                    println!(
                        "[THREAD][arm64] cond_wait block tid={} -> tid={} cond=0x{:X} mutex=0x{:X}",
                        from_tid, to_tid, cond, mutex
                    );
                    return;
                }

                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_wait(cond=0x{:X}, mutex=0x{:X}, tid={}, signal={}) -> wake={}",
                        cond,
                        mutex,
                        thread_id,
                        consumed_signal,
                        synthetic_wake || consumed_signal
                    ),
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-cond-wait",
                    "pthread_cond_wait",
                )
                    .arg("Cond", format!("0x{:X}", cond))
                    .arg("Mutex", format!("0x{:X}", mutex))
                    .arg("Signal", consumed_signal.to_string())
                    .arg("Wake", (synthetic_wake || consumed_signal).to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_timedwait_relative_np") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let mutex = emu.read_reg("x1").unwrap_or(0);
                let abstime = emu.read_reg("x2").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|mut rt| {
                        let tid = rt.current_thread_id.max(1);
                        let signaled = rt
                            .cond_signal_counts
                            .get_mut(&cond)
                            .map(|count| {
                                if *count > 0 {
                                    *count -= 1;
                                    true
                                } else {
                                    false
                                }
                            })
                            .unwrap_or(false);
                        if signaled {
                            rt.mutex_owners.insert(mutex, tid);
                        }
                        tid
                    })
                    .unwrap_or(1);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_timedwait_relative_np(cond=0x{:X}, mutex=0x{:X}, abstime=0x{:X}, tid={}) -> 0",
                        cond, mutex, abstime, thread_id
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_timedwait_relative_np cond=0x{:X} mutex=0x{:X} abstime=0x{:X} tid={} -> 0",
                    cond, mutex, abstime, thread_id
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pthread_cond_signal") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let cond = emu.read_reg("x0").unwrap_or(0);
                let (thread_id, pending_signals) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    let tid = runtime.current_thread_id.max(1);
                    let waiter = {
                        let waiters = runtime.cond_waiters.get_mut(&cond);
                        waiters.and_then(|queue| queue.pop_front())
                    };
                    let pending = if let Some(waiter) = waiter {
                        runtime.mutex_owners.insert(waiter.mutex, waiter.thread_id);
                        runtime.pending_threads.push_front(waiter.pending);
                        runtime
                            .cond_waiters
                            .get(&cond)
                            .map(|queue| queue.len() as u32)
                            .unwrap_or(0)
                    } else {
                        let signals = runtime
                            .cond_signal_counts
                            .entry(cond)
                            .and_modify(|count| *count = count.saturating_add(1))
                            .or_insert(1);
                        *signals
                    };
                    (tid, pending)
                };
                let mut yielded_to = None;
                {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if runtime.active_thread.is_some() && !runtime.pending_threads.is_empty() {
                        if let Ok(result) = yield_active_arm64_thread(
                            emu,
                            &mut runtime,
                            0,
                            emu.read_reg("lr").unwrap_or(0),
                        ) {
                            yielded_to = result;
                        }
                    }
                }
                if let Some((from_tid, to_tid)) = yielded_to {
                    println!(
                        "[THREAD][arm64] signal yield tid={} -> tid={} cond=0x{:X}",
                        from_tid, to_tid, cond
                    );
                    return;
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pthread_cond_signal(cond=0x{:X}, tid={}, pending_signals={}) -> 0",
                        cond, thread_id, pending_signals
                    ),
                );
                println!(
                    "[IMPORT][arm64] _pthread_cond_signal cond=0x{:X} tid={} pending_signals={} -> 0",
                    cond, thread_id, pending_signals
                );
                let event = thread_event(
                    &arm64_metadata(None, thread_id),
                    "pthread-cond-signal",
                    "pthread_cond_signal",
                )
                    .arg("Cond", format!("0x{:X}", cond))
                    .arg("PendingSignals", pending_signals.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    Ok(())
}
