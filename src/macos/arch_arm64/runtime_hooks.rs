//! Runtime hook installation for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use crate::macos::arm64_runner_support::{
    arm64_process_event, arm64_thread_event, emit_arm64_event, Arm64SharedState,
};
use crate::macos::{
    dispatch_pending_arm64_thread, read_arm64_argv, read_cstring, restore_arm64_context,
    save_arm64_context, SharedTraceBus,
};
use crate::{Emulator, UnicornEmulator};

pub fn install_arm64_runtime_hooks(
    emulator: &mut UnicornEmulator,
    thread_exit_stub: u64,
    done_addr: u64,
    libc_close_trampoline: Option<u64>,
    libc_dup2_trampoline: Option<u64>,
    libc_execve_trampoline: Option<u64>,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let thread_runtime = shared_state.thread_runtime.clone();
    let os_runtime = shared_state.os_runtime.clone();
    let child_trace_budget = shared_state.child_trace_budget.clone();

    {
        let thread_runtime = thread_runtime.clone();
        let os_runtime = os_runtime.clone();
        let child_trace_budget = child_trace_budget.clone();
        emulator.add_code_hook(
            0x10006FDC0,
            0x10007C520,
            move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                if child_trace_budget.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                    return;
                }
                let tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&tid).copied())
                    .unwrap_or(1);
                if pid != 2 {
                    return;
                }
                let remaining =
                    child_trace_budget.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                if remaining == 0 {
                    return;
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let sp = emu.read_reg("sp").unwrap_or(0);
                let x0 = emu.read_reg("x0").unwrap_or(0);
                let x1 = emu.read_reg("x1").unwrap_or(0);
                let x2 = emu.read_reg("x2").unwrap_or(0);
                let x3 = emu.read_reg("x3").unwrap_or(0);
                println!(
                    "[CHILD-TRACE][arm64] pid={} tid={} pc=0x{:X} lr=0x{:X} sp=0x{:X} x0=0x{:X} x1=0x{:X} x2=0x{:X} x3=0x{:X}",
                    pid, tid, address, lr, sp, x0, x1, x2, x3
                );
            },
        )?;
    }

    {
        let thread_runtime = thread_runtime.clone();
        let os_runtime = os_runtime.clone();
        emulator.add_code_hook(
            0x10007C4E4,
            0x10007C4F0,
            move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                let tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&tid).copied())
                    .unwrap_or(1);
                let x0 = emu.read_reg("x0").unwrap_or(0);
                let x1 = emu.read_reg("x1").unwrap_or(0);
                let x2 = emu.read_reg("x2").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                if address == 0x10007C4E4 && x0 == 0 && x2 == 0 && pid > 1 {
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        if let Some(parent_resume) = runtime.fork_parent_resumes.get_mut(&tid) {
                            let mut ctx = save_arm64_context(emu);
                            ctx.x[0] = parent_resume.child_pid;
                            ctx.x[1] = 0;
                            ctx.x[2] = 0;
                            ctx.pc = 0x10007C7C8;
                            parent_resume.context = ctx;
                            println!(
                                "[FORK-RET][arm64] updated parent branch snapshot child_tid={} parent_tid={} child_pid={} pc=0x10007C7C8",
                                tid, parent_resume.parent_tid, parent_resume.child_pid
                            );
                        }
                    }
                }
                println!(
                    "[FORK-RET][arm64] pid={} tid={} pc=0x{:X} x0=0x{:X} x1=0x{:X} x2=0x{:X} lr=0x{:X}",
                    pid, tid, address, x0, x1, x2, lr
                );
            },
        )?;
    }

    {
        let thread_runtime = thread_runtime.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            thread_exit_stub,
            thread_exit_stub + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let child_result = emu.read_reg("x0").unwrap_or(0);
                let mut resumed_parent = false;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if let Some(active) = runtime.active_thread.take() {
                        runtime.current_thread_id = active.parent_thread_id;
                        let _ = restore_arm64_context(
                            emu,
                            &active.parent,
                            child_result,
                            active.parent.lr,
                        );
                        resumed_parent = true;
                    }
                }
                if resumed_parent {
                    println!(
                        "[THREAD][arm64] synthetic thread exit resumes parent with x0=0x{:X}",
                        child_result
                    );
                } else {
                    let _ = emu.write_reg("pc", done_addr);
                }
                let event = arm64_thread_event(0, "thread-exit", "thread_exit_stub")
                    .arg("ChildResult", format!("0x{:X}", child_result))
                    .arg("ResumedParent", resumed_parent.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    {
        let thread_runtime = thread_runtime.clone();
        let os_runtime = os_runtime.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            done_addr,
            done_addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let mut stop_now = false;
                let mut dispatched = false;
                let mut exited_pid = None;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    let pc = emu.read_reg("pc").unwrap_or(0);
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let sp = emu.read_reg("sp").unwrap_or(0);
                    let pid = os_runtime
                        .lock()
                        .ok()
                        .and_then(|os| os.thread_processes.get(&runtime.current_thread_id).copied())
                        .unwrap_or(1);
                    println!(
                        "[THREAD][arm64] reached done_addr current={} pid={} active={} pending={} pc=0x{:X} lr=0x{:X} sp=0x{:X}",
                        runtime.current_thread_id,
                        pid,
                        runtime.active_thread.is_some(),
                        runtime.pending_threads.len(),
                        pc,
                        lr,
                        sp
                    );
                    if runtime.active_thread.is_some() {
                        runtime.active_thread.take();
                    }
                    if let Ok(mut os) = os_runtime.lock() {
                        if let Some(pid) =
                            os.thread_processes.get(&runtime.current_thread_id).copied()
                        {
                            if pid > 1 {
                                if let Some(proc_state) = os.processes.get_mut(&pid) {
                                    proc_state.running = false;
                                    proc_state.exit_status = 0;
                                    exited_pid = Some(pid);
                                }
                            }
                        }
                    }
                    if !runtime.pending_threads.is_empty() {
                        if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                            dispatched = did_dispatch;
                        }
                    } else {
                        stop_now = true;
                    }
                }
                if dispatched {
                    println!("[THREAD][arm64] done_addr dispatches pending synthetic thread");
                } else {
                    if let Some(pid) = exited_pid {
                        println!(
                            "[PROC][arm64] synthetic pid={} reached done_addr and exited",
                            pid
                        );
                    }
                    if stop_now {
                        // Honor the requested stop even when we also marked
                        // a synthetic process as exited. The previous
                        // `else if` chain meant `exited_pid` shadowed
                        // `stop_now`, leaving the runner to keep executing
                        // the dead caller's tail (in RustDoor: a runaway
                        // `waitpid`/`__error` poll after the daemon's
                        // `_exit`).
                        let _ = emu.stop_emulation();
                    }
                }
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(exited_pid.unwrap_or(1));
                let event = arm64_process_event(pid, current_tid, "done-addr", "done_addr")
                    .arg("Dispatched", dispatched.to_string())
                    .arg("StopNow", stop_now.to_string())
                    .arg("ExitedPid", exited_pid.unwrap_or(0).to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(addr) = libc_close_trampoline {
        let os_runtime = os_runtime.clone();
        let thread_runtime = thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&thread_id).copied())
                    .unwrap_or(1);
                if let Ok(mut os) = os_runtime.lock() {
                    os.fd_flags.remove(&fd);
                }
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                println!(
                    "[TRAMPOLINE][arm64] close fd={} pid={} tid={} lr=0x{:X} -> 0",
                    fd, current_pid, thread_id, lr
                );
            },
        )?;
    }

    if let Some(addr) = libc_dup2_trampoline {
        let os_runtime = os_runtime.clone();
        let thread_runtime = thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let oldfd = emu.read_reg("x0").unwrap_or(0);
                let newfd = emu.read_reg("x1").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&thread_id).copied())
                    .unwrap_or(1);
                if let Ok(mut os) = os_runtime.lock() {
                    let inherited_flags = os.fd_flags.get(&oldfd).copied().unwrap_or(0);
                    os.fd_flags.insert(newfd, inherited_flags);
                }
                let _ = emu.write_reg("x0", newfd);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                println!(
                    "[TRAMPOLINE][arm64] dup2 oldfd={} newfd={} pid={} tid={} lr=0x{:X} -> {}",
                    oldfd, newfd, current_pid, thread_id, lr, newfd
                );
            },
        )?;
    }

    if let Some(addr) = libc_execve_trampoline {
        let os_runtime = os_runtime.clone();
        let thread_runtime = thread_runtime.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let argv_ptr = emu.read_reg("x1").unwrap_or(0);
                let envp_ptr = emu.read_reg("x2").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
                let argv = if argv_ptr != 0 {
                    read_arm64_argv(emu, argv_ptr, 16, 256)
                } else {
                    Vec::new()
                };
                let thread_id = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&thread_id).copied())
                    .unwrap_or(1);
                if let Ok(mut os) = os_runtime.lock() {
                    if let Some(proc_state) = os.processes.get_mut(&current_pid) {
                        proc_state.running = false;
                        proc_state.exit_status = 0;
                    }
                }
                let mut dispatched = false;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if runtime
                        .active_thread
                        .as_ref()
                        .map(|active| active.thread_id == thread_id)
                        .unwrap_or(false)
                    {
                        runtime.active_thread.take();
                        if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                            dispatched = did_dispatch;
                        }
                    }
                }
                if !dispatched {
                    let _ = emu.write_reg("x0", 0);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }
                println!(
                    "[TRAMPOLINE][arm64] execve path={:?} argv={:?} envp=0x{:X} pid={} tid={} lr=0x{:X} dispatched={}",
                    path, argv, envp_ptr, current_pid, thread_id, lr, dispatched
                );
            },
        )?;
    }

    Ok(())
}
