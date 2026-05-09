//! Process lifecycle imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::macos::arm64_runner_support::{
    arm64_process_event, emit_arm64_event, record_arm64_import, Arm64ImportTracker,
    Arm64SharedState,
};
use crate::macos::{
    close_synthetic_fd, dispatch_pending_arm64_thread, dispatch_pending_arm64_thread_by_id,
    read_arm64_argv, read_cstring, resolve_process_fd_target, restore_arm64_context,
    save_arm64_context, terminate_synthetic_process, ActiveArm64Thread, Emulator, ForkParentResume,
    PendingArm64Thread, SharedTraceBus, SyntheticFdTarget, SyntheticProcess, MAX_SYNTHETIC_THREADS,
};
use crate::UnicornEmulator;

fn vec_u64_le(bytes: Vec<u8>) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn extract_log_stream_event_messages(predicate: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut rest = predicate;
    while let Some(idx) = rest.find("eventMessage contains") {
        rest = &rest[idx + "eventMessage contains".len()..];
        let Some(start) = rest.find('"') else {
            break;
        };
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        messages.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    messages
}

fn synthetic_log_stream_messages(path: &str, argv: &[String]) -> Vec<String> {
    if path != "log" || !argv.iter().any(|arg| arg == "stream") {
        return Vec::new();
    }
    let mut messages = argv
        .iter()
        .flat_map(|arg| extract_log_stream_event_messages(arg))
        .collect::<Vec<_>>();
    messages.sort();
    messages.dedup();
    messages
}

fn synthetic_log_stream_output(messages: &[String]) -> Vec<u8> {
    let mut output =
        "Timestamp                       Thread     Type        Activity             PID    TTL  \n"
            .as_bytes()
            .to_vec();
    for message in messages {
        output.extend_from_slice(
            format!(
                "2026-05-08 20:00:00.000000+0300 0x000000   Info        0x0                  0      0    {}\n",
                message
            )
            .as_bytes(),
        );
    }
    output
}

fn install_posix_spawn_hook(
    emulator: &mut UnicornEmulator,
    addr: u64,
    call_name: &'static str,
    errno_ptr: u64,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let os_runtime = shared_state.os_runtime.clone();
    let posix_spawn_file_actions = shared_state.posix_spawn_file_actions.clone();
    let thread_runtime = shared_state.thread_runtime.clone();
    let import_tracker = import_tracker.clone();
    let trace_bus_for_hook = trace_bus.clone();
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let pid_ptr = emu.read_reg("x0").unwrap_or(0);
            let path_ptr = emu.read_reg("x1").unwrap_or(0);
            let file_actions_ptr = emu.read_reg("x2").unwrap_or(0);
            let attr_ptr = emu.read_reg("x3").unwrap_or(0);
            let argv_ptr = emu.read_reg("x4").unwrap_or(0);
            let envp_ptr = emu.read_reg("x5").unwrap_or(0);
            let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
            let argv = if argv_ptr != 0 {
                read_arm64_argv(emu, argv_ptr, 16, 256)
            } else {
                Vec::new()
            };
            let file_actions = posix_spawn_file_actions
                .lock()
                .ok()
                .and_then(|actions| actions.get(&file_actions_ptr).cloned())
                .unwrap_or_default();
            let log_stream_messages = synthetic_log_stream_messages(&path, &argv);
            let synthesize_log_stream = !log_stream_messages.is_empty();
            let current_tid = thread_runtime
                .lock()
                .ok()
                .map(|rt| rt.current_thread_id.max(1))
                .unwrap_or(1);
            let current_pid = os_runtime
                .lock()
                .ok()
                .and_then(|os| os.thread_processes.get(&current_tid).copied())
                .unwrap_or(1);
            let (child_pid, result, errno) = {
                let mut os = match os_runtime.lock() {
                    Ok(os) => os,
                    Err(_) => return,
                };
                let pid = os.next_process_id.max(2);
                os.next_process_id = pid.saturating_add(1);
                os.processes.insert(
                    pid,
                    SyntheticProcess {
                        pid,
                        parent_pid: current_pid,
                        exit_status: 0,
                        running: false,
                        reaped: false,
                        exec_path: Some(path.clone()),
                    },
                );
                if synthesize_log_stream {
                    let output = synthetic_log_stream_output(&log_stream_messages);
                    for (fd, newfd) in &file_actions {
                        if *newfd != 1 && *newfd != 2 {
                            continue;
                        }
                        if let Some(SyntheticFdTarget::PipeWrite(pipe_id)) =
                            resolve_process_fd_target(&os, current_pid, *fd)
                        {
                            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                                pipe.buffer.extend(output.iter().copied());
                                pipe.write_open = false;
                            }
                        }
                    }
                }
                (pid, 0u64, 0u32)
            };
            if pid_ptr != 0 {
                let _ = emu.write_memory(pid_ptr, &(child_pid as u32).to_le_bytes());
            }
            let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
            record_arm64_import(
                &import_tracker,
                format!(
                    "{}(pid=0x{:X}, path={:?}, argv={:?}, file_actions=0x{:X}, dup2={:?}, attr=0x{:X}, envp=0x{:X}) -> result={} child_pid={} synthetic_log_stream={}",
                    call_name, pid_ptr, path, argv, file_actions_ptr, file_actions, attr_ptr, envp_ptr, result, child_pid, synthesize_log_stream
                ),
            );
            let event = arm64_process_event(current_pid, current_tid, call_name, call_name)
                .arg("PidPtr", format!("0x{:X}", pid_ptr))
                .arg("ChildPid", child_pid.to_string())
                .arg("Path", path)
                .arg("Argv", format!("{:?}", argv))
                .arg("FileActions", format!("0x{:X}", file_actions_ptr))
                .arg("Dup2", format!("{:?}", file_actions))
                .arg("Attr", format!("0x{:X}", attr_ptr))
                .arg("Envp", format!("0x{:X}", envp_ptr))
                .arg("SyntheticLogStream", synthesize_log_stream.to_string())
                .arg("SyntheticLogMessages", format!("{:?}", log_stream_messages))
                .arg("Errno", errno.to_string())
                .arg("Result", result.to_string());
            emit_arm64_event(&trace_bus_for_hook, event);
        },
    )?;
    Ok(())
}

fn install_posix_spawn_file_action_hooks(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_init") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.insert(actions_ptr, Vec::new());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_init(actions=0x{:X}) -> 0",
                        actions_ptr
                    ),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_adddup2") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                let fd = emu.read_reg("x1").unwrap_or(0);
                let newfd = emu.read_reg("x2").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.entry(actions_ptr).or_default().push((fd, newfd));
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_adddup2(actions=0x{:X}, fd={}, newfd={}) -> 0",
                        actions_ptr, fd, newfd
                    ),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn_file_actions_destroy") {
        let actions = shared_state.posix_spawn_file_actions.clone();
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let actions_ptr = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut actions) = actions.lock() {
                    actions.remove(&actions_ptr);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_posix_spawn_file_actions_destroy(actions=0x{:X}) -> 0",
                        actions_ptr
                    ),
                );
            },
        )?;
    }

    Ok(())
}

pub fn install_arm64_process_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    done_addr: u64,
    errno_ptr: u64,
    trace_bus: &Option<SharedTraceBus>,
    saw_exit: &Arc<AtomicBool>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    install_posix_spawn_file_action_hooks(emulator, stub_map, shared_state, import_tracker)?;

    if let Some(&addr) = stub_map.get("_fork") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let lr = emu.read_reg("lr").unwrap_or(0);
                let parent_ctx = save_arm64_context(emu);
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

                let (child_pid, child_tid, spawned) = {
                    let mut runtime = match thread_runtime.lock() {
                        Ok(rt) => rt,
                        Err(_) => return,
                    };
                    if runtime.next_thread_id > MAX_SYNTHETIC_THREADS + 1 {
                        (u64::MAX, 0u64, false)
                    } else {
                        let child_tid = runtime.next_thread_id;
                        runtime.next_thread_id = runtime.next_thread_id.saturating_add(1);
                        let mut child_ctx = parent_ctx.clone();
                        child_ctx.x[0] = 0;
                        child_ctx.x[1] = 0;
                        child_ctx.x[2] = 0;
                        child_ctx.pc = lr;
                        runtime.pending_threads.push_front(PendingArm64Thread {
                            thread_id: child_tid,
                            entry: 0,
                            arg: 0,
                            stack_top: child_ctx.sp,
                            exit_pc: done_addr,
                            resume: Some(child_ctx),
                        });
                        let child_pid = {
                            let mut os = match os_runtime.lock() {
                                Ok(os) => os,
                                Err(_) => return,
                            };
                            let pid = os.next_process_id.max(2);
                            os.next_process_id = pid.saturating_add(1);
                            os.processes.insert(
                                pid,
                                SyntheticProcess {
                                    pid,
                                    parent_pid,
                                    exit_status: 0,
                                    running: true,
                                    reaped: false,
                                    exec_path: None,
                                },
                            );
                            os.process_thread_ids.insert(child_tid);
                            os.thread_processes.insert(child_tid, pid);
                            pid
                        };
                        let raw_syscall_frame = emu
                            .read_memory(parent_ctx.sp.saturating_add(8), 8)
                            .ok()
                            .and_then(vec_u64_le)
                            .map(|arg_frame| arg_frame.saturating_sub(0x18))
                            .unwrap_or(parent_ctx.sp);
                        let raw_syscall_resume_pc = 0x10006A5F4;
                        let mut parent_resume_ctx = parent_ctx.clone();
                        parent_resume_ctx.x[0] = child_pid;
                        parent_resume_ctx.x[1] = 0;
                        parent_resume_ctx.x[2] = 0;
                        parent_resume_ctx.sp = raw_syscall_frame;
                        parent_resume_ctx.fp = raw_syscall_frame.saturating_add(0x88);
                        parent_resume_ctx.pc = raw_syscall_resume_pc;
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x38),
                            &child_pid.to_le_bytes(),
                        );
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x40),
                            &0u64.to_le_bytes(),
                        );
                        let _ = emu.write_memory(
                            raw_syscall_frame.saturating_add(0x48),
                            &0u64.to_le_bytes(),
                        );
                        runtime.fork_parent_resumes.insert(
                            child_tid,
                            ForkParentResume {
                                parent_tid,
                                child_pid,
                                context: parent_resume_ctx,
                            },
                        );
                        println!(
                            "[PROC][arm64] fork parent resume snapshot child_tid={} parent_tid={} child_pid={} pc=0x{:X} raw_sp=0x{:X}",
                            child_tid, parent_tid, child_pid, raw_syscall_resume_pc, raw_syscall_frame
                        );
                        (child_pid, child_tid, true)
                    }
                };

                let mut yielded_to = None;
                if spawned {
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        if runtime.active_thread.is_some() && !runtime.pending_threads.is_empty() {
                            runtime.active_thread.take();
                            if let Ok(true) =
                                dispatch_pending_arm64_thread_by_id(emu, &mut runtime, child_tid)
                            {
                                yielded_to = Some((parent_tid, child_tid));
                            }
                        } else if runtime.active_thread.is_none() && !runtime.pending_threads.is_empty()
                        {
                            if let Ok(true) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                                yielded_to = Some((parent_tid, child_tid));
                            }
                        }
                    }
                } else {
                    let _ = emu.write_reg("x0", u64::MAX);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }

                if yielded_to.is_none() {
                    let _ = emu.write_reg("x0", child_pid);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_fork(parent_tid={}, parent_pid={}) -> pid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X}",
                        parent_tid, parent_pid, child_pid, child_tid, lr, parent_ctx.lr
                    ),
                );
                if let Some((from_tid, to_tid)) = yielded_to {
                    println!(
                        "[PROC][arm64] _fork parent_pid={} child_pid={} parent_tid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X} parent_sp=0x{:X} yield {}->{}",
                        parent_pid, child_pid, parent_tid, child_tid, lr, parent_ctx.lr, parent_ctx.sp, from_tid, to_tid
                    );
                } else {
                    println!(
                        "[PROC][arm64] _fork parent_pid={} child_pid={} parent_tid={} child_tid={} resume_pc=0x{:X} parent_lr=0x{:X} parent_sp=0x{:X}",
                        parent_pid, child_pid, parent_tid, child_tid, lr, parent_ctx.lr, parent_ctx.sp
                    );
                }
                let event = arm64_process_event(parent_pid, parent_tid, "fork", "fork")
                    .arg("ChildPid", child_pid.to_string())
                    .arg("ChildTid", child_tid.to_string())
                    .arg("Spawned", spawned.to_string())
                    .arg("ResumePc", format!("0x{:X}", lr))
                    .arg("ParentLr", format!("0x{:X}", parent_ctx.lr))
                    .arg("ParentSp", format!("0x{:X}", parent_ctx.sp));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawn") {
        install_posix_spawn_hook(
            emulator,
            addr,
            "posix_spawn",
            errno_ptr,
            trace_bus,
            shared_state,
            import_tracker,
        )?;
    }

    if let Some(&addr) = stub_map.get("_posix_spawnp") {
        install_posix_spawn_hook(
            emulator,
            addr,
            "posix_spawnp",
            errno_ptr,
            trace_bus,
            shared_state,
            import_tracker,
        )?;
    }

    for (sym, call_label, has_rusage) in
        [("_wait4", "wait4", true), ("_waitpid", "waitpid", false)]
    {
        let Some(&addr) = stub_map.get(sym) else {
            continue;
        };
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let pid_arg = emu.read_reg("x0").unwrap_or(0);
                let status_ptr = emu.read_reg("x1").unwrap_or(0);
                let options = emu.read_reg("x2").unwrap_or(0);
                let rusage_ptr = if has_rusage {
                    emu.read_reg("x3").unwrap_or(0)
                } else {
                    0
                };
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                // WNOHANG (option bit 1) means the caller is polling. Once
                // we've delivered the synthetic exit for a child the caller
                // typically loops again expecting -1/ECHILD; otherwise the
                // RustDoor daemon (and many shells) spin in a tight WNOHANG
                // poll burning the entire instruction budget.
                let wnohang = options & 1 != 0;
                let (result, status_value, errno) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let found = os.processes.iter_mut().find(|(pid, proc_state)| {
                        if **pid == 1 || proc_state.parent_pid != current_pid || proc_state.reaped {
                            return false;
                        }
                        if pid_arg > 0 && **pid != pid_arg {
                            return false;
                        }
                        !proc_state.running
                    });
                    if let Some((pid, proc_state)) = found {
                        proc_state.reaped = true;
                        (*pid, (proc_state.exit_status as u32) << 8, 0u32)
                    } else {
                        let has_child = os.processes.iter().any(|(pid, proc_state)| {
                            *pid != 1
                                && proc_state.parent_pid == current_pid
                                && (pid_arg == 0 || *pid == pid_arg)
                                && !proc_state.reaped
                        });
                        if has_child && !wnohang {
                            (0u64, 0u32, 0u32)
                        } else {
                            // Either no children or WNOHANG with no
                            // dead child to reap. Report ECHILD so
                            // poll loops can advance instead of spinning.
                            (u64::MAX, 0u32, 10u32)
                        }
                    }
                };
                if status_ptr != 0 && result != u64::MAX {
                    let _ = emu.write_memory(status_ptr, &status_value.to_le_bytes());
                }
                if rusage_ptr != 0 {
                    let _ = emu.write_memory(rusage_ptr, &[0u8; 32]);
                }
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "{sym}(pid={pid_arg}, status=0x{status_ptr:X}, options=0x{options:X}) -> pid={result} status=0x{status_value:X} errno={errno}"
                    ),
                );
                println!(
                    "[PROC][arm64] {sym} pid={pid_arg} status=0x{status_ptr:X} options=0x{options:X} rusage=0x{rusage_ptr:X} current_pid={current_pid} -> pid={result} status=0x{status_value:X} errno={errno}"
                );
                let event = arm64_process_event(current_pid, current_tid, call_label, call_label)
                    .arg("TargetPid", pid_arg.to_string())
                    .arg("ResultPid", result.to_string())
                    .arg("StatusPtr", format!("0x{:X}", status_ptr))
                    .arg("StatusValue", status_value.to_string())
                    .arg("Options", format!("0x{:X}", options))
                    .arg("RusagePtr", format!("0x{:X}", rusage_ptr))
                    .arg("Wnohang", wnohang.to_string())
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_execve") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let argv_ptr = emu.read_reg("x1").unwrap_or(0);
                let envp_ptr = emu.read_reg("x2").unwrap_or(0);
                let path = read_cstring(emu, path_ptr, 1024).unwrap_or_default();
                let argv = if argv_ptr != 0 {
                    read_arm64_argv(emu, argv_ptr, 16, 256)
                } else {
                    Vec::new()
                };
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                let mut stdin_capture_info = None;
                if let Ok(mut os) = os_runtime.lock() {
                    if let Some(proc_state) = os.processes.get_mut(&current_pid) {
                        proc_state.exec_path = Some(path.clone());
                    }
                    if let Some(SyntheticFdTarget::PipeRead(pipe_id)) =
                        resolve_process_fd_target(&os, current_pid, 0)
                    {
                        if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                            pipe.capture_label = Some(format!("pid={} {} {:?}", current_pid, path, argv));
                            pipe.capture_consumer_pid = Some(current_pid);
                            stdin_capture_info = Some((pipe_id, pipe.read_fd, pipe.write_fd));
                        }
                    }
                    let close_on_exec_fds = os
                        .process_fds
                        .get(&current_pid)
                        .map(|fds| {
                            fds.iter()
                                .copied()
                                .filter(|fd| *fd > 2 && os.fd_flags.get(fd).copied().unwrap_or(0) & 1 != 0)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    for fd in close_on_exec_fds {
                        let _ = close_synthetic_fd(&mut os, current_pid, fd);
                    }
                    terminate_synthetic_process(&mut os, current_pid, 0);
                }

                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_execve(path={:?}, argv={:?}, envp=0x{:X}) [pid={}, tid={}]",
                        path, argv, envp_ptr, current_pid, current_tid
                    ),
                );
                println!(
                    "[PROC][arm64] _execve pid={} tid={} path={:?} argv={:?} envp=0x{:X}",
                    current_pid, current_tid, path, argv, envp_ptr
                );
                if let Some((pipe_id, read_fd, write_fd)) = stdin_capture_info {
                    println!(
                        "[CAPTURE][arm64] process-stdin armed pid={} path={:?} pipe_id={} read_fd={} write_fd={}",
                        current_pid, path, pipe_id, read_fd, write_fd
                    );
                }

                let mut dispatched = false;
                let mut resumed_parent_tid = None;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if runtime
                        .active_thread
                        .as_ref()
                        .map(|active| active.thread_id == current_tid)
                        .unwrap_or(false)
                    {
                        runtime.active_thread.take();
                        if let Some(parent_resume) = runtime.fork_parent_resumes.get(&current_tid).cloned() {
                            runtime.pending_threads.retain(|thread| thread.thread_id != parent_resume.parent_tid);
                            runtime.current_thread_id = parent_resume.parent_tid;
                            runtime.active_thread = Some(ActiveArm64Thread {
                                thread_id: parent_resume.parent_tid,
                                parent_thread_id: current_tid,
                                parent: save_arm64_context(emu),
                            });
                            if restore_arm64_context(
                                emu,
                                &parent_resume.context,
                                parent_resume.child_pid,
                                parent_resume.context.pc,
                            )
                            .is_ok()
                            {
                                let restored_pc = emu.read_reg("pc").unwrap_or(0);
                                let restored_sp = emu.read_reg("sp").unwrap_or(0);
                                let restored_x0 = emu.read_reg("x0").unwrap_or(0);
                                let restored_x2 = emu.read_reg("x2").unwrap_or(0);
                                println!(
                                    "[PROC][arm64] fork parent context restored tid={} pc=0x{:X} sp=0x{:X} x0=0x{:X} x2=0x{:X}",
                                    parent_resume.parent_tid, restored_pc, restored_sp, restored_x0, restored_x2
                                );
                                dispatched = true;
                                resumed_parent_tid = Some(parent_resume.parent_tid);
                            }
                        }
                        if !dispatched {
                            if let Ok(did_dispatch) = dispatch_pending_arm64_thread(emu, &mut runtime) {
                                dispatched = did_dispatch;
                            }
                        }
                    }
                }
                if dispatched {
                    if let Some(parent_tid) = resumed_parent_tid {
                        println!(
                            "[PROC][arm64] execve consumed synthetic child pid={} tid={} and resumed fork parent tid={}",
                            current_pid, current_tid, parent_tid
                        );
                    } else {
                        println!(
                            "[PROC][arm64] execve consumed synthetic child pid={} and dispatched next thread",
                            current_pid
                        );
                    }
                } else {
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let _ = emu.write_reg("x0", 0);
                    if lr != 0 {
                        let _ = emu.write_reg("pc", lr);
                    }
                }
                let event = arm64_process_event(current_pid, current_tid, "execve", "execve")
                    .arg("Path", path)
                    .arg("Argv", format!("{:?}", argv))
                    .arg("Envp", format!("0x{:X}", envp_ptr))
                    .arg("Dispatched", dispatched.to_string())
                    .arg(
                        "ResumedParentTid",
                        resumed_parent_tid.unwrap_or(0).to_string(),
                    );
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    // Hook both `__exit` (the BSD `_exit(2)` syscall wrapper, symbol prefix
    // `_` + name `_exit`) and `_exit` (the C library `exit(3)` that runs
    // atexit handlers and tail-calls `_exit(2)`, symbol prefix `_` + name
    // `exit`). Without an `_exit` hook the post-fork parent in RustDoor
    // never terminates and instead falls through into a `waitpid`-WNOHANG
    // poll loop that consumes the entire timeout budget without ever
    // reaching the actual command-execution stage.
    for sym in ["__exit", "_exit"] {
        let Some(&addr) = stub_map.get(sym) else {
            continue;
        };
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let saw_exit_import = saw_exit.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let code = emu.read_reg("x0").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let sp = emu.read_reg("sp").unwrap_or(0);
                let caller_lr = if sp != 0 {
                    emu.read_memory(sp, 8).ok().and_then(vec_u64_le).unwrap_or(0)
                } else {
                    0
                };
                let _lr_code = emu.read_memory(lr.saturating_sub(8), 24).unwrap_or_default();
                let current_tid = thread_runtime
                    .lock()
                    .ok()
                    .map(|rt| rt.current_thread_id.max(1))
                    .unwrap_or(1);
                let current_pid = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| os.thread_processes.get(&current_tid).copied())
                    .unwrap_or(1);
                if code == 253 && lr == 0x10006FDEC {
                    let mut dispatched_parent = false;
                    let mut dispatched_tid = 0;
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        let resume_tid = runtime
                            .pending_threads
                            .iter()
                            .find(|thread| {
                                thread.resume.as_ref().map(|ctx| ctx.pc == 0x10006A5F4).unwrap_or(false)
                            })
                            .map(|thread| thread.thread_id);
                        if let Some(resume_tid) = resume_tid {
                            runtime.active_thread.take();
                            if let Ok(did_dispatch) =
                                dispatch_pending_arm64_thread_by_id(emu, &mut runtime, resume_tid)
                            {
                                dispatched_parent = did_dispatch;
                                dispatched_tid = resume_tid;
                            }
                        }
                    }
                    if dispatched_parent {
                        record_arm64_import(
                            &import_tracker,
                            format!("__exit(code=253, tid={}) suppressed post-exec child tail", current_tid),
                        );
                        println!(
                            "[PROC][arm64] suppressed impossible post-exec child __exit(253) tid={} -> dispatched fork parent tid={}",
                            current_tid, dispatched_tid
                        );
                        return;
                    }
                }
                saw_exit_import.store(true, std::sync::atomic::Ordering::Relaxed);
                let has_other_threads = {
                    let runtime = thread_runtime.lock().ok();
                    let os = os_runtime.lock().ok();
                    if let (Some(runtime), Some(os)) = (runtime.as_ref(), os.as_ref()) {
                        let pending_match = runtime.pending_threads.iter().any(|thread| {
                            thread.thread_id != current_tid
                                && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                        });
                        let active_match = runtime
                            .active_thread
                            .as_ref()
                            .map(|thread| {
                                thread.thread_id != current_tid
                                    && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                            })
                            .unwrap_or(false);
                        let waiting_match = runtime.cond_waiters.values().any(|queue| {
                            queue.iter().any(|thread| {
                                thread.thread_id != current_tid
                                    && os.thread_processes.get(&thread.thread_id).copied() == Some(current_pid)
                            })
                        });
                        pending_match || active_match || waiting_match
                    } else {
                        false
                    }
                };
                if let Ok(mut os) = os_runtime.lock() {
                    if has_other_threads {
                        os.thread_processes.remove(&current_tid);
                        os.process_thread_ids.remove(&current_tid);
                    } else {
                        terminate_synthetic_process(&mut os, current_pid, code as i32);
                    }
                }
                let mut dispatched = false;
                if let Ok(mut runtime) = thread_runtime.lock() {
                    if runtime
                        .active_thread
                        .as_ref()
                        .map(|active| active.thread_id == current_tid)
                        .unwrap_or(false)
                    {
                        runtime.active_thread.take();
                        if let Ok(did_dispatch) =
                            dispatch_pending_arm64_thread(emu, &mut runtime)
                        {
                            dispatched = did_dispatch;
                        }
                    }
                }
                if !dispatched {
                    // The exiting thread was the last live thread we can
                    // schedule. The pre-existing behavior fell through to
                    // `pc = lr`, which left the now-dead caller's
                    // instructions as the active execution path — for the
                    // RustDoor daemon that meant a runaway
                    // `waitpid`/`__error` poll loop after `_exit` consumed
                    // the entire timeout budget. Park PC at done_addr so
                    // the runner stops cleanly with a real `post_exit`
                    // status instead of executing the dead caller's tail.
                    let _ = emu.write_reg("pc", done_addr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "{sym}(code={code}, pid={current_pid}, tid={current_tid}, lr=0x{lr:X}, caller=0x{caller_lr:X})"
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "exit", sym)
                    .arg("Code", code.to_string())
                    .arg("HasOtherThreads", has_other_threads.to_string())
                    .arg("Dispatched", dispatched.to_string())
                    .arg("Lr", format!("0x{:X}", lr))
                    .arg("CallerLr", format!("0x{:X}", caller_lr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    Ok(())
}
