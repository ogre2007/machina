//! File descriptor, kqueue, and memory-map related imports for the legacy arm64 runner.

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::macos::arm64_runner_support::{
    arm64_io_event, arm64_kqueue_event, arm64_memory_event, arm64_process_event, emit_arm64_event,
    record_arm64_import, Arm64ImportTracker, Arm64SharedState,
};
use crate::macos::{
    align_up, bind_process_fd_target, close_directory_stream, close_synthetic_fd,
    extract_ascii_indicators, fnv1a64_hex, fstat_guest_file, lossy_data_preview,
    open_directory_stream, open_guest_file, read_guest_directory_entry, read_guest_file,
    register_process_fd, resolve_directory_stream_fd, resolve_guest_path,
    resolve_process_fd_target, sanitize_capture_label, shannon_entropy, stat_guest_path,
    terminate_synthetic_process, Emulator, PendingArm64Thread, SharedTraceBus, SyntheticFdTarget,
    SyntheticKeventRegistration, SyntheticPipe,
};
use crate::UnicornEmulator;

fn vec_u64_le(bytes: Vec<u8>) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn read_cstring(emu: &mut dyn Emulator, addr: u64, max_len: usize) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    for i in 0..max_len {
        let Ok(bytes) = emu.read_memory(addr + i as u64, 1) else {
            break;
        };
        let Some(&byte) = bytes.first() else {
            break;
        };
        if byte == 0 {
            break;
        }
        out.push(byte);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_env_value_ptr(
    emu: &mut dyn Emulator,
    envp_addr: u64,
    name: &str,
    max_entries: usize,
) -> u64 {
    if envp_addr == 0 || name.is_empty() || name.contains('=') {
        return 0;
    }
    for index in 0..max_entries {
        let ptr_addr = envp_addr + (index as u64 * 8);
        let Ok(raw_ptr) = emu.read_memory(ptr_addr, 8) else {
            break;
        };
        let Some(env_addr) = vec_u64_le(raw_ptr) else {
            break;
        };
        if env_addr == 0 {
            break;
        }
        let entry = read_cstring(emu, env_addr, 512);
        let Some((entry_name, value)) = entry.split_once('=') else {
            continue;
        };
        if entry_name == name {
            return env_addr + entry_name.len() as u64 + 1;
        }
        if value.is_empty() {
            continue;
        }
    }
    0
}

fn write_fake_stat(emu: &mut dyn Emulator, buf: u64, size: u64) {
    const STAT_SIZE: usize = 128;
    if buf == 0 {
        return;
    }
    let mut out = vec![0u8; STAT_SIZE];
    out[48..56].copy_from_slice(&size.to_le_bytes());
    let _ = emu.write_memory(buf, &out);
}

fn write_fake_dirent(
    emu: &mut dyn Emulator,
    entry_buf: u64,
    cookie: u64,
    name: &str,
    is_dir: bool,
) {
    const DIRENT_SIZE: usize = 1048;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    if entry_buf == 0 {
        return;
    }
    let mut out = vec![0u8; DIRENT_SIZE];
    let name_bytes = name.as_bytes();
    let max_name_len = DIRENT_SIZE.saturating_sub(21 + 1);
    let copy_len = name_bytes.len().min(max_name_len);
    let reclen = (21 + copy_len + 1) as u16;
    out[0..8].copy_from_slice(&cookie.to_le_bytes());
    out[8..16].copy_from_slice(&cookie.to_le_bytes());
    out[16..18].copy_from_slice(&reclen.to_le_bytes());
    out[18..20].copy_from_slice(&(copy_len as u16).to_le_bytes());
    out[20] = if is_dir { DT_DIR } else { DT_REG };
    out[21..21 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    let _ = emu.write_memory(entry_buf, &out);
}

fn fcntl_cmd_name(cmd: u64) -> &'static str {
    match cmd {
        1 => "F_GETFD",
        2 => "F_SETFD",
        3 => "F_GETFL",
        4 => "F_SETFL",
        67 => "F_DUPFD_CLOEXEC",
        _ => "UNKNOWN",
    }
}

fn sysconf_name(name: u64) -> &'static str {
    match name {
        29 => "_SC_PAGESIZE",
        30 => "_SC_PAGE_SIZE",
        57 => "_SC_NPROCESSORS_CONF",
        58 => "_SC_NPROCESSORS_ONLN",
        _ => "UNKNOWN",
    }
}

pub fn install_arm64_io_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    errno_ptr: u64,
    mmap_end: u64,
    mmap_next: &Arc<AtomicU64>,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let malloc_allocations = shared_state.malloc_allocations.clone();
    let malloc_next_addr = shared_state.malloc_next_addr.clone();
    let process_bootstrap = shared_state.process_bootstrap;

    if let Some(&addr) = stub_map.get("_kqueue") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
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
                let kq_fd = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let kq_fd = os.next_kqueue_fd.max(0x20_000);
                    os.next_kqueue_fd = kq_fd.saturating_add(1);
                    os.kqueues.entry(kq_fd).or_default();
                    register_process_fd(&mut os, current_pid, kq_fd);
                    kq_fd
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", kq_fd);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_kqueue(pid={}, tid={}) -> {}",
                        current_pid, current_tid, kq_fd
                    ),
                );
                let event = arm64_kqueue_event(current_pid, current_tid, "kqueue")
                    .arg("KqueueFd", kq_fd.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_kevent") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                const EV_ADD: u16 = 0x0001;
                const EV_DELETE: u16 = 0x0002;
                const EV_ENABLE: u16 = 0x0004;
                const EV_DISABLE: u16 = 0x0008;
                const EV_EOF: u16 = 0x8000;
                const EVFILT_READ: i16 = -1;
                const EVFILT_WRITE: i16 = -2;

                let kq_fd = emu.read_reg("x0").unwrap_or(0);
                let changelist = emu.read_reg("x1").unwrap_or(0);
                let nchanges = emu.read_reg("x2").unwrap_or(0);
                let eventlist = emu.read_reg("x3").unwrap_or(0);
                let nevents = emu.read_reg("x4").unwrap_or(0);
                let timeout_ptr = emu.read_reg("x5").unwrap_or(0);
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
                let mut change_summaries = Vec::new();
                let mut registration_debug = Vec::new();
                let ready_events = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let registrations_snapshot = {
                        let registrations = os.kqueues.entry(kq_fd).or_default();
                        for idx in 0..nchanges {
                            let entry_addr = changelist + (idx as u64).saturating_mul(32);
                            let entry = emu.read_memory(entry_addr, 32).unwrap_or_default();
                            if entry.len() < 32 {
                                continue;
                            }
                            let ident =
                                u64::from_le_bytes(entry[0..8].try_into().unwrap_or([0; 8]));
                            let filter =
                                i16::from_le_bytes(entry[8..10].try_into().unwrap_or([0; 2]));
                            let flags =
                                u16::from_le_bytes(entry[10..12].try_into().unwrap_or([0; 2]));
                            let fflags =
                                u32::from_le_bytes(entry[12..16].try_into().unwrap_or([0; 4]));
                            let data =
                                i64::from_le_bytes(entry[16..24].try_into().unwrap_or([0; 8]));
                            let udata =
                                u64::from_le_bytes(entry[24..32].try_into().unwrap_or([0; 8]));
                            change_summaries.push(format!(
                                "ident={} filter={} flags=0x{:X} fflags=0x{:X} data={} udata=0x{:X}",
                                ident, filter, flags, fflags, data, udata
                            ));
                            if flags & EV_DELETE != 0 {
                                registrations.retain(|reg| !(reg.ident == ident && reg.filter == filter));
                                continue;
                            }
                            if flags & EV_ADD != 0 || flags & EV_ENABLE != 0 {
                                registrations.retain(|reg| !(reg.ident == ident && reg.filter == filter));
                                if flags & EV_DISABLE == 0 {
                                    registrations.push(SyntheticKeventRegistration {
                                        ident,
                                        filter,
                                        flags,
                                        fflags,
                                        data,
                                        udata,
                                    });
                                }
                            }
                        }
                        registrations.clone()
                    };

                    let mut ready = Vec::new();
                    for reg in registrations_snapshot.iter() {
                        let Some(target) = resolve_process_fd_target(&os, current_pid, reg.ident) else {
                            registration_debug.push(format!(
                                "ident={} filter={} unresolved",
                                reg.ident, reg.filter
                            ));
                            continue;
                        };
                        match target {
                            SyntheticFdTarget::PipeRead(pipe_id) => {
                                if let Some(pipe) = os.pipes.get(&pipe_id) {
                                    let available = pipe.buffer.len() as u64;
                                    let eof = !pipe.write_open;
                                    registration_debug.push(format!(
                                        "ident={} filter={} pipe={} kind=read available={} read_open={} write_open={}",
                                        reg.ident, reg.filter, pipe_id, available, pipe.read_open, pipe.write_open
                                    ));
                                    if reg.filter == EVFILT_READ && (available > 0 || eof) {
                                        ready.push((
                                            reg.ident,
                                            reg.filter,
                                            if eof { EV_EOF } else { 0 },
                                            available,
                                            reg.fflags,
                                            reg.udata,
                                        ));
                                    }
                                }
                            }
                            SyntheticFdTarget::PipeWrite(pipe_id) => {
                                if let Some(pipe) = os.pipes.get(&pipe_id) {
                                    let buffered = pipe.buffer.len() as u64;
                                    let eof = !pipe.read_open;
                                    registration_debug.push(format!(
                                        "ident={} filter={} pipe={} kind=write buffered={} read_open={} write_open={}",
                                        reg.ident, reg.filter, pipe_id, buffered, pipe.read_open, pipe.write_open
                                    ));
                                    if reg.filter == EVFILT_WRITE && (pipe.read_open || eof) {
                                        ready.push((
                                            reg.ident,
                                            reg.filter,
                                            if eof { EV_EOF } else { 0 },
                                            buffered,
                                            reg.fflags,
                                            reg.udata,
                                        ));
                                    }
                                }
                            }
                            SyntheticFdTarget::File(_) => {
                                registration_debug.push(format!(
                                    "ident={} filter={} file",
                                    reg.ident, reg.filter
                                ));
                            }
                            SyntheticFdTarget::Directory(_) => {
                                registration_debug.push(format!(
                                    "ident={} filter={} directory",
                                    reg.ident, reg.filter
                                ));
                            }
                        }
                    }
                    ready
                };

                let mut emitted = 0u64;
                let mut emitted_summaries = Vec::new();
                if eventlist != 0 {
                    for (idx, (ident, filter, flags, data, fflags, udata)) in
                        ready_events.into_iter().take(nevents as usize).enumerate()
                    {
                        let entry_addr = eventlist + (idx as u64).saturating_mul(32);
                        let mut entry = [0u8; 32];
                        entry[0..8].copy_from_slice(&ident.to_le_bytes());
                        entry[8..10].copy_from_slice(&filter.to_le_bytes());
                        entry[10..12].copy_from_slice(&flags.to_le_bytes());
                        entry[12..16].copy_from_slice(&fflags.to_le_bytes());
                        entry[16..24].copy_from_slice(&(data as i64).to_le_bytes());
                        entry[24..32].copy_from_slice(&udata.to_le_bytes());
                        let _ = emu.write_memory(entry_addr, &entry);
                        if current_tid == 2 && nchanges == 0 && emitted_summaries.len() < 8 {
                            emitted_summaries.push(format!(
                                "ident={} filter={} flags=0x{:X} fflags=0x{:X} data={} udata=0x{:X}",
                                ident, filter, flags, fflags, data, udata
                            ));
                        }
                        emitted = emitted.saturating_add(1);
                    }
                }

                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", emitted);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_kevent(kq={}, nchanges={}, nevents={}, pid={}, tid={}) -> {}",
                        kq_fd, nchanges, nevents, current_pid, current_tid, emitted
                    ),
                );
                if !change_summaries.is_empty() {
                    println!(
                        "[KQUEUE][arm64] kq={} pid={} tid={} nchanges={} changes={}",
                        kq_fd, current_pid, current_tid, nchanges, change_summaries.join(", ")
                    );
                }
                if emitted == 0 && nchanges == 0 && current_tid == 2 && !registration_debug.is_empty() {
                    println!(
                        "[KQUEUE-STATE][arm64] kq={} pid={} tid={} regs={}",
                        kq_fd, current_pid, current_tid, registration_debug.join(" | ")
                    );
                }
                if emitted > 0 && nchanges == 0 && current_tid == 2 && !emitted_summaries.is_empty() {
                    println!(
                        "[KQUEUE-EMIT][arm64] kq={} pid={} tid={} events={}",
                        kq_fd, current_pid, current_tid, emitted_summaries.join(" | ")
                    );
                }
                let event = arm64_kqueue_event(current_pid, current_tid, "kevent")
                    .arg("KqueueFd", kq_fd.to_string())
                    .arg("Nchanges", nchanges.to_string())
                    .arg("Nevents", nevents.to_string())
                    .arg("Emitted", emitted.to_string())
                    .arg("TimeoutPtr", format!("0x{:X}", timeout_ptr));
                let event = if !change_summaries.is_empty() {
                    event.arg(
                        "Changes",
                        change_summaries
                            .iter()
                            .take(4)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | "),
                    )
                } else {
                    event
                };
                let event = if !emitted_summaries.is_empty() {
                    event.arg(
                        "Ready",
                        emitted_summaries
                            .iter()
                            .take(4)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | "),
                    )
                } else {
                    event
                };
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_pipe") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let pipefd_ptr = emu.read_reg("x0").unwrap_or(0);
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
                let (read_fd, write_fd) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let read_fd = os.next_fd;
                    let write_fd = os.next_fd.saturating_add(1);
                    os.next_fd = os.next_fd.saturating_add(2);
                    os.pipes.insert(
                        read_fd,
                        SyntheticPipe {
                            read_fd,
                            write_fd,
                            buffer: std::collections::VecDeque::new(),
                            read_open: true,
                            write_open: true,
                            capture_label: None,
                            capture_consumer_pid: None,
                            captured_data: Vec::new(),
                        },
                    );
                    os.fd_targets
                        .insert(read_fd, SyntheticFdTarget::PipeRead(read_fd));
                    os.fd_targets
                        .insert(write_fd, SyntheticFdTarget::PipeWrite(read_fd));
                    bind_process_fd_target(
                        &mut os,
                        current_pid,
                        read_fd,
                        SyntheticFdTarget::PipeRead(read_fd),
                    );
                    bind_process_fd_target(
                        &mut os,
                        current_pid,
                        write_fd,
                        SyntheticFdTarget::PipeWrite(read_fd),
                    );
                    (read_fd, write_fd)
                };
                if pipefd_ptr != 0 {
                    let _ = emu.write_memory(pipefd_ptr, &(read_fd as u32).to_le_bytes());
                    let _ = emu.write_memory(pipefd_ptr + 4, &(write_fd as u32).to_le_bytes());
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_pipe(pipefd=0x{:X}) -> [{}, {}]",
                        pipefd_ptr, read_fd, write_fd
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "pipe")
                    .arg("PipefdPtr", format!("0x{:X}", pipefd_ptr))
                    .arg("ReadFd", read_fd.to_string())
                    .arg("WriteFd", write_fd.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_fcntl") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
                let cmd = emu.read_reg("x1").unwrap_or(0);
                let arg = emu.read_reg("x2").unwrap_or(0);
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
                let result = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match cmd {
                        1 => os.fd_flags.get(&fd).copied().unwrap_or(0),
                        2 => {
                            os.fd_flags.insert(fd, arg);
                            0
                        }
                        3 | 4 => 0,
                        _ => 0,
                    }
                };
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_fcntl(fd={}, cmd={}, arg=0x{:X}) -> 0x{:X}",
                        fd, cmd, arg, result
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "fcntl")
                    .arg("Fd", fd.to_string())
                    .arg("Cmd", cmd.to_string())
                    .arg("CmdName", fcntl_cmd_name(cmd))
                    .arg("Arg", format!("0x{:X}", arg))
                    .arg("Result", format!("0x{:X}", result));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_signal") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let signum = emu.read_reg("x0").unwrap_or(0);
                let handler = emu.read_reg("x1").unwrap_or(0);
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_signal(signum={}, handler=0x{:X}) -> 0x0", signum, handler),
                );
                let event = arm64_io_event(current_pid, current_tid, "signal")
                    .arg("Signal", signum.to_string())
                    .arg("Handler", format!("0x{:X}", handler))
                    .arg("Result", "0x0");
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_memcpy") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dst = emu.read_reg("x0").unwrap_or(0);
                let src = emu.read_reg("x1").unwrap_or(0);
                let len = emu.read_reg("x2").unwrap_or(0) as usize;
                if dst != 0 && src != 0 && len != 0 {
                    if let Ok(bytes) = emu.read_memory(src, len) {
                        let _ = emu.write_memory(dst, &bytes);
                    }
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", dst);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_memcpy(dst=0x{:X}, src=0x{:X}, len=0x{:X}) -> 0x{:X}",
                        dst, src, len, dst
                    ),
                );
                let event = arm64_memory_event("memcpy")
                    .arg("Dst", format!("0x{:X}", dst))
                    .arg("Src", format!("0x{:X}", src))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_memmove") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dst = emu.read_reg("x0").unwrap_or(0);
                let src = emu.read_reg("x1").unwrap_or(0);
                let len = emu.read_reg("x2").unwrap_or(0) as usize;
                if dst != 0 && src != 0 && len != 0 {
                    if let Ok(bytes) = emu.read_memory(src, len) {
                        let _ = emu.write_memory(dst, &bytes);
                    }
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", dst);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_memmove(dst=0x{:X}, src=0x{:X}, len=0x{:X}) -> 0x{:X}",
                        dst, src, len, dst
                    ),
                );
                let event = arm64_memory_event("memmove")
                    .arg("Dst", format!("0x{:X}", dst))
                    .arg("Src", format!("0x{:X}", src))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_memset") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dst = emu.read_reg("x0").unwrap_or(0);
                let value = emu.read_reg("x1").unwrap_or(0) as u8;
                let len = emu.read_reg("x2").unwrap_or(0) as usize;
                if dst != 0 && len != 0 {
                    let _ = emu.write_memory(dst, &vec![value; len]);
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", dst);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_memset(dst=0x{:X}, value=0x{:X}, len=0x{:X}) -> 0x{:X}",
                        dst, value, len, dst
                    ),
                );
                let event = arm64_memory_event("memset")
                    .arg("Dst", format!("0x{:X}", dst))
                    .arg("Value", format!("0x{:X}", value))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_memcmp") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let left = emu.read_reg("x0").unwrap_or(0);
                let right = emu.read_reg("x1").unwrap_or(0);
                let len = emu.read_reg("x2").unwrap_or(0) as usize;
                let result = if left == 0 || right == 0 || len == 0 {
                    0i64
                } else {
                    let left_bytes = emu.read_memory(left, len).unwrap_or_default();
                    let right_bytes = emu.read_memory(right, len).unwrap_or_default();
                    let mut cmp = 0i64;
                    for (lhs, rhs) in left_bytes.iter().zip(right_bytes.iter()) {
                        if lhs != rhs {
                            cmp = (*lhs as i64) - (*rhs as i64);
                            break;
                        }
                    }
                    cmp
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result as u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_memcmp(left=0x{:X}, right=0x{:X}, len=0x{:X}) -> {}",
                        left, right, len, result
                    ),
                );
                let event = arm64_memory_event("memcmp")
                    .arg("Left", format!("0x{:X}", left))
                    .arg("Right", format!("0x{:X}", right))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Result", result.to_string())
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_calloc").or_else(|| stub_map.get("_cmalloc")) {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let malloc_next_addr = malloc_next_addr.clone();
        let malloc_allocations = malloc_allocations.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let nmemb = emu.read_reg("x0").unwrap_or(0);
                let size = emu.read_reg("x1").unwrap_or(0);
                let total = nmemb.saturating_mul(size).max(1);
                let aligned = (total + 0xFFF) & !0xFFF;
                let result = {
                    let mut next = match malloc_next_addr.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let addr = (*next + 0xF) & !0xF;
                    *next = addr.saturating_add(aligned);
                    let _ = emu.map_data_memory(addr, aligned);
                    let _ = emu.write_memory(addr, &vec![0u8; total as usize]);
                    if let Ok(mut allocations) = malloc_allocations.lock() {
                        allocations.insert(addr, total);
                    }
                    addr
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_calloc(nmemb=0x{:X}, size=0x{:X}) -> 0x{:X}",
                        nmemb, size, result
                    ),
                );
                let event = arm64_memory_event("calloc")
                    .arg("Nmemb", format!("0x{:X}", nmemb))
                    .arg("Size", format!("0x{:X}", size))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_realloc") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let malloc_next_addr = malloc_next_addr.clone();
        let malloc_allocations = malloc_allocations.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let old_ptr = emu.read_reg("x0").unwrap_or(0);
                let new_size = emu.read_reg("x1").unwrap_or(0).max(1);
                let aligned = (new_size + 0xFFF) & !0xFFF;
                let result = {
                    let mut next = match malloc_next_addr.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let new_ptr = (*next + 0xF) & !0xF;
                    *next = new_ptr.saturating_add(aligned);
                    let _ = emu.map_data_memory(new_ptr, aligned);
                    let old_size = malloc_allocations
                        .lock()
                        .ok()
                        .and_then(|allocs| allocs.get(&old_ptr).copied())
                        .unwrap_or(0);
                    let copy_size = old_size.min(new_size) as usize;
                    if old_ptr != 0 && copy_size != 0 {
                        if let Ok(bytes) = emu.read_memory(old_ptr, copy_size) {
                            let _ = emu.write_memory(new_ptr, &bytes);
                        }
                    }
                    if let Ok(mut allocations) = malloc_allocations.lock() {
                        allocations.remove(&old_ptr);
                        allocations.insert(new_ptr, new_size);
                    }
                    new_ptr
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_realloc(ptr=0x{:X}, size=0x{:X}) -> 0x{:X}",
                        old_ptr, new_size, result
                    ),
                );
                let event = arm64_memory_event("realloc")
                    .arg("OldPtr", format!("0x{:X}", old_ptr))
                    .arg("Size", format!("0x{:X}", new_size))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_free") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        let malloc_allocations = malloc_allocations.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let ptr = emu.read_reg("x0").unwrap_or(0);
                if let Ok(mut allocations) = malloc_allocations.lock() {
                    allocations.remove(&ptr);
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("_free(ptr=0x{:X})", ptr));
                let event = arm64_memory_event("free")
                    .arg("Ptr", format!("0x{:X}", ptr))
                    .arg("Pid", current_pid.to_string())
                    .arg("Tid", current_tid.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_sysconf") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let name = emu.read_reg("x0").unwrap_or(0);
                let result = match name {
                    29 | 30 => 4096,
                    57 | 58 => 8,
                    _ => 1,
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_sysconf(name={} {}) -> {}",
                        name,
                        sysconf_name(name),
                        result
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "sysconf")
                    .arg("Name", name.to_string())
                    .arg("NameStr", sysconf_name(name))
                    .arg("Result", result.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__NSGetArgc") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
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
                let result = process_bootstrap.argc_addr;
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("__NSGetArgc() -> 0x{:X}", result));
                let event =
                    arm64_process_event(current_pid, current_tid, "ns-getargc", "__NSGetArgc")
                        .arg("Result", format!("0x{:X}", result))
                        .arg("Argc", process_bootstrap.argc.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__NSGetArgv") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
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
                let result = process_bootstrap.ns_argv_ptr_addr;
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(&import_tracker, format!("__NSGetArgv() -> 0x{:X}", result));
                let event =
                    arm64_process_event(current_pid, current_tid, "ns-getargv", "__NSGetArgv")
                        .arg("Result", format!("0x{:X}", result))
                        .arg("Argv", format!("0x{:X}", process_bootstrap.argv_addr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("__NSGetEnviron") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
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
                let result = process_bootstrap.ns_envp_ptr_addr;
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("__NSGetEnviron() -> 0x{:X}", result),
                );
                let event = arm64_process_event(
                    current_pid,
                    current_tid,
                    "ns-getenviron",
                    "__NSGetEnviron",
                )
                .arg("Result", format!("0x{:X}", result))
                .arg("Envp", format!("0x{:X}", process_bootstrap.envp_addr));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_getenv") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let name_ptr = emu.read_reg("x0").unwrap_or(0);
                let name = read_cstring(emu, name_ptr, 128);
                let result = find_env_value_ptr(emu, process_bootstrap.envp_addr, &name, 64);
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_getenv(name={:?}) -> 0x{:X}", name, result),
                );
                let event = arm64_process_event(current_pid, current_tid, "getenv", "getenv")
                    .arg("Name", name)
                    .arg("Result", format!("0x{:X}", result));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_strlen") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let str_ptr = emu.read_reg("x0").unwrap_or(0);
                let mut len = 0u64;
                while len < 0x10000 {
                    let Ok(bytes) = emu.read_memory(str_ptr.saturating_add(len), 1) else {
                        break;
                    };
                    let Some(&byte) = bytes.first() else {
                        break;
                    };
                    if byte == 0 {
                        break;
                    }
                    len = len.saturating_add(1);
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", len);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_strlen(str=0x{:X}) -> {}", str_ptr, len),
                );
                let event = arm64_process_event(current_pid, current_tid, "strlen", "strlen")
                    .arg("Ptr", format!("0x{:X}", str_ptr))
                    .arg("Result", len.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_open") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let flags = emu.read_reg("x1").unwrap_or(0);
                let mode = emu.read_reg("x2").unwrap_or(0);
                let path = read_cstring(emu, path_ptr, 4096);
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
                let (result, errno, resolved) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match open_guest_file(&mut os, current_pid, &path) {
                        Ok((fd, resolved)) => (fd, 0u32, resolved),
                        Err(errno) => (
                            u64::MAX,
                            errno,
                            resolve_guest_path(&os.guest_files.guest_fs_base, &path),
                        ),
                    }
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_open(path={:?}, flags=0x{:X}, mode=0x{:X}) -> {} errno={}",
                        path, flags, mode, result, errno
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "open")
                    .arg("Path", path)
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Mode", format!("0x{:X}", mode))
                    .arg("Result", result.to_string())
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_opendir") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let path_ptr = emu.read_reg("x0").unwrap_or(0);
                let path = read_cstring(emu, path_ptr, 4096);
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
                let (result, errno, resolved) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match open_guest_file(&mut os, current_pid, &path) {
                        Ok((fd, resolved)) => match open_directory_stream(&mut os, current_pid, fd)
                        {
                            Ok(dir_stream) => (dir_stream, 0u32, resolved),
                            Err(errno) => {
                                let _ = close_synthetic_fd(&mut os, current_pid, fd);
                                (0u64, errno, resolved)
                            }
                        },
                        Err(errno) => (
                            0u64,
                            errno,
                            resolve_guest_path(&os.guest_files.guest_fs_base, &path),
                        ),
                    }
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_opendir(path={:?}) -> 0x{:X} errno={}",
                        path, result, errno
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "opendir")
                    .arg("Path", path)
                    .arg("Resolved", resolved.display().to_string())
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_fdopendir") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
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
                let (result, errno) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match open_directory_stream(&mut os, current_pid, fd) {
                        Ok(dir_stream) => (dir_stream, 0u32),
                        Err(errno) => (0u64, errno),
                    }
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_fdopendir(fd={}) -> 0x{:X} errno={}", fd, result, errno),
                );
                let event = arm64_io_event(current_pid, current_tid, "fdopendir")
                    .arg("Fd", fd.to_string())
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_close") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
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
                let target_before_close = os_runtime
                    .lock()
                    .ok()
                    .and_then(|os| resolve_process_fd_target(&os, current_pid, fd));
                let closed_pipe = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    close_synthetic_fd(&mut os, current_pid, fd)
                };
                let capture_closed = match target_before_close {
                    Some(SyntheticFdTarget::PipeWrite(pipe_id)) => {
                        let live_capture = os_runtime.lock().ok().and_then(|mut os| {
                            let (label, consumer_pid, data, still_open) = {
                                let pipe = os.pipes.get(&pipe_id)?;
                                (
                                    pipe.capture_label.clone()?,
                                    pipe.capture_consumer_pid,
                                    pipe.captured_data.clone(),
                                    pipe.write_open,
                                )
                            };
                            if still_open {
                                return None;
                            }
                            if let Some(pid) = consumer_pid {
                                terminate_synthetic_process(&mut os, pid, 0);
                            }
                            Some((pipe_id, label, consumer_pid, data))
                        });
                        live_capture.or_else(|| {
                            let pipe = closed_pipe.as_ref()?;
                            Some((
                                pipe_id,
                                pipe.capture_label.clone()?,
                                pipe.capture_consumer_pid,
                                pipe.captured_data.clone(),
                            ))
                        })
                    }
                    _ => None,
                };
                let _ = emu.write_reg("x0", 0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_close(fd={}, pid={}, tid={}, lr=0x{:X}) -> 0", fd, current_pid, thread_id, lr),
                );
                if let Some((pipe_id, label, consumer_pid, data)) = capture_closed {
                    let preview = lossy_data_preview(&data, 256);
                    let raw_hash = fnv1a64_hex(&data);
                    let raw_entropy = shannon_entropy(&data);
                    let capture_kind = "process-stdin";
                    let capture_dir = std::path::Path::new("target").join("machina-captures");
                    let mut artifact_summary = String::new();
                    let mut analysis_summary = String::new();
                    let raw_indicators = extract_ascii_indicators(&data, 8, 8);
                    if !raw_indicators.is_empty() {
                        analysis_summary.push_str(&format!(" indicators={:?}", raw_indicators));
                    }
                    if std::fs::create_dir_all(&capture_dir).is_ok() {
                        let safe_label = sanitize_capture_label(&label);
                        let raw_path = capture_dir.join(format!("pipe_{}_{}_stdin.stdin", pipe_id, safe_label));
                        if std::fs::write(&raw_path, &data).is_ok() {
                            artifact_summary.push_str(&format!(" raw={}", raw_path.display()));
                        }
                    }
                    println!(
                        "[CAPTURE][arm64] {} complete pipe_id={} closed_by_pid={} consumer_pid={:?} target={} total_bytes={} raw_fnv1a64={} raw_entropy={:.3} preview={}{}{}",
                        capture_kind, pipe_id, current_pid, consumer_pid, label, data.len(), raw_hash, raw_entropy, preview, artifact_summary, analysis_summary
                    );
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_closedir") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dirp = emu.read_reg("x0").unwrap_or(0);
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
                let (result, errno, fd) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match close_directory_stream(&mut os, current_pid, dirp) {
                        Ok(fd) => (0u64, 0u32, fd),
                        Err(errno) => (u64::MAX, errno, 0u64),
                    }
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_closedir(dirp=0x{:X}, fd={}) -> {} errno={}",
                        dirp, fd, result, errno
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "closedir")
                    .arg("Dirp", format!("0x{:X}", dirp))
                    .arg("Fd", fd.to_string())
                    .arg("Result", result.to_string())
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_dup2") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
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
                let result = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    let _ = close_synthetic_fd(&mut os, current_pid, newfd);
                    let inherited_flags = os.fd_flags.get(&oldfd).copied().unwrap_or(0) & !1;
                    os.fd_flags.insert(newfd, inherited_flags);
                    if let Some(target) = resolve_process_fd_target(&os, current_pid, oldfd) {
                        bind_process_fd_target(&mut os, current_pid, newfd, target);
                    }
                    newfd
                };
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_dup2(oldfd={}, newfd={}, pid={}, tid={}, lr=0x{:X}) -> {}",
                        oldfd, newfd, current_pid, thread_id, lr, result
                    ),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_read") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
                let buf = emu.read_reg("x1").unwrap_or(0);
                let count = emu.read_reg("x2").unwrap_or(0) as usize;
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
                let (result, preview, eof) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match resolve_process_fd_target(&os, current_pid, fd) {
                        Some(SyntheticFdTarget::PipeRead(pipe_id)) => {
                            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                                let to_read = count.min(pipe.buffer.len());
                                let mut data = Vec::with_capacity(to_read);
                                for _ in 0..to_read {
                                    if let Some(byte) = pipe.buffer.pop_front() {
                                        data.push(byte);
                                    }
                                }
                                let eof = !pipe.write_open && pipe.buffer.is_empty();
                                if !data.is_empty() {
                                    let recent_reads = os
                                        .last_pipe_reads
                                        .entry((current_pid, current_tid))
                                        .or_default();
                                    recent_reads.push_back(data.clone());
                                    while recent_reads.len() > 8 {
                                        recent_reads.pop_front();
                                    }
                                }
                                (data.len() as u64, data, eof)
                            } else {
                                (0, Vec::new(), true)
                            }
                        }
                        Some(SyntheticFdTarget::File(_)) => {
                            read_guest_file(&mut os, current_pid, fd, count)
                                .map(|(chunk, eof)| (chunk.len() as u64, chunk, eof))
                                .unwrap_or((0, Vec::new(), true))
                        }
                        _ => (0, Vec::new(), true),
                    }
                };
                if buf != 0 && !preview.is_empty() {
                    let _ = emu.write_memory(buf, &preview);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_read(fd={}, count={}, pid={}, tid={}) -> {} bytes eof={}",
                        fd, count, current_pid, current_tid, result, eof
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "read")
                    .arg("Fd", fd.to_string())
                    .arg("Count", count.to_string())
                    .arg("Result", result.to_string())
                    .arg("Eof", eof.to_string())
                    .arg("Preview", lossy_data_preview(&preview, 128));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_readdir_r") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let dirp = emu.read_reg("x0").unwrap_or(0);
                let entry_buf = emu.read_reg("x1").unwrap_or(0);
                let result_ptr = emu.read_reg("x2").unwrap_or(0);
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
                let (errno, hit_name, hit_is_dir) = {
                    let mut os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match resolve_directory_stream_fd(&os, current_pid, dirp) {
                        Some(fd) => match read_guest_directory_entry(&mut os, current_pid, fd) {
                            Some(entry) => {
                                write_fake_dirent(emu, entry_buf, 1, &entry.name, entry.is_dir);
                                if result_ptr != 0 {
                                    let _ = emu.write_memory(result_ptr, &entry_buf.to_le_bytes());
                                }
                                (0u32, Some(entry.name), Some(entry.is_dir))
                            }
                            None => {
                                if result_ptr != 0 {
                                    let _ = emu.write_memory(result_ptr, &0u64.to_le_bytes());
                                }
                                (0u32, None, None)
                            }
                        },
                        None => (9u32, None, None),
                    }
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_readdir_r(dirp=0x{:X}, entry=0x{:X}, result=0x{:X}) -> errno={} name={:?}",
                        dirp, entry_buf, result_ptr, errno, hit_name
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "readdir_r")
                    .arg("Dirp", format!("0x{:X}", dirp))
                    .arg("EntryBuf", format!("0x{:X}", entry_buf))
                    .arg("ResultPtr", format!("0x{:X}", result_ptr))
                    .arg("Errno", errno.to_string())
                    .arg("Name", hit_name.unwrap_or_default())
                    .arg("IsDir", hit_is_dir.unwrap_or(false).to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    for symbol in ["_stat", "_lstat"] {
        if let Some(&addr) = stub_map.get(symbol) {
            let os_runtime = shared_state.os_runtime.clone();
            let import_tracker = import_tracker.clone();
            let trace_bus_for_hook = trace_bus.clone();
            let symbol_name = symbol.to_string();
            emulator.add_code_hook(
                addr,
                addr + 4,
                move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                    let path_ptr = emu.read_reg("x0").unwrap_or(0);
                    let stat_buf = emu.read_reg("x1").unwrap_or(0);
                    let path = read_cstring(emu, path_ptr, 4096);
                    let (result, errno, size, resolved) =
                        match os_runtime.lock().ok().map(|os| stat_guest_path(&os, &path)) {
                            Some(Ok((size, resolved))) => (0u64, 0u32, size, resolved),
                            _ => (
                                u64::MAX,
                                2u32,
                                0u64,
                                std::path::PathBuf::from(".").join(path.trim_start_matches('/')),
                            ),
                        };
                    if result == 0 {
                        write_fake_stat(emu, stat_buf, size);
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
                            "{}(path={:?}, buf=0x{:X}) -> {} errno={} size={}",
                            symbol_name, path, stat_buf, result, errno, size
                        ),
                    );
                    let event = arm64_io_event(1, 1, symbol_name.clone())
                        .arg("Path", path)
                        .arg("Resolved", resolved.display().to_string())
                        .arg("Buf", format!("0x{:X}", stat_buf))
                        .arg("Result", result.to_string())
                        .arg("Errno", errno.to_string())
                        .arg("Size", size.to_string());
                    emit_arm64_event(&trace_bus_for_hook, event);
                },
            )?;
        }
    }

    if let Some(&addr) = stub_map.get("_fstat") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
                let stat_buf = emu.read_reg("x1").unwrap_or(0);
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
                let (result, errno, size) = {
                    let os = match os_runtime.lock() {
                        Ok(os) => os,
                        Err(_) => return,
                    };
                    match fstat_guest_file(&os, current_pid, fd) {
                        Ok(size) => (0u64, 0u32, size),
                        Err(errno) => (u64::MAX, errno as u32, 0u64),
                    }
                };
                if result == 0 {
                    write_fake_stat(emu, stat_buf, size);
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
                        "_fstat(fd={}, buf=0x{:X}) -> {} errno={} size={}",
                        fd, stat_buf, result, errno, size
                    ),
                );
                let event = arm64_io_event(current_pid, current_tid, "fstat")
                    .arg("Fd", fd.to_string())
                    .arg("Buf", format!("0x{:X}", stat_buf))
                    .arg("Result", result.to_string())
                    .arg("Errno", errno.to_string())
                    .arg("Size", size.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_getcwd") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let buf = emu.read_reg("x0").unwrap_or(0);
                let size = emu.read_reg("x1").unwrap_or(0) as usize;
                let cwd = b"/Users/analyst\0";
                let (result, errno) = if buf != 0 && size >= cwd.len() {
                    let _ = emu.write_memory(buf, cwd);
                    (buf, 0u32)
                } else {
                    (0u64, 34u32)
                };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_getcwd(buf=0x{:X}, size={}) -> 0x{:X}", buf, size, result),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_getrlimit") {
        let import_tracker = import_tracker.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let resource = emu.read_reg("x0").unwrap_or(0);
                let rlp = emu.read_reg("x1").unwrap_or(0);
                if rlp != 0 {
                    let lim = u64::MAX / 4;
                    let _ = emu.write_memory(rlp, &lim.to_le_bytes());
                    let _ = emu.write_memory(rlp + 8, &lim.to_le_bytes());
                }
                let _ = emu.write_memory(errno_ptr, &0u32.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_getrlimit(resource={}, rlp=0x{:X}) -> 0", resource, rlp),
                );
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_sigaction") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let signum = emu.read_reg("x0").unwrap_or(0);
                let act = emu.read_reg("x1").unwrap_or(0);
                let oldact = emu.read_reg("x2").unwrap_or(0);
                if oldact != 0 {
                    let _ = emu.write_memory(oldact, &[0u8; 32]);
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_sigaction(signum={}, act=0x{:X}, oldact=0x{:X}) -> 0",
                        signum, act, oldact
                    ),
                );
                let event = arm64_process_event(current_pid, current_tid, "sigaction", "sigaction")
                    .arg("Signal", signum.to_string())
                    .arg("Act", format!("0x{:X}", act))
                    .arg("OldAct", format!("0x{:X}", oldact))
                    .arg("Result", "0");
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_sigaltstack") {
        let thread_runtime = shared_state.thread_runtime.clone();
        let os_runtime = shared_state.os_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let ss = emu.read_reg("x0").unwrap_or(0);
                let old_ss = emu.read_reg("x1").unwrap_or(0);
                if old_ss != 0 {
                    let _ = emu.write_memory(old_ss, &[0u8; 24]);
                }
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
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_sigaltstack(ss=0x{:X}, old_ss=0x{:X}) -> 0", ss, old_ss),
                );
                let event =
                    arm64_process_event(current_pid, current_tid, "sigaltstack", "sigaltstack")
                        .arg("Stack", format!("0x{:X}", ss))
                        .arg("OldStack", format!("0x{:X}", old_ss))
                        .arg("Result", "0");
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_malloc") {
        let malloc_next_addr = shared_state.malloc_next_addr.clone();
        let malloc_allocations = shared_state.malloc_allocations.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 8,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let requested = emu.read_reg("x0").unwrap_or(0);
                let alloc_size = align_up(requested.max(1), 0x10);
                let page_size = align_up(alloc_size, 0x1000);
                let result = {
                    let mut next = match malloc_next_addr.lock() {
                        Ok(next) => next,
                        Err(_) => return,
                    };
                    let addr = *next;
                    *next = next.saturating_add(page_size);
                    let _ = emu.map_data_memory(addr, page_size);
                    let _ = emu.write_memory(addr, &vec![0u8; alloc_size as usize]);
                    addr
                };
                if let Ok(mut allocations) = malloc_allocations.lock() {
                    allocations.insert(result, alloc_size);
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!("_malloc(size=0x{:X}) -> 0x{:X}", requested, result),
                );
                let event = arm64_memory_event("malloc")
                    .arg("Size", format!("0x{:X}", requested))
                    .arg("Result", format!("0x{:X}", result));
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_write") {
        let os_runtime = shared_state.os_runtime.clone();
        let thread_runtime = shared_state.thread_runtime.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let fd = emu.read_reg("x0").unwrap_or(0);
                let buf = emu.read_reg("x1").unwrap_or(0);
                let count = emu.read_reg("x2").unwrap_or(0) as usize;
                let capture_len = count.min(4 * 1024 * 1024);
                let mut data = if buf != 0 && count > 0 {
                    emu.read_memory(buf, capture_len).unwrap_or_default()
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
                if fd >= 65536
                    && count == 8
                    && data.iter().all(|byte| *byte == 0)
                    && thread_runtime
                        .lock()
                        .ok()
                        .and_then(|rt| {
                            rt.fork_parent_resumes
                                .get(&current_tid)
                                .cloned()
                                .or_else(|| {
                                    rt.fork_parent_resumes
                                        .values()
                                        .find(|resume| resume.parent_tid == current_tid)
                                        .cloned()
                                })
                        })
                        .is_some()
                {
                    if let Ok(mut runtime) = thread_runtime.lock() {
                        let resume_key = if runtime.fork_parent_resumes.contains_key(&current_tid) {
                            Some(current_tid)
                        } else {
                            runtime
                                .fork_parent_resumes
                                .iter()
                                .find(|(_, resume)| resume.parent_tid == current_tid)
                                .map(|(child_tid, _)| *child_tid)
                        };
                        if let Some(parent_resume) =
                            resume_key.and_then(|key| runtime.fork_parent_resumes.remove(&key))
                        {
                            let queued_parent_tid = if parent_resume.parent_tid == current_tid {
                                10_000 + parent_resume.parent_tid
                            } else {
                                parent_resume.parent_tid
                            };
                            runtime
                                .pending_threads
                                .retain(|thread| thread.thread_id != queued_parent_tid);
                            runtime.pending_threads.push_front(PendingArm64Thread {
                                thread_id: queued_parent_tid,
                                entry: 0,
                                arg: 0,
                                stack_top: parent_resume.context.sp,
                                exit_pc: 0,
                                resume: Some(parent_resume.context.clone()),
                            });
                            if let Ok(mut os) = os_runtime.lock() {
                                os.thread_processes.insert(queued_parent_tid, current_pid);
                                os.process_thread_ids.insert(queued_parent_tid);
                            }
                            println!(
                                "[PROC][arm64] suppressed impossible post-exec child error write fd={} tid={} -> queued fork parent tid={} pc=0x{:X}",
                                fd, current_tid, queued_parent_tid, parent_resume.context.pc
                            );
                            record_arm64_import(
                                &import_tracker,
                                format!(
                                    "_write(fd={}, count=8, tid={}) suppressed post-exec child tail",
                                    fd, current_tid
                                ),
                            );
                            let lr = emu.read_reg("lr").unwrap_or(0);
                            if lr != 0 {
                                let _ = emu.write_reg("pc", lr);
                            }
                            return;
                        }
                    }
                }
                let mut pipe_capture = None;
                let mut substituted_recent_read = false;
                if !data.is_empty() {
                    if let Ok(mut os) = os_runtime.lock() {
                        if let Some(SyntheticFdTarget::PipeWrite(pipe_id)) =
                            resolve_process_fd_target(&os, current_pid, fd)
                        {
                            if data.len() == count && data.iter().all(|byte| *byte == 0) {
                                if let Some(recent_reads) = os.last_pipe_reads.get_mut(&(current_pid, current_tid)) {
                                    if recent_reads
                                        .front()
                                        .map(|recent_read| recent_read.len() == data.len())
                                        .unwrap_or(false)
                                    {
                                        let recent_read = recent_reads.pop_front().unwrap_or_default();
                                        data = recent_read;
                                        substituted_recent_read = true;
                                    }
                                }
                            } else if let Some(recent_reads) = os.last_pipe_reads.get_mut(&(current_pid, current_tid)) {
                                if recent_reads
                                    .front()
                                    .map(|recent_read| recent_read.as_slice() == data.as_slice())
                                    .unwrap_or(false)
                                {
                                    recent_reads.pop_front();
                                }
                            }
                            if let Some(pipe) = os.pipes.get_mut(&pipe_id) {
                                pipe.buffer.extend(data.iter().copied());
                                if let Some(label) = pipe.capture_label.clone() {
                                    pipe.captured_data.extend(data.iter().copied());
                                    let preview = lossy_data_preview(&pipe.captured_data, 256);
                                    pipe_capture = Some((label, pipe.captured_data.len(), preview));
                                }
                            }
                        }
                    }
                }
                let lr = emu.read_reg("lr").unwrap_or(0);
                let sp = emu.read_reg("sp").unwrap_or(0);
                let caller_lr = if sp != 0 {
                    emu.read_memory(sp, 8).ok().and_then(vec_u64_le).unwrap_or(0)
                } else {
                    0
                };
                let lr_code = emu.read_memory(lr.saturating_sub(8), 24).unwrap_or_default();
                let _ = emu.write_reg("x0", count as u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                if !data.is_empty() {
                    let preview = lossy_data_preview(&data, 256);
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_write(fd={}, count={}, captured={}, pid={}, tid={}, lr=0x{:X}, caller=0x{:X}) -> {:?}",
                            fd, count, data.len(), current_pid, current_tid, lr, caller_lr, preview
                        ),
                    );
                    if fd >= 65536 {
                        println!(
                            "[TRACE][arm64] _write synthetic fd={} substituted_recent_read={} lr_code={:02X?}",
                            fd, substituted_recent_read, lr_code
                        );
                    }
                    if let Some((label, total_len, capture_preview)) = pipe_capture {
                        println!(
                            "[CAPTURE][arm64] process-stdin source_fd={} pid={} tid={} target={} total_bytes={} preview={}",
                            fd, current_pid, current_tid, label, total_len, capture_preview
                        );
                    }
                } else {
                    record_arm64_import(
                        &import_tracker,
                        format!(
                            "_write(fd={}, count={}, pid={}, tid={}, buf=0x{:X}, lr=0x{:X}, caller=0x{:X})",
                            fd, count, current_pid, current_tid, buf, lr, caller_lr
                        ),
                    );
                    if fd >= 65536 {
                        println!(
                            "[TRACE][arm64] _write synthetic fd={} lr_code={:02X?}",
                            fd, lr_code
                        );
                    }
                }
                let preview = if data.is_empty() {
                    String::new()
                } else {
                    lossy_data_preview(&data, 128)
                };
                let event = arm64_io_event(current_pid, current_tid, "write")
                    .arg("Fd", fd.to_string())
                    .arg("Count", count.to_string())
                    .arg("Captured", data.len().to_string())
                    .arg("Buf", format!("0x{:X}", buf))
                    .arg("Preview", preview);
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_mmap") {
        let mmap_next_import = mmap_next.clone();
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let req_addr = emu.read_reg("x0").unwrap_or(0);
                let len = align_up(emu.read_reg("x1").unwrap_or(0).max(0x1000), 0x1000);
                let prot = emu.read_reg("x2").unwrap_or(0);
                let flags = emu.read_reg("x3").unwrap_or(0);
                let fd = emu.read_reg("x4").unwrap_or(u64::MAX);
                let offset = emu.read_reg("x5").unwrap_or(0);
                let mut map_addr = if req_addr == 0 {
                    mmap_next_import.fetch_add(len, std::sync::atomic::Ordering::Relaxed)
                } else {
                    req_addr
                };
                map_addr = align_up(map_addr, 0x1000);
                let result = if req_addr == 0 && map_addr.saturating_add(len) > mmap_end {
                    u64::MAX
                } else {
                    match emu.reserve_lazy_data_memory(map_addr, len) {
                        Ok(()) => map_addr,
                        Err(err) => {
                            println!(
                                "[IMPORT][arm64] _mmap reserve failed addr=0x{:X} len=0x{:X}: {}",
                                map_addr, len, err
                            );
                            u64::MAX
                        }
                    }
                };
                let errno = if result == u64::MAX { 12u32 } else { 0u32 };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_mmap(req=0x{:X}, len=0x{:X}, prot=0x{:X}, flags=0x{:X}, fd={}, off=0x{:X}) -> 0x{:X}",
                        req_addr, len, prot, flags, fd, offset, result
                    ),
                );
                let event = arm64_memory_event("mmap")
                    .arg("ReqAddr", format!("0x{:X}", req_addr))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Prot", format!("0x{:X}", prot))
                    .arg("Flags", format!("0x{:X}", flags))
                    .arg("Fd", fd.to_string())
                    .arg("Offset", format!("0x{:X}", offset))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_munmap") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let map_addr = emu.read_reg("x0").unwrap_or(0);
                let len = align_up(emu.read_reg("x1").unwrap_or(0).max(0x1000), 0x1000);
                let result = match emu.unmap_lazy_memory(map_addr, len) {
                    Ok(()) => 0u64,
                    Err(err) => {
                        println!(
                            "[IMPORT][arm64] _munmap failed addr=0x{:X} len=0x{:X}: {}",
                            map_addr, len, err
                        );
                        u64::MAX
                    }
                };
                let errno = if result == u64::MAX { 22u32 } else { 0u32 };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_munmap(addr=0x{:X}, len=0x{:X}) -> 0x{:X}",
                        map_addr, len, result
                    ),
                );
                let event = arm64_memory_event("munmap")
                    .arg("Addr", format!("0x{:X}", map_addr))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_mprotect") {
        let import_tracker = import_tracker.clone();
        let trace_bus_for_hook = trace_bus.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let map_addr = emu.read_reg("x0").unwrap_or(0);
                let len = align_up(emu.read_reg("x1").unwrap_or(0).max(0x1000), 0x1000);
                let prot_bits = emu.read_reg("x2").unwrap_or(0);
                let mut prot = unicorn_engine::Prot::NONE;
                if prot_bits & 0x1 != 0 {
                    prot |= unicorn_engine::Prot::READ;
                }
                if prot_bits & 0x2 != 0 {
                    prot |= unicorn_engine::Prot::WRITE;
                }
                if prot_bits & 0x4 != 0 {
                    prot |= unicorn_engine::Prot::EXEC;
                }
                let result = match emu.protect_lazy_memory(map_addr, len, prot) {
                    Ok(()) => 0u64,
                    Err(err) => {
                        println!(
                            "[IMPORT][arm64] _mprotect failed addr=0x{:X} len=0x{:X} prot=0x{:X}: {}",
                            map_addr, len, prot_bits, err
                        );
                        u64::MAX
                    }
                };
                let errno = if result == u64::MAX { 22u32 } else { 0u32 };
                let _ = emu.write_memory(errno_ptr, &errno.to_le_bytes());
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", result);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
                record_arm64_import(
                    &import_tracker,
                    format!(
                        "_mprotect(addr=0x{:X}, len=0x{:X}, prot=0x{:X}) -> 0x{:X}",
                        map_addr, len, prot_bits, result
                    ),
                );
                let event = arm64_memory_event("mprotect")
                    .arg("Addr", format!("0x{:X}", map_addr))
                    .arg("Len", format!("0x{:X}", len))
                    .arg("Prot", format!("0x{:X}", prot_bits))
                    .arg("Result", format!("0x{:X}", result))
                    .arg("Errno", errno.to_string());
                emit_arm64_event(&trace_bus_for_hook, event);
            },
        )?;
    }

    Ok(())
}
