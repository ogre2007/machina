//! Diagnostic hooks and stop reporting for the legacy arm64 runner.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::macos::{
    emit_runner_trace_event, lossy_data_preview, process_event, runtime_process_metadata,
    SharedTraceBus,
};
use crate::{Emulator, MachoBinary, UnicornEmulator};

fn debug_stdout_enabled() -> bool {
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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_hex_u64(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(hex, 16).ok()
}

/// Resolve the canonical instruction/time budget for the active run profile.
///
/// Returns `(profile_label, timeout_usecs_default, instruction_count_default)`.
///
/// Real-world macOS Mach-O samples (especially Rust binaries with large
/// `OnceLock`/TLS initialization graphs like RustDoor) routinely need more
/// than the original 10M-instruction budget just to finish startup, well
/// before reaching the malware-interesting C2 / spawn / file logic. The
/// `MACHINA_PROFILE` knob lets analysts opt into longer budgets without
/// having to set every limit env var by hand.
///
/// Recognized values (case-insensitive, leading/trailing whitespace ignored):
///
/// - `default` / unset / empty → 60 s, 50_000_000 instructions
/// - `short`                   → 15 s, 10_000_000 instructions  (legacy cap)
/// - `long`                    → 120 s, 200_000_000 instructions
/// - `extended`                → 300 s, 1_000_000_000 instructions
///
/// Explicit `MACHINA_TIMEOUT_USECS` / `MACHINA_MAX_INSTRUCTIONS` always win.
fn resolve_run_profile() -> (&'static str, u64, usize) {
    let raw = std::env::var("MACHINA_PROFILE").ok();
    let label: String = raw
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match label.as_str() {
        "short" | "legacy" | "compat" => ("short", 15_000_000, 10_000_000),
        "long" | "rustdoor" => ("long", 120_000_000, 200_000_000),
        "extended" | "deep" => ("extended", 300_000_000, 1_000_000_000),
        _ => ("default", 60_000_000, 50_000_000),
    }
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
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

fn read_qword_preview(emu: &mut UnicornEmulator, addr: u64, count: usize) -> Option<String> {
    if addr < 0x1000 || count == 0 {
        return None;
    }
    let bytes = emu.read_memory(addr, count * 8).ok()?;
    let mut parts = Vec::new();
    for chunk in bytes.chunks_exact(8).take(count) {
        let raw = <[u8; 8]>::try_from(chunk).ok()?;
        let value = u64::from_le_bytes(raw);
        parts.push(format!("0x{:X}", value));
    }
    Some(parts.join(","))
}

fn read_byte_preview(emu: &mut UnicornEmulator, addr: u64, count: usize) -> Option<String> {
    if addr < 0x1000 || count == 0 {
        return None;
    }
    let bytes = emu.read_memory(addr, count).ok()?;
    Some(lossy_data_preview(&bytes, count))
}

fn current_arm64_brk_immediate(emu: &mut UnicornEmulator) -> Option<u16> {
    let pc = emu.read_reg("pc").ok()?;
    let bytes = emu.read_memory(pc, 4).ok()?;
    let raw = <[u8; 4]>::try_from(bytes.as_slice()).ok()?;
    let instr = u32::from_le_bytes(raw);
    if (instr & 0xFFE0_001F) == 0xD420_0000 {
        Some(((instr >> 5) & 0xFFFF) as u16)
    } else {
        None
    }
}

pub fn install_arm64_diagnostic_hooks(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    runtime_firstmoduledata: Option<u64>,
    actual_entry: u64,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = (binary, runtime_firstmoduledata, trace_bus, process_name);

    let startup_trace_count = Arc::new(AtomicUsize::new(0));
    let startup_trace_counter = startup_trace_count.clone();
    emulator.add_code_hook(
        actual_entry,
        done_addr + 4,
        move |emu: &mut machina::UnicornEmulator, address: u64, size: u32| {
            let seen = startup_trace_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if seen >= 64 {
                return;
            }
            let sp = emu.read_reg("sp").unwrap_or(0);
            let lr = emu.read_reg("lr").unwrap_or(0);
            let x0 = emu.read_reg("x0").unwrap_or(0);
            let x1 = emu.read_reg("x1").unwrap_or(0);
            let x2 = emu.read_reg("x2").unwrap_or(0);
            let x3 = emu.read_reg("x3").unwrap_or(0);
            let tpidr_el0 = emu.read_reg("tpidr_el0").unwrap_or(0);
            let tpidrro_el0 = emu.read_reg("tpidrro_el0").unwrap_or(0);
            let bytes = emu.read_memory(address, size as usize).unwrap_or_default();
            if debug_stdout_enabled() {
                println!(
                    "[STARTUP][arm64 #{:02}] pc=0x{:X} lr=0x{:X} sp=0x{:X} x0=0x{:X} x1=0x{:X} x2=0x{:X} x3=0x{:X} tpidr_el0=0x{:X} tpidrro_el0=0x{:X} bytes={:02X?}",
                    seen,
                    address,
                    lr,
                    sp,
                    x0,
                    x1,
                    x2,
                    x3,
                    tpidr_el0,
                    tpidrro_el0,
                    bytes
                );
            }
            if address == done_addr {
                if debug_stdout_enabled() {
                    println!("[STARTUP][arm64] reached done_addr");
                }
            }
        },
    )?;

    if let (Some(window_start), Some(window_end)) = (
        env_hex_u64("MACHINA_TRACE_WINDOW_START"),
        env_hex_u64("MACHINA_TRACE_WINDOW_END"),
    ) {
        let max_hits = env_usize("MACHINA_TRACE_WINDOW_HITS", 128);
        let window_hits = Arc::new(AtomicUsize::new(0));
        let trace_bus_for_hook = trace_bus.clone();
        let process_name = process_name.to_string();
        let window_hits_counter = window_hits.clone();
        emulator.add_code_hook(
            window_start,
            window_end,
            move |emu: &mut machina::UnicornEmulator, address: u64, size: u32| {
                let seen = window_hits_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if seen >= max_hits {
                    return;
                }
                let sp = emu.read_reg("sp").unwrap_or(0);
                let lr = emu.read_reg("lr").unwrap_or(0);
                let x0 = emu.read_reg("x0").unwrap_or(0);
                let x1 = emu.read_reg("x1").unwrap_or(0);
                let x2 = emu.read_reg("x2").unwrap_or(0);
                let x3 = emu.read_reg("x3").unwrap_or(0);
                let x8 = emu.read_reg("x8").unwrap_or(0);
                let x9 = emu.read_reg("x9").unwrap_or(0);
                let x10 = emu.read_reg("x10").unwrap_or(0);
                let x11 = emu.read_reg("x11").unwrap_or(0);
                let bytes = emu.read_memory(address, size as usize).unwrap_or_default();
                let metadata = runtime_process_metadata(process_name.clone());
                let mut event = process_event(&metadata, "trace-window", "trace-window")
                    .arg("Pc", format!("0x{:X}", address))
                    .arg("Lr", format!("0x{:X}", lr))
                    .arg("Sp", format!("0x{:X}", sp))
                    .arg("X0", format!("0x{:X}", x0))
                    .arg("X1", format!("0x{:X}", x1))
                    .arg("X2", format!("0x{:X}", x2))
                    .arg("X3", format!("0x{:X}", x3))
                    .arg("X8", format!("0x{:X}", x8))
                    .arg("X9", format!("0x{:X}", x9))
                    .arg("X10", format!("0x{:X}", x10))
                    .arg("X11", format!("0x{:X}", x11))
                    .arg("Bytes", format!("{:02X?}", bytes));
                if let Some(preview) = read_byte_preview(emu, x0, 64) {
                    event = event.arg("X0Preview", preview);
                }
                if let Some(preview) = read_byte_preview(emu, x1, 64) {
                    event = event.arg("X1Preview", preview);
                }
                if let Some(preview) = read_byte_preview(emu, x2, 64) {
                    event = event.arg("X2Preview", preview);
                }
                emit_runner_trace_event(&trace_bus_for_hook, &metadata, event);
            },
        )?;
    }

    if env_bool("MACHINA_AUTH_DISPATCH_DIAG") {
        let auth_points: &[(u64, &str)] = &[
            (0x10004CAA8, "auth-helper-entry"),
            (0x10004CB30, "auth-branch-cb30"),
            (0x10004CBC0, "auth-branch-cbc0"),
            (0x10004CC10, "auth-branch-cc10"),
            (0x10004CC38, "auth-branch-cc38"),
            (0x10004CDB4, "auth-branch-cdb4"),
            (0x10004C8CC, "auth-dispatch-c8cc"),
            (0x10004C8F4, "auth-dispatch-c8f4"),
            (0x10004FFAC, "auth-dispatch-ffac"),
            (0x1000571A0, "auth-dispatch-71a0"),
            (0x10011EE0C, "auth-dispatch-ee0c"),
            (0x1001222F8, "auth-dispatch-22f8"),
        ];
        let hit_limit = env_usize("MACHINA_AUTH_DISPATCH_HITS", 128);
        let auth_hits = Arc::new(AtomicUsize::new(0));
        for (addr, tag) in auth_points {
            let trace_bus_for_hook = trace_bus.clone();
            let process_name = process_name.to_string();
            let tag = (*tag).to_string();
            let auth_hits_counter = auth_hits.clone();
            emulator.add_code_hook(
                *addr,
                *addr + 4,
                move |emu: &mut machina::UnicornEmulator, address: u64, size: u32| {
                    let seen = auth_hits_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if seen >= hit_limit {
                        return;
                    }
                    let lr = emu.read_reg("lr").unwrap_or(0);
                    let sp = emu.read_reg("sp").unwrap_or(0);
                    let x0 = emu.read_reg("x0").unwrap_or(0);
                    let x1 = emu.read_reg("x1").unwrap_or(0);
                    let x2 = emu.read_reg("x2").unwrap_or(0);
                    let x6 = emu.read_reg("x6").unwrap_or(0);
                    let x8 = emu.read_reg("x8").unwrap_or(0);
                    let x9 = emu.read_reg("x9").unwrap_or(0);
                    let x10 = emu.read_reg("x10").unwrap_or(0);
                    let x11 = emu.read_reg("x11").unwrap_or(0);
                    let x23 = emu.read_reg("x23").unwrap_or(0);
                    let x25 = emu.read_reg("x25").unwrap_or(0);
                    let bytes = emu.read_memory(address, size as usize).unwrap_or_default();
                    let metadata = runtime_process_metadata(process_name.clone());
                    let mut event = process_event(&metadata, tag.clone(), "auth-dispatch-diag")
                        .arg("Pc", format!("0x{:X}", address))
                        .arg("Lr", format!("0x{:X}", lr))
                        .arg("Sp", format!("0x{:X}", sp))
                        .arg("X0", format!("0x{:X}", x0))
                        .arg("X1", format!("0x{:X}", x1))
                        .arg("X2", format!("0x{:X}", x2))
                        .arg("X6", format!("0x{:X}", x6))
                        .arg("X8", format!("0x{:X}", x8))
                        .arg("X9", format!("0x{:X}", x9))
                        .arg("X10", format!("0x{:X}", x10))
                        .arg("X11", format!("0x{:X}", x11))
                        .arg("X23", format!("0x{:X}", x23))
                        .arg("X25", format!("0x{:X}", x25))
                        .arg("Bytes", format!("{:02X?}", bytes));
                    if let Some(preview) = read_qword_preview(emu, x0, 4) {
                        event = event.arg("X0Qwords", preview);
                    }
                    if let Some(preview) = read_qword_preview(emu, x1, 4) {
                        event = event.arg("X1Qwords", preview);
                    }
                    if let Some(preview) = read_qword_preview(emu, x2, 4) {
                        event = event.arg("X2Qwords", preview);
                    }
                    emit_runner_trace_event(&trace_bus_for_hook, &metadata, event);
                },
            )?;
        }
    }

    Ok(())
}

pub struct Arm64RunReport {
    pub actual_entry: u64,
    pub done_addr: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub stub_base: u64,
    pub stub_size: u64,
    pub saw_exit: Arc<AtomicBool>,
    pub syscall_count: Arc<AtomicUsize>,
    pub import_count: Arc<AtomicUsize>,
    pub last_stub: Arc<Mutex<Option<String>>>,
    pub recent_imports: Arc<Mutex<VecDeque<String>>>,
    pub synthetic_stop_reason: Arc<Mutex<Option<String>>>,
    pub trace_bus: Option<SharedTraceBus>,
    pub process_name: String,
}

pub fn run_arm64_with_diagnostics(
    emulator: &mut UnicornEmulator,
    report: Arm64RunReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let emit_stop_status = |status: &str, detail: &str, emulator: &mut UnicornEmulator| {
        let metadata = runtime_process_metadata(report.process_name.clone());
        let pc = emulator.read_reg("pc").unwrap_or(0);
        let lr = emulator.read_reg("lr").unwrap_or(0);
        let sp = emulator.read_reg("sp").unwrap_or(0);
        let x0 = emulator.read_reg("x0").unwrap_or(0);
        let x1 = emulator.read_reg("x1").unwrap_or(0);
        let x2 = emulator.read_reg("x2").unwrap_or(0);
        let event = process_event(&metadata, "emulation-stop", "emulation-stop")
            .arg("Status", status)
            .arg("Detail", detail.to_string())
            .arg("Pc", format!("0x{:X}", pc))
            .arg("Lr", format!("0x{:X}", lr))
            .arg("Sp", format!("0x{:X}", sp))
            .arg("X0", format!("0x{:X}", x0))
            .arg("X1", format!("0x{:X}", x1))
            .arg("X2", format!("0x{:X}", x2))
            .arg(
                "SawExit",
                report
                    .saw_exit
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .to_string(),
            )
            .arg(
                "Syscalls",
                report
                    .syscall_count
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .to_string(),
            )
            .arg(
                "Imports",
                report
                    .import_count
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .to_string(),
            );
        emit_runner_trace_event(&report.trace_bus, &metadata, event);
    };

    let (profile_name, profile_timeout, profile_instructions) = resolve_run_profile();
    let timeout_usecs = env_u64("MACHINA_TIMEOUT_USECS", profile_timeout);
    let instruction_count = env_usize("MACHINA_MAX_INSTRUCTIONS", profile_instructions);
    {
        let metadata = runtime_process_metadata(report.process_name.clone());
        let event = process_event(&metadata, "run-profile", "run-profile")
            .arg("Profile", profile_name)
            .arg("TimeoutUsecs", timeout_usecs.to_string())
            .arg("MaxInstructions", instruction_count.to_string());
        emit_runner_trace_event(&report.trace_bus, &metadata, event);
    }
    let start = Instant::now();
    match emulator.run_with_limits(report.actual_entry, None, timeout_usecs, instruction_count) {
        Ok(()) => {
            let pc = emulator.read_reg("pc").unwrap_or(0);
            let elapsed_usecs = start.elapsed().as_micros() as u64;
            let timed_out =
                timeout_usecs != 0 && elapsed_usecs >= timeout_usecs.saturating_sub(5_000);
            let detail = if let Some(imm) = current_arm64_brk_immediate(emulator) {
                format!("brk_trap_0x{:X}", imm)
            } else if pc == report.done_addr {
                "done_addr".to_string()
            } else if report.saw_exit.load(std::sync::atomic::Ordering::Relaxed) {
                "post_exit".to_string()
            } else if let Some(reason) = report
                .synthetic_stop_reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone())
            {
                reason
            } else if timed_out {
                "timeout_budget_exhausted".to_string()
            } else if instruction_count != 0 {
                "instruction_budget_exhausted".to_string()
            } else {
                "returned_without_done_addr".to_string()
            };
            emit_stop_status("ok", &detail, emulator);
        }
        Err(e) => {
            let pc = emulator.read_reg("pc").unwrap_or(0);
            let x1 = emulator.read_reg("x1").unwrap_or(0);
            let msg = e.to_string();
            let graceful_reason = if (msg.contains("FETCH_UNMAPPED")
                || msg.contains("Invalid memory fetch"))
                && (pc == 0 || pc == 1)
            {
                Some("Treating return from entry as graceful stop")
            } else if report.saw_exit.load(std::sync::atomic::Ordering::Relaxed)
                && (msg.contains("UNMAPPED") || msg.contains("Invalid memory"))
                && pc >= report.stub_base
                && pc < report.stub_base + report.stub_size
            {
                Some("Treating post-exit stub tail as graceful stop")
            } else if report.saw_exit.load(std::sync::atomic::Ordering::Relaxed)
                && (msg.contains("WRITE_UNMAPPED") || msg.contains("Invalid memory write"))
                && x1 == 0x3EA
            {
                Some("Treating post-exit Go fatal tail as graceful stop")
            } else if pc >= report.stack_base
                && pc < report.stack_base + report.stack_size
                && (msg.contains("INSN_INVALID")
                    || msg.contains("Invalid instruction")
                    || msg.contains("FETCH")
                    || msg.contains("Invalid memory fetch"))
            {
                Some("Treating stack-return tail as graceful stop")
            } else {
                None
            };

            if graceful_reason.is_some() {
                emit_stop_status("graceful", graceful_reason.unwrap_or("graceful"), emulator);
                return Ok(());
            }

            emit_stop_status("error", &msg, emulator);
            return Err(format!("Emulation stopped with error: {}", e).into());
        }
    }

    Ok(())
}
