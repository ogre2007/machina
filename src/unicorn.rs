macro_rules! eprintln {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::eprintln!($($arg)*);
        }
    };
}

macro_rules! println {
    ($($arg:tt)*) => {
        if crate::macos::debug_stdout_enabled() {
            std::println!($($arg)*);
        }
    };
}

use std::any::Any;
use std::sync::{Arc, Mutex};

use unicorn_engine::{unicorn_const::HookType, Arch, MemType, Mode, Prot, RegisterARM64, Unicorn};

use crate::macos::arm64_runner_support::{arm64_memory_event, emit_arm64_event};
use crate::macos::os::{ArchType, Emulator as EmulatorTrait, LogLevel, MacOsError};
use crate::SharedTraceBus;

#[derive(Clone, Copy)]
struct LazyMapRegion {
    start: u64,
    end: u64,
    prot: Prot,
}

fn format_memory_value(value: i64, size: usize) -> String {
    if size == 0 {
        return "[]".to_string();
    }
    let bytes = value.to_le_bytes();
    let take = size.min(bytes.len());
    let rendered = bytes[..take]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    format!("[{}]", rendered)
}

fn canonicalize_tagged_addr(addr: u64, pc: u64) -> Vec<u64> {
    let low32 = addr & 0xFFFF_FFFF;
    let pc_high = pc & 0xFFFF_FFFF_0000_0000;
    let mut candidates = Vec::with_capacity(3);
    candidates.push(low32);
    if pc_high != 0 {
        candidates.push(pc_high | low32);
    }
    candidates.push(0x1_0000_0000 | low32);
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn arm64_mem_base_reg(instr: u32) -> Option<u8> {
    let top = ((instr >> 24) & 0xFF) as u8;
    match top {
        0x28 | 0x29 | 0x68 | 0x69 | 0xA8 | 0xA9 | 0xE8 | 0xE9 | 0x38 | 0x39 | 0x78 | 0x79
        | 0xB8 | 0xB9 | 0xF8 | 0xF9 => Some(((instr >> 5) & 0x1F) as u8),
        _ => None,
    }
}

fn arm64_reg_id(reg: u8) -> Option<i32> {
    Some(match reg {
        0 => RegisterARM64::X0 as i32,
        1 => RegisterARM64::X1 as i32,
        2 => RegisterARM64::X2 as i32,
        3 => RegisterARM64::X3 as i32,
        4 => RegisterARM64::X4 as i32,
        5 => RegisterARM64::X5 as i32,
        6 => RegisterARM64::X6 as i32,
        7 => RegisterARM64::X7 as i32,
        8 => RegisterARM64::X8 as i32,
        9 => RegisterARM64::X9 as i32,
        10 => RegisterARM64::X10 as i32,
        11 => RegisterARM64::X11 as i32,
        12 => RegisterARM64::X12 as i32,
        13 => RegisterARM64::X13 as i32,
        14 => RegisterARM64::X14 as i32,
        15 => RegisterARM64::X15 as i32,
        16 => RegisterARM64::X16 as i32,
        17 => RegisterARM64::X17 as i32,
        18 => RegisterARM64::X18 as i32,
        19 => RegisterARM64::X19 as i32,
        20 => RegisterARM64::X20 as i32,
        21 => RegisterARM64::X21 as i32,
        22 => RegisterARM64::X22 as i32,
        23 => RegisterARM64::X23 as i32,
        24 => RegisterARM64::X24 as i32,
        25 => RegisterARM64::X25 as i32,
        26 => RegisterARM64::X26 as i32,
        27 => RegisterARM64::X27 as i32,
        28 => RegisterARM64::X28 as i32,
        29 => RegisterARM64::FP as i32,
        30 => RegisterARM64::LR as i32,
        31 => RegisterARM64::SP as i32,
        _ => return None,
    })
}

fn rewrite_tagged_mem_base<'a>(
    uc: &mut Unicorn<'a, ()>,
    instr: u32,
    fault_addr: u64,
    pc: u64,
) -> Option<(u8, u64, u64)> {
    if fault_addr < 0x1000 || (fault_addr >> 48) == 0 {
        return None;
    }
    let reg = arm64_mem_base_reg(instr)?;
    let reg_id = arm64_reg_id(reg)?;
    let base = uc.reg_read(reg_id).ok()?;
    for candidate in canonicalize_tagged_addr(fault_addr, pc) {
        if uc.mem_read_as_vec(candidate, 1).is_err() {
            continue;
        }
        let delta = fault_addr.wrapping_sub(base);
        let rewritten = candidate.wrapping_sub(delta);
        uc.reg_write(reg_id, rewritten).ok()?;
        return Some((reg, base, rewritten));
    }
    None
}

fn map_tagged_alias_page<'a>(
    uc: &mut Unicorn<'a, ()>,
    fault_addr: u64,
    pc: u64,
) -> Option<(u64, u64)> {
    if (fault_addr >> 48) == 0 {
        return None;
    }
    let alias_page = fault_addr & !0xFFF;
    let page_off = (fault_addr & 0xFFF) as usize;
    for candidate in canonicalize_tagged_addr(fault_addr, pc) {
        let source_page = candidate & !0xFFF;
        let Ok(page) = uc.mem_read_as_vec(source_page, 0x1000) else {
            continue;
        };
        if page_off >= page.len() {
            continue;
        }
        if uc
            .mem_map(alias_page, 0x1000, Prot::READ | Prot::WRITE | Prot::EXEC)
            .is_err()
            && uc.mem_read_as_vec(alias_page, 1).is_err()
        {
            continue;
        }
        if uc.mem_write(alias_page, &page).is_err() {
            continue;
        }
        return Some((fault_addr, candidate));
    }
    None
}

/// Map a fresh writable page at an "off-canvas" tagged data address.
///
/// `map_tagged_alias_page` only fires when bits 48+ of the fault address are
/// set (TBI top-byte tagging). Rust binaries also produce wide tagged
/// pointers in lower nibbles — for example RustDoor's post-`waitpid`
/// `WaitStatus` write at `[x19, #8]` resolves to `0xA0000000A` because the
/// caller packs an enum discriminant into bits 32–35. The canonical low-32
/// candidate (`0xA`) is in PAGEZERO and the high-only candidate is unmapped,
/// so the existing alias mapper gives up and the run fails on
/// `WRITE_UNMAPPED`.
///
/// As a permissive fallback, when a data fault hits an address that is
/// clearly above the legitimate user-space heap/mmap arena (high bits 32–47
/// non-zero) and below the TBI range, just synthesize a writable page so the
/// store can proceed. This is a "ghost" page — reads later return whatever
/// the program wrote — which is enough to let the emulation move past these
/// pointer-tagged structs into the malware's interesting behavior.
fn map_off_canvas_data_page<'a>(
    uc: &mut Unicorn<'a, ()>,
    fault_addr: u64,
) -> Option<u64> {
    // Only kick in for pointers far outside any mapped region; bail early
    // for anything Unicorn would already accept (low-32 or kernel-tag).
    if fault_addr < 0x1_0000_0000 {
        return None;
    }
    if (fault_addr >> 48) != 0 {
        // Already covered by `map_tagged_alias_page`.
        return None;
    }
    let alias_page = fault_addr & !0xFFF;
    if uc.mem_read_as_vec(alias_page, 1).is_ok() {
        return None;
    }
    if uc
        .mem_map(alias_page, 0x1000, Prot::READ | Prot::WRITE)
        .is_err()
    {
        return None;
    }
    Some(alias_page)
}

/// After mapping a copy of a canonical page at the tagged PC alias, also
/// redirect PC to the canonical address. Without this, instructions in the
/// alias page execute with PC-relative addressing producing more tagged
/// faults for every `bl`, `b`, or `adrp` — the tag propagates forward and
/// the binary spends the entire instruction budget faulting through tagged
/// pages instead of running real code.
fn rewrite_tagged_fetch_pc<'a>(
    uc: &mut Unicorn<'a, ()>,
    fault_addr: u64,
    pc: u64,
    canonical: u64,
) -> Option<(u64, u64)> {
    if pc != fault_addr || canonical == fault_addr {
        return None;
    }
    if uc.mem_read_as_vec(canonical, 4).is_err() {
        return None;
    }
    uc.reg_write(RegisterARM64::PC as i32, canonical).ok()?;
    Some((fault_addr, canonical))
}

pub struct UnicornEmulator {
    uc: Unicorn<'static, ()>,
    arch: ArchType,
    automap_low_page: bool,
    lazy_map_regions: Arc<Mutex<Vec<LazyMapRegion>>>,
    lazy_map_hook_installed: bool,
    syscall_handler:
        Option<Box<dyn FnMut(&mut dyn EmulatorTrait) -> Result<i64, MacOsError> + Send + 'static>>,
    syscall_hooks_installed: bool,
}

impl UnicornEmulator {
    pub fn new(arch: ArchType) -> Result<Self, MacOsError> {
        let uc = Unicorn::new(Arch::ARM64, Mode::ARM)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to create unicorn: {}", e)))?;

        Ok(Self {
            uc,
            arch,
            automap_low_page: false,
            lazy_map_regions: Arc::new(Mutex::new(Vec::new())),
            lazy_map_hook_installed: false,
            syscall_handler: None,
            syscall_hooks_installed: false,
        })
    }

    pub fn new_arm64() -> Result<Self, MacOsError> {
        Self::new(ArchType::Arm64)
    }

    pub fn map_code_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE | Prot::EXEC)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn map_memory_with_prot(
        &mut self,
        addr: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, prot)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn map_data_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn protect_memory(&mut self, addr: u64, size: u64, prot: Prot) -> Result<(), MacOsError> {
        self.uc
            .mem_protect(addr, size, prot)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to protect memory: {}", e)))
    }

    pub fn reserve_lazy_data_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.reserve_lazy_memory(addr, size, Prot::READ | Prot::WRITE)
    }

    pub fn reserve_lazy_memory(
        &mut self,
        addr: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MacOsError> {
        self.ensure_lazy_map_hook()?;
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        let mut regions = self
            .lazy_map_regions
            .lock()
            .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
        regions.push(LazyMapRegion { start, end, prot });
        Ok(())
    }

    pub fn unmap_lazy_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        {
            let mut regions = self
                .lazy_map_regions
                .lock()
                .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
            let mut next = Vec::with_capacity(regions.len());
            for region in regions.iter().copied() {
                if end <= region.start || start >= region.end {
                    next.push(region);
                    continue;
                }
                if start > region.start {
                    next.push(LazyMapRegion {
                        start: region.start,
                        end: start,
                        prot: region.prot,
                    });
                }
                if end < region.end {
                    next.push(LazyMapRegion {
                        start: end,
                        end: region.end,
                        prot: region.prot,
                    });
                }
            }
            *regions = next;
        }

        let mut cur = start;
        while cur < end {
            let _ = self.uc.mem_unmap(cur, 0x1000);
            cur = cur.saturating_add(0x1000);
        }
        Ok(())
    }

    pub fn protect_lazy_memory(
        &mut self,
        addr: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MacOsError> {
        let start = addr & !0xFFF;
        let end = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        {
            let mut regions = self
                .lazy_map_regions
                .lock()
                .map_err(|_| MacOsError::Unicorn("Failed to lock lazy map regions".to_string()))?;
            let mut next = Vec::with_capacity(regions.len() + 2);
            let mut covered = false;
            for region in regions.iter().copied() {
                if end <= region.start || start >= region.end {
                    next.push(region);
                    continue;
                }
                if start > region.start {
                    next.push(LazyMapRegion {
                        start: region.start,
                        end: start,
                        prot: region.prot,
                    });
                }
                next.push(LazyMapRegion {
                    start: start.max(region.start),
                    end: end.min(region.end),
                    prot,
                });
                if end < region.end {
                    next.push(LazyMapRegion {
                        start: end,
                        end: region.end,
                        prot: region.prot,
                    });
                }
                covered = true;
            }
            if !covered {
                next.push(LazyMapRegion { start, end, prot });
            }
            *regions = next;
        }

        let mut cur = start;
        while cur < end {
            let _ = self.uc.mem_protect(cur, 0x1000, prot);
            cur = cur.saturating_add(0x1000);
        }
        Ok(())
    }

    pub fn map_writable_code_memory(&mut self, addr: u64, size: u64) -> Result<(), MacOsError> {
        self.uc
            .mem_map(addr, size, Prot::READ | Prot::WRITE | Prot::EXEC)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to map memory: {}", e)))
    }

    pub fn add_code_hook<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<(), MacOsError>
    where
        F: Fn(&mut UnicornEmulator, u64, u32) + Send + 'static,
    {
        let self_ptr: *mut UnicornEmulator = self as *mut UnicornEmulator;
        self.uc
            .add_code_hook(begin, end, move |_uc, addr, size| unsafe {
                callback(&mut *self_ptr, addr, size);
            })
            .map(|_| ())
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add code hook: {}", e)))
    }

    fn ensure_syscall_hooks(&mut self) -> Result<(), MacOsError> {
        if !(self.syscall_handler.is_some() && !self.syscall_hooks_installed) {
            return Ok(());
        }

        let self_ptr: *mut UnicornEmulator = self as *mut UnicornEmulator;
        match self.arch {
            ArchType::Arm64 => {
                self.uc
                    .add_intr_hook(move |_uc, intno| unsafe {
                        // AArch64 SVC triggers interrupt number 2 in Unicorn.
                        if intno != 2 {
                            let emu = &mut *self_ptr;
                            let _ = emu.uc.emu_stop();
                            return;
                        }
                        let emu = &mut *self_ptr;
                        let mut handler_opt = emu.syscall_handler.take();
                        if let Some(mut handler) = handler_opt.take() {
                            let _ = handler(emu);
                            emu.syscall_handler = Some(handler);
                        }
                    })
                    .map_err(|e| {
                        MacOsError::Unicorn(format!("Failed to add ARM64 interrupt hook: {}", e))
                    })?;
            }
        }
        self.syscall_hooks_installed = true;
        Ok(())
    }

    fn ensure_lazy_map_hook(&mut self) -> Result<(), MacOsError> {
        if self.lazy_map_hook_installed {
            return Ok(());
        }

        let lazy_map_regions = self.lazy_map_regions.clone();
        self.uc
            .add_mem_hook(
                HookType::MEM_UNMAPPED,
                1,
                0,
                move |uc, _mem_type, addr, size, _value| {
                    let page_start = addr & !0xFFF;
                    let page_end =
                        (addr.saturating_add(size as u64).saturating_add(0xFFF)) & !0xFFF;
                    let region = {
                        let regions = match lazy_map_regions.lock() {
                            Ok(guard) => guard,
                            Err(_) => return false,
                        };
                        regions
                            .iter()
                            .find(|region| addr >= region.start && addr < region.end)
                            .copied()
                    };
                    let Some(region) = region else {
                        return false;
                    };

                    let map_start = page_start.max(region.start);
                    let map_end = page_end.min(region.end);
                    if map_start >= map_end {
                        return false;
                    }

                    let mut cur = map_start;
                    while cur < map_end {
                        match uc.mem_map(cur, 0x1000, region.prot) {
                            Ok(()) => {}
                            Err(_) => {
                                if uc.mem_read_as_vec(cur, 1).is_err() {
                                    return false;
                                }
                            }
                        }
                        cur = cur.saturating_add(0x1000);
                    }
                    true
                },
            )
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add lazy map hook: {}", e)))?;
        self.lazy_map_hook_installed = true;
        Ok(())
    }

    pub fn run_with_limits(
        &mut self,
        begin: u64,
        end: Option<u64>,
        timeout_usecs: u64,
        instruction_count: usize,
    ) -> Result<(), MacOsError> {
        self.ensure_syscall_hooks()?;

        self.uc
            .emu_start(
                begin,
                end.unwrap_or(u64::MAX),
                timeout_usecs,
                instruction_count,
            )
            .map_err(|e| MacOsError::Unicorn(format!("Emulation failed: {}", e)))
    }

    pub fn stop_emulation(&mut self) -> Result<(), MacOsError> {
        self.uc
            .emu_stop()
            .map_err(|e| MacOsError::Unicorn(format!("Failed to stop emulation: {}", e)))
    }

    pub fn install_unmapped_memory_debug_hook(
        &mut self,
        trace_bus: &Option<SharedTraceBus>,
    ) -> Result<(), MacOsError> {
        let arch = self.arch;
        let automap_low_page = self.automap_low_page;
        let lazy_map_regions = self.lazy_map_regions.clone();
        let trace_bus_for_memhook = trace_bus.clone();
        self.uc
            .add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, move |uc, mem_type, addr, size, value| {
                let (pc_reg, sp_reg): (i32, i32) = match arch {
                    ArchType::Arm64 => (RegisterARM64::PC as i32, RegisterARM64::SP as i32),
                };
                let pc = uc.reg_read(pc_reg).unwrap_or(0);
                let sp = uc.reg_read(sp_reg).unwrap_or(0);
                let instr = uc
                    .mem_read_as_vec(pc, 4)
                    .ok()
                    .and_then(|raw| <[u8; 4]>::try_from(raw.as_slice()).ok())
                    .map(u32::from_le_bytes);
                if let Some(instr) = instr {
                    if let Some((reg, original, rewritten)) =
                        rewrite_tagged_mem_base(uc, instr, addr, pc)
                    {
                        let alias = map_tagged_alias_page(uc, addr, pc);
                        let mut event = arm64_memory_event("tagged-pointer-rewrite")
                            .arg("FaultAddr", format!("0x{:X}", addr))
                            .arg("Reg", format!("x{}", reg))
                            .arg("Original", format!("0x{:X}", original))
                            .arg("Rewritten", format!("0x{:X}", rewritten))
                            .arg("Memtype", format!("{:?}", mem_type))
                            .arg("pc", format!("0x{:X}", pc));
                        if let Some((fault_addr, candidate)) = alias {
                            event = event
                                .arg("AliasFaultAddr", format!("0x{:X}", fault_addr))
                                .arg("AliasCandidate", format!("0x{:X}", candidate));
                        }
                        emit_arm64_event(&trace_bus_for_memhook, event);
                        return true;
                    }
                }
                if let Some((fault_addr, candidate)) = map_tagged_alias_page(uc, addr, pc) {
                    let mut event = arm64_memory_event("tagged-pointer-alias")
                        .arg("FaultAddr", format!("0x{:X}", fault_addr))
                        .arg("Candidate", format!("0x{:X}", candidate))
                        .arg("Memtype", format!("{:?}", mem_type))
                        .arg("pc", format!("0x{:X}", pc));
                    if matches!(mem_type, MemType::FETCH_UNMAPPED) && pc == fault_addr {
                        if let Some((rewrote_from, rewrote_to)) =
                            rewrite_tagged_fetch_pc(uc, fault_addr, pc, candidate)
                        {
                            event = event
                                .arg("PcRewriteFrom", format!("0x{:X}", rewrote_from))
                                .arg("PcRewriteTo", format!("0x{:X}", rewrote_to));
                        }
                    }
                    emit_arm64_event(&trace_bus_for_memhook, event);
                    return true;
                }
                if matches!(
                    mem_type,
                    MemType::WRITE_UNMAPPED | MemType::READ_UNMAPPED
                ) {
                    if let Some(alias_page) = map_off_canvas_data_page(uc, addr) {
                        let event = arm64_memory_event("off-canvas-data-page")
                            .arg("FaultAddr", format!("0x{:X}", addr))
                            .arg("AliasPage", format!("0x{:X}", alias_page))
                            .arg("Memtype", format!("{:?}", mem_type))
                            .arg("pc", format!("0x{:X}", pc));
                        emit_arm64_event(&trace_bus_for_memhook, event);
                        return true;
                    }
                }
                let code = uc.mem_read_as_vec(pc, 8).unwrap_or_default();
                let value_bytes = format_memory_value(value, size as usize);
                let is_lazy_reserved_touch = {
                    let regions = match lazy_map_regions.lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            eprintln!("[UNMAPPED] failed to lock lazy map regions");
                            return false;
                        }
                    };
                    regions.iter().any(|region| addr >= region.start && addr < region.end)
                };
                let is_go_post_exit_tail = matches!(arch, ArchType::Arm64)
                    && matches!(mem_type, MemType::WRITE_UNMAPPED)
                    && addr == 0x3ea;
                if is_go_post_exit_tail {
                    eprintln!(
                        "[UNMAPPED][{:?}] expected Go post-exit tail addr=0x{:x} size={} value=0x{:x} bytes={} pc=0x{:x} sp=0x{:x} code={:02x?}",
                        arch, addr, size, value as u64, value_bytes, pc, sp, code
                    );
                } else if is_lazy_reserved_touch {
                let event = arm64_memory_event("Lazymap_write")
                    .arg("Addr", format!("0x{:X}", addr))
                    .arg("Size", format!("0x{:X}", size))
                    .arg("Memtype", format!("{:?}", mem_type)) 
                    .arg("Value", format!("0x{:X}", value))
                                        .arg("Bytes", format!("{}", value_bytes))

                    .arg("pc", format!("0x{:X}", pc))
                    .arg("Code", format!("{:02x?}", code));
                emit_arm64_event(&trace_bus_for_memhook, event);
                } else {
                    eprintln!(
                        "[UNMAPPED][{:?}] kind={:?} addr=0x{:x} size={} value=0x{:x} bytes={} pc=0x{:x} sp=0x{:x} code={:02x?}",
                        arch, mem_type, addr, size, value as u64, value_bytes, pc, sp, code
                    );
                }
                if automap_low_page && addr < 0x1000 {
                    let _ = uc.mem_map(0, 0x1000, Prot::READ | Prot::WRITE);
                    return true;
                }
                false
            })
            .map(|_| ())
            .map_err(|e| MacOsError::Unicorn(format!("Failed to add unmapped memory hook: {}", e)))
    }

    pub fn set_automap_low_page(&mut self, enabled: bool) {
        self.automap_low_page = enabled;
    }
}

impl EmulatorTrait for UnicornEmulator {
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, MacOsError> {
        let mut data = vec![0u8; size];
        self.uc
            .mem_read(addr, &mut data)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to read memory: {}", e)))?;
        Ok(data)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MacOsError> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| MacOsError::Unicorn(format!("Failed to write memory: {}", e)))
    }

    fn read_reg(&self, reg: &str) -> Result<u64, MacOsError> {
        match self.arch {
            ArchType::Arm64 => {
                let rid = match reg {
                    "x0" => RegisterARM64::X0,
                    "x1" => RegisterARM64::X1,
                    "x2" => RegisterARM64::X2,
                    "x3" => RegisterARM64::X3,
                    "x4" => RegisterARM64::X4,
                    "x5" => RegisterARM64::X5,
                    "x6" => RegisterARM64::X6,
                    "x7" => RegisterARM64::X7,
                    "x8" => RegisterARM64::X8,
                    "x9" => RegisterARM64::X9,
                    "x10" => RegisterARM64::X10,
                    "x11" => RegisterARM64::X11,
                    "x12" => RegisterARM64::X12,
                    "x13" => RegisterARM64::X13,
                    "x14" => RegisterARM64::X14,
                    "x15" => RegisterARM64::X15,
                    "x16" => RegisterARM64::X16,
                    "x17" => RegisterARM64::X17,
                    "x18" => RegisterARM64::X18,
                    "x19" => RegisterARM64::X19,
                    "x20" => RegisterARM64::X20,
                    "x21" => RegisterARM64::X21,
                    "x22" => RegisterARM64::X22,
                    "x23" => RegisterARM64::X23,
                    "x24" => RegisterARM64::X24,
                    "x25" => RegisterARM64::X25,
                    "x26" => RegisterARM64::X26,
                    "x27" => RegisterARM64::X27,
                    "x28" => RegisterARM64::X28,
                    "tpidr_el0" => RegisterARM64::TPIDR_EL0,
                    "tpidrro_el0" => RegisterARM64::TPIDRRO_EL0,
                    "fp" => RegisterARM64::FP,
                    "lr" => RegisterARM64::LR,
                    "sp" => RegisterARM64::SP,
                    "pc" => RegisterARM64::PC,
                    _ => {
                        return Err(MacOsError::InvalidArgument(format!(
                            "Unknown register: {}",
                            reg
                        )))
                    }
                };
                self.uc
                    .reg_read(rid)
                    .map_err(|e| MacOsError::Unicorn(format!("Failed to read register: {}", e)))
            }
        }
    }

    fn write_reg(&mut self, reg: &str, value: u64) -> Result<(), MacOsError> {
        match self.arch {
            ArchType::Arm64 => {
                let rid = match reg {
                    "x0" => RegisterARM64::X0,
                    "x1" => RegisterARM64::X1,
                    "x2" => RegisterARM64::X2,
                    "x3" => RegisterARM64::X3,
                    "x4" => RegisterARM64::X4,
                    "x5" => RegisterARM64::X5,
                    "x6" => RegisterARM64::X6,
                    "x7" => RegisterARM64::X7,
                    "x8" => RegisterARM64::X8,
                    "x9" => RegisterARM64::X9,
                    "x10" => RegisterARM64::X10,
                    "x11" => RegisterARM64::X11,
                    "x12" => RegisterARM64::X12,
                    "x13" => RegisterARM64::X13,
                    "x14" => RegisterARM64::X14,
                    "x15" => RegisterARM64::X15,
                    "x16" => RegisterARM64::X16,
                    "x17" => RegisterARM64::X17,
                    "x18" => RegisterARM64::X18,
                    "x19" => RegisterARM64::X19,
                    "x20" => RegisterARM64::X20,
                    "x21" => RegisterARM64::X21,
                    "x22" => RegisterARM64::X22,
                    "x23" => RegisterARM64::X23,
                    "x24" => RegisterARM64::X24,
                    "x25" => RegisterARM64::X25,
                    "x26" => RegisterARM64::X26,
                    "x27" => RegisterARM64::X27,
                    "x28" => RegisterARM64::X28,
                    "tpidr_el0" => RegisterARM64::TPIDR_EL0,
                    "tpidrro_el0" => RegisterARM64::TPIDRRO_EL0,
                    "fp" => RegisterARM64::FP,
                    "lr" => RegisterARM64::LR,
                    "sp" => RegisterARM64::SP,
                    "pc" => RegisterARM64::PC,
                    _ => {
                        return Err(MacOsError::InvalidArgument(format!(
                            "Unknown register: {}",
                            reg
                        )))
                    }
                };
                self.uc
                    .reg_write(rid, value)
                    .map_err(|e| MacOsError::Unicorn(format!("Failed to write register: {}", e)))
            }
        }
    }

    fn stack_push(&mut self, value: u64) -> Result<(), MacOsError> {
        let sp = self.read_reg("sp")?;
        let new_sp = sp - 8;
        self.write_memory(new_sp, &value.to_le_bytes())?;
        self.write_reg("sp", new_sp)
    }

    fn stack_pop(&mut self) -> Result<u64, MacOsError> {
        let sp = self.read_reg("sp")?;
        let data = self.read_memory(sp, 8)?;
        let value = u64::from_le_bytes(data[..8].try_into().unwrap());
        self.write_reg("sp", sp + 8)?;
        Ok(value)
    }

    fn stack_read(&self, offset: i64) -> Result<u64, MacOsError> {
        let sp = self.read_reg("sp")?;
        let addr = (sp as i64 + offset) as u64;
        let data = self.read_memory(addr, 8)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    fn hook_syscall(
        &mut self,
        handler: Box<dyn FnMut(&mut dyn EmulatorTrait) -> Result<i64, MacOsError> + Send>,
    ) {
        self.syscall_handler = Some(handler);
    }

    fn run(&mut self, begin: u64, end: Option<u64>) -> Result<(), MacOsError> {
        self.run_with_limits(begin, end, 0, 0)
    }

    fn arch_type(&self) -> ArchType {
        self.arch
    }

    fn log(&mut self, level: LogLevel, msg: &str) {
        match level {
            LogLevel::Debug => println!("[DEBUG] {}", msg),
            LogLevel::Info => println!("[INFO] {}", msg),
            LogLevel::Warn => println!("[WARN] {}", msg),
            LogLevel::Error => println!("[ERROR] {}", msg),
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
