//! Binary-specific setup helpers for the legacy arm64 runner.

use std::collections::HashMap;

use crate::macos::{
    patch_section64_u64_slots, process_event, runtime_process_metadata, trim_name, SharedTraceBus,
};
use crate::{Emulator, MachoBinary, UnicornEmulator};

#[derive(Clone, Copy, Debug, Default)]
pub struct Arm64RuntimeSymbols {
    pub tls_g: Option<u64>,
    pub firstmoduledata: Option<u64>,
    pub libc_close_trampoline: Option<u64>,
    pub libc_dup2_trampoline: Option<u64>,
    pub libc_execve_trampoline: Option<u64>,
}

pub fn find_arm64_runtime_symbols(binary: &MachoBinary) -> Arm64RuntimeSymbols {
    Arm64RuntimeSymbols {
        tls_g: crate::macos::find_symbol_address(binary, "_runtime.tls_g"),
        firstmoduledata: crate::macos::find_symbol_address(binary, "_runtime.firstmoduledata"),
        libc_close_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_close_trampoline",
        ),
        libc_dup2_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_dup2_trampoline",
        ),
        libc_execve_trampoline: crate::macos::find_symbol_address(
            binary,
            "syscall.libc_execve_trampoline",
        ),
    }
}

pub fn log_arm64_runtime_symbols(
    symbols: Arm64RuntimeSymbols,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) {
    if let Some(addr) = symbols.tls_g {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "runtime-symbol",
            "runtime_symbol",
            &[
                ("Name", "_runtime.tls_g".to_string()),
                ("Address", format!("0x{:X}", addr)),
            ],
        );
    }
    if let Some(addr) = symbols.firstmoduledata {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "runtime-symbol",
            "runtime_symbol",
            &[
                ("Name", "_runtime.firstmoduledata".to_string()),
                ("Address", format!("0x{:X}", addr)),
            ],
        );
    }
}

pub fn patch_arm64_symbol_pointers(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    undefs: &[(String, u8)],
    stub_map: &HashMap<String, u64>,
    done_addr: u64,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let patch_section = |emulator: &mut UnicornEmulator,
                         section: &crate::macos::loader::command::Section64,
                         section_name: &str|
     -> Result<(), Box<dyn std::error::Error>> {
        let addr = section.addr;
        let size = section.size;
        if size == 0 {
            return Ok(());
        }
        let page_size = 0x1000;
        let aligned_size = ((size + page_size - 1) / page_size) * page_size;
        let _ = emulator.map_writable_code_memory(addr, aligned_size);
        let patched = patch_section64_u64_slots(emulator, binary, section, |_, _, sym_name, _| {
            Some(
                sym_name
                    .and_then(|name| stub_map.get(&name).copied())
                    .unwrap_or(done_addr),
            )
        });
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            section_name,
            "patch_symbol_pointers",
            &[
                ("Section", section_name.to_string()),
                ("Address", format!("0x{:X}", addr)),
                ("Count", patched.to_string()),
            ],
        );
        Ok(())
    };

    if let Some(la_symbol_ptr) = binary.get_lazy_symbol_ptr_section() {
        patch_section(emulator, la_symbol_ptr, "__la_symbol_ptr")?;
    }

    if let Some(nl_symbol_ptr) = binary.get_nl_symbol_ptr_section() {
        patch_section(emulator, nl_symbol_ptr, "__nl_symbol_ptr")?;
    }

    for (segment, section_name) in [
        ("__DATA", "__got"),
        ("__DATA_CONST", "__got"),
        ("__AUTH_CONST", "__auth_got"),
        ("__DATA", "__auth_got"),
        ("__AUTH", "__auth_got"),
    ] {
        if let Some(section) = binary.get_section(segment, section_name) {
            patch_section(emulator, section, section_name)?;
        }
    }

    let mut chained_like_patched = 0u64;
    let image_base = binary
        .segments
        .iter()
        .filter(|seg| seg.segname_str() != "__PAGEZERO" && seg.vmaddr != 0)
        .map(|seg| seg.vmaddr)
        .min()
        .unwrap_or(0x1000_00000);
    let mapped_ranges = binary
        .segments
        .iter()
        .filter(|seg| seg.segname_str() != "__PAGEZERO" && seg.vmsize != 0)
        .map(|seg| (seg.vmaddr, seg.vmaddr.saturating_add(seg.vmsize)))
        .collect::<Vec<_>>();
    let mut signed_code_ptrs_patched = 0u64;
    for segment in &binary.segments {
        let seg_name = segment.segname_str();
        if !matches!(
            seg_name.as_str(),
            "__DATA" | "__DATA_CONST" | "__AUTH" | "__AUTH_CONST"
        ) {
            continue;
        }
        for section in &segment.sections {
            let sect_name = trim_name(&section.sectname);
            if sect_name == "__thread_vars" {
                let Some(tlv_bootstrap_addr) = stub_map.get("__tlv_bootstrap").copied() else {
                    continue;
                };
                let count = section.size / 0x18;
                for i in 0..count {
                    let slot_addr = section.addr + i * 0x18;
                    let _ = emulator.write_memory(slot_addr, &tlv_bootstrap_addr.to_le_bytes());
                    chained_like_patched += 1;
                }
                continue;
            }
            if !matches!(
                sect_name.as_str(),
                "__data" | "__const" | "__auth_ptr" | "__objc_data" | "__objc_selrefs"
            ) {
                continue;
            }
            let count = section.size / 8;
            for i in 0..count {
                let slot_addr = section.addr + i * 8;
                let Ok(bytes) = emulator.read_memory(slot_addr, 8) else {
                    continue;
                };
                let Ok(raw) = <[u8; 8]>::try_from(bytes.as_slice()) else {
                    continue;
                };
                let raw_value = u64::from_le_bytes(raw);
                if (raw_value & 0x8000_0000_0000_0000) == 0 {
                    continue;
                }
                let ordinal = (raw_value & 0xFFFF) as usize;
                if let Some((sym_name, _)) = undefs.get(ordinal) {
                    let target = stub_map.get(sym_name).copied().unwrap_or(done_addr);
                    let _ = emulator.write_memory(slot_addr, &target.to_le_bytes());
                    chained_like_patched += 1;
                    continue;
                }

                if let Some(target) =
                    sanitize_arm64_signed_code_pointer(raw_value, image_base, &mapped_ranges)
                {
                    let _ = emulator.write_memory(slot_addr, &target.to_le_bytes());
                    signed_code_ptrs_patched += 1;
                }
            }
        }
    }
    if chained_like_patched > 0 {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "chained-bind-like",
            "patch_symbol_pointers",
            &[
                ("Section", "data-auth-bind".to_string()),
                ("Count", chained_like_patched.to_string()),
            ],
        );
    }
    if signed_code_ptrs_patched > 0 {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "signed-code-pointers",
            "patch_symbol_pointers",
            &[
                ("Section", "data-signed-code".to_string()),
                ("Count", signed_code_ptrs_patched.to_string()),
            ],
        );
    }

    Ok(())
}

pub fn install_arm64_lse_atomic_hooks(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(text) = binary.get_section("__TEXT", "__text") else {
        return Ok(());
    };
    if text.size == 0 {
        return Ok(());
    }

    let bytes = emulator.read_memory(text.addr, text.size as usize)?;
    let mut installed = 0u64;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if !is_arm64_lse_cas(word) && !is_arm64_lse_ldadd(word) && !is_arm64_ldapr(word) {
            continue;
        }
        let hook_addr = text.addr + (index as u64 * 4);
        let trace_bus_for_hook = trace_bus.clone();
        let process_name = process_name.to_string();
        emulator.add_code_hook(
            hook_addr,
            hook_addr + 4,
            move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                let Ok(raw) = emu.read_memory(address, 4) else {
                    return;
                };
                let Ok(raw4) = <[u8; 4]>::try_from(raw.as_slice()) else {
                    return;
                };
                let instr = u32::from_le_bytes(raw4);
                let event = if is_arm64_lse_cas(instr) {
                    emulate_arm64_lse_cas(emu, instr)
                } else if is_arm64_lse_ldadd(instr) {
                    emulate_arm64_lse_ldadd(emu, instr)
                } else if is_arm64_ldapr(instr) {
                    emulate_arm64_ldapr(emu, instr)
                } else {
                    None
                };
                let Some(event) = event else {
                    return;
                };
                emit_arm64_binary_event(
                    &trace_bus_for_hook,
                    &process_name,
                    "lse-atomic",
                    "lse_atomic",
                    &event,
                );
            },
        )?;
        installed += 1;
    }

    if installed > 0 {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "lse-atomic-hooks",
            "install_lse_atomic_hooks",
            &[
                ("Section", "__TEXT.__text".to_string()),
                ("Count", installed.to_string()),
            ],
        );
    }

    Ok(())
}

pub fn install_arm64_indirect_branch_hooks(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(text) = binary.get_section("__TEXT", "__text") else {
        return Ok(());
    };
    if text.size == 0 {
        return Ok(());
    }

    let image_base = binary
        .segments
        .iter()
        .filter(|seg| seg.segname_str() != "__PAGEZERO" && seg.vmaddr != 0)
        .map(|seg| seg.vmaddr)
        .min()
        .unwrap_or(0x1000_00000);
    let mapped_ranges = binary
        .segments
        .iter()
        .filter(|seg| seg.segname_str() != "__PAGEZERO" && seg.vmsize != 0)
        .map(|seg| (seg.vmaddr, seg.vmaddr.saturating_add(seg.vmsize)))
        .collect::<Vec<_>>();

    let bytes = emulator.read_memory(text.addr, text.size as usize)?;
    let mut installed = 0u64;
    let mut load_sanitizers = 0u64;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let Some((kind, reg)) = decode_arm64_indirect_branch(word) else {
            continue;
        };
        let hook_addr = text.addr + (index as u64 * 4);
        if index > 0 {
            let prev = u32::from_le_bytes([
                bytes[(index - 1) * 4],
                bytes[(index - 1) * 4 + 1],
                bytes[(index - 1) * 4 + 2],
                bytes[(index - 1) * 4 + 3],
            ]);
            if let Some((rt, rn, imm)) = decode_arm64_ldr_uimm64(prev) {
                if rt == reg {
                    let trace_bus_for_load = trace_bus.clone();
                    let process_name = process_name.to_string();
                    let mapped_ranges = mapped_ranges.clone();
                    let load_addr = hook_addr - 4;
                    emulator.add_code_hook(
                        load_addr,
                        load_addr + 4,
                        move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                            let Some(base) = read_arm64_addr_reg(emu, rn) else {
                                return;
                            };
                            let slot_addr = base.saturating_add(imm);
                            let Ok(raw) = emu.read_memory(slot_addr, 8) else {
                                return;
                            };
                            let Ok(raw8) = <[u8; 8]>::try_from(raw.as_slice()) else {
                                return;
                            };
                            let current = u64::from_le_bytes(raw8);
                            let Some(sanitized) =
                                sanitize_arm64_indirect_target(current, image_base, &mapped_ranges)
                            else {
                                return;
                            };
                            if sanitized == current {
                                return;
                            }
                            let _ = emu.write_memory(slot_addr, &sanitized.to_le_bytes());
                            emit_arm64_binary_event(
                                &trace_bus_for_load,
                                &process_name,
                                "indirect-load-sanitize",
                                "indirect_load_sanitize",
                                &[
                                    ("Pc", format!("0x{:X}", address)),
                                    ("BranchReg", format!("x{}", reg)),
                                    ("BaseReg", format!("x{}", rn)),
                                    ("Slot", format!("0x{:X}", slot_addr)),
                                    ("Offset", format!("0x{:X}", imm)),
                                    ("Target", format!("0x{:X}", current)),
                                    ("Sanitized", format!("0x{:X}", sanitized)),
                                ],
                            );
                        },
                    )?;
                    load_sanitizers += 1;
                }
            }
        }
        let trace_bus_for_hook = trace_bus.clone();
        let process_name = process_name.to_string();
        let mapped_ranges = mapped_ranges.clone();
        emulator.add_code_hook(
            hook_addr,
            hook_addr + 4,
            move |emu: &mut machina::UnicornEmulator, address: u64, _size: u32| {
                let target = read_arm64_gpr(emu, reg, true).unwrap_or(0);
                let Some(sanitized) =
                    sanitize_arm64_indirect_target(target, image_base, &mapped_ranges)
                else {
                    return;
                };
                if sanitized == target {
                    return;
                }
                let reg_name = format!("x{}", reg);
                let _ = emu.write_reg(&reg_name, sanitized);
                emit_arm64_binary_event(
                    &trace_bus_for_hook,
                    &process_name,
                    "indirect-branch-sanitize",
                    "indirect_branch_sanitize",
                    &[
                        ("Kind", kind.to_string()),
                        ("Pc", format!("0x{:X}", address)),
                        ("Reg", format!("x{}", reg)),
                        ("Target", format!("0x{:X}", target)),
                        ("Sanitized", format!("0x{:X}", sanitized)),
                    ],
                );
            },
        )?;
        installed += 1;
    }

    if installed > 0 {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "indirect-branch-hooks",
            "install_indirect_branch_hooks",
            &[
                ("Section", "__TEXT.__text".to_string()),
                ("Count", installed.to_string()),
            ],
        );
    }
    if load_sanitizers > 0 {
        emit_arm64_binary_event(
            trace_bus,
            process_name,
            "indirect-load-hooks",
            "install_indirect_branch_hooks",
            &[
                ("Section", "__TEXT.__text".to_string()),
                ("Count", load_sanitizers.to_string()),
            ],
        );
    }

    Ok(())
}

pub fn resolve_arm64_entry(binary: &MachoBinary) -> u64 {
    let entry = binary.entry_point.unwrap_or(0);
    if entry >= 0x100000000 && entry < 0x300000000 {
        entry
    } else if let Some(seg) = binary.segments.iter().find(|s| s.segname_str() == "__TEXT") {
        seg.vmaddr + entry
    } else {
        entry
    }
}

fn emit_arm64_binary_event(
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
    name: impl Into<String>,
    call: impl Into<String>,
    args: &[(&str, String)],
) {
    if let Some(bus) = trace_bus {
        let mut event = process_event(
            &runtime_process_metadata(process_name.to_string()),
            name,
            call,
        );
        for (key, value) in args {
            event = event.arg(*key, value.clone());
        }
        let _ = bus.send(event);
    }
}

fn is_arm64_lse_cas(instr: u32) -> bool {
    let mask = (1u32 << 31)
        | (1u32 << 29)
        | (1u32 << 28)
        | (1u32 << 27)
        | (1u32 << 26)
        | (1u32 << 25)
        | (1u32 << 24)
        | (1u32 << 23)
        | (1u32 << 21)
        | (0x1Fu32 << 10);
    let value = (1u32 << 31) | (1u32 << 27) | (1u32 << 23) | (1u32 << 21) | (0x1Fu32 << 10);
    (instr & mask) == value
}

fn is_arm64_lse_ldadd(instr: u32) -> bool {
    // Atomic memory operation, LDADD/STADD family. This covers acquire/release
    // variants and both 32-bit and 64-bit forms.
    (instr & 0x3F20_F000) == 0x3820_0000
}

fn is_arm64_ldapr(instr: u32) -> bool {
    // LDAPR is an acquire load used by modern arm64 runtime code. Some Unicorn
    // builds do not advance it correctly, so emulate it as a plain load plus pc.
    (instr & 0x3FFF_FC00) == 0x38BF_C000
}

fn decode_arm64_indirect_branch(instr: u32) -> Option<(&'static str, u8)> {
    let reg = ((instr >> 5) & 0x1F) as u8;
    match instr & 0xFFFF_FC1F {
        0xD61F_0000 => Some(("br", reg)),
        0xD63F_0000 => Some(("blr", reg)),
        _ => None,
    }
}

fn decode_arm64_ldr_uimm64(instr: u32) -> Option<(u8, u8, u64)> {
    if (instr & 0xFFC0_0000) != 0xF940_0000 {
        return None;
    }
    let rt = (instr & 0x1F) as u8;
    let rn = ((instr >> 5) & 0x1F) as u8;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    Some((rt, rn, imm12 << 3))
}

fn sanitize_arm64_indirect_target(
    target: u64,
    image_base: u64,
    mapped_ranges: &[(u64, u64)],
) -> Option<u64> {
    if is_in_mapped_ranges(target, mapped_ranges) {
        return Some(target);
    }
    if (target >> 48) == 0 {
        return None;
    }
    let low32 = target & 0xFFFF_FFFF;
    let image_high = image_base & 0xFFFF_FFFF_0000_0000;
    let candidate = image_high | low32;
    if is_in_mapped_ranges(candidate, mapped_ranges) {
        return Some(candidate);
    }
    None
}

fn is_in_mapped_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| addr >= *start && addr < *end)
}

fn sanitize_arm64_signed_code_pointer(
    raw_value: u64,
    image_base: u64,
    mapped_ranges: &[(u64, u64)],
) -> Option<u64> {
    if is_in_mapped_ranges(raw_value, mapped_ranges) {
        return Some(raw_value);
    }
    if (raw_value >> 48) == 0 {
        return None;
    }
    let low32 = raw_value & 0xFFFF_FFFF;
    let image_high = image_base & 0xFFFF_FFFF_0000_0000;
    let candidate = image_high | low32;
    if is_in_mapped_ranges(candidate, mapped_ranges) {
        return Some(candidate);
    }
    None
}

fn emulate_arm64_lse_cas(
    emu: &mut machina::UnicornEmulator,
    instr: u32,
) -> Option<Vec<(&'static str, String)>> {
    let is_64 = ((instr >> 30) & 1) != 0;
    let acquire = ((instr >> 22) & 1) != 0;
    let release = ((instr >> 15) & 1) != 0;
    let rs = ((instr >> 16) & 0x1F) as u8;
    let rn = ((instr >> 5) & 0x1F) as u8;
    let rt = (instr & 0x1F) as u8;
    let addr = if rn == 31 {
        emu.read_reg("sp").ok()?
    } else {
        emu.read_reg(&format!("x{}", rn)).ok()?
    };
    let compare = read_arm64_gpr(emu, rs, is_64)?;
    let new_value = read_arm64_gpr(emu, rt, is_64)?;
    let old_value = if is_64 {
        let bytes = emu.read_memory(addr, 8).ok()?;
        u64::from_le_bytes(<[u8; 8]>::try_from(bytes.as_slice()).ok()?)
    } else {
        let bytes = emu.read_memory(addr, 4).ok()?;
        u32::from_le_bytes(<[u8; 4]>::try_from(bytes.as_slice()).ok()?) as u64
    };

    if old_value == compare {
        if is_64 {
            let _ = emu.write_memory(addr, &new_value.to_le_bytes());
        } else {
            let _ = emu.write_memory(addr, &(new_value as u32).to_le_bytes());
        }
    }
    write_arm64_gpr(emu, rs, old_value, is_64)?;
    let pc = emu.read_reg("pc").ok()?;
    let _ = emu.write_reg("pc", pc.saturating_add(4));

    Some(vec![
        ("Pc", format!("0x{:X}", pc)),
        ("Address", format!("0x{:X}", addr)),
        ("Kind", if is_64 { "cas64" } else { "cas32" }.to_string()),
        ("Acquire", acquire.to_string()),
        ("Release", release.to_string()),
        ("Compare", format!("0x{:X}", compare)),
        ("NewValue", format!("0x{:X}", new_value)),
        ("OldValue", format!("0x{:X}", old_value)),
        ("Swapped", (old_value == compare).to_string()),
        ("Rs", rs.to_string()),
        ("Rt", rt.to_string()),
        ("Rn", rn.to_string()),
        ("Encoding", format!("0x{:08X}", instr)),
    ])
}

fn emulate_arm64_lse_ldadd(
    emu: &mut machina::UnicornEmulator,
    instr: u32,
) -> Option<Vec<(&'static str, String)>> {
    let is_64 = ((instr >> 30) & 1) != 0;
    let acquire = ((instr >> 23) & 1) != 0;
    let release = ((instr >> 22) & 1) != 0;
    let rs = ((instr >> 16) & 0x1F) as u8;
    let rn = ((instr >> 5) & 0x1F) as u8;
    let rt = (instr & 0x1F) as u8;
    let addr = if rn == 31 {
        emu.read_reg("sp").ok()?
    } else {
        emu.read_reg(&format!("x{}", rn)).ok()?
    };
    let addend = read_arm64_gpr(emu, rs, is_64)?;
    let old_value = if is_64 {
        let bytes = emu.read_memory(addr, 8).ok()?;
        u64::from_le_bytes(<[u8; 8]>::try_from(bytes.as_slice()).ok()?)
    } else {
        let bytes = emu.read_memory(addr, 4).ok()?;
        u32::from_le_bytes(<[u8; 4]>::try_from(bytes.as_slice()).ok()?) as u64
    };
    let new_value = if is_64 {
        old_value.wrapping_add(addend)
    } else {
        (old_value as u32).wrapping_add(addend as u32) as u64
    };

    if is_64 {
        let _ = emu.write_memory(addr, &new_value.to_le_bytes());
    } else {
        let _ = emu.write_memory(addr, &(new_value as u32).to_le_bytes());
    }
    write_arm64_gpr(emu, rt, old_value, is_64)?;
    let pc = emu.read_reg("pc").ok()?;
    let _ = emu.write_reg("pc", pc.saturating_add(4));

    Some(vec![
        ("Pc", format!("0x{:X}", pc)),
        ("Address", format!("0x{:X}", addr)),
        (
            "Kind",
            if is_64 {
                "ldadd64"
            } else {
                "ldadd32"
            }
            .to_string(),
        ),
        ("Acquire", acquire.to_string()),
        ("Release", release.to_string()),
        ("Addend", format!("0x{:X}", addend)),
        ("OldValue", format!("0x{:X}", old_value)),
        ("NewValue", format!("0x{:X}", new_value)),
        ("Rs", rs.to_string()),
        ("Rt", rt.to_string()),
        ("Rn", rn.to_string()),
        ("Encoding", format!("0x{:08X}", instr)),
    ])
}

fn emulate_arm64_ldapr(
    emu: &mut machina::UnicornEmulator,
    instr: u32,
) -> Option<Vec<(&'static str, String)>> {
    let is_64 = ((instr >> 30) & 1) != 0;
    let rn = ((instr >> 5) & 0x1F) as u8;
    let rt = (instr & 0x1F) as u8;
    let addr = if rn == 31 {
        emu.read_reg("sp").ok()?
    } else {
        emu.read_reg(&format!("x{}", rn)).ok()?
    };
    let value = if is_64 {
        let bytes = emu.read_memory(addr, 8).ok()?;
        u64::from_le_bytes(<[u8; 8]>::try_from(bytes.as_slice()).ok()?)
    } else {
        let bytes = emu.read_memory(addr, 4).ok()?;
        u32::from_le_bytes(<[u8; 4]>::try_from(bytes.as_slice()).ok()?) as u64
    };
    write_arm64_gpr(emu, rt, value, is_64)?;
    let pc = emu.read_reg("pc").ok()?;
    let _ = emu.write_reg("pc", pc.saturating_add(4));

    Some(vec![
        ("Pc", format!("0x{:X}", pc)),
        ("Address", format!("0x{:X}", addr)),
        (
            "Kind",
            if is_64 { "ldapr64" } else { "ldapr32" }.to_string(),
        ),
        ("Value", format!("0x{:X}", value)),
        ("Rt", rt.to_string()),
        ("Rn", rn.to_string()),
        ("Encoding", format!("0x{:08X}", instr)),
    ])
}

fn read_arm64_gpr(emu: &mut machina::UnicornEmulator, reg: u8, is_64: bool) -> Option<u64> {
    if reg == 31 {
        return Some(0);
    }
    let value = emu.read_reg(&format!("x{}", reg)).ok()?;
    Some(if is_64 { value } else { value as u32 as u64 })
}

fn write_arm64_gpr(
    emu: &mut machina::UnicornEmulator,
    reg: u8,
    value: u64,
    is_64: bool,
) -> Option<()> {
    if reg == 31 {
        return Some(());
    }
    emu.write_reg(
        &format!("x{}", reg),
        if is_64 { value } else { value as u32 as u64 },
    )
    .ok()?;
    Some(())
}

fn read_arm64_addr_reg(emu: &mut machina::UnicornEmulator, reg: u8) -> Option<u64> {
    if reg == 31 {
        return emu.read_reg("sp").ok();
    }
    emu.read_reg(&format!("x{}", reg)).ok()
}
