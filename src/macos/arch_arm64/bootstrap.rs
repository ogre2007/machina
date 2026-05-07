//! Bootstrap helpers for the legacy arm64 no-dyld runner.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::macos::{
    align_up, alloc_bytes, find_symbol_address, install_stub_region, io_event, memory_event,
    process_event, reload_file_backed_range, setup_arm64_stack_bootstrap, setup_guest_memory_arena,
    GuestMemoryArenaConfig, GuestProcessBootstrap, SharedTraceBus, StubIsa, StubRegion,
    TraceMetadata,
};
use crate::{Emulator, MachoBinary, UnicornEmulator};
use unicorn_engine::Prot;

#[derive(Debug)]
pub struct Arm64BootstrapState {
    pub heap_base: u64,
    pub mmap_base: u64,
    pub mmap_end: u64,
    pub mmap_next: Arc<AtomicU64>,
    pub errno_ptr: u64,
    pub stub_region: StubRegion,
    pub process_bootstrap: GuestProcessBootstrap,
}

pub fn map_arm64_binary_segments(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let metadata = TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name.to_string());
    let mut max_addr: u64 = 0;
    for seg in &binary.segments {
        let seg_name = seg.segname_str();
        if seg_name == "__PAGEZERO" {
            continue;
        }

        if seg.vmsize > 0 {
            let page_size = 0x1000;
            let aligned_size = ((seg.vmsize + page_size - 1) / page_size) * page_size;
            let initial_prot = Prot::READ | Prot::WRITE | Prot::EXEC;
            emulator.map_memory_with_prot(seg.vmaddr, aligned_size, initial_prot)?;
            if let Some(bus) = trace_bus {
                let _ = bus.send(
                    metadata.apply_to(
                        memory_event(&metadata, "map-segment")
                            .arg("Segment", seg_name.clone())
                            .arg("VmAddr", format!("0x{:X}", seg.vmaddr))
                            .arg("VmSize", format!("0x{:X}", seg.vmsize))
                            .arg("FileOff", format!("0x{:X}", seg.fileoff))
                            .arg("FileSize", format!("0x{:X}", seg.filesize)),
                    ),
                );
            }

            if seg.filesize > 0 {
                let end = (seg.fileoff + seg.filesize) as usize;
                if end <= binary.data.len() {
                    let file_data = &binary.data[seg.fileoff as usize..end];
                    let _ = emulator.write_memory(seg.vmaddr, file_data);
                }
            }

            let final_prot = arm64_segment_prot(seg.initprot);
            let _ = emulator.protect_memory(seg.vmaddr, aligned_size, final_prot);
            if let Some(bus) = trace_bus {
                let _ = bus.send(
                    metadata.apply_to(
                        memory_event(&metadata, "protect-segment")
                            .arg("Segment", seg_name.clone())
                            .arg("VmAddr", format!("0x{:X}", seg.vmaddr))
                            .arg("VmSize", format!("0x{:X}", seg.vmsize))
                            .arg("Prot", format!("{:?}", final_prot)),
                    ),
                );
            }

            let seg_end = seg.vmaddr + seg.vmsize;
            if seg_end > max_addr {
                max_addr = seg_end;
            }
        }
    }

    if let Some(pclntab) = find_symbol_address(binary, "_runtime.pclntab") {
        reload_file_backed_range(emulator, binary, pclntab, 0x40, "_runtime.pclntab header")?;
    }

    Ok(max_addr)
}

fn arm64_segment_prot(initprot: i32) -> Prot {
    let mut prot = Prot::NONE;
    if initprot & crate::macos::loader::consts::vm_protection::VM_PROT_READ != 0 {
        prot |= Prot::READ;
    }
    if initprot & crate::macos::loader::consts::vm_protection::VM_PROT_WRITE != 0 {
        prot |= Prot::WRITE;
    }
    if initprot & crate::macos::loader::consts::vm_protection::VM_PROT_EXECUTE != 0 {
        prot |= Prot::EXEC;
    }
    if prot == Prot::NONE {
        Prot::READ
    } else {
        prot
    }
}

pub fn setup_arm64_bootstrap_state(
    emulator: &mut UnicornEmulator,
    binary: &MachoBinary,
    binary_path: &str,
    max_addr: u64,
    sp: u64,
    trace_bus: &Option<SharedTraceBus>,
    process_name: &str,
) -> Result<Arm64BootstrapState, Box<dyn std::error::Error>> {
    let metadata = TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name.to_string());
    let arena = setup_guest_memory_arena(emulator, GuestMemoryArenaConfig::arm64(max_addr))?;
    if let Some(bus) = trace_bus {
        let _ = bus.send(
            memory_event(&metadata, "memory-arena")
                .arg("HeapBase", format!("0x{:X}", arena.heap_base))
                .arg("MmapBase", format!("0x{:X}", arena.mmap_base))
                .arg("MmapEnd", format!("0x{:X}", arena.mmap_end)),
        );
    }
    let mmap_next = Arc::new(AtomicU64::new(arena.mmap_base));

    let mut heap_cursor = arena.heap_cursor;
    let bootstrap = setup_arm64_stack_bootstrap(emulator, &mut heap_cursor, binary_path, sp)?;
    if let Some(bus) = trace_bus {
        let _ = bus.send(
            process_event(&metadata, "stack-bootstrap", "stack-bootstrap")
                .arg("StackArgcAddr", format!("0x{:X}", bootstrap.argc_addr))
                .arg("Argc", bootstrap.argc.to_string())
                .arg("Argv", format!("0x{:X}", bootstrap.argv_addr))
                .arg("Envp", format!("0x{:X}", bootstrap.envp_addr)),
        );
    }

    let tls_base = align_up(heap_cursor + 0x1000, 0x1000);
    let _ = emulator.map_data_memory(tls_base, 0x4000);
    emulator.write_reg("tpidr_el0", tls_base)?;
    emulator.write_reg("tpidrro_el0", tls_base)?;
    if let Some(bus) = trace_bus {
        let _ = bus.send(io_event(&metadata, "tls").arg("TlsBase", format!("0x{:X}", tls_base)));
    }

    heap_cursor = tls_base + 0x4000;
    let errno_ptr = alloc_bytes(emulator, &mut heap_cursor, &[0u8; 8])?;

    let stub_region = install_stub_region(emulator, StubIsa::Arm64, true)?;
    if let Some(bus) = trace_bus {
        let _ = bus.send(
            process_event(&metadata, "stub-region", "stub-region")
                .arg("ErrnoPtr", format!("0x{:X}", errno_ptr))
                .arg("Base", format!("0x{:X}", stub_region.base))
                .arg("Size", format!("0x{:X}", stub_region.size))
                .arg("DoneAddr", format!("0x{:X}", stub_region.done_addr)),
        );
    }

    let _ = binary;

    Ok(Arm64BootstrapState {
        heap_base: arena.heap_base,
        mmap_base: arena.mmap_base,
        mmap_end: arena.mmap_end,
        mmap_next,
        errno_ptr,
        stub_region,
        process_bootstrap: bootstrap,
    })
}
