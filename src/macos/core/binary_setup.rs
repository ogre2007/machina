pub use crate::macos::arm64_binary_setup::{Arm64RuntimeSymbols, *};

pub type RuntimeSymbols = Arm64RuntimeSymbols;

pub fn find_runtime_symbols(binary: &crate::MachoBinary) -> RuntimeSymbols {
    crate::macos::arm64_binary_setup::find_arm64_runtime_symbols(binary)
}

pub fn log_runtime_symbols(
    symbols: RuntimeSymbols,
    trace_bus: &Option<crate::macos::SharedTraceBus>,
    process_name: &str,
) {
    crate::macos::arm64_binary_setup::log_arm64_runtime_symbols(symbols, trace_bus, process_name)
}

pub fn patch_symbol_pointers(
    emulator: &mut crate::UnicornEmulator,
    binary: &crate::MachoBinary,
    undefs: &[(String, u8)],
    stub_map: &std::collections::HashMap<String, u64>,
    done_addr: u64,
    trace_bus: &Option<crate::macos::SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::macos::arm64_binary_setup::patch_arm64_symbol_pointers(
        emulator,
        binary,
        undefs,
        stub_map,
        done_addr,
        trace_bus,
        process_name,
    )
}

pub fn resolve_entry(binary: &crate::MachoBinary) -> u64 {
    crate::macos::arm64_binary_setup::resolve_arm64_entry(binary)
}
