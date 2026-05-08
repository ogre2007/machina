pub use crate::macos::arm64_bootstrap::{Arm64BootstrapState, *};

pub type BootstrapState = Arm64BootstrapState;

pub fn map_binary_segments(
    emulator: &mut crate::UnicornEmulator,
    binary: &crate::MachoBinary,
    trace_bus: &Option<crate::SharedTraceBus>,
    process_name: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    crate::macos::arm64_bootstrap::map_arm64_binary_segments(
        emulator,
        binary,
        trace_bus,
        process_name,
    )
}

pub fn setup_bootstrap_state(
    emulator: &mut crate::UnicornEmulator,
    binary: &crate::MachoBinary,
    binary_path: &str,
    max_addr: u64,
    sp: u64,
    trace_bus: &Option<crate::SharedTraceBus>,
    process_name: &str,
) -> Result<BootstrapState, Box<dyn std::error::Error>> {
    crate::macos::arm64_bootstrap::setup_arm64_bootstrap_state(
        emulator,
        binary,
        binary_path,
        max_addr,
        sp,
        trace_bus,
        process_name,
    )
}
