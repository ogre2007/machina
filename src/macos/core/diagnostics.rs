pub use crate::macos::arm64_diagnostics::{Arm64RunReport, *};

pub type RunReport = Arm64RunReport;

pub fn install_diagnostic_hooks(
    emulator: &mut crate::UnicornEmulator,
    binary: &crate::MachoBinary,
    firstmoduledata: Option<u64>,
    actual_entry: u64,
    done_addr: u64,
    trace_bus: &Option<crate::SharedTraceBus>,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::macos::arm64_diagnostics::install_arm64_diagnostic_hooks(
        emulator,
        binary,
        firstmoduledata,
        actual_entry,
        done_addr,
        trace_bus,
        process_name,
    )
}

pub fn run_with_diagnostics(
    emulator: &mut crate::UnicornEmulator,
    report: RunReport,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::macos::arm64_diagnostics::run_arm64_with_diagnostics(emulator, report)
}
