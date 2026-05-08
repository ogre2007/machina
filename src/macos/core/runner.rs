pub use crate::macos::arm64_runner::*;

pub fn emulate_macos_binary(binary_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    crate::macos::arm64_runner::emulate_macos_arm64_binary(binary_path)
}
