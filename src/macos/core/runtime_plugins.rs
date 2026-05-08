//! Runtime hook plugins for standalone Mach-O runners.
//!
//! Trace plugins decide how to render or route events. Runtime plugins own
//! actual emulation behavior: they register hooks, mutate guest state, and
//! emit structured events as a side effect.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::Arc;

use crate::macos::{
    default_guest_fs_base, default_syscall_name, emit_runner_trace_event,
    handle_basic_macos_syscall, SharedTraceBus, SyscallInvocation, SyscallRuntimeState,
    TraceMetadata,
};
use crate::{ArchType, Emulator, MacOsError, UnicornEmulator};

pub fn runtime_process_metadata(process_name: impl Into<String>) -> TraceMetadata {
    TraceMetadata::new()
        .pid(1)
        .ppid(0)
        .tid(1)
        .running_process(process_name)
}

#[derive(Clone)]
pub struct RuntimeContextCore {
    pub process_name: String,
    pub binary_path: PathBuf,
    pub done_addr: u64,
    pub heap_base: u64,
    pub mmap_base: u64,
    pub mmap_end: u64,
    pub runtime: SyscallRuntimeState,
    pub trace_bus: Option<SharedTraceBus>,
}

#[derive(Clone)]
pub struct Arm64RuntimeContext {
    pub core: RuntimeContextCore,
}

pub type RuntimeContext = Arm64RuntimeContext;

impl RuntimeContextCore {
    pub fn new_with_runtime(
        process_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        done_addr: u64,
        heap_base: u64,
        mmap_base: u64,
        mmap_end: u64,
        runtime: SyscallRuntimeState,
        trace_bus: Option<SharedTraceBus>,
    ) -> Self {
        Self {
            process_name: process_name.into(),
            binary_path: binary_path.into(),
            done_addr,
            heap_base,
            mmap_base,
            mmap_end,
            runtime,
            trace_bus,
        }
    }
}

impl Arm64RuntimeContext {
    pub fn new(
        process_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        done_addr: u64,
        heap_base: u64,
        mmap_base: u64,
        mmap_end: u64,
        mmap_next: Arc<AtomicU64>,
        saw_exit: Arc<AtomicBool>,
        trace_bus: Option<SharedTraceBus>,
    ) -> Self {
        let binary_path = binary_path.into();
        let guest_fs_base = default_guest_fs_base(&binary_path, "arm64_ios");
        Self {
            core: RuntimeContextCore::new_with_runtime(
                process_name,
                binary_path,
                done_addr,
                heap_base,
                mmap_base,
                mmap_end,
                SyscallRuntimeState {
                    done_addr,
                    heap_base,
                    mmap_base,
                    mmap_end,
                    mmap_next,
                    syscall_count: Arc::new(AtomicUsize::new(0)),
                    next_fd: Arc::new(AtomicU64::new(3)),
                    saw_exit,
                    fd_table: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                    guest_fs_base,
                },
                trace_bus,
            ),
        }
    }

    pub fn metadata(&self) -> TraceMetadata {
        runtime_process_metadata(self.core.process_name.clone())
    }
}

pub trait Arm64RuntimePlugin {
    fn name(&self) -> &'static str;

    fn install(
        &self,
        emulator: &mut UnicornEmulator,
        context: &Arm64RuntimeContext,
    ) -> Result<(), MacOsError>;
}

pub trait RuntimePlugin: Arm64RuntimePlugin {}

impl<T: Arm64RuntimePlugin + ?Sized> RuntimePlugin for T {}

pub fn install_arm64_runtime_plugins(
    emulator: &mut UnicornEmulator,
    context: &Arm64RuntimeContext,
    plugins: &[&dyn Arm64RuntimePlugin],
) -> Result<(), MacOsError> {
    for plugin in plugins {
        plugin.install(emulator, context)?;
    }
    Ok(())
}

pub fn install_runtime_plugins(
    emulator: &mut UnicornEmulator,
    context: &RuntimeContext,
    plugins: &[&dyn RuntimePlugin],
) -> Result<(), MacOsError> {
    let plugins: Vec<&dyn Arm64RuntimePlugin> = plugins
        .iter()
        .map(|plugin| *plugin as &dyn Arm64RuntimePlugin)
        .collect();
    install_arm64_runtime_plugins(emulator, context, &plugins)
}

pub struct Arm64SyscallRuntimePlugin;

pub struct SyscallRuntimePlugin;

impl SyscallRuntimePlugin {
    pub fn name(&self) -> &'static str {
        Arm64SyscallRuntimePlugin.name()
    }
}

impl Arm64RuntimePlugin for SyscallRuntimePlugin {
    fn name(&self) -> &'static str {
        "syscall-runtime"
    }

    fn install(
        &self,
        emulator: &mut UnicornEmulator,
        context: &Arm64RuntimeContext,
    ) -> Result<(), MacOsError> {
        Arm64SyscallRuntimePlugin.install(emulator, context)
    }
}

impl Arm64RuntimePlugin for Arm64SyscallRuntimePlugin {
    fn name(&self) -> &'static str {
        "arm64-syscall-runtime"
    }

    fn install(
        &self,
        emulator: &mut UnicornEmulator,
        context: &Arm64RuntimeContext,
    ) -> Result<(), MacOsError> {
        let runtime = context.core.runtime.clone();
        let trace_bus = context.core.trace_bus.clone();
        let metadata = context.metadata();

        emulator.hook_syscall(Box::new(move |emu: &mut dyn Emulator| {
            if emu.arch_type() != ArchType::Arm64 {
                return Ok(0);
            }

            let pc = emu.read_reg("pc")?;
            let num = emu.read_reg("x16")?;
            let args = [
                emu.read_reg("x0")?,
                emu.read_reg("x1")?,
                emu.read_reg("x2")?,
                emu.read_reg("x3")?,
                emu.read_reg("x4")?,
                emu.read_reg("x5")?,
            ];
            let invocation = SyscallInvocation {
                num,
                name: default_syscall_name(num),
                pc,
                args,
            };
            let outcome = handle_basic_macos_syscall(
                emu,
                &invocation,
                &metadata,
                &runtime,
                "arm64-syscall-runtime",
            )?;

            emu.write_reg("x0", outcome.return_value)?;
            if let Some(stop_addr) = outcome.stop_addr {
                emu.write_reg("pc", stop_addr)?;
            } else {
                emu.write_reg("pc", pc + 4)?;
            }

            emit_runner_trace_event(&trace_bus, &TraceMetadata::new(), outcome.event);
            Ok(0)
        }));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_syscall_plugin_has_stable_name() {
        assert_eq!(Arm64SyscallRuntimePlugin.name(), "arm64-syscall-runtime");
    }
}
