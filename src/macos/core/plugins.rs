//! Built-in architecture-independent trace plugin presets.
//!
//! These presets are the bridge from low-level intercepted events to
//! DRAKVUF-like operator-facing streams such as `procmon`, `syscalls`,
//! `filemon`, and `memmon`.

use crate::macos::trace::{CallTracePlugin, PluginRegistry, TraceCategory};

pub fn register_plugins(registry: &mut PluginRegistry) {
    registry.register(
        CallTracePlugin::new("procmon")
            .category(TraceCategory::Process)
            .category(TraceCategory::Thread)
            .call("execve")
            .call("fork")
            .call("wait4")
            .call("exit")
            .call("__exit"),
    );
    registry.register(
        CallTracePlugin::new("syscalls")
            .category(TraceCategory::Syscall)
            .call("open")
            .call("read")
            .call("write")
            .call("close")
            .call("mmap")
            .call("munmap")
            .call("mprotect")
            .call("sysctl"),
    );
    registry.register(
        CallTracePlugin::new("filemon")
            .category(TraceCategory::Io)
            .call("open")
            .call("close")
            .call("read")
            .call("write")
            .call("dup2")
            .call("pipe")
            .call("fcntl"),
    );
    registry.register(
        CallTracePlugin::new("memmon")
            .category(TraceCategory::Memory)
            .call("mmap")
            .call("munmap")
            .call("mprotect")
            .call("brk"),
    );
    registry.register(
        CallTracePlugin::new("kqueuemon")
            .category(TraceCategory::Kqueue)
            .call("kqueue")
            .call("kevent"),
    );
    registry.register(CallTracePlugin::new("detect").category(TraceCategory::Detect));
    registry.register(CallTracePlugin::new("capture").category(TraceCategory::Capture));
    registry.register(
        CallTracePlugin::new("loader")
            .category(TraceCategory::Loader)
            .call("dyld")
            .call("stub_patch"),
    );
    registry.register(
        CallTracePlugin::new("imports")
            .category(TraceCategory::Import)
            .call("ptrace")
            .call("execve")
            .call("fork")
            .call("kevent")
            .call("kqueue")
            .call("import-hit"),
    );
}

#[cfg(test)]
mod tests {
    use crate::macos::trace::{PluginRegistry, TraceCategory, TraceEvent};

    use super::*;
    #[test]
    fn malware_preset_claims_detection_and_import_events() {
        let mut plugins = PluginRegistry::new();
        register_plugins(&mut plugins);

        let produced =
            plugins.dispatch(&TraceEvent::new(TraceCategory::Import, "ptrace").call("ptrace"));

        assert!(produced
            .iter()
            .any(|event| event.plugin.as_deref() == Some("imports")));
    }
}
