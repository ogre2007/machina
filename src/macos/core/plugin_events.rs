//! Architecture-independent event builders for plugin-oriented tracing.

use crate::macos::trace::{TraceCategory, TraceEvent};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceMetadata {
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub tid: Option<u64>,
    pub running_process: Option<String>,
}

impl TraceMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pid(mut self, pid: u64) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn ppid(mut self, ppid: u64) -> Self {
        self.ppid = Some(ppid);
        self
    }

    pub fn tid(mut self, tid: u64) -> Self {
        self.tid = Some(tid);
        self
    }

    pub fn running_process(mut self, process: impl Into<String>) -> Self {
        self.running_process = Some(process.into());
        self
    }

    pub fn apply_to(&self, mut event: TraceEvent) -> TraceEvent {
        if let Some(pid) = self.pid {
            event = event.pid(pid);
        }
        if let Some(ppid) = self.ppid {
            event = event.ppid(ppid);
        }
        if let Some(tid) = self.tid {
            event = event.tid(tid);
        }
        if let Some(process) = &self.running_process {
            event = event.running_process(process.clone());
        }
        event
    }
}

pub fn process_event(
    metadata: &TraceMetadata,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Process, name)
            .call(call)
            .message("process lifecycle event"),
    )
}

pub fn import_event(
    metadata: &TraceMetadata,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    metadata.apply_to(TraceEvent::new(TraceCategory::Import, name).call(call))
}

pub fn thread_event(
    metadata: &TraceMetadata,
    name: impl Into<String>,
    call: impl Into<String>,
) -> TraceEvent {
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Thread, name)
            .call(call)
            .message("thread lifecycle event"),
    )
}

pub fn syscall_event(metadata: &TraceMetadata, call: impl Into<String>) -> TraceEvent {
    let call = call.into();
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Syscall, "syscall")
            .call(call.clone())
            .message(format!("syscall {}", call)),
    )
}

pub fn io_event(metadata: &TraceMetadata, call: impl Into<String>) -> TraceEvent {
    let call = call.into();
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Io, call.clone())
            .call(call.clone())
            .message(format!("io {}", call)),
    )
}

pub fn memory_event(metadata: &TraceMetadata, call: impl Into<String>) -> TraceEvent {
    let call = call.into();
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Memory, call.clone())
            .call(call.clone())
            .message(format!("memory {}", call)),
    )
}

pub fn kqueue_event(metadata: &TraceMetadata, call: impl Into<String>) -> TraceEvent {
    let call = call.into();
    metadata.apply_to(
        TraceEvent::new(TraceCategory::Kqueue, call.clone())
            .call(call.clone())
            .message(format!("kqueue {}", call)),
    )
}

pub fn capture_event(metadata: &TraceMetadata, name: impl Into<String>) -> TraceEvent {
    metadata.apply_to(TraceEvent::new(TraceCategory::Capture, name))
}

pub fn detect_event(metadata: &TraceMetadata, name: impl Into<String>) -> TraceEvent {
    metadata.apply_to(TraceEvent::new(TraceCategory::Detect, name))
}

#[cfg(test)]
mod tests {
    use crate::macos::plugins::register_plugins;
    use crate::macos::trace::PluginRegistry;

    use super::*;

    #[test]
    fn metadata_applies_stable_process_fields() {
        let meta = TraceMetadata::new()
            .pid(42)
            .ppid(1)
            .tid(7)
            .running_process("sample");

        let event = syscall_event(&meta, "write");

        assert_eq!(event.pid, Some(42));
        assert_eq!(event.ppid, Some(1));
        assert_eq!(event.tid, Some(7));
        assert_eq!(event.running_process.as_deref(), Some("sample"));
        assert_eq!(event.call.as_deref(), Some("write"));
    }

    #[test]
    fn drakvuf_plugins_claim_built_events() {
        let mut registry = PluginRegistry::new();
        register_plugins(&mut registry);

        let meta = TraceMetadata::new().pid(2).tid(9);
        let event = process_event(&meta, "execve", "execve");
        let produced = registry.dispatch(&event);

        assert!(produced
            .iter()
            .any(|event| event.plugin.as_deref() == Some("procmon")));
    }
}
