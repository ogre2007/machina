//! Core macOS emulation orchestration.
//!
//! New emulator features should be shaped around these library-level types.

use std::path::PathBuf;

use crate::macos::plugin_events::{
    capture_event, detect_event, io_event, kqueue_event, memory_event, process_event,
    syscall_event, thread_event, TraceMetadata,
};
use crate::macos::plugins::register_plugins;
use crate::macos::trace::{
    PluginRegistry, StdoutTraceSink, TraceConfig, TraceEvent, TraceSink, Tracer,
};
use crate::MachoBinary;

pub const DEFAULT_SAMPLE_PATH: &str = r"fixtures\macos\bin\arm64_hello";
pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosCpu {
    Arm64,
}

impl MacosCpu {
    pub fn cputype(self) -> u32 {
        match self {
            Self::Arm64 => CPU_TYPE_ARM64,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmulationOptions {
    pub trace: TraceConfig,
    pub max_threads: usize,
    pub max_instructions: Option<u64>,
    pub capture_dir: PathBuf,
}

impl Default for EmulationOptions {
    fn default() -> Self {
        Self {
            trace: TraceConfig::jsonl(),
            max_threads: 6,
            max_instructions: None,
            capture_dir: PathBuf::from("target/machina-captures"),
        }
    }
}

impl EmulationOptions {
    pub fn jsonl_trace() -> Self {
        Self {
            trace: TraceConfig::jsonl(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationStatus {
    Completed,
    Stopped(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulationReport {
    pub status: EmulationStatus,
    pub syscalls: u64,
    pub imports: u64,
    pub detections: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchSummary {
    pub ok: usize,
    pub skipped: usize,
    pub failed: usize,
}

impl EmulationReport {
    pub fn completed() -> Self {
        Self {
            status: EmulationStatus::Completed,
            syscalls: 0,
            imports: 0,
            detections: 0,
        }
    }
}

pub fn collect_targets(args: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for arg in args {
        let path = PathBuf::from(arg);
        if path.is_file() {
            out.push(path);
            continue;
        }

        if path.is_dir() {
            let mut stack = vec![path];
            while let Some(dir) = stack.pop() {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                        } else if path.is_file() {
                            out.push(path);
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn macho_cputype(binary: &MachoBinary) -> u32 {
    binary
        .header_64
        .as_ref()
        .map(|h| h.cputype)
        .or_else(|| binary.header_32.as_ref().map(|h| h.cputype))
        .unwrap_or(0)
}

pub fn cpu_type_name(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_ARM64 => "arm64",
        _ => "unknown",
    }
}

pub fn ensure_macho_cpu(binary: &MachoBinary, expected: MacosCpu) -> Result<u32, String> {
    let cputype = macho_cputype(binary);
    if cputype == expected.cputype() {
        Ok(cputype)
    } else {
        Err(format!(
            "Unsupported Mach-O CPU type 0x{:X} ({}) in {} runner",
            cputype,
            cpu_type_name(cputype),
            expected.name()
        ))
    }
}

pub fn targets_from_args(args: &[String]) -> Result<Vec<PathBuf>, String> {
    if args.is_empty() {
        return Ok(vec![PathBuf::from(DEFAULT_SAMPLE_PATH)]);
    }

    let targets = collect_targets(args);
    if targets.is_empty() {
        Err("No files found in provided paths".to_string())
    } else {
        Ok(targets)
    }
}

pub fn run_target_batch<F>(targets: Vec<PathBuf>, mut runner: F) -> BatchSummary
where
    F: FnMut(&str) -> Result<(), Box<dyn std::error::Error>>,
{
    let trace_bus = crate::macos::shared_trace_bus_from_env();
    let batch_meta = TraceMetadata::new()
        .pid(0)
        .ppid(0)
        .tid(0)
        .running_process("machina");
    crate::macos::emit_runner_trace_event(
        &trace_bus,
        &TraceMetadata::new(),
        process_event(&batch_meta, "batch-start", "run_target_batch")
            .arg("Targets", targets.len().to_string()),
    );
    let mut summary = BatchSummary::default();

    for target in targets {
        let target_str = target.to_string_lossy().to_string();
        crate::macos::emit_runner_trace_event(
            &trace_bus,
            &TraceMetadata::new(),
            process_event(&batch_meta, "target-start", "run_target")
                .arg("Path", target_str.clone()),
        );
        match runner(&target_str) {
            Ok(()) => {
                summary.ok += 1;
                crate::macos::emit_runner_trace_event(
                    &trace_bus,
                    &TraceMetadata::new(),
                    process_event(&batch_meta, "target-complete", "run_target")
                        .arg("Path", target_str)
                        .arg("Status", "ok"),
                );
            }
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("Unsupported Mach-O CPU type") {
                    summary.skipped += 1;
                    crate::macos::emit_runner_trace_event(
                        &trace_bus,
                        &TraceMetadata::new(),
                        process_event(&batch_meta, "target-skip", "run_target")
                            .arg("Path", target_str)
                            .arg("Status", "skip")
                            .arg("Reason", msg),
                    );
                } else {
                    summary.failed += 1;
                    crate::macos::emit_runner_trace_event(
                        &trace_bus,
                        &TraceMetadata::new(),
                        process_event(&batch_meta, "target-fail", "run_target")
                            .arg("Path", target_str)
                            .arg("Status", "fail")
                            .arg("Reason", msg),
                    );
                }
            }
        }
    }

    crate::macos::emit_runner_trace_event(
        &trace_bus,
        &TraceMetadata::new(),
        process_event(&batch_meta, "batch-summary", "run_target_batch")
            .arg("Ok", summary.ok.to_string())
            .arg("Skip", summary.skipped.to_string())
            .arg("Fail", summary.failed.to_string()),
    );

    summary
}

pub struct MacosEmulator<S: TraceSink = StdoutTraceSink> {
    pub options: EmulationOptions,
    tracer: Tracer<S>,
    plugins: PluginRegistry,
}

impl MacosEmulator<StdoutTraceSink> {
    pub fn stdout(options: EmulationOptions) -> Self {
        let tracer = Tracer::new(options.trace.clone(), StdoutTraceSink);
        Self::new(options, tracer)
    }
}

impl<S: TraceSink> MacosEmulator<S> {
    pub fn new(options: EmulationOptions, tracer: Tracer<S>) -> Self {
        let mut plugins = PluginRegistry::new();
        register_plugins(&mut plugins);
        Self {
            options,
            tracer,
            plugins,
        }
    }

    pub fn register_plugin<P: crate::macos::trace::TracePlugin + 'static>(&mut self, plugin: P) {
        self.plugins.register(plugin);
    }

    pub fn emit_trace(&mut self, event: TraceEvent) {
        for event in self.plugins.dispatch(&event) {
            self.tracer.emit(event);
        }
    }

    pub fn emit_process_event(
        &mut self,
        metadata: &TraceMetadata,
        name: impl Into<String>,
        call: impl Into<String>,
    ) {
        self.emit_trace(process_event(metadata, name, call));
    }

    pub fn emit_thread_event(
        &mut self,
        metadata: &TraceMetadata,
        name: impl Into<String>,
        call: impl Into<String>,
    ) {
        self.emit_trace(thread_event(metadata, name, call));
    }

    pub fn emit_syscall_event(&mut self, metadata: &TraceMetadata, call: impl Into<String>) {
        self.emit_trace(syscall_event(metadata, call));
    }

    pub fn emit_io_event(&mut self, metadata: &TraceMetadata, call: impl Into<String>) {
        self.emit_trace(io_event(metadata, call));
    }

    pub fn emit_memory_event(&mut self, metadata: &TraceMetadata, call: impl Into<String>) {
        self.emit_trace(memory_event(metadata, call));
    }

    pub fn emit_kqueue_event(&mut self, metadata: &TraceMetadata, call: impl Into<String>) {
        self.emit_trace(kqueue_event(metadata, call));
    }

    pub fn emit_capture_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>) {
        self.emit_trace(capture_event(metadata, name));
    }

    pub fn emit_detect_event(&mut self, metadata: &TraceMetadata, name: impl Into<String>) {
        self.emit_trace(detect_event(metadata, name));
    }

    pub fn into_tracer(self) -> Tracer<S> {
        self.tracer
    }
}

#[cfg(test)]
mod tests {
    use crate::macos::trace::{
        TraceCategory, TraceConfig, TraceEvent, TracePlugin, Tracer, WriterTraceSink,
    };

    use super::*;

    struct DetectExecve;

    impl TracePlugin for DetectExecve {
        fn name(&self) -> &'static str {
            "detect-execve"
        }

        fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent> {
            if event.call.as_deref() == Some("execve") {
                Some(
                    TraceEvent::new(TraceCategory::Detect, "process_execution")
                        .plugin(self.name())
                        .pid(event.pid.unwrap_or(0)),
                )
            } else {
                None
            }
        }
    }

    #[test]
    fn emulator_dispatches_trace_events_through_plugins() {
        let options = EmulationOptions {
            trace: TraceConfig::full_jsonl(),
            ..EmulationOptions::default()
        };
        let tracer = Tracer::new(options.trace.clone(), WriterTraceSink::new(Vec::new()));
        let mut emulator = MacosEmulator::new(options, tracer);
        emulator.register_plugin(DetectExecve);

        emulator.emit_trace(TraceEvent::new(TraceCategory::Process, "execve").call("execve"));

        let output = String::from_utf8(emulator.into_tracer().into_sink().into_inner()).unwrap();
        println!("{}", output);
        assert!(output.contains("\"Event\":\"execve\""));
        assert!(output.contains("\"plugin\":\"detect-execve\""));
        assert!(output.contains("\"Event\":\"process_execution\""));
    }

    #[test]
    fn emulator_helper_methods_emit_built_plugin_events() {
        let options = EmulationOptions {
            trace: TraceConfig::full_jsonl(),
            ..EmulationOptions::default()
        };
        let tracer = Tracer::new(options.trace.clone(), WriterTraceSink::new(Vec::new()));
        let mut emulator = MacosEmulator::new(options, tracer);
        let meta = TraceMetadata::new()
            .pid(2)
            .ppid(1)
            .tid(3)
            .running_process("sample");

        emulator.emit_syscall_event(&meta, "write");

        let output = String::from_utf8(emulator.into_tracer().into_sink().into_inner()).unwrap();

        assert!(output.contains("\"plugin\":\"syscalls\""));
        assert!(output.contains("\"PID\":2"));
        assert!(output.contains("\"PPID\":1"));
        assert!(output.contains("\"TID\":3"));
        assert!(output.contains("\"RunningProcess\":\"sample\""));
        assert!(output.contains("\"Call\":\"write\""));
    }

    #[test]
    fn compact_trace_prefers_semantic_filemon_events() {
        let options = EmulationOptions {
            trace: TraceConfig::compact_jsonl(),
            ..EmulationOptions::default()
        };
        let tracer = Tracer::new(options.trace.clone(), WriterTraceSink::new(Vec::new()));
        let mut emulator = MacosEmulator::new(options, tracer);
        let meta = TraceMetadata::new()
            .pid(2)
            .ppid(1)
            .tid(3)
            .running_process("sample");

        emulator.emit_io_event(&meta, "read");
        emulator.emit_syscall_event(&meta, "read");

        let output = String::from_utf8(emulator.into_tracer().into_sink().into_inner()).unwrap();

        assert!(output.contains("\"plugin\":\"filemon\""));
        assert!(!output.contains("\"plugin\":\"syscalls\""));
        assert!(!output.contains("\"Category\":"));
        assert!(!output.contains("\"Message\":"));
    }
}
