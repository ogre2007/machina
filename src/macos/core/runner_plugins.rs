//! Lightweight plugin-oriented tracing bridge for standalone runners.
//!
//! Legacy runner entrypoints still print directly today. This module lets them
//! begin emitting architecture-independent `TraceEvent`s without being fully
//! rewritten around `MacosEmulator`.

use crate::macos::plugin_events::TraceMetadata;
use crate::macos::trace::{StdoutTraceSink, TraceConfig, TraceEvent};
use crate::macos::{EmulationOptions, MacosEmulator};

pub type SharedTraceBus = std::sync::mpsc::Sender<TraceEvent>;

pub fn shared_trace_bus_from_env() -> Option<SharedTraceBus> {
    let enabled = std::env::var("MACHINA_PLUGIN_TRACE")
        .ok()
        .map(|value| {
            let value = value.trim();
            if value.eq_ignore_ascii_case("0")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no")
                || value.eq_ignore_ascii_case("off")
            {
                return false;
            }
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
        .unwrap_or(true);
    if !enabled {
        return None;
    }

    let mut options = EmulationOptions::default();
    let format = std::env::var("MACHINA_TRACE_FORMAT")
        .unwrap_or_else(|_| "jsonl".to_string())
        .to_ascii_lowercase();
    let profile = std::env::var("MACHINA_TRACE_PROFILE")
        .unwrap_or_else(|_| "compact".to_string())
        .to_ascii_lowercase();
    options.trace = match (format.as_str(), profile.as_str()) {
        ("human", "debug") => {
            let mut config = TraceConfig::human();
            config.profile = crate::macos::TraceProfile::Debug;
            config
        }
        ("human", _) => {
            let mut config = TraceConfig::human();
            config.profile = crate::macos::TraceProfile::Full;
            config
        }
        (_, "full") => TraceConfig::full_jsonl(),
        (_, "debug") => TraceConfig::debug_jsonl(),
        _ => TraceConfig::compact_jsonl(),
    };

    let (tx, rx) = std::sync::mpsc::channel::<TraceEvent>();
    std::thread::spawn(move || {
        let mut emulator = MacosEmulator::<StdoutTraceSink>::stdout(options);
        while let Ok(event) = rx.recv() {
            emulator.emit_trace(event);
        }
    });

    Some(tx)
}

pub fn emit_event(bus: &Option<SharedTraceBus>, metadata: &TraceMetadata, event: TraceEvent) {
    if let Some(bus) = bus {
        let _ = bus.send(metadata.apply_to(event));
    }
}

pub use emit_event as emit_runner_trace_event;
