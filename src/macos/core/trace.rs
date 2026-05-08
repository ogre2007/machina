//! Structured trace events for macOS emulation.
//!
//! JSONL output follows the DRAKVUF shape: each emitted line is a single JSON
//! object with a `plugin` field and stable process metadata. Plugins decide
//! which intercepted events are written to the log.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TraceCategory {
    Loader,
    Import,
    Syscall,
    Process,
    Thread,
    Memory,
    Io,
    Capture,
    Detect,
    Kqueue,
}

impl TraceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Import => "import",
            Self::Syscall => "syscall",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Memory => "memory",
            Self::Io => "io",
            Self::Capture => "capture",
            Self::Detect => "detect",
            Self::Kqueue => "kqueue",
        }
    }
}

impl fmt::Display for TraceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    Human,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceProfile {
    Compact,
    Full,
    Debug,
}

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub format: TraceFormat,
    pub profile: TraceProfile,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            format: TraceFormat::Jsonl,
            profile: TraceProfile::Compact,
        }
    }
}

impl TraceConfig {
    pub fn human() -> Self {
        Self {
            format: TraceFormat::Human,
            profile: TraceProfile::Full,
        }
    }

    pub fn jsonl() -> Self {
        Self::default()
    }

    pub fn compact_jsonl() -> Self {
        Self {
            format: TraceFormat::Jsonl,
            profile: TraceProfile::Compact,
        }
    }

    pub fn full_jsonl() -> Self {
        Self {
            format: TraceFormat::Jsonl,
            profile: TraceProfile::Full,
        }
    }

    pub fn debug_jsonl() -> Self {
        Self {
            format: TraceFormat::Jsonl,
            profile: TraceProfile::Debug,
        }
    }

    pub fn only_jsonl() -> Self {
        Self::jsonl()
    }

    pub fn only_human() -> Self {
        Self::human()
    }

    pub fn enable_category(self, _category: TraceCategory) -> Self {
        self
    }

    pub fn enable_call(self, _call: impl Into<String>) -> Self {
        self
    }

    pub fn is_enabled(&self, event: &TraceEvent) -> bool {
        if event.plugin.is_none() {
            return false;
        }

        match self.profile {
            TraceProfile::Compact => !is_compact_suppressed(event),
            TraceProfile::Full | TraceProfile::Debug => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub plugin: Option<String>,
    pub timestamp_us: u64,
    pub category: TraceCategory,
    pub name: String,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub tid: Option<u64>,
    pub running_process: Option<String>,
    pub call: Option<String>,
    pub args: BTreeMap<String, String>,
    pub result: Option<String>,
    pub message: Option<String>,
}

impl TraceEvent {
    pub fn new(category: TraceCategory, name: impl Into<String>) -> Self {
        Self {
            plugin: None,
            timestamp_us: unix_timestamp_us(),
            category,
            name: name.into(),
            pid: None,
            ppid: None,
            tid: None,
            running_process: None,
            call: None,
            args: BTreeMap::new(),
            result: None,
            message: None,
        }
    }

    pub fn plugin(mut self, plugin: impl Into<String>) -> Self {
        self.plugin = Some(plugin.into());
        self
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

    pub fn call(mut self, call: impl Into<String>) -> Self {
        self.call = Some(call.into());
        self
    }

    pub fn arg(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(name.into(), value.into());
        self
    }

    pub fn result(mut self, result: impl Into<String>) -> Self {
        self.result = Some(result.into());
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn render(&self, config: &TraceConfig) -> String {
        match config.format {
            TraceFormat::Human => self.render_human(),
            TraceFormat::Jsonl => self.render_jsonl(config.profile),
        }
    }

    pub fn render_human(&self) -> String {
        let plugin = self.plugin.as_deref().unwrap_or(self.category.as_str());
        let mut line = format!("[{}] {}", plugin.to_ascii_uppercase(), self.name);

        if let Some(pid) = self.pid {
            line.push_str(&format!(" pid={}", pid));
        }
        if let Some(ppid) = self.ppid {
            line.push_str(&format!(" ppid={}", ppid));
        }
        if let Some(tid) = self.tid {
            line.push_str(&format!(" tid={}", tid));
        }
        if let Some(process) = &self.running_process {
            line.push_str(&format!(" process={}", process));
        }
        if let Some(call) = &self.call {
            line.push_str(&format!(" call={}", call));
        }
        for (name, value) in &self.args {
            line.push_str(&format!(" {}={}", name, value));
        }
        if let Some(result) = &self.result {
            line.push_str(&format!(" -> {}", result));
        }
        if let Some(message) = &self.message {
            line.push_str(&format!(" {}", message));
        }

        line
    }

    pub fn render_jsonl(&self, profile: TraceProfile) -> String {
        let mut out = String::new();
        out.push('{');

        let plugin = self.plugin.as_deref().unwrap_or(self.category.as_str());
        push_json_string(&mut out, "plugin", plugin, true);
        push_json_string(
            &mut out,
            "TimeStamp",
            &format_timestamp(self.timestamp_us),
            false,
        );
        if let Some(pid) = self.pid {
            push_json_number(&mut out, "PID", pid, false);
        }
        if !matches!(profile, TraceProfile::Compact) {
            if let Some(ppid) = self.ppid {
                push_json_number(&mut out, "PPID", ppid, false);
            }
        }
        if let Some(tid) = self.tid {
            push_json_number(&mut out, "TID", tid, false);
        }
        if let Some(process) = &self.running_process {
            push_json_string(&mut out, "RunningProcess", process, false);
        }

        let suppress_event = matches!(profile, TraceProfile::Compact)
            && self.call.as_deref().is_some_and(|call| call == self.name);
        if !suppress_event {
            push_json_string(&mut out, "Event", &self.name, false);
        }
        if !matches!(profile, TraceProfile::Compact) {
            push_json_string(&mut out, "Category", self.category.as_str(), false);
        }

        if let Some(call) = &self.call {
            push_json_string(&mut out, "Call", call, false);
        }
        for (name, value) in &self.args {
            push_json_string(&mut out, name, value, false);
        }
        if let Some(result) = &self.result {
            push_json_string(&mut out, "Result", result, false);
        }
        if !matches!(profile, TraceProfile::Compact) {
            if let Some(message) = &self.message {
                push_json_string(&mut out, "Message", message, false);
            }
        }

        out.push('}');
        out
    }
}

pub trait TraceSink {
    fn emit_line(&mut self, line: &str);
}

#[derive(Debug, Default)]
pub struct StdoutTraceSink;

impl TraceSink for StdoutTraceSink {
    fn emit_line(&mut self, line: &str) {
        println!("{}", line);
    }
}

#[derive(Debug)]
pub struct WriterTraceSink<W: Write> {
    writer: W,
}

impl<W: Write> WriterTraceSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> TraceSink for WriterTraceSink<W> {
    fn emit_line(&mut self, line: &str) {
        let _ = writeln!(self.writer, "{}", line);
    }
}

pub type StdoutTracer = Tracer<StdoutTraceSink>;

#[derive(Debug)]
pub struct Tracer<S: TraceSink = StdoutTraceSink> {
    config: TraceConfig,
    sink: S,
    pending_burst: Vec<PendingBurst>,
    seen_compact_lazy_pages: HashSet<String>,
}

impl StdoutTracer {
    pub fn stdout(config: TraceConfig) -> Self {
        Self::new(config, StdoutTraceSink)
    }
}

impl<S: TraceSink> Tracer<S> {
    pub fn new(config: TraceConfig, sink: S) -> Self {
        Self {
            config,
            sink,
            pending_burst: Vec::new(),
            seen_compact_lazy_pages: HashSet::new(),
        }
    }

    pub fn config(&self) -> &TraceConfig {
        &self.config
    }

    pub fn emit(&mut self, event: TraceEvent) {
        if !self.config.is_enabled(&event) {
            return;
        }

        if matches!(self.config.profile, TraceProfile::Compact)
            && self.should_skip_compact_lazy_page(&event)
        {
            return;
        }

        if matches!(self.config.profile, TraceProfile::Compact)
            && is_compact_burst_candidate(&event)
        {
            self.emit_compact_burst(event);
            return;
        }

        self.flush_pending_burst();
        self.sink.emit_line(&event.render(&self.config));
    }

    pub fn into_sink(mut self) -> S {
        self.flush_pending_burst();
        self.sink
    }

    fn emit_compact_burst(&mut self, event: TraceEvent) {
        let signature = burst_signature(&event);
        if let Some(pending) = self
            .pending_burst
            .iter_mut()
            .find(|pending| pending.signature == signature)
        {
            pending.count += 1;
        } else {
            self.pending_burst.push(PendingBurst {
                signature,
                event,
                count: 1,
            });
        }
    }

    fn flush_pending_burst(&mut self) {
        for pending in self.pending_burst.drain(..) {
            self.sink.emit_line(&pending.event.render(&self.config));
            if pending.count > 1 {
                let repeat_count = pending.count - 1;
                let mut summary = TraceEvent::new(pending.event.category, "burst")
                    .plugin(
                        pending
                            .event
                            .plugin
                            .clone()
                            .unwrap_or_else(|| pending.event.category.as_str().to_string()),
                    )
                    .call(
                        pending
                            .event
                            .call
                            .clone()
                            .unwrap_or_else(|| pending.event.name.clone()),
                    )
                    .arg("RepeatCount", repeat_count.to_string());
                if let Some(pid) = pending.event.pid {
                    summary = summary.pid(pid);
                }
                if let Some(tid) = pending.event.tid {
                    summary = summary.tid(tid);
                }
                if let Some(process) = &pending.event.running_process {
                    summary = summary.running_process(process.clone());
                }

                for key in ["Symbol", "Address", "Path", "Fd"] {
                    if let Some(value) = pending.event.args.get(key) {
                        summary = summary.arg(key, value.clone());
                    }
                }

                self.sink.emit_line(&summary.render(&self.config));
            }
        }
    }

    fn should_skip_compact_lazy_page(&mut self, event: &TraceEvent) -> bool {
        let Some(key) = compact_lazy_page_key(event) else {
            return false;
        };
        !self.seen_compact_lazy_pages.insert(key)
    }
}

#[derive(Debug)]
struct PendingBurst {
    signature: String,
    event: TraceEvent,
    count: usize,
}

fn is_compact_suppressed(event: &TraceEvent) -> bool {
    let plugin = event.plugin.as_deref().unwrap_or_default();
    let call = event.call.as_deref().unwrap_or(event.name.as_str());

    if plugin == "syscalls" {
        return true;
    }

    if plugin == "imports" && call == "import-hit" {
        if is_compact_covered_import_hit(event) || is_compact_low_signal_import_hit(event) {
            return true;
        }
    }

    if plugin == "memmon" && is_compact_hot_memory_runtime_call(call) {
        return true;
    }

    if call == "install_import_stub" {
        return true;
    }

    if plugin == "imports" && event.name == "import-stub" {
        return true;
    }

    if call == "kevent" {
        return is_compact_trivial_kevent(event);
    }

    if call == "fcntl" {
        return is_compact_trivial_fcntl(event);
    }

    matches!(
        call,
        "_mach_absolute_time" | "_usleep" | "_kevent" | "_pthread_cond_wait"
    )
}

fn is_compact_burst_candidate(event: &TraceEvent) -> bool {
    let call = event.call.as_deref().unwrap_or(event.name.as_str());
    let symbol = event.name.as_str();

    matches!(
        call,
        "_mach_absolute_time" | "_usleep" | "_kevent" | "_pthread_cond_wait"
    ) || (call == "import-hit"
        && matches!(
            symbol,
            "_mach_absolute_time" | "_usleep" | "_kevent" | "_pthread_cond_wait"
        ))
}

fn event_arg_u64(event: &TraceEvent, key: &str) -> Option<u64> {
    event.args.get(key).and_then(|value| {
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(
                || value.parse::<u64>().ok(),
                |hex| u64::from_str_radix(hex, 16).ok(),
            )
    })
}

fn event_arg_nonempty(event: &TraceEvent, key: &str) -> bool {
    event.args.get(key).is_some_and(|value| !value.is_empty())
}

fn is_compact_trivial_kevent(event: &TraceEvent) -> bool {
    let plugin = event.plugin.as_deref().unwrap_or_default();
    if plugin == "imports" {
        return true;
    }

    let emitted = event_arg_u64(event, "Emitted").unwrap_or(0);
    let has_changes = event_arg_nonempty(event, "Changes");
    let has_ready = event_arg_nonempty(event, "Ready");

    !(emitted > 0 || has_changes || has_ready)
}

fn is_compact_trivial_fcntl(event: &TraceEvent) -> bool {
    let cmd_name = event.args.get("CmdName").map(String::as_str).unwrap_or("");
    !matches!(cmd_name, "F_SETFD" | "F_SETFL" | "F_DUPFD_CLOEXEC")
}

fn is_compact_covered_import_hit(event: &TraceEvent) -> bool {
    matches!(
        event.name.as_str(),
        "_malloc"
            | "_calloc"
            | "_realloc"
            | "_free"
            | "_memcpy"
            | "_memmove"
            | "_memset"
            | "_memcmp"
            | "_strlen"
            | "_kqueue"
            | "_kevent"
            | "_pipe"
            | "_fcntl"
            | "_close"
            | "_dup2"
            | "_open"
            | "_read"
            | "_write"
            | "_mmap"
            | "_munmap"
            | "_mprotect"
            | "_opendir"
            | "_fdopendir"
            | "_readdir_r"
            | "_closedir"
            | "_fork"
            | "_wait4"
            | "_execve"
            | "__exit"
            | "_pthread_key_create"
            | "___error"
            | "_pthread_setspecific"
            | "_pthread_getspecific"
            | "_pthread_self"
            | "_pthread_create"
            | "_pthread_mutex_lock"
            | "_pthread_mutex_unlock"
            | "_pthread_cond_wait"
            | "_pthread_cond_signal"
            | "_pthread_cond_broadcast"
            | "_mach_absolute_time"
            | "_usleep"
            | "_mach_timebase_info"
            | "_sysctl"
            | "_sysctlbyname"
            | "_notify_is_valid_token"
            | "_CFStringCreateWithBytes"
            | "_CFDataCreate"
            | "_CFDataGetBytePtr"
            | "_CFArrayCreateMutable"
            | "_CFArrayAppendValue"
            | "_CFRelease"
            | "_CFRetain"
            | "_SecPolicyCreateBasicX509"
            | "_SecTrustCreateWithCertificates"
            | "_SecTrustEvaluateWithError"
            | "_xpc_date_create_from_current"
    )
}

fn is_compact_hot_memory_runtime_call(call: &str) -> bool {
    matches!(
        call,
        "malloc" | "calloc" | "realloc" | "free" | "memcpy" | "memmove" | "memset" | "memcmp"
    )
}

fn is_compact_low_signal_import_hit(event: &TraceEvent) -> bool {
    matches!(
        event.name.as_str(),
        "_madvise"
            | "_sigaction"
            | "_pthread_sigmask"
            | "_sigaltstack"
            | "_mlock"
            | "_clock_gettime"
            | "_getaddrinfo"
            | "_freeaddrinfo"
            | "_pthread_kill"
            | "_pthread_attr_init"
            | "_pthread_attr_setdetachstate"
            | "_pthread_attr_getstacksize"
    )
}

fn burst_signature(event: &TraceEvent) -> String {
    let plugin = event.plugin.as_deref().unwrap_or_default();
    let call = event.call.as_deref().unwrap_or(event.name.as_str());
    let symbol = event.args.get("Symbol").cloned().unwrap_or_default();
    let address = event.args.get("Address").cloned().unwrap_or_default();
    let path = event.args.get("Path").cloned().unwrap_or_default();
    let fd = event.args.get("Fd").cloned().unwrap_or_default();
    let pid = event.pid.unwrap_or(0);
    let tid = event.tid.unwrap_or(0);
    format!("{plugin}|{call}|{symbol}|{address}|{path}|{fd}|{pid}|{tid}")
}

fn compact_lazy_page_key(event: &TraceEvent) -> Option<String> {
    let call = event.call.as_deref().unwrap_or(event.name.as_str());
    if call != "Lazymap_write" {
        return None;
    }

    let addr = event_arg_u64(event, "Addr")?;
    let memtype = event.args.get("Memtype").cloned().unwrap_or_default();
    Some(format!("{memtype}|0x{:X}", addr >> 12))
}

pub trait TracePlugin {
    fn name(&self) -> &'static str;
    fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent>;
}

#[derive(Debug, Clone)]
pub struct CallTracePlugin {
    name: &'static str,
    categories: HashSet<TraceCategory>,
    calls: HashSet<String>,
}

impl CallTracePlugin {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            categories: HashSet::new(),
            calls: HashSet::new(),
        }
    }

    pub fn category(mut self, category: TraceCategory) -> Self {
        self.categories.insert(category);
        self
    }

    pub fn call(mut self, call: impl Into<String>) -> Self {
        self.calls.insert(call.into());
        self
    }

    fn matches(&self, event: &TraceEvent) -> bool {
        self.categories.contains(&event.category)
            || event
                .call
                .as_ref()
                .is_some_and(|call| self.calls.contains(call))
            || self.calls.contains(&event.name)
    }
}

impl TracePlugin for CallTracePlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent> {
        if self.matches(event) {
            Some(event.clone().plugin(self.name))
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn TracePlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P: TracePlugin + 'static>(&mut self, plugin: P) {
        self.plugins.push(Box::new(plugin));
    }

    pub fn dispatch(&mut self, event: &TraceEvent) -> Vec<TraceEvent> {
        let mut produced = Vec::new();
        for plugin in &mut self.plugins {
            if let Some(event) = plugin.on_event(event) {
                produced.push(event);
            }
        }
        produced
    }

    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|plugin| plugin.name()).collect()
    }
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn unix_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn format_timestamp(timestamp_us: u64) -> String {
    format!(
        "{}.{:06}",
        timestamp_us / 1_000_000,
        timestamp_us % 1_000_000
    )
}

fn push_json_string(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":\"");
    out.push_str(&json_escape(value));
    out.push('"');
}

fn push_json_number(out: &mut String, key: &str, value: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(&json_escape(key));
    out.push_str("\":");
    out.push_str(&value.to_string());
}

pub fn memory_writer() -> (
    Tracer<WriterTraceSink<Vec<u8>>>,
    impl FnOnce(Tracer<WriterTraceSink<Vec<u8>>>) -> io::Result<String>,
) {
    let tracer = Tracer::new(TraceConfig::jsonl(), WriterTraceSink::new(Vec::new()));
    let finish = |tracer: Tracer<WriterTraceSink<Vec<u8>>>| {
        String::from_utf8(tracer.into_sink().into_inner())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    };
    (tracer, finish)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n\t"), "a\\\"b\\\\c\\n\\t");
    }

    #[test]
    fn jsonl_event_uses_drakvuf_style_fields() {
        let event = TraceEvent::new(TraceCategory::Process, "execve")
            .plugin("procmon")
            .pid(2)
            .ppid(1)
            .tid(6)
            .running_process("sample")
            .call("execve")
            .arg("Path", "/bin/sh")
            .arg("Argv", "[\"/bin/sh\"]")
            .result("0")
            .message("synthetic process consumed");

        let json = event.render_jsonl(TraceProfile::Full);

        assert!(json.contains("\"plugin\":\"procmon\""));
        assert!(json.contains("\"TimeStamp\":\""));
        assert!(json.contains("\"PID\":2"));
        assert!(json.contains("\"PPID\":1"));
        assert!(json.contains("\"RunningProcess\":\"sample\""));
        assert!(json.contains("\"Call\":\"execve\""));
        assert!(json.contains("\"Path\":\"/bin/sh\""));
    }

    #[test]
    fn tracer_does_not_emit_unclaimed_events() {
        let (mut tracer, finish) = memory_writer();
        tracer.emit(TraceEvent::new(TraceCategory::Import, "write").call("write"));

        assert_eq!(finish(tracer).unwrap(), "");
    }

    #[test]
    fn compact_jsonl_omits_category_and_message() {
        let event = TraceEvent::new(TraceCategory::Process, "execve")
            .plugin("procmon")
            .pid(2)
            .ppid(1)
            .tid(6)
            .running_process("sample")
            .call("execve")
            .message("process lifecycle event");

        let json = event.render_jsonl(TraceProfile::Compact);

        assert!(json.contains("\"Call\":\"execve\""));
        assert!(!json.contains("\"Category\":"));
        assert!(!json.contains("\"Message\":"));
        assert!(!json.contains("\"PPID\":"));
        assert!(!json.contains("\"Event\":"));
    }

    #[test]
    fn compact_suppresses_hot_noise_import_bursts() {
        let config = TraceConfig::compact_jsonl();
        let mut tracer = Tracer::new(config, WriterTraceSink::new(Vec::new()));

        let event = TraceEvent::new(TraceCategory::Import, "_mach_absolute_time")
            .plugin("imports")
            .pid(1)
            .tid(2)
            .call("import-hit")
            .arg("Symbol", "_mach_absolute_time")
            .arg("Address", "0x200003900");

        tracer.emit(event.clone());
        tracer.emit(event.clone());
        tracer.emit(event);

        let output = String::from_utf8(tracer.into_sink().into_inner()).unwrap();
        assert!(output.trim().is_empty());
    }

    #[test]
    fn compact_suppresses_trivial_kevent_but_keeps_meaningful_one() {
        let trivial = TraceEvent::new(TraceCategory::Kqueue, "kevent")
            .plugin("kqueuemon")
            .call("kevent")
            .arg("Emitted", "0")
            .arg("TimeoutPtr", "0x0");
        let meaningful = TraceEvent::new(TraceCategory::Kqueue, "kevent")
            .plugin("kqueuemon")
            .call("kevent")
            .arg("Emitted", "1")
            .arg("Ready", "ident=4 filter=EVFILT_READ");

        assert!(is_compact_suppressed(&trivial));
        assert!(!is_compact_suppressed(&meaningful));
    }

    #[test]
    fn compact_suppresses_timeout_only_kevent() {
        let timeout_only = TraceEvent::new(TraceCategory::Kqueue, "kevent")
            .plugin("kqueuemon")
            .call("kevent")
            .arg("Emitted", "0")
            .arg("Nchanges", "0")
            .arg("Nevents", "64")
            .arg("TimeoutPtr", "0x3301F528");

        assert!(is_compact_suppressed(&timeout_only));
    }

    #[test]
    fn compact_suppresses_trivial_fcntl_but_keeps_state_changing_one() {
        let getfl = TraceEvent::new(TraceCategory::Io, "fcntl")
            .plugin("filemon")
            .call("fcntl")
            .arg("CmdName", "F_GETFL");
        let setfl = TraceEvent::new(TraceCategory::Io, "fcntl")
            .plugin("filemon")
            .call("fcntl")
            .arg("CmdName", "F_SETFL");

        assert!(is_compact_suppressed(&getfl));
        assert!(!is_compact_suppressed(&setfl));
    }

    #[test]
    fn compact_suppresses_import_hit_when_semantic_plugin_covers_symbol() {
        let import_hit = TraceEvent::new(TraceCategory::Import, "_fcntl")
            .plugin("imports")
            .call("import-hit")
            .arg("Address", "0x200002400");
        let import_hit_unknown = TraceEvent::new(TraceCategory::Import, "_unknown_symbol")
            .plugin("imports")
            .call("import-hit")
            .arg("Address", "0x20000FF00");

        assert!(is_compact_suppressed(&import_hit));
        assert!(!is_compact_suppressed(&import_hit_unknown));
    }

    #[test]
    fn compact_suppresses_import_stub_install_events() {
        let install = TraceEvent::new(TraceCategory::Process, "import-stub")
            .plugin("procmon")
            .call("install_import_stub")
            .arg("Symbol", "_open");

        assert!(is_compact_suppressed(&install));
    }

    #[test]
    fn compact_keeps_first_lazymap_touch_per_page_and_memtype() {
        let config = TraceConfig::compact_jsonl();
        let mut tracer = Tracer::new(config, WriterTraceSink::new(Vec::new()));

        let first = TraceEvent::new(TraceCategory::Memory, "Lazymap_write")
            .plugin("memmon")
            .call("Lazymap_write")
            .arg("Addr", "0x4000014000")
            .arg("Memtype", "WRITE_UNMAPPED");
        let same_page = TraceEvent::new(TraceCategory::Memory, "Lazymap_write")
            .plugin("memmon")
            .call("Lazymap_write")
            .arg("Addr", "0x4000014FF8")
            .arg("Memtype", "WRITE_UNMAPPED");
        let different_page = TraceEvent::new(TraceCategory::Memory, "Lazymap_write")
            .plugin("memmon")
            .call("Lazymap_write")
            .arg("Addr", "0x4000015000")
            .arg("Memtype", "WRITE_UNMAPPED");

        tracer.emit(first);
        tracer.emit(same_page);
        tracer.emit(different_page);

        let output = String::from_utf8(tracer.into_sink().into_inner()).unwrap();
        let lines = output.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"Addr\":\"0x4000014000\""));
        assert!(lines[1].contains("\"Addr\":\"0x4000015000\""));
    }

    #[test]
    fn compact_suppresses_low_signal_import_hit_but_keeps_uncovered_unknowns() {
        let low_signal = TraceEvent::new(TraceCategory::Import, "_madvise")
            .plugin("imports")
            .call("import-hit")
            .arg("Address", "0x200003B00");
        let unknown = TraceEvent::new(TraceCategory::Import, "_future_import")
            .plugin("imports")
            .call("import-hit")
            .arg("Address", "0x20000AB00");

        assert!(is_compact_suppressed(&low_signal));
        assert!(!is_compact_suppressed(&unknown));
    }

    #[test]
    fn call_plugin_claims_enabled_calls() {
        let mut plugin = CallTracePlugin::new("syscalls").call("write");
        let write = TraceEvent::new(TraceCategory::Syscall, "syscall").call("write");
        let open = TraceEvent::new(TraceCategory::Syscall, "syscall").call("open");

        assert_eq!(
            plugin.on_event(&write).unwrap().plugin.as_deref(),
            Some("syscalls")
        );
        assert!(plugin.on_event(&open).is_none());
    }

    struct ExecPlugin;

    impl TracePlugin for ExecPlugin {
        fn name(&self) -> &'static str {
            "procmon"
        }

        fn on_event(&mut self, event: &TraceEvent) -> Option<TraceEvent> {
            if event.call.as_deref() == Some("execve") {
                Some(event.clone().plugin(self.name()))
            } else {
                None
            }
        }
    }

    #[test]
    fn plugin_registry_only_emits_plugin_selected_events() {
        let mut plugins = PluginRegistry::new();
        plugins.register(ExecPlugin);

        let produced =
            plugins.dispatch(&TraceEvent::new(TraceCategory::Process, "exec").call("execve"));

        assert_eq!(plugins.plugin_names(), vec!["procmon"]);
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].plugin.as_deref(), Some("procmon"));
    }
}
