//! Helpers for captured guest data.

#[derive(Debug, Clone, PartialEq)]
pub struct CaptureSummary {
    pub bytes: usize,
    pub fnv1a64: String,
    pub entropy: f64,
    pub preview: String,
    pub indicators: Vec<String>,
}

impl CaptureSummary {
    pub fn from_bytes(data: &[u8], preview_len: usize) -> Self {
        Self {
            bytes: data.len(),
            fnv1a64: fnv1a64_hex(data),
            entropy: shannon_entropy(data),
            preview: lossy_data_preview(data, preview_len),
            indicators: extract_ascii_indicators(data, 8, 8),
        }
    }
}

pub fn sanitize_capture_label(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .chars()
        .take(80)
        .collect()
}

pub fn fnv1a64_hex(data: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .copied()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn lossy_data_preview(data: &[u8], max_len: usize) -> String {
    let preview_len = data.len().min(max_len);
    let mut preview = String::new();
    for &byte in &data[..preview_len] {
        match byte {
            b'\n' => preview.push_str("\\n"),
            b'\r' => preview.push_str("\\r"),
            b'\t' => preview.push_str("\\t"),
            b'\\' => preview.push_str("\\\\"),
            b'"' => preview.push_str("\\\""),
            0x20..=0x7e => preview.push(byte as char),
            _ => preview.push('.'),
        }
    }
    if data.len() > preview_len {
        preview.push_str(&format!("...<{} bytes total>", data.len()));
    }
    preview
}

pub fn extract_ascii_indicators(data: &[u8], min_len: usize, max_items: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
            continue;
        }
        maybe_push_indicator(&mut result, &current, min_len, max_items);
        if result.len() >= max_items {
            return result;
        }
        current.clear();
    }

    maybe_push_indicator(&mut result, &current, min_len, max_items);
    result
}

fn maybe_push_indicator(
    result: &mut Vec<String>,
    current: &[u8],
    min_len: usize,
    max_items: usize,
) {
    if current.len() < min_len || result.len() >= max_items {
        return;
    }

    let text = String::from_utf8_lossy(current).trim().to_string();
    if text.is_empty() {
        return;
    }

    let interesting = text.contains("http")
        || text.contains("curl")
        || text.contains("wget")
        || text.contains("/bin/")
        || text.contains("chmod")
        || text.contains("osascript")
        || text.contains("launchctl")
        || text.contains("VERSION")
        || text.contains("ADVISORY");

    if interesting || result.is_empty() {
        result.push(text.chars().take(160).collect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_sanitizer_keeps_paths_filesystem_safe() {
        assert_eq!(
            sanitize_capture_label("pid=2 /bin/sh [\"x\"]"),
            "pid_2__bin_sh___x"
        );
    }

    #[test]
    fn preview_escapes_control_characters() {
        assert_eq!(lossy_data_preview(b"a\nb\tc", 32), "a\\nb\\tc");
    }

    #[test]
    fn preview_replaces_binary_noise_with_dots_and_json_safe_escapes() {
        assert_eq!(
            lossy_data_preview(&[0, b'"', b'\\', 0xff, b'A', b'\r'], 32),
            ".\\\"\\\\.A\\r"
        );
    }

    #[test]
    fn summary_extracts_stable_capture_metadata() {
        let summary = CaptureSummary::from_bytes(b"curl http://example.test/payload\n", 16);

        assert_eq!(summary.bytes, 33);
        assert_eq!(summary.fnv1a64.len(), 16);
        assert!(summary.entropy > 0.0);
        assert!(summary.preview.contains("curl"));
        assert!(summary.indicators[0].contains("http://example.test"));
    }
}
