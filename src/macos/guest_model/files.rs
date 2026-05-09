//! Architecture-agnostic guest-visible file and synthetic device model.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub enum GuestOpenTarget {
    File(u64),
    Directory(u64),
}

#[derive(Clone, Debug)]
pub enum SyntheticGuestFileKind {
    HostBytes(Vec<u8>),
    Urandom,
}

#[derive(Clone, Debug)]
pub struct SyntheticGuestFile {
    pub raw_path: String,
    pub resolved_path: PathBuf,
    pub kind: SyntheticGuestFileKind,
}

#[derive(Clone, Debug)]
pub struct SyntheticGuestDirectory {
    pub raw_path: String,
    pub resolved_path: PathBuf,
    pub entries: Vec<GuestDirectoryEntry>,
}

#[derive(Clone, Debug)]
pub struct GuestDirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct GuestPathPolicy {
    pub materialize_missing_paths: bool,
    pub synthetic_file_size: usize,
}

impl Default for GuestPathPolicy {
    fn default() -> Self {
        Self {
            materialize_missing_paths: true,
            synthetic_file_size: 4096,
        }
    }
}

#[derive(Debug, Default)]
pub struct GuestFileTable {
    pub next_file_id: u64,
    pub next_dir_id: u64,
    pub guest_fs_base: PathBuf,
    pub policy: GuestPathPolicy,
    pub files: HashMap<u64, SyntheticGuestFile>,
    pub directories: HashMap<u64, SyntheticGuestDirectory>,
    pub file_offsets: HashMap<(u64, u64), usize>,
    pub directory_offsets: HashMap<(u64, u64), usize>,
}

impl GuestFileTable {
    pub fn new(guest_fs_base: PathBuf) -> Self {
        Self {
            next_file_id: 1,
            next_dir_id: 1,
            guest_fs_base,
            ..Default::default()
        }
    }
}

pub fn resolve_guest_path(guest_fs_base: &Path, raw_path: &str) -> PathBuf {
    if raw_path.starts_with('/') {
        guest_fs_base.join(raw_path.trim_start_matches('/'))
    } else {
        guest_fs_base.join(raw_path)
    }
}

fn pseudo_random_bytes(seed: &str, size: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for byte in seed.as_bytes() {
        state = state.rotate_left(7) ^ (*byte as u64);
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
    }
    let mut out = Vec::with_capacity(size);
    for idx in 0..size {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let mut byte = state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8;
        if idx % 97 == 0 {
            byte = b'{';
        } else if idx % 97 == 1 {
            byte = b'}';
        } else if idx % 53 == 0 {
            byte = b'\n';
        } else if !byte.is_ascii_graphic() && byte != b' ' {
            byte = b'a' + (byte % 26);
        }
        out.push(byte);
    }
    out
}

pub fn materialize_synthetic_file_bytes(raw_path: &str, size: usize) -> Vec<u8> {
    let lower = raw_path.to_ascii_lowercase();
    if lower.ends_with("local state") {
        return br#"{"profile":{"info_cache":{"Default":{"name":"Default"}}},"os_crypt":{"encrypted_key":"QUJDREVGR0g="}}"#
            .to_vec();
    }
    if lower.ends_with("cookies") || lower.ends_with("login data") {
        return pseudo_random_bytes(raw_path, size.max(2048));
    }
    if lower.ends_with(".json")
        || lower.ends_with(".sqlite")
        || lower.ends_with(".ldb")
        || lower.ends_with(".log")
        || lower.ends_with(".txt")
    {
        return pseudo_random_bytes(raw_path, size.clamp(256, 1024));
    }
    if lower.contains("wallet") || lower.contains("seed") || lower.contains("key") {
        return pseudo_random_bytes(raw_path, size.clamp(512, 1024));
    }
    pseudo_random_bytes(raw_path, size)
}

fn path_looks_like_directory(raw_path: &str) -> bool {
    if raw_path.ends_with('/') || raw_path.ends_with('\\') {
        return true;
    }
    let Some(last) = raw_path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
    else {
        return true;
    };
    if last.is_empty() {
        return true;
    }
    let lower = last.to_ascii_lowercase();
    if lower == "default"
        || lower.starts_with("profile")
        || lower == "wallets"
        || lower == "profiles"
        || lower == "chrome"
        || lower == "firefox"
        || lower == "exodus"
        || lower == "coinomi"
        || lower == "leveldb"
    {
        return true;
    }
    !last.contains('.')
}

fn synthetic_directory_entries(raw_path: &str) -> Vec<GuestDirectoryEntry> {
    fn push_dir(entries: &mut Vec<GuestDirectoryEntry>, name: &str) {
        entries.push(GuestDirectoryEntry {
            name: name.to_string(),
            is_dir: true,
            size: 0,
        });
    }

    fn push_file(entries: &mut Vec<GuestDirectoryEntry>, name: &str, size: u64) {
        entries.push(GuestDirectoryEntry {
            name: name.to_string(),
            is_dir: false,
            size,
        });
    }

    let lower = raw_path.to_ascii_lowercase();
    let mut entries = vec![
        GuestDirectoryEntry {
            name: ".".to_string(),
            is_dir: true,
            size: 0,
        },
        GuestDirectoryEntry {
            name: "..".to_string(),
            is_dir: true,
            size: 0,
        },
    ];

    if lower.contains("firefox/profiles") {
        push_dir(&mut entries, "default-release");
        push_dir(&mut entries, "dev-edition-default");
    } else if lower.contains("google/chrome")
        || lower.contains("brave-browser")
        || lower.contains("microsoft edge")
    {
        push_dir(&mut entries, "Default");
        push_dir(&mut entries, "Profile 1");
        push_file(&mut entries, "Local State", 512);
    } else if lower.contains("leveldb") {
        push_file(&mut entries, "000003.ldb", 8192);
        push_file(&mut entries, "CURRENT", 16);
        push_file(&mut entries, "MANIFEST-000001", 2048);
    } else if lower.contains("wallet") || lower.contains("exodus") || lower.contains("coinomi") {
        push_file(&mut entries, "wallet.dat", 512);
        push_file(&mut entries, "seed.seco", 512);
        push_file(&mut entries, "config.json", 512);
    } else if lower.ends_with("/default") || lower.ends_with("\\default") {
        push_file(&mut entries, "Cookies", 8192);
        push_file(&mut entries, "Login Data", 12288);
        push_file(&mut entries, "History", 4096);
        push_dir(&mut entries, "Local Storage");
    } else {
        push_dir(&mut entries, "Default");
        push_dir(&mut entries, "Profile 1");
        push_file(&mut entries, "manifest.json", 512);
        push_file(&mut entries, "data.bin", 2048);
    }
    entries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    entries
}

fn synthetic_path_size(raw_path: &str, policy: &GuestPathPolicy) -> u64 {
    materialize_synthetic_file_bytes(raw_path, policy.synthetic_file_size).len() as u64
}

fn should_materialize_missing_path(raw_path: &str) -> bool {
    let Some(name) = raw_path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
    else {
        return true;
    };
    if name.starts_with(".inj_") {
        return false;
    }
    // RustDoor opens /tmp/com.apple.lock as a daemon-singleton check —
    // if it exists the new instance assumes another daemon is already
    // running and exits before reaching the C2 command loop. Treat the
    // file as absent so the freshly-emulated daemon "wins" the lock and
    // proceeds into the interesting commands.
    if raw_path == "/tmp/com.apple.lock" {
        return false;
    }
    true
}

fn synthesize_missing_open_target(
    table: &mut GuestFileTable,
    pid: u64,
    fd: u64,
    raw_path: &str,
    resolved: &Path,
) -> (GuestOpenTarget, PathBuf) {
    if path_looks_like_directory(raw_path) {
        let dir_id = table.next_dir_id.max(1);
        table.next_dir_id = dir_id.saturating_add(1);
        table.directories.insert(
            dir_id,
            SyntheticGuestDirectory {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.to_path_buf(),
                entries: synthetic_directory_entries(raw_path),
            },
        );
        table.directory_offsets.insert((pid, fd), 0);
        (GuestOpenTarget::Directory(dir_id), resolved.to_path_buf())
    } else {
        let file_id = table.next_file_id.max(1);
        table.next_file_id = file_id.saturating_add(1);
        table.files.insert(
            file_id,
            SyntheticGuestFile {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.to_path_buf(),
                kind: SyntheticGuestFileKind::HostBytes(materialize_synthetic_file_bytes(
                    raw_path,
                    table.policy.synthetic_file_size,
                )),
            },
        );
        table.file_offsets.insert((pid, fd), 0);
        (GuestOpenTarget::File(file_id), resolved.to_path_buf())
    }
}

fn read_directory_entries(resolved: &Path) -> Result<Vec<GuestDirectoryEntry>, u32> {
    let mut entries = vec![
        GuestDirectoryEntry {
            name: ".".to_string(),
            is_dir: true,
            size: 0,
        },
        GuestDirectoryEntry {
            name: "..".to_string(),
            is_dir: true,
            size: 0,
        },
    ];
    let read_dir = std::fs::read_dir(resolved).map_err(|_| 2u32)?;
    for entry in read_dir.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        entries.push(GuestDirectoryEntry {
            name: file_name,
            is_dir: meta.is_dir(),
            size: meta.len(),
        });
    }
    entries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    Ok(entries)
}

pub fn open_guest_path(
    table: &mut GuestFileTable,
    pid: u64,
    fd: u64,
    raw_path: &str,
) -> Result<(GuestOpenTarget, PathBuf), u32> {
    let resolved = resolve_guest_path(&table.guest_fs_base, raw_path);
    if raw_path == "/dev/urandom" {
        let file_id = table.next_file_id.max(1);
        table.next_file_id = file_id.saturating_add(1);
        table.files.insert(
            file_id,
            SyntheticGuestFile {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.clone(),
                kind: SyntheticGuestFileKind::Urandom,
            },
        );
        table.file_offsets.insert((pid, fd), 0);
        return Ok((GuestOpenTarget::File(file_id), resolved));
    }

    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) => meta,
        Err(_)
            if table.policy.materialize_missing_paths
                && should_materialize_missing_path(raw_path) =>
        {
            return Ok(synthesize_missing_open_target(
                table, pid, fd, raw_path, &resolved,
            ));
        }
        Err(_) => return Err(2u32),
    };
    if meta.is_dir() {
        let dir_id = table.next_dir_id.max(1);
        table.next_dir_id = dir_id.saturating_add(1);
        table.directories.insert(
            dir_id,
            SyntheticGuestDirectory {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.clone(),
                entries: read_directory_entries(&resolved)?,
            },
        );
        table.directory_offsets.insert((pid, fd), 0);
        Ok((GuestOpenTarget::Directory(dir_id), resolved))
    } else {
        let data = std::fs::read(&resolved).map_err(|_| 2u32)?;
        let file_id = table.next_file_id.max(1);
        table.next_file_id = file_id.saturating_add(1);
        table.files.insert(
            file_id,
            SyntheticGuestFile {
                raw_path: raw_path.to_string(),
                resolved_path: resolved.clone(),
                kind: SyntheticGuestFileKind::HostBytes(data),
            },
        );
        table.file_offsets.insert((pid, fd), 0);
        Ok((GuestOpenTarget::File(file_id), resolved))
    }
}

pub fn read_guest_file(
    table: &mut GuestFileTable,
    pid: u64,
    fd: u64,
    file_id: u64,
    count: usize,
) -> Option<(Vec<u8>, bool)> {
    let current_offset = table.file_offsets.get(&(pid, fd)).copied().unwrap_or(0);
    let (chunk, next_offset, eof) = match table.files.get(&file_id)? {
        SyntheticGuestFile {
            kind: SyntheticGuestFileKind::HostBytes(data),
            ..
        } => {
            let start = current_offset.min(data.len());
            let end = start.saturating_add(count).min(data.len());
            (data[start..end].to_vec(), end, end >= data.len())
        }
        SyntheticGuestFile {
            kind: SyntheticGuestFileKind::Urandom,
            ..
        } => {
            let mut out = Vec::with_capacity(count);
            let mut state = (current_offset as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xA5A5_5A5A_C3C3_3C3C);
            for _ in 0..count {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let byte = state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8;
                out.push(byte);
            }
            (out, current_offset.saturating_add(count), false)
        }
    };
    table.file_offsets.insert((pid, fd), next_offset);
    Some((chunk, eof))
}

pub fn stat_guest_path(table: &GuestFileTable, raw_path: &str) -> Result<(u64, PathBuf), u32> {
    let resolved = resolve_guest_path(&table.guest_fs_base, raw_path);
    match raw_path {
        "/dev/urandom" => Ok((0, resolved)),
        _ => match std::fs::metadata(&resolved) {
            Ok(meta) => Ok((meta.len(), resolved)),
            Err(_)
                if table.policy.materialize_missing_paths
                    && should_materialize_missing_path(raw_path) =>
            {
                Ok((synthetic_path_size(raw_path, &table.policy), resolved))
            }
            Err(_) => Err(2),
        },
    }
}

pub fn fstat_guest_file(table: &GuestFileTable, file_id: u64) -> Result<u64, u32> {
    match table.files.get(&file_id) {
        Some(SyntheticGuestFile {
            kind: SyntheticGuestFileKind::HostBytes(data),
            ..
        }) => Ok(data.len() as u64),
        Some(SyntheticGuestFile {
            kind: SyntheticGuestFileKind::Urandom,
            ..
        }) => Ok(0),
        None => Err(9),
    }
}

pub fn read_guest_directory_entry(
    table: &mut GuestFileTable,
    pid: u64,
    fd: u64,
    dir_id: u64,
) -> Option<GuestDirectoryEntry> {
    let current_offset = table
        .directory_offsets
        .get(&(pid, fd))
        .copied()
        .unwrap_or(0);
    let dir = table.directories.get(&dir_id)?;
    let entry = dir.entries.get(current_offset)?.clone();
    table
        .directory_offsets
        .insert((pid, fd), current_offset.saturating_add(1));
    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> GuestFileTable {
        GuestFileTable::new(std::env::temp_dir().join("machina-guest-files-test"))
    }

    #[test]
    fn stat_materializes_missing_analysis_artifacts() {
        let table = table();
        assert!(stat_guest_path(
            &table,
            "/Users/analyst/Library/Application Support/Google/Chrome/Default/Login Data"
        )
        .is_ok());
    }

    #[test]
    fn stat_does_not_materialize_injection_markers() {
        let table = table();
        assert_eq!(
            stat_guest_path(&table, "/Users/analyst/.docks/.inj_launch_chr"),
            Err(2)
        );
    }

    #[test]
    fn stat_does_not_materialize_rustdoor_singleton_lock() {
        let table = table();
        assert_eq!(stat_guest_path(&table, "/tmp/com.apple.lock"), Err(2));
    }
}
