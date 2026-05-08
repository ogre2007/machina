use std::path::Path;

use crate::macos::guest_memory::{alloc_bytes, alloc_cstr, stack_push_u64};
use crate::macos::{Emulator, MacOsError};
use crate::UnicornEmulator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestProcessBootstrap {
    pub argc: u64,
    pub arg0_addr: u64,
    pub env0_addr: u64,
    pub apple0_addr: u64,
    pub argv_addr: u64,
    pub envp_addr: u64,
    pub argc_addr: u64,
    pub ns_argv_ptr_addr: u64,
    pub ns_envp_ptr_addr: u64,
}

fn program_name(binary_path: &str) -> String {
    let normalized = binary_path.replace('\\', "/");
    Path::new(&normalized)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("program")
        .to_string()
}

pub fn setup_arm64_stack_bootstrap(
    emulator: &mut UnicornEmulator,
    heap_cursor: &mut u64,
    binary_path: &str,
    sp: u64,
) -> Result<GuestProcessBootstrap, MacOsError> {
    let argc = 1u64;
    let program_name = program_name(binary_path);
    let arg0_addr = alloc_cstr(emulator, heap_cursor, &program_name)?;
    let env_values = [
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/Users/analyst",
        "USER=analyst",
        "LOGNAME=analyst",
        "SHELL=/bin/zsh",
        "TMPDIR=/private/tmp/machina-analyst",
        "__CF_USER_TEXT_ENCODING=0x1F5:0:0",
    ];
    let mut env_addrs = Vec::with_capacity(env_values.len());
    for value in env_values {
        env_addrs.push(alloc_cstr(emulator, heap_cursor, value)?);
    }
    let env0_addr = env_addrs.first().copied().unwrap_or(0);
    let apple0_addr = alloc_cstr(emulator, heap_cursor, binary_path)?;

    let mut stack_sp = sp;
    stack_push_u64(emulator, &mut stack_sp, 0)?;
    let _apple_vec_addr = stack_push_u64(emulator, &mut stack_sp, apple0_addr)?;
    stack_push_u64(emulator, &mut stack_sp, 0)?;
    let mut envp_addr = 0;
    for &env_addr in env_addrs.iter().rev() {
        envp_addr = stack_push_u64(emulator, &mut stack_sp, env_addr)?;
    }
    stack_push_u64(emulator, &mut stack_sp, 0)?;
    let argv_addr = stack_push_u64(emulator, &mut stack_sp, arg0_addr)?;
    let argc_addr = stack_push_u64(emulator, &mut stack_sp, argc)?;

    emulator.write_reg("sp", argc_addr & !0xF)?;
    emulator.write_reg("x0", argc)?;
    emulator.write_reg("x1", argv_addr)?;
    emulator.write_reg("x2", envp_addr)?;
    let ns_argv_ptr_addr = alloc_bytes(emulator, heap_cursor, &[0u8; 8])?;
    emulator.write_memory(ns_argv_ptr_addr, &argv_addr.to_le_bytes())?;
    let ns_envp_ptr_addr = alloc_bytes(emulator, heap_cursor, &[0u8; 8])?;
    emulator.write_memory(ns_envp_ptr_addr, &envp_addr.to_le_bytes())?;

    Ok(GuestProcessBootstrap {
        argc,
        arg0_addr,
        env0_addr,
        apple0_addr,
        argv_addr,
        envp_addr,
        argc_addr,
        ns_argv_ptr_addr,
        ns_envp_ptr_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_name_uses_basename_or_safe_fallback() {
        assert_eq!(
            program_name(r"fixtures\macos\bin\arm64_hello"),
            "arm64_hello"
        );
        assert_eq!(program_name(""), "program");
    }
}
