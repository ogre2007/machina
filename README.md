# Machina

`Machina` is a Rust project for emulating macOS `arm64` Mach-O binaries with a
malware-analysis focus.

The project is intentionally no longer a generic Qiling port. Its current scope
is:

- `arm64` macOS userland binaries
- Unicorn-backed CPU emulation
- synthetic macOS runtime services
- JSONL-first tracing and detection workflows
- fixture-driven compatibility work against real samples, including stealers

## Repository layout

- [src/bin/machina.rs](D:/dev/quiling/qiling/src/bin/machina.rs): CLI entrypoint
- [src/macos](D:/dev/quiling/qiling/src/macos): macOS emulation code
- [src/macos/core/mod.rs](D:/dev/quiling/qiling/src/macos/core/mod.rs): architecture-neutral emulation pipeline, tracing, and runtime façades
- [src/macos/arch_arm64/mod.rs](D:/dev/quiling/qiling/src/macos/arch_arm64/mod.rs): grouped view of arm64-specific modules
- [src/macos/platform_apple/mod.rs](D:/dev/quiling/qiling/src/macos/platform_apple/mod.rs): grouped view of Apple compatibility layers
- [src/macos/guest_model/mod.rs](D:/dev/quiling/qiling/src/macos/guest_model/mod.rs): grouped view of guest filesystem and memory helpers
- [fixtures](D:/dev/quiling/qiling/fixtures): development sample corpus and analysis notes
- [docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md): current fixture status and observed behavior

## Unicorn dependency

Machina uses the published `unicorn-engine` / `unicorn-engine-sys` crates as
normal Cargo dependencies.

There is no vendored Unicorn source tree in the repository anymore, and Unicorn
is not managed as a git submodule. [build.rs](D:/dev/quiling/qiling/build.rs)
only handles Windows-side `unicorn.dll` placement after Cargo builds the crate.

## Logging

Default runtime output is expected to be structured JSONL through the trace bus.
Human-readable `println!` diagnostics are legacy-only and should be treated as
debug output to be removed or gated over time.

Useful knobs:

- `MACHINA_PLUGIN_TRACE=1`: enable plugin trace bus
- `MACHINA_TRACE_FORMAT=jsonl`: force JSONL output
- `MACHINA_TRACE_FORMAT=human`: legacy human-readable sink for debugging
- `MACHINA_INDIRECT_BRANCH_MODE=fast`: default; skip expensive indirect-branch sanitizers
- `MACHINA_INDIRECT_BRANCH_MODE=sanitize`: enable indirect-branch sanitizers for debugging signed or tagged branch targets
- `MACHINA_PROFILE=default`: default; 60s timeout, 50M instruction budget (suitable for most samples and CI)
- `MACHINA_PROFILE=short`: legacy 15s / 10M-instruction budget (for tight smoke runs)
- `MACHINA_PROFILE=long`: 120s / 200M-instruction budget (recommended for RustDoor and other Rust binaries with large startup graphs)
- `MACHINA_PROFILE=extended`: 300s / 1B-instruction budget (deep analysis runs)
- `MACHINA_TIMEOUT_USECS` / `MACHINA_MAX_INSTRUCTIONS`: explicit overrides; always win over the active profile

## Build

```powershell
cargo build --bin machina
```

## Run

```powershell
cargo run --bin machina -- fixtures\macos\bin\arm64_hello
```

## Local AMOS integration check

Generate a JSONL trace:

```powershell
.\target\debug\machina.exe fixtures\macos\bin\2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho > amos-trace.jsonl
```

Validate that execution reached stealer logic and private-file access:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\ci\check_amos_trace.ps1 amos-trace.jsonl
```

## Sample corpus

The project keeps a small local corpus in
[fixtures/macos/bin](D:/dev/quiling/qiling/fixtures/macos/bin).

Two important analysis targets today:

- `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`
  AMOS stealer sample used to drive browser/wallet compatibility work
- `0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho`
  large arm64 sample used for deeper runtime and synthetic API coverage work

See [fixtures/README.md](D:/dev/quiling/qiling/fixtures/README.md) and
[docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md).

## Project status

Working today:

- arm64 Mach-O loading and execution
- synthetic imports, syscalls, guest filesystem model
- JSONL plugin events
- real sample progression into malware logic for AMOS-style paths

Still in progress:

- deeper normalization of all remaining legacy stdout diagnostics
- broader synthetic macOS API coverage
- directory-heavy profile emulation and richer artifact capture
- publication cleanup of remaining legacy compatibility layers inherited from the Qiling-era codebase

## License

GPL-2.0
