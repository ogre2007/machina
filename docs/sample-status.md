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
  - daemon child PID=3 now reaches persistence/setup activity:
    - opens `~/.zshrc` (read-only then read-write) for shell-startup persistence injection
    - opens `~/.docks/cron` for cron-style persistence
    - creates `/tmp/com.apple.lock.<timestamp>` IPC/marker files
  - the LSE atomic hook now also handles `SWP[A][L]` and the rest of the `LDADD`/`LDCLR`/`LDEOR`/`LDSET`/`LDSMAX`/`LDSMIN`/`LDUMAX`/`LDUMIN` family, not just `CAS`/`LDADD`/`LDAPR`. The OnceLock release `SWPAL x8, x8, [x19]` at `0x10018242C` previously hung because Unicorn did not advance PC for it; with the explicit emulator that path now completes.
  - the synthetic `_waitpid` import now reports `ECHILD` for `WNOHANG` polls when no reapable child is left, mirroring `_wait4`. Without that, the post-OnceLock daemon spun forever in `waitpid(-1, &status, WNOHANG) == 0`.
  - the parent process (`PID=1`, after the daemon detached) now reaches Chrome-injection probing:
    - `_stat /Applications/Google Chrome.app/Contents/MacOS/Google Chrome` (Chrome detection)
    - `_stat /Users/analyst/.docks/.inj_rc_chr` → `ENOENT` (Chrome rc-injection marker)
    - `_stat /Users/analyst/.docks/.inj_launch_chr` → `ENOENT` (Chrome launch-injection marker)
  - currently stops with `WRITE_UNMAPPED` to a tagged pointer (`x0=0xA00000002`, tag `0xA`) downstream of the second `_waitpid`/`__error` poll, before the Chrome injection actually runs. The tagged data-write fault is not yet handled by the alias-page mapper.
- Important implication:
  - the main blocker has moved from the daemon's parking_lot-style atomic loop into a tagged-pointer data-write fault during Chrome injection bookkeeping
  - next compatibility work should extend the tagged-pointer alias mapper to write-side faults that synthesize a writable canonical-aliased page, then verify whether the parent reaches the actual `posix_spawnp` of `osascript` / `chflags hidden npm` / `curl` / `zsh -c zip -r ...` commands

## Corpus hygiene

- New samples should be added with a short status note here.
