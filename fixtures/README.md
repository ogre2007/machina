Machina keeps its local sample corpus in [fixtures/macos/bin](D:/dev/quiling/qiling/fixtures/macos/bin).

This corpus is intentionally small and is used for:

- smoke testing
- compatibility work against real binaries
- documenting analysis progress

## Important fixtures

- `arm64_hello`
  Minimal arm64 smoke-test binary.
- `2d0dda75bfc90e7ffda72640eb32c7ff9f51c90c30f4a6d1e05df93e58848f36.macho`
  AMOS stealer sample used to drive browser/wallet emulation work.
- `0393e898f4425195d780346634e619b80f283a8223b9724db56dee87afbba486.macho`
  Large arm64 sample kept as an execution target.

## Status tracking

Current execution and analysis notes live in
[docs/sample-status.md](D:/dev/quiling/qiling/docs/sample-status.md).

This fixture is also used by CI as an integration check: emulator output must
show generic private-file access behavior such as probing browser profile roots
and attempting to open wallet/browser data paths.
