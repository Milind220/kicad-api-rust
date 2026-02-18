# Test CLI Runbook

CLI binary path:
- `test-scripts/kicad-ipc-cli.rs`

Run help:

```bash
cargo run --bin kicad-ipc-cli -- help
```

## Prereqs

1. KiCad running.
2. API socket available (`KICAD_API_SOCKET` optional; auto-default works for typical setup).
3. For board-specific checks: PCB Editor has a board open.

## Commands

Ping:

```bash
cargo run --bin kicad-ipc-cli -- ping
```

Version:

```bash
cargo run --bin kicad-ipc-cli -- version
```

List open PCB docs:

```bash
cargo run --bin kicad-ipc-cli -- open-docs --type pcb
```

Check board open:

```bash
cargo run --bin kicad-ipc-cli -- board-open
```

Get current project path (derived from open PCB docs):

```bash
cargo run --bin kicad-ipc-cli -- project-path
```

Smoke check:

```bash
cargo run --bin kicad-ipc-cli -- smoke
```

## Common Flags

Custom socket:

```bash
cargo run --bin kicad-ipc-cli -- --socket ipc:///tmp/kicad/api.sock ping
```

Custom token:

```bash
cargo run --bin kicad-ipc-cli -- --token "$KICAD_API_TOKEN" version
```

Custom timeout:

```bash
cargo run --bin kicad-ipc-cli -- --timeout-ms 5000 ping
```

## Failure Hints

- `Socket not available`: open KiCad + project/board; verify socket path.
- `BoardNotOpen`: open a board in PCB Editor.
- `AS_UNHANDLED`: command not enabled/handled in current KiCad build/config.
