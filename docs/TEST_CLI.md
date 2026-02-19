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

List nets:

```bash
cargo run --bin kicad-ipc-cli -- nets
```

List enabled board layers:

```bash
cargo run --bin kicad-ipc-cli -- enabled-layers
```

Show active layer:

```bash
cargo run --bin kicad-ipc-cli -- active-layer
```

Show visible layers:

```bash
cargo run --bin kicad-ipc-cli -- visible-layers
```

Show board origin (grid origin by default):

```bash
cargo run --bin kicad-ipc-cli -- board-origin
```

Show drill origin:

```bash
cargo run --bin kicad-ipc-cli -- board-origin --type drill
```

Show summary of current PCB selection by item type:

```bash
cargo run --bin kicad-ipc-cli -- selection-summary
```

Show parsed details for currently selected items:

```bash
cargo run --bin kicad-ipc-cli -- selection-details
```

Show raw protobuf payload bytes for selected items:

```bash
cargo run --bin kicad-ipc-cli -- selection-raw
```

Show pad-level netlist entries (footprint/pad/net):

```bash
cargo run --bin kicad-ipc-cli -- netlist-pads
```

Show parsed details for specific item IDs:

```bash
cargo run --bin kicad-ipc-cli -- items-by-id --id <uuid> --id <uuid>
```

Show item bounding boxes:

```bash
cargo run --bin kicad-ipc-cli -- item-bbox --id <uuid>
```

Include child text in the bounding box (for items such as footprints):

```bash
cargo run --bin kicad-ipc-cli -- item-bbox --id <uuid> --include-text
```

Run hit-test on a specific item:

```bash
cargo run --bin kicad-ipc-cli -- hit-test --id <uuid> --x-nm <x> --y-nm <y> --tolerance-nm 0
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
