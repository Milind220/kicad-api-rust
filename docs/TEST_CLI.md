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

List project net classes:

```bash
cargo run --bin kicad-ipc-cli -- net-classes
```

List text variables for current board document:

```bash
cargo run --bin kicad-ipc-cli -- text-variables
```

Expand text variables in one or more input strings:

```bash
cargo run --bin kicad-ipc-cli -- expand-text-variables --text "${TITLE}" --text "${REVISION}"
```

Measure text extents:

```bash
cargo run --bin kicad-ipc-cli -- text-extents --text "R1"
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

List all PCB object type IDs from the proto enum:

```bash
cargo run --bin kicad-ipc-cli -- types-pcb
```

Dump raw item payloads for one or more PCB object type IDs:

```bash
cargo run --bin kicad-ipc-cli -- items-raw --type-id 11 --type-id 13 --debug
```

Dump raw payloads for all PCB object classes:

```bash
cargo run --bin kicad-ipc-cli -- items-raw-all-pcb --debug
```

Check whether pads/vias have flashed padstack shapes on specific layers:

```bash
cargo run --bin kicad-ipc-cli -- padstack-presence --item-id <uuid> --layer-id 3 --layer-id 34 --debug
```

Get polygonized pad shape(s) on a specific layer:

```bash
cargo run --bin kicad-ipc-cli -- pad-shape-polygon --pad-id <uuid> --layer-id 3 --debug
```

Dump board text (KiCad s-expression):

```bash
cargo run --bin kicad-ipc-cli -- board-as-string
```

Dump selection text (KiCad s-expression):

```bash
cargo run --bin kicad-ipc-cli -- selection-as-string
```

Dump title block fields:

```bash
cargo run --bin kicad-ipc-cli -- title-block
```

Show typed stackup/graphics/appearance:

```bash
cargo run --bin kicad-ipc-cli -- stackup
cargo run --bin kicad-ipc-cli -- graphics-defaults
cargo run --bin kicad-ipc-cli -- appearance
```

Show typed netclass map:

```bash
cargo run --bin kicad-ipc-cli -- netclass
```

Print proto command coverage status (board read):

```bash
cargo run --bin kicad-ipc-cli -- proto-coverage-board-read
```

Generate full board-read reconstruction markdown report:

```bash
cargo run --bin kicad-ipc-cli -- --timeout-ms 60000 board-read-report --out docs/BOARD_READ_REPORT.md
```

Notes:
- Report output is intentionally capped for very large boards to avoid multi-GB files.
- For full raw payloads, use targeted commands such as `items-raw --debug`, `pad-shape-polygon --debug`, and `padstack-presence --debug`.

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
