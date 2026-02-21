# Test CLI Runbook

CLI binary path:
- `test-scripts/kicad-ipc-cli.rs`

Run help:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- help
```

The CLI uses `KiCadClientBlocking` and validates the sync wrapper end-to-end.

## Prereqs

1. KiCad running.
2. API socket available (`KICAD_API_SOCKET` optional; auto-default works for typical setup).
3. For board-specific checks: PCB Editor has a board open.

## Commands

Ping:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- ping
```

Version:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- version
```

Resolve KiCad binary path (default `kicad-cli`):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- kicad-binary-path --binary-name kicad-cli
```

Resolve plugin settings path (default identifier `kicad-ipc-rust`):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- plugin-settings-path --identifier kicad-ipc-rust
```

List open PCB docs:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- open-docs --type pcb
```

Check board open:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- board-open
```

List nets:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- nets
```

List project net classes:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- net-classes
```

Write current net classes back with selected merge mode:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-net-classes --merge-mode merge
```

List text variables for current board document:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- text-variables
```

Set text variables:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-text-variables --merge-mode merge --var REV=A
```

Expand text variables in one or more input strings:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- expand-text-variables --text "${TITLE}" --text "${REVISION}"
```

Measure text extents:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- text-extents --text "R1"
```

Convert text to shape primitives:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- text-as-shapes --text "R1" --text "C5"
```

List enabled board layers:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- enabled-layers
```

Set enabled board layers:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-enabled-layers --copper-layer-count 2 --layer-id 47 --layer-id 52
```

Show active layer:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- active-layer
```

Set active layer:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-active-layer --layer-id 0
```

Show visible layers:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- visible-layers
```

Set visible layers:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-visible-layers --layer-id 0 --layer-id 31
```

Show board origin (grid origin by default):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- board-origin
```

Show drill origin:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- board-origin --type drill
```

Set board origin:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-board-origin --type grid --x-nm 1000000 --y-nm 2000000
```

Refresh PCB editor:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- refresh-editor --frame pcb
```

If your KiCad build does not expose this handler yet, this call may return `AS_UNHANDLED`.

Start a staged commit and print commit ID:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --client-name write-test begin-commit
```

End a staged commit:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --client-name write-test end-commit --id <commit-id> --action drop --message "cli test cleanup"
```

Save current board document:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- save-doc
```

Save a copy of current board document:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- save-copy --path /tmp/example.kicad_pcb --overwrite --include-project
```

Revert current board document from disk:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- revert-doc
```

Run a raw KiCad tool action:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- run-action --action pcbnew.InteractiveSelection.ClearSelection
```

Create raw Any item payload(s):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- create-items --item type.googleapis.com/kiapi.board.types.Text=<hex_payload>
```

Update raw Any item payload(s):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- update-items --item type.googleapis.com/kiapi.board.types.Text=<hex_payload>
```

Delete items by ID:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- delete-items --id <uuid> --id <uuid>
```

Parse and create items from s-expression:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- parse-create-items --contents "(kicad_pcb (version 20240108))"
```

Show summary of current PCB selection by item type:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- selection-summary
```

Show parsed details for currently selected items:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- selection-details
```

Show raw protobuf payload bytes for selected items:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- selection-raw
```

Add items to current selection:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- add-to-selection --id <uuid> --id <uuid>
```

Remove items from current selection:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- remove-from-selection --id <uuid> --id <uuid>
```

Clear current selection:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- clear-selection
```

Show pad-level netlist entries (footprint/pad/net):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- netlist-pads
```

Show parsed details for specific item IDs:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- items-by-id --id <uuid> --id <uuid>
```

Show item bounding boxes:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- item-bbox --id <uuid>
```

Include child text in the bounding box (for items such as footprints):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- item-bbox --id <uuid> --include-text
```

Run hit-test on a specific item:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- hit-test --id <uuid> --x-nm <x> --y-nm <y> --tolerance-nm 0
```

List all PCB object type IDs from the proto enum:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- types-pcb
```

Dump raw item payloads for one or more PCB object type IDs:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- items-raw --type-id 11 --type-id 13 --debug
```

Dump raw payloads for all PCB object classes:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- items-raw-all-pcb --debug
```

Check whether pads/vias have flashed padstack shapes on specific layers:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- padstack-presence --item-id <uuid> --layer-id 3 --layer-id 34 --debug
```

Get polygonized pad shape(s) on a specific layer:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- pad-shape-polygon --pad-id <uuid> --layer-id 3 --debug
```

Dump board text (KiCad s-expression):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- board-as-string
```

Dump selection text (KiCad s-expression):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- selection-as-string
```

Dump title block fields:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- title-block
```

Show typed stackup/graphics/appearance:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- stackup
cargo run --features blocking --bin kicad-ipc-cli -- update-stackup
cargo run --features blocking --bin kicad-ipc-cli -- graphics-defaults
cargo run --features blocking --bin kicad-ipc-cli -- appearance
```

Set editor appearance:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- set-appearance --inactive-layer-display hidden --net-color-display all --board-flip normal --ratsnest-display all-layers
```

Inject DRC marker:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- inject-drc-error --severity error --message "API marker test" --x-nm 1000000 --y-nm 1000000
```

Refill all zones:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- refill-zones
```

Start interactive move tool for one or more item IDs:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- interactive-move --id <uuid> --id <uuid>
```

Show typed netclass map:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- netclass
```

Print proto command coverage status (board read):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- proto-coverage-board-read
```

Generate full board-read reconstruction markdown report:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --timeout-ms 60000 board-read-report --out docs/BOARD_READ_REPORT.md
```

Notes:
- Report output is intentionally capped for very large boards to avoid multi-GB files.
- For full raw payloads, use targeted commands such as `items-raw --debug`, `pad-shape-polygon --debug`, and `padstack-presence --debug`.

Get current project path (derived from open PCB docs):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- project-path
```

Smoke check:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- smoke
```

## Common Flags

Custom socket:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --socket ipc:///tmp/kicad/api.sock ping
```

Custom token:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --token "$KICAD_API_TOKEN" version
```

Stable client name (needed when pairing `begin-commit` and `end-commit` across separate CLI runs):

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --client-name write-test begin-commit
```

Custom timeout:

```bash
cargo run --features blocking --bin kicad-ipc-cli -- --timeout-ms 5000 ping
```

## Failure Hints

- `Socket not available`: open KiCad + project/board; verify socket path.
- `BoardNotOpen`: open a board in PCB Editor.
- `AS_UNHANDLED`: command not enabled/handled in current KiCad build/config.
