# kicad-ipc-rs

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Milind220/kicad-ipc-rust)

MIT-licensed Rust client library for the KiCad IPC API.

Maintainer workflow: see `CONTRIBUTIONS.md`.

## Status

Alpha. `v0.1.1` released.

- Async API (default): implemented and usable.
- Sync/blocking wrapper API (`feature = "blocking"`): implemented with full async parity.
- Real-world user testing: still limited.
- Issues and PRs welcome.

## Usage

### Async API (Default)

`Cargo.toml`:

```toml
[dependencies]
kicad-ipc-rs = "0.1.1"
tokio = { version = "1", features = ["macros", "rt"] }
```

```rust
use kicad_ipc_rs::KiCadClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), kicad_ipc_rs::KiCadError> {
    let client = KiCadClient::connect().await?;
    client.ping().await?;
    let version = client.get_version().await?;
    println!("KiCad: {}", version.full_version);
    Ok(())
}
```

### Sync API (Blocking)

Enable the `blocking` feature and use `KiCadClientBlocking` for synchronous callers:

`Cargo.toml`:

```toml
[dependencies]
kicad-ipc-rs = { version = "0.1.1", features = ["blocking"] }
```

```rust
use kicad_ipc_rs::KiCadClientBlocking;

fn main() -> Result<(), kicad_ipc_rs::KiCadError> {
    let client = KiCadClientBlocking::builder().connect()?;
    client.ping()?;
    let version = client.get_version()?;
    println!("KiCad: {}", version.full_version);
    Ok(())
}
```

Implementation notes:
- Blocking calls run through a dedicated Tokio runtime thread.
- Requests are serialized through a bounded queue.
- Runtime teardown is graceful: in-flight work drains before worker exit.

## Protobuf Source

This crate ships checked-in Rust protobuf output under `src/proto/generated/`.

- Consumers do **not** need KiCad source checkout or git submodules.
- Maintainers regenerate bindings from KiCad upstream via the `kicad` git submodule.
- Current proto pin: KiCad `10.0.0-rc1.1` (`KICAD_API_VERSION = 10.0.0-rc1.1-0-gc7c84125`).

Maintainer refresh flow:

```bash
git submodule update --init --recursive
./scripts/regenerate-protos.sh
```

The regeneration tool also stamps `KICAD_API_VERSION` from the KiCad submodule git revision.

## Local Testing

- CLI runbook: `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rs/docs/TEST_CLI.md`
- CLI help: `cargo run --features blocking --bin kicad-ipc-cli -- help`

## Runtime Compatibility Notes

- KiCad version (`kicad-ipc-cli version`): `10.0.0 (10.0.0-rc1)`

Commands wrapped in this crate but currently unhandled/unsupported by this KiCad build:

| Command | Runtime status | Notes |
| --- | --- | --- |
| `RefreshEditor` | `AS_UNHANDLED` | KiCad responds `no handler available for request of type kiapi.common.commands.RefreshEditor`. |

Runtime-verified operations include:
- `CreateItems`
- `UpdateItems`
- `DeleteItems`

## KiCad v10 RC1.1 API Completion Matrix

Legend:
- `Implemented` = wrapped in current Rust client (`src/client.rs`).
- `Not yet` = exists in proto, not wrapped yet.
- Command messages only (request payloads); helper/response messages excluded.

### Section Coverage

| Section | Proto Commands | Implemented | Coverage |
| --- | ---: | ---: | ---: |
| Common (base) | 6 | 6 | 100% |
| Common editor/document | 23 | 23 | 100% |
| Project manager | 5 | 5 | 100% |
| Board editor (PCB) | 22 | 22 | 100% |
| Schematic editor (dedicated proto commands) | 0 | 0 | n/a |
| **Total** | **56** | **56** | **100%** |

### Common (base)

| KiCad Command | Status | Rust API |
| --- | --- | --- |
| `Ping` | Implemented | `KiCadClient::ping` |
| `GetVersion` | Implemented | `KiCadClient::get_version` |
| `GetKiCadBinaryPath` | Implemented | `KiCadClient::get_kicad_binary_path_raw`, `KiCadClient::get_kicad_binary_path` |
| `GetTextExtents` | Implemented | `KiCadClient::get_text_extents_raw`, `KiCadClient::get_text_extents` |
| `GetTextAsShapes` | Implemented | `KiCadClient::get_text_as_shapes_raw`, `KiCadClient::get_text_as_shapes` |
| `GetPluginSettingsPath` | Implemented | `KiCadClient::get_plugin_settings_path_raw`, `KiCadClient::get_plugin_settings_path` |

### Common editor/document

| KiCad Command | Status | Rust API |
| --- | --- | --- |
| `RefreshEditor` | Implemented | `KiCadClient::refresh_editor` |
| `GetOpenDocuments` | Implemented | `KiCadClient::get_open_documents`, `KiCadClient::get_current_project_path`, `KiCadClient::has_open_board` |
| `SaveDocument` | Implemented | `KiCadClient::save_document_raw`, `KiCadClient::save_document` |
| `SaveCopyOfDocument` | Implemented | `KiCadClient::save_copy_of_document_raw`, `KiCadClient::save_copy_of_document` |
| `RevertDocument` | Implemented | `KiCadClient::revert_document_raw`, `KiCadClient::revert_document` |
| `RunAction` | Implemented | `KiCadClient::run_action_raw`, `KiCadClient::run_action` |
| `BeginCommit` | Implemented | `KiCadClient::begin_commit_raw`, `KiCadClient::begin_commit` |
| `EndCommit` | Implemented | `KiCadClient::end_commit_raw`, `KiCadClient::end_commit` |
| `CreateItems` | Implemented | `KiCadClient::create_items_raw`, `KiCadClient::create_items` |
| `GetItems` | Implemented | `KiCadClient::get_items_raw_by_type_codes`, `KiCadClient::get_items_by_type_codes`, `KiCadClient::get_items_details_by_type_codes`, `KiCadClient::get_all_pcb_items_raw`, `KiCadClient::get_all_pcb_items`, `KiCadClient::get_all_pcb_items_details`, `KiCadClient::get_pad_netlist` |
| `GetItemsById` | Implemented | `KiCadClient::get_items_by_id_raw`, `KiCadClient::get_items_by_id`, `KiCadClient::get_items_by_id_details` |
| `UpdateItems` | Implemented | `KiCadClient::update_items_raw`, `KiCadClient::update_items` |
| `DeleteItems` | Implemented | `KiCadClient::delete_items_raw`, `KiCadClient::delete_items` |
| `GetBoundingBox` | Implemented | `KiCadClient::get_item_bounding_boxes` |
| `GetSelection` | Implemented | `KiCadClient::get_selection_raw`, `KiCadClient::get_selection`, `KiCadClient::get_selection_summary`, `KiCadClient::get_selection_details` |
| `AddToSelection` | Implemented | `KiCadClient::add_to_selection_raw`, `KiCadClient::add_to_selection` |
| `RemoveFromSelection` | Implemented | `KiCadClient::remove_from_selection_raw`, `KiCadClient::remove_from_selection` |
| `ClearSelection` | Implemented | `KiCadClient::clear_selection_raw`, `KiCadClient::clear_selection` |
| `HitTest` | Implemented | `KiCadClient::hit_test_item` |
| `GetTitleBlockInfo` | Implemented | `KiCadClient::get_title_block_info` |
| `SaveDocumentToString` | Implemented | `KiCadClient::get_board_as_string` |
| `SaveSelectionToString` | Implemented | `KiCadClient::get_selection_as_string` |
| `ParseAndCreateItemsFromString` | Implemented | `KiCadClient::parse_and_create_items_from_string_raw`, `KiCadClient::parse_and_create_items_from_string` |

### Project manager

| KiCad Command | Status | Rust API |
| --- | --- | --- |
| `GetNetClasses` | Implemented | `KiCadClient::get_net_classes_raw`, `KiCadClient::get_net_classes` |
| `SetNetClasses` | Implemented | `KiCadClient::set_net_classes_raw`, `KiCadClient::set_net_classes` |
| `ExpandTextVariables` | Implemented | `KiCadClient::expand_text_variables_raw`, `KiCadClient::expand_text_variables` |
| `GetTextVariables` | Implemented | `KiCadClient::get_text_variables_raw`, `KiCadClient::get_text_variables` |
| `SetTextVariables` | Implemented | `KiCadClient::set_text_variables_raw`, `KiCadClient::set_text_variables` |

### Board editor (PCB)

| KiCad Command | Status | Rust API |
| --- | --- | --- |
| `GetBoardStackup` | Implemented | `KiCadClient::get_board_stackup_raw`, `KiCadClient::get_board_stackup` |
| `UpdateBoardStackup` | Implemented | `KiCadClient::update_board_stackup_raw`, `KiCadClient::update_board_stackup` |
| `GetBoardEnabledLayers` | Implemented | `KiCadClient::get_board_enabled_layers` |
| `SetBoardEnabledLayers` | Implemented | `KiCadClient::set_board_enabled_layers` |
| `GetGraphicsDefaults` | Implemented | `KiCadClient::get_graphics_defaults_raw`, `KiCadClient::get_graphics_defaults` |
| `GetBoardOrigin` | Implemented | `KiCadClient::get_board_origin` |
| `SetBoardOrigin` | Implemented | `KiCadClient::set_board_origin` |
| `GetNets` | Implemented | `KiCadClient::get_nets` |
| `GetItemsByNet` | Implemented | `KiCadClient::get_items_by_net_raw`, `KiCadClient::get_items_by_net` |
| `GetItemsByNetClass` | Implemented | `KiCadClient::get_items_by_net_class_raw`, `KiCadClient::get_items_by_net_class` |
| `GetNetClassForNets` | Implemented | `KiCadClient::get_netclass_for_nets_raw`, `KiCadClient::get_netclass_for_nets` |
| `RefillZones` | Implemented | `KiCadClient::refill_zones` |
| `GetPadShapeAsPolygon` | Implemented | `KiCadClient::get_pad_shape_as_polygon_raw`, `KiCadClient::get_pad_shape_as_polygon` |
| `CheckPadstackPresenceOnLayers` | Implemented | `KiCadClient::check_padstack_presence_on_layers_raw`, `KiCadClient::check_padstack_presence_on_layers` |
| `InjectDrcError` | Implemented | `KiCadClient::inject_drc_error_raw`, `KiCadClient::inject_drc_error` |
| `GetVisibleLayers` | Implemented | `KiCadClient::get_visible_layers` |
| `SetVisibleLayers` | Implemented | `KiCadClient::set_visible_layers` |
| `GetActiveLayer` | Implemented | `KiCadClient::get_active_layer` |
| `SetActiveLayer` | Implemented | `KiCadClient::set_active_layer` |
| `GetBoardEditorAppearanceSettings` | Implemented | `KiCadClient::get_board_editor_appearance_settings_raw`, `KiCadClient::get_board_editor_appearance_settings` |
| `SetBoardEditorAppearanceSettings` | Implemented | `KiCadClient::set_board_editor_appearance_settings` |
| `InteractiveMoveItems` | Implemented | `KiCadClient::interactive_move_items_raw`, `KiCadClient::interactive_move_items` |

### Schematic editor

| Item | Value |
| --- | --- |
| Dedicated commands in `kicad/api/proto/schematic/schematic_commands.proto` | None in current proto snapshot |
| Coverage | n/a |

### Symbol editor

| Item | Value |
| --- | --- |
| Dedicated symbol-editor command proto | None in current snapshot |
| Current path | Uses common editor/document commands via `DocumentType::DOCTYPE_SYMBOL` |

### Footprint editor

| Item | Value |
| --- | --- |
| Dedicated footprint-editor command proto | None in current snapshot |
| Current path | Uses common editor/document commands via `DocumentType::DOCTYPE_FOOTPRINT` |

## Roadmap

`v0.2.0` target:
- Expand runtime + integration testing coverage.
- Set up CI to run checks/tests on commits and PRs.
- Continue API hardening/docs/examples for stable `1.0` path.
