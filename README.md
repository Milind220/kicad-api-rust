# KiCad IPC API Rust

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Milind220/kicad-ipc-rust)

MIT-licensed Rust bindings for the KiCad IPC API.

## Current Status

Early scaffold phase. Core architecture + step-by-step implementation plan:
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/prompts/IPC_RUST_EXECUTION_PLAN.md`
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/README.md`

## Roadmap

1. Async-first layered client (`v0.1.0`)
2. Full PCB read surface + trace write capability (`v0.1.0`)
3. Blocking wrapper parity (`v0.2.0`)

## Local Testing

- CLI runbook: `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/docs/TEST_CLI.md`

## Runtime Compatibility Notes (Current Test Rig)

- Last verified: 2026-02-20
- KiCad version (`kicad-ipc-cli version`): `10.0.0 (10.0.0-rc1)`

Commands wrapped in this crate but currently unhandled/unsupported by this KiCad build:

| Command | Runtime status | Notes |
| --- | --- | --- |
| `RefreshEditor` | `AS_UNHANDLED` | KiCad responds `no handler available for request of type kiapi.common.commands.RefreshEditor`. |

Deferred manual/runtime verification (implemented after 2026-02-20 while user unavailable):

- `GetKiCadBinaryPath`
- `GetPluginSettingsPath`
- `SaveDocument`
- `SaveCopyOfDocument`
- `RevertDocument`
- `RunAction`
- `CreateItems`
- `UpdateItems`
- `DeleteItems`
- `ParseAndCreateItemsFromString`
- `SetNetClasses`
- `SetTextVariables`

## KiCad v10 RC1.1 API Completion Matrix

Source of truth for this matrix:
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/common/commands/base_commands.proto`
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/common/commands/editor_commands.proto`
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/common/commands/project_commands.proto`
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/board/board_commands.proto`
- `/Users/milindsharma/Developer/kicad-oss/kicad-ipc-rust/proto/schematic/schematic_commands.proto`

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
| Board editor (PCB) | 22 | 20 | 91% |
| Schematic editor (dedicated proto commands) | 0 | 0 | n/a |
| **Total** | **56** | **54** | **96%** |

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
| `UpdateBoardStackup` | Not yet | - |
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
| `InteractiveMoveItems` | Not yet | - |

### Schematic editor

| Item | Value |
| --- | --- |
| Dedicated commands in `proto/schematic/schematic_commands.proto` | None in current proto snapshot |
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
