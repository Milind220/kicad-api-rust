use crate::error::KiCadError;

use super::decode::*;
use super::format::*;
use super::items::{
    bucket_items_by_pcb_object_type, deleted_item_ids_from_response, pcb_object_type_for_any,
};
use super::mappers::*;
use super::{
    envelope, is_get_open_documents_unhandled, normalize_socket_uri, project_path_from_environment,
    resolve_current_project_path, select_single_board_document, select_single_project_path,
    CMD_BEGIN_COMMIT, CMD_CREATE_ITEMS, CMD_DELETE_ITEMS, CMD_END_COMMIT, CMD_GET_BOARD_LAYER_NAME,
    CMD_GET_NETS, CMD_GET_SELECTION, CMD_GET_VERSION, CMD_PING, KIPRJMOD_ENV, PCB_OBJECT_TYPES,
    RES_BOARD_LAYER_NAME_RESPONSE, RES_CREATE_ITEMS_RESPONSE, RES_DELETE_ITEMS_RESPONSE,
    RES_GET_NETS, RES_GET_VERSION, RES_PROTOBUF_EMPTY, RES_SELECTION_RESPONSE,
};

#[cfg(test)]
mod tests {
    use super::{
        any_to_pretty_debug, board_editor_appearance_settings_to_proto, board_stackup_to_proto,
        board_text_spec_to_proto, bucket_items_by_pcb_object_type, commit_action_to_proto,
        decode_pcb_item, deleted_item_ids_from_response, drc_severity_to_proto,
        ensure_item_deletion_status_ok, ensure_item_request_ok, ensure_item_status_ok,
        is_get_open_documents_unhandled, layer_to_model, map_board_stackup, map_commit_session,
        map_hit_test_result, map_item_bounding_boxes, map_merge_mode_to_proto,
        map_polygon_with_holes, map_run_action_status, model_document_to_proto,
        normalize_socket_uri, pad_netlist_from_footprint_items, pcb_object_type_for_any,
        project_document_proto, project_path_from_environment, resolve_current_project_path,
        response_payload_as_any, select_single_board_document, select_single_project_path,
        selection_item_detail, summarize_item_details, summarize_selection,
        text_horizontal_alignment_to_proto, text_spec_to_proto, KiCadError, KIPRJMOD_ENV,
        PCB_OBJECT_TYPES,
    };
    use crate::model::board::{
        BoardLayerInfo, BoardStackup, BoardStackupLayer, BoardStackupLayerType, BoardTextSpec,
        PcbBarcodeErrorCorrection, PcbBarcodeKind, PcbItem, PcbViaType, Vector2Nm,
    };
    use crate::model::common::{
        CommitAction, DocumentSpecifier, DocumentType, ProjectInfo, TextAttributesSpec,
        TextHorizontalAlignment, TextSpec, TextVerticalAlignment,
    };
    use prost::Message;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn normalize_socket_uri_adds_ipc_scheme() {
        let normalized = normalize_socket_uri("/tmp/kicad/api.sock");
        assert_eq!(normalized, "ipc:///tmp/kicad/api.sock");
    }

    #[test]
    fn normalize_socket_uri_preserves_existing_scheme() {
        let normalized = normalize_socket_uri("ipc:///tmp/kicad/api.sock");
        assert_eq!(normalized, "ipc:///tmp/kicad/api.sock");
    }

    #[test]
    fn project_document_proto_uses_project_type() {
        let document = project_document_proto();
        assert_eq!(document.r#type, DocumentType::Project.to_proto());
        assert!(document.identifier.is_none());
    }

    #[test]
    fn select_single_project_path_picks_unique_path() {
        let docs = vec![DocumentSpecifier {
            document_type: DocumentType::Pcb,
            board_filename: Some("demo.kicad_pcb".to_string()),
            project: ProjectInfo {
                name: Some("demo".to_string()),
                path: Some(PathBuf::from("/tmp/demo")),
            },
        }];

        let result = select_single_project_path(&docs)
            .expect("a single project path should be selected when exactly one path exists");
        assert_eq!(result, PathBuf::from("/tmp/demo"));
    }

    #[test]
    fn select_single_project_path_errors_on_ambiguity() {
        let docs = vec![
            DocumentSpecifier {
                document_type: DocumentType::Pcb,
                board_filename: Some("a.kicad_pcb".to_string()),
                project: ProjectInfo {
                    name: Some("a".to_string()),
                    path: Some(PathBuf::from("/tmp/a")),
                },
            },
            DocumentSpecifier {
                document_type: DocumentType::Pcb,
                board_filename: Some("b.kicad_pcb".to_string()),
                project: ProjectInfo {
                    name: Some("b".to_string()),
                    path: Some(PathBuf::from("/tmp/b")),
                },
            },
        ];

        let result = select_single_project_path(&docs);
        assert!(matches!(
            result,
            Err(KiCadError::AmbiguousProjectPath { .. })
        ));
    }

    #[test]
    fn select_single_project_path_requires_open_board() {
        let docs: Vec<DocumentSpecifier> = Vec::new();
        let result = select_single_project_path(&docs);
        assert!(matches!(result, Err(KiCadError::BoardNotOpen)));
    }

    #[test]
    fn resolve_current_project_path_reads_env_when_open_docs_unhandled() {
        let _guard = ENV_MUTEX.lock().expect("env mutex should lock");
        std::env::set_var(KIPRJMOD_ENV, "/tmp/kicad-env-project");

        let result = resolve_current_project_path(Err(KiCadError::ApiStatus {
            code: "AS_UNHANDLED".to_string(),
            message:
                "no handler available for request of type kiapi.common.commands.GetOpenDocuments"
                    .to_string(),
        }))
        .expect("KIPRJMOD fallback should resolve project path");

        assert_eq!(result, PathBuf::from("/tmp/kicad-env-project"));
        std::env::remove_var(KIPRJMOD_ENV);
    }

    #[test]
    fn resolve_current_project_path_keeps_original_error_without_env() {
        let _guard = ENV_MUTEX.lock().expect("env mutex should lock");
        std::env::remove_var(KIPRJMOD_ENV);

        let err = resolve_current_project_path(Err(KiCadError::ApiStatus {
            code: "AS_UNHANDLED".to_string(),
            message:
                "no handler available for request of type kiapi.common.commands.GetOpenDocuments"
                    .to_string(),
        }))
        .expect_err("without env fallback should keep original unhandled error");

        assert!(matches!(err, KiCadError::ApiStatus { .. }));
    }

    #[test]
    fn resolve_current_project_path_does_not_fallback_when_no_board_docs() {
        let _guard = ENV_MUTEX.lock().expect("env mutex should lock");
        std::env::set_var(KIPRJMOD_ENV, "/tmp/kicad-env-project");

        let err = resolve_current_project_path(Ok(Vec::new()))
            .expect_err("no-board docs should remain BoardNotOpen");
        assert!(matches!(err, KiCadError::BoardNotOpen));

        std::env::remove_var(KIPRJMOD_ENV);
    }

    #[test]
    fn project_path_from_environment_ignores_empty_values() {
        let _guard = ENV_MUTEX.lock().expect("env mutex should lock");
        std::env::set_var(KIPRJMOD_ENV, "   ");
        assert!(project_path_from_environment().is_none());
        std::env::remove_var(KIPRJMOD_ENV);
    }

    #[test]
    fn is_get_open_documents_unhandled_matches_expected_shape() {
        let unhandled = KiCadError::ApiStatus {
            code: "AS_UNHANDLED".to_string(),
            message: String::new(),
        };
        assert!(is_get_open_documents_unhandled(&unhandled));

        let other = KiCadError::ApiStatus {
            code: "AS_BAD_REQUEST".to_string(),
            message: "bad request".to_string(),
        };
        assert!(!is_get_open_documents_unhandled(&other));
    }

    #[test]
    fn select_single_board_document_errors_on_multiple_open_boards() {
        let docs = vec![
            DocumentSpecifier {
                document_type: DocumentType::Pcb,
                board_filename: Some("a.kicad_pcb".to_string()),
                project: ProjectInfo {
                    name: Some("a".to_string()),
                    path: Some(PathBuf::from("/tmp/a")),
                },
            },
            DocumentSpecifier {
                document_type: DocumentType::Pcb,
                board_filename: Some("b.kicad_pcb".to_string()),
                project: ProjectInfo {
                    name: Some("b".to_string()),
                    path: Some(PathBuf::from("/tmp/b")),
                },
            },
        ];

        let result = select_single_board_document(&docs);
        assert!(matches!(
            result,
            Err(KiCadError::AmbiguousBoardSelection { .. })
        ));
    }

    #[test]
    fn layer_to_model_formats_unknown_id() {
        let layer = layer_to_model(999);
        assert_eq!(layer.name, "UNKNOWN_LAYER(999)");
        assert_eq!(layer.id, 999);
    }

    #[test]
    fn model_document_to_proto_carries_board_filename_and_project() {
        let document = DocumentSpecifier {
            document_type: DocumentType::Pcb,
            board_filename: Some("demo.kicad_pcb".to_string()),
            project: ProjectInfo {
                name: Some("demo".to_string()),
                path: Some(PathBuf::from("/tmp/demo")),
            },
        };

        let proto = model_document_to_proto(&document);
        assert_eq!(
            proto.r#type,
            crate::model::common::DocumentType::Pcb.to_proto()
        );
        let identifier = proto.identifier.expect("identifier should be present");
        match identifier {
            crate::proto::kiapi::common::types::document_specifier::Identifier::BoardFilename(
                filename,
            ) => assert_eq!(filename, "demo.kicad_pcb"),
            other => panic!("unexpected identifier variant: {other:?}"),
        }

        let project = proto.project.expect("project should be present");
        assert_eq!(project.name, "demo");
        assert_eq!(project.path, "/tmp/demo");
    }

    #[test]
    fn map_commit_session_maps_commit_id() {
        let response = crate::proto::kiapi::common::commands::BeginCommitResponse {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "commit-123".to_string(),
            }),
        };

        let session = map_commit_session(response).expect("commit id should map");
        assert_eq!(session.id, "commit-123");
    }

    #[test]
    fn map_commit_session_requires_commit_id() {
        let response = crate::proto::kiapi::common::commands::BeginCommitResponse { id: None };
        let err = map_commit_session(response).expect_err("missing id must fail");
        assert!(matches!(err, KiCadError::InvalidResponse { .. }));
    }

    #[test]
    fn commit_action_to_proto_maps_known_variants() {
        assert_eq!(
            commit_action_to_proto(CommitAction::Commit),
            crate::proto::kiapi::common::commands::CommitAction::CmaCommit as i32
        );
        assert_eq!(
            commit_action_to_proto(CommitAction::Drop),
            crate::proto::kiapi::common::commands::CommitAction::CmaDrop as i32
        );
    }

    #[test]
    fn map_merge_mode_to_proto_maps_known_variants() {
        assert_eq!(
            map_merge_mode_to_proto(crate::model::common::MapMergeMode::Merge),
            crate::proto::kiapi::common::types::MapMergeMode::MmmMerge as i32
        );
        assert_eq!(
            map_merge_mode_to_proto(crate::model::common::MapMergeMode::Replace),
            crate::proto::kiapi::common::types::MapMergeMode::MmmReplace as i32
        );
    }

    #[test]
    fn drc_severity_to_proto_maps_known_variants() {
        assert_eq!(
            drc_severity_to_proto(crate::model::board::DrcSeverity::Warning),
            crate::proto::kiapi::board::commands::DrcSeverity::DrsWarning as i32
        );
        assert_eq!(
            drc_severity_to_proto(crate::model::board::DrcSeverity::Error),
            crate::proto::kiapi::board::commands::DrcSeverity::DrsError as i32
        );
    }

    #[test]
    fn board_editor_appearance_settings_to_proto_maps_known_variants() {
        let proto = board_editor_appearance_settings_to_proto(
            crate::model::board::BoardEditorAppearanceSettings {
                inactive_layer_display: crate::model::board::InactiveLayerDisplayMode::Hidden,
                net_color_display: crate::model::board::NetColorDisplayMode::Ratsnest,
                board_flip: crate::model::board::BoardFlipMode::FlippedX,
                ratsnest_display: crate::model::board::RatsnestDisplayMode::VisibleLayers,
            },
        );

        assert_eq!(
            proto.inactive_layer_display,
            crate::proto::kiapi::board::commands::InactiveLayerDisplayMode::IldmHidden as i32
        );
        assert_eq!(
            proto.net_color_display,
            crate::proto::kiapi::board::commands::NetColorDisplayMode::NcdmRatsnest as i32
        );
        assert_eq!(
            proto.board_flip,
            crate::proto::kiapi::board::commands::BoardFlipMode::BfmFlippedX as i32
        );
        assert_eq!(
            proto.ratsnest_display,
            crate::proto::kiapi::board::commands::RatsnestDisplayMode::RdmVisibleLayers as i32
        );
    }

    #[test]
    fn map_board_stackup_defaults_missing_optional_messages() {
        let mapped = map_board_stackup(crate::proto::kiapi::board::BoardStackup::default());
        assert_eq!(mapped.finish_type_name, "");
        assert!(!mapped.impedance_controlled);
        assert!(!mapped.edge_has_connector);
        assert!(!mapped.edge_has_castellated_pads);
        assert!(!mapped.edge_has_edge_plating);
        assert!(mapped.layers.is_empty());
    }

    #[test]
    fn map_board_stackup_maps_unknown_layer_type_enum() {
        let mapped = map_board_stackup(crate::proto::kiapi::board::BoardStackup {
            finish: None,
            impedance: None,
            edge: None,
            layers: vec![crate::proto::kiapi::board::BoardStackupLayer {
                thickness: None,
                layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                enabled: true,
                r#type: 777,
                dielectric: None,
                color: None,
                material_name: String::new(),
                user_name: String::new(),
            }],
        });
        assert!(matches!(
            mapped.layers.first().map(|layer| layer.layer_type),
            Some(BoardStackupLayerType::Unknown(777))
        ));
    }

    #[test]
    fn board_stackup_to_proto_maps_unknown_layer_type_and_missing_nested_messages() {
        let proto = board_stackup_to_proto(BoardStackup {
            finish_type_name: String::new(),
            impedance_controlled: false,
            edge_has_connector: false,
            edge_has_castellated_pads: false,
            edge_has_edge_plating: false,
            layers: vec![BoardStackupLayer {
                layer: BoardLayerInfo {
                    id: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    name: "BL_F_Cu".to_string(),
                },
                user_name: "F.Cu".to_string(),
                material_name: "Copper".to_string(),
                enabled: true,
                thickness_nm: None,
                layer_type: BoardStackupLayerType::Unknown(321),
                color: None,
                dielectric_layers: Vec::new(),
            }],
        });

        assert!(proto.finish.is_none());
        assert!(
            !proto
                .impedance
                .expect("impedance should always be present")
                .is_controlled
        );
        let edge = proto.edge.expect("edge should always be present");
        assert!(edge.connector.is_none());
        assert!(
            !edge
                .castellation
                .expect("castellation should be present")
                .has_castellated_pads
        );
        assert!(
            !edge
                .plating
                .expect("plating should be present")
                .has_edge_plating
        );
        let layer = proto.layers.first().expect("one layer should be present");
        assert!(layer.thickness.is_none());
        assert_eq!(layer.r#type, 321);
        assert!(layer.dielectric.is_none());
        assert!(layer.color.is_none());
    }

    #[test]
    fn board_stackup_to_proto_preserves_edge_connector_presence() {
        let proto = board_stackup_to_proto(BoardStackup {
            finish_type_name: "ENIG".to_string(),
            impedance_controlled: true,
            edge_has_connector: true,
            edge_has_castellated_pads: true,
            edge_has_edge_plating: true,
            layers: Vec::new(),
        });
        assert_eq!(
            proto.finish.expect("finish should be present").type_name,
            "ENIG"
        );
        let edge = proto.edge.expect("edge should be present");
        assert!(edge.connector.is_some());
        assert!(
            edge.castellation
                .expect("castellation should be present")
                .has_castellated_pads
        );
        assert!(
            edge.plating
                .expect("plating should be present")
                .has_edge_plating
        );
    }

    #[test]
    fn response_payload_as_any_validates_type_url() {
        let response = crate::proto::kiapi::common::ApiResponse {
            header: None,
            status: None,
            message: Some(prost_types::Any {
                type_url: super::envelope::type_url("kiapi.common.commands.GetVersionResponse"),
                value: Vec::new(),
            }),
        };

        let err = response_payload_as_any(response, "kiapi.common.commands.BeginCommitResponse")
            .expect_err("wrong type_url must fail");
        assert!(matches!(err, KiCadError::UnexpectedPayloadType { .. }));
    }

    #[test]
    fn response_payload_as_any_accepts_google_protobuf_empty_type() {
        let response = crate::proto::kiapi::common::ApiResponse {
            header: None,
            status: None,
            message: Some(prost_types::Any {
                type_url: super::envelope::type_url("google.protobuf.Empty"),
                value: Vec::new(),
            }),
        };

        let payload = response_payload_as_any(response, "google.protobuf.Empty")
            .expect("google.protobuf.Empty payload type should be accepted");
        assert_eq!(
            payload.type_url,
            super::envelope::type_url("google.protobuf.Empty")
        );
    }

    #[test]
    fn get_board_layer_name_response_decodes_expected_type_url() {
        let payload = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.commands.BoardLayerNameResponse"),
            value: crate::proto::kiapi::board::commands::BoardLayerNameResponse {
                name: "In1.Cu".to_string(),
            }
            .encode_to_vec(),
        };

        let decoded: crate::proto::kiapi::board::commands::BoardLayerNameResponse =
            super::decode_any(&payload, super::RES_BOARD_LAYER_NAME_RESPONSE)
                .expect("layer-name response should decode");

        assert_eq!(decoded.name, "In1.Cu");
    }

    #[test]
    fn get_board_layer_name_response_rejects_wrong_type_url() {
        let payload = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.commands.BoardLayerResponse"),
            value: crate::proto::kiapi::board::commands::BoardLayerNameResponse {
                name: "F.Cu".to_string(),
            }
            .encode_to_vec(),
        };

        let err =
            super::decode_any::<crate::proto::kiapi::board::commands::BoardLayerNameResponse>(
                &payload,
                super::RES_BOARD_LAYER_NAME_RESPONSE,
            )
            .expect_err("mismatched type_url should fail");

        assert!(matches!(err, KiCadError::UnexpectedPayloadType { .. }));
    }

    #[test]
    fn get_board_layer_name_command_type_url_matches_proto_name() {
        let command = crate::proto::kiapi::board::commands::GetBoardLayerName {
            board: None,
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
        };

        let any = super::envelope::pack_any(&command, super::CMD_GET_BOARD_LAYER_NAME);

        assert_eq!(
            any.type_url,
            super::envelope::type_url("kiapi.board.commands.GetBoardLayerName")
        );
    }

    #[test]
    fn summarize_selection_counts_payload_types() {
        let items = vec![
            prost_types::Any {
                type_url: "type.googleapis.com/kiapi.board.types.Track".to_string(),
                value: vec![1, 2, 3],
            },
            prost_types::Any {
                type_url: "type.googleapis.com/kiapi.board.types.Track".to_string(),
                value: vec![9],
            },
            prost_types::Any {
                type_url: "type.googleapis.com/kiapi.board.types.Via".to_string(),
                value: vec![7, 7],
            },
        ];

        let summary = summarize_selection(&items);
        assert_eq!(summary.total_items, 3);
        assert_eq!(summary.type_url_counts.len(), 2);
        assert_eq!(summary.type_url_counts[0].count, 2);
        assert_eq!(
            summary.type_url_counts[0].type_url,
            "type.googleapis.com/kiapi.board.types.Track"
        );
        assert_eq!(summary.type_url_counts[1].count, 1);
        assert_eq!(
            summary.type_url_counts[1].type_url,
            "type.googleapis.com/kiapi.board.types.Via"
        );
    }

    #[test]
    fn selection_item_detail_reports_track_fields() {
        let track = crate::proto::kiapi::board::types::Track {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "track-id".to_string(),
            }),
            start: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 1, y_nm: 2 }),
            end: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 3, y_nm: 4 }),
            width: Some(crate::proto::kiapi::common::types::Distance { value_nm: 99 }),
            locked: 0,
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
            net: Some(crate::proto::kiapi::board::types::Net {
                code: Some(crate::proto::kiapi::board::types::NetCode { value: 12 }),
                name: "GND".to_string(),
            }),
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Track"),
            value: track.encode_to_vec(),
        };

        let detail = selection_item_detail(&item).expect("track detail should decode");
        assert!(detail.contains("track id=track-id"));
        assert!(detail.contains("layer=BL_F_Cu"));
        assert!(detail.contains("net=12:GND"));
    }

    #[test]
    fn decode_pcb_item_maps_track_locked_state() {
        let track = crate::proto::kiapi::board::types::Track {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "track-id".to_string(),
            }),
            start: None,
            end: None,
            width: None,
            locked: crate::proto::kiapi::common::types::LockedState::LsLocked as i32,
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
            net: None,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Track"),
            value: track.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("track payload should decode");
        match parsed {
            PcbItem::Track(track) => {
                assert_eq!(track.id.as_deref(), Some("track-id"));
                assert_eq!(track.locked, crate::model::board::ItemLockState::Locked);
            }
            other => panic!("expected track item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_maps_via_layers() {
        let via = crate::proto::kiapi::board::types::Via {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "via-id".to_string(),
            }),
            position: Some(crate::proto::kiapi::common::types::Vector2 {
                x_nm: 100,
                y_nm: 200,
            }),
            pad_stack: Some(crate::proto::kiapi::board::types::PadStack {
                layers: vec![
                    crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    crate::proto::kiapi::board::types::BoardLayer::BlBCu as i32,
                ],
                drill: Some(crate::proto::kiapi::board::types::DrillProperties {
                    start_layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    end_layer: crate::proto::kiapi::board::types::BoardLayer::BlBCu as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            locked: 0,
            net: Some(crate::proto::kiapi::board::types::Net {
                code: Some(crate::proto::kiapi::board::types::NetCode { value: 7 }),
                name: "VCC".to_string(),
            }),
            r#type: crate::proto::kiapi::board::types::ViaType::VtBlindBuried as i32,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Via"),
            value: via.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("via payload should decode");
        match parsed {
            PcbItem::Via(via) => {
                assert_eq!(via.id.as_deref(), Some("via-id"));
                assert_eq!(via.via_type, PcbViaType::BlindBuried);
                let layers = via.layers.expect("via layers should decode");
                assert_eq!(layers.padstack_layers.len(), 2);
                assert_eq!(layers.padstack_layers[0].name, "BL_F_Cu");
                assert_eq!(layers.padstack_layers[1].name, "BL_B_Cu");
                assert_eq!(
                    layers
                        .drill_start_layer
                        .as_ref()
                        .map(|layer| layer.name.as_str()),
                    Some("BL_F_Cu")
                );
                assert_eq!(
                    layers
                        .drill_end_layer
                        .as_ref()
                        .map(|layer| layer.name.as_str()),
                    Some("BL_B_Cu")
                );
            }
            other => panic!("expected via item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_surfaces_padstack_orientation_for_an_oblong_pad() {
        // A rotated milled slot: a 3.0 mm x 1.2 mm oblong drill on a pad rotated
        // 37.5 degrees. KiCad reports that rotation on the pad stack
        // (`PadStack.angle`, "the overall rotation of this padstack"); the model
        // used to drop it. Prove it now reaches `PcbPadStack.angle_degrees`,
        // alongside the slot dimensions and shape needed to machine it.
        let pad = crate::proto::kiapi::board::types::Pad {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "pad-oblong".to_string(),
            }),
            locked: 0,
            number: "1".to_string(),
            net: None,
            r#type: crate::proto::kiapi::board::types::PadType::PtNpth as i32,
            pad_stack: Some(crate::proto::kiapi::board::types::PadStack {
                layers: vec![crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32],
                drill: Some(crate::proto::kiapi::board::types::DrillProperties {
                    start_layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    end_layer: crate::proto::kiapi::board::types::BoardLayer::BlBCu as i32,
                    diameter: Some(crate::proto::kiapi::common::types::Vector2 {
                        x_nm: 3_000_000,
                        y_nm: 1_200_000,
                    }),
                    shape: crate::proto::kiapi::board::types::DrillShape::DsOblong as i32,
                    ..Default::default()
                }),
                angle: Some(crate::proto::kiapi::common::types::Angle {
                    value_degrees: 37.5,
                }),
                ..Default::default()
            }),
            position: Some(crate::proto::kiapi::common::types::Vector2 {
                x_nm: 5_000_000,
                y_nm: 6_000_000,
            }),
            copper_clearance_override: None,
            pad_to_die_length: None,
            symbol_pin: None,
            pad_to_die_delay: None,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Pad"),
            value: pad.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("pad payload should decode");
        match parsed {
            PcbItem::Pad(pad) => {
                let stack = pad.pad_stack.expect("pad stack should decode");
                assert_eq!(
                    stack.angle_degrees,
                    Some(37.5),
                    "pad-stack orientation must survive decoding"
                );
                let drill = stack.drill.expect("drill should decode");
                let diameter = drill.diameter_nm.expect("slot diameter should decode");
                assert_eq!((diameter.x_nm, diameter.y_nm), (3_000_000, 1_200_000));
                assert_eq!(drill.shape.as_deref(), Some("DS_OBLONG"));
            }
            other => panic!("expected pad item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_leaves_padstack_orientation_none_when_unset() {
        // A plain round through-hole: no rotation reported, so the orientation
        // stays absent rather than defaulting to zero.
        let pad = crate::proto::kiapi::board::types::Pad {
            id: None,
            locked: 0,
            number: "1".to_string(),
            net: None,
            r#type: crate::proto::kiapi::board::types::PadType::PtPth as i32,
            pad_stack: Some(crate::proto::kiapi::board::types::PadStack {
                drill: Some(crate::proto::kiapi::board::types::DrillProperties {
                    diameter: Some(crate::proto::kiapi::common::types::Vector2 {
                        x_nm: 800_000,
                        y_nm: 800_000,
                    }),
                    shape: crate::proto::kiapi::board::types::DrillShape::DsCircle as i32,
                    ..Default::default()
                }),
                angle: None,
                ..Default::default()
            }),
            position: None,
            copper_clearance_override: None,
            pad_to_die_length: None,
            symbol_pin: None,
            pad_to_die_delay: None,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Pad"),
            value: pad.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("pad payload should decode");
        match parsed {
            PcbItem::Pad(pad) => {
                let stack = pad.pad_stack.expect("pad stack should decode");
                assert_eq!(stack.angle_degrees, None);
            }
            other => panic!("expected pad item, got {other:?}"),
        }
    }

    #[test]
    fn selection_item_detail_reports_via_layers() {
        let via = crate::proto::kiapi::board::types::Via {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "via-id".to_string(),
            }),
            position: Some(crate::proto::kiapi::common::types::Vector2 {
                x_nm: 100,
                y_nm: 200,
            }),
            pad_stack: Some(crate::proto::kiapi::board::types::PadStack {
                layers: vec![
                    crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    crate::proto::kiapi::board::types::BoardLayer::BlBCu as i32,
                ],
                drill: Some(crate::proto::kiapi::board::types::DrillProperties {
                    start_layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
                    end_layer: crate::proto::kiapi::board::types::BoardLayer::BlBCu as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            locked: 0,
            net: None,
            r#type: crate::proto::kiapi::board::types::ViaType::VtThrough as i32,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Via"),
            value: via.encode_to_vec(),
        };

        let detail = selection_item_detail(&item).expect("via detail should decode");
        assert!(detail.contains("type=VT_THROUGH"));
        assert!(detail.contains("pad_layers=BL_F_Cu,BL_B_Cu"));
        assert!(detail.contains("drill_span=BL_F_Cu->BL_B_Cu"));
    }

    #[test]
    fn decode_pcb_item_maps_group_item_ids() {
        let group = crate::proto::kiapi::board::types::Group {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "group-id".to_string(),
            }),
            name: "group-a".to_string(),
            items: vec![
                crate::proto::kiapi::common::types::Kiid {
                    value: "item-1".to_string(),
                },
                crate::proto::kiapi::common::types::Kiid {
                    value: "item-2".to_string(),
                },
            ],
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Group"),
            value: group.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("group payload should decode");
        match parsed {
            PcbItem::Group(group) => {
                assert_eq!(group.id.as_deref(), Some("group-id"));
                assert_eq!(group.item_count, 2);
                assert_eq!(
                    group.item_ids,
                    vec!["item-1".to_string(), "item-2".to_string()]
                );
            }
            other => panic!("expected group item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_maps_board_text_attributes() {
        let text = crate::proto::kiapi::board::types::BoardText {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "text-id".to_string(),
            }),
            text: Some(crate::proto::kiapi::common::types::Text {
                position: Some(crate::proto::kiapi::common::types::Vector2 {
                    x_nm: 123,
                    y_nm: 456,
                }),
                attributes: Some(crate::proto::kiapi::common::types::TextAttributes {
                    font_name: "KiCad Font".to_string(),
                    horizontal_alignment:
                        crate::proto::kiapi::common::types::HorizontalAlignment::HaCenter as i32,
                    vertical_alignment: crate::proto::kiapi::common::types::VerticalAlignment::VaTop
                        as i32,
                    stroke_width: Some(crate::proto::kiapi::common::types::Distance {
                        value_nm: 42,
                    }),
                    italic: true,
                    bold: false,
                    underlined: true,
                    mirrored: false,
                    multiline: true,
                    keep_upright: true,
                    size: Some(crate::proto::kiapi::common::types::Vector2 {
                        x_nm: 777,
                        y_nm: 888,
                    }),
                    ..Default::default()
                }),
                text: "HELLO".to_string(),
                hyperlink: "https://example.com".to_string(),
            }),
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFSilkS as i32,
            knockout: true,
            locked: crate::proto::kiapi::common::types::LockedState::LsUnlocked as i32,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.BoardText"),
            value: text.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("board text payload should decode");
        match parsed {
            PcbItem::BoardText(text) => {
                assert_eq!(text.id.as_deref(), Some("text-id"));
                assert_eq!(text.text.as_deref(), Some("HELLO"));
                assert_eq!(text.hyperlink.as_deref(), Some("https://example.com"));
                assert!(text.knockout);
                let attributes = text.attributes.expect("text attributes should map");
                assert_eq!(attributes.font_name.as_deref(), Some("KiCad Font"));
                assert_eq!(
                    attributes.horizontal_alignment.as_deref(),
                    Some("HA_CENTER")
                );
                assert_eq!(attributes.vertical_alignment.as_deref(), Some("VA_TOP"));
                assert_eq!(attributes.stroke_width_nm, Some(42));
                assert_eq!(
                    attributes.size_nm.map(|v| (v.x_nm, v.y_nm)),
                    Some((777, 888))
                );
            }
            other => panic!("expected board text item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_maps_reference_image() {
        let reference_image = crate::proto::kiapi::board::types::ReferenceImage {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "ref-image-id".to_string(),
            }),
            layer: crate::proto::kiapi::board::types::BoardLayer::BlDwgsUser as i32,
            position: Some(crate::proto::kiapi::common::types::Vector2 {
                x_nm: 1000,
                y_nm: 2000,
            }),
            transform_origin_offset: Some(crate::proto::kiapi::common::types::Vector2 {
                x_nm: 10,
                y_nm: 20,
            }),
            image_scale: Some(crate::proto::kiapi::common::types::Ratio { value: 1.25 }),
            image_data: vec![1, 2, 3, 4],
            locked: crate::proto::kiapi::common::types::LockedState::LsLocked as i32,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.ReferenceImage"),
            value: reference_image.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("reference image payload should decode");
        match parsed {
            PcbItem::ReferenceImage(reference_image) => {
                assert_eq!(reference_image.id.as_deref(), Some("ref-image-id"));
                assert_eq!(reference_image.layer.name, "BL_Dwgs_User");
                assert_eq!(
                    reference_image.position_nm.map(|p| (p.x_nm, p.y_nm)),
                    Some((1000, 2000))
                );
                assert_eq!(reference_image.image_scale, Some(1.25));
                assert_eq!(reference_image.image_data_len, 4);
                assert_eq!(
                    reference_image.locked,
                    crate::model::board::ItemLockState::Locked
                );
            }
            other => panic!("expected reference image item, got {other:?}"),
        }
    }

    #[test]
    fn decode_pcb_item_maps_barcode() {
        let barcode = crate::proto::kiapi::board::types::Barcode {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "barcode-id".to_string(),
            }),
            text: "HELLO".to_string(),
            kind: crate::proto::kiapi::board::types::BarcodeKind::BkQrCode as i32,
            error_correction: crate::proto::kiapi::board::types::BarcodeErrorCorrection::BecM
                as i32,
            position: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 5, y_nm: 6 }),
            orientation: Some(crate::proto::kiapi::common::types::Angle {
                value_degrees: 90.0,
            }),
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFSilkS as i32,
            width: Some(crate::proto::kiapi::common::types::Distance { value_nm: 700 }),
            height: Some(crate::proto::kiapi::common::types::Distance { value_nm: 800 }),
            show_text: true,
            text_height: Some(crate::proto::kiapi::common::types::Distance { value_nm: 120 }),
            knockout: true,
            knockout_margin: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 3, y_nm: 4 }),
            locked: crate::proto::kiapi::common::types::LockedState::LsUnlocked as i32,
        };

        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.Barcode"),
            value: barcode.encode_to_vec(),
        };

        let parsed = decode_pcb_item(item).expect("barcode payload should decode");
        match parsed {
            PcbItem::Barcode(barcode) => {
                assert_eq!(barcode.id.as_deref(), Some("barcode-id"));
                assert_eq!(barcode.text, "HELLO");
                assert_eq!(barcode.kind, PcbBarcodeKind::QrCode);
                assert_eq!(barcode.error_correction, PcbBarcodeErrorCorrection::M);
                assert_eq!(barcode.orientation_deg, Some(90.0));
                assert!(barcode.show_text);
                assert!(barcode.knockout);
                assert_eq!(barcode.width_nm, Some(700));
                assert_eq!(barcode.height_nm, Some(800));
            }
            other => panic!("expected barcode item, got {other:?}"),
        }
    }

    #[test]
    fn pad_netlist_from_footprint_items_extracts_pad_entries() {
        let pad = crate::proto::kiapi::board::types::Pad {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "pad-id".to_string(),
            }),
            locked: 0,
            number: "1".to_string(),
            net: Some(crate::proto::kiapi::board::types::Net {
                code: Some(crate::proto::kiapi::board::types::NetCode { value: 5 }),
                name: "Net-(P1-PM)".to_string(),
            }),
            r#type: crate::proto::kiapi::board::types::PadType::PtPth as i32,
            pad_stack: None,
            position: None,
            copper_clearance_override: None,
            pad_to_die_length: None,
            symbol_pin: None,
            pad_to_die_delay: None,
        };

        let footprint = crate::proto::kiapi::board::types::FootprintInstance {
            id: Some(crate::proto::kiapi::common::types::Kiid {
                value: "fp-id".to_string(),
            }),
            position: None,
            orientation: None,
            layer: crate::proto::kiapi::board::types::BoardLayer::BlFCu as i32,
            locked: 0,
            definition: Some(crate::proto::kiapi::board::types::Footprint {
                id: None,
                anchor: None,
                attributes: None,
                overrides: None,
                net_ties: Vec::new(),
                private_layers: Vec::new(),
                reference_field: None,
                value_field: None,
                datasheet_field: None,
                description_field: None,
                items: vec![prost_types::Any {
                    type_url: super::envelope::type_url("kiapi.board.types.Pad"),
                    value: pad.encode_to_vec(),
                }],
                jumpers: None,
            }),
            reference_field: Some(crate::proto::kiapi::board::types::Field {
                id: None,
                name: "Reference".to_string(),
                text: Some(crate::proto::kiapi::board::types::BoardText {
                    id: None,
                    text: Some(crate::proto::kiapi::common::types::Text {
                        position: None,
                        attributes: None,
                        text: "P1".to_string(),
                        hyperlink: String::new(),
                    }),
                    layer: 0,
                    knockout: false,
                    locked: 0,
                }),
                visible: true,
            }),
            value_field: None,
            datasheet_field: None,
            description_field: None,
            attributes: None,
            overrides: None,
            symbol_path: None,
            symbol_sheet_name: String::new(),
            symbol_sheet_filename: String::new(),
            symbol_footprint_filters: String::new(),
        };

        let items = vec![prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.FootprintInstance"),
            value: footprint.encode_to_vec(),
        }];

        let netlist = pad_netlist_from_footprint_items(items)
            .expect("pad netlist should decode from footprint");
        assert_eq!(netlist.len(), 1);
        let entry = &netlist[0];
        assert_eq!(entry.footprint_reference.as_deref(), Some("P1"));
        assert_eq!(entry.pad_number, "1");
        assert_eq!(entry.net_code, Some(5));
    }

    #[test]
    fn ensure_item_request_ok_accepts_ok_and_rejects_non_ok() {
        assert!(ensure_item_request_ok(
            crate::proto::kiapi::common::types::ItemRequestStatus::IrsOk as i32
        )
        .is_ok());

        assert!(ensure_item_request_ok(
            crate::proto::kiapi::common::types::ItemRequestStatus::IrsDocumentNotFound as i32
        )
        .is_err());
    }

    #[test]
    fn ensure_item_status_ok_accepts_ok_and_rejects_non_ok() {
        assert!(
            ensure_item_status_ok(Some(crate::proto::kiapi::common::commands::ItemStatus {
                code: crate::proto::kiapi::common::commands::ItemStatusCode::IscOk as i32,
                error_message: String::new(),
            }))
            .is_ok()
        );

        let err = ensure_item_status_ok(Some(crate::proto::kiapi::common::commands::ItemStatus {
            code: crate::proto::kiapi::common::commands::ItemStatusCode::IscInvalidType as i32,
            error_message: "bad item type".to_string(),
        }))
        .expect_err("non-OK item status should fail");
        match err {
            KiCadError::ItemStatus { code } => assert!(code.contains("ISC_INVALID_TYPE")),
            _ => panic!("expected item status error"),
        }
    }

    #[test]
    fn ensure_item_deletion_status_ok_accepts_ok_and_rejects_non_ok() {
        assert!(ensure_item_deletion_status_ok(
            crate::proto::kiapi::common::commands::ItemDeletionStatus::IdsOk as i32
        )
        .is_ok());

        let err = ensure_item_deletion_status_ok(
            crate::proto::kiapi::common::commands::ItemDeletionStatus::IdsNonexistent as i32,
        )
        .expect_err("non-OK item deletion status should fail");
        match err {
            KiCadError::ItemStatus { code } => assert_eq!(code, "IDS_NONEXISTENT"),
            _ => panic!("expected item status error"),
        }
    }

    #[test]
    fn summarize_item_details_reports_unknown_payload_as_unparsed() {
        let items = vec![prost_types::Any {
            type_url: "type.googleapis.com/kiapi.board.types.UnknownThing".to_string(),
            value: vec![1, 2, 3, 4],
        }];

        let details =
            summarize_item_details(items).expect("unknown types should still produce detail rows");
        assert_eq!(details.len(), 1);
        assert!(details[0].detail.contains("unparsed payload"));
        assert_eq!(details[0].raw_len, 4);
    }

    #[test]
    fn map_item_bounding_boxes_maps_ids_and_dimensions() {
        let ids = vec![crate::proto::kiapi::common::types::Kiid {
            value: "id-1".to_string(),
        }];
        let boxes = vec![crate::proto::kiapi::common::types::Box2 {
            position: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 10, y_nm: 20 }),
            size: Some(crate::proto::kiapi::common::types::Vector2 { x_nm: 30, y_nm: 40 }),
        }];

        let mapped = map_item_bounding_boxes(ids, boxes)
            .expect("box mapping should succeed when position and size are present");
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].item_id, "id-1");
        assert_eq!(mapped[0].x_nm, 10);
        assert_eq!(mapped[0].y_nm, 20);
        assert_eq!(mapped[0].width_nm, 30);
        assert_eq!(mapped[0].height_nm, 40);
    }

    #[test]
    fn map_hit_test_result_covers_known_variants() {
        assert_eq!(
            map_hit_test_result(
                crate::proto::kiapi::common::commands::HitTestResult::HtrHit as i32
            ),
            crate::model::common::ItemHitTestResult::Hit
        );
        assert_eq!(
            map_hit_test_result(
                crate::proto::kiapi::common::commands::HitTestResult::HtrNoHit as i32
            ),
            crate::model::common::ItemHitTestResult::NoHit
        );
    }

    #[test]
    fn map_run_action_status_covers_known_variants() {
        assert_eq!(
            map_run_action_status(
                crate::proto::kiapi::common::commands::RunActionStatus::RasOk as i32
            ),
            crate::model::common::RunActionStatus::Ok
        );
        assert_eq!(
            map_run_action_status(
                crate::proto::kiapi::common::commands::RunActionStatus::RasInvalid as i32
            ),
            crate::model::common::RunActionStatus::Invalid
        );
        assert_eq!(
            map_run_action_status(
                crate::proto::kiapi::common::commands::RunActionStatus::RasFrameNotOpen as i32
            ),
            crate::model::common::RunActionStatus::FrameNotOpen
        );
        assert_eq!(
            map_run_action_status(1234),
            crate::model::common::RunActionStatus::Unknown(1234)
        );
    }

    #[test]
    fn text_horizontal_alignment_to_proto_covers_known_variants() {
        assert_eq!(
            text_horizontal_alignment_to_proto(TextHorizontalAlignment::Left),
            crate::proto::kiapi::common::types::HorizontalAlignment::HaLeft as i32
        );
        assert_eq!(
            text_horizontal_alignment_to_proto(TextHorizontalAlignment::Indeterminate),
            crate::proto::kiapi::common::types::HorizontalAlignment::HaIndeterminate as i32
        );
    }

    #[test]
    fn text_spec_to_proto_maps_optional_fields() {
        let spec = TextSpec {
            text: "R1".to_string(),
            position_nm: Some(crate::model::board::Vector2Nm {
                x_nm: 1_000,
                y_nm: 2_000,
            }),
            attributes: Some(TextAttributesSpec {
                font_name: Some("KiCad Font".to_string()),
                horizontal_alignment: TextHorizontalAlignment::Center,
                ..TextAttributesSpec::default()
            }),
            hyperlink: Some("https://example.com".to_string()),
        };

        let proto = text_spec_to_proto(spec);
        assert_eq!(proto.text, "R1");
        assert_eq!(proto.hyperlink, "https://example.com");
        let position = proto.position.expect("position should be present");
        assert_eq!(position.x_nm, 1_000);
        assert_eq!(position.y_nm, 2_000);
        let attributes = proto.attributes.expect("attributes should be present");
        assert_eq!(attributes.font_name, "KiCad Font");
        assert_eq!(
            attributes.horizontal_alignment,
            crate::proto::kiapi::common::types::HorizontalAlignment::HaCenter as i32
        );
    }

    #[test]
    fn board_text_spec_to_proto_matches_kicad_python_defaults() {
        let spec = BoardTextSpec::front_silkscreen(
            "SILK",
            Vector2Nm {
                x_nm: 186_000_000,
                y_nm: 90_500_000,
            },
            Some(TextAttributesSpec {
                horizontal_alignment: TextHorizontalAlignment::Center,
                vertical_alignment: TextVerticalAlignment::Center,
                stroke_width_nm: Some(150_000),
                size_nm: Some(Vector2Nm {
                    x_nm: 1_500_000,
                    y_nm: 1_500_000,
                }),
                ..TextAttributesSpec::default()
            }),
        );

        let proto = board_text_spec_to_proto(spec);
        assert!(
            proto.id.is_none(),
            "unset IDs should let KiCad assign the created text KIID"
        );
        assert_eq!(
            proto.layer,
            crate::proto::kiapi::board::types::BoardLayer::BlFSilkS as i32
        );
        assert_eq!(
            proto.locked,
            crate::proto::kiapi::common::types::LockedState::LsUnlocked as i32
        );
        let text = proto.text.expect("text payload should be present");
        assert_eq!(text.text, "SILK");
        assert_eq!(
            text.position.map(|point| (point.x_nm, point.y_nm)),
            Some((186_000_000, 90_500_000))
        );
        let attributes = text.attributes.expect("attributes should be present");
        assert_eq!(
            attributes.horizontal_alignment,
            crate::proto::kiapi::common::types::HorizontalAlignment::HaCenter as i32
        );
        assert_eq!(
            attributes.stroke_width.map(|width| width.value_nm),
            Some(150_000)
        );
    }

    #[test]
    fn bucket_items_by_pcb_object_type_groups_combined_get_items_response() {
        let track = crate::proto::kiapi::board::types::Track::default();
        let text = crate::proto::kiapi::board::types::BoardText::default();
        let rows = bucket_items_by_pcb_object_type(vec![
            prost_types::Any {
                type_url: super::envelope::type_url("kiapi.board.types.Track"),
                value: track.encode_to_vec(),
            },
            prost_types::Any {
                type_url: super::envelope::type_url("kiapi.board.types.BoardText"),
                value: text.encode_to_vec(),
            },
        ])
        .expect("known item types should bucket");

        let trace_bucket = rows
            .iter()
            .find(|(object_type, _)| object_type.name == "KOT_PCB_TRACE")
            .expect("trace bucket should exist");
        assert_eq!(trace_bucket.1.len(), 1);
        let text_bucket = rows
            .iter()
            .find(|(object_type, _)| object_type.name == "KOT_PCB_TEXT")
            .expect("text bucket should exist");
        assert_eq!(text_bucket.1.len(), 1);
        let total_bucketed: usize = rows.iter().map(|(_, items)| items.len()).sum();
        assert_eq!(total_bucketed, 2);
    }

    #[test]
    fn bucket_items_by_pcb_object_type_rejects_unmapped_payloads() {
        let err = bucket_items_by_pcb_object_type(vec![prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.FutureThing"),
            value: Vec::new(),
        }])
        .expect_err("unknown returned item types should not be silently dropped");

        assert!(err
            .to_string()
            .contains("GetItems returned unmapped PCB item type"));
    }

    #[test]
    fn deleted_item_ids_from_response_falls_back_to_requested_ids_for_empty_success_rows() {
        let ids = deleted_item_ids_from_response(
            vec!["item-1".to_string()],
            crate::proto::kiapi::common::commands::DeleteItemsResponse {
                status: crate::proto::kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                deleted_items: Vec::new(),
                ..Default::default()
            },
        )
        .expect("empty successful delete response should use requested ids");

        assert_eq!(ids, vec!["item-1".to_string()]);
    }

    #[test]
    fn pcb_object_type_for_any_maps_board_text() {
        let item = prost_types::Any {
            type_url: super::envelope::type_url("kiapi.board.types.BoardText"),
            value: Vec::new(),
        };
        let object_type = pcb_object_type_for_any(&item).expect("board text should map");
        assert_eq!(object_type.name, "KOT_PCB_TEXT");
    }

    #[test]
    fn pcb_object_type_catalog_contains_expected_trace_entry() {
        assert!(PCB_OBJECT_TYPES
            .iter()
            .any(|entry| entry.name == "KOT_PCB_TRACE" && entry.code == 11));
    }

    #[test]
    fn any_to_pretty_debug_handles_unknown_type_without_error() {
        let unknown = prost_types::Any {
            type_url: "type.googleapis.com/kiapi.board.types.DoesNotExist".to_string(),
            value: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let debug = any_to_pretty_debug(&unknown)
            .expect("unknown Any payload type should not fail debug rendering");
        assert!(debug.contains("unparsed_any"));
        assert!(debug.contains("raw_len=4"));
    }

    #[test]
    fn map_polygon_with_holes_maps_points_and_arcs() {
        let polygon = crate::proto::kiapi::common::types::PolygonWithHoles {
            outline: Some(crate::proto::kiapi::common::types::PolyLine {
                nodes: vec![
                    crate::proto::kiapi::common::types::PolyLineNode {
                        geometry: Some(
                            crate::proto::kiapi::common::types::poly_line_node::Geometry::Point(
                                crate::proto::kiapi::common::types::Vector2 { x_nm: 10, y_nm: 20 },
                            ),
                        ),
                    },
                    crate::proto::kiapi::common::types::PolyLineNode {
                        geometry: Some(
                            crate::proto::kiapi::common::types::poly_line_node::Geometry::Arc(
                                crate::proto::kiapi::common::types::ArcStartMidEnd {
                                    start: Some(crate::proto::kiapi::common::types::Vector2 {
                                        x_nm: 0,
                                        y_nm: 0,
                                    }),
                                    mid: Some(crate::proto::kiapi::common::types::Vector2 {
                                        x_nm: 5,
                                        y_nm: 5,
                                    }),
                                    end: Some(crate::proto::kiapi::common::types::Vector2 {
                                        x_nm: 10,
                                        y_nm: 0,
                                    }),
                                },
                            ),
                        ),
                    },
                ],
                closed: true,
            }),
            holes: vec![crate::proto::kiapi::common::types::PolyLine {
                nodes: vec![crate::proto::kiapi::common::types::PolyLineNode {
                    geometry: Some(
                        crate::proto::kiapi::common::types::poly_line_node::Geometry::Point(
                            crate::proto::kiapi::common::types::Vector2 { x_nm: 1, y_nm: 1 },
                        ),
                    ),
                }],
                closed: true,
            }],
        };

        let mapped = map_polygon_with_holes(polygon).expect("polygon mapping should succeed");
        let outline = mapped.outline.expect("outline should be present");
        assert_eq!(outline.nodes.len(), 2);
        assert!(outline.closed);
        assert_eq!(mapped.holes.len(), 1);
    }

    #[test]
    fn map_polygon_with_holes_rejects_missing_arc_points() {
        let polygon = crate::proto::kiapi::common::types::PolygonWithHoles {
            outline: Some(crate::proto::kiapi::common::types::PolyLine {
                nodes: vec![crate::proto::kiapi::common::types::PolyLineNode {
                    geometry: Some(
                        crate::proto::kiapi::common::types::poly_line_node::Geometry::Arc(
                            crate::proto::kiapi::common::types::ArcStartMidEnd {
                                start: Some(crate::proto::kiapi::common::types::Vector2 {
                                    x_nm: 0,
                                    y_nm: 0,
                                }),
                                mid: None,
                                end: Some(crate::proto::kiapi::common::types::Vector2 {
                                    x_nm: 10,
                                    y_nm: 0,
                                }),
                            },
                        ),
                    ),
                }],
                closed: false,
            }),
            holes: Vec::new(),
        };

        let err = map_polygon_with_holes(polygon).expect_err("missing arc point must fail");
        assert!(matches!(err, KiCadError::InvalidResponse { .. }));
    }

    #[test]
    fn cmd_constants_use_kiapi_prefix() {
        let cmd_constants = [
            super::CMD_PING,
            super::CMD_GET_VERSION,
            super::CMD_GET_NETS,
            super::CMD_GET_SELECTION,
            super::CMD_CREATE_ITEMS,
            super::CMD_DELETE_ITEMS,
            super::CMD_BEGIN_COMMIT,
            super::CMD_END_COMMIT,
        ];
        for cmd in cmd_constants {
            assert!(
                cmd.starts_with("kiapi."),
                "CMD constant '{cmd}' should start with 'kiapi.'"
            );
        }
    }

    #[test]
    fn res_constants_use_expected_prefix() {
        let res_constants = [
            super::RES_GET_VERSION,
            super::RES_GET_NETS,
            super::RES_SELECTION_RESPONSE,
            super::RES_CREATE_ITEMS_RESPONSE,
            super::RES_DELETE_ITEMS_RESPONSE,
            super::RES_PROTOBUF_EMPTY,
        ];
        for res in res_constants {
            assert!(
                res.starts_with("kiapi.") || res.starts_with("google.protobuf."),
                "RES constant '{res}' should start with 'kiapi.' or 'google.protobuf.'"
            );
        }
    }

    #[test]
    fn pcb_object_types_catalog_is_nonempty_and_valid() {
        assert!(
            !super::PCB_OBJECT_TYPES.is_empty(),
            "PCB_OBJECT_TYPES should contain at least one entry"
        );
        for entry in super::PCB_OBJECT_TYPES.iter() {
            assert!(
                !entry.name.is_empty(),
                "PCB object type name should not be empty"
            );
            assert!(
                entry.code >= 0,
                "PCB object type code should be non-negative"
            );
        }
    }
}
