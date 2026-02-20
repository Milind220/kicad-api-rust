use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::envelope;
use crate::error::KiCadError;
use crate::model::board::{
    ArcStartMidEndNm, BoardEditorAppearanceSettings, BoardEnabledLayers, BoardFlipMode,
    BoardLayerClass, BoardLayerGraphicsDefault, BoardLayerInfo, BoardNet, BoardOriginKind,
    BoardStackup, BoardStackupDielectricProperties, BoardStackupLayer, BoardStackupLayerType,
    ColorRgba, DrcSeverity, GraphicsDefaults, InactiveLayerDisplayMode, NetClassBoardSettings,
    NetClassForNetEntry, NetClassInfo, NetClassType, NetColorDisplayMode, PadNetEntry,
    PadShapeAsPolygonEntry, PadstackPresenceEntry, PadstackPresenceState, PcbArc,
    PcbBoardGraphicShape, PcbBoardText, PcbBoardTextBox, PcbDimension, PcbField, PcbFootprint,
    PcbGroup, PcbItem, PcbPad, PcbPadType, PcbTrack, PcbUnknownItem, PcbVia, PcbViaType, PcbZone,
    PcbZoneType, PolyLineNm, PolyLineNodeGeometryNm, PolygonWithHolesNm, RatsnestDisplayMode,
    Vector2Nm,
};
use crate::model::common::{
    CommitAction, CommitSession, DocumentSpecifier, DocumentType, EditorFrameType, ItemBoundingBox,
    ItemHitTestResult, MapMergeMode, PcbObjectTypeCode, ProjectInfo, RunActionStatus,
    SelectionItemDetail, SelectionSummary, SelectionTypeCount, TextAsShapesEntry,
    TextAttributesSpec, TextBoxSpec, TextExtents, TextHorizontalAlignment, TextObjectSpec,
    TextShape, TextShapeGeometry, TextSpec, TextVerticalAlignment, TitleBlockInfo, VersionInfo,
};
use crate::proto::kiapi::board as board_proto;
use crate::proto::kiapi::board::commands as board_commands;
use crate::proto::kiapi::board::types as board_types;
use crate::proto::kiapi::common::commands as common_commands;
use crate::proto::kiapi::common::project as common_project;
use crate::proto::kiapi::common::types as common_types;
use crate::transport::Transport;

const KICAD_API_SOCKET_ENV: &str = "KICAD_API_SOCKET";
const KICAD_API_TOKEN_ENV: &str = "KICAD_API_TOKEN";

const CMD_PING: &str = "kiapi.common.commands.Ping";
const CMD_GET_VERSION: &str = "kiapi.common.commands.GetVersion";
const CMD_GET_KICAD_BINARY_PATH: &str = "kiapi.common.commands.GetKiCadBinaryPath";
const CMD_GET_PLUGIN_SETTINGS_PATH: &str = "kiapi.common.commands.GetPluginSettingsPath";
const CMD_GET_NET_CLASSES: &str = "kiapi.common.commands.GetNetClasses";
const CMD_SET_NET_CLASSES: &str = "kiapi.common.commands.SetNetClasses";
const CMD_GET_TEXT_VARIABLES: &str = "kiapi.common.commands.GetTextVariables";
const CMD_EXPAND_TEXT_VARIABLES: &str = "kiapi.common.commands.ExpandTextVariables";
const CMD_GET_TEXT_EXTENTS: &str = "kiapi.common.commands.GetTextExtents";
const CMD_GET_TEXT_AS_SHAPES: &str = "kiapi.common.commands.GetTextAsShapes";
const CMD_REFRESH_EDITOR: &str = "kiapi.common.commands.RefreshEditor";
const CMD_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocuments";
const CMD_RUN_ACTION: &str = "kiapi.common.commands.RunAction";
const CMD_GET_NETS: &str = "kiapi.board.commands.GetNets";
const CMD_GET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.GetBoardEnabledLayers";
const CMD_SET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.SetBoardEnabledLayers";
const CMD_GET_ACTIVE_LAYER: &str = "kiapi.board.commands.GetActiveLayer";
const CMD_SET_ACTIVE_LAYER: &str = "kiapi.board.commands.SetActiveLayer";
const CMD_GET_VISIBLE_LAYERS: &str = "kiapi.board.commands.GetVisibleLayers";
const CMD_SET_VISIBLE_LAYERS: &str = "kiapi.board.commands.SetVisibleLayers";
const CMD_GET_BOARD_ORIGIN: &str = "kiapi.board.commands.GetBoardOrigin";
const CMD_SET_BOARD_ORIGIN: &str = "kiapi.board.commands.SetBoardOrigin";
const CMD_GET_BOARD_STACKUP: &str = "kiapi.board.commands.GetBoardStackup";
const CMD_GET_GRAPHICS_DEFAULTS: &str = "kiapi.board.commands.GetGraphicsDefaults";
const CMD_GET_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.GetBoardEditorAppearanceSettings";
const CMD_SET_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.SetBoardEditorAppearanceSettings";
const CMD_GET_ITEMS_BY_NET: &str = "kiapi.board.commands.GetItemsByNet";
const CMD_GET_ITEMS_BY_NET_CLASS: &str = "kiapi.board.commands.GetItemsByNetClass";
const CMD_GET_NETCLASS_FOR_NETS: &str = "kiapi.board.commands.GetNetClassForNets";
const CMD_REFILL_ZONES: &str = "kiapi.board.commands.RefillZones";
const CMD_GET_PAD_SHAPE_AS_POLYGON: &str = "kiapi.board.commands.GetPadShapeAsPolygon";
const CMD_CHECK_PADSTACK_PRESENCE_ON_LAYERS: &str =
    "kiapi.board.commands.CheckPadstackPresenceOnLayers";
const CMD_INJECT_DRC_ERROR: &str = "kiapi.board.commands.InjectDrcError";
const CMD_GET_SELECTION: &str = "kiapi.common.commands.GetSelection";
const CMD_ADD_TO_SELECTION: &str = "kiapi.common.commands.AddToSelection";
const CMD_REMOVE_FROM_SELECTION: &str = "kiapi.common.commands.RemoveFromSelection";
const CMD_CLEAR_SELECTION: &str = "kiapi.common.commands.ClearSelection";
const CMD_BEGIN_COMMIT: &str = "kiapi.common.commands.BeginCommit";
const CMD_END_COMMIT: &str = "kiapi.common.commands.EndCommit";
const CMD_CREATE_ITEMS: &str = "kiapi.common.commands.CreateItems";
const CMD_UPDATE_ITEMS: &str = "kiapi.common.commands.UpdateItems";
const CMD_DELETE_ITEMS: &str = "kiapi.common.commands.DeleteItems";
const CMD_PARSE_AND_CREATE_ITEMS_FROM_STRING: &str =
    "kiapi.common.commands.ParseAndCreateItemsFromString";
const CMD_GET_ITEMS: &str = "kiapi.common.commands.GetItems";
const CMD_GET_ITEMS_BY_ID: &str = "kiapi.common.commands.GetItemsById";
const CMD_GET_BOUNDING_BOX: &str = "kiapi.common.commands.GetBoundingBox";
const CMD_HIT_TEST: &str = "kiapi.common.commands.HitTest";
const CMD_GET_TITLE_BLOCK_INFO: &str = "kiapi.common.commands.GetTitleBlockInfo";
const CMD_SAVE_DOCUMENT: &str = "kiapi.common.commands.SaveDocument";
const CMD_SAVE_COPY_OF_DOCUMENT: &str = "kiapi.common.commands.SaveCopyOfDocument";
const CMD_REVERT_DOCUMENT: &str = "kiapi.common.commands.RevertDocument";
const CMD_SAVE_DOCUMENT_TO_STRING: &str = "kiapi.common.commands.SaveDocumentToString";
const CMD_SAVE_SELECTION_TO_STRING: &str = "kiapi.common.commands.SaveSelectionToString";

const RES_GET_VERSION: &str = "kiapi.common.commands.GetVersionResponse";
const RES_PATH_RESPONSE: &str = "kiapi.common.commands.PathResponse";
const RES_STRING_RESPONSE: &str = "kiapi.common.commands.StringResponse";
const RES_NET_CLASSES_RESPONSE: &str = "kiapi.common.commands.NetClassesResponse";
const RES_TEXT_VARIABLES: &str = "kiapi.common.project.TextVariables";
const RES_EXPAND_TEXT_VARIABLES_RESPONSE: &str =
    "kiapi.common.commands.ExpandTextVariablesResponse";
const RES_BOX2: &str = "kiapi.common.types.Box2";
const RES_GET_TEXT_AS_SHAPES_RESPONSE: &str = "kiapi.common.commands.GetTextAsShapesResponse";
const RES_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocumentsResponse";
const RES_RUN_ACTION_RESPONSE: &str = "kiapi.common.commands.RunActionResponse";
const RES_GET_NETS: &str = "kiapi.board.commands.NetsResponse";
const RES_GET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.BoardEnabledLayersResponse";
const RES_BOARD_LAYER_RESPONSE: &str = "kiapi.board.commands.BoardLayerResponse";
const RES_BOARD_LAYERS: &str = "kiapi.board.commands.BoardLayers";
const RES_BOARD_STACKUP_RESPONSE: &str = "kiapi.board.commands.BoardStackupResponse";
const RES_GRAPHICS_DEFAULTS_RESPONSE: &str = "kiapi.board.commands.GraphicsDefaultsResponse";
const RES_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.BoardEditorAppearanceSettings";
const RES_NETCLASS_FOR_NETS_RESPONSE: &str = "kiapi.board.commands.NetClassForNetsResponse";
const RES_PAD_SHAPE_AS_POLYGON_RESPONSE: &str = "kiapi.board.commands.PadShapeAsPolygonResponse";
const RES_PADSTACK_PRESENCE_RESPONSE: &str = "kiapi.board.commands.PadstackPresenceResponse";
const RES_INJECT_DRC_ERROR_RESPONSE: &str = "kiapi.board.commands.InjectDrcErrorResponse";
const RES_VECTOR2: &str = "kiapi.common.types.Vector2";
const RES_SELECTION_RESPONSE: &str = "kiapi.common.commands.SelectionResponse";
const RES_BEGIN_COMMIT_RESPONSE: &str = "kiapi.common.commands.BeginCommitResponse";
const RES_END_COMMIT_RESPONSE: &str = "kiapi.common.commands.EndCommitResponse";
const RES_CREATE_ITEMS_RESPONSE: &str = "kiapi.common.commands.CreateItemsResponse";
const RES_UPDATE_ITEMS_RESPONSE: &str = "kiapi.common.commands.UpdateItemsResponse";
const RES_DELETE_ITEMS_RESPONSE: &str = "kiapi.common.commands.DeleteItemsResponse";
const RES_GET_ITEMS_RESPONSE: &str = "kiapi.common.commands.GetItemsResponse";
const RES_GET_BOUNDING_BOX_RESPONSE: &str = "kiapi.common.commands.GetBoundingBoxResponse";
const RES_HIT_TEST_RESPONSE: &str = "kiapi.common.commands.HitTestResponse";
const RES_TITLE_BLOCK_INFO: &str = "kiapi.common.types.TitleBlockInfo";
const RES_SAVED_DOCUMENT_RESPONSE: &str = "kiapi.common.commands.SavedDocumentResponse";
const RES_SAVED_SELECTION_RESPONSE: &str = "kiapi.common.commands.SavedSelectionResponse";
const RES_PROTOBUF_EMPTY: &str = "google.protobuf.Empty";

const PAD_QUERY_CHUNK_SIZE: usize = 256;

const PCB_OBJECT_TYPES: [PcbObjectTypeCode; 18] = [
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbFootprint as i32,
        name: "KOT_PCB_FOOTPRINT",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbPad as i32,
        name: "KOT_PCB_PAD",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbShape as i32,
        name: "KOT_PCB_SHAPE",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbReferenceImage as i32,
        name: "KOT_PCB_REFERENCE_IMAGE",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbField as i32,
        name: "KOT_PCB_FIELD",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbGenerator as i32,
        name: "KOT_PCB_GENERATOR",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbText as i32,
        name: "KOT_PCB_TEXT",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbTextbox as i32,
        name: "KOT_PCB_TEXTBOX",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbTable as i32,
        name: "KOT_PCB_TABLE",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbTablecell as i32,
        name: "KOT_PCB_TABLECELL",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbTrace as i32,
        name: "KOT_PCB_TRACE",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbVia as i32,
        name: "KOT_PCB_VIA",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbArc as i32,
        name: "KOT_PCB_ARC",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbMarker as i32,
        name: "KOT_PCB_MARKER",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbDimension as i32,
        name: "KOT_PCB_DIMENSION",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbZone as i32,
        name: "KOT_PCB_ZONE",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbGroup as i32,
        name: "KOT_PCB_GROUP",
    },
    PcbObjectTypeCode {
        code: common_types::KiCadObjectType::KotPcbBarcode as i32,
        name: "KOT_PCB_BARCODE",
    },
];

#[derive(Clone, Debug)]
pub struct KiCadClient {
    inner: Arc<ClientInner>,
}

#[derive(Debug)]
struct ClientInner {
    transport: Transport,
    token: Mutex<String>,
    client_name: String,
    timeout: Duration,
    socket_uri: String,
}

#[derive(Clone, Debug)]
struct ClientConfig {
    timeout: Duration,
    socket_uri: Option<String>,
    token: Option<String>,
    client_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            config: ClientConfig {
                timeout: Duration::from_millis(3_000),
                socket_uri: None,
                token: None,
                client_name: None,
            },
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    pub fn socket_path(mut self, socket_path: impl Into<String>) -> Self {
        self.config.socket_uri = Some(socket_path.into());
        self
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.config.token = Some(token.into());
        self
    }

    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.config.client_name = Some(client_name.into());
        self
    }

    pub async fn connect(self) -> Result<KiCadClient, KiCadError> {
        let socket_uri = resolve_socket_uri(self.config.socket_uri.as_deref());
        if is_missing_ipc_socket(&socket_uri) {
            return Err(KiCadError::SocketUnavailable { socket_uri });
        }

        let timeout = self.config.timeout;
        let transport = Transport::connect(&socket_uri, timeout)?;

        let token = self
            .config
            .token
            .or_else(|| std::env::var(KICAD_API_TOKEN_ENV).ok())
            .unwrap_or_default();

        let client_name = self.config.client_name.unwrap_or_else(default_client_name);

        Ok(KiCadClient {
            inner: Arc::new(ClientInner {
                transport,
                token: Mutex::new(token),
                client_name,
                timeout,
                socket_uri,
            }),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KiCadClient {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub async fn connect() -> Result<Self, KiCadError> {
        ClientBuilder::new().connect().await
    }

    pub fn timeout(&self) -> Duration {
        self.inner.timeout
    }

    pub fn socket_uri(&self) -> &str {
        &self.inner.socket_uri
    }

    pub async fn ping(&self) -> Result<(), KiCadError> {
        let command = envelope::pack_any(&common_commands::Ping {}, CMD_PING);
        self.send_command(command).await?;
        Ok(())
    }

    pub async fn refresh_editor(&self, frame: EditorFrameType) -> Result<(), KiCadError> {
        let command = envelope::pack_any(
            &common_commands::RefreshEditor {
                frame: frame.to_proto(),
            },
            CMD_REFRESH_EDITOR,
        );
        self.send_command(command).await?;
        Ok(())
    }

    pub async fn run_action_raw(
        &self,
        action: impl Into<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::RunAction {
            action: action.into(),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_RUN_ACTION))
            .await?;
        response_payload_as_any(response, RES_RUN_ACTION_RESPONSE)
    }

    pub async fn run_action(
        &self,
        action: impl Into<String>,
    ) -> Result<RunActionStatus, KiCadError> {
        let payload = self.run_action_raw(action).await?;
        let response: common_commands::RunActionResponse =
            decode_any(&payload, RES_RUN_ACTION_RESPONSE)?;
        Ok(map_run_action_status(response.status))
    }

    pub async fn get_version(&self) -> Result<VersionInfo, KiCadError> {
        let command = envelope::pack_any(&common_commands::GetVersion {}, CMD_GET_VERSION);
        let response = self.send_command(command).await?;

        let payload: common_commands::GetVersionResponse =
            envelope::unpack_any(&response, RES_GET_VERSION)?;

        let version = payload.version.ok_or_else(|| KiCadError::MissingPayload {
            expected_type_url: "kiapi.common.types.KiCadVersion".to_string(),
        })?;

        Ok(VersionInfo {
            major: version.major,
            minor: version.minor,
            patch: version.patch,
            full_version: version.full_version,
        })
    }

    pub async fn get_kicad_binary_path_raw(
        &self,
        binary_name: impl Into<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetKiCadBinaryPath {
            binary_name: binary_name.into(),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_KICAD_BINARY_PATH))
            .await?;
        response_payload_as_any(response, RES_PATH_RESPONSE)
    }

    pub async fn get_kicad_binary_path(
        &self,
        binary_name: impl Into<String>,
    ) -> Result<String, KiCadError> {
        let payload = self.get_kicad_binary_path_raw(binary_name).await?;
        let response: common_commands::PathResponse = decode_any(&payload, RES_PATH_RESPONSE)?;
        Ok(response.path)
    }

    pub async fn get_plugin_settings_path_raw(
        &self,
        identifier: impl Into<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetPluginSettingsPath {
            identifier: identifier.into(),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_PLUGIN_SETTINGS_PATH))
            .await?;
        response_payload_as_any(response, RES_STRING_RESPONSE)
    }

    pub async fn get_plugin_settings_path(
        &self,
        identifier: impl Into<String>,
    ) -> Result<String, KiCadError> {
        let payload = self.get_plugin_settings_path_raw(identifier).await?;
        let response: common_commands::StringResponse = decode_any(&payload, RES_STRING_RESPONSE)?;
        Ok(response.response)
    }

    pub async fn get_open_documents(
        &self,
        document_type: DocumentType,
    ) -> Result<Vec<DocumentSpecifier>, KiCadError> {
        let command = common_commands::GetOpenDocuments {
            r#type: document_type.to_proto(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_OPEN_DOCUMENTS))
            .await?;

        let payload: common_commands::GetOpenDocumentsResponse =
            envelope::unpack_any(&response, RES_GET_OPEN_DOCUMENTS)?;

        Ok(payload
            .documents
            .into_iter()
            .filter_map(map_document_specifier)
            .collect())
    }

    pub async fn get_net_classes_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetNetClasses {};
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_NET_CLASSES))
            .await?;
        response_payload_as_any(response, RES_NET_CLASSES_RESPONSE)
    }

    pub async fn get_net_classes(&self) -> Result<Vec<NetClassInfo>, KiCadError> {
        let payload = self.get_net_classes_raw().await?;
        let response: common_commands::NetClassesResponse =
            decode_any(&payload, RES_NET_CLASSES_RESPONSE)?;

        let mut classes: Vec<NetClassInfo> = response
            .net_classes
            .into_iter()
            .map(map_net_class_info)
            .collect();
        classes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(classes)
    }

    pub async fn set_net_classes_raw(
        &self,
        net_classes: Vec<NetClassInfo>,
        merge_mode: MapMergeMode,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SetNetClasses {
            net_classes: net_classes
                .into_iter()
                .map(net_class_info_to_proto)
                .collect(),
            merge_mode: map_merge_mode_to_proto(merge_mode),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_SET_NET_CLASSES))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    pub async fn set_net_classes(
        &self,
        net_classes: Vec<NetClassInfo>,
        merge_mode: MapMergeMode,
    ) -> Result<Vec<NetClassInfo>, KiCadError> {
        let _ = self.set_net_classes_raw(net_classes, merge_mode).await?;
        self.get_net_classes().await
    }

    pub async fn get_text_variables_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetTextVariables {
            document: Some(self.current_board_document_proto().await?),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_TEXT_VARIABLES))
            .await?;
        response_payload_as_any(response, RES_TEXT_VARIABLES)
    }

    pub async fn get_text_variables(&self) -> Result<BTreeMap<String, String>, KiCadError> {
        let payload = self.get_text_variables_raw().await?;
        let response: common_project::TextVariables = decode_any(&payload, RES_TEXT_VARIABLES)?;
        Ok(response.variables.into_iter().collect())
    }

    pub async fn expand_text_variables_raw(
        &self,
        text: Vec<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::ExpandTextVariables {
            document: Some(self.current_board_document_proto().await?),
            text,
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_EXPAND_TEXT_VARIABLES))
            .await?;
        response_payload_as_any(response, RES_EXPAND_TEXT_VARIABLES_RESPONSE)
    }

    pub async fn expand_text_variables(
        &self,
        text: Vec<String>,
    ) -> Result<Vec<String>, KiCadError> {
        let payload = self.expand_text_variables_raw(text).await?;
        let response: common_commands::ExpandTextVariablesResponse =
            decode_any(&payload, RES_EXPAND_TEXT_VARIABLES_RESPONSE)?;
        Ok(response.text)
    }

    pub async fn get_text_extents_raw(
        &self,
        text: TextSpec,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetTextExtents {
            text: Some(text_spec_to_proto(text)),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_TEXT_EXTENTS))
            .await?;
        response_payload_as_any(response, RES_BOX2)
    }

    pub async fn get_text_extents(&self, text: TextSpec) -> Result<TextExtents, KiCadError> {
        let payload = self.get_text_extents_raw(text).await?;
        let response: common_types::Box2 = decode_any(&payload, RES_BOX2)?;
        let position = response
            .position
            .ok_or_else(|| KiCadError::InvalidResponse {
                reason: "GetTextExtents response missing position".to_string(),
            })?;
        let size = response.size.ok_or_else(|| KiCadError::InvalidResponse {
            reason: "GetTextExtents response missing size".to_string(),
        })?;

        Ok(TextExtents {
            x_nm: position.x_nm,
            y_nm: position.y_nm,
            width_nm: size.x_nm,
            height_nm: size.y_nm,
        })
    }

    pub async fn get_text_as_shapes_raw(
        &self,
        text: Vec<TextObjectSpec>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::GetTextAsShapes {
            text: text.into_iter().map(text_object_spec_to_proto).collect(),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_TEXT_AS_SHAPES))
            .await?;
        response_payload_as_any(response, RES_GET_TEXT_AS_SHAPES_RESPONSE)
    }

    pub async fn get_text_as_shapes(
        &self,
        text: Vec<TextObjectSpec>,
    ) -> Result<Vec<TextAsShapesEntry>, KiCadError> {
        let payload = self.get_text_as_shapes_raw(text).await?;
        let response: common_commands::GetTextAsShapesResponse =
            decode_any(&payload, RES_GET_TEXT_AS_SHAPES_RESPONSE)?;

        response
            .text_with_shapes
            .into_iter()
            .map(map_text_with_shapes)
            .collect()
    }

    pub async fn get_current_project_path(&self) -> Result<PathBuf, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        select_single_project_path(&docs)
    }

    pub async fn has_open_board(&self) -> Result<bool, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        Ok(!docs.is_empty())
    }

    pub async fn begin_commit_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::BeginCommit {};
        let response = self
            .send_command(envelope::pack_any(&command, CMD_BEGIN_COMMIT))
            .await?;
        response_payload_as_any(response, RES_BEGIN_COMMIT_RESPONSE)
    }

    pub async fn begin_commit(&self) -> Result<CommitSession, KiCadError> {
        let payload = self.begin_commit_raw().await?;
        let response: common_commands::BeginCommitResponse =
            decode_any(&payload, RES_BEGIN_COMMIT_RESPONSE)?;
        map_commit_session(response)
    }

    pub async fn end_commit_raw(
        &self,
        session: CommitSession,
        action: CommitAction,
        message: impl Into<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        if session.id.is_empty() {
            return Err(KiCadError::Config {
                reason: "end_commit_raw requires a non-empty commit session id".to_string(),
            });
        }

        let command = common_commands::EndCommit {
            id: Some(common_types::Kiid { value: session.id }),
            action: commit_action_to_proto(action),
            message: message.into(),
        };
        let response = self
            .send_command(envelope::pack_any(&command, CMD_END_COMMIT))
            .await?;
        response_payload_as_any(response, RES_END_COMMIT_RESPONSE)
    }

    pub async fn end_commit(
        &self,
        session: CommitSession,
        action: CommitAction,
        message: impl Into<String>,
    ) -> Result<(), KiCadError> {
        self.end_commit_raw(session, action, message).await?;
        Ok(())
    }

    pub async fn create_items_raw(
        &self,
        items: Vec<prost_types::Any>,
        container_id: Option<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::CreateItems {
            header: Some(self.current_board_item_header().await?),
            items,
            container: container_id.map(|value| common_types::Kiid { value }),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_CREATE_ITEMS))
            .await?;
        response_payload_as_any(response, RES_CREATE_ITEMS_RESPONSE)
    }

    pub async fn create_items(
        &self,
        items: Vec<prost_types::Any>,
        container_id: Option<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let payload = self.create_items_raw(items, container_id).await?;
        let response: common_commands::CreateItemsResponse =
            decode_any(&payload, RES_CREATE_ITEMS_RESPONSE)?;
        ensure_item_request_ok(response.status)?;

        response
            .created_items
            .into_iter()
            .map(|row| {
                ensure_item_status_ok(row.status)?;
                row.item.ok_or_else(|| KiCadError::InvalidResponse {
                    reason: "CreateItemsResponse missing created item payload".to_string(),
                })
            })
            .collect()
    }

    pub async fn update_items_raw(
        &self,
        items: Vec<prost_types::Any>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::UpdateItems {
            header: Some(self.current_board_item_header().await?),
            items,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_UPDATE_ITEMS))
            .await?;
        response_payload_as_any(response, RES_UPDATE_ITEMS_RESPONSE)
    }

    pub async fn update_items(
        &self,
        items: Vec<prost_types::Any>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let payload = self.update_items_raw(items).await?;
        let response: common_commands::UpdateItemsResponse =
            decode_any(&payload, RES_UPDATE_ITEMS_RESPONSE)?;
        ensure_item_request_ok(response.status)?;

        response
            .updated_items
            .into_iter()
            .map(|row| {
                ensure_item_status_ok(row.status)?;
                row.item.ok_or_else(|| KiCadError::InvalidResponse {
                    reason: "UpdateItemsResponse missing updated item payload".to_string(),
                })
            })
            .collect()
    }

    pub async fn delete_items_raw(
        &self,
        item_ids: Vec<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::DeleteItems {
            header: Some(self.current_board_item_header().await?),
            item_ids: item_ids
                .into_iter()
                .map(|value| common_types::Kiid { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_DELETE_ITEMS))
            .await?;
        response_payload_as_any(response, RES_DELETE_ITEMS_RESPONSE)
    }

    pub async fn delete_items(&self, item_ids: Vec<String>) -> Result<Vec<String>, KiCadError> {
        let payload = self.delete_items_raw(item_ids).await?;
        let response: common_commands::DeleteItemsResponse =
            decode_any(&payload, RES_DELETE_ITEMS_RESPONSE)?;
        ensure_item_request_ok(response.status)?;

        response
            .deleted_items
            .into_iter()
            .map(|row| {
                ensure_item_deletion_status_ok(row.status)?;
                row.id
                    .map(|id| id.value)
                    .ok_or_else(|| KiCadError::InvalidResponse {
                        reason: "DeleteItemsResponse missing deleted item id".to_string(),
                    })
            })
            .collect()
    }

    pub async fn parse_and_create_items_from_string_raw(
        &self,
        contents: impl Into<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::ParseAndCreateItemsFromString {
            document: Some(self.current_board_document_proto().await?),
            contents: contents.into(),
        };

        let response = self
            .send_command(envelope::pack_any(
                &command,
                CMD_PARSE_AND_CREATE_ITEMS_FROM_STRING,
            ))
            .await?;
        response_payload_as_any(response, RES_CREATE_ITEMS_RESPONSE)
    }

    pub async fn parse_and_create_items_from_string(
        &self,
        contents: impl Into<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let payload = self
            .parse_and_create_items_from_string_raw(contents)
            .await?;
        let response: common_commands::CreateItemsResponse =
            decode_any(&payload, RES_CREATE_ITEMS_RESPONSE)?;
        ensure_item_request_ok(response.status)?;

        response
            .created_items
            .into_iter()
            .map(|row| {
                ensure_item_status_ok(row.status)?;
                row.item.ok_or_else(|| KiCadError::InvalidResponse {
                    reason: "CreateItemsResponse missing created item payload".to_string(),
                })
            })
            .collect()
    }

    pub async fn get_nets(&self) -> Result<Vec<BoardNet>, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::GetNets {
            board: Some(board),
            netclass_filter: Vec::new(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_NETS))
            .await?;

        let payload: board_commands::NetsResponse = envelope::unpack_any(&response, RES_GET_NETS)?;

        Ok(payload
            .nets
            .into_iter()
            .map(|net| BoardNet {
                code: net.code.map_or(0, |code| code.value),
                name: net.name,
            })
            .collect())
    }

    pub async fn get_board_enabled_layers(&self) -> Result<BoardEnabledLayers, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::GetBoardEnabledLayers { board: Some(board) };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_BOARD_ENABLED_LAYERS))
            .await?;

        let payload: board_commands::BoardEnabledLayersResponse =
            envelope::unpack_any(&response, RES_GET_BOARD_ENABLED_LAYERS)?;

        Ok(map_board_enabled_layers_response(payload))
    }

    pub async fn set_board_enabled_layers(
        &self,
        copper_layer_count: u32,
        layer_ids: Vec<i32>,
    ) -> Result<BoardEnabledLayers, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::SetBoardEnabledLayers {
            board: Some(board),
            copper_layer_count,
            layers: layer_ids,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SET_BOARD_ENABLED_LAYERS))
            .await?;

        let payload: board_commands::BoardEnabledLayersResponse =
            envelope::unpack_any(&response, RES_GET_BOARD_ENABLED_LAYERS)?;
        Ok(map_board_enabled_layers_response(payload))
    }

    pub async fn get_active_layer(&self) -> Result<BoardLayerInfo, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::GetActiveLayer { board: Some(board) };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ACTIVE_LAYER))
            .await?;

        let payload: board_commands::BoardLayerResponse =
            envelope::unpack_any(&response, RES_BOARD_LAYER_RESPONSE)?;

        Ok(layer_to_model(payload.layer))
    }

    pub async fn set_active_layer(&self, layer_id: i32) -> Result<(), KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::SetActiveLayer {
            board: Some(board),
            layer: layer_id,
        };

        self.send_command(envelope::pack_any(&command, CMD_SET_ACTIVE_LAYER))
            .await?;
        Ok(())
    }

    pub async fn get_visible_layers(&self) -> Result<Vec<BoardLayerInfo>, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::GetVisibleLayers { board: Some(board) };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_VISIBLE_LAYERS))
            .await?;

        let payload: board_commands::BoardLayers =
            envelope::unpack_any(&response, RES_BOARD_LAYERS)?;

        Ok(payload.layers.into_iter().map(layer_to_model).collect())
    }

    pub async fn set_visible_layers(&self, layer_ids: Vec<i32>) -> Result<(), KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::SetVisibleLayers {
            board: Some(board),
            layers: layer_ids,
        };

        self.send_command(envelope::pack_any(&command, CMD_SET_VISIBLE_LAYERS))
            .await?;
        Ok(())
    }

    pub async fn get_board_origin(&self, kind: BoardOriginKind) -> Result<Vector2Nm, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::GetBoardOrigin {
            board: Some(board),
            r#type: board_origin_kind_to_proto(kind),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_BOARD_ORIGIN))
            .await?;

        let payload: common_types::Vector2 = envelope::unpack_any(&response, RES_VECTOR2)?;
        Ok(Vector2Nm {
            x_nm: payload.x_nm,
            y_nm: payload.y_nm,
        })
    }

    pub async fn set_board_origin(
        &self,
        kind: BoardOriginKind,
        origin: Vector2Nm,
    ) -> Result<(), KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::SetBoardOrigin {
            board: Some(board),
            r#type: board_origin_kind_to_proto(kind),
            origin: Some(vector2_nm_to_proto(origin)),
        };

        self.send_command(envelope::pack_any(&command, CMD_SET_BOARD_ORIGIN))
            .await?;
        Ok(())
    }

    pub async fn get_selection_summary(&self) -> Result<SelectionSummary, KiCadError> {
        let document = self.current_board_document_proto().await?;
        let command = common_commands::GetSelection {
            header: Some(common_types::ItemHeader {
                document: Some(document),
                container: None,
                field_mask: None,
            }),
            types: Vec::new(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_SELECTION))
            .await?;

        let payload: common_commands::SelectionResponse =
            envelope::unpack_any(&response, RES_SELECTION_RESPONSE)?;

        Ok(summarize_selection(payload.items))
    }

    pub async fn get_selection_raw(&self) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = common_commands::GetSelection {
            header: Some(self.current_board_item_header().await?),
            types: Vec::new(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_SELECTION))
            .await?;

        let payload: common_commands::SelectionResponse =
            envelope::unpack_any(&response, RES_SELECTION_RESPONSE)?;

        Ok(payload.items)
    }

    pub async fn get_selection_details(&self) -> Result<Vec<SelectionItemDetail>, KiCadError> {
        let items = self.get_selection_raw().await?;
        summarize_item_details(items)
    }

    pub async fn get_selection(&self) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self.get_selection_raw().await?;
        decode_pcb_items(items)
    }

    pub async fn add_to_selection_raw(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = common_commands::AddToSelection {
            header: Some(self.current_board_item_header().await?),
            items: item_ids
                .into_iter()
                .map(|value| common_types::Kiid { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_ADD_TO_SELECTION))
            .await?;

        match envelope::unpack_any::<common_commands::SelectionResponse>(
            &response,
            RES_SELECTION_RESPONSE,
        ) {
            Ok(payload) => Ok(payload.items),
            Err(KiCadError::UnexpectedPayloadType {
                expected_type_url: _,
                actual_type_url,
            }) if actual_type_url == envelope::type_url(RES_PROTOBUF_EMPTY) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    pub async fn add_to_selection(
        &self,
        item_ids: Vec<String>,
    ) -> Result<SelectionSummary, KiCadError> {
        let items = self.add_to_selection_raw(item_ids).await?;
        Ok(summarize_selection(items))
    }

    pub async fn clear_selection_raw(&self) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = common_commands::ClearSelection {
            header: Some(self.current_board_item_header().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_CLEAR_SELECTION))
            .await?;

        match envelope::unpack_any::<common_commands::SelectionResponse>(
            &response,
            RES_SELECTION_RESPONSE,
        ) {
            Ok(payload) => Ok(payload.items),
            Err(KiCadError::UnexpectedPayloadType {
                expected_type_url: _,
                actual_type_url,
            }) if actual_type_url == envelope::type_url(RES_PROTOBUF_EMPTY) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    pub async fn clear_selection(&self) -> Result<SelectionSummary, KiCadError> {
        let items = self.clear_selection_raw().await?;
        Ok(summarize_selection(items))
    }

    pub async fn remove_from_selection_raw(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = common_commands::RemoveFromSelection {
            header: Some(self.current_board_item_header().await?),
            items: item_ids
                .into_iter()
                .map(|value| common_types::Kiid { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_REMOVE_FROM_SELECTION))
            .await?;

        match envelope::unpack_any::<common_commands::SelectionResponse>(
            &response,
            RES_SELECTION_RESPONSE,
        ) {
            Ok(payload) => Ok(payload.items),
            Err(KiCadError::UnexpectedPayloadType {
                expected_type_url: _,
                actual_type_url,
            }) if actual_type_url == envelope::type_url(RES_PROTOBUF_EMPTY) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_from_selection(
        &self,
        item_ids: Vec<String>,
    ) -> Result<SelectionSummary, KiCadError> {
        let items = self.remove_from_selection_raw(item_ids).await?;
        Ok(summarize_selection(items))
    }

    pub async fn get_pad_netlist(&self) -> Result<Vec<PadNetEntry>, KiCadError> {
        let footprint_items = self
            .get_items_raw(vec![common_types::KiCadObjectType::KotPcbFootprint as i32])
            .await?;
        pad_netlist_from_footprint_items(footprint_items)
    }

    pub fn pcb_object_type_codes() -> &'static [PcbObjectTypeCode] {
        &PCB_OBJECT_TYPES
    }

    pub fn pcb_object_type_name(type_code: i32) -> Option<&'static str> {
        PCB_OBJECT_TYPES
            .iter()
            .find(|entry| entry.code == type_code)
            .map(|entry| entry.name)
    }

    pub fn debug_any_item(item: &prost_types::Any) -> Result<String, KiCadError> {
        any_to_pretty_debug(item)
    }

    pub async fn get_items_raw_by_type_codes(
        &self,
        type_codes: Vec<i32>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        self.get_items_raw(type_codes).await
    }

    pub async fn get_items_details_by_type_codes(
        &self,
        type_codes: Vec<i32>,
    ) -> Result<Vec<SelectionItemDetail>, KiCadError> {
        let items = self.get_items_raw(type_codes).await?;
        summarize_item_details(items)
    }

    pub async fn get_items_by_type_codes(
        &self,
        type_codes: Vec<i32>,
    ) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self.get_items_raw(type_codes).await?;
        decode_pcb_items(items)
    }

    pub async fn get_all_pcb_items_raw(
        &self,
    ) -> Result<Vec<(PcbObjectTypeCode, Vec<prost_types::Any>)>, KiCadError> {
        let mut rows = Vec::with_capacity(PCB_OBJECT_TYPES.len());
        for object_type in PCB_OBJECT_TYPES {
            let items = self.get_items_raw(vec![object_type.code]).await?;
            rows.push((object_type, items));
        }

        Ok(rows)
    }

    pub async fn get_all_pcb_items_details(
        &self,
    ) -> Result<Vec<(PcbObjectTypeCode, Vec<SelectionItemDetail>)>, KiCadError> {
        let mut rows = Vec::with_capacity(PCB_OBJECT_TYPES.len());
        for object_type in PCB_OBJECT_TYPES {
            let items = self.get_items_raw(vec![object_type.code]).await?;
            rows.push((object_type, summarize_item_details(items)?));
        }

        Ok(rows)
    }

    pub async fn get_all_pcb_items(
        &self,
    ) -> Result<Vec<(PcbObjectTypeCode, Vec<PcbItem>)>, KiCadError> {
        let mut rows = Vec::with_capacity(PCB_OBJECT_TYPES.len());
        for object_type in PCB_OBJECT_TYPES {
            let items = self.get_items_raw(vec![object_type.code]).await?;
            rows.push((object_type, decode_pcb_items(items)?));
        }

        Ok(rows)
    }

    pub async fn get_items_by_net_raw(
        &self,
        type_codes: Vec<i32>,
        net_codes: Vec<i32>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = board_commands::GetItemsByNet {
            header: Some(self.current_board_item_header().await?),
            types: type_codes,
            net_codes: net_codes
                .into_iter()
                .map(|value| board_types::NetCode { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ITEMS_BY_NET))
            .await?;
        let payload: common_commands::GetItemsResponse =
            envelope::unpack_any(&response, RES_GET_ITEMS_RESPONSE)?;
        ensure_item_request_ok(payload.status)?;
        Ok(payload.items)
    }

    pub async fn get_items_by_net(
        &self,
        type_codes: Vec<i32>,
        net_codes: Vec<i32>,
    ) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self.get_items_by_net_raw(type_codes, net_codes).await?;
        decode_pcb_items(items)
    }

    pub async fn get_items_by_net_class_raw(
        &self,
        type_codes: Vec<i32>,
        net_classes: Vec<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = board_commands::GetItemsByNetClass {
            header: Some(self.current_board_item_header().await?),
            types: type_codes,
            net_classes,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ITEMS_BY_NET_CLASS))
            .await?;
        let payload: common_commands::GetItemsResponse =
            envelope::unpack_any(&response, RES_GET_ITEMS_RESPONSE)?;
        ensure_item_request_ok(payload.status)?;
        Ok(payload.items)
    }

    pub async fn get_items_by_net_class(
        &self,
        type_codes: Vec<i32>,
        net_classes: Vec<String>,
    ) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self
            .get_items_by_net_class_raw(type_codes, net_classes)
            .await?;
        decode_pcb_items(items)
    }

    pub async fn get_netclass_for_nets_raw(
        &self,
        nets: Vec<BoardNet>,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = board_commands::GetNetClassForNets {
            net: nets
                .into_iter()
                .map(|net| board_types::Net {
                    code: Some(board_types::NetCode { value: net.code }),
                    name: net.name,
                })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_NETCLASS_FOR_NETS))
            .await?;

        response_payload_as_any(response, RES_NETCLASS_FOR_NETS_RESPONSE)
    }

    pub async fn get_netclass_for_nets(
        &self,
        nets: Vec<BoardNet>,
    ) -> Result<Vec<NetClassForNetEntry>, KiCadError> {
        let payload = self.get_netclass_for_nets_raw(nets).await?;
        let response: board_commands::NetClassForNetsResponse =
            decode_any(&payload, RES_NETCLASS_FOR_NETS_RESPONSE)?;
        Ok(map_netclass_for_nets_response(response))
    }

    pub async fn refill_zones(&self, zone_ids: Vec<String>) -> Result<(), KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::RefillZones {
            board: Some(board),
            zones: zone_ids
                .into_iter()
                .map(|value| common_types::Kiid { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_REFILL_ZONES))
            .await?;
        let _ = response_payload_as_any(response, RES_PROTOBUF_EMPTY)?;
        Ok(())
    }

    pub async fn get_pad_shape_as_polygon_raw(
        &self,
        pad_ids: Vec<String>,
        layer_id: i32,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        if pad_ids.is_empty() {
            return Ok(Vec::new());
        }

        let board = self.current_board_document_proto().await?;
        let mut payloads = Vec::new();
        for chunk in pad_ids.chunks(PAD_QUERY_CHUNK_SIZE) {
            let command = board_commands::GetPadShapeAsPolygon {
                board: Some(board.clone()),
                pads: chunk
                    .iter()
                    .cloned()
                    .map(|value| common_types::Kiid { value })
                    .collect(),
                layer: layer_id,
            };

            let response = self
                .send_command(envelope::pack_any(&command, CMD_GET_PAD_SHAPE_AS_POLYGON))
                .await?;
            payloads.push(response_payload_as_any(
                response,
                RES_PAD_SHAPE_AS_POLYGON_RESPONSE,
            )?);
        }

        Ok(payloads)
    }

    pub async fn get_pad_shape_as_polygon(
        &self,
        pad_ids: Vec<String>,
        layer_id: i32,
    ) -> Result<Vec<PadShapeAsPolygonEntry>, KiCadError> {
        if pad_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let layer_name = layer_to_model(layer_id).name;

        let payloads = self.get_pad_shape_as_polygon_raw(pad_ids, layer_id).await?;
        for payload in payloads {
            let payload: board_commands::PadShapeAsPolygonResponse =
                decode_any(&payload, RES_PAD_SHAPE_AS_POLYGON_RESPONSE)?;

            if payload.pads.len() != payload.polygons.len() {
                return Err(KiCadError::InvalidResponse {
                    reason: format!(
                        "GetPadShapeAsPolygon returned mismatched arrays: pads={}, polygons={}",
                        payload.pads.len(),
                        payload.polygons.len()
                    ),
                });
            }

            for (pad, polygon) in payload.pads.into_iter().zip(payload.polygons.into_iter()) {
                entries.push(PadShapeAsPolygonEntry {
                    pad_id: pad.value,
                    layer_id,
                    layer_name: layer_name.clone(),
                    polygon: map_polygon_with_holes(polygon)?,
                });
            }
        }

        Ok(entries)
    }

    pub async fn check_padstack_presence_on_layers_raw(
        &self,
        item_ids: Vec<String>,
        layer_ids: Vec<i32>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        if item_ids.is_empty() || layer_ids.is_empty() {
            return Ok(Vec::new());
        }

        let board = self.current_board_document_proto().await?;
        let mut payloads = Vec::new();
        for chunk in item_ids.chunks(PAD_QUERY_CHUNK_SIZE) {
            let command = board_commands::CheckPadstackPresenceOnLayers {
                board: Some(board.clone()),
                items: chunk
                    .iter()
                    .cloned()
                    .map(|value| common_types::Kiid { value })
                    .collect(),
                layers: layer_ids.clone(),
            };
            let response = self
                .send_command(envelope::pack_any(
                    &command,
                    CMD_CHECK_PADSTACK_PRESENCE_ON_LAYERS,
                ))
                .await?;
            payloads.push(response_payload_as_any(
                response,
                RES_PADSTACK_PRESENCE_RESPONSE,
            )?);
        }

        Ok(payloads)
    }

    pub async fn check_padstack_presence_on_layers(
        &self,
        item_ids: Vec<String>,
        layer_ids: Vec<i32>,
    ) -> Result<Vec<PadstackPresenceEntry>, KiCadError> {
        if item_ids.is_empty() || layer_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let payloads = self
            .check_padstack_presence_on_layers_raw(item_ids, layer_ids)
            .await?;
        for payload in payloads {
            let payload: board_commands::PadstackPresenceResponse =
                decode_any(&payload, RES_PADSTACK_PRESENCE_RESPONSE)?;
            for row in payload.entries {
                let item = row.item.ok_or_else(|| KiCadError::InvalidResponse {
                    reason: "PadstackPresenceEntry missing item id".to_string(),
                })?;

                let layer = layer_to_model(row.layer);
                let presence = map_padstack_presence(row.presence);

                entries.push(PadstackPresenceEntry {
                    item_id: item.value,
                    layer_id: row.layer,
                    layer_name: layer.name,
                    presence,
                });
            }
        }

        Ok(entries)
    }

    pub async fn inject_drc_error_raw(
        &self,
        severity: DrcSeverity,
        message: impl Into<String>,
        position: Option<Vector2Nm>,
        item_ids: Vec<String>,
    ) -> Result<prost_types::Any, KiCadError> {
        let board = self.current_board_document_proto().await?;
        let command = board_commands::InjectDrcError {
            board: Some(board),
            severity: drc_severity_to_proto(severity),
            message: message.into(),
            position: position.map(vector2_nm_to_proto),
            items: item_ids
                .into_iter()
                .map(|value| common_types::Kiid { value })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_INJECT_DRC_ERROR))
            .await?;
        response_payload_as_any(response, RES_INJECT_DRC_ERROR_RESPONSE)
    }

    pub async fn inject_drc_error(
        &self,
        severity: DrcSeverity,
        message: impl Into<String>,
        position: Option<Vector2Nm>,
        item_ids: Vec<String>,
    ) -> Result<Option<String>, KiCadError> {
        let payload = self
            .inject_drc_error_raw(severity, message, position, item_ids)
            .await?;
        let response: board_commands::InjectDrcErrorResponse =
            decode_any(&payload, RES_INJECT_DRC_ERROR_RESPONSE)?;
        Ok(response.marker.map(|marker| marker.value))
    }

    pub async fn get_board_stackup_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = board_commands::GetBoardStackup {
            board: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_BOARD_STACKUP))
            .await?;

        response_payload_as_any(response, RES_BOARD_STACKUP_RESPONSE)
    }

    pub async fn get_board_stackup(&self) -> Result<BoardStackup, KiCadError> {
        let payload = self.get_board_stackup_raw().await?;
        let response: board_commands::BoardStackupResponse =
            decode_any(&payload, RES_BOARD_STACKUP_RESPONSE)?;
        Ok(map_board_stackup(response.stackup.unwrap_or_default()))
    }

    pub async fn get_graphics_defaults_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = board_commands::GetGraphicsDefaults {
            board: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_GRAPHICS_DEFAULTS))
            .await?;

        response_payload_as_any(response, RES_GRAPHICS_DEFAULTS_RESPONSE)
    }

    pub async fn get_graphics_defaults(&self) -> Result<GraphicsDefaults, KiCadError> {
        let payload = self.get_graphics_defaults_raw().await?;
        let response: board_commands::GraphicsDefaultsResponse =
            decode_any(&payload, RES_GRAPHICS_DEFAULTS_RESPONSE)?;
        Ok(map_graphics_defaults(response.defaults.unwrap_or_default()))
    }

    pub async fn get_board_editor_appearance_settings_raw(
        &self,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = board_commands::GetBoardEditorAppearanceSettings {};

        let response = self
            .send_command(envelope::pack_any(
                &command,
                CMD_GET_BOARD_EDITOR_APPEARANCE_SETTINGS,
            ))
            .await?;

        response_payload_as_any(response, RES_BOARD_EDITOR_APPEARANCE_SETTINGS)
    }

    pub async fn get_board_editor_appearance_settings(
        &self,
    ) -> Result<BoardEditorAppearanceSettings, KiCadError> {
        let payload = self.get_board_editor_appearance_settings_raw().await?;
        let response: board_commands::BoardEditorAppearanceSettings =
            decode_any(&payload, RES_BOARD_EDITOR_APPEARANCE_SETTINGS)?;
        Ok(map_board_editor_appearance_settings(response))
    }

    pub async fn set_board_editor_appearance_settings(
        &self,
        settings: BoardEditorAppearanceSettings,
    ) -> Result<BoardEditorAppearanceSettings, KiCadError> {
        let command = board_commands::SetBoardEditorAppearanceSettings {
            settings: Some(board_editor_appearance_settings_to_proto(settings)),
        };

        let response = self
            .send_command(envelope::pack_any(
                &command,
                CMD_SET_BOARD_EDITOR_APPEARANCE_SETTINGS,
            ))
            .await?;
        let _ = response_payload_as_any(response, RES_PROTOBUF_EMPTY)?;
        self.get_board_editor_appearance_settings().await
    }

    pub async fn get_title_block_info(&self) -> Result<TitleBlockInfo, KiCadError> {
        let command = common_commands::GetTitleBlockInfo {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_TITLE_BLOCK_INFO))
            .await?;
        let payload: common_types::TitleBlockInfo =
            envelope::unpack_any(&response, RES_TITLE_BLOCK_INFO)?;

        let comments = vec![
            payload.comment1,
            payload.comment2,
            payload.comment3,
            payload.comment4,
            payload.comment5,
            payload.comment6,
            payload.comment7,
            payload.comment8,
            payload.comment9,
        ]
        .into_iter()
        .filter(|comment| !comment.is_empty())
        .collect();

        Ok(TitleBlockInfo {
            title: payload.title,
            date: payload.date,
            revision: payload.revision,
            company: payload.company,
            comments,
        })
    }

    pub async fn save_document_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SaveDocument {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    pub async fn save_document(&self) -> Result<(), KiCadError> {
        let _ = self.save_document_raw().await?;
        Ok(())
    }

    pub async fn save_copy_of_document_raw(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SaveCopyOfDocument {
            document: Some(self.current_board_document_proto().await?),
            path: path.into(),
            options: Some(common_commands::SaveOptions {
                overwrite,
                include_project,
            }),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_COPY_OF_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    pub async fn save_copy_of_document(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<(), KiCadError> {
        let _ = self
            .save_copy_of_document_raw(path, overwrite, include_project)
            .await?;
        Ok(())
    }

    pub async fn revert_document_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::RevertDocument {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_REVERT_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    pub async fn revert_document(&self) -> Result<(), KiCadError> {
        let _ = self.revert_document_raw().await?;
        Ok(())
    }

    pub async fn get_board_as_string(&self) -> Result<String, KiCadError> {
        let command = common_commands::SaveDocumentToString {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_DOCUMENT_TO_STRING))
            .await?;
        let payload: common_commands::SavedDocumentResponse =
            envelope::unpack_any(&response, RES_SAVED_DOCUMENT_RESPONSE)?;
        Ok(payload.contents)
    }

    pub async fn get_selection_as_string(&self) -> Result<String, KiCadError> {
        let command = common_commands::SaveSelectionToString {};

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_SELECTION_TO_STRING))
            .await?;
        let payload: common_commands::SavedSelectionResponse =
            envelope::unpack_any(&response, RES_SAVED_SELECTION_RESPONSE)?;
        Ok(payload.contents)
    }

    pub async fn get_items_by_id_raw(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }

        let command = common_commands::GetItemsById {
            header: Some(self.current_board_item_header().await?),
            items: item_ids
                .into_iter()
                .map(|id| common_types::Kiid { value: id })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ITEMS_BY_ID))
            .await?;

        let payload: common_commands::GetItemsResponse =
            envelope::unpack_any(&response, RES_GET_ITEMS_RESPONSE)?;

        ensure_item_request_ok(payload.status)?;
        Ok(payload.items)
    }

    pub async fn get_items_by_id_details(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<SelectionItemDetail>, KiCadError> {
        let items = self.get_items_by_id_raw(item_ids).await?;
        summarize_item_details(items)
    }

    pub async fn get_items_by_id(&self, item_ids: Vec<String>) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self.get_items_by_id_raw(item_ids).await?;
        decode_pcb_items(items)
    }

    pub async fn get_item_bounding_boxes(
        &self,
        item_ids: Vec<String>,
        include_child_text: bool,
    ) -> Result<Vec<ItemBoundingBox>, KiCadError> {
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mode = if include_child_text {
            common_commands::BoundingBoxMode::BbmItemAndChildText
        } else {
            common_commands::BoundingBoxMode::BbmItemOnly
        };

        let command = common_commands::GetBoundingBox {
            header: Some(self.current_board_item_header().await?),
            items: item_ids
                .into_iter()
                .map(|id| common_types::Kiid { value: id })
                .collect(),
            mode: mode as i32,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_BOUNDING_BOX))
            .await?;

        let payload: common_commands::GetBoundingBoxResponse =
            envelope::unpack_any(&response, RES_GET_BOUNDING_BOX_RESPONSE)?;

        map_item_bounding_boxes(payload.items, payload.boxes)
    }

    pub async fn hit_test_item(
        &self,
        item_id: String,
        position: Vector2Nm,
        tolerance_nm: i32,
    ) -> Result<ItemHitTestResult, KiCadError> {
        let command = common_commands::HitTest {
            header: Some(self.current_board_item_header().await?),
            id: Some(common_types::Kiid { value: item_id }),
            position: Some(common_types::Vector2 {
                x_nm: position.x_nm,
                y_nm: position.y_nm,
            }),
            tolerance: tolerance_nm,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_HIT_TEST))
            .await?;

        let payload: common_commands::HitTestResponse =
            envelope::unpack_any(&response, RES_HIT_TEST_RESPONSE)?;

        Ok(map_hit_test_result(payload.result))
    }

    async fn send_command(
        &self,
        command: prost_types::Any,
    ) -> Result<crate::proto::kiapi::common::ApiResponse, KiCadError> {
        let token = self
            .inner
            .token
            .lock()
            .map_err(|_| KiCadError::InternalPoisoned)?
            .clone();

        let request_bytes = envelope::encode_request(&token, &self.inner.client_name, command)?;
        let response_bytes = self.inner.transport.roundtrip(request_bytes).await?;

        let response = envelope::decode_response(&response_bytes)?;

        if let Some(err) = envelope::status_error(&response) {
            return Err(err);
        }

        if token.is_empty() {
            if let Some(header) = response.header.as_ref() {
                if !header.kicad_token.is_empty() {
                    let mut guard = self
                        .inner
                        .token
                        .lock()
                        .map_err(|_| KiCadError::InternalPoisoned)?;
                    *guard = header.kicad_token.clone();
                }
            }
        }

        Ok(response)
    }

    async fn current_board_document_proto(
        &self,
    ) -> Result<common_types::DocumentSpecifier, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        let selected = select_single_board_document(&docs)?;
        Ok(model_document_to_proto(selected))
    }

    async fn current_board_item_header(&self) -> Result<common_types::ItemHeader, KiCadError> {
        Ok(common_types::ItemHeader {
            document: Some(self.current_board_document_proto().await?),
            container: None,
            field_mask: None,
        })
    }

    async fn get_items_raw(&self, types: Vec<i32>) -> Result<Vec<prost_types::Any>, KiCadError> {
        let command = common_commands::GetItems {
            header: Some(self.current_board_item_header().await?),
            types,
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ITEMS))
            .await?;

        let payload: common_commands::GetItemsResponse =
            envelope::unpack_any(&response, RES_GET_ITEMS_RESPONSE)?;

        ensure_item_request_ok(payload.status)?;
        Ok(payload.items)
    }
}

fn map_document_specifier(source: common_types::DocumentSpecifier) -> Option<DocumentSpecifier> {
    let document_type = DocumentType::from_proto(source.r#type)?;
    let board_filename = match source.identifier {
        Some(common_types::document_specifier::Identifier::BoardFilename(filename)) => {
            Some(filename)
        }
        _ => None,
    };

    let project = source.project.unwrap_or_default();

    let project_info = ProjectInfo {
        name: if project.name.is_empty() {
            None
        } else {
            Some(project.name)
        },
        path: if project.path.is_empty() {
            None
        } else {
            Some(PathBuf::from(project.path))
        },
    };

    Some(DocumentSpecifier {
        document_type,
        board_filename,
        project: project_info,
    })
}

fn model_document_to_proto(document: &DocumentSpecifier) -> common_types::DocumentSpecifier {
    let identifier = document.board_filename.as_ref().map(|filename| {
        common_types::document_specifier::Identifier::BoardFilename(filename.clone())
    });

    let project = common_types::ProjectSpecifier {
        name: document.project.name.clone().unwrap_or_default(),
        path: document
            .project
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
    };

    common_types::DocumentSpecifier {
        r#type: document.document_type.to_proto(),
        project: Some(project),
        identifier,
    }
}

fn text_spec_to_proto(text: TextSpec) -> common_types::Text {
    common_types::Text {
        position: text.position_nm.map(vector2_nm_to_proto),
        attributes: text.attributes.map(text_attributes_spec_to_proto),
        text: text.text,
        hyperlink: text.hyperlink.unwrap_or_default(),
    }
}

fn text_attributes_spec_to_proto(attributes: TextAttributesSpec) -> common_types::TextAttributes {
    common_types::TextAttributes {
        font_name: attributes.font_name.unwrap_or_default(),
        horizontal_alignment: text_horizontal_alignment_to_proto(attributes.horizontal_alignment),
        vertical_alignment: text_vertical_alignment_to_proto(attributes.vertical_alignment),
        angle: attributes
            .angle_degrees
            .map(|value_degrees| common_types::Angle { value_degrees }),
        line_spacing: attributes.line_spacing.unwrap_or(1.0),
        stroke_width: attributes
            .stroke_width_nm
            .map(|value_nm| common_types::Distance { value_nm }),
        italic: attributes.italic,
        bold: attributes.bold,
        underlined: attributes.underlined,
        visible: true,
        mirrored: attributes.mirrored,
        multiline: attributes.multiline,
        keep_upright: attributes.keep_upright,
        size: attributes.size_nm.map(vector2_nm_to_proto),
    }
}

fn text_horizontal_alignment_to_proto(value: TextHorizontalAlignment) -> i32 {
    match value {
        TextHorizontalAlignment::Unknown => common_types::HorizontalAlignment::HaUnknown as i32,
        TextHorizontalAlignment::Left => common_types::HorizontalAlignment::HaLeft as i32,
        TextHorizontalAlignment::Center => common_types::HorizontalAlignment::HaCenter as i32,
        TextHorizontalAlignment::Right => common_types::HorizontalAlignment::HaRight as i32,
        TextHorizontalAlignment::Indeterminate => {
            common_types::HorizontalAlignment::HaIndeterminate as i32
        }
    }
}

fn text_vertical_alignment_to_proto(value: TextVerticalAlignment) -> i32 {
    match value {
        TextVerticalAlignment::Unknown => common_types::VerticalAlignment::VaUnknown as i32,
        TextVerticalAlignment::Top => common_types::VerticalAlignment::VaTop as i32,
        TextVerticalAlignment::Center => common_types::VerticalAlignment::VaCenter as i32,
        TextVerticalAlignment::Bottom => common_types::VerticalAlignment::VaBottom as i32,
        TextVerticalAlignment::Indeterminate => {
            common_types::VerticalAlignment::VaIndeterminate as i32
        }
    }
}

fn text_box_spec_to_proto(text: TextBoxSpec) -> common_types::TextBox {
    common_types::TextBox {
        top_left: text.top_left_nm.map(vector2_nm_to_proto),
        bottom_right: text.bottom_right_nm.map(vector2_nm_to_proto),
        attributes: text.attributes.map(text_attributes_spec_to_proto),
        text: text.text,
    }
}

fn text_object_spec_to_proto(text: TextObjectSpec) -> common_commands::TextOrTextBox {
    let inner = match text {
        TextObjectSpec::Text(value) => {
            common_commands::text_or_text_box::Inner::Text(text_spec_to_proto(value))
        }
        TextObjectSpec::TextBox(value) => {
            common_commands::text_or_text_box::Inner::Textbox(text_box_spec_to_proto(value))
        }
    };
    common_commands::TextOrTextBox { inner: Some(inner) }
}

fn map_text_horizontal_alignment_from_proto(value: i32) -> TextHorizontalAlignment {
    match common_types::HorizontalAlignment::try_from(value) {
        Ok(common_types::HorizontalAlignment::HaLeft) => TextHorizontalAlignment::Left,
        Ok(common_types::HorizontalAlignment::HaCenter) => TextHorizontalAlignment::Center,
        Ok(common_types::HorizontalAlignment::HaRight) => TextHorizontalAlignment::Right,
        Ok(common_types::HorizontalAlignment::HaIndeterminate) => {
            TextHorizontalAlignment::Indeterminate
        }
        _ => TextHorizontalAlignment::Unknown,
    }
}

fn map_text_vertical_alignment_from_proto(value: i32) -> TextVerticalAlignment {
    match common_types::VerticalAlignment::try_from(value) {
        Ok(common_types::VerticalAlignment::VaTop) => TextVerticalAlignment::Top,
        Ok(common_types::VerticalAlignment::VaCenter) => TextVerticalAlignment::Center,
        Ok(common_types::VerticalAlignment::VaBottom) => TextVerticalAlignment::Bottom,
        Ok(common_types::VerticalAlignment::VaIndeterminate) => {
            TextVerticalAlignment::Indeterminate
        }
        _ => TextVerticalAlignment::Unknown,
    }
}

fn map_text_attributes_spec_from_proto(
    attributes: common_types::TextAttributes,
) -> TextAttributesSpec {
    TextAttributesSpec {
        font_name: if attributes.font_name.is_empty() {
            None
        } else {
            Some(attributes.font_name)
        },
        horizontal_alignment: map_text_horizontal_alignment_from_proto(
            attributes.horizontal_alignment,
        ),
        vertical_alignment: map_text_vertical_alignment_from_proto(attributes.vertical_alignment),
        angle_degrees: attributes.angle.map(|value| value.value_degrees),
        line_spacing: Some(attributes.line_spacing),
        stroke_width_nm: map_optional_distance_nm(attributes.stroke_width),
        italic: attributes.italic,
        bold: attributes.bold,
        underlined: attributes.underlined,
        mirrored: attributes.mirrored,
        multiline: attributes.multiline,
        keep_upright: attributes.keep_upright,
        size_nm: attributes.size.map(map_vector2_nm),
    }
}

fn map_text_spec_from_proto(text: common_types::Text) -> TextSpec {
    TextSpec {
        text: text.text,
        position_nm: text.position.map(map_vector2_nm),
        attributes: text.attributes.map(map_text_attributes_spec_from_proto),
        hyperlink: if text.hyperlink.is_empty() {
            None
        } else {
            Some(text.hyperlink)
        },
    }
}

fn map_text_box_spec_from_proto(text: common_types::TextBox) -> TextBoxSpec {
    TextBoxSpec {
        text: text.text,
        top_left_nm: text.top_left.map(map_vector2_nm),
        bottom_right_nm: text.bottom_right.map(map_vector2_nm),
        attributes: text.attributes.map(map_text_attributes_spec_from_proto),
    }
}

fn map_text_object_spec_from_proto(text: common_commands::TextOrTextBox) -> Option<TextObjectSpec> {
    match text.inner {
        Some(common_commands::text_or_text_box::Inner::Text(value)) => {
            Some(TextObjectSpec::Text(map_text_spec_from_proto(value)))
        }
        Some(common_commands::text_or_text_box::Inner::Textbox(value)) => {
            Some(TextObjectSpec::TextBox(map_text_box_spec_from_proto(value)))
        }
        None => None,
    }
}

fn map_text_shape_geometry(
    shape: common_types::GraphicShape,
) -> Result<TextShapeGeometry, KiCadError> {
    match shape.geometry {
        Some(common_types::graphic_shape::Geometry::Segment(segment)) => {
            Ok(TextShapeGeometry::Segment {
                start_nm: segment.start.map(map_vector2_nm),
                end_nm: segment.end.map(map_vector2_nm),
            })
        }
        Some(common_types::graphic_shape::Geometry::Rectangle(rectangle)) => {
            Ok(TextShapeGeometry::Rectangle {
                top_left_nm: rectangle.top_left.map(map_vector2_nm),
                bottom_right_nm: rectangle.bottom_right.map(map_vector2_nm),
                corner_radius_nm: map_optional_distance_nm(rectangle.corner_radius),
            })
        }
        Some(common_types::graphic_shape::Geometry::Arc(arc)) => Ok(TextShapeGeometry::Arc {
            start_nm: arc.start.map(map_vector2_nm),
            mid_nm: arc.mid.map(map_vector2_nm),
            end_nm: arc.end.map(map_vector2_nm),
        }),
        Some(common_types::graphic_shape::Geometry::Circle(circle)) => {
            Ok(TextShapeGeometry::Circle {
                center_nm: circle.center.map(map_vector2_nm),
                radius_point_nm: circle.radius_point.map(map_vector2_nm),
            })
        }
        Some(common_types::graphic_shape::Geometry::Polygon(polygon)) => {
            let polygons = polygon
                .polygons
                .into_iter()
                .map(map_polygon_with_holes)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TextShapeGeometry::Polygon { polygons })
        }
        Some(common_types::graphic_shape::Geometry::Bezier(bezier)) => {
            Ok(TextShapeGeometry::Bezier {
                start_nm: bezier.start.map(map_vector2_nm),
                control1_nm: bezier.control1.map(map_vector2_nm),
                control2_nm: bezier.control2.map(map_vector2_nm),
                end_nm: bezier.end.map(map_vector2_nm),
            })
        }
        None => Ok(TextShapeGeometry::Unknown),
    }
}

fn map_text_shape(shape: common_types::GraphicShape) -> Result<TextShape, KiCadError> {
    let geometry = map_text_shape_geometry(shape.clone())?;
    let attributes = shape.attributes.unwrap_or_default();
    let stroke = attributes.stroke;
    let fill = attributes.fill;

    Ok(TextShape {
        geometry,
        stroke_width_nm: stroke
            .clone()
            .and_then(|value| map_optional_distance_nm(value.width)),
        stroke_style: stroke.as_ref().map(|value| value.style),
        stroke_color: stroke.and_then(|value| map_optional_color(value.color)),
        fill_type: fill.as_ref().map(|value| value.fill_type),
        fill_color: fill.and_then(|value| map_optional_color(value.color)),
    })
}

fn map_text_with_shapes(
    row: common_commands::TextWithShapes,
) -> Result<TextAsShapesEntry, KiCadError> {
    let source = row.text.and_then(map_text_object_spec_from_proto);
    let shapes = row
        .shapes
        .unwrap_or_default()
        .shapes
        .into_iter()
        .map(map_text_shape)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TextAsShapesEntry { source, shapes })
}

fn layer_to_model(layer_id: i32) -> BoardLayerInfo {
    let name = board_types::BoardLayer::try_from(layer_id)
        .map(|layer| layer.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN_LAYER({layer_id})"));

    BoardLayerInfo { id: layer_id, name }
}

fn map_board_enabled_layers_response(
    payload: board_commands::BoardEnabledLayersResponse,
) -> BoardEnabledLayers {
    BoardEnabledLayers {
        copper_layer_count: payload.copper_layer_count,
        layers: payload.layers.into_iter().map(layer_to_model).collect(),
    }
}

fn board_origin_kind_to_proto(kind: BoardOriginKind) -> i32 {
    match kind {
        BoardOriginKind::Grid => board_commands::BoardOriginType::BotGrid as i32,
        BoardOriginKind::Drill => board_commands::BoardOriginType::BotDrill as i32,
    }
}

fn drc_severity_to_proto(value: DrcSeverity) -> i32 {
    match value {
        DrcSeverity::Warning => board_commands::DrcSeverity::DrsWarning as i32,
        DrcSeverity::Error => board_commands::DrcSeverity::DrsError as i32,
        DrcSeverity::Exclusion => board_commands::DrcSeverity::DrsExclusion as i32,
        DrcSeverity::Ignore => board_commands::DrcSeverity::DrsIgnore as i32,
        DrcSeverity::Info => board_commands::DrcSeverity::DrsInfo as i32,
        DrcSeverity::Action => board_commands::DrcSeverity::DrsAction as i32,
        DrcSeverity::Debug => board_commands::DrcSeverity::DrsDebug as i32,
        DrcSeverity::Undefined => board_commands::DrcSeverity::DrsUndefined as i32,
    }
}

fn commit_action_to_proto(action: CommitAction) -> i32 {
    match action {
        CommitAction::Commit => common_commands::CommitAction::CmaCommit as i32,
        CommitAction::Drop => common_commands::CommitAction::CmaDrop as i32,
    }
}

fn map_merge_mode_to_proto(value: MapMergeMode) -> i32 {
    match value {
        MapMergeMode::Merge => common_types::MapMergeMode::MmmMerge as i32,
        MapMergeMode::Replace => common_types::MapMergeMode::MmmReplace as i32,
    }
}

fn summarize_selection(items: Vec<prost_types::Any>) -> SelectionSummary {
    let mut counts = BTreeMap::<String, usize>::new();

    for item in &items {
        let entry = counts.entry(item.type_url.clone()).or_insert(0);
        *entry += 1;
    }

    SelectionSummary {
        total_items: items.len(),
        type_url_counts: counts
            .into_iter()
            .map(|(type_url, count)| SelectionTypeCount { type_url, count })
            .collect(),
    }
}

fn summarize_item_details(
    items: Vec<prost_types::Any>,
) -> Result<Vec<SelectionItemDetail>, KiCadError> {
    let mut details = Vec::with_capacity(items.len());
    for item in items {
        let raw_len = item.value.len();
        let type_url = item.type_url.clone();
        let detail = selection_item_detail(&item)?;
        details.push(SelectionItemDetail {
            type_url,
            detail,
            raw_len,
        });
    }

    Ok(details)
}

fn map_commit_session(
    response: common_commands::BeginCommitResponse,
) -> Result<CommitSession, KiCadError> {
    let id = response.id.ok_or_else(|| KiCadError::InvalidResponse {
        reason: "BeginCommit response missing commit id".to_string(),
    })?;

    if id.value.is_empty() {
        return Err(KiCadError::InvalidResponse {
            reason: "BeginCommit response returned empty commit id".to_string(),
        });
    }

    Ok(CommitSession { id: id.value })
}

fn ensure_item_request_ok(status: i32) -> Result<(), KiCadError> {
    let request_status = common_types::ItemRequestStatus::try_from(status)
        .unwrap_or(common_types::ItemRequestStatus::IrsUnknown);

    if request_status != common_types::ItemRequestStatus::IrsOk {
        return Err(KiCadError::ItemStatus {
            code: request_status.as_str_name().to_string(),
        });
    }

    Ok(())
}

fn ensure_item_status_ok(status: Option<common_commands::ItemStatus>) -> Result<(), KiCadError> {
    let status = status.unwrap_or_default();
    let code = common_commands::ItemStatusCode::try_from(status.code)
        .unwrap_or(common_commands::ItemStatusCode::IscUnknown);

    if code != common_commands::ItemStatusCode::IscOk {
        let detail = if status.error_message.is_empty() {
            code.as_str_name().to_string()
        } else {
            format!("{}: {}", code.as_str_name(), status.error_message)
        };

        return Err(KiCadError::ItemStatus { code: detail });
    }

    Ok(())
}

fn ensure_item_deletion_status_ok(status: i32) -> Result<(), KiCadError> {
    let code = common_commands::ItemDeletionStatus::try_from(status)
        .unwrap_or(common_commands::ItemDeletionStatus::IdsUnknown);

    if code != common_commands::ItemDeletionStatus::IdsOk {
        return Err(KiCadError::ItemStatus {
            code: code.as_str_name().to_string(),
        });
    }

    Ok(())
}

fn map_item_bounding_boxes(
    item_ids: Vec<common_types::Kiid>,
    boxes: Vec<common_types::Box2>,
) -> Result<Vec<ItemBoundingBox>, KiCadError> {
    let mut mapped = Vec::with_capacity(item_ids.len().min(boxes.len()));
    for (item_id, bbox) in item_ids.into_iter().zip(boxes.into_iter()) {
        let position = bbox.position.ok_or_else(|| KiCadError::InvalidResponse {
            reason: format!("missing bounding-box position for item `{}`", item_id.value),
        })?;
        let size = bbox.size.ok_or_else(|| KiCadError::InvalidResponse {
            reason: format!("missing bounding-box size for item `{}`", item_id.value),
        })?;

        mapped.push(ItemBoundingBox {
            item_id: item_id.value,
            x_nm: position.x_nm,
            y_nm: position.y_nm,
            width_nm: size.x_nm,
            height_nm: size.y_nm,
        });
    }

    Ok(mapped)
}

fn map_hit_test_result(value: i32) -> ItemHitTestResult {
    let result = common_commands::HitTestResult::try_from(value)
        .unwrap_or(common_commands::HitTestResult::HtrUnknown);

    match result {
        common_commands::HitTestResult::HtrHit => ItemHitTestResult::Hit,
        common_commands::HitTestResult::HtrNoHit => ItemHitTestResult::NoHit,
        common_commands::HitTestResult::HtrUnknown => ItemHitTestResult::Unknown,
    }
}

fn map_run_action_status(value: i32) -> RunActionStatus {
    let status = common_commands::RunActionStatus::try_from(value)
        .unwrap_or(common_commands::RunActionStatus::RasUnknown);

    match status {
        common_commands::RunActionStatus::RasOk => RunActionStatus::Ok,
        common_commands::RunActionStatus::RasInvalid => RunActionStatus::Invalid,
        common_commands::RunActionStatus::RasFrameNotOpen => RunActionStatus::FrameNotOpen,
        common_commands::RunActionStatus::RasUnknown => RunActionStatus::Unknown(value),
    }
}

fn map_polygon_with_holes(
    polygon: common_types::PolygonWithHoles,
) -> Result<PolygonWithHolesNm, KiCadError> {
    Ok(PolygonWithHolesNm {
        outline: polygon.outline.map(map_polyline).transpose()?,
        holes: polygon
            .holes
            .into_iter()
            .map(map_polyline)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn map_polyline(line: common_types::PolyLine) -> Result<PolyLineNm, KiCadError> {
    Ok(PolyLineNm {
        nodes: line
            .nodes
            .into_iter()
            .map(map_polyline_node)
            .collect::<Result<Vec<_>, _>>()?,
        closed: line.closed,
    })
}

fn map_polyline_node(
    node: common_types::PolyLineNode,
) -> Result<PolyLineNodeGeometryNm, KiCadError> {
    match node.geometry {
        Some(common_types::poly_line_node::Geometry::Point(point)) => {
            Ok(PolyLineNodeGeometryNm::Point(map_vector2_nm(point)))
        }
        Some(common_types::poly_line_node::Geometry::Arc(arc)) => {
            let start = arc.start.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing start point".to_string(),
            })?;
            let mid = arc.mid.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing mid point".to_string(),
            })?;
            let end = arc.end.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing end point".to_string(),
            })?;
            Ok(PolyLineNodeGeometryNm::Arc(ArcStartMidEndNm {
                start: map_vector2_nm(start),
                mid: map_vector2_nm(mid),
                end: map_vector2_nm(end),
            }))
        }
        None => Err(KiCadError::InvalidResponse {
            reason: "polyline node has no geometry".to_string(),
        }),
    }
}

fn map_vector2_nm(value: common_types::Vector2) -> Vector2Nm {
    Vector2Nm {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

fn vector2_nm_to_proto(value: Vector2Nm) -> common_types::Vector2 {
    common_types::Vector2 {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

fn decode_any<T: prost::Message + Default>(
    payload: &prost_types::Any,
    expected_type_name: &str,
) -> Result<T, KiCadError> {
    let expected_type_url = envelope::type_url(expected_type_name);
    if payload.type_url != expected_type_url {
        return Err(KiCadError::UnexpectedPayloadType {
            expected_type_url,
            actual_type_url: payload.type_url.clone(),
        });
    }

    T::decode(payload.value.as_slice()).map_err(|err| KiCadError::ProtobufDecode(err.to_string()))
}

fn response_payload_as_any(
    response: crate::proto::kiapi::common::ApiResponse,
    expected_type_name: &str,
) -> Result<prost_types::Any, KiCadError> {
    let payload = response.message.ok_or_else(|| KiCadError::MissingPayload {
        expected_type_url: envelope::type_url(expected_type_name),
    })?;

    let expected_type_url = envelope::type_url(expected_type_name);
    if payload.type_url != expected_type_url {
        return Err(KiCadError::UnexpectedPayloadType {
            expected_type_url,
            actual_type_url: payload.type_url,
        });
    }

    Ok(payload)
}

fn map_optional_distance_nm(distance: Option<common_types::Distance>) -> Option<i64> {
    distance.map(|value| value.value_nm)
}

fn map_optional_color(color: Option<common_types::Color>) -> Option<ColorRgba> {
    color.map(|value| ColorRgba {
        r: value.r,
        g: value.g,
        b: value.b,
        a: value.a,
    })
}

fn map_optional_net(net: Option<board_types::Net>) -> Option<BoardNet> {
    net.map(|value| BoardNet {
        code: value.code.map_or(0, |code| code.value),
        name: value.name,
    })
}

fn map_padstack_presence(value: i32) -> PadstackPresenceState {
    match board_commands::PadstackPresence::try_from(value) {
        Ok(board_commands::PadstackPresence::PspPresent) => PadstackPresenceState::Present,
        Ok(board_commands::PadstackPresence::PspNotPresent) => PadstackPresenceState::NotPresent,
        _ => PadstackPresenceState::Unknown(value),
    }
}

fn map_board_stackup_layer_type(value: i32) -> BoardStackupLayerType {
    match board_proto::BoardStackupLayerType::try_from(value) {
        Ok(board_proto::BoardStackupLayerType::BsltCopper) => BoardStackupLayerType::Copper,
        Ok(board_proto::BoardStackupLayerType::BsltDielectric) => BoardStackupLayerType::Dielectric,
        Ok(board_proto::BoardStackupLayerType::BsltSilkscreen) => BoardStackupLayerType::Silkscreen,
        Ok(board_proto::BoardStackupLayerType::BsltSoldermask) => BoardStackupLayerType::SolderMask,
        Ok(board_proto::BoardStackupLayerType::BsltSolderpaste) => {
            BoardStackupLayerType::SolderPaste
        }
        Ok(board_proto::BoardStackupLayerType::BsltUndefined) => BoardStackupLayerType::Undefined,
        _ => BoardStackupLayerType::Unknown(value),
    }
}

fn map_board_layer_class(value: i32) -> BoardLayerClass {
    match board_proto::BoardLayerClass::try_from(value) {
        Ok(board_proto::BoardLayerClass::BlcSilkscreen) => BoardLayerClass::Silkscreen,
        Ok(board_proto::BoardLayerClass::BlcCopper) => BoardLayerClass::Copper,
        Ok(board_proto::BoardLayerClass::BlcEdges) => BoardLayerClass::Edges,
        Ok(board_proto::BoardLayerClass::BlcCourtyard) => BoardLayerClass::Courtyard,
        Ok(board_proto::BoardLayerClass::BlcFabrication) => BoardLayerClass::Fabrication,
        Ok(board_proto::BoardLayerClass::BlcOther) => BoardLayerClass::Other,
        _ => BoardLayerClass::Unknown(value),
    }
}

fn map_inactive_layer_display_mode(value: i32) -> InactiveLayerDisplayMode {
    match board_commands::InactiveLayerDisplayMode::try_from(value) {
        Ok(board_commands::InactiveLayerDisplayMode::IldmNormal) => {
            InactiveLayerDisplayMode::Normal
        }
        Ok(board_commands::InactiveLayerDisplayMode::IldmDimmed) => {
            InactiveLayerDisplayMode::Dimmed
        }
        Ok(board_commands::InactiveLayerDisplayMode::IldmHidden) => {
            InactiveLayerDisplayMode::Hidden
        }
        _ => InactiveLayerDisplayMode::Unknown(value),
    }
}

fn inactive_layer_display_mode_to_proto(value: InactiveLayerDisplayMode) -> i32 {
    match value {
        InactiveLayerDisplayMode::Normal => {
            board_commands::InactiveLayerDisplayMode::IldmNormal as i32
        }
        InactiveLayerDisplayMode::Dimmed => {
            board_commands::InactiveLayerDisplayMode::IldmDimmed as i32
        }
        InactiveLayerDisplayMode::Hidden => {
            board_commands::InactiveLayerDisplayMode::IldmHidden as i32
        }
        InactiveLayerDisplayMode::Unknown(value) => value,
    }
}

fn map_net_color_display_mode(value: i32) -> NetColorDisplayMode {
    match board_commands::NetColorDisplayMode::try_from(value) {
        Ok(board_commands::NetColorDisplayMode::NcdmAll) => NetColorDisplayMode::All,
        Ok(board_commands::NetColorDisplayMode::NcdmRatsnest) => NetColorDisplayMode::Ratsnest,
        Ok(board_commands::NetColorDisplayMode::NcdmOff) => NetColorDisplayMode::Off,
        _ => NetColorDisplayMode::Unknown(value),
    }
}

fn net_color_display_mode_to_proto(value: NetColorDisplayMode) -> i32 {
    match value {
        NetColorDisplayMode::All => board_commands::NetColorDisplayMode::NcdmAll as i32,
        NetColorDisplayMode::Ratsnest => board_commands::NetColorDisplayMode::NcdmRatsnest as i32,
        NetColorDisplayMode::Off => board_commands::NetColorDisplayMode::NcdmOff as i32,
        NetColorDisplayMode::Unknown(value) => value,
    }
}

fn map_board_flip_mode(value: i32) -> BoardFlipMode {
    match board_commands::BoardFlipMode::try_from(value) {
        Ok(board_commands::BoardFlipMode::BfmNormal) => BoardFlipMode::Normal,
        Ok(board_commands::BoardFlipMode::BfmFlippedX) => BoardFlipMode::FlippedX,
        _ => BoardFlipMode::Unknown(value),
    }
}

fn board_flip_mode_to_proto(value: BoardFlipMode) -> i32 {
    match value {
        BoardFlipMode::Normal => board_commands::BoardFlipMode::BfmNormal as i32,
        BoardFlipMode::FlippedX => board_commands::BoardFlipMode::BfmFlippedX as i32,
        BoardFlipMode::Unknown(value) => value,
    }
}

fn map_ratsnest_display_mode(value: i32) -> RatsnestDisplayMode {
    match board_commands::RatsnestDisplayMode::try_from(value) {
        Ok(board_commands::RatsnestDisplayMode::RdmAllLayers) => RatsnestDisplayMode::AllLayers,
        Ok(board_commands::RatsnestDisplayMode::RdmVisibleLayers) => {
            RatsnestDisplayMode::VisibleLayers
        }
        _ => RatsnestDisplayMode::Unknown(value),
    }
}

fn ratsnest_display_mode_to_proto(value: RatsnestDisplayMode) -> i32 {
    match value {
        RatsnestDisplayMode::AllLayers => board_commands::RatsnestDisplayMode::RdmAllLayers as i32,
        RatsnestDisplayMode::VisibleLayers => {
            board_commands::RatsnestDisplayMode::RdmVisibleLayers as i32
        }
        RatsnestDisplayMode::Unknown(value) => value,
    }
}

fn map_board_stackup(stackup: board_proto::BoardStackup) -> BoardStackup {
    let finish_type_name = stackup
        .finish
        .map(|finish| finish.type_name)
        .unwrap_or_default();
    let impedance_controlled = stackup
        .impedance
        .map(|impedance| impedance.is_controlled)
        .unwrap_or(false);
    let edge = stackup.edge.unwrap_or_default();
    let edge_has_castellated_pads = edge
        .castellation
        .map(|value| value.has_castellated_pads)
        .unwrap_or(false);
    let edge_has_edge_plating = edge
        .plating
        .map(|value| value.has_edge_plating)
        .unwrap_or(false);

    let layers = stackup
        .layers
        .into_iter()
        .map(|layer| BoardStackupLayer {
            layer: layer_to_model(layer.layer),
            user_name: layer.user_name,
            material_name: layer.material_name,
            enabled: layer.enabled,
            thickness_nm: map_optional_distance_nm(layer.thickness),
            layer_type: map_board_stackup_layer_type(layer.r#type),
            color: map_optional_color(layer.color),
            dielectric_layers: layer
                .dielectric
                .unwrap_or_default()
                .layer
                .into_iter()
                .map(|dielectric| BoardStackupDielectricProperties {
                    epsilon_r: dielectric.epsilon_r,
                    loss_tangent: dielectric.loss_tangent,
                    material_name: dielectric.material_name,
                    thickness_nm: map_optional_distance_nm(dielectric.thickness),
                })
                .collect(),
        })
        .collect();

    BoardStackup {
        finish_type_name,
        impedance_controlled,
        edge_has_castellated_pads,
        edge_has_edge_plating,
        layers,
    }
}

fn map_graphics_defaults(defaults: board_proto::GraphicsDefaults) -> GraphicsDefaults {
    GraphicsDefaults {
        layers: defaults
            .layers
            .into_iter()
            .map(|layer| {
                let text = layer.text.unwrap_or_default();
                let text_font_name = if text.font_name.is_empty() {
                    None
                } else {
                    Some(text.font_name)
                };
                BoardLayerGraphicsDefault {
                    layer_class: map_board_layer_class(layer.layer),
                    line_thickness_nm: map_optional_distance_nm(layer.line_thickness),
                    text_font_name,
                    text_size_nm: text.size.map(map_vector2_nm),
                    text_stroke_width_nm: map_optional_distance_nm(text.stroke_width),
                }
            })
            .collect(),
    }
}

fn map_board_editor_appearance_settings(
    settings: board_commands::BoardEditorAppearanceSettings,
) -> BoardEditorAppearanceSettings {
    BoardEditorAppearanceSettings {
        inactive_layer_display: map_inactive_layer_display_mode(settings.inactive_layer_display),
        net_color_display: map_net_color_display_mode(settings.net_color_display),
        board_flip: map_board_flip_mode(settings.board_flip),
        ratsnest_display: map_ratsnest_display_mode(settings.ratsnest_display),
    }
}

fn board_editor_appearance_settings_to_proto(
    settings: BoardEditorAppearanceSettings,
) -> board_commands::BoardEditorAppearanceSettings {
    board_commands::BoardEditorAppearanceSettings {
        inactive_layer_display: inactive_layer_display_mode_to_proto(
            settings.inactive_layer_display,
        ),
        net_color_display: net_color_display_mode_to_proto(settings.net_color_display),
        board_flip: board_flip_mode_to_proto(settings.board_flip),
        ratsnest_display: ratsnest_display_mode_to_proto(settings.ratsnest_display),
    }
}

fn net_class_type_to_proto(value: NetClassType) -> i32 {
    match value {
        NetClassType::Explicit => common_project::NetClassType::NctExplicit as i32,
        NetClassType::Implicit => common_project::NetClassType::NctImplicit as i32,
        NetClassType::Unknown(raw) => raw,
    }
}

fn net_class_info_to_proto(value: NetClassInfo) -> common_project::NetClass {
    let board = value
        .board
        .map(|board| common_project::NetClassBoardSettings {
            clearance: board
                .clearance_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            track_width: board
                .track_width_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_track_width: board
                .diff_pair_track_width_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_gap: board
                .diff_pair_gap_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_via_gap: board
                .diff_pair_via_gap_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            via_stack: if board.has_via_stack {
                Some(board_types::PadStack::default())
            } else {
                None
            },
            microvia_stack: if board.has_microvia_stack {
                Some(board_types::PadStack::default())
            } else {
                None
            },
            color: board.color.map(|color| common_types::Color {
                r: color.r,
                g: color.g,
                b: color.b,
                a: color.a,
            }),
            tuning_profile: board.tuning_profile,
        });

    common_project::NetClass {
        name: value.name,
        priority: value.priority,
        board,
        schematic: None,
        r#type: net_class_type_to_proto(value.class_type),
        constituents: value.constituents,
    }
}

fn map_net_class_type(value: i32) -> NetClassType {
    match common_project::NetClassType::try_from(value) {
        Ok(common_project::NetClassType::NctExplicit) => NetClassType::Explicit,
        Ok(common_project::NetClassType::NctImplicit) => NetClassType::Implicit,
        _ => NetClassType::Unknown(value),
    }
}

fn map_net_class_info(net_class: common_project::NetClass) -> NetClassInfo {
    let board = net_class.board.map(|board| NetClassBoardSettings {
        clearance_nm: map_optional_distance_nm(board.clearance),
        track_width_nm: map_optional_distance_nm(board.track_width),
        diff_pair_track_width_nm: map_optional_distance_nm(board.diff_pair_track_width),
        diff_pair_gap_nm: map_optional_distance_nm(board.diff_pair_gap),
        diff_pair_via_gap_nm: map_optional_distance_nm(board.diff_pair_via_gap),
        color: map_optional_color(board.color),
        tuning_profile: board.tuning_profile.filter(|value| !value.is_empty()),
        has_via_stack: board.via_stack.is_some(),
        has_microvia_stack: board.microvia_stack.is_some(),
    });

    NetClassInfo {
        name: net_class.name,
        priority: net_class.priority,
        class_type: map_net_class_type(net_class.r#type),
        constituents: net_class.constituents,
        board,
    }
}

fn map_netclass_for_nets_response(
    response: board_commands::NetClassForNetsResponse,
) -> Vec<NetClassForNetEntry> {
    let mut rows: Vec<(String, common_project::NetClass)> = response.classes.into_iter().collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    rows.into_iter()
        .map(|(net_name, net_class)| NetClassForNetEntry {
            net_name,
            net_class: map_net_class_info(net_class),
        })
        .collect()
}

fn map_via_type(value: i32) -> PcbViaType {
    match board_types::ViaType::try_from(value) {
        Ok(board_types::ViaType::VtThrough) => PcbViaType::Through,
        Ok(board_types::ViaType::VtBlindBuried) => PcbViaType::BlindBuried,
        Ok(board_types::ViaType::VtMicro) => PcbViaType::Micro,
        Ok(board_types::ViaType::VtBlind) => PcbViaType::Blind,
        Ok(board_types::ViaType::VtBuried) => PcbViaType::Buried,
        _ => PcbViaType::Unknown(value),
    }
}

fn map_pad_type(value: i32) -> PcbPadType {
    match board_types::PadType::try_from(value) {
        Ok(board_types::PadType::PtPth) => PcbPadType::Pth,
        Ok(board_types::PadType::PtSmd) => PcbPadType::Smd,
        Ok(board_types::PadType::PtEdgeConnector) => PcbPadType::EdgeConnector,
        Ok(board_types::PadType::PtNpth) => PcbPadType::Npth,
        _ => PcbPadType::Unknown(value),
    }
}

fn map_zone_type(value: i32) -> PcbZoneType {
    match board_types::ZoneType::try_from(value) {
        Ok(board_types::ZoneType::ZtCopper) => PcbZoneType::Copper,
        Ok(board_types::ZoneType::ZtGraphical) => PcbZoneType::Graphical,
        Ok(board_types::ZoneType::ZtRuleArea) => PcbZoneType::RuleArea,
        Ok(board_types::ZoneType::ZtTeardrop) => PcbZoneType::Teardrop,
        _ => PcbZoneType::Unknown(value),
    }
}

fn decode_pcb_items(items: Vec<prost_types::Any>) -> Result<Vec<PcbItem>, KiCadError> {
    items.into_iter().map(decode_pcb_item).collect()
}

fn decode_pcb_item(item: prost_types::Any) -> Result<PcbItem, KiCadError> {
    if item.type_url == envelope::type_url("kiapi.board.types.Track") {
        let track = decode_any::<board_types::Track>(&item, "kiapi.board.types.Track")?;
        return Ok(PcbItem::Track(PcbTrack {
            id: track.id.map(|id| id.value),
            start_nm: track.start.map(map_vector2_nm),
            end_nm: track.end.map(map_vector2_nm),
            width_nm: map_optional_distance_nm(track.width),
            layer: layer_to_model(track.layer),
            net: map_optional_net(track.net),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Arc") {
        let arc = decode_any::<board_types::Arc>(&item, "kiapi.board.types.Arc")?;
        return Ok(PcbItem::Arc(PcbArc {
            id: arc.id.map(|id| id.value),
            start_nm: arc.start.map(map_vector2_nm),
            mid_nm: arc.mid.map(map_vector2_nm),
            end_nm: arc.end.map(map_vector2_nm),
            width_nm: map_optional_distance_nm(arc.width),
            layer: layer_to_model(arc.layer),
            net: map_optional_net(arc.net),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Via") {
        let via = decode_any::<board_types::Via>(&item, "kiapi.board.types.Via")?;
        return Ok(PcbItem::Via(PcbVia {
            id: via.id.map(|id| id.value),
            position_nm: via.position.map(map_vector2_nm),
            via_type: map_via_type(via.r#type),
            net: map_optional_net(via.net),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.FootprintInstance") {
        let footprint = decode_any::<board_types::FootprintInstance>(
            &item,
            "kiapi.board.types.FootprintInstance",
        )?;
        let reference = footprint
            .reference_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());
        let pad_count = footprint
            .definition
            .as_ref()
            .map(|definition| {
                definition
                    .items
                    .iter()
                    .filter(|entry| entry.type_url == envelope::type_url("kiapi.board.types.Pad"))
                    .count()
            })
            .unwrap_or(0);

        return Ok(PcbItem::Footprint(PcbFootprint {
            id: footprint.id.map(|id| id.value),
            reference,
            position_nm: footprint.position.map(map_vector2_nm),
            orientation_deg: footprint.orientation.map(|angle| angle.value_degrees),
            layer: layer_to_model(footprint.layer),
            pad_count,
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Pad") {
        let pad = decode_any::<board_types::Pad>(&item, "kiapi.board.types.Pad")?;
        return Ok(PcbItem::Pad(PcbPad {
            id: pad.id.map(|id| id.value),
            number: pad.number,
            pad_type: map_pad_type(pad.r#type),
            position_nm: pad.position.map(map_vector2_nm),
            net: map_optional_net(pad.net),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardGraphicShape") {
        let shape = decode_any::<board_types::BoardGraphicShape>(
            &item,
            "kiapi.board.types.BoardGraphicShape",
        )?;
        let geometry_kind = shape
            .shape
            .as_ref()
            .and_then(|graphic| graphic.geometry.as_ref())
            .map(|value| format!("{value:?}"));
        return Ok(PcbItem::BoardGraphicShape(PcbBoardGraphicShape {
            id: shape.id.map(|id| id.value),
            layer: layer_to_model(shape.layer),
            net: map_optional_net(shape.net),
            geometry_kind,
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardText") {
        let text = decode_any::<board_types::BoardText>(&item, "kiapi.board.types.BoardText")?;
        return Ok(PcbItem::BoardText(PcbBoardText {
            id: text.id.map(|id| id.value),
            layer: layer_to_model(text.layer),
            text: text.text.map(|value| value.text),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardTextBox") {
        let textbox =
            decode_any::<board_types::BoardTextBox>(&item, "kiapi.board.types.BoardTextBox")?;
        return Ok(PcbItem::BoardTextBox(PcbBoardTextBox {
            id: textbox.id.map(|id| id.value),
            layer: layer_to_model(textbox.layer),
            text: textbox.textbox.map(|value| value.text),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Field") {
        let field = decode_any::<board_types::Field>(&item, "kiapi.board.types.Field")?;
        let text = field
            .text
            .and_then(|board_text| board_text.text)
            .map(|value| value.text);
        return Ok(PcbItem::Field(PcbField {
            name: field.name,
            visible: field.visible,
            text,
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Zone") {
        let zone = decode_any::<board_types::Zone>(&item, "kiapi.board.types.Zone")?;
        return Ok(PcbItem::Zone(PcbZone {
            id: zone.id.map(|id| id.value),
            name: zone.name,
            zone_type: map_zone_type(zone.r#type),
            layer_count: zone.layers.len(),
            filled: zone.filled,
            polygon_count: zone.filled_polygons.len(),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Dimension") {
        let dimension = decode_any::<board_types::Dimension>(&item, "kiapi.board.types.Dimension")?;
        return Ok(PcbItem::Dimension(PcbDimension {
            id: dimension.id.map(|id| id.value),
            layer: layer_to_model(dimension.layer),
            text: dimension.text.map(|value| value.text),
            style_kind: dimension.dimension_style.map(|value| format!("{value:?}")),
        }));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Group") {
        let group = decode_any::<board_types::Group>(&item, "kiapi.board.types.Group")?;
        return Ok(PcbItem::Group(PcbGroup {
            id: group.id.map(|id| id.value),
            name: group.name,
            item_count: group.items.len(),
        }));
    }

    Ok(PcbItem::Unknown(PcbUnknownItem {
        type_url: item.type_url,
        raw_len: item.value.len(),
    }))
}

fn pad_netlist_from_footprint_items(
    footprint_items: Vec<prost_types::Any>,
) -> Result<Vec<PadNetEntry>, KiCadError> {
    let mut entries = Vec::new();
    for item in footprint_items {
        if item.type_url != envelope::type_url("kiapi.board.types.FootprintInstance") {
            continue;
        }

        let footprint = decode_any::<board_types::FootprintInstance>(
            &item,
            "kiapi.board.types.FootprintInstance",
        )?;

        let footprint_reference = footprint
            .reference_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());

        let footprint_id = footprint.id.as_ref().map(|id| id.value.clone());

        let footprint_definition = footprint.definition.unwrap_or_default();
        for sub_item in footprint_definition.items {
            if sub_item.type_url != envelope::type_url("kiapi.board.types.Pad") {
                continue;
            }

            let pad = decode_any::<board_types::Pad>(&sub_item, "kiapi.board.types.Pad")?;
            let (net_code, net_name) = match pad.net {
                Some(net) => {
                    let code = net.code.map(|code| code.value);
                    let name = if net.name.is_empty() {
                        None
                    } else {
                        Some(net.name)
                    };
                    (code, name)
                }
                None => (None, None),
            };

            entries.push(PadNetEntry {
                footprint_reference: footprint_reference.clone(),
                footprint_id: footprint_id.clone(),
                pad_id: pad.id.map(|id| id.value),
                pad_number: pad.number,
                net_code,
                net_name,
            });
        }
    }

    Ok(entries)
}

fn selection_item_detail(item: &prost_types::Any) -> Result<String, KiCadError> {
    if item.type_url == envelope::type_url("kiapi.board.types.Track") {
        let track = decode_any::<board_types::Track>(item, "kiapi.board.types.Track")?;
        return Ok(format_track_selection_detail(track));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Arc") {
        let arc = decode_any::<board_types::Arc>(item, "kiapi.board.types.Arc")?;
        return Ok(format_arc_selection_detail(arc));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Via") {
        let via = decode_any::<board_types::Via>(item, "kiapi.board.types.Via")?;
        return Ok(format_via_selection_detail(via));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.FootprintInstance") {
        let footprint = decode_any::<board_types::FootprintInstance>(
            item,
            "kiapi.board.types.FootprintInstance",
        )?;
        return Ok(format_footprint_selection_detail(footprint));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Field") {
        let field = decode_any::<board_types::Field>(item, "kiapi.board.types.Field")?;
        return Ok(format_field_selection_detail(field));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardText") {
        let text = decode_any::<board_types::BoardText>(item, "kiapi.board.types.BoardText")?;
        return Ok(format_board_text_selection_detail(text));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardTextBox") {
        let textbox =
            decode_any::<board_types::BoardTextBox>(item, "kiapi.board.types.BoardTextBox")?;
        return Ok(format_board_textbox_selection_detail(textbox));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Pad") {
        let pad = decode_any::<board_types::Pad>(item, "kiapi.board.types.Pad")?;
        return Ok(format_pad_selection_detail(pad));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardGraphicShape") {
        let shape = decode_any::<board_types::BoardGraphicShape>(
            item,
            "kiapi.board.types.BoardGraphicShape",
        )?;
        return Ok(format_board_graphic_shape_selection_detail(shape));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Zone") {
        let zone = decode_any::<board_types::Zone>(item, "kiapi.board.types.Zone")?;
        return Ok(format_zone_selection_detail(zone));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Dimension") {
        let dimension = decode_any::<board_types::Dimension>(item, "kiapi.board.types.Dimension")?;
        return Ok(format_dimension_selection_detail(dimension));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Group") {
        let group = decode_any::<board_types::Group>(item, "kiapi.board.types.Group")?;
        return Ok(format_group_selection_detail(group));
    }

    Ok(format!("unparsed payload ({} bytes)", item.value.len()))
}

fn format_track_selection_detail(track: board_types::Track) -> String {
    let id = track.id.map_or_else(|| "-".to_string(), |id| id.value);
    let start = track
        .start
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let end = track
        .end
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let width = track
        .width
        .map_or_else(|| "-".to_string(), |w| w.value_nm.to_string());
    let layer = layer_to_model(track.layer).name;
    let net = track
        .net
        .map(|n| format!("{}:{}", n.code.map_or(0, |c| c.value), n.name))
        .unwrap_or_else(|| "-".to_string());
    format!("track id={id} start_nm={start} end_nm={end} width_nm={width} layer={layer} net={net}")
}

fn format_arc_selection_detail(arc: board_types::Arc) -> String {
    let id = arc.id.map_or_else(|| "-".to_string(), |id| id.value);
    let start = arc
        .start
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let mid = arc
        .mid
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let end = arc
        .end
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let width = arc
        .width
        .map_or_else(|| "-".to_string(), |w| w.value_nm.to_string());
    let layer = layer_to_model(arc.layer).name;
    let net = arc
        .net
        .map(|n| format!("{}:{}", n.code.map_or(0, |c| c.value), n.name))
        .unwrap_or_else(|| "-".to_string());
    format!(
        "arc id={id} start_nm={start} mid_nm={mid} end_nm={end} width_nm={width} layer={layer} net={net}"
    )
}

fn format_via_selection_detail(via: board_types::Via) -> String {
    let id = via.id.map_or_else(|| "-".to_string(), |id| id.value);
    let position = via
        .position
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let net = via
        .net
        .map(|n| format!("{}:{}", n.code.map_or(0, |c| c.value), n.name))
        .unwrap_or_else(|| "-".to_string());
    let via_type = board_types::ViaType::try_from(via.r#type)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", via.r#type));
    format!("via id={id} pos_nm={position} type={via_type} net={net}")
}

fn format_footprint_selection_detail(footprint: board_types::FootprintInstance) -> String {
    let id = footprint.id.map_or_else(|| "-".to_string(), |id| id.value);
    let reference = footprint
        .reference_field
        .as_ref()
        .and_then(|field| field.text.as_ref())
        .and_then(|board_text| board_text.text.as_ref())
        .map(|text| text.text.clone())
        .unwrap_or_else(|| "-".to_string());
    let position = footprint
        .position
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let orientation_deg = footprint.orientation.map_or_else(
        || "-".to_string(),
        |orientation| orientation.value_degrees.to_string(),
    );
    let layer = layer_to_model(footprint.layer).name;
    let pad_count = footprint
        .definition
        .as_ref()
        .map(|definition| {
            definition
                .items
                .iter()
                .filter(|entry| entry.type_url == envelope::type_url("kiapi.board.types.Pad"))
                .count()
        })
        .unwrap_or(0);
    format!(
        "footprint id={id} ref={reference} pos_nm={position} orientation_deg={orientation_deg} layer={layer} pad_count={pad_count}"
    )
}

fn format_field_selection_detail(field: board_types::Field) -> String {
    let text = field
        .text
        .as_ref()
        .and_then(|board_text| board_text.text.as_ref())
        .map(|text| text.text.clone())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "field name={} visible={} text={}",
        field.name, field.visible, text
    )
}

fn format_board_text_selection_detail(text: board_types::BoardText) -> String {
    let id = text.id.map_or_else(|| "-".to_string(), |id| id.value);
    let layer = layer_to_model(text.layer).name;
    let body = text
        .text
        .as_ref()
        .map(|value| value.text.clone())
        .unwrap_or_else(|| "-".to_string());
    format!("text id={id} layer={layer} text={body}")
}

fn format_board_textbox_selection_detail(textbox: board_types::BoardTextBox) -> String {
    let id = textbox.id.map_or_else(|| "-".to_string(), |id| id.value);
    let layer = layer_to_model(textbox.layer).name;
    let body = textbox
        .textbox
        .as_ref()
        .map(|value| value.text.clone())
        .unwrap_or_else(|| "-".to_string());
    format!("textbox id={id} layer={layer} text={body}")
}

fn format_pad_selection_detail(pad: board_types::Pad) -> String {
    let id = pad.id.map_or_else(|| "-".to_string(), |id| id.value);
    let pad_type = board_types::PadType::try_from(pad.r#type)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", pad.r#type));
    let position = pad
        .position
        .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
    let net = pad
        .net
        .map(|n| format!("{}:{}", n.code.map_or(0, |c| c.value), n.name))
        .unwrap_or_else(|| "-".to_string());
    format!(
        "pad id={id} number={} type={pad_type} pos_nm={position} net={net}",
        pad.number
    )
}

fn format_board_graphic_shape_selection_detail(shape: board_types::BoardGraphicShape) -> String {
    let id = shape.id.map_or_else(|| "-".to_string(), |id| id.value);
    let layer = layer_to_model(shape.layer).name;
    let net = shape
        .net
        .map(|n| format!("{}:{}", n.code.map_or(0, |c| c.value), n.name))
        .unwrap_or_else(|| "-".to_string());
    let geometry = shape
        .shape
        .as_ref()
        .map(|graphic| format!("{:?}", graphic.geometry))
        .unwrap_or_else(|| "-".to_string());
    format!("graphic id={id} layer={layer} net={net} geometry={geometry}")
}

fn format_zone_selection_detail(zone: board_types::Zone) -> String {
    let id = zone.id.map_or_else(|| "-".to_string(), |id| id.value);
    let zone_type = board_types::ZoneType::try_from(zone.r#type)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", zone.r#type));
    format!(
        "zone id={id} name={} type={} layer_count={} filled={} polygon_count={}",
        zone.name,
        zone_type,
        zone.layers.len(),
        zone.filled,
        zone.filled_polygons.len()
    )
}

fn format_dimension_selection_detail(dimension: board_types::Dimension) -> String {
    let id = dimension.id.map_or_else(|| "-".to_string(), |id| id.value);
    let layer = layer_to_model(dimension.layer).name;
    let text = dimension
        .text
        .as_ref()
        .map(|value| value.text.clone())
        .unwrap_or_else(|| "-".to_string());
    let style = format!("{:?}", dimension.dimension_style);
    format!(
        "dimension id={id} layer={layer} text={} style={style}",
        text
    )
}

fn format_group_selection_detail(group: board_types::Group) -> String {
    let id = group.id.map_or_else(|| "-".to_string(), |id| id.value);
    format!(
        "group id={id} name={} item_count={}",
        group.name,
        group.items.len()
    )
}

fn any_to_pretty_debug(item: &prost_types::Any) -> Result<String, KiCadError> {
    macro_rules! debug_any {
        ($(($url:literal, $ty:ty)),* $(,)?) => {
            $(
                if item.type_url == envelope::type_url($url) {
                    let value = decode_any::<$ty>(item, $url)?;
                    return Ok(format!("{:#?}", value));
                }
            )*
        };
    }

    debug_any!(
        ("kiapi.board.types.Track", board_types::Track),
        ("kiapi.board.types.Arc", board_types::Arc),
        ("kiapi.board.types.Via", board_types::Via),
        (
            "kiapi.board.types.FootprintInstance",
            board_types::FootprintInstance
        ),
        ("kiapi.board.types.Pad", board_types::Pad),
        (
            "kiapi.board.types.BoardGraphicShape",
            board_types::BoardGraphicShape
        ),
        ("kiapi.board.types.BoardText", board_types::BoardText),
        ("kiapi.board.types.BoardTextBox", board_types::BoardTextBox),
        ("kiapi.board.types.Field", board_types::Field),
        ("kiapi.board.types.Zone", board_types::Zone),
        ("kiapi.board.types.Dimension", board_types::Dimension),
        ("kiapi.board.types.Group", board_types::Group),
    );

    Ok(format!(
        "unparsed_any type_url={} raw_len={}",
        item.type_url,
        item.value.len()
    ))
}

fn select_single_board_document(
    docs: &[DocumentSpecifier],
) -> Result<&DocumentSpecifier, KiCadError> {
    if docs.is_empty() {
        return Err(KiCadError::BoardNotOpen);
    }

    if docs.len() > 1 {
        let boards = docs
            .iter()
            .map(|doc| {
                doc.board_filename
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string())
            })
            .collect();
        return Err(KiCadError::AmbiguousBoardSelection { boards });
    }

    Ok(&docs[0])
}

fn select_single_project_path(docs: &[DocumentSpecifier]) -> Result<PathBuf, KiCadError> {
    let mut paths = BTreeSet::new();
    for doc in docs {
        if let Some(path) = doc.project.path.as_ref() {
            paths.insert(path.display().to_string());
        }
    }

    if paths.is_empty() {
        return Err(KiCadError::BoardNotOpen);
    }

    if paths.len() > 1 {
        return Err(KiCadError::AmbiguousProjectPath {
            paths: paths.into_iter().collect(),
        });
    }

    let first = paths.into_iter().next().ok_or(KiCadError::BoardNotOpen)?;
    Ok(PathBuf::from(first))
}

fn resolve_socket_uri(explicit: Option<&str>) -> String {
    if let Some(socket) = explicit {
        return normalize_socket_uri(socket);
    }

    if let Ok(socket) = std::env::var(KICAD_API_SOCKET_ENV) {
        if !socket.is_empty() {
            return normalize_socket_uri(&socket);
        }
    }

    normalize_socket_uri(default_socket_path().to_string_lossy().as_ref())
}

fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return std::env::temp_dir().join("kicad").join("api.sock");
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let flatpak = PathBuf::from(home)
                .join(".var")
                .join("app")
                .join("org.kicad.KiCad")
                .join("cache")
                .join("tmp")
                .join("kicad")
                .join("api.sock");
            if flatpak.exists() {
                return flatpak;
            }
        }

        PathBuf::from("/tmp/kicad/api.sock")
    }
}

fn normalize_socket_uri(socket: &str) -> String {
    if socket.contains("://") {
        return socket.to_string();
    }

    format!("ipc://{socket}")
}

fn ipc_path_from_uri(socket_uri: &str) -> Option<PathBuf> {
    let raw_path = socket_uri.strip_prefix("ipc://")?;
    Some(PathBuf::from(raw_path))
}

fn is_missing_ipc_socket(socket_uri: &str) -> bool {
    if let Some(path) = ipc_path_from_uri(socket_uri) {
        return !path.exists();
    }

    false
}

fn default_client_name() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    format!("kicad-ipc-{}-{millis}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{
        any_to_pretty_debug, board_editor_appearance_settings_to_proto, commit_action_to_proto,
        drc_severity_to_proto, ensure_item_deletion_status_ok, ensure_item_request_ok,
        ensure_item_status_ok, layer_to_model, map_commit_session, map_hit_test_result,
        map_item_bounding_boxes, map_merge_mode_to_proto, map_polygon_with_holes,
        map_run_action_status, model_document_to_proto, normalize_socket_uri,
        pad_netlist_from_footprint_items, response_payload_as_any, select_single_board_document,
        select_single_project_path, selection_item_detail, summarize_item_details,
        summarize_selection, text_horizontal_alignment_to_proto, text_spec_to_proto,
        PCB_OBJECT_TYPES,
    };
    use crate::error::KiCadError;
    use crate::model::common::{
        CommitAction, DocumentSpecifier, DocumentType, ProjectInfo, TextAttributesSpec,
        TextHorizontalAlignment, TextSpec,
    };
    use prost::Message;
    use std::path::PathBuf;

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

        let summary = summarize_selection(items);
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
}
