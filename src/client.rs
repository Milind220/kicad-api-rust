use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::envelope;
use crate::error::KiCadError;
use crate::model::board::{
    BoardEnabledLayers, BoardLayerInfo, BoardNet, BoardOriginKind, PadNetEntry, Vector2Nm,
};
use crate::model::common::{
    DocumentSpecifier, DocumentType, ItemBoundingBox, ItemHitTestResult, PcbObjectTypeCode,
    ProjectInfo, SelectionItemDetail, SelectionSummary, SelectionTypeCount, TitleBlockInfo,
    VersionInfo,
};
use crate::proto::kiapi::board::commands as board_commands;
use crate::proto::kiapi::board::types as board_types;
use crate::proto::kiapi::common::commands as common_commands;
use crate::proto::kiapi::common::types as common_types;
use crate::transport::Transport;

const KICAD_API_SOCKET_ENV: &str = "KICAD_API_SOCKET";
const KICAD_API_TOKEN_ENV: &str = "KICAD_API_TOKEN";

const CMD_PING: &str = "kiapi.common.commands.Ping";
const CMD_GET_VERSION: &str = "kiapi.common.commands.GetVersion";
const CMD_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocuments";
const CMD_GET_NETS: &str = "kiapi.board.commands.GetNets";
const CMD_GET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.GetBoardEnabledLayers";
const CMD_GET_ACTIVE_LAYER: &str = "kiapi.board.commands.GetActiveLayer";
const CMD_GET_VISIBLE_LAYERS: &str = "kiapi.board.commands.GetVisibleLayers";
const CMD_GET_BOARD_ORIGIN: &str = "kiapi.board.commands.GetBoardOrigin";
const CMD_GET_BOARD_STACKUP: &str = "kiapi.board.commands.GetBoardStackup";
const CMD_GET_GRAPHICS_DEFAULTS: &str = "kiapi.board.commands.GetGraphicsDefaults";
const CMD_GET_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.GetBoardEditorAppearanceSettings";
const CMD_GET_ITEMS_BY_NET: &str = "kiapi.board.commands.GetItemsByNet";
const CMD_GET_ITEMS_BY_NET_CLASS: &str = "kiapi.board.commands.GetItemsByNetClass";
const CMD_GET_NETCLASS_FOR_NETS: &str = "kiapi.board.commands.GetNetClassForNets";
const CMD_GET_SELECTION: &str = "kiapi.common.commands.GetSelection";
const CMD_GET_ITEMS: &str = "kiapi.common.commands.GetItems";
const CMD_GET_ITEMS_BY_ID: &str = "kiapi.common.commands.GetItemsById";
const CMD_GET_BOUNDING_BOX: &str = "kiapi.common.commands.GetBoundingBox";
const CMD_HIT_TEST: &str = "kiapi.common.commands.HitTest";
const CMD_GET_TITLE_BLOCK_INFO: &str = "kiapi.common.commands.GetTitleBlockInfo";
const CMD_SAVE_DOCUMENT_TO_STRING: &str = "kiapi.common.commands.SaveDocumentToString";
const CMD_SAVE_SELECTION_TO_STRING: &str = "kiapi.common.commands.SaveSelectionToString";

const RES_GET_VERSION: &str = "kiapi.common.commands.GetVersionResponse";
const RES_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocumentsResponse";
const RES_GET_NETS: &str = "kiapi.board.commands.NetsResponse";
const RES_GET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.BoardEnabledLayersResponse";
const RES_BOARD_LAYER_RESPONSE: &str = "kiapi.board.commands.BoardLayerResponse";
const RES_BOARD_LAYERS: &str = "kiapi.board.commands.BoardLayers";
const RES_BOARD_STACKUP_RESPONSE: &str = "kiapi.board.commands.BoardStackupResponse";
const RES_GRAPHICS_DEFAULTS_RESPONSE: &str = "kiapi.board.commands.GraphicsDefaultsResponse";
const RES_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.BoardEditorAppearanceSettings";
const RES_NETCLASS_FOR_NETS_RESPONSE: &str = "kiapi.board.commands.NetClassForNetsResponse";
const RES_VECTOR2: &str = "kiapi.common.types.Vector2";
const RES_SELECTION_RESPONSE: &str = "kiapi.common.commands.SelectionResponse";
const RES_GET_ITEMS_RESPONSE: &str = "kiapi.common.commands.GetItemsResponse";
const RES_GET_BOUNDING_BOX_RESPONSE: &str = "kiapi.common.commands.GetBoundingBoxResponse";
const RES_HIT_TEST_RESPONSE: &str = "kiapi.common.commands.HitTestResponse";
const RES_TITLE_BLOCK_INFO: &str = "kiapi.common.types.TitleBlockInfo";
const RES_SAVED_DOCUMENT_RESPONSE: &str = "kiapi.common.commands.SavedDocumentResponse";
const RES_SAVED_SELECTION_RESPONSE: &str = "kiapi.common.commands.SavedSelectionResponse";

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

    pub async fn get_current_project_path(&self) -> Result<PathBuf, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        select_single_project_path(&docs)
    }

    pub async fn has_open_board(&self) -> Result<bool, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        Ok(!docs.is_empty())
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

        Ok(BoardEnabledLayers {
            copper_layer_count: payload.copper_layer_count,
            layers: payload.layers.into_iter().map(layer_to_model).collect(),
        })
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

    pub async fn get_netclass_for_nets_debug(
        &self,
        nets: Vec<BoardNet>,
    ) -> Result<String, KiCadError> {
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
        let payload: board_commands::NetClassForNetsResponse =
            envelope::unpack_any(&response, RES_NETCLASS_FOR_NETS_RESPONSE)?;
        Ok(format!("{:#?}", payload.classes))
    }

    pub async fn get_board_stackup_debug(&self) -> Result<String, KiCadError> {
        let command = board_commands::GetBoardStackup {
            board: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_BOARD_STACKUP))
            .await?;
        let payload: board_commands::BoardStackupResponse =
            envelope::unpack_any(&response, RES_BOARD_STACKUP_RESPONSE)?;
        Ok(format!("{:#?}", payload.stackup))
    }

    pub async fn get_graphics_defaults_debug(&self) -> Result<String, KiCadError> {
        let command = board_commands::GetGraphicsDefaults {
            board: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_GRAPHICS_DEFAULTS))
            .await?;
        let payload: board_commands::GraphicsDefaultsResponse =
            envelope::unpack_any(&response, RES_GRAPHICS_DEFAULTS_RESPONSE)?;
        Ok(format!("{:#?}", payload.defaults))
    }

    pub async fn get_board_editor_appearance_settings_debug(&self) -> Result<String, KiCadError> {
        let command = board_commands::GetBoardEditorAppearanceSettings {};

        let response = self
            .send_command(envelope::pack_any(
                &command,
                CMD_GET_BOARD_EDITOR_APPEARANCE_SETTINGS,
            ))
            .await?;
        let payload: board_commands::BoardEditorAppearanceSettings =
            envelope::unpack_any(&response, RES_BOARD_EDITOR_APPEARANCE_SETTINGS)?;
        Ok(format!("{:#?}", payload))
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

fn layer_to_model(layer_id: i32) -> BoardLayerInfo {
    let name = board_types::BoardLayer::try_from(layer_id)
        .map(|layer| layer.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN_LAYER({layer_id})"));

    BoardLayerInfo { id: layer_id, name }
}

fn board_origin_kind_to_proto(kind: BoardOriginKind) -> i32 {
    match kind {
        BoardOriginKind::Grid => board_commands::BoardOriginType::BotGrid as i32,
        BoardOriginKind::Drill => board_commands::BoardOriginType::BotDrill as i32,
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

        return Ok(format!(
            "track id={id} start_nm={start} end_nm={end} width_nm={width} layer={layer} net={net}"
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Arc") {
        let arc = decode_any::<board_types::Arc>(item, "kiapi.board.types.Arc")?;
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
        return Ok(format!(
            "arc id={id} start_nm={start} mid_nm={mid} end_nm={end} width_nm={width} layer={layer} net={net}"
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Via") {
        let via = decode_any::<board_types::Via>(item, "kiapi.board.types.Via")?;
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
        return Ok(format!(
            "via id={id} pos_nm={position} type={via_type} net={net}"
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.FootprintInstance") {
        let fp = decode_any::<board_types::FootprintInstance>(
            item,
            "kiapi.board.types.FootprintInstance",
        )?;
        let id = fp.id.map_or_else(|| "-".to_string(), |id| id.value);
        let reference = fp
            .reference_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .unwrap_or_else(|| "-".to_string());
        let position = fp
            .position
            .map_or_else(|| "-".to_string(), |v| format!("{},{}", v.x_nm, v.y_nm));
        let orientation_deg = fp.orientation.map_or_else(
            || "-".to_string(),
            |orientation| orientation.value_degrees.to_string(),
        );
        let layer = layer_to_model(fp.layer).name;
        let pad_count = fp
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
        return Ok(format!(
            "footprint id={id} ref={reference} pos_nm={position} orientation_deg={orientation_deg} layer={layer} pad_count={pad_count}"
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Field") {
        let field = decode_any::<board_types::Field>(item, "kiapi.board.types.Field")?;
        let text = field
            .text
            .as_ref()
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .unwrap_or_else(|| "-".to_string());
        return Ok(format!(
            "field name={} visible={} text={}",
            field.name, field.visible, text
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardText") {
        let text = decode_any::<board_types::BoardText>(item, "kiapi.board.types.BoardText")?;
        let id = text.id.map_or_else(|| "-".to_string(), |id| id.value);
        let layer = layer_to_model(text.layer).name;
        let body = text
            .text
            .as_ref()
            .map(|value| value.text.clone())
            .unwrap_or_else(|| "-".to_string());
        return Ok(format!("text id={id} layer={layer} text={body}"));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardTextBox") {
        let textbox =
            decode_any::<board_types::BoardTextBox>(item, "kiapi.board.types.BoardTextBox")?;
        let id = textbox.id.map_or_else(|| "-".to_string(), |id| id.value);
        let layer = layer_to_model(textbox.layer).name;
        let body = textbox
            .textbox
            .as_ref()
            .map(|value| value.text.clone())
            .unwrap_or_else(|| "-".to_string());
        return Ok(format!("textbox id={id} layer={layer} text={body}"));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Pad") {
        let pad = decode_any::<board_types::Pad>(item, "kiapi.board.types.Pad")?;
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
        return Ok(format!(
            "pad id={id} number={} type={pad_type} pos_nm={position} net={net}",
            pad.number
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardGraphicShape") {
        let shape = decode_any::<board_types::BoardGraphicShape>(
            item,
            "kiapi.board.types.BoardGraphicShape",
        )?;
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
        return Ok(format!(
            "graphic id={id} layer={layer} net={net} geometry={geometry}"
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Zone") {
        let zone = decode_any::<board_types::Zone>(item, "kiapi.board.types.Zone")?;
        let id = zone.id.map_or_else(|| "-".to_string(), |id| id.value);
        let zone_type = board_types::ZoneType::try_from(zone.r#type)
            .map(|value| value.as_str_name().to_string())
            .unwrap_or_else(|_| format!("UNKNOWN({})", zone.r#type));
        return Ok(format!(
            "zone id={id} name={} type={} layer_count={} filled={} polygon_count={}",
            zone.name,
            zone_type,
            zone.layers.len(),
            zone.filled,
            zone.filled_polygons.len()
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Dimension") {
        let dimension = decode_any::<board_types::Dimension>(item, "kiapi.board.types.Dimension")?;
        let id = dimension.id.map_or_else(|| "-".to_string(), |id| id.value);
        let layer = layer_to_model(dimension.layer).name;
        let text = dimension
            .text
            .as_ref()
            .map(|value| value.text.clone())
            .unwrap_or_else(|| "-".to_string());
        let style = format!("{:?}", dimension.dimension_style);
        return Ok(format!(
            "dimension id={id} layer={layer} text={} style={style}",
            text
        ));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Group") {
        let group = decode_any::<board_types::Group>(item, "kiapi.board.types.Group")?;
        let id = group.id.map_or_else(|| "-".to_string(), |id| id.value);
        return Ok(format!(
            "group id={id} name={} item_count={}",
            group.name,
            group.items.len()
        ));
    }

    Ok(format!("unparsed payload ({} bytes)", item.value.len()))
}

fn any_to_pretty_debug(item: &prost_types::Any) -> Result<String, KiCadError> {
    if item.type_url == envelope::type_url("kiapi.board.types.Track") {
        let value = decode_any::<board_types::Track>(item, "kiapi.board.types.Track")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Arc") {
        let value = decode_any::<board_types::Arc>(item, "kiapi.board.types.Arc")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Via") {
        let value = decode_any::<board_types::Via>(item, "kiapi.board.types.Via")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.FootprintInstance") {
        let value = decode_any::<board_types::FootprintInstance>(
            item,
            "kiapi.board.types.FootprintInstance",
        )?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Pad") {
        let value = decode_any::<board_types::Pad>(item, "kiapi.board.types.Pad")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardGraphicShape") {
        let value = decode_any::<board_types::BoardGraphicShape>(
            item,
            "kiapi.board.types.BoardGraphicShape",
        )?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardText") {
        let value = decode_any::<board_types::BoardText>(item, "kiapi.board.types.BoardText")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.BoardTextBox") {
        let value =
            decode_any::<board_types::BoardTextBox>(item, "kiapi.board.types.BoardTextBox")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Field") {
        let value = decode_any::<board_types::Field>(item, "kiapi.board.types.Field")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Zone") {
        let value = decode_any::<board_types::Zone>(item, "kiapi.board.types.Zone")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Dimension") {
        let value = decode_any::<board_types::Dimension>(item, "kiapi.board.types.Dimension")?;
        return Ok(format!("{:#?}", value));
    }

    if item.type_url == envelope::type_url("kiapi.board.types.Group") {
        let value = decode_any::<board_types::Group>(item, "kiapi.board.types.Group")?;
        return Ok(format!("{:#?}", value));
    }

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
        any_to_pretty_debug, ensure_item_request_ok, layer_to_model, map_hit_test_result,
        map_item_bounding_boxes, model_document_to_proto, normalize_socket_uri,
        pad_netlist_from_footprint_items, select_single_board_document, select_single_project_path,
        selection_item_detail, summarize_item_details, summarize_selection, PCB_OBJECT_TYPES,
    };
    use crate::error::KiCadError;
    use crate::model::common::{DocumentSpecifier, DocumentType, ProjectInfo};
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
}
