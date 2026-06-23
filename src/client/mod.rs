mod board;
mod common;
mod decode;
mod document;
mod format;
mod geometry;
mod items;
mod mappers;
mod selection;

#[cfg(test)]
mod tests;

use self::mappers::*;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::envelope;
use crate::error::KiCadError;
use crate::model::common::*;
use crate::proto::kiapi::common::commands as common_commands;
use crate::proto::kiapi::common::types as common_types;
use crate::transport::Transport;

/// Sends a protobuf command and validates the response type URL.
///
/// This macro reduces boilerplate in the `_raw` RPC methods. It packs
/// the given command, sends it, and returns a validated `prost_types::Any`.
macro_rules! rpc {
    ($self:expr, $cmd_type_url:expr, $command:expr, $res_type_url:expr) => {{
        let response = $self
            .send_command(crate::envelope::pack_any(&$command, $cmd_type_url))
            .await?;
        super::mappers::response_payload_as_any(response, $res_type_url)
    }};
}

pub(crate) use rpc;

pub(crate) const KICAD_API_SOCKET_ENV: &str = "KICAD_API_SOCKET";
pub(crate) const KICAD_API_TOKEN_ENV: &str = "KICAD_API_TOKEN";
pub(crate) const KIPRJMOD_ENV: &str = "KIPRJMOD";
pub(crate) const CMD_PING: &str = "kiapi.common.commands.Ping";
pub(crate) const CMD_GET_VERSION: &str = "kiapi.common.commands.GetVersion";
pub(crate) const CMD_GET_KICAD_BINARY_PATH: &str = "kiapi.common.commands.GetKiCadBinaryPath";
pub(crate) const CMD_GET_PLUGIN_SETTINGS_PATH: &str = "kiapi.common.commands.GetPluginSettingsPath";
pub(crate) const CMD_GET_NET_CLASSES: &str = "kiapi.common.commands.GetNetClasses";
pub(crate) const CMD_SET_NET_CLASSES: &str = "kiapi.common.commands.SetNetClasses";
pub(crate) const CMD_GET_TEXT_VARIABLES: &str = "kiapi.common.commands.GetTextVariables";
pub(crate) const CMD_SET_TEXT_VARIABLES: &str = "kiapi.common.commands.SetTextVariables";
pub(crate) const CMD_EXPAND_TEXT_VARIABLES: &str = "kiapi.common.commands.ExpandTextVariables";
pub(crate) const CMD_GET_TEXT_EXTENTS: &str = "kiapi.common.commands.GetTextExtents";
pub(crate) const CMD_GET_TEXT_AS_SHAPES: &str = "kiapi.common.commands.GetTextAsShapes";
pub(crate) const CMD_REFRESH_EDITOR: &str = "kiapi.common.commands.RefreshEditor";
pub(crate) const CMD_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocuments";
pub(crate) const CMD_RUN_ACTION: &str = "kiapi.common.commands.RunAction";
pub(crate) const CMD_GET_NETS: &str = "kiapi.board.commands.GetNets";
pub(crate) const CMD_GET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.GetBoardEnabledLayers";
pub(crate) const CMD_SET_BOARD_ENABLED_LAYERS: &str = "kiapi.board.commands.SetBoardEnabledLayers";
pub(crate) const CMD_GET_ACTIVE_LAYER: &str = "kiapi.board.commands.GetActiveLayer";
pub(crate) const CMD_SET_ACTIVE_LAYER: &str = "kiapi.board.commands.SetActiveLayer";
pub(crate) const CMD_GET_VISIBLE_LAYERS: &str = "kiapi.board.commands.GetVisibleLayers";
pub(crate) const CMD_SET_VISIBLE_LAYERS: &str = "kiapi.board.commands.SetVisibleLayers";
pub(crate) const CMD_GET_BOARD_LAYER_NAME: &str = "kiapi.board.commands.GetBoardLayerName";
pub(crate) const CMD_GET_BOARD_ORIGIN: &str = "kiapi.board.commands.GetBoardOrigin";
pub(crate) const CMD_SET_BOARD_ORIGIN: &str = "kiapi.board.commands.SetBoardOrigin";
pub(crate) const CMD_GET_BOARD_STACKUP: &str = "kiapi.board.commands.GetBoardStackup";
pub(crate) const CMD_UPDATE_BOARD_STACKUP: &str = "kiapi.board.commands.UpdateBoardStackup";
pub(crate) const CMD_GET_GRAPHICS_DEFAULTS: &str = "kiapi.board.commands.GetGraphicsDefaults";
pub(crate) const CMD_GET_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.GetBoardEditorAppearanceSettings";
pub(crate) const CMD_SET_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.SetBoardEditorAppearanceSettings";
pub(crate) const CMD_INTERACTIVE_MOVE_ITEMS: &str = "kiapi.board.commands.InteractiveMoveItems";
pub(crate) const CMD_GET_ITEMS_BY_NET: &str = "kiapi.board.commands.GetItemsByNet";
pub(crate) const CMD_GET_ITEMS_BY_NET_CLASS: &str = "kiapi.board.commands.GetItemsByNetClass";
pub(crate) const CMD_GET_CONNECTED_ITEMS: &str = "kiapi.board.commands.GetConnectedItems";
pub(crate) const CMD_GET_NETCLASS_FOR_NETS: &str = "kiapi.board.commands.GetNetClassForNets";
pub(crate) const CMD_REFILL_ZONES: &str = "kiapi.board.commands.RefillZones";
pub(crate) const CMD_GET_PAD_SHAPE_AS_POLYGON: &str = "kiapi.board.commands.GetPadShapeAsPolygon";
pub(crate) const CMD_CHECK_PADSTACK_PRESENCE_ON_LAYERS: &str =
    "kiapi.board.commands.CheckPadstackPresenceOnLayers";
pub(crate) const CMD_INJECT_DRC_ERROR: &str = "kiapi.board.commands.InjectDrcError";
pub(crate) const CMD_GET_SELECTION: &str = "kiapi.common.commands.GetSelection";
pub(crate) const CMD_ADD_TO_SELECTION: &str = "kiapi.common.commands.AddToSelection";
pub(crate) const CMD_REMOVE_FROM_SELECTION: &str = "kiapi.common.commands.RemoveFromSelection";
pub(crate) const CMD_CLEAR_SELECTION: &str = "kiapi.common.commands.ClearSelection";
pub(crate) const CMD_BEGIN_COMMIT: &str = "kiapi.common.commands.BeginCommit";
pub(crate) const CMD_END_COMMIT: &str = "kiapi.common.commands.EndCommit";
pub(crate) const CMD_CREATE_ITEMS: &str = "kiapi.common.commands.CreateItems";
pub(crate) const CMD_UPDATE_ITEMS: &str = "kiapi.common.commands.UpdateItems";
pub(crate) const CMD_DELETE_ITEMS: &str = "kiapi.common.commands.DeleteItems";
pub(crate) const CMD_PARSE_AND_CREATE_ITEMS_FROM_STRING: &str =
    "kiapi.common.commands.ParseAndCreateItemsFromString";
pub(crate) const CMD_GET_ITEMS: &str = "kiapi.common.commands.GetItems";
pub(crate) const CMD_GET_ITEMS_BY_ID: &str = "kiapi.common.commands.GetItemsById";
pub(crate) const CMD_GET_BOUNDING_BOX: &str = "kiapi.common.commands.GetBoundingBox";
pub(crate) const CMD_HIT_TEST: &str = "kiapi.common.commands.HitTest";
pub(crate) const CMD_GET_TITLE_BLOCK_INFO: &str = "kiapi.common.commands.GetTitleBlockInfo";
pub(crate) const CMD_SET_TITLE_BLOCK_INFO: &str = "kiapi.common.commands.SetTitleBlockInfo";
pub(crate) const CMD_SAVE_DOCUMENT: &str = "kiapi.common.commands.SaveDocument";
pub(crate) const CMD_SAVE_COPY_OF_DOCUMENT: &str = "kiapi.common.commands.SaveCopyOfDocument";
pub(crate) const CMD_REVERT_DOCUMENT: &str = "kiapi.common.commands.RevertDocument";
pub(crate) const CMD_SAVE_DOCUMENT_TO_STRING: &str = "kiapi.common.commands.SaveDocumentToString";
pub(crate) const CMD_SAVE_SELECTION_TO_STRING: &str = "kiapi.common.commands.SaveSelectionToString";

pub(crate) const RES_GET_VERSION: &str = "kiapi.common.commands.GetVersionResponse";
pub(crate) const RES_PATH_RESPONSE: &str = "kiapi.common.commands.PathResponse";
pub(crate) const RES_STRING_RESPONSE: &str = "kiapi.common.commands.StringResponse";
pub(crate) const RES_NET_CLASSES_RESPONSE: &str = "kiapi.common.commands.NetClassesResponse";
pub(crate) const RES_TEXT_VARIABLES: &str = "kiapi.common.project.TextVariables";
pub(crate) const RES_EXPAND_TEXT_VARIABLES_RESPONSE: &str =
    "kiapi.common.commands.ExpandTextVariablesResponse";
pub(crate) const RES_BOX2: &str = "kiapi.common.types.Box2";
pub(crate) const RES_GET_TEXT_AS_SHAPES_RESPONSE: &str =
    "kiapi.common.commands.GetTextAsShapesResponse";
pub(crate) const RES_GET_OPEN_DOCUMENTS: &str = "kiapi.common.commands.GetOpenDocumentsResponse";
pub(crate) const RES_RUN_ACTION_RESPONSE: &str = "kiapi.common.commands.RunActionResponse";
pub(crate) const RES_GET_NETS: &str = "kiapi.board.commands.NetsResponse";
pub(crate) const RES_GET_BOARD_ENABLED_LAYERS: &str =
    "kiapi.board.commands.BoardEnabledLayersResponse";
pub(crate) const RES_BOARD_LAYER_RESPONSE: &str = "kiapi.board.commands.BoardLayerResponse";
pub(crate) const RES_BOARD_LAYERS: &str = "kiapi.board.commands.BoardLayers";
pub(crate) const RES_BOARD_LAYER_NAME_RESPONSE: &str =
    "kiapi.board.commands.BoardLayerNameResponse";
pub(crate) const RES_BOARD_STACKUP_RESPONSE: &str = "kiapi.board.commands.BoardStackupResponse";
pub(crate) const RES_GRAPHICS_DEFAULTS_RESPONSE: &str =
    "kiapi.board.commands.GraphicsDefaultsResponse";
pub(crate) const RES_BOARD_EDITOR_APPEARANCE_SETTINGS: &str =
    "kiapi.board.commands.BoardEditorAppearanceSettings";
pub(crate) const RES_NETCLASS_FOR_NETS_RESPONSE: &str =
    "kiapi.board.commands.NetClassForNetsResponse";
pub(crate) const RES_PAD_SHAPE_AS_POLYGON_RESPONSE: &str =
    "kiapi.board.commands.PadShapeAsPolygonResponse";
pub(crate) const RES_PADSTACK_PRESENCE_RESPONSE: &str =
    "kiapi.board.commands.PadstackPresenceResponse";
pub(crate) const RES_INJECT_DRC_ERROR_RESPONSE: &str =
    "kiapi.board.commands.InjectDrcErrorResponse";
pub(crate) const RES_VECTOR2: &str = "kiapi.common.types.Vector2";
pub(crate) const RES_SELECTION_RESPONSE: &str = "kiapi.common.commands.SelectionResponse";
pub(crate) const RES_BEGIN_COMMIT_RESPONSE: &str = "kiapi.common.commands.BeginCommitResponse";
pub(crate) const RES_END_COMMIT_RESPONSE: &str = "kiapi.common.commands.EndCommitResponse";
pub(crate) const RES_CREATE_ITEMS_RESPONSE: &str = "kiapi.common.commands.CreateItemsResponse";
pub(crate) const RES_UPDATE_ITEMS_RESPONSE: &str = "kiapi.common.commands.UpdateItemsResponse";
pub(crate) const RES_DELETE_ITEMS_RESPONSE: &str = "kiapi.common.commands.DeleteItemsResponse";
pub(crate) const RES_GET_ITEMS_RESPONSE: &str = "kiapi.common.commands.GetItemsResponse";
pub(crate) const RES_GET_BOUNDING_BOX_RESPONSE: &str =
    "kiapi.common.commands.GetBoundingBoxResponse";
pub(crate) const RES_HIT_TEST_RESPONSE: &str = "kiapi.common.commands.HitTestResponse";
pub(crate) const RES_TITLE_BLOCK_INFO: &str = "kiapi.common.types.TitleBlockInfo";
pub(crate) const RES_SAVED_DOCUMENT_RESPONSE: &str = "kiapi.common.commands.SavedDocumentResponse";
pub(crate) const RES_SAVED_SELECTION_RESPONSE: &str =
    "kiapi.common.commands.SavedSelectionResponse";
pub(crate) const RES_PROTOBUF_EMPTY: &str = "google.protobuf.Empty";

pub(crate) const PAD_QUERY_CHUNK_SIZE: usize = 256;

pub(crate) static PCB_OBJECT_TYPES: [PcbObjectTypeCode; 18] = [
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
/// Async IPC client for communicating with a running KiCad instance.
///
/// Create with [`KiCadClient::connect`] for defaults or [`KiCadClient::builder`]
/// to override socket path, timeout, token, or client name.
pub struct KiCadClient {
    inner: Arc<ClientInner>,
}

#[derive(Debug)]
pub(crate) struct ClientInner {
    pub(crate) transport: Transport,
    pub(crate) token: Mutex<String>,
    pub(crate) client_name: String,
    pub(crate) timeout: Duration,
    pub(crate) socket_uri: String,
}

#[derive(Clone, Debug)]
struct ClientConfig {
    timeout: Duration,
    socket_uri: Option<String>,
    token: Option<String>,
    client_name: Option<String>,
}

#[derive(Clone, Debug)]
/// Builder for [`KiCadClient`].
///
/// Defaults:
/// - timeout: `3s`
/// - socket path: `KICAD_API_SOCKET` env var, then platform default
/// - token: `KICAD_API_TOKEN` env var, then empty
/// - client name: autogenerated
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    /// Creates a builder with sensible defaults for local KiCad IPC usage.
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

    /// Sets per-request timeout used by the IPC transport.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Sets explicit KiCad IPC socket URI/path.
    ///
    /// If unset, the builder resolves from environment/defaults.
    pub fn socket_path(mut self, socket_path: impl Into<String>) -> Self {
        self.config.socket_uri = Some(socket_path.into());
        self
    }

    /// Sets the IPC authentication token.
    ///
    /// If unset, the builder uses `KICAD_API_TOKEN` when present.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.config.token = Some(token.into());
        self
    }

    /// Sets the client name reported to KiCad.
    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.config.client_name = Some(client_name.into());
        self
    }

    /// Connects to KiCad IPC with the configured options.
    ///
    /// # Errors
    /// Returns [`KiCadError`] when socket discovery, connection, or transport
    /// initialization fails.
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
    /// Returns a configurable builder for creating a [`KiCadClient`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Connects with default builder settings.
    pub async fn connect() -> Result<Self, KiCadError> {
        ClientBuilder::new().connect().await
    }

    /// Returns the per-request timeout configured for this client.
    pub fn timeout(&self) -> Duration {
        self.inner.timeout
    }

    /// Returns the IPC socket URI/path used by this client.
    pub fn socket_uri(&self) -> &str {
        &self.inner.socket_uri
    }

    /// Sends a raw protobuf `Any` command and returns the raw response payload.
    ///
    /// This is an escape hatch for commands not yet wrapped by typed methods.
    pub async fn send_raw_command(
        &self,
        command: prost_types::Any,
    ) -> Result<prost_types::Any, KiCadError> {
        let command_type_url = command.type_url.clone();
        let response = self.send_command(command).await?;
        response.message.ok_or(KiCadError::MissingPayload {
            expected_type_url: format!("response payload for `{command_type_url}`"),
        })
    }

    pub(crate) async fn send_command(
        &self,
        command: prost_types::Any,
    ) -> Result<crate::proto::kiapi::common::ApiResponse, KiCadError> {
        let command_type_url = command.type_url.clone();
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
            return Err(match err {
                KiCadError::ApiStatus { code, message } => KiCadError::ApiStatus {
                    code,
                    message: if message.is_empty() {
                        format!("command `{command_type_url}` failed")
                    } else {
                        format!("{message} (command `{command_type_url}`)")
                    },
                },
                other => other,
            });
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

    pub(crate) async fn current_board_document_proto(
        &self,
    ) -> Result<common_types::DocumentSpecifier, KiCadError> {
        let docs = self.get_open_documents(DocumentType::Pcb).await?;
        let selected = select_single_board_document(&docs)?;
        Ok(model_document_to_proto(selected))
    }

    pub(crate) async fn current_board_item_header(
        &self,
    ) -> Result<common_types::ItemHeader, KiCadError> {
        Ok(common_types::ItemHeader {
            document: Some(self.current_board_document_proto().await?),
            container: None,
            field_mask: None,
        })
    }

    pub(crate) async fn get_items_raw(
        &self,
        types: Vec<i32>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
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

pub(crate) fn map_document_specifier(
    source: common_types::DocumentSpecifier,
) -> Option<DocumentSpecifier> {
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

pub(crate) fn select_single_board_document(
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

pub(crate) fn select_single_project_path(
    docs: &[DocumentSpecifier],
) -> Result<PathBuf, KiCadError> {
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

pub(crate) fn resolve_current_project_path(
    docs_result: Result<Vec<DocumentSpecifier>, KiCadError>,
) -> Result<PathBuf, KiCadError> {
    match docs_result {
        Ok(docs) => select_single_project_path(&docs),
        Err(err) if is_get_open_documents_unhandled(&err) => {
            project_path_from_environment().ok_or(err)
        }
        Err(err) => Err(err),
    }
}

fn project_path_from_environment() -> Option<PathBuf> {
    let value = std::env::var(KIPRJMOD_ENV).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(PathBuf::from(trimmed))
}

pub(crate) fn is_get_open_documents_unhandled(err: &KiCadError) -> bool {
    matches!(
        err,
        KiCadError::ApiStatus { code, .. } if code == "AS_UNHANDLED"
    )
}

pub(crate) fn is_get_items_by_id_unhandled(err: &KiCadError) -> bool {
    matches!(
        err,
        KiCadError::ApiStatus { code, .. } if code == "AS_UNHANDLED"
    )
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

pub(crate) fn normalize_socket_uri(socket: &str) -> String {
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
        #[cfg(target_os = "windows")]
        {
            // On Windows, nng's ipc:// transport uses named pipes, not filesystem
            // sockets. A path.exists() check is always false even when KiCad is
            // running. Instead, probe the named pipe directly: a successful open
            // or ERROR_PIPE_BUSY (231) both mean a server is listening.
            let pipe_path = format!(r"\\.\pipe\{}", path.display());
            return match std::fs::OpenOptions::new().read(true).open(&pipe_path) {
                Ok(_) => false,
                Err(e) => e.raw_os_error() != Some(231),
            };
        }

        #[cfg(not(target_os = "windows"))]
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
