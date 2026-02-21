use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KiCadError {
    #[error("invalid configuration: {reason}")]
    Config { reason: String },

    #[error("KiCad IPC socket not available at `{socket_uri}`. Open KiCad and open a project/board first.")]
    SocketUnavailable { socket_uri: String },

    #[error("connection failed for `{socket_uri}`: {reason}")]
    Connection { socket_uri: String, reason: String },

    #[error("transport send failed: {reason}")]
    TransportSend { reason: String },

    #[error("transport receive failed: {reason}")]
    TransportReceive { reason: String },

    #[error("transport task is unavailable")]
    TransportClosed,

    #[error("request timed out after {timeout:?}")]
    Timeout { timeout: Duration },

    #[error("API status error `{code}`: {message}")]
    ApiStatus { code: String, message: String },

    #[error("item request status error `{code}`")]
    ItemStatus { code: String },

    #[error("invalid API response: {reason}")]
    InvalidResponse { reason: String },

    #[error("API response missing payload for `{expected_type_url}`")]
    MissingPayload { expected_type_url: String },

    #[error("unexpected payload type; expected `{expected_type_url}`, got `{actual_type_url}`")]
    UnexpectedPayloadType {
        expected_type_url: String,
        actual_type_url: String,
    },

    #[error("protobuf encode failed: {0}")]
    ProtobufEncode(String),

    #[error("protobuf decode failed: {0}")]
    ProtobufDecode(String),

    #[error("runtime task join failed: {0}")]
    RuntimeJoin(String),

    #[error("blocking runtime is unavailable")]
    BlockingRuntimeClosed,

    #[error("mutex poisoned")]
    InternalPoisoned,

    #[error("no open PCB document found; open a board in KiCad first")]
    BoardNotOpen,

    #[error("multiple project paths found across open PCB docs: {paths:?}")]
    AmbiguousProjectPath { paths: Vec<String> },

    #[error("multiple PCB documents are open; unable to choose one board context: {boards:?}")]
    AmbiguousBoardSelection { boards: Vec<String> },
}
