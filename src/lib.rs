//! Async-first Rust bindings for the KiCad IPC API.
//!
//! Layering:
//! - transport
//! - envelope
//! - command builders
//! - high-level client

pub mod client;
pub mod commands;
pub mod envelope;
pub mod error;
pub mod model;
pub mod transport;

#[cfg(feature = "blocking")]
pub mod blocking;

pub(crate) mod proto;

pub use crate::client::{ClientBuilder, KiCadClient};
pub use crate::error::KiCadError;
pub use crate::model::board::{
    BoardEnabledLayers, BoardLayerInfo, BoardNet, BoardOriginKind, PadNetEntry, Vector2Nm,
};
pub use crate::model::common::{
    DocumentSpecifier, DocumentType, ItemBoundingBox, ItemHitTestResult, SelectionItemDetail,
    SelectionSummary, SelectionTypeCount, VersionInfo,
};
