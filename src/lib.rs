//! # KiCad IPC RS
//!
//! **Async-first, pure-Rust IPC bindings for KiCad's official API.**
//! Production-focused Rust API surface, typed models, and a blocking wrapper for sync callers.
//!
//! ## Why this crate?
//!
//! | Capability | `kicad-ipc-rs` | Official Python bindings (`kicad-python`) | Official Rust bindings (`kicad-rs`) |
//! | --- | --- | --- | --- |
//! | Rust-native client API | ✅ Yes | ❌ Python package | ⚠️ Development preview |
//! | Async-first API design | ✅ `KiCadClient` | ⚠️ App-managed event-loop model | ⚠️ Development preview |
//! | Blocking support for sync apps | ✅ `feature = "blocking"` | ✅ Native Python sync usage | ⚠️ Development preview |
//! | Wrapped KiCad command coverage (current proto snapshot) | ✅ 59/59 command wrappers | Unknown | Unknown |
//! | Maintainer focus | ✅ This crate is actively maintained for Rust users | ✅ Official KiCad Python package | ⚠️ Preview status |
//!
//! Evidence and references:
//! - `kicad-python` package: <https://gitlab.com/kicad/code/kicad-python>
//! - `kicad-rs` package (states "development preview with no docs yet"): <https://gitlab.com/kicad/code/kicad-rs>
//! - Coverage matrix and runtime notes: <https://github.com/Milind220/kicad-ipc-rs#kicad-v1001-api-reference>
//!
//! ## Quickstart (async)
//! ```no_run
//! use kicad_ipc_rs::KiCadClient;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), kicad_ipc_rs::KiCadError> {
//!     let client = KiCadClient::connect().await?;
//!     client.ping().await?;
//!     let version = client.get_version().await?;
//!     println!("KiCad: {}", version.full_version);
//!     Ok(())
//! }
//! ```
//!
//! ## Quickstart (blocking)
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # fn run() -> Result<(), kicad_ipc_rs::KiCadError> {
//! use kicad_ipc_rs::KiCadClientBlocking;
//! let client = KiCadClientBlocking::connect()?;
//! let version = client.get_version()?;
//! println!("KiCad: {}", version.full_version);
//! # Ok(())
//! # }
//! ```
//!
//! Architecture layers:
//! - transport
//! - envelope
//! - command builders
//! - high-level client
//!
//! PCB item modeling layers:
//! - **raw IPC**: [`prost_types::Any`] envelopes carrying KiCad protobuf payloads
//! - **read model**: [`PcbItem`] typed enums for inspection-oriented reads
//! - **editable model**: [`EditablePcbItem`] typed wrappers for mutate/update flows
//!
//! For editable mutate/update item flows, see the README section
//! "Making Changes to PCBs" for a short end-to-end example.
#![warn(missing_docs)]
/// High-level async client and request/response convenience methods.
#[allow(clippy::module_inception)]
pub mod client;
/// Low-level command payload builders.
///
/// This module is public for advanced integrations and debugging, but most users
/// should prefer [`crate::client::KiCadClient`] methods.
#[allow(missing_docs)]
pub mod commands;
/// Envelope helpers for command/response packing and unpacking.
///
/// This is primarily an advanced/internal surface.
#[allow(missing_docs)]
pub mod envelope;
/// Error types returned by this crate.
#[allow(missing_docs)]
pub mod error;
mod kicad_api_version;
/// Stable data models used by typed client APIs.
#[allow(missing_docs)]
pub mod model;
/// IPC transport implementation details.
///
/// Most applications should not need to use this module directly.
#[allow(missing_docs)]
pub mod transport;

#[cfg(feature = "blocking")]
/// Blocking wrapper over the async client.
pub mod blocking;

pub(crate) mod pcb_item_type_urls;
pub(crate) mod proto;
#[cfg(feature = "blocking")]
pub use crate::blocking::{KiCadClientBlocking, KiCadClientBlockingBuilder};
pub use crate::client::{ClientBuilder, KiCadClient};
pub use crate::error::KiCadError;
pub use crate::kicad_api_version::KICAD_API_VERSION;
pub use crate::model::board::{
    ArcStartMidEndNm, BoardEditorAppearanceSettings, BoardEnabledLayers, BoardFlipMode,
    BoardLayerClass, BoardLayerGraphicsDefault, BoardLayerInfo, BoardNet, BoardOriginKind,
    BoardStackup, BoardStackupDielectricProperties, BoardStackupLayer, BoardStackupLayerType,
    BoardTextSpec, ColorRgba, DrcSeverity, GraphicsDefaults, InactiveLayerDisplayMode,
    ItemLockState, NetClassBoardSettings, NetClassForNetEntry, NetClassInfo, NetClassType,
    NetColorDisplayMode, PadNetEntry, PadShapeAsPolygonEntry, PadstackPresenceEntry,
    PadstackPresenceState, PcbArc, PcbBarcode, PcbBarcodeErrorCorrection, PcbBarcodeKind,
    PcbBoardGraphicShape, PcbBoardText, PcbBoardTextBox, PcbDimension, PcbDimensionStyle, PcbField,
    PcbFootprintInstance, PcbFootprintSymbolLink, PcbGraphicShapeGeometry, PcbGroup, PcbItem,
    PcbPad, PcbPadStack, PcbPadType, PcbPadstackDrill, PcbReferenceImage, PcbSymbolPinInfo,
    PcbTextAttributes, PcbTrack, PcbUnknownItem, PcbVia, PcbViaLayers, PcbViaType, PcbZone,
    PcbZoneLayerProperty, PcbZoneType, PolyLineNm, PolyLineNodeGeometryNm, PolygonWithHolesNm,
    RatsnestDisplayMode, Vector2Nm,
};
pub use crate::model::common::{
    CommitAction, CommitSession, DocumentSpecifier, DocumentType, EditorFrameType, ItemBoundingBox,
    ItemHitTestResult, MapMergeMode, PcbObjectTypeCode, RunActionStatus, SelectionItemDetail,
    SelectionMutationResult, SelectionStringDump, SelectionSummary, SelectionTypeCount,
    TextAsShapesEntry, TextAttributesSpec, TextBoxSpec, TextExtents, TextHorizontalAlignment,
    TextObjectSpec, TextShape, TextShapeGeometry, TextSpec, TextVerticalAlignment, TitleBlockInfo,
    VersionInfo,
};
pub use crate::model::editable::*;
