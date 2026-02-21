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
mod kicad_api_version;
pub mod model;
pub mod transport;

#[cfg(feature = "blocking")]
pub mod blocking;

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
    ColorRgba, DrcSeverity, GraphicsDefaults, InactiveLayerDisplayMode, NetClassBoardSettings,
    NetClassForNetEntry, NetClassInfo, NetClassType, NetColorDisplayMode, PadNetEntry,
    PadShapeAsPolygonEntry, PadstackPresenceEntry, PadstackPresenceState, PcbArc,
    PcbBoardGraphicShape, PcbBoardText, PcbBoardTextBox, PcbDimension, PcbField, PcbFootprint,
    PcbGroup, PcbItem, PcbPad, PcbPadType, PcbTrack, PcbUnknownItem, PcbVia, PcbViaType, PcbZone,
    PcbZoneType, PolyLineNm, PolyLineNodeGeometryNm, PolygonWithHolesNm, RatsnestDisplayMode,
    Vector2Nm,
};
pub use crate::model::common::{
    CommitAction, CommitSession, DocumentSpecifier, DocumentType, EditorFrameType, ItemBoundingBox,
    ItemHitTestResult, MapMergeMode, PcbObjectTypeCode, RunActionStatus, SelectionItemDetail,
    SelectionSummary, SelectionTypeCount, TextAsShapesEntry, TextAttributesSpec, TextBoxSpec,
    TextExtents, TextHorizontalAlignment, TextObjectSpec, TextShape, TextShapeGeometry, TextSpec,
    TextVerticalAlignment, TitleBlockInfo, VersionInfo,
};
