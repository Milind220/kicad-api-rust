use std::path::PathBuf;
use std::str::FromStr;

use crate::model::board::{ColorRgba, PcbItem, PolygonWithHolesNm, Vector2Nm};
use crate::proto::kiapi::common::types as common_types;

#[derive(Clone, Debug, Eq, PartialEq)]
/// KiCad semantic version returned by `GetVersion`.
pub struct VersionInfo {
    /// Major version component.
    pub major: u32,
    /// Minor version component.
    pub minor: u32,
    /// Patch version component.
    pub patch: u32,
    /// Full KiCad version string (includes prerelease/build details).
    pub full_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// KiCad top-level frame/editor targets used by API commands.
pub enum EditorFrameType {
    /// KiCad project manager frame.
    ProjectManager,
    /// Schematic editor frame.
    SchematicEditor,
    /// PCB editor frame.
    PcbEditor,
    /// Spice simulator frame.
    SpiceSimulator,
    /// Symbol editor frame.
    SymbolEditor,
    /// Footprint editor frame.
    FootprintEditor,
    /// Drawing-sheet editor frame.
    DrawingSheetEditor,
}

impl EditorFrameType {
    pub(crate) fn to_proto(self) -> i32 {
        match self {
            Self::ProjectManager => common_types::FrameType::FtProjectManager as i32,
            Self::SchematicEditor => common_types::FrameType::FtSchematicEditor as i32,
            Self::PcbEditor => common_types::FrameType::FtPcbEditor as i32,
            Self::SpiceSimulator => common_types::FrameType::FtSpiceSimulator as i32,
            Self::SymbolEditor => common_types::FrameType::FtSymbolEditor as i32,
            Self::FootprintEditor => common_types::FrameType::FtFootprintEditor as i32,
            Self::DrawingSheetEditor => common_types::FrameType::FtDrawingSheetEditor as i32,
        }
    }
}

impl std::fmt::Display for EditorFrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ProjectManager => "project-manager",
            Self::SchematicEditor => "schematic",
            Self::PcbEditor => "pcb",
            Self::SpiceSimulator => "spice",
            Self::SymbolEditor => "symbol",
            Self::FootprintEditor => "footprint",
            Self::DrawingSheetEditor => "drawing-sheet",
        };
        write!(f, "{value}")
    }
}

impl FromStr for EditorFrameType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "project-manager" => Ok(Self::ProjectManager),
            "schematic" => Ok(Self::SchematicEditor),
            "pcb" => Ok(Self::PcbEditor),
            "spice" => Ok(Self::SpiceSimulator),
            "symbol" => Ok(Self::SymbolEditor),
            "footprint" => Ok(Self::FootprintEditor),
            "drawing-sheet" => Ok(Self::DrawingSheetEditor),
            _ => Err(format!(
                "unknown frame `{value}`; expected one of: project-manager, schematic, pcb, spice, symbol, footprint, drawing-sheet"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// KiCad document type selector used by document-scoped APIs.
pub enum DocumentType {
    /// Schematic document.
    Schematic,
    /// Symbol document.
    Symbol,
    /// PCB document.
    Pcb,
    /// Footprint document.
    Footprint,
    /// Drawing-sheet document.
    DrawingSheet,
    /// Project-level document.
    Project,
}

impl DocumentType {
    pub(crate) fn to_proto(self) -> i32 {
        match self {
            Self::Schematic => common_types::DocumentType::DoctypeSchematic as i32,
            Self::Symbol => common_types::DocumentType::DoctypeSymbol as i32,
            Self::Pcb => common_types::DocumentType::DoctypePcb as i32,
            Self::Footprint => common_types::DocumentType::DoctypeFootprint as i32,
            Self::DrawingSheet => common_types::DocumentType::DoctypeDrawingSheet as i32,
            Self::Project => common_types::DocumentType::DoctypeProject as i32,
        }
    }

    pub(crate) fn from_proto(value: i32) -> Option<Self> {
        let ty = common_types::DocumentType::try_from(value).ok()?;
        match ty {
            common_types::DocumentType::DoctypeSchematic => Some(Self::Schematic),
            common_types::DocumentType::DoctypeSymbol => Some(Self::Symbol),
            common_types::DocumentType::DoctypePcb => Some(Self::Pcb),
            common_types::DocumentType::DoctypeFootprint => Some(Self::Footprint),
            common_types::DocumentType::DoctypeDrawingSheet => Some(Self::DrawingSheet),
            common_types::DocumentType::DoctypeProject => Some(Self::Project),
            common_types::DocumentType::DoctypeUnknown => None,
        }
    }
}

impl std::fmt::Display for DocumentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Schematic => "schematic",
            Self::Symbol => "symbol",
            Self::Pcb => "pcb",
            Self::Footprint => "footprint",
            Self::DrawingSheet => "drawing-sheet",
            Self::Project => "project",
        };

        write!(f, "{value}")
    }
}

impl FromStr for DocumentType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "schematic" => Ok(Self::Schematic),
            "symbol" => Ok(Self::Symbol),
            "pcb" => Ok(Self::Pcb),
            "footprint" => Ok(Self::Footprint),
            "drawing-sheet" => Ok(Self::DrawingSheet),
            "project" => Ok(Self::Project),
            _ => Err(format!(
                "unknown document type `{value}`; expected one of: schematic, symbol, pcb, footprint, drawing-sheet, project"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Minimal project information attached to open-document responses.
pub struct ProjectInfo {
    /// Project display name, if provided by KiCad.
    pub name: Option<String>,
    /// Project filesystem path, if available.
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Descriptor for an open KiCad document.
pub struct DocumentSpecifier {
    /// KiCad document type.
    pub document_type: DocumentType,
    /// Board filename when relevant.
    pub board_filename: Option<String>,
    /// Owning project metadata.
    pub project: ProjectInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Count of selected items for a specific protobuf type URL.
pub struct SelectionTypeCount {
    /// Protobuf type URL for the selected item type.
    pub type_url: String,
    /// Number of selected items of this type.
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Summary of current selection composition.
pub struct SelectionSummary {
    /// Total selected item count.
    pub total_items: usize,
    /// Per-type counts by protobuf type URL.
    pub type_url_counts: Vec<SelectionTypeCount>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Human/debug-friendly selection entry detail.
pub struct SelectionItemDetail {
    /// Protobuf type URL.
    pub type_url: String,
    /// Decoded/debug string detail.
    pub detail: String,
    /// Raw payload length in bytes.
    pub raw_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Selection dump returned by `get_selection_as_string`.
pub struct SelectionStringDump {
    /// Ordered ids included in the serialized selection payload.
    pub ids: Vec<String>,
    /// Selection serialized as KiCad s-expression text.
    pub contents: String,
}

#[derive(Clone, Debug, PartialEq)]
/// Result of add/remove/clear selection mutations.
pub struct SelectionMutationResult {
    /// Decoded selected items after mutation.
    pub items: Vec<PcbItem>,
    /// Compact composition summary for the same selection state.
    pub summary: SelectionSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Opaque commit session identifier returned by `begin_commit`.
pub struct CommitSession {
    /// KiCad commit session id.
    pub id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Final action to apply when ending a commit session.
pub enum CommitAction {
    /// Persist commit changes.
    Commit,
    /// Discard commit changes.
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Status result returned by `run_action`.
pub enum RunActionStatus {
    /// Action succeeded.
    Ok,
    /// Action name or payload was invalid.
    Invalid,
    /// Target editor frame was not open.
    FrameNotOpen,
    /// Unrecognized status code from KiCad.
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Merge strategy for map-like update APIs.
pub enum MapMergeMode {
    /// Merge provided entries into existing map.
    Merge,
    /// Replace existing map with provided entries.
    Replace,
}

impl std::fmt::Display for MapMergeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Merge => write!(f, "merge"),
            Self::Replace => write!(f, "replace"),
        }
    }
}

impl FromStr for MapMergeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "merge" => Ok(Self::Merge),
            "replace" => Ok(Self::Replace),
            _ => Err(format!(
                "unknown merge mode `{value}`; expected `merge` or `replace`"
            )),
        }
    }
}

impl std::fmt::Display for CommitAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Commit => write!(f, "commit"),
            Self::Drop => write!(f, "drop"),
        }
    }
}

impl FromStr for CommitAction {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "commit" => Ok(Self::Commit),
            "drop" => Ok(Self::Drop),
            _ => Err(format!(
                "unknown commit action `{value}`; expected `commit` or `drop`"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Title block fields from the active document.
pub struct TitleBlockInfo {
    /// Title block title.
    pub title: String,
    /// Title block date.
    pub date: String,
    /// Revision string.
    pub revision: String,
    /// Company field.
    pub company: String,
    /// Comment slot values in `comment1..comment9` order.
    ///
    /// Internal empty gaps are preserved (`["A", "", "C"]` maps to
    /// comment1/comment2/comment3), while trailing empty slots may be trimmed
    /// from this public vector representation.
    pub comments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemBoundingBox {
    pub item_id: String,
    pub x_nm: i64,
    pub y_nm: i64,
    pub width_nm: i64,
    pub height_nm: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemHitTestResult {
    Unknown,
    NoHit,
    Hit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcbObjectTypeCode {
    pub code: i32,
    pub name: &'static str,
}

impl PcbObjectTypeCode {
    /// Creates the KiCad object type code for PCB footprints.
    pub const fn new_footprint_instance() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbFootprint as i32,
            name: "KOT_PCB_FOOTPRINT",
        }
    }

    /// Creates the KiCad object type code for PCB pads.
    pub const fn new_pad() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbPad as i32,
            name: "KOT_PCB_PAD",
        }
    }

    /// Creates the KiCad object type code for PCB graphic shapes.
    pub const fn new_shape() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbShape as i32,
            name: "KOT_PCB_SHAPE",
        }
    }

    /// Creates the KiCad object type code for PCB text.
    pub const fn new_text() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbText as i32,
            name: "KOT_PCB_TEXT",
        }
    }

    /// Creates the KiCad object type code for PCB text boxes.
    pub const fn new_textbox() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbTextbox as i32,
            name: "KOT_PCB_TEXTBOX",
        }
    }

    /// Creates the KiCad object type code for PCB tracks/traces.
    pub const fn new_trace() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbTrace as i32,
            name: "KOT_PCB_TRACE",
        }
    }

    /// Creates the KiCad object type code for PCB vias.
    pub const fn new_via() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbVia as i32,
            name: "KOT_PCB_VIA",
        }
    }

    /// Creates the KiCad object type code for PCB arcs.
    pub const fn new_arc() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbArc as i32,
            name: "KOT_PCB_ARC",
        }
    }

    /// Creates the KiCad object type code for PCB dimensions.
    pub const fn new_dimension() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbDimension as i32,
            name: "KOT_PCB_DIMENSION",
        }
    }

    /// Creates the KiCad object type code for PCB zones.
    pub const fn new_zone() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbZone as i32,
            name: "KOT_PCB_ZONE",
        }
    }

    /// Creates the KiCad object type code for PCB groups.
    pub const fn new_group() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbGroup as i32,
            name: "KOT_PCB_GROUP",
        }
    }

    /// Creates the KiCad object type code for PCB barcodes.
    pub const fn new_barcode() -> Self {
        Self {
            code: common_types::KiCadObjectType::KotPcbBarcode as i32,
            name: "KOT_PCB_BARCODE",
        }
    }

    /// Resolves a PCB object type code from its numeric KiCad enum value.
    pub fn from_code(code: i32) -> Option<Self> {
        let kind = common_types::KiCadObjectType::try_from(code).ok()?;
        let name = kind.as_str_name();
        name.starts_with("KOT_PCB_").then_some(Self { code, name })
    }

    /// Resolves a PCB object type from a proto enum name or friendly name.
    ///
    /// Accepts values like `KOT_PCB_TRACE`, `trace`, `track`, `footprint`,
    /// `text`, and `silkscreen-text` where applicable.
    pub fn from_name(value: &str) -> Option<Self> {
        let normalized = value
            .trim()
            .trim_start_matches("KOT_PCB_")
            .replace(['-', ' '], "_")
            .to_ascii_uppercase();

        let kind = match normalized.as_str() {
            "FOOTPRINT" => common_types::KiCadObjectType::KotPcbFootprint,
            "PAD" => common_types::KiCadObjectType::KotPcbPad,
            "SHAPE" | "GRAPHIC_SHAPE" | "GRAPHIC" => common_types::KiCadObjectType::KotPcbShape,
            "REFERENCE_IMAGE" => common_types::KiCadObjectType::KotPcbReferenceImage,
            "FIELD" => common_types::KiCadObjectType::KotPcbField,
            "GENERATOR" => common_types::KiCadObjectType::KotPcbGenerator,
            "TEXT" | "BOARD_TEXT" | "SILKSCREEN_TEXT" => common_types::KiCadObjectType::KotPcbText,
            "TEXTBOX" | "TEXT_BOX" | "BOARD_TEXTBOX" => {
                common_types::KiCadObjectType::KotPcbTextbox
            }
            "TABLE" => common_types::KiCadObjectType::KotPcbTable,
            "TABLECELL" | "TABLE_CELL" => common_types::KiCadObjectType::KotPcbTablecell,
            "TRACE" | "TRACK" => common_types::KiCadObjectType::KotPcbTrace,
            "VIA" => common_types::KiCadObjectType::KotPcbVia,
            "ARC" => common_types::KiCadObjectType::KotPcbArc,
            "MARKER" => common_types::KiCadObjectType::KotPcbMarker,
            "DIMENSION" => common_types::KiCadObjectType::KotPcbDimension,
            "ZONE" => common_types::KiCadObjectType::KotPcbZone,
            "GROUP" => common_types::KiCadObjectType::KotPcbGroup,
            "BARCODE" => common_types::KiCadObjectType::KotPcbBarcode,
            _ => common_types::KiCadObjectType::from_str_name(value.trim())?,
        };

        Some(Self {
            code: kind as i32,
            name: kind.as_str_name(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextHorizontalAlignment {
    Unknown,
    Left,
    Center,
    Right,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextVerticalAlignment {
    Unknown,
    Top,
    Center,
    Bottom,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TextAttributesSpec {
    pub font_name: Option<String>,
    pub horizontal_alignment: TextHorizontalAlignment,
    pub vertical_alignment: TextVerticalAlignment,
    pub angle_degrees: Option<f64>,
    pub line_spacing: Option<f64>,
    pub stroke_width_nm: Option<i64>,
    pub italic: bool,
    pub bold: bool,
    pub underlined: bool,
    pub mirrored: bool,
    pub multiline: bool,
    pub keep_upright: bool,
    pub size_nm: Option<Vector2Nm>,
}

impl Default for TextAttributesSpec {
    fn default() -> Self {
        Self {
            font_name: None,
            horizontal_alignment: TextHorizontalAlignment::Unknown,
            vertical_alignment: TextVerticalAlignment::Unknown,
            angle_degrees: None,
            line_spacing: None,
            stroke_width_nm: None,
            italic: false,
            bold: false,
            underlined: false,
            mirrored: false,
            multiline: false,
            keep_upright: false,
            size_nm: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TextSpec {
    pub text: String,
    pub position_nm: Option<Vector2Nm>,
    pub attributes: Option<TextAttributesSpec>,
    pub hyperlink: Option<String>,
}

impl TextSpec {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            position_nm: None,
            attributes: None,
            hyperlink: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextExtents {
    pub x_nm: i64,
    pub y_nm: i64,
    pub width_nm: i64,
    pub height_nm: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TextBoxSpec {
    pub text: String,
    pub top_left_nm: Option<Vector2Nm>,
    pub bottom_right_nm: Option<Vector2Nm>,
    pub attributes: Option<TextAttributesSpec>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TextObjectSpec {
    Text(TextSpec),
    TextBox(TextBoxSpec),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TextShapeGeometry {
    Segment {
        start_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
    },
    Rectangle {
        top_left_nm: Option<Vector2Nm>,
        bottom_right_nm: Option<Vector2Nm>,
        corner_radius_nm: Option<i64>,
    },
    Arc {
        start_nm: Option<Vector2Nm>,
        mid_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
    },
    Circle {
        center_nm: Option<Vector2Nm>,
        radius_point_nm: Option<Vector2Nm>,
    },
    Polygon {
        polygons: Vec<PolygonWithHolesNm>,
    },
    Bezier {
        start_nm: Option<Vector2Nm>,
        control1_nm: Option<Vector2Nm>,
        control2_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
    },
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TextShape {
    pub geometry: TextShapeGeometry,
    pub stroke_width_nm: Option<i64>,
    pub stroke_style: Option<i32>,
    pub stroke_color: Option<ColorRgba>,
    pub fill_type: Option<i32>,
    pub fill_color: Option<ColorRgba>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TextAsShapesEntry {
    pub source: Option<TextObjectSpec>,
    pub shapes: Vec<TextShape>,
}

impl std::fmt::Display for ItemHitTestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Unknown => "unknown",
            Self::NoHit => "no-hit",
            Self::Hit => "hit",
        };

        write!(f, "{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitAction, EditorFrameType, MapMergeMode, PcbObjectTypeCode};
    use std::str::FromStr;

    #[test]
    fn commit_action_parses_known_values() {
        assert_eq!(CommitAction::from_str("commit"), Ok(CommitAction::Commit));
        assert_eq!(CommitAction::from_str("drop"), Ok(CommitAction::Drop));
    }

    #[test]
    fn commit_action_rejects_unknown_values() {
        assert!(CommitAction::from_str("rollback").is_err());
    }

    #[test]
    fn editor_frame_type_parses_known_values() {
        assert_eq!(
            EditorFrameType::from_str("pcb"),
            Ok(EditorFrameType::PcbEditor)
        );
        assert_eq!(
            EditorFrameType::from_str("project-manager"),
            Ok(EditorFrameType::ProjectManager)
        );
    }

    #[test]
    fn editor_frame_type_rejects_unknown_values() {
        assert!(EditorFrameType::from_str("layout").is_err());
    }

    #[test]
    fn map_merge_mode_parses_known_values() {
        assert_eq!(MapMergeMode::from_str("merge"), Ok(MapMergeMode::Merge));
        assert_eq!(MapMergeMode::from_str("replace"), Ok(MapMergeMode::Replace));
    }

    #[test]
    fn map_merge_mode_rejects_unknown_values() {
        assert!(MapMergeMode::from_str("upsert").is_err());
    }

    #[test]
    fn pcb_object_type_code_resolves_friendly_names() {
        assert_eq!(
            PcbObjectTypeCode::from_name("track").map(|value| value.code),
            Some(PcbObjectTypeCode::new_trace().code)
        );
        assert_eq!(
            PcbObjectTypeCode::from_name("KOT_PCB_FOOTPRINT").map(|value| value.code),
            Some(PcbObjectTypeCode::new_footprint_instance().code)
        );
    }
}
