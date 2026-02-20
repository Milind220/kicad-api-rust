use std::path::PathBuf;
use std::str::FromStr;

use crate::model::board::{ColorRgba, PolygonWithHolesNm, Vector2Nm};
use crate::proto::kiapi::common::types as common_types;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub full_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorFrameType {
    ProjectManager,
    SchematicEditor,
    PcbEditor,
    SpiceSimulator,
    SymbolEditor,
    FootprintEditor,
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
pub enum DocumentType {
    Schematic,
    Symbol,
    Pcb,
    Footprint,
    DrawingSheet,
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
pub struct ProjectInfo {
    pub name: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentSpecifier {
    pub document_type: DocumentType,
    pub board_filename: Option<String>,
    pub project: ProjectInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionTypeCount {
    pub type_url: String,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionSummary {
    pub total_items: usize,
    pub type_url_counts: Vec<SelectionTypeCount>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionItemDetail {
    pub type_url: String,
    pub detail: String,
    pub raw_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSession {
    pub id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitAction {
    Commit,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunActionStatus {
    Ok,
    Invalid,
    FrameNotOpen,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapMergeMode {
    Merge,
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
pub struct TitleBlockInfo {
    pub title: String,
    pub date: String,
    pub revision: String,
    pub company: String,
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
    use super::{CommitAction, EditorFrameType, MapMergeMode};
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
}
