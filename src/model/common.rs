use std::path::PathBuf;
use std::str::FromStr;

use crate::model::board::Vector2Nm;
use crate::proto::kiapi::common::types as common_types;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub full_version: String,
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
