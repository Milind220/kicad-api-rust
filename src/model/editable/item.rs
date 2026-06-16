/// Typed kind classification for editable PCB item payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditablePcbItemKind {
    /// A board track segment.
    Track,
    /// A board arc track segment.
    Arc,
    /// A via item.
    Via,
    /// A placed footprint instance.
    FootprintInstance,
    /// A footprint pad.
    Pad,
    /// A board graphic shape.
    BoardGraphicShape,
    /// A board text item.
    BoardText,
    /// A board text box item.
    BoardTextBox,
    /// A footprint field item.
    Field,
    /// A board zone.
    Zone,
    /// A board dimension.
    Dimension,
    /// A board group.
    Group,
    /// A board reference image.
    ReferenceImage,
    /// A board barcode.
    Barcode,
    /// A payload whose type URL is not recognized by this crate version.
    Unknown,
}
/// Layer presence model for editable PCB items.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayerSet {
    /// Item belongs to exactly one board layer id.
    Single(i32),
    /// Item belongs to multiple board layer ids.
    Multi(Vec<i32>),
    /// Item layer membership is represented by a padstack definition.
    Padstack,
    /// Item has no direct layer relationship.
    None,
}

/// Raw editable payload wrapper for unknown/unsupported item types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPcbItem {
    /// Original protobuf payload.
    pub raw: prost_types::Any,
}
