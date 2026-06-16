use std::str::FromStr;

use crate::proto::kiapi::board::types::BoardLayer;

#[derive(Clone, Debug, Eq, PartialEq)]
/// KiCad net descriptor.
pub struct BoardNet {
    /// Numeric net code (legacy identifier in KiCad 10.0.1+ APIs).
    pub code: i32,
    /// Net name (authoritative identifier for KiCad 10.0.1+ net queries).
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Board layer descriptor.
pub struct BoardLayerInfo {
    /// KiCad layer id.
    pub id: i32,
    /// Human-readable layer name.
    pub name: String,
}

impl BoardLayerInfo {
    /// Returns KiCad's canonical file/UI layer name for a layer id.
    ///
    /// Examples include `F.Cu`, `B.Cu`, `F.SilkS`, and `Edge.Cuts`.
    pub fn canonical_name_for_id(id: i32) -> Option<String> {
        let layer = BoardLayer::try_from(id).ok()?;
        let proto_name = layer.as_str_name();
        match proto_name {
            "BL_UNKNOWN" | "BL_UNDEFINED" | "BL_UNSELECTED" => None,
            _ => proto_name
                .strip_prefix("BL_")
                .map(|name| name.replace('_', ".")),
        }
    }

    /// Resolves a canonical KiCad layer name, proto enum name, or numeric id.
    ///
    /// Accepts values like `F.SilkS`, `BL_F_SilkS`, and `40`.
    pub fn id_from_name(value: &str) -> Option<i32> {
        let trimmed = value.trim();
        if let Ok(id) = trimmed.parse::<i32>() {
            return BoardLayer::try_from(id).ok().map(|_| id);
        }

        if let Some(layer) = BoardLayer::from_str_name(trimmed) {
            return Some(layer as i32);
        }

        (0..=128).find(|id| {
            Self::canonical_name_for_id(*id)
                .as_deref()
                .is_some_and(|name| name == trimmed)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Enabled layer set for a board.
pub struct BoardEnabledLayers {
    /// Number of copper layers configured in the board stack.
    pub copper_layer_count: u32,
    /// Enabled board layers.
    pub layers: Vec<BoardLayerInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Board origin kind.
pub enum BoardOriginKind {
    /// Grid origin.
    Grid,
    /// Drill/place origin.
    Drill,
}

impl FromStr for BoardOriginKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "grid" => Ok(Self::Grid),
            "drill" => Ok(Self::Drill),
            _ => Err(format!(
                "unknown board origin kind `{value}`; expected `grid` or `drill`"
            )),
        }
    }
}

impl std::fmt::Display for BoardOriginKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grid => write!(f, "grid"),
            Self::Drill => write!(f, "drill"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// 2D coordinate in nanometer units.
pub struct Vector2Nm {
    /// X coordinate in nm.
    pub x_nm: i64,
    /// Y coordinate in nm.
    pub y_nm: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Pad-to-net lookup row derived from footprint items.
pub struct PadNetEntry {
    /// Footprint reference (e.g. `U1`) when available.
    pub footprint_reference: Option<String>,
    /// Footprint id when available.
    pub footprint_id: Option<String>,
    /// Pad item id when available.
    pub pad_id: Option<String>,
    /// Pad number/text as shown in KiCad.
    pub pad_number: String,
    /// Net code when connected.
    pub net_code: Option<i32>,
    /// Net name when connected.
    pub net_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Arc geometry in nanometer units.
pub struct ArcStartMidEndNm {
    /// Arc start point.
    pub start: Vector2Nm,
    /// Arc midpoint.
    pub mid: Vector2Nm,
    /// Arc end point.
    pub end: Vector2Nm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Polyline node geometry.
pub enum PolyLineNodeGeometryNm {
    /// Straight segment point.
    Point(Vector2Nm),
    /// Arc segment node.
    Arc(ArcStartMidEndNm),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Polyline geometry.
pub struct PolyLineNm {
    /// Ordered geometry nodes.
    pub nodes: Vec<PolyLineNodeGeometryNm>,
    /// Whether last node closes back to first.
    pub closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Polygon with optional interior holes.
pub struct PolygonWithHolesNm {
    /// Outer outline polygon.
    pub outline: Option<PolyLineNm>,
    /// Interior holes.
    pub holes: Vec<PolyLineNm>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PadShapeAsPolygonEntry {
    pub pad_id: String,
    pub layer_id: i32,
    pub layer_name: String,
    pub polygon: PolygonWithHolesNm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PadstackPresenceEntry {
    pub item_id: String,
    pub layer_id: i32,
    pub layer_name: String,
    pub presence: PadstackPresenceState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PadstackPresenceState {
    Present,
    NotPresent,
    Unknown(i32),
}

impl std::fmt::Display for PadstackPresenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present => write!(f, "PSP_PRESENT"),
            Self::NotPresent => write!(f, "PSP_NOT_PRESENT"),
            Self::Unknown(value) => write!(f, "UNKNOWN({value})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ColorRgba {
    pub r: f64,
    pub g: f64,
    pub b: f64,
    pub a: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardStackupLayerType {
    Copper,
    Dielectric,
    Silkscreen,
    SolderMask,
    SolderPaste,
    Undefined,
    Unknown(i32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoardStackupDielectricProperties {
    pub epsilon_r: f64,
    pub loss_tangent: f64,
    pub material_name: String,
    pub thickness_nm: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoardStackupLayer {
    pub layer: BoardLayerInfo,
    pub user_name: String,
    pub material_name: String,
    pub enabled: bool,
    pub thickness_nm: Option<i64>,
    pub layer_type: BoardStackupLayerType,
    pub color: Option<ColorRgba>,
    pub dielectric_layers: Vec<BoardStackupDielectricProperties>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoardStackup {
    pub finish_type_name: String,
    pub impedance_controlled: bool,
    pub edge_has_connector: bool,
    pub edge_has_castellated_pads: bool,
    pub edge_has_edge_plating: bool,
    pub layers: Vec<BoardStackupLayer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardLayerClass {
    Silkscreen,
    Copper,
    Edges,
    Courtyard,
    Fabrication,
    Other,
    Unknown(i32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoardLayerGraphicsDefault {
    pub layer_class: BoardLayerClass,
    pub line_thickness_nm: Option<i64>,
    pub text_font_name: Option<String>,
    pub text_size_nm: Option<Vector2Nm>,
    pub text_stroke_width_nm: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GraphicsDefaults {
    pub layers: Vec<BoardLayerGraphicsDefault>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InactiveLayerDisplayMode {
    Normal,
    Dimmed,
    Hidden,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetColorDisplayMode {
    All,
    Ratsnest,
    Off,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardFlipMode {
    Normal,
    FlippedX,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RatsnestDisplayMode {
    AllLayers,
    VisibleLayers,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrcSeverity {
    Warning,
    Error,
    Exclusion,
    Ignore,
    Info,
    Action,
    Debug,
    Undefined,
}

impl std::fmt::Display for DrcSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Exclusion => "exclusion",
            Self::Ignore => "ignore",
            Self::Info => "info",
            Self::Action => "action",
            Self::Debug => "debug",
            Self::Undefined => "undefined",
        };
        write!(f, "{value}")
    }
}

impl FromStr for DrcSeverity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "exclusion" => Ok(Self::Exclusion),
            "ignore" => Ok(Self::Ignore),
            "info" => Ok(Self::Info),
            "action" => Ok(Self::Action),
            "debug" => Ok(Self::Debug),
            "undefined" => Ok(Self::Undefined),
            _ => Err(format!(
                "unknown drc severity `{value}`; expected warning, error, exclusion, ignore, info, action, debug, or undefined"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoardEditorAppearanceSettings {
    pub inactive_layer_display: InactiveLayerDisplayMode,
    pub net_color_display: NetColorDisplayMode,
    pub board_flip: BoardFlipMode,
    pub ratsnest_display: RatsnestDisplayMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetClassType {
    Explicit,
    Implicit,
    Unknown(i32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetClassBoardSettings {
    pub clearance_nm: Option<i64>,
    pub track_width_nm: Option<i64>,
    pub diff_pair_track_width_nm: Option<i64>,
    pub diff_pair_gap_nm: Option<i64>,
    pub diff_pair_via_gap_nm: Option<i64>,
    pub color: Option<ColorRgba>,
    pub tuning_profile: Option<String>,
    pub has_via_stack: bool,
    pub has_microvia_stack: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetClassInfo {
    pub name: String,
    pub priority: Option<i32>,
    pub class_type: NetClassType,
    pub constituents: Vec<String>,
    pub board: Option<NetClassBoardSettings>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetClassForNetEntry {
    pub net_name: String,
    pub net_class: NetClassInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcbViaType {
    Through,
    BlindBuried,
    Micro,
    Blind,
    Buried,
    Unknown(i32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbViaLayers {
    pub padstack_layers: Vec<BoardLayerInfo>,
    pub drill_start_layer: Option<BoardLayerInfo>,
    pub drill_end_layer: Option<BoardLayerInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcbPadType {
    Pth,
    Smd,
    EdgeConnector,
    Npth,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcbZoneType {
    Copper,
    Graphical,
    RuleArea,
    Teardrop,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemLockState {
    Unlocked,
    Locked,
    Unknown(i32),
}

impl ItemLockState {
    /// Returns true when this lock state is locked.
    pub fn is_locked(self) -> bool {
        matches!(self, Self::Locked)
    }
}

#[derive(Clone, Debug, PartialEq)]
/// Specification for creating a board text item through `CreateItems`.
///
/// This mirrors the official `kicad-python` `BoardText` wrapper: leave `id`
/// unset to let KiCad assign the KIID in the create response.
pub struct BoardTextSpec {
    /// Optional KIID to request. Leave `None` for KiCad-assigned IDs.
    pub id: Option<String>,
    /// Text payload, position, attributes, and hyperlink.
    pub text: crate::model::common::TextSpec,
    /// KiCad board layer id, for example `40` for `F.SilkS`.
    pub layer_id: i32,
    /// Whether to enable knockout rendering.
    pub knockout: bool,
    /// Requested item lock state.
    pub locked: ItemLockState,
}

impl BoardTextSpec {
    /// Creates a board text specification on the given layer.
    pub fn new(
        text: impl Into<String>,
        position_nm: Vector2Nm,
        layer_id: i32,
        attributes: Option<crate::model::common::TextAttributesSpec>,
    ) -> Self {
        Self {
            id: None,
            text: crate::model::common::TextSpec {
                text: text.into(),
                position_nm: Some(position_nm),
                attributes,
                hyperlink: None,
            },
            layer_id,
            knockout: false,
            locked: ItemLockState::Unlocked,
        }
    }

    /// Creates a board text specification on the front silkscreen layer.
    pub fn front_silkscreen(
        text: impl Into<String>,
        position_nm: Vector2Nm,
        attributes: Option<crate::model::common::TextAttributesSpec>,
    ) -> Self {
        Self::new(text, position_nm, BoardLayer::BlFSilkS as i32, attributes)
        // these could now be removed
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbPadStackLayer {
    pub layer: i32,
    pub shape: i32,
    pub size: Option<Vector2Nm>,
    pub corner_rounding_ratio: f64,
    pub chamfer_ratio: f64,
    pub chamfered_corners: Option<PcbChamferedRectCorners>,
    pub custom_shapes: Vec<PcbBoardGraphicShape>,
    pub custom_anchor_shape: i32,
    pub zone_settings: Option<PcbZoneConnectionSettings>,
    pub trapezoid_delta: Option<Vector2Nm>,
    pub offset: Option<Vector2Nm>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcbPadStackOuterLayer {
    pub solder_mask_mode: i32,
    pub solder_paste_mode: i32,
    pub solder_mask_settings: Option<PcbSolderMaskOverrides>,
    pub solder_paste_settings: Option<PcbSolderPasteOverrides>,
    pub plugging_mode: i32,
    pub covering_mode: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PcbChamferedRectCorners {
    pub top_left: bool,
    pub top_right: bool,
    pub bottom_left: bool,
    pub bottom_right: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcbZoneConnectionSettings {
    pub zone_connection: i32,
    pub thermal_spokes: Option<PcbThermalSpokeSettings>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcbThermalSpokeSettings {
    pub width: Option<i64>,
    pub angle: Option<f64>,
    pub gap: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbPadstackDrill {
    pub start_layer: BoardLayerInfo,
    pub end_layer: BoardLayerInfo,
    pub diameter_nm: Option<Vector2Nm>,
    pub shape: Option<String>,
    pub capped: Option<String>,
    pub filled: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbPadStack {
    pub stack_type: Option<String>,
    pub layers: Vec<BoardLayerInfo>,
    pub drill: Option<PcbPadstackDrill>,
    pub unconnected_layer_removal: Option<String>,

    pub copper_layers: Vec<PcbPadStackLayer>,
    pub angle: Option<f64>,
    pub front_outer_layers: Option<PcbPadStackOuterLayer>,
    pub back_outer_layers: Option<PcbPadStackOuterLayer>,
    pub zone_settings: Option<PcbZoneConnectionSettings>,

    // these could now be removed
    pub copper_layer_count: usize,
    pub has_front_outer_layers: bool,
    pub has_back_outer_layers: bool,
    pub has_zone_settings: bool,

    pub secondary_drill: Option<PcbPadstackDrill>,
    pub tertiary_drill: Option<PcbPadstackDrill>,
    pub has_front_post_machining: bool,
    pub has_back_post_machining: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbSymbolPinInfo {
    pub name: String,
    pub pin_type: Option<String>,
    pub no_connect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbTextAttributes {
    pub font_name: Option<String>,
    pub horizontal_alignment: Option<String>,
    pub vertical_alignment: Option<String>,
    pub stroke_width_nm: Option<i64>,
    pub italic: bool,
    pub bold: bool,
    pub underlined: bool,
    pub mirrored: bool,
    pub multiline: bool,
    pub keep_upright: bool,
    pub size_nm: Option<Vector2Nm>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcbGraphicShapeGeometry {
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
        polygon_count: usize,
    },
    Bezier {
        start_nm: Option<Vector2Nm>,
        control1_nm: Option<Vector2Nm>,
        control2_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbZoneLayerProperty {
    pub layer: BoardLayerInfo,
    pub hatching_offset_nm: Option<Vector2Nm>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcbDimensionStyle {
    Aligned {
        start_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
        height_nm: Option<i64>,
        extension_height_nm: Option<i64>,
    },
    Orthogonal {
        start_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
        height_nm: Option<i64>,
        extension_height_nm: Option<i64>,
        alignment: Option<String>,
    },
    Radial {
        center_nm: Option<Vector2Nm>,
        radius_point_nm: Option<Vector2Nm>,
        leader_length_nm: Option<i64>,
    },
    Leader {
        start_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
        border_style: Option<String>,
    },
    Center {
        center_nm: Option<Vector2Nm>,
        end_nm: Option<Vector2Nm>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbFootprintSymbolLink {
    pub has_symbol_path: bool,
    pub sheet_name: Option<String>,
    pub sheet_filename: Option<String>,
    pub footprint_filters: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbTrack {
    pub id: Option<String>,
    pub start_nm: Option<Vector2Nm>,
    pub end_nm: Option<Vector2Nm>,
    pub width_nm: Option<i64>,
    pub locked: ItemLockState,
    pub layer: BoardLayerInfo,
    pub net: Option<BoardNet>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbArc {
    pub id: Option<String>,
    pub start_nm: Option<Vector2Nm>,
    pub mid_nm: Option<Vector2Nm>,
    pub end_nm: Option<Vector2Nm>,
    pub width_nm: Option<i64>,
    pub locked: ItemLockState,
    pub layer: BoardLayerInfo,
    pub net: Option<BoardNet>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbVia {
    pub id: Option<String>,
    pub position_nm: Option<Vector2Nm>,
    pub via_type: PcbViaType,
    pub locked: ItemLockState,
    pub layers: Option<PcbViaLayers>,
    pub pad_stack: Option<PcbPadStack>,
    pub net: Option<BoardNet>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbFootprintInstance {
    pub id: Option<String>,
    pub reference: Option<String>,
    pub position_nm: Option<Vector2Nm>,
    pub orientation_deg: Option<f64>,
    pub layer: BoardLayerInfo,
    pub locked: ItemLockState,
    pub definition: Option<PcbFootprint>,
    pub value: Option<String>,
    pub datasheet: Option<String>,
    pub description: Option<String>,

    pub has_attributes: bool,
    pub has_overrides: bool,
    pub has_definition: bool,

    pub definition_item_count: usize,
    pub symbol_link: Option<PcbFootprintSymbolLink>,
    pub pad_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcbFootprintAttributes {
    pub description: String,
    pub keywords: String,
    pub not_in_schematic: bool,
    pub exclude_from_position_files: bool,
    pub exclude_from_bill_of_materials: bool,
    pub exempt_from_courtyard_requirement: bool,
    pub do_not_populate: bool,
    pub mounting_style: i32,
    /// Since: 9.0.7
    pub allow_soldermask_bridges: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcbFootprintDesignRuleOverrides {
    pub solder_mask: Option<PcbSolderMaskOverrides>,
    pub solder_paste: Option<PcbSolderPasteOverrides>,
    pub copper_clearance_nm: Option<i64>,
    pub zone_connection: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PcbSolderMaskOverrides {
    /// Solder mask expansion/contraction
    pub solder_mask_margin_nm: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PcbSolderPasteOverrides {
    /// Solder paste expansion/contraction
    pub solder_paste_margin_nm: Option<i64>,
    /// Solder paste expansion/contraction ratio
    pub solder_paste_margin_ratio: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbJumperSettings {
    /// / If true, duplicate pad names in this footprint are jumpered together
    pub duplicate_names_are_jumpered: bool,
    pub groups: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbFootprint {
    pub id: Option<String>,
    pub anchor: Option<Vector2Nm>,
    pub attributes: Option<PcbFootprintAttributes>,
    pub overrides: Option<PcbFootprintDesignRuleOverrides>,
    pub net_ties: Vec<Vec<String>>,
    pub private_layers: Vec<i32>,
    pub reference: Option<String>,
    pub value: Option<String>,
    pub datasheet: Option<String>,
    pub description: Option<String>,
    pub items: Vec<PcbItem>,
    pub jumpers: Option<PcbJumperSettings>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbPad {
    pub id: Option<String>,
    pub locked: ItemLockState,
    pub number: String,
    pub pad_type: PcbPadType,
    pub position_nm: Option<Vector2Nm>,
    pub pad_stack: Option<PcbPadStack>,
    pub copper_clearance_override_nm: Option<i64>,
    pub pad_to_die_length_nm: Option<i64>,
    pub pad_to_die_delay_as: Option<i64>,
    pub symbol_pin: Option<PcbSymbolPinInfo>,
    pub net: Option<BoardNet>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbBoardGraphicShape {
    pub id: Option<String>,
    pub layer: BoardLayerInfo,
    pub locked: ItemLockState,
    pub net: Option<BoardNet>,
    pub geometry_kind: Option<String>,
    pub geometry: Option<PcbGraphicShapeGeometry>,
    pub stroke_width_nm: Option<i64>,
    pub stroke_style: Option<String>,
    pub fill_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbBoardText {
    pub id: Option<String>,
    pub layer: BoardLayerInfo,
    pub text: Option<String>,
    pub position_nm: Option<Vector2Nm>,
    pub hyperlink: Option<String>,
    pub attributes: Option<PcbTextAttributes>,
    pub knockout: bool,
    pub locked: ItemLockState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbBoardTextBox {
    pub id: Option<String>,
    pub layer: BoardLayerInfo,
    pub text: Option<String>,
    pub top_left_nm: Option<Vector2Nm>,
    pub bottom_right_nm: Option<Vector2Nm>,
    pub attributes: Option<PcbTextAttributes>,
    pub locked: ItemLockState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbField {
    pub name: String,
    pub visible: bool,
    pub text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbZone {
    pub id: Option<String>,
    pub name: String,
    pub zone_type: PcbZoneType,
    pub layers: Vec<BoardLayerInfo>,
    pub layer_count: usize,
    pub priority: u32,
    pub locked: ItemLockState,
    pub filled: bool,
    pub polygon_count: usize,
    pub outline_polygon_count: usize,
    pub has_copper_settings: bool,
    pub has_rule_area_settings: bool,
    pub border_style: Option<String>,
    pub border_pitch_nm: Option<i64>,
    pub layer_properties: Vec<PcbZoneLayerProperty>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbDimension {
    pub id: Option<String>,
    pub layer: BoardLayerInfo,
    pub locked: ItemLockState,
    pub text: Option<String>,
    pub style_kind: Option<String>,
    pub style: Option<PcbDimensionStyle>,
    pub override_text_enabled: bool,
    pub override_text: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub unit: Option<String>,
    pub unit_format: Option<String>,
    pub arrow_direction: Option<String>,
    pub precision: Option<String>,
    pub suppress_trailing_zeroes: bool,
    pub line_thickness_nm: Option<i64>,
    pub arrow_length_nm: Option<i64>,
    pub extension_offset_nm: Option<i64>,
    pub text_position: Option<String>,
    pub keep_text_aligned: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcbReferenceImage {
    pub id: Option<String>,
    pub layer: BoardLayerInfo,
    pub position_nm: Option<Vector2Nm>,
    pub transform_origin_offset_nm: Option<Vector2Nm>,
    pub image_scale: Option<f64>,
    pub image_data_len: usize,
    pub locked: ItemLockState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcbBarcodeKind {
    Unknown,
    Code39,
    Code128,
    DataMatrix,
    QrCode,
    MicroQrCode,
    Unrecognized(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcbBarcodeErrorCorrection {
    Unknown,
    L,
    M,
    Q,
    H,
    Unrecognized(i32),
}
#[derive(Clone, Debug, PartialEq)]
pub struct PcbBarcode {
    pub id: Option<String>,
    pub text: String,
    pub kind: PcbBarcodeKind,
    pub error_correction: PcbBarcodeErrorCorrection,
    pub position_nm: Option<Vector2Nm>,
    pub orientation_deg: Option<f64>,
    pub layer: BoardLayerInfo,
    pub width_nm: Option<i64>,
    pub height_nm: Option<i64>,
    pub show_text: bool,
    pub text_height_nm: Option<i64>,
    pub knockout: bool,
    pub knockout_margin_nm: Option<Vector2Nm>,
    pub locked: ItemLockState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbGroup {
    pub id: Option<String>,
    pub name: String,
    pub item_count: usize,
    pub item_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcbUnknownItem {
    pub type_url: String,
    pub raw_len: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PcbItem {
    Track(PcbTrack),
    Arc(PcbArc),
    Via(PcbVia),
    FootprintInstance(PcbFootprintInstance),
    Pad(PcbPad),
    BoardGraphicShape(PcbBoardGraphicShape),
    BoardText(PcbBoardText),
    BoardTextBox(PcbBoardTextBox),
    Field(PcbField),
    Zone(PcbZone),
    Dimension(PcbDimension),
    ReferenceImage(PcbReferenceImage),
    Barcode(PcbBarcode),
    Group(PcbGroup),
    Unknown(PcbUnknownItem),
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{BoardLayerInfo, BoardOriginKind, DrcSeverity};

    #[test]
    fn board_origin_kind_parses_known_values() {
        assert_eq!(
            BoardOriginKind::from_str("grid").expect("grid should parse"),
            BoardOriginKind::Grid
        );
        assert_eq!(
            BoardOriginKind::from_str("drill").expect("drill should parse"),
            BoardOriginKind::Drill
        );
    }

    #[test]
    fn board_origin_kind_rejects_unknown_values() {
        let result = BoardOriginKind::from_str("other");
        assert!(result.is_err());
    }

    #[test]
    fn board_layer_info_resolves_canonical_and_proto_names() {
        assert_eq!(BoardLayerInfo::id_from_name("F.SilkS"), Some(40));
        assert_eq!(BoardLayerInfo::id_from_name("BL_F_SilkS"), Some(40));
        assert_eq!(
            BoardLayerInfo::canonical_name_for_id(40).as_deref(),
            Some("F.SilkS")
        );
    }

    #[test]
    fn drc_severity_parses_known_values() {
        assert_eq!(
            DrcSeverity::from_str("warning").expect("warning should parse"),
            DrcSeverity::Warning
        );
        assert_eq!(
            DrcSeverity::from_str("error").expect("error should parse"),
            DrcSeverity::Error
        );
    }

    #[test]
    fn drc_severity_rejects_unknown_values() {
        let result = DrcSeverity::from_str("fatal");
        assert!(result.is_err());
    }
}
