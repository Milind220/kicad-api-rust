//! Proto-to-model and model-to-proto conversion functions.

use std::collections::BTreeMap;

use crate::envelope;
use crate::error::KiCadError;
use crate::model::board::*;
use crate::model::common::*;
use crate::pcb_item_type_urls;
use crate::proto::kiapi::board as board_proto;
use crate::proto::kiapi::board::commands as board_commands;
use crate::proto::kiapi::board::types as board_types;
use crate::proto::kiapi::common::commands as common_commands;
use crate::proto::kiapi::common::project as common_project;
use crate::proto::kiapi::common::types as common_types;

use super::format::selection_item_detail;
pub(crate) fn model_document_to_proto(
    document: &DocumentSpecifier,
) -> common_types::DocumentSpecifier {
    let identifier = document.board_filename.as_ref().map(|filename| {
        common_types::document_specifier::Identifier::BoardFilename(filename.clone())
    });

    let project = common_types::ProjectSpecifier {
        name: document.project.name.clone().unwrap_or_default(),
        path: document
            .project
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
    };

    common_types::DocumentSpecifier {
        r#type: document.document_type.to_proto(),
        project: Some(project),
        identifier,
    }
}
pub(crate) fn project_document_proto() -> common_types::DocumentSpecifier {
    common_types::DocumentSpecifier {
        r#type: DocumentType::Project.to_proto(),
        project: Some(common_types::ProjectSpecifier::default()),
        identifier: None,
    }
}

pub(crate) fn text_spec_to_proto(text: TextSpec) -> common_types::Text {
    common_types::Text {
        position: text.position_nm.map(vector2_nm_to_proto),
        attributes: text.attributes.map(text_attributes_spec_to_proto),
        text: text.text,
        hyperlink: text.hyperlink.unwrap_or_default(),
    }
}

pub(crate) fn text_attributes_spec_to_proto(
    attributes: TextAttributesSpec,
) -> common_types::TextAttributes {
    common_types::TextAttributes {
        font_name: attributes.font_name.unwrap_or_default(),
        horizontal_alignment: text_horizontal_alignment_to_proto(attributes.horizontal_alignment),
        vertical_alignment: text_vertical_alignment_to_proto(attributes.vertical_alignment),
        angle: attributes
            .angle_degrees
            .map(|value_degrees| common_types::Angle { value_degrees }),
        line_spacing: attributes.line_spacing.unwrap_or(1.0),
        stroke_width: attributes
            .stroke_width_nm
            .map(|value_nm| common_types::Distance { value_nm }),
        italic: attributes.italic,
        bold: attributes.bold,
        underlined: attributes.underlined,
        visible: true,
        mirrored: attributes.mirrored,
        multiline: attributes.multiline,
        keep_upright: attributes.keep_upright,
        size: attributes.size_nm.map(vector2_nm_to_proto),
    }
}

pub(crate) fn text_horizontal_alignment_to_proto(value: TextHorizontalAlignment) -> i32 {
    match value {
        TextHorizontalAlignment::Unknown => common_types::HorizontalAlignment::HaUnknown as i32,
        TextHorizontalAlignment::Left => common_types::HorizontalAlignment::HaLeft as i32,
        TextHorizontalAlignment::Center => common_types::HorizontalAlignment::HaCenter as i32,
        TextHorizontalAlignment::Right => common_types::HorizontalAlignment::HaRight as i32,
        TextHorizontalAlignment::Indeterminate => {
            common_types::HorizontalAlignment::HaIndeterminate as i32
        }
    }
}

pub(crate) fn text_vertical_alignment_to_proto(value: TextVerticalAlignment) -> i32 {
    match value {
        TextVerticalAlignment::Unknown => common_types::VerticalAlignment::VaUnknown as i32,
        TextVerticalAlignment::Top => common_types::VerticalAlignment::VaTop as i32,
        TextVerticalAlignment::Center => common_types::VerticalAlignment::VaCenter as i32,
        TextVerticalAlignment::Bottom => common_types::VerticalAlignment::VaBottom as i32,
        TextVerticalAlignment::Indeterminate => {
            common_types::VerticalAlignment::VaIndeterminate as i32
        }
    }
}

pub(crate) fn text_box_spec_to_proto(text: TextBoxSpec) -> common_types::TextBox {
    common_types::TextBox {
        top_left: text.top_left_nm.map(vector2_nm_to_proto),
        bottom_right: text.bottom_right_nm.map(vector2_nm_to_proto),
        attributes: text.attributes.map(text_attributes_spec_to_proto),
        text: text.text,
    }
}

pub(crate) fn text_object_spec_to_proto(text: TextObjectSpec) -> common_commands::TextOrTextBox {
    let inner = match text {
        TextObjectSpec::Text(value) => {
            common_commands::text_or_text_box::Inner::Text(text_spec_to_proto(value))
        }
        TextObjectSpec::TextBox(value) => {
            common_commands::text_or_text_box::Inner::Textbox(text_box_spec_to_proto(value))
        }
    };
    common_commands::TextOrTextBox { inner: Some(inner) }
}

pub(crate) fn item_lock_state_to_proto(value: ItemLockState) -> i32 {
    match value {
        ItemLockState::Unlocked => common_types::LockedState::LsUnlocked as i32,
        ItemLockState::Locked => common_types::LockedState::LsLocked as i32,
        ItemLockState::Unknown(value) => value,
    }
}

pub(crate) fn board_text_spec_to_proto(spec: BoardTextSpec) -> board_types::BoardText {
    board_types::BoardText {
        id: spec.id.map(|value| common_types::Kiid { value }),
        text: Some(text_spec_to_proto(spec.text)),
        layer: spec.layer_id,
        knockout: spec.knockout,
        locked: item_lock_state_to_proto(spec.locked),
    }
}

pub(crate) fn board_text_spec_to_any(spec: BoardTextSpec) -> prost_types::Any {
    envelope::pack_any(
        &board_text_spec_to_proto(spec),
        pcb_item_type_urls::BOARD_TEXT,
    )
}

pub(crate) fn map_text_horizontal_alignment_from_proto(value: i32) -> TextHorizontalAlignment {
    match common_types::HorizontalAlignment::try_from(value) {
        Ok(common_types::HorizontalAlignment::HaLeft) => TextHorizontalAlignment::Left,
        Ok(common_types::HorizontalAlignment::HaCenter) => TextHorizontalAlignment::Center,
        Ok(common_types::HorizontalAlignment::HaRight) => TextHorizontalAlignment::Right,
        Ok(common_types::HorizontalAlignment::HaIndeterminate) => {
            TextHorizontalAlignment::Indeterminate
        }
        _ => TextHorizontalAlignment::Unknown,
    }
}

pub(crate) fn map_text_vertical_alignment_from_proto(value: i32) -> TextVerticalAlignment {
    match common_types::VerticalAlignment::try_from(value) {
        Ok(common_types::VerticalAlignment::VaTop) => TextVerticalAlignment::Top,
        Ok(common_types::VerticalAlignment::VaCenter) => TextVerticalAlignment::Center,
        Ok(common_types::VerticalAlignment::VaBottom) => TextVerticalAlignment::Bottom,
        Ok(common_types::VerticalAlignment::VaIndeterminate) => {
            TextVerticalAlignment::Indeterminate
        }
        _ => TextVerticalAlignment::Unknown,
    }
}

pub(crate) fn map_text_attributes_spec_from_proto(
    attributes: common_types::TextAttributes,
) -> TextAttributesSpec {
    TextAttributesSpec {
        font_name: if attributes.font_name.is_empty() {
            None
        } else {
            Some(attributes.font_name)
        },
        horizontal_alignment: map_text_horizontal_alignment_from_proto(
            attributes.horizontal_alignment,
        ),
        vertical_alignment: map_text_vertical_alignment_from_proto(attributes.vertical_alignment),
        angle_degrees: attributes.angle.map(|value| value.value_degrees),
        line_spacing: Some(attributes.line_spacing),
        stroke_width_nm: map_optional_distance_nm(attributes.stroke_width),
        italic: attributes.italic,
        bold: attributes.bold,
        underlined: attributes.underlined,
        mirrored: attributes.mirrored,
        multiline: attributes.multiline,
        keep_upright: attributes.keep_upright,
        size_nm: attributes.size.map(map_vector2_nm),
    }
}

pub(crate) fn map_text_spec_from_proto(text: common_types::Text) -> TextSpec {
    TextSpec {
        text: text.text,
        position_nm: text.position.map(map_vector2_nm),
        attributes: text.attributes.map(map_text_attributes_spec_from_proto),
        hyperlink: if text.hyperlink.is_empty() {
            None
        } else {
            Some(text.hyperlink)
        },
    }
}

pub(crate) fn map_text_box_spec_from_proto(text: common_types::TextBox) -> TextBoxSpec {
    TextBoxSpec {
        text: text.text,
        top_left_nm: text.top_left.map(map_vector2_nm),
        bottom_right_nm: text.bottom_right.map(map_vector2_nm),
        attributes: text.attributes.map(map_text_attributes_spec_from_proto),
    }
}

pub(crate) fn map_text_object_spec_from_proto(
    text: common_commands::TextOrTextBox,
) -> Option<TextObjectSpec> {
    match text.inner {
        Some(common_commands::text_or_text_box::Inner::Text(value)) => {
            Some(TextObjectSpec::Text(map_text_spec_from_proto(value)))
        }
        Some(common_commands::text_or_text_box::Inner::Textbox(value)) => {
            Some(TextObjectSpec::TextBox(map_text_box_spec_from_proto(value)))
        }
        None => None,
    }
}

pub(crate) fn map_text_shape_geometry(
    shape: common_types::GraphicShape,
) -> Result<TextShapeGeometry, KiCadError> {
    match shape.geometry {
        Some(common_types::graphic_shape::Geometry::Segment(segment)) => {
            Ok(TextShapeGeometry::Segment {
                start_nm: segment.start.map(map_vector2_nm),
                end_nm: segment.end.map(map_vector2_nm),
            })
        }
        Some(common_types::graphic_shape::Geometry::Rectangle(rectangle)) => {
            Ok(TextShapeGeometry::Rectangle {
                top_left_nm: rectangle.top_left.map(map_vector2_nm),
                bottom_right_nm: rectangle.bottom_right.map(map_vector2_nm),
                corner_radius_nm: map_optional_distance_nm(rectangle.corner_radius),
            })
        }
        Some(common_types::graphic_shape::Geometry::Arc(arc)) => Ok(TextShapeGeometry::Arc {
            start_nm: arc.start.map(map_vector2_nm),
            mid_nm: arc.mid.map(map_vector2_nm),
            end_nm: arc.end.map(map_vector2_nm),
        }),
        Some(common_types::graphic_shape::Geometry::Circle(circle)) => {
            Ok(TextShapeGeometry::Circle {
                center_nm: circle.center.map(map_vector2_nm),
                radius_point_nm: circle.radius_point.map(map_vector2_nm),
            })
        }
        Some(common_types::graphic_shape::Geometry::Polygon(polygon)) => {
            let polygons = polygon
                .polygons
                .into_iter()
                .map(map_polygon_with_holes)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TextShapeGeometry::Polygon { polygons })
        }
        Some(common_types::graphic_shape::Geometry::Bezier(bezier)) => {
            Ok(TextShapeGeometry::Bezier {
                start_nm: bezier.start.map(map_vector2_nm),
                control1_nm: bezier.control1.map(map_vector2_nm),
                control2_nm: bezier.control2.map(map_vector2_nm),
                end_nm: bezier.end.map(map_vector2_nm),
            })
        }
        None => Ok(TextShapeGeometry::Unknown),
    }
}

pub(crate) fn map_text_shape(shape: common_types::GraphicShape) -> Result<TextShape, KiCadError> {
    let geometry = map_text_shape_geometry(shape.clone())?;
    let attributes = shape.attributes.unwrap_or_default();
    let stroke = attributes.stroke;
    let fill = attributes.fill;

    Ok(TextShape {
        geometry,
        stroke_width_nm: stroke.and_then(|value| map_optional_distance_nm(value.width)),
        stroke_style: stroke.as_ref().map(|value| value.style),
        stroke_color: stroke.and_then(|value| map_optional_color(value.color)),
        fill_type: fill.as_ref().map(|value| value.fill_type),
        fill_color: fill.and_then(|value| map_optional_color(value.color)),
    })
}

pub(crate) fn map_text_with_shapes(
    row: common_commands::TextWithShapes,
) -> Result<TextAsShapesEntry, KiCadError> {
    let source = row.text.and_then(map_text_object_spec_from_proto);
    let shapes = row
        .shapes
        .unwrap_or_default()
        .shapes
        .into_iter()
        .map(map_text_shape)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TextAsShapesEntry { source, shapes })
}

pub(crate) fn layer_to_model(layer_id: i32) -> BoardLayerInfo {
    let name = board_types::BoardLayer::try_from(layer_id)
        .map(|layer| layer.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN_LAYER({layer_id})"));

    BoardLayerInfo { id: layer_id, name }
}

pub(crate) fn map_board_enabled_layers_response(
    payload: board_commands::BoardEnabledLayersResponse,
) -> BoardEnabledLayers {
    BoardEnabledLayers {
        copper_layer_count: payload.copper_layer_count,
        layers: payload.layers.into_iter().map(layer_to_model).collect(),
    }
}

pub(crate) fn board_origin_kind_to_proto(kind: BoardOriginKind) -> i32 {
    match kind {
        BoardOriginKind::Grid => board_commands::BoardOriginType::BotGrid as i32,
        BoardOriginKind::Drill => board_commands::BoardOriginType::BotDrill as i32,
    }
}

pub(crate) fn drc_severity_to_proto(value: DrcSeverity) -> i32 {
    match value {
        DrcSeverity::Warning => board_commands::DrcSeverity::DrsWarning as i32,
        DrcSeverity::Error => board_commands::DrcSeverity::DrsError as i32,
        DrcSeverity::Exclusion => board_commands::DrcSeverity::DrsExclusion as i32,
        DrcSeverity::Ignore => board_commands::DrcSeverity::DrsIgnore as i32,
        DrcSeverity::Info => board_commands::DrcSeverity::DrsInfo as i32,
        DrcSeverity::Action => board_commands::DrcSeverity::DrsAction as i32,
        DrcSeverity::Debug => board_commands::DrcSeverity::DrsDebug as i32,
        DrcSeverity::Undefined => board_commands::DrcSeverity::DrsUndefined as i32,
    }
}

pub(crate) fn commit_action_to_proto(action: CommitAction) -> i32 {
    match action {
        CommitAction::Commit => common_commands::CommitAction::CmaCommit as i32,
        CommitAction::Drop => common_commands::CommitAction::CmaDrop as i32,
    }
}

pub(crate) fn map_merge_mode_to_proto(value: MapMergeMode) -> i32 {
    match value {
        MapMergeMode::Merge => common_types::MapMergeMode::MmmMerge as i32,
        MapMergeMode::Replace => common_types::MapMergeMode::MmmReplace as i32,
    }
}

pub(crate) fn summarize_selection(items: &[prost_types::Any]) -> SelectionSummary {
    let mut counts = BTreeMap::<String, usize>::new();

    for item in items {
        let entry = counts.entry(item.type_url.clone()).or_insert(0);
        *entry += 1;
    }

    SelectionSummary {
        total_items: items.len(),
        type_url_counts: counts
            .into_iter()
            .map(|(type_url, count)| SelectionTypeCount { type_url, count })
            .collect(),
    }
}

pub(crate) fn summarize_item_details(
    items: Vec<prost_types::Any>,
) -> Result<Vec<SelectionItemDetail>, KiCadError> {
    let mut details = Vec::with_capacity(items.len());
    for item in items {
        let raw_len = item.value.len();
        let type_url = item.type_url.clone();
        let detail = selection_item_detail(&item)?;
        details.push(SelectionItemDetail {
            type_url,
            detail,
            raw_len,
        });
    }

    Ok(details)
}

pub(crate) fn map_commit_session(
    response: common_commands::BeginCommitResponse,
) -> Result<CommitSession, KiCadError> {
    let id = response.id.ok_or_else(|| KiCadError::InvalidResponse {
        reason: "BeginCommit response missing commit id".to_string(),
    })?;

    if id.value.is_empty() {
        return Err(KiCadError::InvalidResponse {
            reason: "BeginCommit response returned empty commit id".to_string(),
        });
    }

    Ok(CommitSession { id: id.value })
}

pub(crate) fn ensure_item_request_ok(status: i32) -> Result<(), KiCadError> {
    let request_status = common_types::ItemRequestStatus::try_from(status)
        .unwrap_or(common_types::ItemRequestStatus::IrsUnknown);

    if request_status != common_types::ItemRequestStatus::IrsOk {
        return Err(KiCadError::ItemStatus {
            code: request_status.as_str_name().to_string(),
        });
    }

    Ok(())
}

pub(crate) fn ensure_item_status_ok(
    status: Option<common_commands::ItemStatus>,
) -> Result<(), KiCadError> {
    let status = status.unwrap_or_default();
    let code = common_commands::ItemStatusCode::try_from(status.code)
        .unwrap_or(common_commands::ItemStatusCode::IscUnknown);

    if code != common_commands::ItemStatusCode::IscOk {
        let detail = if status.error_message.is_empty() {
            code.as_str_name().to_string()
        } else {
            format!("{}: {}", code.as_str_name(), status.error_message)
        };

        return Err(KiCadError::ItemStatus { code: detail });
    }

    Ok(())
}

pub(crate) fn ensure_item_deletion_status_ok(status: i32) -> Result<(), KiCadError> {
    let code = common_commands::ItemDeletionStatus::try_from(status)
        .unwrap_or(common_commands::ItemDeletionStatus::IdsUnknown);

    if code != common_commands::ItemDeletionStatus::IdsOk {
        return Err(KiCadError::ItemStatus {
            code: code.as_str_name().to_string(),
        });
    }

    Ok(())
}

pub(crate) fn map_item_bounding_boxes(
    item_ids: Vec<common_types::Kiid>,
    boxes: Vec<common_types::Box2>,
) -> Result<Vec<ItemBoundingBox>, KiCadError> {
    let mut mapped = Vec::with_capacity(item_ids.len().min(boxes.len()));
    for (item_id, bbox) in item_ids.into_iter().zip(boxes.into_iter()) {
        let position = bbox.position.ok_or_else(|| KiCadError::InvalidResponse {
            reason: format!("missing bounding-box position for item `{}`", item_id.value),
        })?;
        let size = bbox.size.ok_or_else(|| KiCadError::InvalidResponse {
            reason: format!("missing bounding-box size for item `{}`", item_id.value),
        })?;

        mapped.push(ItemBoundingBox {
            item_id: item_id.value,
            x_nm: position.x_nm,
            y_nm: position.y_nm,
            width_nm: size.x_nm,
            height_nm: size.y_nm,
        });
    }

    Ok(mapped)
}

pub(crate) fn map_hit_test_result(value: i32) -> ItemHitTestResult {
    let result = common_commands::HitTestResult::try_from(value)
        .unwrap_or(common_commands::HitTestResult::HtrUnknown);

    match result {
        common_commands::HitTestResult::HtrHit => ItemHitTestResult::Hit,
        common_commands::HitTestResult::HtrNoHit => ItemHitTestResult::NoHit,
        common_commands::HitTestResult::HtrUnknown => ItemHitTestResult::Unknown,
    }
}

pub(crate) fn map_run_action_status(value: i32) -> RunActionStatus {
    let status = common_commands::RunActionStatus::try_from(value)
        .unwrap_or(common_commands::RunActionStatus::RasUnknown);

    match status {
        common_commands::RunActionStatus::RasOk => RunActionStatus::Ok,
        common_commands::RunActionStatus::RasInvalid => RunActionStatus::Invalid,
        common_commands::RunActionStatus::RasFrameNotOpen => RunActionStatus::FrameNotOpen,
        common_commands::RunActionStatus::RasUnknown => RunActionStatus::Unknown(value),
    }
}

pub(crate) fn map_polygon_with_holes(
    polygon: common_types::PolygonWithHoles,
) -> Result<PolygonWithHolesNm, KiCadError> {
    Ok(PolygonWithHolesNm {
        outline: polygon.outline.map(map_polyline).transpose()?,
        holes: polygon
            .holes
            .into_iter()
            .map(map_polyline)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn map_polyline(line: common_types::PolyLine) -> Result<PolyLineNm, KiCadError> {
    Ok(PolyLineNm {
        nodes: line
            .nodes
            .into_iter()
            .map(map_polyline_node)
            .collect::<Result<Vec<_>, _>>()?,
        closed: line.closed,
    })
}

pub(crate) fn map_polyline_node(
    node: common_types::PolyLineNode,
) -> Result<PolyLineNodeGeometryNm, KiCadError> {
    match node.geometry {
        Some(common_types::poly_line_node::Geometry::Point(point)) => {
            Ok(PolyLineNodeGeometryNm::Point(map_vector2_nm(point)))
        }
        Some(common_types::poly_line_node::Geometry::Arc(arc)) => {
            let start = arc.start.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing start point".to_string(),
            })?;
            let mid = arc.mid.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing mid point".to_string(),
            })?;
            let end = arc.end.ok_or_else(|| KiCadError::InvalidResponse {
                reason: "polyline arc node missing end point".to_string(),
            })?;
            Ok(PolyLineNodeGeometryNm::Arc(ArcStartMidEndNm {
                start: map_vector2_nm(start),
                mid: map_vector2_nm(mid),
                end: map_vector2_nm(end),
            }))
        }
        None => Err(KiCadError::InvalidResponse {
            reason: "polyline node has no geometry".to_string(),
        }),
    }
}

pub(crate) fn map_vector2_nm(value: common_types::Vector2) -> Vector2Nm {
    Vector2Nm {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

pub(crate) fn vector2_nm_to_proto(value: Vector2Nm) -> common_types::Vector2 {
    common_types::Vector2 {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

pub(crate) fn decode_any<T: prost::Message + Default>(
    payload: &prost_types::Any,
    expected_type_name: &str,
) -> Result<T, KiCadError> {
    let expected_type_url = envelope::type_url(expected_type_name);
    if payload.type_url != expected_type_url {
        return Err(KiCadError::UnexpectedPayloadType {
            expected_type_url,
            actual_type_url: payload.type_url.clone(),
        });
    }

    T::decode(payload.value.as_slice()).map_err(|err| KiCadError::ProtobufDecode(err.to_string()))
}

pub(crate) fn response_payload_as_any(
    response: crate::proto::kiapi::common::ApiResponse,
    expected_type_name: &str,
) -> Result<prost_types::Any, KiCadError> {
    let payload = response.message.ok_or_else(|| KiCadError::MissingPayload {
        expected_type_url: envelope::type_url(expected_type_name),
    })?;

    let expected_type_url = envelope::type_url(expected_type_name);
    if payload.type_url != expected_type_url {
        return Err(KiCadError::UnexpectedPayloadType {
            expected_type_url,
            actual_type_url: payload.type_url,
        });
    }

    Ok(payload)
}

pub(crate) fn map_optional_distance_nm(distance: Option<common_types::Distance>) -> Option<i64> {
    distance.map(|value| value.value_nm)
}

pub(crate) fn map_optional_color(color: Option<common_types::Color>) -> Option<ColorRgba> {
    color.map(|value| ColorRgba {
        r: value.r,
        g: value.g,
        b: value.b,
        a: value.a,
    })
}

pub(crate) fn map_optional_net(net: Option<board_types::Net>) -> Option<BoardNet> {
    net.map(|value| BoardNet {
        code: value.code.map_or(0, |code| code.value),
        name: value.name,
    })
}

pub(crate) fn map_footprint(
    fp: Option<board_types::Footprint>,
    decode_pcb_item: impl Fn(prost_types::Any) -> Result<PcbItem, KiCadError>,
) -> Option<PcbFootprint> {
    fp.map(|footprint| {
        let reference = footprint
            .reference_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());
        let value = footprint
            .value_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());
        let datasheet = footprint
            .datasheet_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());
        let description = footprint
            .description_field
            .as_ref()
            .and_then(|field| field.text.as_ref())
            .and_then(|board_text| board_text.text.as_ref())
            .map(|text| text.text.clone())
            .filter(|value| !value.is_empty());

        let attributes = footprint
            .attributes
            .map(|attribute| PcbFootprintAttributes {
                description: attribute.description,
                keywords: attribute.keywords,
                not_in_schematic: attribute.not_in_schematic,
                exclude_from_position_files: attribute.exclude_from_position_files,
                exclude_from_bill_of_materials: attribute.exclude_from_bill_of_materials,
                exempt_from_courtyard_requirement: attribute.exempt_from_courtyard_requirement,
                do_not_populate: attribute.do_not_populate,
                mounting_style: attribute.mounting_style,
                allow_soldermask_bridges: attribute.allow_soldermask_bridges,
            });
        let overrides = footprint
            .overrides
            .map(|ovr| PcbFootprintDesignRuleOverrides {
                solder_mask: ovr.solder_mask.map(|mask| PcbSolderMaskOverrides {
                    solder_mask_margin_nm: map_optional_distance_nm(mask.solder_mask_margin),
                }),
                solder_paste: ovr.solder_paste.map(|paste| PcbSolderPasteOverrides {
                    solder_paste_margin_nm: map_optional_distance_nm(paste.solder_paste_margin),
                    solder_paste_margin_ratio: paste
                        .solder_paste_margin_ratio
                        .map(|ratio| ratio.value),
                }),
                copper_clearance_nm: map_optional_distance_nm(ovr.copper_clearance),
                zone_connection: ovr.zone_connection,
            });
        let net_ties = footprint
            .net_ties
            .iter()
            .map(|tie| tie.pad_number.clone())
            .collect();
        let items = footprint
            .items
            .iter()
            .flat_map(|item| decode_pcb_item(item.clone()))
            .collect();
        let jumpers = footprint.jumpers.map(|jumper| PcbJumperSettings {
            duplicate_names_are_jumpered: jumper.duplicate_names_are_jumpered,
            groups: jumper
                .groups
                .iter()
                .map(|group| group.pad_names.clone())
                .collect(),
        });

        PcbFootprint {
            id: footprint.id.as_ref().map(|id| id.entry_name.clone()),
            anchor: footprint.anchor.map(map_vector2_nm),
            attributes,
            overrides,
            net_ties,
            private_layers: footprint.private_layers,
            reference,
            value,
            datasheet,
            description,
            items,
            jumpers,
        }
    })
}

pub(crate) fn map_padstack_presence(value: i32) -> PadstackPresenceState {
    match board_commands::PadstackPresence::try_from(value) {
        Ok(board_commands::PadstackPresence::PspPresent) => PadstackPresenceState::Present,
        Ok(board_commands::PadstackPresence::PspNotPresent) => PadstackPresenceState::NotPresent,
        _ => PadstackPresenceState::Unknown(value),
    }
}

pub(crate) fn map_board_stackup_layer_type(value: i32) -> BoardStackupLayerType {
    match board_proto::BoardStackupLayerType::try_from(value) {
        Ok(board_proto::BoardStackupLayerType::BsltCopper) => BoardStackupLayerType::Copper,
        Ok(board_proto::BoardStackupLayerType::BsltDielectric) => BoardStackupLayerType::Dielectric,
        Ok(board_proto::BoardStackupLayerType::BsltSilkscreen) => BoardStackupLayerType::Silkscreen,
        Ok(board_proto::BoardStackupLayerType::BsltSoldermask) => BoardStackupLayerType::SolderMask,
        Ok(board_proto::BoardStackupLayerType::BsltSolderpaste) => {
            BoardStackupLayerType::SolderPaste
        }
        Ok(board_proto::BoardStackupLayerType::BsltUndefined) => BoardStackupLayerType::Undefined,
        _ => BoardStackupLayerType::Unknown(value),
    }
}

pub(crate) fn board_stackup_layer_type_to_proto(value: BoardStackupLayerType) -> i32 {
    match value {
        BoardStackupLayerType::Copper => board_proto::BoardStackupLayerType::BsltCopper as i32,
        BoardStackupLayerType::Dielectric => {
            board_proto::BoardStackupLayerType::BsltDielectric as i32
        }
        BoardStackupLayerType::Silkscreen => {
            board_proto::BoardStackupLayerType::BsltSilkscreen as i32
        }
        BoardStackupLayerType::SolderMask => {
            board_proto::BoardStackupLayerType::BsltSoldermask as i32
        }
        BoardStackupLayerType::SolderPaste => {
            board_proto::BoardStackupLayerType::BsltSolderpaste as i32
        }
        BoardStackupLayerType::Undefined => {
            board_proto::BoardStackupLayerType::BsltUndefined as i32
        }
        BoardStackupLayerType::Unknown(value) => value,
    }
}

pub(crate) fn map_board_layer_class(value: i32) -> BoardLayerClass {
    match board_proto::BoardLayerClass::try_from(value) {
        Ok(board_proto::BoardLayerClass::BlcSilkscreen) => BoardLayerClass::Silkscreen,
        Ok(board_proto::BoardLayerClass::BlcCopper) => BoardLayerClass::Copper,
        Ok(board_proto::BoardLayerClass::BlcEdges) => BoardLayerClass::Edges,
        Ok(board_proto::BoardLayerClass::BlcCourtyard) => BoardLayerClass::Courtyard,
        Ok(board_proto::BoardLayerClass::BlcFabrication) => BoardLayerClass::Fabrication,
        Ok(board_proto::BoardLayerClass::BlcOther) => BoardLayerClass::Other,
        _ => BoardLayerClass::Unknown(value),
    }
}

pub(crate) fn map_inactive_layer_display_mode(value: i32) -> InactiveLayerDisplayMode {
    match board_commands::InactiveLayerDisplayMode::try_from(value) {
        Ok(board_commands::InactiveLayerDisplayMode::IldmNormal) => {
            InactiveLayerDisplayMode::Normal
        }
        Ok(board_commands::InactiveLayerDisplayMode::IldmDimmed) => {
            InactiveLayerDisplayMode::Dimmed
        }
        Ok(board_commands::InactiveLayerDisplayMode::IldmHidden) => {
            InactiveLayerDisplayMode::Hidden
        }
        _ => InactiveLayerDisplayMode::Unknown(value),
    }
}

pub(crate) fn inactive_layer_display_mode_to_proto(value: InactiveLayerDisplayMode) -> i32 {
    match value {
        InactiveLayerDisplayMode::Normal => {
            board_commands::InactiveLayerDisplayMode::IldmNormal as i32
        }
        InactiveLayerDisplayMode::Dimmed => {
            board_commands::InactiveLayerDisplayMode::IldmDimmed as i32
        }
        InactiveLayerDisplayMode::Hidden => {
            board_commands::InactiveLayerDisplayMode::IldmHidden as i32
        }
        InactiveLayerDisplayMode::Unknown(value) => value,
    }
}

pub(crate) fn map_net_color_display_mode(value: i32) -> NetColorDisplayMode {
    match board_commands::NetColorDisplayMode::try_from(value) {
        Ok(board_commands::NetColorDisplayMode::NcdmAll) => NetColorDisplayMode::All,
        Ok(board_commands::NetColorDisplayMode::NcdmRatsnest) => NetColorDisplayMode::Ratsnest,
        Ok(board_commands::NetColorDisplayMode::NcdmOff) => NetColorDisplayMode::Off,
        _ => NetColorDisplayMode::Unknown(value),
    }
}

pub(crate) fn net_color_display_mode_to_proto(value: NetColorDisplayMode) -> i32 {
    match value {
        NetColorDisplayMode::All => board_commands::NetColorDisplayMode::NcdmAll as i32,
        NetColorDisplayMode::Ratsnest => board_commands::NetColorDisplayMode::NcdmRatsnest as i32,
        NetColorDisplayMode::Off => board_commands::NetColorDisplayMode::NcdmOff as i32,
        NetColorDisplayMode::Unknown(value) => value,
    }
}

pub(crate) fn map_board_flip_mode(value: i32) -> BoardFlipMode {
    match board_commands::BoardFlipMode::try_from(value) {
        Ok(board_commands::BoardFlipMode::BfmNormal) => BoardFlipMode::Normal,
        Ok(board_commands::BoardFlipMode::BfmFlippedX) => BoardFlipMode::FlippedX,
        _ => BoardFlipMode::Unknown(value),
    }
}

pub(crate) fn board_flip_mode_to_proto(value: BoardFlipMode) -> i32 {
    match value {
        BoardFlipMode::Normal => board_commands::BoardFlipMode::BfmNormal as i32,
        BoardFlipMode::FlippedX => board_commands::BoardFlipMode::BfmFlippedX as i32,
        BoardFlipMode::Unknown(value) => value,
    }
}

pub(crate) fn map_ratsnest_display_mode(value: i32) -> RatsnestDisplayMode {
    match board_commands::RatsnestDisplayMode::try_from(value) {
        Ok(board_commands::RatsnestDisplayMode::RdmAllLayers) => RatsnestDisplayMode::AllLayers,
        Ok(board_commands::RatsnestDisplayMode::RdmVisibleLayers) => {
            RatsnestDisplayMode::VisibleLayers
        }
        _ => RatsnestDisplayMode::Unknown(value),
    }
}

pub(crate) fn ratsnest_display_mode_to_proto(value: RatsnestDisplayMode) -> i32 {
    match value {
        RatsnestDisplayMode::AllLayers => board_commands::RatsnestDisplayMode::RdmAllLayers as i32,
        RatsnestDisplayMode::VisibleLayers => {
            board_commands::RatsnestDisplayMode::RdmVisibleLayers as i32
        }
        RatsnestDisplayMode::Unknown(value) => value,
    }
}

pub(crate) fn map_board_stackup(stackup: board_proto::BoardStackup) -> BoardStackup {
    let finish_type_name = stackup
        .finish
        .map(|finish| finish.type_name)
        .unwrap_or_default();
    let impedance_controlled = stackup
        .impedance
        .map(|impedance| impedance.is_controlled)
        .unwrap_or(false);
    let edge = stackup.edge.unwrap_or_default();
    let edge_has_connector = edge.connector.is_some();
    let edge_has_castellated_pads = edge
        .castellation
        .map(|value| value.has_castellated_pads)
        .unwrap_or(false);
    let edge_has_edge_plating = edge
        .plating
        .map(|value| value.has_edge_plating)
        .unwrap_or(false);

    let layers = stackup
        .layers
        .into_iter()
        .map(|layer| BoardStackupLayer {
            layer: layer_to_model(layer.layer),
            user_name: layer.user_name,
            material_name: layer.material_name,
            enabled: layer.enabled,
            thickness_nm: map_optional_distance_nm(layer.thickness),
            layer_type: map_board_stackup_layer_type(layer.r#type),
            color: map_optional_color(layer.color),
            dielectric_layers: layer
                .dielectric
                .unwrap_or_default()
                .layer
                .into_iter()
                .map(|dielectric| BoardStackupDielectricProperties {
                    epsilon_r: dielectric.epsilon_r,
                    loss_tangent: dielectric.loss_tangent,
                    material_name: dielectric.material_name,
                    thickness_nm: map_optional_distance_nm(dielectric.thickness),
                })
                .collect(),
        })
        .collect();

    BoardStackup {
        finish_type_name,
        impedance_controlled,
        edge_has_connector,
        edge_has_castellated_pads,
        edge_has_edge_plating,
        layers,
    }
}

pub(crate) fn board_stackup_to_proto(stackup: BoardStackup) -> board_proto::BoardStackup {
    board_proto::BoardStackup {
        finish: (!stackup.finish_type_name.is_empty()).then_some(board_proto::BoardFinish {
            type_name: stackup.finish_type_name,
        }),
        impedance: Some(board_proto::BoardImpedanceControl {
            is_controlled: stackup.impedance_controlled,
        }),
        edge: Some(board_proto::BoardEdgeSettings {
            connector: stackup
                .edge_has_connector
                .then_some(board_proto::BoardEdgeConnector {}),
            castellation: Some(board_proto::Castellation {
                has_castellated_pads: stackup.edge_has_castellated_pads,
            }),
            plating: Some(board_proto::EdgePlating {
                has_edge_plating: stackup.edge_has_edge_plating,
            }),
        }),
        layers: stackup
            .layers
            .into_iter()
            .map(board_stackup_layer_to_proto)
            .collect(),
    }
}

pub(crate) fn board_stackup_layer_to_proto(
    layer: BoardStackupLayer,
) -> board_proto::BoardStackupLayer {
    board_proto::BoardStackupLayer {
        thickness: layer
            .thickness_nm
            .map(|value_nm| common_types::Distance { value_nm }),
        layer: layer.layer.id,
        enabled: layer.enabled,
        r#type: board_stackup_layer_type_to_proto(layer.layer_type),
        dielectric: (!layer.dielectric_layers.is_empty()).then(|| {
            board_proto::BoardStackupDielectricLayer {
                layer: layer
                    .dielectric_layers
                    .into_iter()
                    .map(|dielectric| board_proto::BoardStackupDielectricProperties {
                        epsilon_r: dielectric.epsilon_r,
                        loss_tangent: dielectric.loss_tangent,
                        material_name: dielectric.material_name,
                        thickness: dielectric
                            .thickness_nm
                            .map(|value_nm| common_types::Distance { value_nm }),
                    })
                    .collect(),
            }
        }),
        color: layer.color.map(|color| common_types::Color {
            r: color.r,
            g: color.g,
            b: color.b,
            a: color.a,
        }),
        material_name: layer.material_name,
        user_name: layer.user_name,
    }
}

pub(crate) fn map_graphics_defaults(defaults: board_proto::GraphicsDefaults) -> GraphicsDefaults {
    GraphicsDefaults {
        layers: defaults
            .layers
            .into_iter()
            .map(|layer| {
                let text = layer.text.unwrap_or_default();
                let text_font_name = if text.font_name.is_empty() {
                    None
                } else {
                    Some(text.font_name)
                };
                BoardLayerGraphicsDefault {
                    layer_class: map_board_layer_class(layer.layer),
                    line_thickness_nm: map_optional_distance_nm(layer.line_thickness),
                    text_font_name,
                    text_size_nm: text.size.map(map_vector2_nm),
                    text_stroke_width_nm: map_optional_distance_nm(text.stroke_width),
                }
            })
            .collect(),
    }
}

pub(crate) fn map_board_editor_appearance_settings(
    settings: board_commands::BoardEditorAppearanceSettings,
) -> BoardEditorAppearanceSettings {
    BoardEditorAppearanceSettings {
        inactive_layer_display: map_inactive_layer_display_mode(settings.inactive_layer_display),
        net_color_display: map_net_color_display_mode(settings.net_color_display),
        board_flip: map_board_flip_mode(settings.board_flip),
        ratsnest_display: map_ratsnest_display_mode(settings.ratsnest_display),
    }
}

pub(crate) fn board_editor_appearance_settings_to_proto(
    settings: BoardEditorAppearanceSettings,
) -> board_commands::BoardEditorAppearanceSettings {
    board_commands::BoardEditorAppearanceSettings {
        inactive_layer_display: inactive_layer_display_mode_to_proto(
            settings.inactive_layer_display,
        ),
        net_color_display: net_color_display_mode_to_proto(settings.net_color_display),
        board_flip: board_flip_mode_to_proto(settings.board_flip),
        ratsnest_display: ratsnest_display_mode_to_proto(settings.ratsnest_display),
    }
}

pub(crate) fn net_class_type_to_proto(value: NetClassType) -> i32 {
    match value {
        NetClassType::Explicit => common_project::NetClassType::NctExplicit as i32,
        NetClassType::Implicit => common_project::NetClassType::NctImplicit as i32,
        NetClassType::Unknown(raw) => raw,
    }
}

pub(crate) fn net_class_info_to_proto(value: NetClassInfo) -> common_project::NetClass {
    let board = value
        .board
        .map(|board| common_project::NetClassBoardSettings {
            clearance: board
                .clearance_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            track_width: board
                .track_width_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_track_width: board
                .diff_pair_track_width_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_gap: board
                .diff_pair_gap_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            diff_pair_via_gap: board
                .diff_pair_via_gap_nm
                .map(|value_nm| common_types::Distance { value_nm }),
            via_stack: if board.has_via_stack {
                Some(board_types::PadStack::default())
            } else {
                None
            },
            microvia_stack: if board.has_microvia_stack {
                Some(board_types::PadStack::default())
            } else {
                None
            },
            color: board.color.map(|color| common_types::Color {
                r: color.r,
                g: color.g,
                b: color.b,
                a: color.a,
            }),
            tuning_profile: board.tuning_profile,
        });

    common_project::NetClass {
        name: value.name,
        priority: value.priority,
        board,
        schematic: None,
        r#type: net_class_type_to_proto(value.class_type),
        constituents: value.constituents,
    }
}

pub(crate) fn map_net_class_type(value: i32) -> NetClassType {
    match common_project::NetClassType::try_from(value) {
        Ok(common_project::NetClassType::NctExplicit) => NetClassType::Explicit,
        Ok(common_project::NetClassType::NctImplicit) => NetClassType::Implicit,
        _ => NetClassType::Unknown(value),
    }
}

pub(crate) fn map_net_class_info(net_class: common_project::NetClass) -> NetClassInfo {
    let board = net_class.board.map(|board| NetClassBoardSettings {
        clearance_nm: map_optional_distance_nm(board.clearance),
        track_width_nm: map_optional_distance_nm(board.track_width),
        diff_pair_track_width_nm: map_optional_distance_nm(board.diff_pair_track_width),
        diff_pair_gap_nm: map_optional_distance_nm(board.diff_pair_gap),
        diff_pair_via_gap_nm: map_optional_distance_nm(board.diff_pair_via_gap),
        color: map_optional_color(board.color),
        tuning_profile: board.tuning_profile.filter(|value| !value.is_empty()),
        has_via_stack: board.via_stack.is_some(),
        has_microvia_stack: board.microvia_stack.is_some(),
    });

    NetClassInfo {
        name: net_class.name,
        priority: net_class.priority,
        class_type: map_net_class_type(net_class.r#type),
        constituents: net_class.constituents,
        board,
    }
}

pub(crate) fn map_netclass_for_nets_response(
    response: board_commands::NetClassForNetsResponse,
) -> Vec<NetClassForNetEntry> {
    let mut rows: Vec<(String, common_project::NetClass)> = response.classes.into_iter().collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    rows.into_iter()
        .map(|(net_name, net_class)| NetClassForNetEntry {
            net_name,
            net_class: map_net_class_info(net_class),
        })
        .collect()
}

pub(crate) fn map_via_type(value: i32) -> PcbViaType {
    match board_types::ViaType::try_from(value) {
        Ok(board_types::ViaType::VtThrough) => PcbViaType::Through,
        Ok(board_types::ViaType::VtBlindBuried) => PcbViaType::BlindBuried,
        Ok(board_types::ViaType::VtMicro) => PcbViaType::Micro,
        Ok(board_types::ViaType::VtBlind) => PcbViaType::Blind,
        Ok(board_types::ViaType::VtBuried) => PcbViaType::Buried,
        _ => PcbViaType::Unknown(value),
    }
}

pub(crate) fn map_lock_state(value: i32) -> ItemLockState {
    match common_types::LockedState::try_from(value) {
        Ok(common_types::LockedState::LsUnlocked) => ItemLockState::Unlocked,
        Ok(common_types::LockedState::LsLocked) => ItemLockState::Locked,
        _ => ItemLockState::Unknown(value),
    }
}

pub(crate) fn map_padstack_drill(drill: board_types::DrillProperties) -> PcbPadstackDrill {
    let shape = board_types::DrillShape::try_from(drill.shape)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", drill.shape));
    let capped = board_types::ViaDrillCappingMode::try_from(drill.capped)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", drill.capped));
    let filled = board_types::ViaDrillFillingMode::try_from(drill.filled)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", drill.filled));

    PcbPadstackDrill {
        start_layer: layer_to_model(drill.start_layer),
        end_layer: layer_to_model(drill.end_layer),
        diameter_nm: drill.diameter.map(map_vector2_nm),
        shape: Some(shape),
        capped: Some(capped),
        filled: Some(filled),
    }
}

pub(crate) fn map_pad_stack(pad_stack: Option<&board_types::PadStack>) -> Option<PcbPadStack> {
    let pad_stack = pad_stack?;

    let stack_type = board_types::PadStackType::try_from(pad_stack.r#type)
        .map(|value| value.as_str_name().to_string())
        .unwrap_or_else(|_| format!("UNKNOWN({})", pad_stack.r#type));
    let unconnected_layer_removal =
        board_types::UnconnectedLayerRemoval::try_from(pad_stack.unconnected_layer_removal)
            .map(|value| value.as_str_name().to_string())
            .unwrap_or_else(|_| format!("UNKNOWN({})", pad_stack.unconnected_layer_removal));

    Some(PcbPadStack {
        stack_type: Some(stack_type),
        layers: pad_stack
            .layers
            .iter()
            .copied()
            .map(layer_to_model)
            .collect(),
        drill: pad_stack.drill.map(map_padstack_drill),
        unconnected_layer_removal: Some(unconnected_layer_removal),

        copper_layers: map_pad_stack_layers(&pad_stack.copper_layers),
        angle: pad_stack.angle.map(|value| value.value_degrees),
        front_outer_layers: map_pad_stack_outer_layer(pad_stack.front_outer_layers.as_ref()),
        back_outer_layers: map_pad_stack_outer_layer(pad_stack.front_outer_layers.as_ref()),
        zone_settings: map_zone_settings(pad_stack.zone_settings.as_ref()),

        copper_layer_count: pad_stack.copper_layers.len(),
        has_front_outer_layers: pad_stack.front_outer_layers.is_some(),
        has_back_outer_layers: pad_stack.back_outer_layers.is_some(),
        has_zone_settings: pad_stack.zone_settings.is_some(),

        secondary_drill: pad_stack.secondary_drill.map(map_padstack_drill),
        tertiary_drill: pad_stack.tertiary_drill.map(map_padstack_drill),
        has_front_post_machining: pad_stack.front_post_machining.is_some(),
        has_back_post_machining: pad_stack.back_post_machining.is_some(),
    })
}

pub(crate) fn decode_board_graphic_shape(
    shape: &board_types::BoardGraphicShape,
) -> PcbBoardGraphicShape {
    let geometry_kind = map_graphic_shape_kind(shape.shape.as_ref());
    let geometry = map_graphic_shape_geometry(shape.shape.as_ref());
    let stroke_width_nm = shape
        .shape
        .as_ref()
        .and_then(|graphic| graphic.attributes.as_ref())
        .and_then(|attrs| attrs.stroke.as_ref())
        .and_then(|stroke| stroke.width)
        .map(|width| width.value_nm);
    let stroke_style = shape
        .shape
        .as_ref()
        .and_then(|graphic| graphic.attributes.as_ref())
        .and_then(|attrs| attrs.stroke.as_ref())
        .map(|stroke| {
            common_types::StrokeLineStyle::try_from(stroke.style)
                .map(|value| value.as_str_name().to_string())
                .unwrap_or_else(|_| format!("UNKNOWN({})", stroke.style))
        });
    let fill_type = shape
        .shape
        .as_ref()
        .and_then(|graphic| graphic.attributes.as_ref())
        .and_then(|attrs| attrs.fill.as_ref())
        .map(|fill| {
            common_types::GraphicFillType::try_from(fill.fill_type)
                .map(|value| value.as_str_name().to_string())
                .unwrap_or_else(|_| format!("UNKNOWN({})", fill.fill_type))
        });
    PcbBoardGraphicShape {
        id: shape.id.as_ref().map(|id| id.value.clone()),
        layer: layer_to_model(shape.layer),
        locked: map_lock_state(shape.locked),
        net: map_optional_net(shape.net.clone()),
        geometry_kind,
        geometry,
        stroke_width_nm,
        stroke_style,
        fill_type,
    }
}

pub(crate) fn map_pad_stack_layers(
    pad_stack_layers: &[board_types::PadStackLayer],
) -> Vec<PcbPadStackLayer> {
    pad_stack_layers
        .iter()
        .map(|pad_stack_layer| PcbPadStackLayer {
            layer: pad_stack_layer.layer,
            shape: pad_stack_layer.shape,
            size: pad_stack_layer.size.map(map_vector2_nm),
            corner_rounding_ratio: pad_stack_layer.corner_rounding_ratio,
            chamfer_ratio: pad_stack_layer.chamfer_ratio,
            chamfered_corners: pad_stack_layer.chamfered_corners.map(|corners| {
                PcbChamferedRectCorners {
                    top_left: corners.top_left,
                    top_right: corners.top_right,
                    bottom_left: corners.bottom_left,
                    bottom_right: corners.bottom_right,
                }
            }),
            custom_shapes: pad_stack_layer
                .custom_shapes
                .iter()
                .map(decode_board_graphic_shape)
                .collect(),
            custom_anchor_shape: pad_stack_layer.custom_anchor_shape,
            zone_settings: map_zone_settings(pad_stack_layer.zone_settings.as_ref()),
            trapezoid_delta: pad_stack_layer.trapezoid_delta.map(map_vector2_nm),
            offset: pad_stack_layer.offset.map(map_vector2_nm),
        })
        .collect()
}

pub(crate) fn map_pad_stack_outer_layer(
    pad_stack_outer_layer: Option<&board_types::PadStackOuterLayer>,
) -> Option<PcbPadStackOuterLayer> {
    pad_stack_outer_layer.map(|pad_stack_outer_layer| PcbPadStackOuterLayer {
        solder_mask_mode: pad_stack_outer_layer.solder_mask_mode,
        solder_paste_mode: pad_stack_outer_layer.solder_paste_mode,
        solder_mask_settings: pad_stack_outer_layer.solder_mask_settings.map(|mask| {
            PcbSolderMaskOverrides {
                solder_mask_margin_nm: map_optional_distance_nm(mask.solder_mask_margin),
            }
        }),
        solder_paste_settings: pad_stack_outer_layer.solder_paste_settings.map(|paste| {
            PcbSolderPasteOverrides {
                solder_paste_margin_nm: map_optional_distance_nm(paste.solder_paste_margin),
                solder_paste_margin_ratio: paste.solder_paste_margin_ratio.map(|ratio| ratio.value),
            }
        }),
        plugging_mode: pad_stack_outer_layer.plugging_mode,
        covering_mode: pad_stack_outer_layer.covering_mode,
    })
}

pub(crate) fn map_zone_settings(
    zone_settings: Option<&board_types::ZoneConnectionSettings>,
) -> Option<PcbZoneConnectionSettings> {
    zone_settings.map(|zone_settings| PcbZoneConnectionSettings {
        zone_connection: zone_settings.zone_connection,
        thermal_spokes: zone_settings.thermal_spokes.map(|thermal_spokes| {
            PcbThermalSpokeSettings {
                width: map_optional_distance_nm(thermal_spokes.width),
                angle: thermal_spokes.angle.map(|angle| angle.value_degrees),
                gap: map_optional_distance_nm(thermal_spokes.gap),
            }
        }),
    })
}

pub(crate) fn map_via_layers(pad_stack: Option<&board_types::PadStack>) -> Option<PcbViaLayers> {
    let pad_stack = pad_stack?;

    let (drill_start_layer, drill_end_layer) = if let Some(drill) = pad_stack.drill.as_ref() {
        (
            Some(layer_to_model(drill.start_layer)),
            Some(layer_to_model(drill.end_layer)),
        )
    } else {
        (None, None)
    };

    Some(PcbViaLayers {
        padstack_layers: pad_stack
            .layers
            .iter()
            .copied()
            .map(layer_to_model)
            .collect(),
        drill_start_layer,
        drill_end_layer,
    })
}

pub(crate) fn map_text_attributes(
    attributes: Option<common_types::TextAttributes>,
) -> Option<PcbTextAttributes> {
    let attributes = attributes?;
    let font_name = (!attributes.font_name.is_empty()).then_some(attributes.font_name);
    let horizontal_alignment =
        common_types::HorizontalAlignment::try_from(attributes.horizontal_alignment)
            .map(|value| value.as_str_name().to_string())
            .ok();
    let vertical_alignment =
        common_types::VerticalAlignment::try_from(attributes.vertical_alignment)
            .map(|value| value.as_str_name().to_string())
            .ok();

    Some(PcbTextAttributes {
        font_name,
        horizontal_alignment,
        vertical_alignment,
        stroke_width_nm: map_optional_distance_nm(attributes.stroke_width),
        italic: attributes.italic,
        bold: attributes.bold,
        underlined: attributes.underlined,
        mirrored: attributes.mirrored,
        multiline: attributes.multiline,
        keep_upright: attributes.keep_upright,
        size_nm: attributes.size.map(map_vector2_nm),
    })
}

pub(crate) fn map_graphic_shape_kind(shape: Option<&common_types::GraphicShape>) -> Option<String> {
    let geometry = shape?.geometry.as_ref()?;
    Some(match geometry {
        common_types::graphic_shape::Geometry::Segment(_) => "SEGMENT".to_string(),
        common_types::graphic_shape::Geometry::Rectangle(_) => "RECTANGLE".to_string(),
        common_types::graphic_shape::Geometry::Arc(_) => "ARC".to_string(),
        common_types::graphic_shape::Geometry::Circle(_) => "CIRCLE".to_string(),
        common_types::graphic_shape::Geometry::Polygon(_) => "POLYGON".to_string(),
        common_types::graphic_shape::Geometry::Bezier(_) => "BEZIER".to_string(),
    })
}

pub(crate) fn map_graphic_shape_geometry(
    shape: Option<&common_types::GraphicShape>,
) -> Option<PcbGraphicShapeGeometry> {
    let geometry = shape?.geometry.as_ref()?;
    match geometry {
        common_types::graphic_shape::Geometry::Segment(segment) => {
            Some(PcbGraphicShapeGeometry::Segment {
                start_nm: segment.start.map(map_vector2_nm),
                end_nm: segment.end.map(map_vector2_nm),
            })
        }
        common_types::graphic_shape::Geometry::Rectangle(rect) => {
            Some(PcbGraphicShapeGeometry::Rectangle {
                top_left_nm: rect.top_left.map(map_vector2_nm),
                bottom_right_nm: rect.bottom_right.map(map_vector2_nm),
                corner_radius_nm: map_optional_distance_nm(rect.corner_radius),
            })
        }
        common_types::graphic_shape::Geometry::Arc(arc) => Some(PcbGraphicShapeGeometry::Arc {
            start_nm: arc.start.map(map_vector2_nm),
            mid_nm: arc.mid.map(map_vector2_nm),
            end_nm: arc.end.map(map_vector2_nm),
        }),
        common_types::graphic_shape::Geometry::Circle(circle) => {
            Some(PcbGraphicShapeGeometry::Circle {
                center_nm: circle.center.map(map_vector2_nm),
                radius_point_nm: circle.radius_point.map(map_vector2_nm),
            })
        }
        common_types::graphic_shape::Geometry::Polygon(polyset) => {
            Some(PcbGraphicShapeGeometry::Polygon {
                polygon_count: polyset.polygons.len(),
            })
        }
        common_types::graphic_shape::Geometry::Bezier(bezier) => {
            Some(PcbGraphicShapeGeometry::Bezier {
                start_nm: bezier.start.map(map_vector2_nm),
                control1_nm: bezier.control1.map(map_vector2_nm),
                control2_nm: bezier.control2.map(map_vector2_nm),
                end_nm: bezier.end.map(map_vector2_nm),
            })
        }
    }
}
