use crate::error::KiCadError;
use crate::model::board::Vector2Nm;
use crate::proto::kiapi::{board::types as board_types, common::types as common_types};

use super::{kiid_value, vector2_from_proto, vector2_to_proto};

macro_rules! impl_proto_wrapper {
    ($name:ident, $proto:ty) => {
        #[derive(Clone, Debug, PartialEq)]
        /// Typed editable PCB item wrapper preserving the full protobuf payload.
        pub struct $name {
            pub(super) proto: $proto,
        }

        impl $name {
            /// Wraps a decoded protobuf item.
            pub fn from_proto(proto: $proto) -> Self {
                Self { proto }
            }

            /// Returns the underlying protobuf payload.
            ///
            /// Advanced escape hatch: most callers should prefer typed helper
            /// methods on wrapper structs and [`super::EditablePcbItem`].
            pub fn proto(&self) -> &$proto {
                &self.proto
            }

            /// Returns a mutable reference to the underlying protobuf payload.
            ///
            /// Advanced escape hatch: this bypasses typed invariants enforced by
            /// helper setters, so prefer typed methods when available.
            pub fn proto_mut(&mut self) -> &mut $proto {
                &mut self.proto
            }

            /// Consumes this wrapper and returns the underlying protobuf payload.
            ///
            /// Advanced escape hatch for low-level IPC interop.
            pub fn into_proto(self) -> $proto {
                self.proto
            }
        }
    };
}

impl_proto_wrapper!(TrackItem, board_types::Track);
impl_proto_wrapper!(ArcItem, board_types::Arc);
impl_proto_wrapper!(ViaItem, board_types::Via);
impl_proto_wrapper!(FootprintInstanceItem, board_types::FootprintInstance);
impl_proto_wrapper!(PadItem, board_types::Pad);
impl_proto_wrapper!(BoardGraphicShapeItem, board_types::BoardGraphicShape);
impl_proto_wrapper!(BoardTextItem, board_types::BoardText);
impl_proto_wrapper!(BoardTextBoxItem, board_types::BoardTextBox);
impl_proto_wrapper!(FieldItem, board_types::Field);
impl_proto_wrapper!(ZoneItem, board_types::Zone);
impl_proto_wrapper!(DimensionItem, board_types::Dimension);
impl_proto_wrapper!(GroupItem, board_types::Group);
impl_proto_wrapper!(ReferenceImageItem, board_types::ReferenceImage);
impl_proto_wrapper!(BarcodeItem, board_types::Barcode);
impl TrackItem {
    /// Returns the track KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the track layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the track layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }

    /// Returns the start point in nanometers, if present.
    pub fn start_nm(&self) -> Option<Vector2Nm> {
        self.proto.start.map(vector2_from_proto)
    }

    /// Returns the end point in nanometers, if present.
    pub fn end_nm(&self) -> Option<Vector2Nm> {
        self.proto.end.map(vector2_from_proto)
    }

    /// Sets the start point.
    pub fn set_start_nm(&mut self, value: Vector2Nm) {
        self.proto.start = Some(vector2_to_proto(value));
    }

    /// Sets the end point.
    pub fn set_end_nm(&mut self, value: Vector2Nm) {
        self.proto.end = Some(vector2_to_proto(value));
    }
}

impl ArcItem {
    /// Returns the arc KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the arc layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the arc layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }

    /// Returns the start point in nanometers, if present.
    pub fn start_nm(&self) -> Option<Vector2Nm> {
        self.proto.start.map(vector2_from_proto)
    }

    /// Returns the midpoint in nanometers, if present.
    pub fn mid_nm(&self) -> Option<Vector2Nm> {
        self.proto.mid.map(vector2_from_proto)
    }

    /// Returns the end point in nanometers, if present.
    pub fn end_nm(&self) -> Option<Vector2Nm> {
        self.proto.end.map(vector2_from_proto)
    }

    /// Sets the start point.
    pub fn set_start_nm(&mut self, value: Vector2Nm) {
        self.proto.start = Some(vector2_to_proto(value));
    }

    /// Sets the midpoint.
    pub fn set_mid_nm(&mut self, value: Vector2Nm) {
        self.proto.mid = Some(vector2_to_proto(value));
    }

    /// Sets the end point.
    pub fn set_end_nm(&mut self, value: Vector2Nm) {
        self.proto.end = Some(vector2_to_proto(value));
    }
}

impl ViaItem {
    /// Returns the via KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the via position in nanometers, if present.
    pub fn position_nm(&self) -> Option<Vector2Nm> {
        self.proto.position.map(vector2_from_proto)
    }

    /// Sets via position.
    pub fn set_position_nm(&mut self, value: Vector2Nm) {
        self.proto.position = Some(vector2_to_proto(value));
    }
}

impl FootprintInstanceItem {
    /// Returns the footprint KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the footprint layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the footprint layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl PadItem {
    /// Returns the pad KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }
}

impl BoardGraphicShapeItem {
    /// Returns the shape KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the shape layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the shape layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl BoardTextItem {
    /// Returns the text KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the text layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the text layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl BoardTextBoxItem {
    /// Returns the text box KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the text box layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the text box layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl FieldItem {
    /// Returns the field id value, if present.
    pub fn field_id(&self) -> Option<i32> {
        self.proto.id.map(|id| id.id)
    }

    /// Returns nested board text, if present.
    pub fn text(&self) -> Option<&board_types::BoardText> {
        self.proto.text.as_ref()
    }

    /// Returns mutable nested board text, if present.
    pub fn text_mut(&mut self) -> Option<&mut board_types::BoardText> {
        self.proto.text.as_mut()
    }

    /// Sets the layer id on the nested board text.
    pub fn set_layer_id(&mut self, layer_id: i32) -> Result<(), KiCadError> {
        let text = self
            .proto
            .text
            .as_mut()
            .ok_or_else(|| KiCadError::InvalidResponse {
                reason: "field has no nested board text; cannot set layer".to_string(),
            })?;
        text.layer = layer_id;
        Ok(())
    }
}

impl ZoneItem {
    /// Returns the zone KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the zone layer ids.
    pub fn layer_ids(&self) -> &[i32] {
        &self.proto.layers
    }

    /// Replaces the zone layer ids.
    pub fn set_layer_ids(&mut self, layer_ids: Vec<i32>) {
        self.proto.layers = layer_ids;
    }
}

impl DimensionItem {
    /// Returns the dimension KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the dimension layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the dimension layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl GroupItem {
    /// Builds a new group with no id and the provided member KIID values.
    pub fn new(name: impl Into<String>, member_ids: Vec<String>) -> Self {
        Self {
            proto: board_types::Group {
                id: None,
                name: name.into(),
                items: member_ids
                    .into_iter()
                    .map(|value| common_types::Kiid { value })
                    .collect(),
            },
        }
    }

    /// Returns the group KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns member KIID values.
    pub fn member_ids(&self) -> Vec<&str> {
        self.proto
            .items
            .iter()
            .map(|item| item.value.as_str())
            .collect()
    }

    /// Returns the group name.
    pub fn name(&self) -> &str {
        &self.proto.name
    }

    /// Sets the group name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.proto.name = name.into();
    }

    /// Replaces the member KIID values.
    pub fn set_member_ids(&mut self, member_ids: Vec<String>) {
        self.proto.items = member_ids
            .into_iter()
            .map(|value| common_types::Kiid { value })
            .collect();
    }
}

impl ReferenceImageItem {
    /// Returns the reference image KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the reference image layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the reference image layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}

impl BarcodeItem {
    /// Returns the barcode KIID value.
    pub fn id(&self) -> Option<&str> {
        kiid_value(&self.proto.id)
    }

    /// Returns the barcode layer id.
    pub fn layer_id(&self) -> i32 {
        self.proto.layer
    }

    /// Sets the barcode layer id.
    pub fn set_layer_id(&mut self, layer_id: i32) {
        self.proto.layer = layer_id;
    }
}
