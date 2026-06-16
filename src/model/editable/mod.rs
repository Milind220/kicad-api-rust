use crate::envelope;
use crate::error::KiCadError;
use crate::model::board::Vector2Nm;
use crate::pcb_item_type_urls;
use crate::proto::kiapi::common::types as common_types;
use prost::Message;
use prost_types::Any;

mod item;
mod wrappers;

pub use item::*;
pub use wrappers::*;

/// Ergonomic typed editable board item.
#[derive(Clone, Debug, PartialEq)]
pub enum EditablePcbItem {
    /// Track item.
    Track(TrackItem),
    /// Arc item.
    Arc(ArcItem),
    /// Via item.
    Via(ViaItem),
    /// Footprint instance item.
    FootprintInstance(FootprintInstanceItem),
    /// Pad item.
    Pad(PadItem),
    /// Board graphic shape item.
    BoardGraphicShape(BoardGraphicShapeItem),
    /// Board text item.
    BoardText(BoardTextItem),
    /// Board text box item.
    BoardTextBox(BoardTextBoxItem),
    /// Field item.
    Field(FieldItem),
    /// Zone item.
    Zone(ZoneItem),
    /// Dimension item.
    Dimension(DimensionItem),
    /// Group item.
    Group(GroupItem),
    /// Reference image item.
    ReferenceImage(ReferenceImageItem),
    /// Barcode item.
    Barcode(BarcodeItem),
    /// Unknown payload preserved as-is.
    Unknown(RawPcbItem),
}
impl EditablePcbItem {
    /// Decodes a raw protobuf payload into a typed editable PCB item.
    pub fn from_any(raw: Any) -> Result<Self, KiCadError> {
        let type_url = raw.type_url.clone();

        if type_url == envelope::type_url(pcb_item_type_urls::TRACK) {
            return Ok(Self::Track(TrackItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::TRACK,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::ARC) {
            return Ok(Self::Arc(ArcItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::ARC,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::VIA) {
            return Ok(Self::Via(ViaItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::VIA,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::FOOTPRINT_INSTANCE) {
            return Ok(Self::FootprintInstance(FootprintInstanceItem::from_proto(
                decode_item(&raw, pcb_item_type_urls::FOOTPRINT_INSTANCE)?,
            )));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::PAD) {
            return Ok(Self::Pad(PadItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::PAD,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::BOARD_GRAPHIC_SHAPE) {
            return Ok(Self::BoardGraphicShape(BoardGraphicShapeItem::from_proto(
                decode_item(&raw, pcb_item_type_urls::BOARD_GRAPHIC_SHAPE)?,
            )));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::BOARD_TEXT) {
            return Ok(Self::BoardText(BoardTextItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::BOARD_TEXT,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::BOARD_TEXT_BOX) {
            return Ok(Self::BoardTextBox(BoardTextBoxItem::from_proto(
                decode_item(&raw, pcb_item_type_urls::BOARD_TEXT_BOX)?,
            )));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::FIELD) {
            return Ok(Self::Field(FieldItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::FIELD,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::ZONE) {
            return Ok(Self::Zone(ZoneItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::ZONE,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::DIMENSION) {
            return Ok(Self::Dimension(DimensionItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::DIMENSION,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::GROUP) {
            return Ok(Self::Group(GroupItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::GROUP,
            )?)));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::REFERENCE_IMAGE) {
            return Ok(Self::ReferenceImage(ReferenceImageItem::from_proto(
                decode_item(&raw, pcb_item_type_urls::REFERENCE_IMAGE)?,
            )));
        }
        if type_url == envelope::type_url(pcb_item_type_urls::BARCODE) {
            return Ok(Self::Barcode(BarcodeItem::from_proto(decode_item(
                &raw,
                pcb_item_type_urls::BARCODE,
            )?)));
        }

        Ok(Self::Unknown(RawPcbItem { raw }))
    }
    /// Converts this editable item into a raw protobuf payload.
    pub fn into_any(self) -> Any {
        match self {
            Self::Track(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::TRACK),
            Self::Arc(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::ARC),
            Self::Via(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::VIA),
            Self::FootprintInstance(item) => {
                envelope::pack_any(&item.proto, pcb_item_type_urls::FOOTPRINT_INSTANCE)
            }
            Self::Pad(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::PAD),
            Self::BoardGraphicShape(item) => {
                envelope::pack_any(&item.proto, pcb_item_type_urls::BOARD_GRAPHIC_SHAPE)
            }
            Self::BoardText(item) => {
                envelope::pack_any(&item.proto, pcb_item_type_urls::BOARD_TEXT)
            }
            Self::BoardTextBox(item) => {
                envelope::pack_any(&item.proto, pcb_item_type_urls::BOARD_TEXT_BOX)
            }
            Self::Field(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::FIELD),
            Self::Zone(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::ZONE),
            Self::Dimension(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::DIMENSION),
            Self::Group(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::GROUP),
            Self::ReferenceImage(item) => {
                envelope::pack_any(&item.proto, pcb_item_type_urls::REFERENCE_IMAGE)
            }
            Self::Barcode(item) => envelope::pack_any(&item.proto, pcb_item_type_urls::BARCODE),
            Self::Unknown(item) => item.raw,
        }
    }
    /// Clones and returns this item as a raw protobuf payload.
    pub fn as_any(&self) -> Any {
        self.clone().into_any()
    }

    /// Returns the item kind.
    pub fn kind(&self) -> EditablePcbItemKind {
        match self {
            Self::Track(_) => EditablePcbItemKind::Track,
            Self::Arc(_) => EditablePcbItemKind::Arc,
            Self::Via(_) => EditablePcbItemKind::Via,
            Self::FootprintInstance(_) => EditablePcbItemKind::FootprintInstance,
            Self::Pad(_) => EditablePcbItemKind::Pad,
            Self::BoardGraphicShape(_) => EditablePcbItemKind::BoardGraphicShape,
            Self::BoardText(_) => EditablePcbItemKind::BoardText,
            Self::BoardTextBox(_) => EditablePcbItemKind::BoardTextBox,
            Self::Field(_) => EditablePcbItemKind::Field,
            Self::Zone(_) => EditablePcbItemKind::Zone,
            Self::Dimension(_) => EditablePcbItemKind::Dimension,
            Self::Group(_) => EditablePcbItemKind::Group,
            Self::ReferenceImage(_) => EditablePcbItemKind::ReferenceImage,
            Self::Barcode(_) => EditablePcbItemKind::Barcode,
            Self::Unknown(_) => EditablePcbItemKind::Unknown,
        }
    }
    /// Returns the KIID-based item id when the underlying proto has one.
    ///
    /// For `Field`, this intentionally returns `None` because fields use `FieldId`
    /// instead of a KIID and should not be exposed as fake KIID references.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Track(item) => item.id(),
            Self::Arc(item) => item.id(),
            Self::Via(item) => item.id(),
            Self::FootprintInstance(item) => item.id(),
            Self::Pad(item) => item.id(),
            Self::BoardGraphicShape(item) => item.id(),
            Self::BoardText(item) => item.id(),
            Self::BoardTextBox(item) => item.id(),
            Self::Field(_) => None,
            Self::Zone(item) => item.id(),
            Self::Dimension(item) => item.id(),
            Self::Group(item) => item.id(),
            Self::ReferenceImage(item) => item.id(),
            Self::Barcode(item) => item.id(),
            Self::Unknown(_) => None,
        }
    }
    /// Returns layer-set semantics for this item.
    pub fn layer_set(&self) -> LayerSet {
        match self {
            Self::Track(item) => LayerSet::Single(item.layer_id()),
            Self::Arc(item) => LayerSet::Single(item.layer_id()),
            Self::Via(_) => LayerSet::Padstack,
            Self::FootprintInstance(item) => LayerSet::Single(item.layer_id()),
            Self::Pad(_) => LayerSet::Padstack,
            Self::BoardGraphicShape(item) => LayerSet::Single(item.layer_id()),
            Self::BoardText(item) => LayerSet::Single(item.layer_id()),
            Self::BoardTextBox(item) => LayerSet::Single(item.layer_id()),
            Self::Field(item) => item
                .text()
                .map(|text| LayerSet::Single(text.layer))
                .unwrap_or(LayerSet::None),
            Self::Zone(item) => LayerSet::Multi(item.proto.layers.clone()),
            Self::Dimension(item) => LayerSet::Single(item.layer_id()),
            Self::Group(_) => LayerSet::None,
            Self::ReferenceImage(item) => LayerSet::Single(item.layer_id()),
            Self::Barcode(item) => LayerSet::Single(item.layer_id()),
            Self::Unknown(_) => LayerSet::None,
        }
    }
    /// Attempts to set the layer id for single-layer items.
    pub fn set_layer_id(&mut self, layer_id: i32) -> Result<(), KiCadError> {
        match self {
            Self::Track(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::Arc(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::FootprintInstance(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::BoardGraphicShape(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::BoardText(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::BoardTextBox(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::Field(item) => item.set_layer_id(layer_id),
            Self::Dimension(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::ReferenceImage(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::Barcode(item) => {
                item.set_layer_id(layer_id);
                Ok(())
            }
            Self::Via(_) => unsupported_set_layer("via"),
            Self::Pad(_) => unsupported_set_layer("pad"),
            Self::Zone(_) => unsupported_set_layer("zone"),
            Self::Group(_) => unsupported_set_layer("group"),
            Self::Unknown(_) => unsupported_set_layer("unknown"),
        }
    }
    /// Attempts to replace layer ids for multi-layer items.
    pub fn set_layer_ids(&mut self, layer_ids: Vec<i32>) -> Result<(), KiCadError> {
        match self {
            Self::Zone(item) => {
                item.set_layer_ids(layer_ids);
                Ok(())
            }
            _ => Err(KiCadError::InvalidResponse {
                reason: format!("set_layer_ids is not supported for {:?} items", self.kind()),
            }),
        }
    }
}

impl TryFrom<Any> for EditablePcbItem {
    type Error = KiCadError;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        Self::from_any(value)
    }
}

impl From<EditablePcbItem> for Any {
    fn from(value: EditablePcbItem) -> Self {
        value.into_any()
    }
}

fn decode_item<T: Message + Default>(raw: &Any, type_name: &str) -> Result<T, KiCadError> {
    T::decode(raw.value.as_slice()).map_err(|err| {
        KiCadError::ProtobufDecode(format!(
            "failed decoding `{}` from `{}`: {}",
            type_name, raw.type_url, err
        ))
    })
}

fn vector2_to_proto(value: Vector2Nm) -> common_types::Vector2 {
    common_types::Vector2 {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

fn vector2_from_proto(value: common_types::Vector2) -> Vector2Nm {
    Vector2Nm {
        x_nm: value.x_nm,
        y_nm: value.y_nm,
    }
}

fn kiid_value(kiid: &Option<common_types::Kiid>) -> Option<&str> {
    kiid.as_ref().map(|id| id.value.as_str())
}

fn unsupported_set_layer(item_kind: &str) -> Result<(), KiCadError> {
    Err(KiCadError::InvalidResponse {
        reason: format!("set_layer_id is not supported for {item_kind} items"),
    })
}

#[cfg(test)]
mod tests;
