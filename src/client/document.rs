//! Document operations: save, revert, title block, and string serialization.

use super::decode::decode_pcb_items;
use super::mappers::*;
use super::{
    KiCadClient, CMD_GET_ITEMS_BY_ID, CMD_GET_TITLE_BLOCK_INFO, CMD_REVERT_DOCUMENT,
    CMD_SAVE_COPY_OF_DOCUMENT, CMD_SAVE_DOCUMENT, CMD_SAVE_DOCUMENT_TO_STRING,
    CMD_SAVE_SELECTION_TO_STRING, CMD_SET_TITLE_BLOCK_INFO, RES_GET_ITEMS_RESPONSE,
    RES_PROTOBUF_EMPTY, RES_SAVED_DOCUMENT_RESPONSE, RES_SAVED_SELECTION_RESPONSE,
    RES_TITLE_BLOCK_INFO,
};
use crate::envelope;
use crate::error::KiCadError;
use crate::model::board::*;
use crate::model::common::*;
use crate::model::editable::*;
use crate::proto::kiapi::common::commands as common_commands;
use crate::proto::kiapi::common::types as common_types;
impl KiCadClient {
    /// Reads title block metadata from the active PCB document.
    ///
    /// `TitleBlockInfo::comments` preserves fixed `comment1..comment9` slot
    /// ordering, including internal empty gaps, and trims only trailing empty
    /// slots from the returned vector.
    pub async fn get_title_block_info(&self) -> Result<TitleBlockInfo, KiCadError> {
        let command = common_commands::GetTitleBlockInfo {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_TITLE_BLOCK_INFO))
            .await?;
        let payload: common_types::TitleBlockInfo =
            envelope::unpack_any(&response, RES_TITLE_BLOCK_INFO)?;

        Ok(title_block_info_from_proto(payload))
    }

    /// Sets title block metadata on the active PCB document and returns raw operation payload.
    pub async fn set_title_block_info_raw(
        &self,
        title_block: TitleBlockInfo,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SetTitleBlockInfo {
            document: Some(self.current_board_document_proto().await?),
            title_block: Some(title_block_info_to_proto(title_block)),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SET_TITLE_BLOCK_INFO))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    /// Sets title block metadata on the active PCB document.
    ///
    /// `TitleBlockInfo::comments` is interpreted as fixed `comment1..comment9`
    /// slots in order. Internal empty slots are preserved; values beyond slot 9
    /// are ignored.
    pub async fn set_title_block_info(
        &self,
        title_block: TitleBlockInfo,
    ) -> Result<(), KiCadError> {
        let _ = self.set_title_block_info_raw(title_block).await?;
        Ok(())
    }

    /// Saves the active PCB document and returns the raw operation payload.
    pub async fn save_document_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SaveDocument {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    /// Saves the active PCB document.
    pub async fn save_document(&self) -> Result<(), KiCadError> {
        let _ = self.save_document_raw().await?;
        Ok(())
    }

    /// Saves a copy of the active PCB document and returns raw operation payload.
    pub async fn save_copy_of_document_raw(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::SaveCopyOfDocument {
            document: Some(self.current_board_document_proto().await?),
            path: path.into(),
            options: Some(common_commands::SaveOptions {
                overwrite,
                include_project,
            }),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_COPY_OF_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    /// Saves a copy of the active PCB document.
    pub async fn save_copy_of_document(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<(), KiCadError> {
        let _ = self
            .save_copy_of_document_raw(path, overwrite, include_project)
            .await?;
        Ok(())
    }

    /// Reverts unsaved changes in the active PCB document and returns raw payload.
    pub async fn revert_document_raw(&self) -> Result<prost_types::Any, KiCadError> {
        let command = common_commands::RevertDocument {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_REVERT_DOCUMENT))
            .await?;
        response_payload_as_any(response, RES_PROTOBUF_EMPTY)
    }

    /// Reverts unsaved changes in the active PCB document.
    pub async fn revert_document(&self) -> Result<(), KiCadError> {
        let _ = self.revert_document_raw().await?;
        Ok(())
    }

    /// Serializes the active PCB document to KiCad's string format.
    pub async fn get_board_as_string(&self) -> Result<String, KiCadError> {
        let command = common_commands::SaveDocumentToString {
            document: Some(self.current_board_document_proto().await?),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_DOCUMENT_TO_STRING))
            .await?;
        let payload: common_commands::SavedDocumentResponse =
            envelope::unpack_any(&response, RES_SAVED_DOCUMENT_RESPONSE)?;
        Ok(payload.contents)
    }

    /// Serializes current selection to KiCad's string format.
    pub async fn get_selection_as_string(&self) -> Result<SelectionStringDump, KiCadError> {
        let command = common_commands::SaveSelectionToString {};

        let response = self
            .send_command(envelope::pack_any(&command, CMD_SAVE_SELECTION_TO_STRING))
            .await?;
        let payload: common_commands::SavedSelectionResponse =
            envelope::unpack_any(&response, RES_SAVED_SELECTION_RESPONSE)?;
        Ok(SelectionStringDump {
            ids: payload.ids.into_iter().map(|id| id.value).collect(),
            contents: payload.contents,
        })
    }

    /// Fetches items by id and returns raw protobuf payloads.
    pub async fn get_items_by_id_raw(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<prost_types::Any>, KiCadError> {
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }

        let command = common_commands::GetItemsById {
            header: Some(self.current_board_item_header().await?),
            items: item_ids
                .into_iter()
                .map(|id| common_types::Kiid { value: id })
                .collect(),
        };

        let response = self
            .send_command(envelope::pack_any(&command, CMD_GET_ITEMS_BY_ID))
            .await?;

        let payload: common_commands::GetItemsResponse =
            envelope::unpack_any(&response, RES_GET_ITEMS_RESPONSE)?;

        ensure_item_request_ok(payload.status)?;
        Ok(payload.items)
    }

    /// Fetches items by id and returns lightweight decoded detail rows.
    pub async fn get_items_by_id_details(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<SelectionItemDetail>, KiCadError> {
        let items = self.get_items_by_id_raw(item_ids).await?;
        summarize_item_details(items)
    }

    /// Fetches editable items by id using raw IPC item payloads.
    ///
    /// This is an ergonomic wrapper around [`KiCadClient::get_items_by_id_raw`]
    /// that preserves payloads as editable items for mutate/update workflows.
    ///
    /// Falls back to a broader type-code fetch + client-side KIID filter when
    /// the running KiCad reports `AS_UNHANDLED` for the `GetItemsById`
    /// command (observed on KiCad 10.0.0 builds where the targeted lookup
    /// handler is not registered). All other API errors propagate normally.
    pub async fn get_editable_items_by_id(
        &self,
        item_ids: Vec<String>,
    ) -> Result<Vec<EditablePcbItem>, KiCadError> {
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }

        match self.get_items_by_id_raw(item_ids.clone()).await {
            Ok(items) => items.into_iter().map(EditablePcbItem::try_from).collect(),
            Err(err) if super::is_get_items_by_id_unhandled(&err) => {
                self.get_editable_items_by_id_via_type_codes(&item_ids)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    /// Fallback for [`KiCadClient::get_editable_items_by_id`] when the
    /// `GetItemsById` IPC command is unavailable on the running KiCad.
    ///
    /// Fetches every known PCB item type via `GetItems` and filters
    /// client-side by KIID. This path is broader than `GetItemsById`
    /// (it traverses every item on the board) and is only used when the
    /// targeted lookup is unsupported.
    async fn get_editable_items_by_id_via_type_codes(
        &self,
        item_ids: &[String],
    ) -> Result<Vec<EditablePcbItem>, KiCadError> {
        let type_codes: Vec<i32> = super::PCB_OBJECT_TYPES
            .iter()
            .map(|object_type| object_type.code)
            .collect();
        let items = self.get_editable_items_by_type_codes(type_codes).await?;
        Ok(filter_editable_items_by_kiid(items, item_ids))
    }
    /// Fetches and decodes items by KiCad item id.
    pub async fn get_items_by_id(&self, item_ids: Vec<String>) -> Result<Vec<PcbItem>, KiCadError> {
        let items = self.get_items_by_id_raw(item_ids).await?;
        decode_pcb_items(items)
    }
}

fn title_block_info_from_proto(payload: common_types::TitleBlockInfo) -> TitleBlockInfo {
    let mut comments = vec![
        payload.comment1,
        payload.comment2,
        payload.comment3,
        payload.comment4,
        payload.comment5,
        payload.comment6,
        payload.comment7,
        payload.comment8,
        payload.comment9,
    ];

    while comments.last().is_some_and(|comment| comment.is_empty()) {
        comments.pop();
    }

    TitleBlockInfo {
        title: payload.title,
        date: payload.date,
        revision: payload.revision,
        company: payload.company,
        comments,
    }
}
fn title_block_info_to_proto(title_block: TitleBlockInfo) -> common_types::TitleBlockInfo {
    let mut comments = title_block.comments;
    comments.truncate(9);

    common_types::TitleBlockInfo {
        title: title_block.title,
        date: title_block.date,
        revision: title_block.revision,
        company: title_block.company,
        comment1: comments.first().cloned().unwrap_or_default(),
        comment2: comments.get(1).cloned().unwrap_or_default(),
        comment3: comments.get(2).cloned().unwrap_or_default(),
        comment4: comments.get(3).cloned().unwrap_or_default(),
        comment5: comments.get(4).cloned().unwrap_or_default(),
        comment6: comments.get(5).cloned().unwrap_or_default(),
        comment7: comments.get(6).cloned().unwrap_or_default(),
        comment8: comments.get(7).cloned().unwrap_or_default(),
        comment9: comments.get(8).cloned().unwrap_or_default(),
    }
}

/// Filters a collection of editable PCB items down to those whose KIID
/// matches one of the supplied wanted ids.
///
/// Items with no KIID (e.g. `Field`, `Unknown`) are dropped. The relative
/// order of matching items is preserved from the input vector.
pub(crate) fn filter_editable_items_by_kiid(
    items: Vec<EditablePcbItem>,
    wanted_ids: &[String],
) -> Vec<EditablePcbItem> {
    let wanted: std::collections::HashSet<&str> = wanted_ids.iter().map(String::as_str).collect();
    items
        .into_iter()
        .filter(|item| item.id().is_some_and(|id| wanted.contains(id)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{title_block_info_from_proto, title_block_info_to_proto};
    use crate::model::common::TitleBlockInfo;
    use crate::proto::kiapi::common::types as common_types;

    #[test]
    fn title_block_preserves_internal_comment_gaps() {
        let title_block = TitleBlockInfo {
            title: "Demo".to_string(),
            date: "2026-04-26".to_string(),
            revision: "A".to_string(),
            company: "Acme".to_string(),
            comments: vec!["first".to_string(), "".to_string(), "third".to_string()],
        };

        let proto = title_block_info_to_proto(title_block.clone());
        assert_eq!(proto.comment1, "first");
        assert_eq!(proto.comment2, "");
        assert_eq!(proto.comment3, "third");

        let mapped = title_block_info_from_proto(proto);
        assert_eq!(mapped, title_block);
    }

    #[test]
    fn title_block_trims_trailing_empty_comment_slots_from_public_vec() {
        let proto = common_types::TitleBlockInfo {
            comment1: "c1".to_string(),
            comment2: "".to_string(),
            comment3: "c3".to_string(),
            comment4: "".to_string(),
            comment5: "".to_string(),
            comment6: "".to_string(),
            comment7: "".to_string(),
            comment8: "".to_string(),
            comment9: "".to_string(),
            ..common_types::TitleBlockInfo::default()
        };

        let mapped = title_block_info_from_proto(proto);
        assert_eq!(mapped.comments, vec!["c1", "", "c3"]);
    }

    #[test]
    fn title_block_to_proto_truncates_to_nine_comment_slots() {
        let title_block = TitleBlockInfo {
            title: String::new(),
            date: String::new(),
            revision: String::new(),
            company: String::new(),
            comments: (1..=11).map(|idx| format!("c{idx}")).collect(),
        };

        let proto = title_block_info_to_proto(title_block);
        assert_eq!(proto.comment1, "c1");
        assert_eq!(proto.comment8, "c8");
        assert_eq!(proto.comment9, "c9");
    }
}
