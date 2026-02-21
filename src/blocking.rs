use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use prost_types::Any;

use crate::client::{ClientBuilder, KiCadClient};
use crate::error::KiCadError;
use crate::model::board::*;
use crate::model::common::*;

const BLOCKING_QUEUE_CAPACITY: usize = 64;

type Job = Box<dyn FnOnce(&tokio::runtime::Runtime) + Send + 'static>;

#[derive(Debug)]
struct BlockingCore {
    job_tx: Mutex<Option<SyncSender<Job>>>,
    worker_thread_id: ThreadId,
    worker_join: Mutex<Option<JoinHandle<()>>>,
}

impl BlockingCore {
    fn start() -> Result<Arc<Self>, KiCadError> {
        let (job_tx, job_rx) = mpsc::sync_channel::<Job>(BLOCKING_QUEUE_CAPACITY);
        let (init_tx, init_rx) = mpsc::sync_channel::<Result<ThreadId, KiCadError>>(1);

        let worker_name = format!("kicad-ipc-blocking-runtime-{}", std::process::id());
        let worker_join = thread::Builder::new()
            .name(worker_name)
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = init_tx.send(Err(KiCadError::RuntimeJoin(err.to_string())));
                        return;
                    }
                };

                let _ = init_tx.send(Ok(thread::current().id()));

                for job in job_rx {
                    job(&runtime);
                }
            })
            .map_err(|err| KiCadError::RuntimeJoin(err.to_string()))?;

        let worker_thread_id = init_rx
            .recv()
            .map_err(|_| KiCadError::BlockingRuntimeClosed)??;

        Ok(Arc::new(Self {
            job_tx: Mutex::new(Some(job_tx)),
            worker_thread_id,
            worker_join: Mutex::new(Some(worker_join)),
        }))
    }

    fn shutdown(&self) {
        if let Ok(mut tx_guard) = self.job_tx.lock() {
            tx_guard.take();
        }

        let handle = match self.worker_join.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        };

        if let Some(handle) = handle {
            if thread::current().id() != self.worker_thread_id {
                let _ = handle.join();
            }
        }
    }

    fn call<T, F>(&self, f: F) -> Result<T, KiCadError>
    where
        T: Send + 'static,
        F: FnOnce(&tokio::runtime::Runtime) -> Result<T, KiCadError> + Send + 'static,
    {
        let sender = {
            let guard = self
                .job_tx
                .lock()
                .map_err(|_| KiCadError::BlockingRuntimeClosed)?;
            guard
                .as_ref()
                .cloned()
                .ok_or(KiCadError::BlockingRuntimeClosed)?
        };

        let (result_tx, result_rx) = mpsc::sync_channel::<Result<T, KiCadError>>(1);

        sender
            .send(Box::new(move |runtime| {
                let result = f(runtime);
                let _ = result_tx.send(result);
            }))
            .map_err(|_| KiCadError::BlockingRuntimeClosed)?;

        result_rx
            .recv()
            .map_err(|_| KiCadError::BlockingRuntimeClosed)?
    }
}

impl Drop for BlockingCore {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Clone, Debug)]
pub struct KiCadClientBlocking {
    inner: KiCadClient,
    core: Arc<BlockingCore>,
}

#[derive(Clone, Debug)]
pub struct KiCadClientBlockingBuilder {
    inner: ClientBuilder,
}

impl KiCadClientBlockingBuilder {
    pub fn new() -> Self {
        Self {
            inner: ClientBuilder::new(),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn socket_path(mut self, socket_path: impl Into<String>) -> Self {
        self.inner = self.inner.socket_path(socket_path);
        self
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.inner = self.inner.token(token);
        self
    }

    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.inner = self.inner.client_name(client_name);
        self
    }

    pub fn connect(self) -> Result<KiCadClientBlocking, KiCadError> {
        let core = BlockingCore::start()?;
        let inner_builder = self.inner;
        let inner = core.call(move |runtime| runtime.block_on(inner_builder.connect()))?;

        Ok(KiCadClientBlocking { inner, core })
    }
}

impl Default for KiCadClientBlockingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! blocking_methods {
    (
        $(fn $name:ident(&self $(, $arg:ident : $arg_ty:ty)*) -> $ret:ty;)+
    ) => {
        $(
            pub fn $name(&self, $($arg: $arg_ty),*) -> $ret {
                let client = self.inner.clone();
                self.core.call(move |runtime| runtime.block_on(async move {
                    client.$name($($arg),*).await
                }))
            }
        )+

        #[cfg(test)]
        pub(crate) const GENERATED_BLOCKING_METHOD_NAMES: &'static [&'static str] = &[
            $(stringify!($name),)+
        ];
    };
}

impl KiCadClientBlocking {
    pub fn builder() -> KiCadClientBlockingBuilder {
        KiCadClientBlockingBuilder::new()
    }

    pub fn connect() -> Result<Self, KiCadError> {
        KiCadClientBlockingBuilder::new().connect()
    }

    pub fn timeout(&self) -> Duration {
        self.inner.timeout()
    }

    pub fn socket_uri(&self) -> &str {
        self.inner.socket_uri()
    }

    pub fn inner(&self) -> &KiCadClient {
        &self.inner
    }

    pub fn run_action_raw(&self, action: impl Into<String>) -> Result<Any, KiCadError> {
        let action = action.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.run_action_raw(action).await })
        })
    }

    pub fn run_action(&self, action: impl Into<String>) -> Result<RunActionStatus, KiCadError> {
        let action = action.into();
        let client = self.inner.clone();
        self.core
            .call(move |runtime| runtime.block_on(async move { client.run_action(action).await }))
    }

    pub fn get_kicad_binary_path_raw(
        &self,
        binary_name: impl Into<String>,
    ) -> Result<Any, KiCadError> {
        let binary_name = binary_name.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.get_kicad_binary_path_raw(binary_name).await })
        })
    }

    pub fn get_kicad_binary_path(
        &self,
        binary_name: impl Into<String>,
    ) -> Result<String, KiCadError> {
        let binary_name = binary_name.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.get_kicad_binary_path(binary_name).await })
        })
    }

    pub fn get_plugin_settings_path_raw(
        &self,
        identifier: impl Into<String>,
    ) -> Result<Any, KiCadError> {
        let identifier = identifier.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.get_plugin_settings_path_raw(identifier).await })
        })
    }

    pub fn get_plugin_settings_path(
        &self,
        identifier: impl Into<String>,
    ) -> Result<String, KiCadError> {
        let identifier = identifier.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.get_plugin_settings_path(identifier).await })
        })
    }

    pub fn end_commit_raw(
        &self,
        session: CommitSession,
        action: CommitAction,
        message: impl Into<String>,
    ) -> Result<Any, KiCadError> {
        let message = message.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.end_commit_raw(session, action, message).await })
        })
    }

    pub fn end_commit(
        &self,
        session: CommitSession,
        action: CommitAction,
        message: impl Into<String>,
    ) -> Result<(), KiCadError> {
        let message = message.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move { client.end_commit(session, action, message).await })
        })
    }

    pub fn parse_and_create_items_from_string_raw(
        &self,
        contents: impl Into<String>,
    ) -> Result<Any, KiCadError> {
        let contents = contents.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move {
                client
                    .parse_and_create_items_from_string_raw(contents)
                    .await
            })
        })
    }

    pub fn parse_and_create_items_from_string(
        &self,
        contents: impl Into<String>,
    ) -> Result<Vec<Any>, KiCadError> {
        let contents = contents.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime
                .block_on(async move { client.parse_and_create_items_from_string(contents).await })
        })
    }

    pub fn inject_drc_error_raw(
        &self,
        severity: DrcSeverity,
        message: impl Into<String>,
        position: Option<Vector2Nm>,
        item_ids: Vec<String>,
    ) -> Result<Any, KiCadError> {
        let message = message.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move {
                client
                    .inject_drc_error_raw(severity, message, position, item_ids)
                    .await
            })
        })
    }

    pub fn inject_drc_error(
        &self,
        severity: DrcSeverity,
        message: impl Into<String>,
        position: Option<Vector2Nm>,
        item_ids: Vec<String>,
    ) -> Result<Option<String>, KiCadError> {
        let message = message.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move {
                client
                    .inject_drc_error(severity, message, position, item_ids)
                    .await
            })
        })
    }

    pub fn save_copy_of_document_raw(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<Any, KiCadError> {
        let path = path.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move {
                client
                    .save_copy_of_document_raw(path, overwrite, include_project)
                    .await
            })
        })
    }

    pub fn save_copy_of_document(
        &self,
        path: impl Into<String>,
        overwrite: bool,
        include_project: bool,
    ) -> Result<(), KiCadError> {
        let path = path.into();
        let client = self.inner.clone();
        self.core.call(move |runtime| {
            runtime.block_on(async move {
                client
                    .save_copy_of_document(path, overwrite, include_project)
                    .await
            })
        })
    }

    blocking_methods! {
        fn ping(&self) -> Result<(), KiCadError>;
        fn refresh_editor(&self, frame: EditorFrameType) -> Result<(), KiCadError>;
        fn get_version(&self) -> Result<VersionInfo, KiCadError>;
        fn get_open_documents(&self, document_type: DocumentType) -> Result<Vec<DocumentSpecifier>, KiCadError>;
        fn get_net_classes_raw(&self) -> Result<Any, KiCadError>;
        fn get_net_classes(&self) -> Result<Vec<NetClassInfo>, KiCadError>;
        fn set_net_classes_raw(&self, net_classes: Vec<NetClassInfo>, merge_mode: MapMergeMode) -> Result<Any, KiCadError>;
        fn set_net_classes(&self, net_classes: Vec<NetClassInfo>, merge_mode: MapMergeMode) -> Result<Vec<NetClassInfo>, KiCadError>;
        fn get_text_variables_raw(&self) -> Result<Any, KiCadError>;
        fn get_text_variables(&self) -> Result<BTreeMap<String, String>, KiCadError>;
        fn set_text_variables_raw(&self, variables: BTreeMap<String, String>, merge_mode: MapMergeMode) -> Result<Any, KiCadError>;
        fn set_text_variables(&self, variables: BTreeMap<String, String>, merge_mode: MapMergeMode) -> Result<BTreeMap<String, String>, KiCadError>;
        fn expand_text_variables_raw(&self, text: Vec<String>) -> Result<Any, KiCadError>;
        fn expand_text_variables(&self, text: Vec<String>) -> Result<Vec<String>, KiCadError>;
        fn get_text_extents_raw(&self, text: TextSpec) -> Result<Any, KiCadError>;
        fn get_text_extents(&self, text: TextSpec) -> Result<TextExtents, KiCadError>;
        fn get_text_as_shapes_raw(&self, text: Vec<TextObjectSpec>) -> Result<Any, KiCadError>;
        fn get_text_as_shapes(&self, text: Vec<TextObjectSpec>) -> Result<Vec<TextAsShapesEntry>, KiCadError>;
        fn get_current_project_path(&self) -> Result<PathBuf, KiCadError>;
        fn has_open_board(&self) -> Result<bool, KiCadError>;
        fn begin_commit_raw(&self) -> Result<Any, KiCadError>;
        fn begin_commit(&self) -> Result<CommitSession, KiCadError>;
        fn create_items_raw(&self, items: Vec<Any>, container_id: Option<String>) -> Result<Any, KiCadError>;
        fn create_items(&self, items: Vec<Any>, container_id: Option<String>) -> Result<Vec<Any>, KiCadError>;
        fn update_items_raw(&self, items: Vec<Any>) -> Result<Any, KiCadError>;
        fn update_items(&self, items: Vec<Any>) -> Result<Vec<Any>, KiCadError>;
        fn delete_items_raw(&self, item_ids: Vec<String>) -> Result<Any, KiCadError>;
        fn delete_items(&self, item_ids: Vec<String>) -> Result<Vec<String>, KiCadError>;
        fn get_nets(&self) -> Result<Vec<BoardNet>, KiCadError>;
        fn get_board_enabled_layers(&self) -> Result<BoardEnabledLayers, KiCadError>;
        fn set_board_enabled_layers(&self, copper_layer_count: u32, layer_ids: Vec<i32>) -> Result<BoardEnabledLayers, KiCadError>;
        fn get_active_layer(&self) -> Result<BoardLayerInfo, KiCadError>;
        fn set_active_layer(&self, layer_id: i32) -> Result<(), KiCadError>;
        fn get_visible_layers(&self) -> Result<Vec<BoardLayerInfo>, KiCadError>;
        fn set_visible_layers(&self, layer_ids: Vec<i32>) -> Result<(), KiCadError>;
        fn get_board_origin(&self, kind: BoardOriginKind) -> Result<Vector2Nm, KiCadError>;
        fn set_board_origin(&self, kind: BoardOriginKind, origin: Vector2Nm) -> Result<(), KiCadError>;
        fn get_selection_summary(&self) -> Result<SelectionSummary, KiCadError>;
        fn get_selection_raw(&self) -> Result<Vec<Any>, KiCadError>;
        fn get_selection_details(&self) -> Result<Vec<SelectionItemDetail>, KiCadError>;
        fn get_selection(&self) -> Result<Vec<PcbItem>, KiCadError>;
        fn add_to_selection_raw(&self, item_ids: Vec<String>) -> Result<Vec<Any>, KiCadError>;
        fn add_to_selection(&self, item_ids: Vec<String>) -> Result<SelectionSummary, KiCadError>;
        fn clear_selection_raw(&self) -> Result<Vec<Any>, KiCadError>;
        fn clear_selection(&self) -> Result<SelectionSummary, KiCadError>;
        fn remove_from_selection_raw(&self, item_ids: Vec<String>) -> Result<Vec<Any>, KiCadError>;
        fn remove_from_selection(&self, item_ids: Vec<String>) -> Result<SelectionSummary, KiCadError>;
        fn get_pad_netlist(&self) -> Result<Vec<PadNetEntry>, KiCadError>;
        fn get_items_raw_by_type_codes(&self, type_codes: Vec<i32>) -> Result<Vec<Any>, KiCadError>;
        fn get_items_details_by_type_codes(&self, type_codes: Vec<i32>) -> Result<Vec<SelectionItemDetail>, KiCadError>;
        fn get_items_by_type_codes(&self, type_codes: Vec<i32>) -> Result<Vec<PcbItem>, KiCadError>;
        fn get_all_pcb_items_raw(&self) -> Result<Vec<(PcbObjectTypeCode, Vec<Any>)>, KiCadError>;
        fn get_all_pcb_items_details(&self) -> Result<Vec<(PcbObjectTypeCode, Vec<SelectionItemDetail>)>, KiCadError>;
        fn get_all_pcb_items(&self) -> Result<Vec<(PcbObjectTypeCode, Vec<PcbItem>)>, KiCadError>;
        fn get_items_by_net_raw(&self, type_codes: Vec<i32>, net_codes: Vec<i32>) -> Result<Vec<Any>, KiCadError>;
        fn get_items_by_net(&self, type_codes: Vec<i32>, net_codes: Vec<i32>) -> Result<Vec<PcbItem>, KiCadError>;
        fn get_items_by_net_class_raw(&self, type_codes: Vec<i32>, net_classes: Vec<String>) -> Result<Vec<Any>, KiCadError>;
        fn get_items_by_net_class(&self, type_codes: Vec<i32>, net_classes: Vec<String>) -> Result<Vec<PcbItem>, KiCadError>;
        fn get_netclass_for_nets_raw(&self, nets: Vec<BoardNet>) -> Result<Any, KiCadError>;
        fn get_netclass_for_nets(&self, nets: Vec<BoardNet>) -> Result<Vec<NetClassForNetEntry>, KiCadError>;
        fn refill_zones(&self, zone_ids: Vec<String>) -> Result<(), KiCadError>;
        fn get_pad_shape_as_polygon_raw(&self, pad_ids: Vec<String>, layer_id: i32) -> Result<Vec<Any>, KiCadError>;
        fn get_pad_shape_as_polygon(&self, pad_ids: Vec<String>, layer_id: i32) -> Result<Vec<PadShapeAsPolygonEntry>, KiCadError>;
        fn check_padstack_presence_on_layers_raw(&self, item_ids: Vec<String>, layer_ids: Vec<i32>) -> Result<Vec<Any>, KiCadError>;
        fn check_padstack_presence_on_layers(&self, item_ids: Vec<String>, layer_ids: Vec<i32>) -> Result<Vec<PadstackPresenceEntry>, KiCadError>;
        fn get_board_stackup_raw(&self) -> Result<Any, KiCadError>;
        fn get_board_stackup(&self) -> Result<BoardStackup, KiCadError>;
        fn update_board_stackup_raw(&self, stackup: BoardStackup) -> Result<Any, KiCadError>;
        fn update_board_stackup(&self, stackup: BoardStackup) -> Result<BoardStackup, KiCadError>;
        fn get_graphics_defaults_raw(&self) -> Result<Any, KiCadError>;
        fn get_graphics_defaults(&self) -> Result<GraphicsDefaults, KiCadError>;
        fn get_board_editor_appearance_settings_raw(&self) -> Result<Any, KiCadError>;
        fn get_board_editor_appearance_settings(&self) -> Result<BoardEditorAppearanceSettings, KiCadError>;
        fn set_board_editor_appearance_settings(&self, settings: BoardEditorAppearanceSettings) -> Result<BoardEditorAppearanceSettings, KiCadError>;
        fn interactive_move_items_raw(&self, item_ids: Vec<String>) -> Result<Any, KiCadError>;
        fn interactive_move_items(&self, item_ids: Vec<String>) -> Result<(), KiCadError>;
        fn get_title_block_info(&self) -> Result<TitleBlockInfo, KiCadError>;
        fn save_document_raw(&self) -> Result<Any, KiCadError>;
        fn save_document(&self) -> Result<(), KiCadError>;
        fn revert_document_raw(&self) -> Result<Any, KiCadError>;
        fn revert_document(&self) -> Result<(), KiCadError>;
        fn get_board_as_string(&self) -> Result<String, KiCadError>;
        fn get_selection_as_string(&self) -> Result<String, KiCadError>;
        fn get_items_by_id_raw(&self, item_ids: Vec<String>) -> Result<Vec<Any>, KiCadError>;
        fn get_items_by_id_details(&self, item_ids: Vec<String>) -> Result<Vec<SelectionItemDetail>, KiCadError>;
        fn get_items_by_id(&self, item_ids: Vec<String>) -> Result<Vec<PcbItem>, KiCadError>;
        fn get_item_bounding_boxes(&self, item_ids: Vec<String>, include_child_text: bool) -> Result<Vec<ItemBoundingBox>, KiCadError>;
        fn hit_test_item(&self, item_id: String, position: Vector2Nm, tolerance_nm: i32) -> Result<ItemHitTestResult, KiCadError>;
    }

    #[cfg(test)]
    pub(crate) const MANUAL_BLOCKING_METHOD_NAMES: &'static [&'static str] = &[
        "connect",
        "run_action_raw",
        "run_action",
        "get_kicad_binary_path_raw",
        "get_kicad_binary_path",
        "get_plugin_settings_path_raw",
        "get_plugin_settings_path",
        "end_commit_raw",
        "end_commit",
        "parse_and_create_items_from_string_raw",
        "parse_and_create_items_from_string",
        "inject_drc_error_raw",
        "inject_drc_error",
        "save_copy_of_document_raw",
        "save_copy_of_document",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::mpsc as std_mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn blocking_core_executes_job_and_returns_result() {
        let core = BlockingCore::start().expect("blocking core must start");
        let value = core
            .call(|_| Ok::<_, KiCadError>(1234))
            .expect("blocking job should execute");
        assert_eq!(value, 1234);
    }

    #[test]
    fn blocking_core_handles_concurrent_submitters() {
        let core = BlockingCore::start().expect("blocking core must start");
        let mut handles = Vec::new();

        for idx in 0..8 {
            let core = Arc::clone(&core);
            handles.push(thread::spawn(move || {
                core.call(move |_| Ok::<_, KiCadError>(idx * 2))
                    .expect("job should return");
            }));
        }

        for handle in handles {
            handle.join().expect("submitter thread must join");
        }
    }

    #[test]
    fn blocking_core_shutdown_drains_inflight_jobs() {
        let core = BlockingCore::start().expect("blocking core must start");
        let (started_tx, started_rx) = std_mpsc::sync_channel::<()>(1);

        let core_for_call = Arc::clone(&core);
        let worker = thread::spawn(move || {
            core_for_call
                .call(move |_| {
                    let _ = started_tx.send(());
                    thread::sleep(Duration::from_millis(120));
                    Ok::<_, KiCadError>(())
                })
                .expect("in-flight job should complete");
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("job should begin");

        let begin = Instant::now();
        core.shutdown();
        let elapsed = begin.elapsed();

        assert!(
            elapsed >= Duration::from_millis(80),
            "shutdown should wait for in-flight job; elapsed: {elapsed:?}"
        );

        worker.join().expect("worker submitter should join");
    }

    #[test]
    fn blocking_core_returns_closed_error_after_shutdown() {
        let core = BlockingCore::start().expect("blocking core must start");
        core.shutdown();

        let err = core
            .call(|_| Ok::<_, KiCadError>(()))
            .expect_err("closed core should reject calls");
        assert!(matches!(err, KiCadError::BlockingRuntimeClosed));
    }

    #[test]
    fn sync_wrapper_covers_async_method_names() {
        let mut async_methods = BTreeSet::new();
        for line in include_str!("client.rs").lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("pub async fn ") {
                if let Some(name) = rest.split('(').next() {
                    async_methods.insert(name.trim().to_string());
                }
            }
        }

        let blocking_methods: BTreeSet<String> =
            KiCadClientBlocking::GENERATED_BLOCKING_METHOD_NAMES
                .iter()
                .chain(KiCadClientBlocking::MANUAL_BLOCKING_METHOD_NAMES.iter())
                .map(|name| (*name).to_string())
                .collect();

        let missing: Vec<String> = async_methods
            .into_iter()
            .filter(|name| !blocking_methods.contains(name))
            .collect();

        assert!(
            missing.is_empty(),
            "missing blocking wrappers for async methods: {:?}",
            missing
        );
    }

    #[test]
    fn impl_into_string_wrapper_signatures_accept_str() {
        fn assert_signatures(client: &KiCadClientBlocking) {
            let _ = client.run_action_raw("pcbnew.Refresh");
            let _ = client.run_action("pcbnew.Refresh");
            let _ = client.get_kicad_binary_path_raw("kicad-cli");
            let _ = client.get_kicad_binary_path("kicad-cli");
            let _ = client.get_plugin_settings_path_raw("kicad-ipc-rs");
            let _ = client.get_plugin_settings_path("kicad-ipc-rs");
            let _ = client.end_commit_raw(
                CommitSession {
                    id: "commit-id".to_string(),
                },
                CommitAction::Drop,
                "test",
            );
            let _ = client.end_commit(
                CommitSession {
                    id: "commit-id".to_string(),
                },
                CommitAction::Drop,
                "test",
            );
            let _ = client.parse_and_create_items_from_string_raw("(kicad_pcb)");
            let _ = client.parse_and_create_items_from_string("(kicad_pcb)");
            let _ = client.inject_drc_error_raw(DrcSeverity::Warning, "marker", None, Vec::new());
            let _ = client.inject_drc_error(DrcSeverity::Warning, "marker", None, Vec::new());
            let _ = client.save_copy_of_document_raw("/tmp/example.kicad_pcb", false, false);
            let _ = client.save_copy_of_document("/tmp/example.kicad_pcb", false, false);
        }

        let _ = assert_signatures as fn(&KiCadClientBlocking);
    }

    #[test]
    fn blocking_smoke_live_when_socket_env_is_set() {
        if std::env::var("KICAD_API_SOCKET").is_err() {
            return;
        }

        let client = KiCadClientBlocking::connect().expect("blocking client should connect");
        client.ping().expect("ping should succeed");
        let _ = client.get_version().expect("version should succeed");
        let _ = client
            .get_open_documents(DocumentType::Pcb)
            .expect("open docs should succeed");
        let _ = client
            .get_visible_layers()
            .expect("board read method should succeed");
    }
}
