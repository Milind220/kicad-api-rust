use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use kicad_ipc::{
    BoardFlipMode, BoardOriginKind, ClientBuilder, CommitAction, CommitSession, DocumentType,
    DrcSeverity, EditorFrameType, InactiveLayerDisplayMode, KiCadClient, KiCadError,
    NetColorDisplayMode, PadstackPresenceState, PcbObjectTypeCode, RatsnestDisplayMode,
    TextObjectSpec, TextShapeGeometry, TextSpec, Vector2Nm,
};

const REPORT_MAX_PAD_NET_ROWS: usize = 2_000;
const REPORT_MAX_PRESENCE_ROWS: usize = 2_000;
const REPORT_MAX_ITEM_DEBUG_ROWS_PER_TYPE: usize = 5;
const REPORT_MAX_ITEM_DEBUG_CHARS: usize = 8_000;
const REPORT_MAX_BOARD_SNAPSHOT_CHARS: usize = 750_000;

#[derive(Debug)]
struct CliConfig {
    socket: Option<String>,
    token: Option<String>,
    client_name: Option<String>,
    timeout_ms: u64,
}

#[derive(Debug)]
enum Command {
    Ping,
    Version,
    OpenDocs {
        document_type: DocumentType,
    },
    ProjectPath,
    BoardOpen,
    NetClasses,
    TextVariables,
    ExpandTextVariables {
        text: Vec<String>,
    },
    TextExtents {
        text: String,
    },
    TextAsShapes {
        text: Vec<String>,
    },
    Nets,
    EnabledLayers,
    SetEnabledLayers {
        copper_layer_count: u32,
        layer_ids: Vec<i32>,
    },
    ActiveLayer,
    SetActiveLayer {
        layer_id: i32,
    },
    VisibleLayers,
    SetVisibleLayers {
        layer_ids: Vec<i32>,
    },
    BoardOrigin {
        kind: BoardOriginKind,
    },
    SetBoardOrigin {
        kind: BoardOriginKind,
        x_nm: i64,
        y_nm: i64,
    },
    InjectDrcError {
        severity: DrcSeverity,
        message: String,
        x_nm: Option<i64>,
        y_nm: Option<i64>,
        item_ids: Vec<String>,
    },
    RefreshEditor {
        frame: EditorFrameType,
    },
    BeginCommit,
    EndCommit {
        id: String,
        action: CommitAction,
        message: String,
    },
    ClearSelection,
    SelectionSummary,
    SelectionDetails,
    SelectionRaw,
    NetlistPads,
    ItemsById {
        item_ids: Vec<String>,
    },
    ItemBBox {
        item_ids: Vec<String>,
        include_child_text: bool,
    },
    HitTest {
        item_id: String,
        x_nm: i64,
        y_nm: i64,
        tolerance_nm: i32,
    },
    PcbTypes,
    ItemsRaw {
        type_codes: Vec<i32>,
        include_debug: bool,
    },
    ItemsRawAllPcb {
        include_debug: bool,
    },
    PadShapePolygon {
        pad_ids: Vec<String>,
        layer_id: i32,
        include_debug: bool,
    },
    PadstackPresence {
        item_ids: Vec<String>,
        layer_ids: Vec<i32>,
        include_debug: bool,
    },
    TitleBlock,
    BoardAsString,
    SelectionAsString,
    Stackup,
    GraphicsDefaults,
    Appearance,
    SetAppearance {
        inactive_layer_display: InactiveLayerDisplayMode,
        net_color_display: NetColorDisplayMode,
        board_flip: BoardFlipMode,
        ratsnest_display: RatsnestDisplayMode,
    },
    RefillZones {
        zone_ids: Vec<String>,
    },
    NetClass,
    BoardReadReport {
        output: PathBuf,
    },
    ProtoCoverageBoardRead,
    Smoke,
    Help,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            if matches!(
                err,
                KiCadError::BoardNotOpen | KiCadError::SocketUnavailable { .. }
            ) {
                eprintln!(
                    "hint: launch KiCad, open a project, and open a PCB editor window before rerunning this command."
                );
            }
            if let KiCadError::ApiStatus { code, message } = &err {
                if code == "AS_UNHANDLED" {
                    eprintln!(
                        "hint: this KiCad build reported the command as unavailable (`{message}`). try `ping` and `version`, or update KiCad/API settings."
                    );
                }
            }
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), KiCadError> {
    let (config, command) = parse_args()?;

    if matches!(command, Command::Help) {
        print_help();
        return Ok(());
    }

    let mut builder = ClientBuilder::new().timeout(Duration::from_millis(config.timeout_ms));
    if let Some(socket) = config.socket {
        builder = builder.socket_path(socket);
    }
    if let Some(token) = config.token {
        builder = builder.token(token);
    }
    if let Some(client_name) = config.client_name {
        builder = builder.client_name(client_name);
    }

    let client = builder.connect().await?;

    match command {
        Command::Ping => {
            client.ping().await?;
            println!("pong");
        }
        Command::Version => {
            let version = client.get_version().await?;
            println!(
                "version: {}.{}.{} ({})",
                version.major, version.minor, version.patch, version.full_version
            );
        }
        Command::OpenDocs { document_type } => {
            let docs = client.get_open_documents(document_type).await?;
            if docs.is_empty() {
                println!("no open `{document_type}` documents");
            } else {
                for (idx, doc) in docs.iter().enumerate() {
                    let board = doc.board_filename.as_deref().unwrap_or("-");
                    let project_name = doc.project.name.as_deref().unwrap_or("-");
                    let project_path = doc
                        .project
                        .path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "-".to_string());

                    println!(
                        "[{idx}] type={} board={} project_name={} project_path={}",
                        doc.document_type, board, project_name, project_path
                    );
                }
            }
        }
        Command::ProjectPath => {
            let path = client.get_current_project_path().await?;
            println!("project_path={}", path.display());
        }
        Command::BoardOpen => {
            let has_board = client.has_open_board().await?;
            if has_board {
                println!("board-open: yes");
            } else {
                return Err(KiCadError::BoardNotOpen);
            }
        }
        Command::NetClasses => {
            let classes = client.get_net_classes().await?;
            println!("net_class_count={}", classes.len());
            for class in classes {
                println!(
                    "name={} type={:?} priority={} constituents={}",
                    class.name,
                    class.class_type,
                    class
                        .priority
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    class.constituents.join(",")
                );
            }
        }
        Command::TextVariables => {
            let variables = client.get_text_variables().await?;
            println!("text_variable_count={}", variables.len());
            for (name, value) in variables {
                println!("name={} value={}", name, value);
            }
        }
        Command::ExpandTextVariables { text } => {
            let expanded = client.expand_text_variables(text.clone()).await?;
            println!("expanded_count={}", expanded.len());
            for (index, value) in expanded.iter().enumerate() {
                println!("[{index}] input={} expanded={}", text[index], value);
            }
        }
        Command::TextExtents { text } => {
            let extents = client.get_text_extents(TextSpec::plain(text)).await?;
            println!(
                "x_nm={} y_nm={} width_nm={} height_nm={}",
                extents.x_nm, extents.y_nm, extents.width_nm, extents.height_nm
            );
        }
        Command::TextAsShapes { text } => {
            let entries = client
                .get_text_as_shapes(
                    text.into_iter()
                        .map(|value| TextObjectSpec::Text(TextSpec::plain(value)))
                        .collect(),
                )
                .await?;
            println!("text_with_shapes_count={}", entries.len());
            for (index, entry) in entries.iter().enumerate() {
                let mut segment_count = 0;
                let mut rectangle_count = 0;
                let mut arc_count = 0;
                let mut circle_count = 0;
                let mut polygon_count = 0;
                let mut bezier_count = 0;
                let mut unknown_count = 0;
                for shape in &entry.shapes {
                    match shape.geometry {
                        TextShapeGeometry::Segment { .. } => segment_count += 1,
                        TextShapeGeometry::Rectangle { .. } => rectangle_count += 1,
                        TextShapeGeometry::Arc { .. } => arc_count += 1,
                        TextShapeGeometry::Circle { .. } => circle_count += 1,
                        TextShapeGeometry::Polygon { .. } => polygon_count += 1,
                        TextShapeGeometry::Bezier { .. } => bezier_count += 1,
                        TextShapeGeometry::Unknown => unknown_count += 1,
                    }
                }
                println!(
                    "[{index}] shape_count={} segment={} rectangle={} arc={} circle={} polygon={} bezier={} unknown={}",
                    entry.shapes.len(),
                    segment_count,
                    rectangle_count,
                    arc_count,
                    circle_count,
                    polygon_count,
                    bezier_count,
                    unknown_count
                );
            }
        }
        Command::Nets => {
            let nets = client.get_nets().await?;
            if nets.is_empty() {
                println!("no nets returned");
            } else {
                for net in nets {
                    println!("code={} name={}", net.code, net.name);
                }
            }
        }
        Command::EnabledLayers => {
            let enabled = client.get_board_enabled_layers().await?;
            println!("copper_layer_count={}", enabled.copper_layer_count);
            for layer in enabled.layers {
                println!("layer_id={} layer_name={}", layer.id, layer.name);
            }
        }
        Command::SetEnabledLayers {
            copper_layer_count,
            layer_ids,
        } => {
            let enabled = client
                .set_board_enabled_layers(copper_layer_count, layer_ids)
                .await?;
            println!("copper_layer_count={}", enabled.copper_layer_count);
            for layer in enabled.layers {
                println!("layer_id={} layer_name={}", layer.id, layer.name);
            }
        }
        Command::ActiveLayer => {
            let layer = client.get_active_layer().await?;
            println!(
                "active_layer_id={} active_layer_name={}",
                layer.id, layer.name
            );
        }
        Command::SetActiveLayer { layer_id } => {
            client.set_active_layer(layer_id).await?;
            println!("set_active_layer_id={}", layer_id);
        }
        Command::VisibleLayers => {
            let layers = client.get_visible_layers().await?;
            if layers.is_empty() {
                println!("no visible layers returned");
            } else {
                for layer in layers {
                    println!("layer_id={} layer_name={}", layer.id, layer.name);
                }
            }
        }
        Command::SetVisibleLayers { layer_ids } => {
            client.set_visible_layers(layer_ids.clone()).await?;
            println!("set_visible_layer_count={}", layer_ids.len());
        }
        Command::BoardOrigin { kind } => {
            let origin = client.get_board_origin(kind).await?;
            println!(
                "origin_kind={} x_nm={} y_nm={}",
                kind, origin.x_nm, origin.y_nm
            );
        }
        Command::SetBoardOrigin { kind, x_nm, y_nm } => {
            client
                .set_board_origin(kind, Vector2Nm { x_nm, y_nm })
                .await?;
            println!("set_origin_kind={} x_nm={} y_nm={}", kind, x_nm, y_nm);
        }
        Command::InjectDrcError {
            severity,
            message,
            x_nm,
            y_nm,
            item_ids,
        } => {
            let position = match (x_nm, y_nm) {
                (Some(x_nm), Some(y_nm)) => Some(Vector2Nm { x_nm, y_nm }),
                _ => None,
            };
            let marker = client
                .inject_drc_error(severity, message, position, item_ids)
                .await?;
            println!(
                "drc_marker_id={}",
                marker.unwrap_or_else(|| "-".to_string())
            );
        }
        Command::RefreshEditor { frame } => {
            client.refresh_editor(frame).await?;
            println!("refresh_editor=ok frame={}", frame);
        }
        Command::BeginCommit => {
            let session = client.begin_commit().await?;
            println!("commit_id={}", session.id);
        }
        Command::EndCommit {
            id,
            action,
            message,
        } => {
            client
                .end_commit(CommitSession { id }, action, message)
                .await?;
            println!("end_commit=ok action={}", action);
        }
        Command::ClearSelection => {
            let summary = client.clear_selection().await?;
            println!("selection_total={}", summary.total_items);
        }
        Command::SelectionSummary => {
            let summary = client.get_selection_summary().await?;
            println!("selection_total={}", summary.total_items);
            for entry in summary.type_url_counts {
                println!("type_url={} count={}", entry.type_url, entry.count);
            }
        }
        Command::SelectionDetails => {
            let details = client.get_selection_details().await?;
            println!("selection_total={}", details.len());
            for (index, item) in details.iter().enumerate() {
                println!(
                    "[{index}] type_url={} raw_len={} detail={}",
                    item.type_url, item.raw_len, item.detail
                );
            }
        }
        Command::SelectionRaw => {
            let items = client.get_selection_raw().await?;
            println!("selection_total={}", items.len());
            for (index, item) in items.iter().enumerate() {
                println!(
                    "[{index}] type_url={} raw_len={} raw_hex={}",
                    item.type_url,
                    item.value.len(),
                    bytes_to_hex(&item.value)
                );
            }
        }
        Command::NetlistPads => {
            let entries = client.get_pad_netlist().await?;
            println!("pad_net_entries={}", entries.len());
            for entry in entries {
                println!(
                    "footprint_ref={} footprint_id={} pad_id={} pad_number={} net_code={} net_name={}",
                    entry.footprint_reference.as_deref().unwrap_or("-"),
                    entry.footprint_id.as_deref().unwrap_or("-"),
                    entry.pad_id.as_deref().unwrap_or("-"),
                    entry.pad_number,
                    entry
                        .net_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    entry.net_name.as_deref().unwrap_or("-")
                );
            }
        }
        Command::ItemsById { item_ids } => {
            let details = client.get_items_by_id_details(item_ids).await?;
            println!("items_total={}", details.len());
            for (index, item) in details.iter().enumerate() {
                println!(
                    "[{index}] type_url={} raw_len={} detail={}",
                    item.type_url, item.raw_len, item.detail
                );
            }
        }
        Command::ItemBBox {
            item_ids,
            include_child_text,
        } => {
            let boxes = client
                .get_item_bounding_boxes(item_ids, include_child_text)
                .await?;
            println!("bbox_total={}", boxes.len());
            for entry in boxes {
                println!(
                    "item_id={} x_nm={} y_nm={} width_nm={} height_nm={}",
                    entry.item_id, entry.x_nm, entry.y_nm, entry.width_nm, entry.height_nm
                );
            }
        }
        Command::HitTest {
            item_id,
            x_nm,
            y_nm,
            tolerance_nm,
        } => {
            let result = client
                .hit_test_item(item_id, Vector2Nm { x_nm, y_nm }, tolerance_nm)
                .await?;
            println!("hit_test={result}");
        }
        Command::PcbTypes => {
            for entry in kicad_ipc::KiCadClient::pcb_object_type_codes() {
                println!("type_id={} type_name={}", entry.code, entry.name);
            }
        }
        Command::ItemsRaw {
            type_codes,
            include_debug,
        } => {
            let items = client
                .get_items_raw_by_type_codes(type_codes.clone())
                .await?;
            println!(
                "items_total={} requested_type_codes={:?}",
                items.len(),
                type_codes
            );
            for (index, item) in items.iter().enumerate() {
                if include_debug {
                    let debug = kicad_ipc::KiCadClient::debug_any_item(item)?
                        .replace('\n', "\\n")
                        .replace('\t', " ");
                    println!(
                        "[{index}] type_url={} raw_len={} raw_hex={} debug={}",
                        item.type_url,
                        item.value.len(),
                        bytes_to_hex(&item.value),
                        debug
                    );
                } else {
                    println!(
                        "[{index}] type_url={} raw_len={} raw_hex={}",
                        item.type_url,
                        item.value.len(),
                        bytes_to_hex(&item.value)
                    );
                }
            }
        }
        Command::ItemsRawAllPcb { include_debug } => {
            for object_type in kicad_ipc::KiCadClient::pcb_object_type_codes() {
                match client
                    .get_items_raw_by_type_codes(vec![object_type.code])
                    .await
                {
                    Ok(items) => {
                        println!(
                            "type_id={} type_name={} item_count={}",
                            object_type.code,
                            object_type.name,
                            items.len()
                        );
                        for (index, item) in items.iter().enumerate() {
                            if include_debug {
                                let debug = kicad_ipc::KiCadClient::debug_any_item(item)?
                                    .replace('\n', "\\n")
                                    .replace('\t', " ");
                                println!(
                                    "  [{index}] type_url={} raw_len={} raw_hex={} debug={}",
                                    item.type_url,
                                    item.value.len(),
                                    bytes_to_hex(&item.value),
                                    debug
                                );
                            } else {
                                println!(
                                    "  [{index}] type_url={} raw_len={} raw_hex={}",
                                    item.type_url,
                                    item.value.len(),
                                    bytes_to_hex(&item.value)
                                );
                            }
                        }
                    }
                    Err(err) => {
                        println!(
                            "type_id={} type_name={} error={}",
                            object_type.code, object_type.name, err
                        );
                    }
                }
            }
        }
        Command::PadShapePolygon {
            pad_ids,
            layer_id,
            include_debug,
        } => {
            let rows = client
                .get_pad_shape_as_polygon(pad_ids.clone(), layer_id)
                .await?;
            println!(
                "pad_shape_total={} layer_id={} requested_pad_count={}",
                rows.len(),
                layer_id,
                pad_ids.len()
            );
            for row in &rows {
                let outline_nodes = row
                    .polygon
                    .outline
                    .as_ref()
                    .map(|outline| outline.nodes.len())
                    .unwrap_or(0);
                println!(
                    "pad_id={} layer_id={} layer_name={} outline_nodes={} hole_count={}",
                    row.pad_id,
                    row.layer_id,
                    row.layer_name,
                    outline_nodes,
                    row.polygon.holes.len()
                );
            }
            if include_debug {
                let raw_chunks = client
                    .get_pad_shape_as_polygon_raw(pad_ids, layer_id)
                    .await?;
                for (chunk_index, chunk) in raw_chunks.iter().enumerate() {
                    let debug = kicad_ipc::KiCadClient::debug_any_item(chunk)?
                        .replace('\n', "\\n")
                        .replace('\t', " ");
                    println!("raw_chunk={chunk_index} debug={debug}");
                }
            }
        }
        Command::PadstackPresence {
            item_ids,
            layer_ids,
            include_debug,
        } => {
            let rows = client
                .check_padstack_presence_on_layers(item_ids.clone(), layer_ids.clone())
                .await?;
            println!(
                "padstack_presence_total={} requested_item_count={} requested_layer_count={}",
                rows.len(),
                item_ids.len(),
                layer_ids.len()
            );
            for row in &rows {
                println!(
                    "item_id={} layer_id={} layer_name={} presence={}",
                    row.item_id, row.layer_id, row.layer_name, row.presence
                );
            }
            if include_debug {
                let raw_chunks = client
                    .check_padstack_presence_on_layers_raw(item_ids, layer_ids)
                    .await?;
                for (chunk_index, chunk) in raw_chunks.iter().enumerate() {
                    let debug = kicad_ipc::KiCadClient::debug_any_item(chunk)?
                        .replace('\n', "\\n")
                        .replace('\t', " ");
                    println!("raw_chunk={chunk_index} debug={debug}");
                }
            }
        }
        Command::TitleBlock => {
            let title_block = client.get_title_block_info().await?;
            println!("title={}", title_block.title);
            println!("date={}", title_block.date);
            println!("revision={}", title_block.revision);
            println!("company={}", title_block.company);
            for (index, comment) in title_block.comments.iter().enumerate() {
                println!("comment{}={}", index + 1, comment);
            }
        }
        Command::BoardAsString => {
            let content = client.get_board_as_string().await?;
            println!("{content}");
        }
        Command::SelectionAsString => {
            let content = client.get_selection_as_string().await?;
            println!("{content}");
        }
        Command::Stackup => {
            let stackup = client.get_board_stackup().await?;
            println!("{stackup:#?}");
        }
        Command::GraphicsDefaults => {
            let defaults = client.get_graphics_defaults().await?;
            println!("{defaults:#?}");
        }
        Command::Appearance => {
            let appearance = client.get_board_editor_appearance_settings().await?;
            println!("{appearance:#?}");
        }
        Command::SetAppearance {
            inactive_layer_display,
            net_color_display,
            board_flip,
            ratsnest_display,
        } => {
            let updated = client
                .set_board_editor_appearance_settings(kicad_ipc::BoardEditorAppearanceSettings {
                    inactive_layer_display,
                    net_color_display,
                    board_flip,
                    ratsnest_display,
                })
                .await?;
            println!("{updated:#?}");
        }
        Command::RefillZones { zone_ids } => {
            client.refill_zones(zone_ids).await?;
            println!("refill_zones_dispatched=ok");
        }
        Command::NetClass => {
            let nets = client.get_nets().await?;
            let netclasses = client.get_netclass_for_nets(nets).await?;
            println!("{netclasses:#?}");
        }
        Command::BoardReadReport { output } => {
            let report = build_board_read_report_markdown(&client).await?;
            fs::write(&output, report).map_err(|err| KiCadError::Config {
                reason: format!("failed to write report to `{}`: {err}", output.display()),
            })?;
            println!("wrote_report={}", output.display());
        }
        Command::ProtoCoverageBoardRead => {
            print_proto_coverage_board_read();
        }
        Command::Smoke => {
            client.ping().await?;
            let version = client.get_version().await?;
            let has_board = client.has_open_board().await?;
            println!(
                "smoke ok: version={}.{}.{} board_open={}",
                version.major, version.minor, version.patch, has_board
            );
        }
        Command::Help => print_help(),
    }

    Ok(())
}

fn parse_args() -> Result<(CliConfig, Command), KiCadError> {
    parse_args_from(std::env::args().skip(1).collect())
}

fn parse_args_from(mut args: Vec<String>) -> Result<(CliConfig, Command), KiCadError> {
    if args.is_empty() {
        return Ok((default_config(), Command::Help));
    }

    let mut config = default_config();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--socket" => {
                let value = args.get(index + 1).ok_or_else(|| KiCadError::Config {
                    reason: "missing value for --socket".to_string(),
                })?;
                config.socket = Some(value.clone());
                args.drain(index..=index + 1);
            }
            "--token" => {
                let value = args.get(index + 1).ok_or_else(|| KiCadError::Config {
                    reason: "missing value for --token".to_string(),
                })?;
                config.token = Some(value.clone());
                args.drain(index..=index + 1);
            }
            "--client-name" => {
                let value = args.get(index + 1).ok_or_else(|| KiCadError::Config {
                    reason: "missing value for --client-name".to_string(),
                })?;
                config.client_name = Some(value.clone());
                args.drain(index..=index + 1);
            }
            "--timeout-ms" => {
                let value = args.get(index + 1).ok_or_else(|| KiCadError::Config {
                    reason: "missing value for --timeout-ms".to_string(),
                })?;
                config.timeout_ms = value.parse::<u64>().map_err(|err| KiCadError::Config {
                    reason: format!("invalid --timeout-ms value `{value}`: {err}"),
                })?;
                args.drain(index..=index + 1);
            }
            _ => {
                index += 1;
            }
        }
    }

    if args.is_empty() {
        return Ok((config, Command::Help));
    }

    let command = match args[0].as_str() {
        "help" | "--help" | "-h" => Command::Help,
        "ping" => Command::Ping,
        "version" => Command::Version,
        "project-path" => Command::ProjectPath,
        "board-open" => Command::BoardOpen,
        "net-classes" => Command::NetClasses,
        "text-variables" => Command::TextVariables,
        "expand-text-variables" => {
            let mut text = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--text" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for expand-text-variables --text".to_string(),
                        })?;
                        text.push(value.clone());
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if text.is_empty() {
                return Err(KiCadError::Config {
                    reason: "expand-text-variables requires one or more `--text <value>` arguments"
                        .to_string(),
                });
            }

            Command::ExpandTextVariables { text }
        }
        "text-extents" => {
            let mut text = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--text" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for text-extents --text".to_string(),
                        })?;
                        text = Some(value.clone());
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            Command::TextExtents {
                text: text.ok_or_else(|| KiCadError::Config {
                    reason: "text-extents requires `--text <value>`".to_string(),
                })?,
            }
        }
        "text-as-shapes" => {
            let mut text = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--text" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for text-as-shapes --text".to_string(),
                        })?;
                        text.push(value.clone());
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if text.is_empty() {
                return Err(KiCadError::Config {
                    reason: "text-as-shapes requires one or more `--text <value>` arguments"
                        .to_string(),
                });
            }

            Command::TextAsShapes { text }
        }
        "nets" => Command::Nets,
        "enabled-layers" => Command::EnabledLayers,
        "set-enabled-layers" => {
            let mut copper_layer_count = None;
            let mut layer_ids = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--copper-layer-count" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-enabled-layers --copper-layer-count"
                                .to_string(),
                        })?;
                        copper_layer_count =
                            Some(value.parse::<u32>().map_err(|err| KiCadError::Config {
                                reason: format!(
                                    "invalid set-enabled-layers --copper-layer-count `{value}`: {err}"
                                ),
                            })?);
                        i += 2;
                    }
                    "--layer-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-enabled-layers --layer-id".to_string(),
                        })?;
                        layer_ids.push(value.parse::<i32>().map_err(|err| KiCadError::Config {
                            reason: format!(
                                "invalid set-enabled-layers --layer-id `{value}`: {err}"
                            ),
                        })?);
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            Command::SetEnabledLayers {
                copper_layer_count: copper_layer_count.ok_or_else(|| KiCadError::Config {
                    reason: "set-enabled-layers requires `--copper-layer-count <u32>`".to_string(),
                })?,
                layer_ids,
            }
        }
        "active-layer" => Command::ActiveLayer,
        "set-active-layer" => {
            let mut layer_id = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--layer-id" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for set-active-layer --layer-id".to_string(),
                    })?;
                    layer_id = Some(value.parse::<i32>().map_err(|err| KiCadError::Config {
                        reason: format!("invalid set-active-layer --layer-id `{value}`: {err}"),
                    })?);
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::SetActiveLayer {
                layer_id: layer_id.ok_or_else(|| KiCadError::Config {
                    reason: "set-active-layer requires `--layer-id <i32>`".to_string(),
                })?,
            }
        }
        "visible-layers" => Command::VisibleLayers,
        "set-visible-layers" => {
            let mut layer_ids = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--layer-id" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for set-visible-layers --layer-id".to_string(),
                    })?;
                    layer_ids.push(value.parse::<i32>().map_err(|err| KiCadError::Config {
                        reason: format!("invalid set-visible-layers --layer-id `{value}`: {err}"),
                    })?);
                    i += 2;
                    continue;
                }
                i += 1;
            }

            if layer_ids.is_empty() {
                return Err(KiCadError::Config {
                    reason: "set-visible-layers requires one or more `--layer-id <i32>` arguments"
                        .to_string(),
                });
            }

            Command::SetVisibleLayers { layer_ids }
        }
        "board-origin" => {
            let mut kind = BoardOriginKind::Grid;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--type" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for board-origin --type".to_string(),
                    })?;
                    kind = BoardOriginKind::from_str(value)
                        .map_err(|err| KiCadError::Config { reason: err })?;
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::BoardOrigin { kind }
        }
        "set-board-origin" => {
            let mut kind = BoardOriginKind::Grid;
            let mut x_nm = None;
            let mut y_nm = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--type" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-board-origin --type".to_string(),
                        })?;
                        kind = BoardOriginKind::from_str(value)
                            .map_err(|err| KiCadError::Config { reason: err })?;
                        i += 2;
                    }
                    "--x-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-board-origin --x-nm".to_string(),
                        })?;
                        x_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid set-board-origin --x-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    "--y-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-board-origin --y-nm".to_string(),
                        })?;
                        y_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid set-board-origin --y-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            Command::SetBoardOrigin {
                kind,
                x_nm: x_nm.ok_or_else(|| KiCadError::Config {
                    reason: "set-board-origin requires `--x-nm <i64>`".to_string(),
                })?,
                y_nm: y_nm.ok_or_else(|| KiCadError::Config {
                    reason: "set-board-origin requires `--y-nm <i64>`".to_string(),
                })?,
            }
        }
        "inject-drc-error" => {
            let mut severity = DrcSeverity::Error;
            let mut message = None;
            let mut x_nm = None;
            let mut y_nm = None;
            let mut item_ids = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--severity" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for inject-drc-error --severity".to_string(),
                        })?;
                        severity = parse_drc_severity(value)
                            .map_err(|err| KiCadError::Config { reason: err })?;
                        i += 2;
                    }
                    "--message" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for inject-drc-error --message".to_string(),
                        })?;
                        message = Some(value.clone());
                        i += 2;
                    }
                    "--x-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for inject-drc-error --x-nm".to_string(),
                        })?;
                        x_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid inject-drc-error --x-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    "--y-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for inject-drc-error --y-nm".to_string(),
                        })?;
                        y_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid inject-drc-error --y-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    "--item-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for inject-drc-error --item-id".to_string(),
                        })?;
                        item_ids.push(value.clone());
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if (x_nm.is_some() && y_nm.is_none()) || (x_nm.is_none() && y_nm.is_some()) {
                return Err(KiCadError::Config {
                    reason:
                        "inject-drc-error requires both --x-nm and --y-nm when providing a position"
                            .to_string(),
                });
            }

            Command::InjectDrcError {
                severity,
                message: message.ok_or_else(|| KiCadError::Config {
                    reason: "inject-drc-error requires `--message <text>`".to_string(),
                })?,
                x_nm,
                y_nm,
                item_ids,
            }
        }
        "refresh-editor" => {
            let mut frame = EditorFrameType::PcbEditor;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--frame" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for refresh-editor --frame".to_string(),
                    })?;
                    frame = EditorFrameType::from_str(value)
                        .map_err(|err| KiCadError::Config { reason: err })?;
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::RefreshEditor { frame }
        }
        "begin-commit" => Command::BeginCommit,
        "end-commit" => {
            let mut id = None;
            let mut action = CommitAction::Commit;
            let mut message = String::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for end-commit --id".to_string(),
                        })?;
                        id = Some(value.clone());
                        i += 2;
                    }
                    "--action" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for end-commit --action".to_string(),
                        })?;
                        action = CommitAction::from_str(value)
                            .map_err(|err| KiCadError::Config { reason: err })?;
                        i += 2;
                    }
                    "--message" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for end-commit --message".to_string(),
                        })?;
                        message = value.clone();
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            Command::EndCommit {
                id: id.ok_or_else(|| KiCadError::Config {
                    reason: "end-commit requires `--id <uuid>`".to_string(),
                })?,
                action,
                message,
            }
        }
        "clear-selection" => Command::ClearSelection,
        "selection-summary" => Command::SelectionSummary,
        "selection-details" => Command::SelectionDetails,
        "selection-raw" => Command::SelectionRaw,
        "netlist-pads" => Command::NetlistPads,
        "items-by-id" => {
            let item_ids = parse_item_ids(&args[1..], "items-by-id")?;
            Command::ItemsById { item_ids }
        }
        "item-bbox" => {
            let mut item_ids = Vec::new();
            let mut include_child_text = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for item-bbox --id".to_string(),
                        })?;
                        item_ids.push(value.clone());
                        i += 2;
                    }
                    "--include-text" => {
                        include_child_text = true;
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if item_ids.is_empty() {
                return Err(KiCadError::Config {
                    reason: "item-bbox requires one or more `--id <uuid>` arguments".to_string(),
                });
            }

            Command::ItemBBox {
                item_ids,
                include_child_text,
            }
        }
        "hit-test" => {
            let mut item_id = None;
            let mut x_nm = None;
            let mut y_nm = None;
            let mut tolerance_nm = 0_i32;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for hit-test --id".to_string(),
                        })?;
                        item_id = Some(value.clone());
                        i += 2;
                    }
                    "--x-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for hit-test --x-nm".to_string(),
                        })?;
                        x_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid hit-test --x-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    "--y-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for hit-test --y-nm".to_string(),
                        })?;
                        y_nm = Some(value.parse::<i64>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid hit-test --y-nm `{value}`: {err}"),
                        })?);
                        i += 2;
                    }
                    "--tolerance-nm" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for hit-test --tolerance-nm".to_string(),
                        })?;
                        tolerance_nm = value.parse::<i32>().map_err(|err| KiCadError::Config {
                            reason: format!("invalid hit-test --tolerance-nm `{value}`: {err}"),
                        })?;
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            Command::HitTest {
                item_id: item_id.ok_or_else(|| KiCadError::Config {
                    reason: "hit-test requires `--id <uuid>`".to_string(),
                })?,
                x_nm: x_nm.ok_or_else(|| KiCadError::Config {
                    reason: "hit-test requires `--x-nm <value>`".to_string(),
                })?,
                y_nm: y_nm.ok_or_else(|| KiCadError::Config {
                    reason: "hit-test requires `--y-nm <value>`".to_string(),
                })?,
                tolerance_nm,
            }
        }
        "types-pcb" => Command::PcbTypes,
        "items-raw" => {
            let mut type_codes = Vec::new();
            let mut include_debug = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--type-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for items-raw --type-id".to_string(),
                        })?;
                        type_codes.push(value.parse::<i32>().map_err(|err| {
                            KiCadError::Config {
                                reason: format!("invalid items-raw --type-id `{value}`: {err}"),
                            }
                        })?);
                        i += 2;
                    }
                    "--debug" => {
                        include_debug = true;
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if type_codes.is_empty() {
                return Err(KiCadError::Config {
                    reason: "items-raw requires one or more `--type-id <i32>` arguments"
                        .to_string(),
                });
            }

            Command::ItemsRaw {
                type_codes,
                include_debug,
            }
        }
        "items-raw-all-pcb" => {
            let include_debug = args.iter().any(|arg| arg == "--debug");
            Command::ItemsRawAllPcb { include_debug }
        }
        "pad-shape-polygon" => {
            let mut pad_ids = Vec::new();
            let mut layer_id = None;
            let mut include_debug = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--pad-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for pad-shape-polygon --pad-id".to_string(),
                        })?;
                        pad_ids.push(value.clone());
                        i += 2;
                    }
                    "--layer-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for pad-shape-polygon --layer-id".to_string(),
                        })?;
                        layer_id =
                            Some(value.parse::<i32>().map_err(|err| KiCadError::Config {
                                reason: format!(
                                    "invalid pad-shape-polygon --layer-id `{value}`: {err}"
                                ),
                            })?);
                        i += 2;
                    }
                    "--debug" => {
                        include_debug = true;
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if pad_ids.is_empty() {
                return Err(KiCadError::Config {
                    reason: "pad-shape-polygon requires one or more `--pad-id <uuid>` arguments"
                        .to_string(),
                });
            }

            Command::PadShapePolygon {
                pad_ids,
                layer_id: layer_id.ok_or_else(|| KiCadError::Config {
                    reason: "pad-shape-polygon requires `--layer-id <i32>`".to_string(),
                })?,
                include_debug,
            }
        }
        "padstack-presence" => {
            let mut item_ids = Vec::new();
            let mut layer_ids = Vec::new();
            let mut include_debug = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--item-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for padstack-presence --item-id".to_string(),
                        })?;
                        item_ids.push(value.clone());
                        i += 2;
                    }
                    "--layer-id" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for padstack-presence --layer-id".to_string(),
                        })?;
                        layer_ids.push(value.parse::<i32>().map_err(|err| KiCadError::Config {
                            reason: format!(
                                "invalid padstack-presence --layer-id `{value}`: {err}"
                            ),
                        })?);
                        i += 2;
                    }
                    "--debug" => {
                        include_debug = true;
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if item_ids.is_empty() {
                return Err(KiCadError::Config {
                    reason: "padstack-presence requires one or more `--item-id <uuid>` arguments"
                        .to_string(),
                });
            }
            if layer_ids.is_empty() {
                return Err(KiCadError::Config {
                    reason: "padstack-presence requires one or more `--layer-id <i32>` arguments"
                        .to_string(),
                });
            }

            Command::PadstackPresence {
                item_ids,
                layer_ids,
                include_debug,
            }
        }
        "title-block" => Command::TitleBlock,
        "board-as-string" => Command::BoardAsString,
        "selection-as-string" => Command::SelectionAsString,
        "stackup" => Command::Stackup,
        "graphics-defaults" => Command::GraphicsDefaults,
        "appearance" => Command::Appearance,
        "set-appearance" => {
            let mut inactive_layer_display = None;
            let mut net_color_display = None;
            let mut board_flip = None;
            let mut ratsnest_display = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--inactive-layer-display" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-appearance --inactive-layer-display"
                                .to_string(),
                        })?;
                        inactive_layer_display = Some(
                            parse_inactive_layer_display_mode(value)
                                .map_err(|err| KiCadError::Config { reason: err })?,
                        );
                        i += 2;
                    }
                    "--net-color-display" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-appearance --net-color-display"
                                .to_string(),
                        })?;
                        net_color_display = Some(
                            parse_net_color_display_mode(value)
                                .map_err(|err| KiCadError::Config { reason: err })?,
                        );
                        i += 2;
                    }
                    "--board-flip" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-appearance --board-flip".to_string(),
                        })?;
                        board_flip = Some(
                            parse_board_flip_mode(value)
                                .map_err(|err| KiCadError::Config { reason: err })?,
                        );
                        i += 2;
                    }
                    "--ratsnest-display" => {
                        let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                            reason: "missing value for set-appearance --ratsnest-display"
                                .to_string(),
                        })?;
                        ratsnest_display = Some(
                            parse_ratsnest_display_mode(value)
                                .map_err(|err| KiCadError::Config { reason: err })?,
                        );
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            Command::SetAppearance {
                inactive_layer_display: inactive_layer_display.ok_or_else(|| KiCadError::Config {
                    reason: "set-appearance requires `--inactive-layer-display <normal|dimmed|hidden>`".to_string(),
                })?,
                net_color_display: net_color_display.ok_or_else(|| KiCadError::Config {
                    reason: "set-appearance requires `--net-color-display <all|ratsnest|off>`"
                        .to_string(),
                })?,
                board_flip: board_flip.ok_or_else(|| KiCadError::Config {
                    reason: "set-appearance requires `--board-flip <normal|flipped-x>`"
                        .to_string(),
                })?,
                ratsnest_display: ratsnest_display.ok_or_else(|| KiCadError::Config {
                    reason:
                        "set-appearance requires `--ratsnest-display <all-layers|visible-layers>`"
                            .to_string(),
                    })?,
            }
        }
        "refill-zones" => {
            let mut zone_ids = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--zone-id" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for refill-zones --zone-id".to_string(),
                    })?;
                    zone_ids.push(value.clone());
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::RefillZones { zone_ids }
        }
        "netclass" => Command::NetClass,
        "proto-coverage-board-read" => Command::ProtoCoverageBoardRead,
        "board-read-report" => {
            let mut output = PathBuf::from("docs/BOARD_READ_REPORT.md");
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--out" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for board-read-report --out".to_string(),
                    })?;
                    output = PathBuf::from(value);
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::BoardReadReport { output }
        }
        "smoke" => Command::Smoke,
        "open-docs" => {
            let mut document_type = DocumentType::Pcb;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--type" {
                    let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                        reason: "missing value for open-docs --type".to_string(),
                    })?;
                    document_type = DocumentType::from_str(value)
                        .map_err(|err| KiCadError::Config { reason: err })?;
                    i += 2;
                    continue;
                }
                i += 1;
            }
            Command::OpenDocs { document_type }
        }
        other => {
            return Err(KiCadError::Config {
                reason: format!("unknown command `{other}`"),
            });
        }
    };

    Ok((config, command))
}

fn parse_inactive_layer_display_mode(value: &str) -> Result<InactiveLayerDisplayMode, String> {
    match value {
        "normal" => Ok(InactiveLayerDisplayMode::Normal),
        "dimmed" => Ok(InactiveLayerDisplayMode::Dimmed),
        "hidden" => Ok(InactiveLayerDisplayMode::Hidden),
        _ => Err(format!(
            "unknown inactive layer display `{value}`; expected normal, dimmed, or hidden"
        )),
    }
}

fn parse_net_color_display_mode(value: &str) -> Result<NetColorDisplayMode, String> {
    match value {
        "all" => Ok(NetColorDisplayMode::All),
        "ratsnest" => Ok(NetColorDisplayMode::Ratsnest),
        "off" => Ok(NetColorDisplayMode::Off),
        _ => Err(format!(
            "unknown net color display `{value}`; expected all, ratsnest, or off"
        )),
    }
}

fn parse_board_flip_mode(value: &str) -> Result<BoardFlipMode, String> {
    match value {
        "normal" => Ok(BoardFlipMode::Normal),
        "flipped-x" => Ok(BoardFlipMode::FlippedX),
        _ => Err(format!(
            "unknown board flip mode `{value}`; expected normal or flipped-x"
        )),
    }
}

fn parse_ratsnest_display_mode(value: &str) -> Result<RatsnestDisplayMode, String> {
    match value {
        "all-layers" => Ok(RatsnestDisplayMode::AllLayers),
        "visible-layers" => Ok(RatsnestDisplayMode::VisibleLayers),
        _ => Err(format!(
            "unknown ratsnest display `{value}`; expected all-layers or visible-layers"
        )),
    }
}

fn parse_drc_severity(value: &str) -> Result<DrcSeverity, String> {
    match value {
        "warning" => Ok(DrcSeverity::Warning),
        "error" => Ok(DrcSeverity::Error),
        "exclusion" => Ok(DrcSeverity::Exclusion),
        "ignore" => Ok(DrcSeverity::Ignore),
        "info" => Ok(DrcSeverity::Info),
        "action" => Ok(DrcSeverity::Action),
        "debug" => Ok(DrcSeverity::Debug),
        "undefined" => Ok(DrcSeverity::Undefined),
        _ => Err(format!(
            "unknown drc severity `{value}`; expected warning, error, exclusion, ignore, info, action, debug, or undefined"
        )),
    }
}

fn default_config() -> CliConfig {
    CliConfig {
        socket: None,
        token: None,
        client_name: None,
        timeout_ms: 15_000,
    }
}

fn print_help() {
    println!(
        "kicad-ipc-cli\n\nUSAGE:\n  cargo run --bin kicad-ipc-cli -- [--socket URI] [--token TOKEN] [--client-name NAME] [--timeout-ms N] <command> [command options]\n\nCOMMANDS:\n  ping                         Check IPC connectivity\n  version                      Fetch KiCad version\n  open-docs [--type <type>]    List open docs (default type: pcb)\n  project-path                 Get current project path from open PCB docs\n  board-open                   Exit non-zero if no PCB doc is open\n  net-classes                  List project netclass definitions\n  text-variables               List text variables for current board document\n  expand-text-variables        Expand variables in provided text values\n                               Options: --text <value> (repeatable)\n  text-extents                 Measure text bounding box\n                               Options: --text <value>\n  text-as-shapes               Convert text to rendered shapes\n                               Options: --text <value> (repeatable)\n  nets                         List board nets (requires one open PCB)\n  netlist-pads                 Emit pad-level netlist data (with footprint context)\n  items-by-id --id <uuid> ...  Show parsed details for specific item IDs\n  item-bbox --id <uuid> ...    Show bounding boxes for item IDs\n  hit-test --id <uuid> --x-nm <x> --y-nm <y> [--tolerance-nm <n>]\n                               Hit-test one item at a point\n  types-pcb                    List PCB KiCad object type IDs from proto enum\n  items-raw --type-id <id> ... Dump raw Any payloads for requested item type IDs\n  items-raw-all-pcb [--debug]  Dump all PCB item payloads across all PCB object types\n  pad-shape-polygon --pad-id <uuid> ... --layer-id <i32> [--debug]\n                               Dump pad polygons on a target layer\n  padstack-presence --item-id <uuid> ... --layer-id <i32> ... [--debug]\n                               Check padstack shape presence matrix across layers\n  title-block                  Show title block fields\n  board-as-string              Dump board as KiCad s-expression text\n  selection-as-string          Dump current selection as KiCad s-expression text\n  stackup                      Show typed board stackup\n  graphics-defaults            Show typed graphics defaults\n  appearance                   Show typed editor appearance settings\n  set-appearance --inactive-layer-display <normal|dimmed|hidden>\n                 --net-color-display <all|ratsnest|off>\n                 --board-flip <normal|flipped-x>\n                 --ratsnest-display <all-layers|visible-layers>\n                               Set editor appearance settings\n  inject-drc-error --severity <s> --message <text> [--x-nm <i64> --y-nm <i64>] [--item-id <uuid> ...]\n                               Inject a DRC marker (severity: warning|error|exclusion|ignore|info|action|debug|undefined)\n  refill-zones [--zone-id <uuid> ...]\n                               Refill all zones or a provided subset\n  netclass                     Show typed netclass map for current board nets\n  proto-coverage-board-read    Print board-read command coverage vs proto\n  board-read-report [--out P]  Write markdown board reconstruction report\n  enabled-layers               List enabled board layers\n  set-enabled-layers --copper-layer-count <u32> [--layer-id <i32> ...]\n                               Set enabled board layer set\n  active-layer                 Show active board layer\n  set-active-layer --layer-id <i32>\n                               Set active board layer\n  visible-layers               Show currently visible board layers\n  set-visible-layers --layer-id <i32> ...\n                               Set visible board layers\n  board-origin [--type <t>]    Show board origin (`grid` default, or `drill`)\n  set-board-origin --type <t> --x-nm <i64> --y-nm <i64>\n                               Set board origin (`grid` or `drill`)\n  refresh-editor [--frame <f>] Refresh a specific editor frame (default: pcb)\n  begin-commit                 Start staged commit and print commit ID\n  end-commit --id <uuid> [--action <commit|drop>] [--message <text>]\n                               End staged commit with commit/drop action\n  clear-selection              Clear current item selection\n  selection-summary            Show current selection item type counts\n  selection-details            Show parsed details for selected items\n  selection-raw                Show raw Any payload bytes for selected items\n  smoke                        ping + version + board-open summary\n  help                         Show help\n\nTYPES:\n  schematic | symbol | pcb | footprint | drawing-sheet | project\n"
    );
}

async fn build_board_read_report_markdown(client: &KiCadClient) -> Result<String, KiCadError> {
    let mut out = String::new();
    out.push_str("# Board Read Reconstruction Report\n\n");
    out.push_str("Generated by `kicad-ipc-cli board-read-report`.\n\n");
    out.push_str("Goal: verify that non-mutating PCB API reads are sufficient to reconstruct board state.\n\n");

    let version = client.get_version().await?;
    out.push_str("## Session\n\n");
    out.push_str(&format!(
        "- KiCad version: {}.{}.{} ({})\n",
        version.major, version.minor, version.patch, version.full_version
    ));
    out.push_str(&format!("- Socket URI: `{}`\n", client.socket_uri()));
    out.push_str(&format!(
        "- Timeout (ms): {}\n\n",
        client.timeout().as_millis()
    ));

    out.push_str("## Open Documents\n\n");
    let docs = client.get_open_documents(DocumentType::Pcb).await?;
    if docs.is_empty() {
        out.push_str("- No open PCB docs\n\n");
    } else {
        for (index, doc) in docs.iter().enumerate() {
            out.push_str(&format!(
                "- [{}] type={} board={} project_name={} project_path={}\n",
                index,
                doc.document_type,
                doc.board_filename.as_deref().unwrap_or("-"),
                doc.project.name.as_deref().unwrap_or("-"),
                doc.project
                    .path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "-".to_string())
            ));
        }
        out.push('\n');
    }

    out.push_str("## Layer / Origin / Nets\n\n");
    let enabled = client.get_board_enabled_layers().await?;
    let enabled_layers = enabled.layers.clone();
    out.push_str(&format!(
        "- copper_layer_count: {}\n",
        enabled.copper_layer_count
    ));
    out.push_str("- enabled_layers:\n");
    for layer in &enabled_layers {
        out.push_str(&format!("  - {} ({})\n", layer.name, layer.id));
    }

    let visible_layers = client.get_visible_layers().await?;
    out.push_str("- visible_layers:\n");
    for layer in visible_layers {
        out.push_str(&format!("  - {} ({})\n", layer.name, layer.id));
    }

    let active_layer = client.get_active_layer().await?;
    out.push_str(&format!(
        "- active_layer: {} ({})\n",
        active_layer.name, active_layer.id
    ));

    let grid_origin = client
        .get_board_origin(kicad_ipc::BoardOriginKind::Grid)
        .await?;
    out.push_str(&format!(
        "- grid_origin_nm: {},{}\n",
        grid_origin.x_nm, grid_origin.y_nm
    ));
    let drill_origin = client
        .get_board_origin(kicad_ipc::BoardOriginKind::Drill)
        .await?;
    out.push_str(&format!(
        "- drill_origin_nm: {},{}\n",
        drill_origin.x_nm, drill_origin.y_nm
    ));

    let nets = client.get_nets().await?;
    out.push_str(&format!("- net_count: {}\n", nets.len()));
    out.push_str("\n### Netlist\n\n");
    for net in &nets {
        out.push_str(&format!("- code={} name={}\n", net.code, net.name));
    }
    out.push('\n');

    out.push_str("### Pad-Level Netlist (Footprint/Pad/Net)\n\n");
    let pad_entries = client.get_pad_netlist().await?;
    let mut pad_ids = BTreeSet::new();
    out.push_str(&format!("- pad_entry_count: {}\n", pad_entries.len()));
    for (index, entry) in pad_entries.iter().enumerate() {
        if let Some(id) = entry.pad_id.as_ref() {
            pad_ids.insert(id.clone());
        }
        if index >= REPORT_MAX_PAD_NET_ROWS {
            continue;
        }
        out.push_str(&format!(
            "- footprint_ref={} footprint_id={} pad_id={} pad_number={} net_code={} net_name={}\n",
            entry.footprint_reference.as_deref().unwrap_or("-"),
            entry.footprint_id.as_deref().unwrap_or("-"),
            entry.pad_id.as_deref().unwrap_or("-"),
            entry.pad_number,
            entry
                .net_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            entry.net_name.as_deref().unwrap_or("-")
        ));
    }
    if pad_entries.len() > REPORT_MAX_PAD_NET_ROWS {
        out.push_str(&format!(
            "- ... omitted {} additional pad net rows (use `netlist-pads` CLI command for full output)\n",
            pad_entries.len() - REPORT_MAX_PAD_NET_ROWS
        ));
    }
    out.push('\n');

    let pad_ids: Vec<String> = pad_ids.into_iter().collect();
    let enabled_layer_ids: Vec<i32> = enabled_layers.iter().map(|layer| layer.id).collect();

    out.push_str("### Padstack Presence Matrix (Pad IDs x Enabled Layers)\n\n");
    out.push_str(&format!(
        "- unique_pad_id_count: {}\n- enabled_layer_count: {}\n",
        pad_ids.len(),
        enabled_layer_ids.len()
    ));

    let mut present_pad_ids_by_layer: BTreeMap<i32, BTreeSet<String>> = BTreeMap::new();
    let presence_rows = client
        .check_padstack_presence_on_layers(pad_ids.clone(), enabled_layer_ids)
        .await?;
    out.push_str(&format!(
        "- presence_entry_count: {}\n",
        presence_rows.len()
    ));
    for row in &presence_rows {
        if row.presence == PadstackPresenceState::Present {
            present_pad_ids_by_layer
                .entry(row.layer_id)
                .or_default()
                .insert(row.item_id.clone());
        }
    }
    for (index, row) in presence_rows.iter().enumerate() {
        if index >= REPORT_MAX_PRESENCE_ROWS {
            continue;
        }
        out.push_str(&format!(
            "- item_id={} layer_id={} layer_name={} presence={}\n",
            row.item_id, row.layer_id, row.layer_name, row.presence
        ));
    }
    if presence_rows.len() > REPORT_MAX_PRESENCE_ROWS {
        out.push_str(&format!(
            "- ... omitted {} additional presence rows (use `padstack-presence` CLI command for full output)\n",
            presence_rows.len() - REPORT_MAX_PRESENCE_ROWS
        ));
    }
    out.push('\n');

    out.push_str("### Pad Shape Polygons (All Present Pad/Layer Pairs)\n\n");
    out.push_str(
        "For full per-node coordinate payloads, run `pad-shape-polygon --pad-id ... --layer-id ... --debug` for targeted pad/layer subsets.\n\n",
    );
    for layer in &enabled_layers {
        let pad_ids_on_layer = present_pad_ids_by_layer
            .get(&layer.id)
            .map(|set| set.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        out.push_str(&format!(
            "#### Layer {} ({})\n\n- pad_count_present: {}\n\n",
            layer.name,
            layer.id,
            pad_ids_on_layer.len()
        ));

        if pad_ids_on_layer.is_empty() {
            continue;
        }

        let polygons = client
            .get_pad_shape_as_polygon(pad_ids_on_layer, layer.id)
            .await?;
        out.push_str(&format!("- polygon_entry_count: {}\n\n", polygons.len()));
        for row in polygons {
            let summary = polygon_geometry_summary(&row.polygon);
            out.push_str(&format!(
                "- pad_id={} layer_id={} layer_name={} outline_nodes={} hole_count={} hole_nodes_total={} point_nodes={} arc_nodes={}\n",
                row.pad_id,
                row.layer_id,
                row.layer_name,
                summary.outline_nodes,
                summary.hole_count,
                summary.hole_nodes_total,
                summary.point_nodes,
                summary.arc_nodes
            ));
        }
        out.push('\n');
    }

    out.push_str("## Board/Editor Structures\n\n");
    out.push_str("### Title Block\n\n");
    let title_block = client.get_title_block_info().await?;
    out.push_str(&format!("- title: {}\n", title_block.title));
    out.push_str(&format!("- date: {}\n", title_block.date));
    out.push_str(&format!("- revision: {}\n", title_block.revision));
    out.push_str(&format!("- company: {}\n", title_block.company));
    for (index, comment) in title_block.comments.iter().enumerate() {
        out.push_str(&format!("- comment{}: {}\n", index + 1, comment));
    }
    out.push('\n');

    out.push_str("### Stackup\n\n```text\n");
    out.push_str(&format!("{:#?}", client.get_board_stackup().await?));
    out.push_str("\n```\n\n");

    out.push_str("### Graphics Defaults\n\n```text\n");
    out.push_str(&format!("{:#?}", client.get_graphics_defaults().await?));
    out.push_str("\n```\n\n");

    out.push_str("### Editor Appearance\n\n```text\n");
    out.push_str(&format!(
        "{:#?}",
        client.get_board_editor_appearance_settings().await?
    ));
    out.push_str("\n```\n\n");

    out.push_str("### NetClass Map\n\n```text\n");
    out.push_str(&format!(
        "{:#?}",
        client
            .get_netclass_for_nets(client.get_nets().await?)
            .await?
    ));
    out.push_str("\n```\n\n");

    out.push_str("## PCB Item Coverage (All KOT_PCB_* Types)\n\n");
    let mut missing_types: Vec<PcbObjectTypeCode> = Vec::new();
    for object_type in kicad_ipc::KiCadClient::pcb_object_type_codes() {
        out.push_str(&format!(
            "### {} ({})\n\n",
            object_type.name, object_type.code
        ));
        match client
            .get_items_raw_by_type_codes(vec![object_type.code])
            .await
        {
            Ok(items) => {
                if items.is_empty() {
                    missing_types.push(*object_type);
                }
                out.push_str(&format!("- status: ok\n- count: {}\n\n", items.len()));

                for (index, item) in items
                    .iter()
                    .take(REPORT_MAX_ITEM_DEBUG_ROWS_PER_TYPE)
                    .enumerate()
                {
                    let mut debug = kicad_ipc::KiCadClient::debug_any_item(item)?;
                    if debug.len() > REPORT_MAX_ITEM_DEBUG_CHARS {
                        debug.truncate(REPORT_MAX_ITEM_DEBUG_CHARS);
                        debug.push_str("\n...<truncated; use items-raw CLI for full payload>");
                    }
                    out.push_str(&format!(
                        "#### item {}\n\n- type_url: `{}`\n- raw_len: `{}`\n\n",
                        index,
                        item.type_url,
                        item.value.len()
                    ));
                    out.push_str("```text\n");
                    out.push_str(&debug);
                    out.push_str("\n```\n\n");
                }
                if items.len() > REPORT_MAX_ITEM_DEBUG_ROWS_PER_TYPE {
                    out.push_str(&format!(
                        "- ... omitted {} additional item debug rows for {} (use `items-raw --type-id {}` for full output)\n\n",
                        items.len() - REPORT_MAX_ITEM_DEBUG_ROWS_PER_TYPE,
                        object_type.name,
                        object_type.code
                    ));
                }
            }
            Err(err) => {
                out.push_str(&format!("- status: error\n- error: `{}`\n\n", err));
            }
        }
    }

    out.push_str("## Missing Item Classes In Current Board\n\n");
    if missing_types.is_empty() {
        out.push_str("- none\n\n");
    } else {
        for object_type in missing_types {
            out.push_str(&format!(
                "- {} ({}) had zero items in this board\n",
                object_type.name, object_type.code
            ));
        }
        out.push_str("\nIf these are important for your reconstruction target, open a denser board and rerun this report.\n\n");
    }

    out.push_str("## Board File Snapshot (Raw)\n\n```scheme\n");
    let mut board_text = client.get_board_as_string().await?;
    if board_text.len() > REPORT_MAX_BOARD_SNAPSHOT_CHARS {
        board_text.truncate(REPORT_MAX_BOARD_SNAPSHOT_CHARS);
        board_text.push_str(
            "\n... ; <truncated board snapshot, rerun `board-as-string` command for full board text>\n",
        );
    }
    out.push_str(&board_text);
    out.push_str("\n```\n\n");

    out.push_str("## Proto Coverage (Board Read)\n\n");
    for (command, status, note) in proto_coverage_board_read_rows() {
        out.push_str(&format!("- `{}` -> `{}` ({})\n", command, status, note));
    }
    out.push('\n');

    Ok(out)
}

fn print_proto_coverage_board_read() {
    for (command, status, note) in proto_coverage_board_read_rows() {
        println!("command={} status={} note={}", command, status, note);
    }
}

fn proto_coverage_board_read_rows() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "kiapi.board.commands.GetBoardStackup",
            "implemented",
            "get_board_stackup_raw/get_board_stackup",
        ),
        (
            "kiapi.board.commands.GetBoardEnabledLayers",
            "implemented",
            "get_board_enabled_layers",
        ),
        (
            "kiapi.board.commands.GetGraphicsDefaults",
            "implemented",
            "get_graphics_defaults_raw/get_graphics_defaults",
        ),
        (
            "kiapi.board.commands.GetBoardOrigin",
            "implemented",
            "get_board_origin",
        ),
        ("kiapi.board.commands.GetNets", "implemented", "get_nets"),
        (
            "kiapi.board.commands.GetItemsByNet",
            "implemented",
            "get_items_by_net_raw",
        ),
        (
            "kiapi.board.commands.GetItemsByNetClass",
            "implemented",
            "get_items_by_net_class_raw",
        ),
        (
            "kiapi.board.commands.GetNetClassForNets",
            "implemented",
            "get_netclass_for_nets_raw/get_netclass_for_nets",
        ),
        (
            "kiapi.board.commands.GetPadShapeAsPolygon",
            "implemented",
            "get_pad_shape_as_polygon_raw/get_pad_shape_as_polygon",
        ),
        (
            "kiapi.board.commands.CheckPadstackPresenceOnLayers",
            "implemented",
            "check_padstack_presence_on_layers_raw/check_padstack_presence_on_layers",
        ),
        (
            "kiapi.board.commands.GetVisibleLayers",
            "implemented",
            "get_visible_layers",
        ),
        (
            "kiapi.board.commands.GetActiveLayer",
            "implemented",
            "get_active_layer",
        ),
        (
            "kiapi.board.commands.GetBoardEditorAppearanceSettings",
            "implemented",
            "get_board_editor_appearance_settings_raw/get_board_editor_appearance_settings",
        ),
        (
            "kiapi.common.commands.GetOpenDocuments",
            "implemented",
            "get_open_documents",
        ),
        (
            "kiapi.common.commands.GetNetClasses",
            "implemented",
            "get_net_classes_raw/get_net_classes",
        ),
        (
            "kiapi.common.commands.GetTextVariables",
            "implemented",
            "get_text_variables_raw/get_text_variables",
        ),
        (
            "kiapi.common.commands.ExpandTextVariables",
            "implemented",
            "expand_text_variables_raw/expand_text_variables",
        ),
        (
            "kiapi.common.commands.GetTextExtents",
            "implemented",
            "get_text_extents_raw/get_text_extents",
        ),
        (
            "kiapi.common.commands.GetTextAsShapes",
            "implemented",
            "get_text_as_shapes_raw/get_text_as_shapes",
        ),
        (
            "kiapi.common.commands.GetItems",
            "implemented",
            "get_items_raw_by_type_codes",
        ),
        (
            "kiapi.common.commands.GetItemsById",
            "implemented",
            "get_items_by_id_raw",
        ),
        (
            "kiapi.common.commands.GetBoundingBox",
            "implemented",
            "get_item_bounding_boxes",
        ),
        (
            "kiapi.common.commands.GetSelection",
            "implemented",
            "get_selection_raw/get_selection_details",
        ),
        (
            "kiapi.common.commands.HitTest",
            "implemented",
            "hit_test_item",
        ),
        (
            "kiapi.common.commands.GetTitleBlockInfo",
            "implemented",
            "get_title_block_info",
        ),
        (
            "kiapi.common.commands.SaveDocumentToString",
            "implemented",
            "get_board_as_string",
        ),
        (
            "kiapi.common.commands.SaveSelectionToString",
            "implemented",
            "get_selection_as_string",
        ),
    ]
}

#[derive(Default)]
struct PolygonGeometrySummary {
    outline_nodes: usize,
    hole_count: usize,
    hole_nodes_total: usize,
    point_nodes: usize,
    arc_nodes: usize,
}

fn polygon_geometry_summary(polygon: &kicad_ipc::PolygonWithHolesNm) -> PolygonGeometrySummary {
    let mut summary = PolygonGeometrySummary {
        hole_count: polygon.holes.len(),
        ..PolygonGeometrySummary::default()
    };

    if let Some(outline) = polygon.outline.as_ref() {
        summary.outline_nodes = outline.nodes.len();
        for node in &outline.nodes {
            match node {
                kicad_ipc::PolyLineNodeGeometryNm::Point(_) => summary.point_nodes += 1,
                kicad_ipc::PolyLineNodeGeometryNm::Arc(_) => summary.arc_nodes += 1,
            }
        }
    }

    for hole in &polygon.holes {
        summary.hole_nodes_total += hole.nodes.len();
        for node in &hole.nodes {
            match node {
                kicad_ipc::PolyLineNodeGeometryNm::Point(_) => summary.point_nodes += 1,
                kicad_ipc::PolyLineNodeGeometryNm::Arc(_) => summary.arc_nodes += 1,
            }
        }
    }

    summary
}

fn parse_item_ids(args: &[String], command_name: &str) -> Result<Vec<String>, KiCadError> {
    let mut item_ids = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--id" {
            let value = args.get(i + 1).ok_or_else(|| KiCadError::Config {
                reason: format!("missing value for {command_name} --id"),
            })?;
            item_ids.push(value.clone());
            i += 2;
            continue;
        }
        i += 1;
    }

    if item_ids.is_empty() {
        return Err(KiCadError::Config {
            reason: format!("{command_name} requires one or more `--id <uuid>` arguments"),
        });
    }

    Ok(item_ids)
}

fn bytes_to_hex(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push(hex_char((byte >> 4) & 0x0f));
        output.push(hex_char(byte & 0x0f));
    }
    output
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args_from, Command};
    use kicad_ipc::{
        BoardFlipMode, BoardOriginKind, CommitAction, DrcSeverity, InactiveLayerDisplayMode,
        NetColorDisplayMode, RatsnestDisplayMode,
    };

    #[test]
    fn parse_args_accepts_client_name_for_commit_flow() {
        let (config, command) = parse_args_from(vec![
            "--client-name".to_string(),
            "write-test".to_string(),
            "begin-commit".to_string(),
        ])
        .expect("client-name + begin-commit should parse");

        assert_eq!(config.client_name.as_deref(), Some("write-test"));
        assert!(matches!(command, Command::BeginCommit));
    }

    #[test]
    fn parse_args_parses_end_commit_flags() {
        let (_, command) = parse_args_from(vec![
            "end-commit".to_string(),
            "--id".to_string(),
            "commit-1".to_string(),
            "--action".to_string(),
            "drop".to_string(),
            "--message".to_string(),
            "cleanup".to_string(),
        ])
        .expect("end-commit args should parse");

        match command {
            Command::EndCommit {
                id,
                action,
                message,
            } => {
                assert_eq!(id, "commit-1");
                assert_eq!(action, CommitAction::Drop);
                assert_eq!(message, "cleanup");
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_refresh_editor_frame() {
        let (_, command) = parse_args_from(vec![
            "refresh-editor".to_string(),
            "--frame".to_string(),
            "schematic".to_string(),
        ])
        .expect("refresh-editor args should parse");

        match command {
            Command::RefreshEditor { frame } => {
                assert_eq!(frame.to_string(), "schematic");
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_clear_selection() {
        let (_, command) = parse_args_from(vec!["clear-selection".to_string()])
            .expect("clear-selection should parse");
        assert!(matches!(command, Command::ClearSelection));
    }

    #[test]
    fn parse_args_parses_set_active_layer() {
        let (_, command) = parse_args_from(vec![
            "set-active-layer".to_string(),
            "--layer-id".to_string(),
            "31".to_string(),
        ])
        .expect("set-active-layer args should parse");

        match command {
            Command::SetActiveLayer { layer_id } => assert_eq!(layer_id, 31),
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_set_enabled_layers() {
        let (_, command) = parse_args_from(vec![
            "set-enabled-layers".to_string(),
            "--copper-layer-count".to_string(),
            "2".to_string(),
            "--layer-id".to_string(),
            "47".to_string(),
            "--layer-id".to_string(),
            "52".to_string(),
        ])
        .expect("set-enabled-layers args should parse");

        match command {
            Command::SetEnabledLayers {
                copper_layer_count,
                layer_ids,
            } => {
                assert_eq!(copper_layer_count, 2);
                assert_eq!(layer_ids, vec![47, 52]);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_set_visible_layers() {
        let (_, command) = parse_args_from(vec![
            "set-visible-layers".to_string(),
            "--layer-id".to_string(),
            "3".to_string(),
            "--layer-id".to_string(),
            "47".to_string(),
        ])
        .expect("set-visible-layers args should parse");

        match command {
            Command::SetVisibleLayers { layer_ids } => assert_eq!(layer_ids, vec![3, 47]),
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_set_board_origin() {
        let (_, command) = parse_args_from(vec![
            "set-board-origin".to_string(),
            "--type".to_string(),
            "drill".to_string(),
            "--x-nm".to_string(),
            "123".to_string(),
            "--y-nm".to_string(),
            "456".to_string(),
        ])
        .expect("set-board-origin args should parse");

        match command {
            Command::SetBoardOrigin { kind, x_nm, y_nm } => {
                assert_eq!(kind, BoardOriginKind::Drill);
                assert_eq!(x_nm, 123);
                assert_eq!(y_nm, 456);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_set_appearance() {
        let (_, command) = parse_args_from(vec![
            "set-appearance".to_string(),
            "--inactive-layer-display".to_string(),
            "hidden".to_string(),
            "--net-color-display".to_string(),
            "off".to_string(),
            "--board-flip".to_string(),
            "flipped-x".to_string(),
            "--ratsnest-display".to_string(),
            "visible-layers".to_string(),
        ])
        .expect("set-appearance args should parse");

        match command {
            Command::SetAppearance {
                inactive_layer_display,
                net_color_display,
                board_flip,
                ratsnest_display,
            } => {
                assert_eq!(inactive_layer_display, InactiveLayerDisplayMode::Hidden);
                assert_eq!(net_color_display, NetColorDisplayMode::Off);
                assert_eq!(board_flip, BoardFlipMode::FlippedX);
                assert_eq!(ratsnest_display, RatsnestDisplayMode::VisibleLayers);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_inject_drc_error() {
        let (_, command) = parse_args_from(vec![
            "inject-drc-error".to_string(),
            "--severity".to_string(),
            "warning".to_string(),
            "--message".to_string(),
            "marker".to_string(),
            "--x-nm".to_string(),
            "100".to_string(),
            "--y-nm".to_string(),
            "200".to_string(),
        ])
        .expect("inject-drc-error args should parse");

        match command {
            Command::InjectDrcError {
                severity,
                message,
                x_nm,
                y_nm,
                item_ids,
            } => {
                assert_eq!(severity, DrcSeverity::Warning);
                assert_eq!(message, "marker");
                assert_eq!(x_nm, Some(100));
                assert_eq!(y_nm, Some(200));
                assert!(item_ids.is_empty());
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }

    #[test]
    fn parse_args_parses_refill_zones() {
        let (_, command) = parse_args_from(vec![
            "refill-zones".to_string(),
            "--zone-id".to_string(),
            "zone-1".to_string(),
            "--zone-id".to_string(),
            "zone-2".to_string(),
        ])
        .expect("refill-zones args should parse");

        match command {
            Command::RefillZones { zone_ids } => {
                assert_eq!(zone_ids, vec!["zone-1".to_string(), "zone-2".to_string()]);
            }
            other => panic!("unexpected command variant: {other:?}"),
        }
    }
}
