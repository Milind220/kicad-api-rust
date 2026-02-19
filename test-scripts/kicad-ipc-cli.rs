use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use kicad_ipc::{
    BoardOriginKind, ClientBuilder, DocumentType, KiCadClient, KiCadError, PcbObjectTypeCode,
    Vector2Nm,
};

#[derive(Debug)]
struct CliConfig {
    socket: Option<String>,
    token: Option<String>,
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
    Nets,
    EnabledLayers,
    ActiveLayer,
    VisibleLayers,
    BoardOrigin {
        kind: BoardOriginKind,
    },
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
    TitleBlock,
    BoardAsString,
    SelectionAsString,
    StackupDebug,
    GraphicsDefaultsDebug,
    AppearanceDebug,
    NetClassDebug,
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
        Command::ActiveLayer => {
            let layer = client.get_active_layer().await?;
            println!(
                "active_layer_id={} active_layer_name={}",
                layer.id, layer.name
            );
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
        Command::BoardOrigin { kind } => {
            let origin = client.get_board_origin(kind).await?;
            println!(
                "origin_kind={} x_nm={} y_nm={}",
                kind, origin.x_nm, origin.y_nm
            );
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
        Command::StackupDebug => {
            let debug = client.get_board_stackup_debug().await?;
            println!("{debug}");
        }
        Command::GraphicsDefaultsDebug => {
            let debug = client.get_graphics_defaults_debug().await?;
            println!("{debug}");
        }
        Command::AppearanceDebug => {
            let debug = client.get_board_editor_appearance_settings_debug().await?;
            println!("{debug}");
        }
        Command::NetClassDebug => {
            let nets = client.get_nets().await?;
            let debug = client.get_netclass_for_nets_debug(nets).await?;
            println!("{debug}");
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();

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
        "nets" => Command::Nets,
        "enabled-layers" => Command::EnabledLayers,
        "active-layer" => Command::ActiveLayer,
        "visible-layers" => Command::VisibleLayers,
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
        "title-block" => Command::TitleBlock,
        "board-as-string" => Command::BoardAsString,
        "selection-as-string" => Command::SelectionAsString,
        "stackup-debug" => Command::StackupDebug,
        "graphics-defaults-debug" => Command::GraphicsDefaultsDebug,
        "appearance-debug" => Command::AppearanceDebug,
        "netclass-debug" => Command::NetClassDebug,
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

fn default_config() -> CliConfig {
    CliConfig {
        socket: None,
        token: None,
        timeout_ms: 3_000,
    }
}

fn print_help() {
    println!(
        "kicad-ipc-cli\n\nUSAGE:\n  cargo run --bin kicad-ipc-cli -- [--socket URI] [--token TOKEN] [--timeout-ms N] <command> [command options]\n\nCOMMANDS:\n  ping                         Check IPC connectivity\n  version                      Fetch KiCad version\n  open-docs [--type <type>]    List open docs (default type: pcb)\n  project-path                 Get current project path from open PCB docs\n  board-open                   Exit non-zero if no PCB doc is open\n  nets                         List board nets (requires one open PCB)\n  netlist-pads                 Emit pad-level netlist data (with footprint context)\n  items-by-id --id <uuid> ...  Show parsed details for specific item IDs\n  item-bbox --id <uuid> ...    Show bounding boxes for item IDs\n  hit-test --id <uuid> --x-nm <x> --y-nm <y> [--tolerance-nm <n>]\n                               Hit-test one item at a point\n  types-pcb                    List PCB KiCad object type IDs from proto enum\n  items-raw --type-id <id> ... Dump raw Any payloads for requested item type IDs\n  items-raw-all-pcb [--debug]  Dump all PCB item payloads across all PCB object types\n  title-block                  Show title block fields\n  board-as-string              Dump board as KiCad s-expression text\n  selection-as-string          Dump current selection as KiCad s-expression text\n  stackup-debug                Dump raw stackup response\n  graphics-defaults-debug      Dump raw graphics defaults response\n  appearance-debug             Dump raw editor appearance settings response\n  netclass-debug               Dump raw netclass map for current board nets\n  proto-coverage-board-read    Print board-read command coverage vs proto\n  board-read-report [--out P]  Write markdown board reconstruction report\n  enabled-layers               List enabled board layers\n  active-layer                 Show active board layer\n  visible-layers               Show currently visible board layers\n  board-origin [--type <t>]    Show board origin (`grid` default, or `drill`)\n  selection-summary            Show current selection item type counts\n  selection-details            Show parsed details for selected items\n  selection-raw                Show raw Any payload bytes for selected items\n  smoke                        ping + version + board-open summary\n  help                         Show help\n\nTYPES:\n  schematic | symbol | pcb | footprint | drawing-sheet | project\n"
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
    out.push_str(&format!(
        "- copper_layer_count: {}\n",
        enabled.copper_layer_count
    ));
    out.push_str("- enabled_layers:\n");
    for layer in enabled.layers {
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
    out.push_str(&format!("- pad_entry_count: {}\n", pad_entries.len()));
    for entry in pad_entries {
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
    out.push('\n');

    out.push_str("## Board/Editor Raw Structures\n\n");
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

    out.push_str("### Stackup (Raw Debug)\n\n```text\n");
    out.push_str(&client.get_board_stackup_debug().await?);
    out.push_str("\n```\n\n");

    out.push_str("### Graphics Defaults (Raw Debug)\n\n```text\n");
    out.push_str(&client.get_graphics_defaults_debug().await?);
    out.push_str("\n```\n\n");

    out.push_str("### Editor Appearance (Raw Debug)\n\n```text\n");
    out.push_str(&client.get_board_editor_appearance_settings_debug().await?);
    out.push_str("\n```\n\n");

    out.push_str("### NetClass Map (Raw Debug)\n\n```text\n");
    out.push_str(&client.get_netclass_for_nets_debug(nets).await?);
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

                for (index, item) in items.iter().enumerate() {
                    out.push_str(&format!(
                        "#### item {}\n\n- type_url: `{}`\n- raw_len: `{}`\n\n",
                        index,
                        item.type_url,
                        item.value.len()
                    ));
                    out.push_str("```text\n");
                    out.push_str(&kicad_ipc::KiCadClient::debug_any_item(item)?);
                    out.push_str("\n```\n\n");
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
    out.push_str(&client.get_board_as_string().await?);
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
            "get_board_stackup_debug",
        ),
        (
            "kiapi.board.commands.GetBoardEnabledLayers",
            "implemented",
            "get_board_enabled_layers",
        ),
        (
            "kiapi.board.commands.GetGraphicsDefaults",
            "implemented",
            "get_graphics_defaults_debug",
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
            "get_netclass_for_nets_debug",
        ),
        (
            "kiapi.board.commands.GetPadShapeAsPolygon",
            "not-yet",
            "pending",
        ),
        (
            "kiapi.board.commands.CheckPadstackPresenceOnLayers",
            "not-yet",
            "pending",
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
            "get_board_editor_appearance_settings_debug",
        ),
        (
            "kiapi.common.commands.GetOpenDocuments",
            "implemented",
            "get_open_documents",
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
