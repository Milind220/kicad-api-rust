use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use kicad_ipc::{BoardOriginKind, ClientBuilder, DocumentType, KiCadError, Vector2Nm};

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
        "kicad-ipc-cli\n\nUSAGE:\n  cargo run --bin kicad-ipc-cli -- [--socket URI] [--token TOKEN] [--timeout-ms N] <command> [command options]\n\nCOMMANDS:\n  ping                         Check IPC connectivity\n  version                      Fetch KiCad version\n  open-docs [--type <type>]    List open docs (default type: pcb)\n  project-path                 Get current project path from open PCB docs\n  board-open                   Exit non-zero if no PCB doc is open\n  nets                         List board nets (requires one open PCB)\n  netlist-pads                 Emit pad-level netlist data (with footprint context)\n  items-by-id --id <uuid> ...  Show parsed details for specific item IDs\n  item-bbox --id <uuid> ...    Show bounding boxes for item IDs\n  hit-test --id <uuid> --x-nm <x> --y-nm <y> [--tolerance-nm <n>]\n                               Hit-test one item at a point\n  enabled-layers               List enabled board layers\n  active-layer                 Show active board layer\n  visible-layers               Show currently visible board layers\n  board-origin [--type <t>]    Show board origin (`grid` default, or `drill`)\n  selection-summary            Show current selection item type counts\n  selection-details            Show parsed details for selected items\n  selection-raw                Show raw Any payload bytes for selected items\n  smoke                        ping + version + board-open summary\n  help                         Show help\n\nTYPES:\n  schematic | symbol | pcb | footprint | drawing-sheet | project\n"
    );
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
