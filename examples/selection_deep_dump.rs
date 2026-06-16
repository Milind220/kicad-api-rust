#[cfg(feature = "blocking")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "blocking")]
use std::thread::sleep;
#[cfg(feature = "blocking")]
use std::time::Duration;

#[cfg(feature = "blocking")]
use kicad_ipc_rs::{
    BoardNet, KiCadClient, KiCadClientBlocking, KiCadError, PcbArc, PcbBoardGraphicShape,
    PcbBoardText, PcbBoardTextBox, PcbDimension, PcbField, PcbFootprintInstance, PcbGroup, PcbItem,
    PcbPad, PcbTrack, PcbVia, PcbZone,
};
#[cfg(feature = "blocking")]
fn retry<T, F>(label: &str, mut op: F) -> Result<T, KiCadError>
where
    F: FnMut() -> Result<T, KiCadError>,
{
    let attempts = 6;
    for attempt in 1..=attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt == attempts {
                    return Err(err);
                }
                eprintln!("warn: {label} attempt {attempt} failed: {err}");
                sleep(Duration::from_millis(300));
            }
        }
    }
    unreachable!("attempt loop exits via return");
}

#[cfg(feature = "blocking")]
fn item_id(item: &PcbItem) -> Option<&str> {
    match item {
        PcbItem::Track(v) => v.id.as_deref(),
        PcbItem::Arc(v) => v.id.as_deref(),
        PcbItem::Via(v) => v.id.as_deref(),
        PcbItem::FootprintInstance(v) => v.id.as_deref(),
        PcbItem::Pad(v) => v.id.as_deref(),
        PcbItem::BoardGraphicShape(v) => v.id.as_deref(),
        PcbItem::BoardText(v) => v.id.as_deref(),
        PcbItem::BoardTextBox(v) => v.id.as_deref(),
        PcbItem::Field(_) => None,
        PcbItem::Zone(v) => v.id.as_deref(),
        PcbItem::Dimension(v) => v.id.as_deref(),
        PcbItem::Group(v) => v.id.as_deref(),
        PcbItem::ReferenceImage(v) => v.id.as_deref(),
        PcbItem::Barcode(v) => v.id.as_deref(),
        PcbItem::Unknown(_) => None,
    }
}
#[cfg(feature = "blocking")]
fn pcb_type_code(name: &str) -> Option<i32> {
    KiCadClient::pcb_object_type_codes()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.code)
}

#[cfg(feature = "blocking")]
fn extract_property(line: &str, key: &str) -> Option<String> {
    let marker = format!("(property \"{key}\" \"");
    let start = line.find(&marker)?;
    let rest = &line[start + marker.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(feature = "blocking")]
fn parse_ref_values_from_selection_sexpr(contents: &str) -> BTreeMap<String, String> {
    let mut refs = Vec::new();
    let mut vals = Vec::new();
    for line in contents.lines() {
        if let Some(reference) = extract_property(line, "Reference") {
            refs.push(reference);
        }
        if let Some(value) = extract_property(line, "Value") {
            vals.push(value);
        }
    }

    let mut out = BTreeMap::new();
    let limit = refs.len().min(vals.len());
    for index in 0..limit {
        out.insert(refs[index].clone(), vals[index].clone());
    }
    out
}

#[cfg(feature = "blocking")]
fn print_item(item: &PcbItem) {
    match item {
        PcbItem::Track(PcbTrack {
            id,
            start_nm,
            end_nm,
            width_nm,
            layer,
            net,
            ..
        }) => {
            println!(
                "  track id={} start={:?} end={:?} width_nm={:?} layer={} net={}",
                id.as_deref().unwrap_or("-"),
                start_nm.map(|v| (v.x_nm, v.y_nm)),
                end_nm.map(|v| (v.x_nm, v.y_nm)),
                width_nm,
                layer.name,
                net.as_ref().map(|v| v.name.as_str()).unwrap_or("-")
            );
        }
        PcbItem::Arc(PcbArc {
            id,
            start_nm,
            mid_nm,
            end_nm,
            width_nm,
            layer,
            net,
            ..
        }) => {
            println!(
                "  arc id={} start={:?} mid={:?} end={:?} width_nm={:?} layer={} net={}",
                id.as_deref().unwrap_or("-"),
                start_nm.map(|v| (v.x_nm, v.y_nm)),
                mid_nm.map(|v| (v.x_nm, v.y_nm)),
                end_nm.map(|v| (v.x_nm, v.y_nm)),
                width_nm,
                layer.name,
                net.as_ref().map(|v| v.name.as_str()).unwrap_or("-")
            );
        }
        PcbItem::Via(PcbVia {
            id,
            position_nm,
            via_type,
            layers,
            net,
            ..
        }) => {
            let stack = layers
                .as_ref()
                .map(|l| {
                    l.padstack_layers
                        .iter()
                        .map(|x| x.name.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  via id={} pos={:?} via_type={:?} layers={} net={}",
                id.as_deref().unwrap_or("-"),
                position_nm.map(|v| (v.x_nm, v.y_nm)),
                via_type,
                stack,
                net.as_ref().map(|v| v.name.as_str()).unwrap_or("-")
            );
        }
        PcbItem::FootprintInstance(PcbFootprintInstance {
            id,
            reference,
            position_nm,
            orientation_deg,
            layer,
            pad_count,
            ..
        }) => {
            println!(
                "  footprint id={} ref={} pos={:?} orientation_deg={:?} layer={} pad_count={}",
                id.as_deref().unwrap_or("-"),
                reference.as_deref().unwrap_or("-"),
                position_nm.map(|v| (v.x_nm, v.y_nm)),
                orientation_deg,
                layer.name,
                pad_count
            );
        }
        PcbItem::Pad(PcbPad {
            id,
            number,
            pad_type,
            position_nm,
            net,
            ..
        }) => {
            println!(
                "  pad id={} number={} pad_type={:?} pos={:?} net={}",
                id.as_deref().unwrap_or("-"),
                number,
                pad_type,
                position_nm.map(|v| (v.x_nm, v.y_nm)),
                net.as_ref().map(|v| v.name.as_str()).unwrap_or("-")
            );
        }
        PcbItem::BoardGraphicShape(PcbBoardGraphicShape {
            id,
            layer,
            net,
            geometry_kind,
            ..
        }) => {
            println!(
                "  shape id={} layer={} geometry={} net={}",
                id.as_deref().unwrap_or("-"),
                layer.name,
                geometry_kind.as_deref().unwrap_or("-"),
                net.as_ref().map(|v| v.name.as_str()).unwrap_or("-")
            );
        }
        PcbItem::BoardText(PcbBoardText {
            id, layer, text, ..
        }) => {
            println!(
                "  text id={} layer={} text={}",
                id.as_deref().unwrap_or("-"),
                layer.name,
                text.as_deref().unwrap_or("-")
            );
        }
        PcbItem::BoardTextBox(PcbBoardTextBox {
            id, layer, text, ..
        }) => {
            println!(
                "  textbox id={} layer={} text={}",
                id.as_deref().unwrap_or("-"),
                layer.name,
                text.as_deref().unwrap_or("-")
            );
        }
        PcbItem::Field(PcbField {
            name,
            visible,
            text,
        }) => {
            println!(
                "  field name={} visible={} text={}",
                name,
                visible,
                text.as_deref().unwrap_or("-")
            );
        }
        PcbItem::Zone(PcbZone {
            id,
            name,
            zone_type,
            layer_count,
            filled,
            polygon_count,
            ..
        }) => {
            println!(
                "  zone id={} name={} zone_type={:?} layers={} filled={} polygons={}",
                id.as_deref().unwrap_or("-"),
                name,
                zone_type,
                layer_count,
                filled,
                polygon_count
            );
        }
        PcbItem::Dimension(PcbDimension {
            id,
            layer,
            text,
            style_kind,
            ..
        }) => {
            println!(
                "  dimension id={} layer={} style={} text={}",
                id.as_deref().unwrap_or("-"),
                layer.name,
                style_kind.as_deref().unwrap_or("-"),
                text.as_deref().unwrap_or("-")
            );
        }
        PcbItem::Group(PcbGroup {
            id,
            name,
            item_count,
            ..
        }) => {
            println!(
                "  group id={} name={} item_count={}",
                id.as_deref().unwrap_or("-"),
                name,
                item_count
            );
        }
        PcbItem::ReferenceImage(v) => {
            println!(
                "  reference_image id={} layer={} image_data_len={}",
                v.id.as_deref().unwrap_or("-"),
                v.layer.name,
                v.image_data_len
            );
        }
        PcbItem::Barcode(v) => {
            println!(
                "  barcode id={} layer={} kind={:?} text={}",
                v.id.as_deref().unwrap_or("-"),
                v.layer.name,
                v.kind,
                v.text
            );
        }
        PcbItem::Unknown(v) => {
            println!("  unknown type={} raw_len={}", v.type_url, v.raw_len);
        }
    }
}
#[cfg(feature = "blocking")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = KiCadClientBlocking::connect()?;

    retry("ping", || client.ping())?;
    let version = retry("get_version", || client.get_version())?;
    println!("version={}", version.full_version);

    let summary = retry("get_selection_summary", || {
        client.get_selection_summary(Vec::new())
    })?;
    println!("selection_total={}", summary.total_items);
    for count in summary.type_url_counts {
        println!(
            "selection_type type_url={} count={}",
            count.type_url, count.count
        );
    }
    if summary.total_items == 0 {
        println!("selection is empty; nothing to inspect");
        return Ok(());
    }

    let selected_items = retry("get_selection", || client.get_selection(Vec::new()))?;
    let selected_details = retry("get_selection_details", || {
        client.get_selection_details(Vec::new())
    })?;
    let selected_raw = retry("get_selection_raw", || client.get_selection_raw(Vec::new()))?;

    println!("selected_items_decoded={}", selected_items.len());
    for item in &selected_items {
        print_item(item);
    }

    println!("selected_items_raw={}", selected_raw.len());
    for (idx, item) in selected_raw.iter().enumerate() {
        println!(
            "  raw[{idx}] type_url={} raw_len={}",
            item.type_url,
            item.value.len()
        );
    }

    println!("selected_items_detail_rows={}", selected_details.len());
    for (idx, row) in selected_details.iter().enumerate() {
        println!(
            "  detail[{idx}] type_url={} raw_len={} detail={}",
            row.type_url, row.raw_len, row.detail
        );
    }

    let selected_ids: Vec<String> = selected_items
        .iter()
        .filter_map(item_id)
        .map(str::to_string)
        .collect();
    println!("selected_ids={}", selected_ids.len());
    for id in &selected_ids {
        println!("  id={id}");
    }

    if !selected_ids.is_empty() {
        let bboxes = retry("get_item_bounding_boxes", || {
            client.get_item_bounding_boxes(selected_ids.clone(), true)
        })?;
        println!("item_bounding_boxes={}", bboxes.len());
        for bbox in bboxes {
            println!(
                "  bbox id={} x_nm={} y_nm={} width_nm={} height_nm={}",
                bbox.item_id, bbox.x_nm, bbox.y_nm, bbox.width_nm, bbox.height_nm
            );
        }
    }

    let mut selected_footprints = Vec::new();
    for item in &selected_items {
        if let PcbItem::FootprintInstance(fp) = item {
            selected_footprints.push(fp.clone());
        }
    }
    let selected_refs: BTreeSet<String> = selected_footprints
        .iter()
        .filter_map(|fp| fp.reference.clone())
        .collect();
    let selected_fp_ids: BTreeSet<String> = selected_footprints
        .iter()
        .filter_map(|fp| fp.id.clone())
        .collect();

    println!("selected_footprints={}", selected_footprints.len());
    for fp in &selected_footprints {
        println!(
            "  footprint ref={} id={} pos={:?} orientation_deg={:?} layer={} pad_count={}",
            fp.reference.as_deref().unwrap_or("-"),
            fp.id.as_deref().unwrap_or("-"),
            fp.position_nm.map(|v| (v.x_nm, v.y_nm)),
            fp.orientation_deg,
            fp.layer.name,
            fp.pad_count
        );
    }

    match retry("get_selection_as_string", || {
        client.get_selection_as_string()
    }) {
        Ok(selection_dump) => {
            println!("selection_string_ids={}", selection_dump.ids.len());
            let ref_values = parse_ref_values_from_selection_sexpr(&selection_dump.contents);
            println!("ref_value_pairs={}", ref_values.len());
            for (reference, value) in ref_values {
                println!("  {reference} => {value}");
            }
        }
        Err(err) => {
            println!("ref_value_pairs unavailable: {err}");
        }
    }

    let pad_netlist = retry("get_pad_netlist", || client.get_pad_netlist())?;
    let mut selected_pad_rows = Vec::new();
    for row in pad_netlist {
        let by_ref = row
            .footprint_reference
            .as_ref()
            .map(|r| selected_refs.contains(r))
            .unwrap_or(false);
        let by_id = row
            .footprint_id
            .as_ref()
            .map(|id| selected_fp_ids.contains(id))
            .unwrap_or(false);
        if by_ref || by_id {
            selected_pad_rows.push(row);
        }
    }

    println!("selected_pad_rows={}", selected_pad_rows.len());
    let mut selected_net_names = BTreeSet::new();
    let mut net_to_selected_refs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in &selected_pad_rows {
        let reference = row
            .footprint_reference
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| "-".to_string());
        let net = row
            .net_name
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  pad ref={} fp_id={} pad_id={} pad_number={} net_code={:?} net_name={}",
            reference,
            row.footprint_id.as_deref().unwrap_or("-"),
            row.pad_id.as_deref().unwrap_or("-"),
            row.pad_number,
            row.net_code,
            net
        );

        if net != "-" {
            selected_net_names.insert(net.clone());
            if reference != "-" {
                net_to_selected_refs
                    .entry(net)
                    .or_default()
                    .insert(reference);
            }
        }
    }

    println!("selected_net_names={}", selected_net_names.len());
    for net in &selected_net_names {
        println!("  net={net}");
    }

    println!("interconnections_among_selected_refs");
    for (net, refs) in &net_to_selected_refs {
        if refs.len() >= 2 {
            println!(
                "  net={} refs={}",
                net,
                refs.iter().cloned().collect::<Vec<_>>().join(",")
            );
        }
    }

    let all_nets = retry("get_nets", || client.get_nets())?;
    let mut name_to_code = BTreeMap::new();
    for net in all_nets {
        name_to_code.insert(net.name, net.code);
    }

    let mut selected_nets: Vec<BoardNet> = selected_net_names
        .iter()
        .map(|name| BoardNet {
            code: *name_to_code.get(name).unwrap_or(&0),
            name: name.clone(),
        })
        .collect();
    selected_nets.sort_by(|left, right| left.name.cmp(&right.name));
    selected_nets.dedup_by(|left, right| left.name == right.name);

    let selected_nets_missing_code = selected_nets.iter().filter(|net| net.code == 0).count();
    if selected_nets_missing_code > 0 {
        println!(
            "selected_nets_missing_legacy_codes={} (name-based queries still used)",
            selected_nets_missing_code
        );
    }
    println!("selected_nets(name-deduped)={:?}", selected_nets);

    let route_type_codes: Vec<i32> = [
        "KOT_PCB_TRACE",
        "KOT_PCB_VIA",
        "KOT_PCB_ARC",
        "KOT_PCB_ZONE",
        "KOT_PCB_PAD",
        "KOT_PCB_SHAPE",
    ]
    .into_iter()
    .filter_map(pcb_type_code)
    .collect();
    println!("route_type_codes={route_type_codes:?}");

    if !selected_nets.is_empty() && !route_type_codes.is_empty() {
        match retry("get_items_by_net", || {
            client.get_items_by_net(route_type_codes.clone(), selected_nets.clone())
        }) {
            Ok(connected_items) => {
                let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
                for item in &connected_items {
                    let label = match item {
                        PcbItem::Track(_) => "track",
                        PcbItem::Via(_) => "via",
                        PcbItem::Arc(_) => "arc",
                        PcbItem::Zone(_) => "zone",
                        PcbItem::Pad(_) => "pad",
                        _ => "other",
                    };
                    *counts.entry(label).or_insert(0) += 1;
                }

                println!("connected_items_on_selected_nets={}", connected_items.len());
                for (label, count) in counts {
                    println!("  connected_{label}s={count}");
                }

                for item in connected_items.iter().take(80) {
                    print_item(item);
                }
            }
            Err(err) => {
                println!("connected_items_on_selected_nets unavailable via GetItemsByNet: {err}");
                println!("connected_items fallback: scan-by-type + local net-name filter");

                let mut items = Vec::new();
                for code in &route_type_codes {
                    match retry("get_items_by_type_code_fallback", || {
                        client.get_items_by_type_codes(vec![*code])
                    }) {
                        Ok(mut bucket) => items.append(&mut bucket),
                        Err(type_err) => {
                            println!("  fallback type_code={code} unavailable: {type_err}");
                        }
                    }
                }

                if items.is_empty() {
                    println!("connected_items fallback unavailable: no items from type scans");
                } else {
                    let filtered: Vec<PcbItem> = items
                        .into_iter()
                        .filter(|item| match item {
                            PcbItem::Track(track) => track
                                .net
                                .as_ref()
                                .map(|n| selected_net_names.contains(&n.name))
                                .unwrap_or(false),
                            PcbItem::Via(via) => via
                                .net
                                .as_ref()
                                .map(|n| selected_net_names.contains(&n.name))
                                .unwrap_or(false),
                            PcbItem::Arc(arc) => arc
                                .net
                                .as_ref()
                                .map(|n| selected_net_names.contains(&n.name))
                                .unwrap_or(false),
                            PcbItem::Pad(pad) => pad
                                .net
                                .as_ref()
                                .map(|n| selected_net_names.contains(&n.name))
                                .unwrap_or(false),
                            PcbItem::BoardGraphicShape(shape) => shape
                                .net
                                .as_ref()
                                .map(|n| selected_net_names.contains(&n.name))
                                .unwrap_or(false),
                            _ => false,
                        })
                        .collect();

                    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
                    for item in &filtered {
                        let label = match item {
                            PcbItem::Track(_) => "track",
                            PcbItem::Via(_) => "via",
                            PcbItem::Arc(_) => "arc",
                            PcbItem::Pad(_) => "pad",
                            PcbItem::BoardGraphicShape(_) => "shape",
                            _ => "other",
                        };
                        *counts.entry(label).or_insert(0) += 1;
                    }

                    println!(
                        "connected_items_on_selected_nets_fallback={}",
                        filtered.len()
                    );
                    for (label, count) in counts {
                        println!("  connected_{label}s={count}");
                    }

                    for item in filtered.iter().take(120) {
                        print_item(item);
                    }
                }
            }
        }
    } else {
        println!("connected_items_on_selected_nets unavailable: no selected net names");
    }

    Ok(())
}

#[cfg(not(feature = "blocking"))]
fn main() {
    eprintln!("run with --features blocking");
    std::process::exit(1);
}
