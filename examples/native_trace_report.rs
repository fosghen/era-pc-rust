//! Offline metadata correlation only: never executes a target or infers event state.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

const MAX_LINE: usize = 32768;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100128;
const MAX_CALLS: usize = 10000;
const MAX_WAIT_MEMBERS: usize = 10000;

#[derive(Clone, Debug)]
struct Call {
    id: u64,
    enter: u64,
    leave: Option<u64>,
    api: String,
    thread: u64,
    fields: Value,
    result: Option<u64>,
    returned_handle: Option<String>,
    caller: Value,
    aliases: Vec<String>,
    uncertain: bool,
}

fn select_fields(fields: &Value) -> Result<Value, String> {
    let mut selected = serde_json::Map::new();
    for key in [
        "manualReset",
        "initialState",
        "namePointer",
        "handle",
        "countRaw",
        "waitAll",
        "timeoutMs",
        "controlCode",
        "inputSize",
        "outputSize",
    ] {
        let v = &fields[key];
        if v.is_null()
            || v.is_boolean()
            || v.as_u64().is_some()
            || v.as_str().is_some_and(|s| s.len() <= 18)
        {
            selected.insert(key.into(), v.clone());
        } else {
            return Err(format!("Invalid bounded field {key}"));
        }
    }
    if let Some(items) = fields["array"]["handles"].as_array() {
        if items.len() > 64 {
            return Err("Wait array exceeds 64 handles".into());
        }
        let handles: Result<Vec<_>, _> = items.iter().map(handle).collect();
        selected.insert("array".into(), json!({"handles": handles?}));
    }
    Ok(Value::Object(selected))
}

fn alias_metadata(p: &Value, api: &str) -> (Vec<String>, bool) {
    let Some(raw) = p["aliases"].as_array() else {
        return (Vec::new(), true);
    };
    if raw.is_empty() || raw.len() > 12 {
        return (Vec::new(), true);
    }
    let mut aliases = Vec::new();
    for v in raw {
        let Some(s) = v.as_str().filter(|s| {
            !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
        }) else {
            return (Vec::new(), true);
        };
        aliases.push(s.to_string());
    }
    let event_encoding_only = matches!(api, "CreateEventA" | "CreateEventW")
        && aliases
            .iter()
            .all(|a| matches!(a.as_str(), "CreateEventA" | "CreateEventW"));
    let uncertain = !aliases.iter().any(|a| a == api)
        || !(aliases.len() == 1 || event_encoding_only)
        || p["ambiguousAliases"] == true
        || !p["fields"]["error"].is_null();
    (aliases, uncertain)
}

fn number(v: &Value, key: &str) -> Result<u64, String> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("Missing/invalid unsigned field {key}"))
}

fn handle(v: &Value) -> Result<String, String> {
    let s = v.as_str().ok_or("Handle must be a hex string")?;
    let digits = s.strip_prefix("0x").ok_or("Handle must start with 0x")?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid handle width/characters".into());
    }
    let n = u64::from_str_radix(digits, 16).map_err(|_| "Invalid handle")?;
    Ok(format!("0x{n:x}"))
}

fn caller(v: &Value) -> Value {
    if v["callerModuleStatus"] != "resolved" {
        return Value::Null;
    }
    let m = &v["callerModule"];
    match (m["name"].as_str(), handle(&m["rva"])) {
        (Some(name), Ok(rva))
            if !name.is_empty()
                && name.len() <= 128
                && !name
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\') =>
        {
            json!({"module": name, "rva": rva})
        }
        _ => Value::Null,
    }
}

fn parse(reader: impl BufRead) -> Result<(Vec<Call>, Value), String> {
    let mut reader = reader;
    let mut total = 0;
    let mut count = 0;
    let mut last_seq = 0;
    let mut calls = Vec::<Call>::new();
    let mut ids = BTreeMap::new();
    let mut summary = Value::Null;
    let mut gaps = 0;
    let mut limits = 0;
    let mut errors = 0;
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take((MAX_LINE + 2) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "Cannot read input")?;
        if n == 0 {
            break;
        }
        total += n;
        count += 1;
        if n > MAX_LINE + 1 || total > MAX_BYTES || count > MAX_RECORDS {
            return Err("Trace size/record budget exceeded".into());
        }
        let row: Value =
            serde_json::from_slice(&line).map_err(|_| format!("Invalid JSON at record {count}"))?;
        if !summary.is_null() {
            return Err("Records after final summary".into());
        }
        if row["type"] == "summary" {
            summary = json!({"reason": row["reason"].as_str(),
                "recorder_dropped": row["recorder_dropped"].as_u64(),
                "instrumentation_errors": row["instrumentation_errors"].as_u64(),
                "resumed": row["resumed"].as_bool()});
            continue;
        }
        if row["type"] == "agent_error" {
            errors += 1;
        }
        if row["type"] != "agent" {
            continue;
        }
        let p = &row["payload"];
        let seq = number(p, "seq")?;
        if seq <= last_seq {
            return Err("Non-increasing observer sequence".into());
        }
        if seq != last_seq + 1 {
            gaps += 1;
        }
        last_seq = seq;
        if p["type"] == "limit" {
            limits += 1;
        }
        if p["type"] != "api" {
            continue;
        }
        let id = number(p, "callId")?;
        let thread = number(p, "threadId")?;
        let api = p["api"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .ok_or("Invalid API name")?;
        if p["phase"] == "enter" {
            if calls.len() >= MAX_CALLS {
                return Err("API call budget exceeded".into());
            }
            if ids.insert(id, calls.len()).is_some() {
                return Err("Duplicate call ID".into());
            }
            let (aliases, uncertain) = alias_metadata(p, api);
            calls.push(Call {
                id,
                enter: seq,
                leave: None,
                api: api.into(),
                thread,
                fields: if uncertain {
                    json!({})
                } else {
                    select_fields(&p["fields"])?
                },
                result: None,
                returned_handle: None,
                caller: caller(p),
                aliases,
                uncertain,
            });
        } else if p["phase"] == "leave" {
            let index = *ids.get(&id).ok_or("Unpaired leave")?;
            let call = &mut calls[index];
            if call.leave.is_some() || call.api != api || call.thread != thread {
                return Err("Inconsistent enter/leave pair".into());
            }
            call.leave = Some(seq);
            call.result = p["fields"]["returnU32"]
                .as_u64()
                .filter(|n| *n <= u32::MAX as u64);
            call.returned_handle = handle(&p["fields"]["returnValue"]).ok();
        } else {
            return Err("Unknown API phase".into());
        }
    }
    Ok((
        calls,
        json!({"records": count, "bytes": total, "sequence_gaps": gaps,
        "limit_markers": limits, "agent_errors": errors, "capture_summary": summary}),
    ))
}

fn point(c: &Call) -> Value {
    json!({"call_id": c.id, "enter_seq": c.enter, "leave_seq": c.leave,
        "api": c.api, "aliases": c.aliases, "uncertain_api_metadata": c.uncertain,
        "thread_id": c.thread, "caller": c.caller, "return_u32": c.result})
}

fn analyze(calls: &[Call], quality: Value) -> Result<Value, String> {
    if calls.len() > MAX_CALLS {
        return Err("API call budget exceeded".into());
    }
    let incomplete = calls.iter().any(|c| c.uncertain)
        || quality["sequence_gaps"].as_u64() != Some(0)
        || quality["limit_markers"].as_u64() != Some(0)
        || quality["agent_errors"].as_u64() != Some(0)
        || quality["capture_summary"]["recorder_dropped"].as_u64() != Some(0)
        || quality["capture_summary"]["instrumentation_errors"].as_u64() != Some(0);
    // All actions are ordered by observation sequence, NOT by assumed OS linearization.
    let mut actions = Vec::new();
    for (index, c) in calls.iter().enumerate() {
        actions.push((c.enter, false, index));
        if let Some(seq) = c.leave {
            actions.push((seq, true, index));
        }
    }
    actions.sort_unstable();
    let mut active = BTreeMap::<String, usize>::new();
    let mut generations = Vec::<Value>::new();
    let mut waits = Vec::new();
    let mut ioctls = Vec::new();
    let mut overlaps = 0;
    let mut targets = BTreeMap::<u64, Option<usize>>::new();
    let mut pending_closes = BTreeMap::<usize, usize>::new();
    let mut unknown_operations = 0;
    let mut total_members = 0;
    let mut uncertain_calls = Vec::new();
    for (_, leaving, index) in actions {
        let c = &calls[index];
        if c.uncertain {
            if !leaving {
                uncertain_calls.push(point(c));
            }
            continue;
        }
        if leaving {
            if c.api == "CloseHandle" {
                if let Some(Some(g)) = targets.get(&c.id) {
                    if let Some(n) = pending_closes.get_mut(g) {
                        *n = n.saturating_sub(1);
                    }
                }
            }
            if matches!(c.api.as_str(), "CreateEventA" | "CreateEventW") {
                if let Some(h) = c.returned_handle.as_ref().filter(|h| h.as_str() != "0x0") {
                    let generation = generations.len();
                    let previous = active.insert(h.clone(), generation);
                    if let Some(old) = previous {
                        overlaps += 1;
                        generations[old]["ambiguous_lifetime"] = json!(true);
                    }
                    generations.push(json!({"id": generation, "handle": h, "created": point(c),
                        "manual_reset_argument": c.fields["manualReset"].as_bool(),
                        "initial_state_argument": c.fields["initialState"].as_bool(),
                        "unnamed": handle(&c.fields["namePointer"]).ok().map(|h| h == "0x0"),
                        "closed": null, "close_overlap": null,
                        "ambiguous_lifetime": previous.is_some(), "operations": []}));
                }
            } else if c.api == "CloseHandle" && c.result.is_some_and(|r| r != 0) {
                let h = handle(&c.fields["handle"])?;
                if let Some(Some(g)) = targets.get(&c.id) {
                    if active.get(&h) == Some(g) {
                        active.remove(&h);
                        generations[*g]["closed"] = point(c);
                    } else {
                        generations[*g]["close_overlap"] = point(c);
                        generations[*g]["ambiguous_lifetime"] = json!(true);
                    }
                }
            }
            continue;
        }
        match c.api.as_str() {
            "SetEvent" | "ResetEvent" | "CloseHandle" | "WaitForSingleObject" => {
                let h = handle(&c.fields["handle"])?;
                let generation = active.get(&h).copied();
                targets.insert(c.id, generation);
                if let Some(g) = generation {
                    if c.api == "CloseHandle" {
                        *pending_closes.entry(g).or_default() += 1;
                    }
                    generations[g]["operations"]
                        .as_array_mut()
                        .unwrap()
                        .push(point(c));
                } else {
                    unknown_operations += 1;
                }
            }
            "WaitForMultipleObjects" => {
                let count = number(&c.fields, "countRaw")?;
                if !(1..=64).contains(&count) {
                    waits.push(json!({"call":point(c),"count":count,"array_available":false,
                        "members":[],"duplicate_handles":null,"diagnostic":"invalid_native_wait_count"}));
                    continue;
                }
                let mut members = Vec::new();
                let mut unique = BTreeSet::new();
                if let Some(handles) = c.fields["array"]["handles"].as_array() {
                    if handles.len() != count as usize {
                        return Err("Wait array count mismatch".into());
                    }
                    total_members += handles.len();
                    if total_members > MAX_WAIT_MEMBERS {
                        return Err("Total wait-member budget exceeded".into());
                    }
                    for h in handles {
                        let h = handle(h)?;
                        unique.insert(h.clone());
                        let generation = active.get(&h);
                        let status = match generation {
                            None => "no_observed_creation",
                            Some(g) if generations[*g]["ambiguous_lifetime"] == true => {
                                "ambiguous_reuse"
                            }
                            Some(g) if pending_closes.get(g).is_some_and(|n| *n > 0) => {
                                "ambiguous_close_interval"
                            }
                            Some(_) if incomplete => "incomplete_observation",
                            Some(_) => "observation_order_only",
                        };
                        members.push(json!({"handle": h, "observed_generation": generation,
                            "correlation_status": status}));
                    }
                }
                waits.push(json!({"call": point(c), "count": count,
                    "wait_all_argument": c.fields["waitAll"].as_bool(),
                    "timeout_ms": c.fields["timeoutMs"].as_u64(),
                    "array_available": members.len() == count as usize,
                    "duplicate_handles": if members.is_empty() { None } else { Some(unique.len() != members.len()) },
                    "members": members,
                    "outcome": if c.leave.is_some() { "return_observed" } else { "return_not_observed" }}));
            }
            "DeviceIoControl" => ioctls.push(json!({"call": point(c),
                "control_code": c.fields["controlCode"].as_u64(),
                "input_size": c.fields["inputSize"].as_u64(),
                "output_size": c.fields["outputSize"].as_u64()})),
            _ => {}
        }
    }
    Ok(
        json!({"schema_version": 1, "quality": quality, "calls": calls.len(),
        "unreturned_calls": calls.iter().filter(|c| c.leave.is_none()).count(),
        "event_generations": generations, "waits": waits, "device_io_controls": ioctls,
        "uncertain_calls": uncertain_calls,
        "overlapping_observed_event_handles": overlaps, "operations_without_observed_event": unknown_operations,
        "limitations": ["Observation-order correlation only, not OS object identity or live state.",
            "Named CreateEvent arguments need not describe an already existing object's state.",
            "Unhooked opens, duplicate handles, native syscalls and concurrent transitions are not reconstructed.",
            "No return observed does not prove deadlock, timeout, or licensing failure.",
            "API caller attribution does not identify a USB device or establish call purpose."]}),
    )
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("Usage: native_trace_report INPUT.jsonl NEW-REPORT.json".into());
    }
    let input = File::open(&args[0]).map_err(|_| "Cannot open input")?;
    let (calls, quality) = parse(BufReader::new(input))?;
    let report = analyze(&calls, quality)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[1])
        .map_err(|_| "Cannot exclusively create output (must not exist)")?;
    // Avoid a separate Windows-mounted-filesystem write for every JSON token.
    let mut output = BufWriter::with_capacity(64 * 1024, output);
    serde_json::to_writer_pretty(&mut output, &report).map_err(|_| "Cannot write report")?;
    output
        .write_all(b"\n")
        .map_err(|_| "Cannot finish report")?;
    output.flush().map_err(|_| "Cannot flush report")?;
    println!(
        "Analyzed {} API calls; metadata report written",
        calls.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn call(
        id: u64,
        enter: u64,
        leave: Option<u64>,
        api: &str,
        fields: Value,
        result: u64,
    ) -> Call {
        Call {
            id,
            enter,
            leave,
            api: api.into(),
            thread: 1,
            fields,
            result: leave.map(|_| result),
            returned_handle: leave.map(|_| format!("0x{result:x}")),
            caller: Value::Null,
            aliases: vec![api.into()],
            uncertain: false,
        }
    }
    fn create(id: u64, seq: u64, h: u64) -> Call {
        call(
            id,
            seq,
            Some(seq + 1),
            "CreateEventW",
            json!({"manualReset":false,"initialState":false,"namePointer":"0x0"}),
            h,
        )
    }
    fn wait(id: u64, seq: u64, handles: Value) -> Call {
        call(
            id,
            seq,
            None,
            "WaitForMultipleObjects",
            json!({"countRaw":handles.as_array().unwrap().len(),
            "array":{"handles":handles},"waitAll":false,"timeoutMs":60000}),
            0,
        )
    }
    #[test]
    fn correlates_without_claiming_current_state() {
        let calls = vec![
            create(1, 1, 16),
            call(2, 3, Some(4), "SetEvent", json!({"handle":"0x10"}), 1),
            wait(3, 5, json!(["0x10"])),
        ];
        let r = analyze(&calls, Value::Null).unwrap();
        assert_eq!(r["waits"][0]["members"][0]["observed_generation"], 0);
        assert_eq!(
            r["event_generations"][0]["operations"][0]["api"],
            "SetEvent"
        );
        assert_eq!(r["waits"][0]["outcome"], "return_not_observed");
        assert!(r["event_generations"][0].get("current_state").is_none());
    }
    #[test]
    fn close_and_reuse_create_distinct_generations() {
        let calls = vec![
            create(1, 1, 16),
            wait(2, 3, json!(["0x10"])),
            call(3, 4, Some(5), "CloseHandle", json!({"handle":"0x10"}), 1),
            wait(4, 6, json!(["0x10"])),
            create(5, 7, 16),
            wait(6, 9, json!(["0x10"])),
        ];
        let r = analyze(&calls, Value::Null).unwrap();
        assert_eq!(r["waits"][0]["members"][0]["observed_generation"], 0);
        assert!(r["waits"][1]["members"][0]["observed_generation"].is_null());
        assert_eq!(r["waits"][2]["members"][0]["observed_generation"], 1);
    }
    #[test]
    fn failed_close_preserves_generation_and_failed_creation_is_not_object() {
        let calls = vec![
            create(1, 1, 0),
            create(2, 3, 16),
            call(3, 5, Some(6), "CloseHandle", json!({"handle":"0x10"}), 0),
            wait(4, 7, json!(["0x10"])),
        ];
        let r = analyze(&calls, Value::Null).unwrap();
        assert_eq!(r["event_generations"].as_array().unwrap().len(), 1);
        assert_eq!(r["waits"][0]["members"][0]["observed_generation"], 0);
    }
    #[test]
    fn preserves_duplicates_unknowns_and_unavailable_array() {
        let mut w = wait(1, 1, json!(["0x10", "0x10", "0x20"]));
        let r = analyze(&[w.clone()], Value::Null).unwrap();
        assert_eq!(r["waits"][0]["duplicate_handles"], true);
        assert_eq!(r["waits"][0]["members"].as_array().unwrap().len(), 3);
        w.fields["array"] = json!({"error":"array_unreadable"});
        assert_eq!(
            analyze(&[w], Value::Null).unwrap()["waits"][0]["array_available"],
            false
        );
    }
    #[test]
    fn no_generation_until_create_returns_and_overlap_is_flagged() {
        let mut c = create(1, 1, 16);
        c.leave = Some(4);
        let r = analyze(
            &[c, wait(2, 2, json!(["0x10"])), create(3, 5, 16)],
            Value::Null,
        )
        .unwrap();
        assert!(r["waits"][0]["members"][0]["observed_generation"].is_null());
        assert_eq!(r["overlapping_observed_event_handles"], 1);
    }
    #[test]
    fn rejects_bad_handles_and_array_counts() {
        for s in ["123", "0x", "0x-1", "0x10000000000000000", "0xzz"] {
            assert!(handle(&json!(s)).is_err());
        }
        assert_eq!(handle(&json!("0x00AB")).unwrap(), "0xab");
        let mut w = wait(1, 1, json!(["0x10"]));
        w.fields["countRaw"] = json!(2);
        assert!(analyze(&[w], Value::Null).is_err());
    }
    fn row(seq: u64, phase: &str, api: &str) -> Value {
        json!({"type":"agent","payload":{"type":"api","seq":seq,"callId":1,
            "threadId":1,"phase":phase,"api":api,"aliases":[api],"fields":{}}})
    }
    fn parse_rows(rows: &[Value]) -> Result<(Vec<Call>, Value), String> {
        let text = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        parse(text.as_bytes())
    }
    #[test]
    fn parser_rejects_duplicate_unpaired_or_mismatched_calls() {
        assert!(parse_rows(&[row(1, "leave", "SetEvent")]).is_err());
        assert!(parse_rows(&[row(1, "enter", "SetEvent"), row(2, "enter", "SetEvent")]).is_err());
        assert!(parse_rows(&[row(1, "enter", "SetEvent"), row(2, "leave", "ResetEvent")]).is_err());
        assert!(parse_rows(&[row(1, "enter", "SetEvent"), row(1, "leave", "SetEvent")]).is_err());
        assert!(parse_rows(&[row(1, "enter", "SetEvent"), row(2, "leave", "SetEvent")]).is_ok());
    }
    #[test]
    fn parser_flags_gaps_truncation_and_enforces_record_bound() {
        let (c, q) = parse_rows(&[row(2, "enter", "SetEvent")]).unwrap();
        assert_eq!(q["sequence_gaps"], 1);
        assert!(q["capture_summary"].is_null());
        assert!(c[0].leave.is_none());
        assert!(parse(vec![b' '; MAX_LINE + 2].as_slice()).is_err());
        assert!(parse_rows(&[json!({"type":"summary"}), row(1, "enter", "SetEvent")]).is_err());
    }
    #[test]
    fn caller_output_never_copies_paths_or_extra_fields() {
        let r = caller(
            &json!({"callerModuleStatus":"resolved","callerModule":{"name":"own.dll","rva":"0x12","path":"secret","dump":"secret"}}),
        );
        assert_eq!(r, json!({"module":"own.dll","rva":"0x12"}));
        assert!(caller(&json!({"callerModule":{"name":"C:\\secret.dll","rva":"0x12"}})).is_null());
    }

    #[test]
    fn alias_uncertainty_never_creates_typed_objects_or_operations() {
        for (api, aliases) in [
            ("CreateEventA", json!(["CreateEventA", "DeviceIoControl"])),
            ("SetEvent", json!(["SetEvent", "ResetEvent"])),
        ] {
            let mut enter = row(1, "enter", api);
            enter["payload"]["aliases"] = aliases;
            let mut leave = row(2, "leave", api);
            leave["payload"]["fields"] = json!({"returnValue":"0x10","returnU32":16});
            let (calls, q) = parse_rows(&[enter, leave]).unwrap();
            let r = analyze(&calls, q).unwrap();
            assert_eq!(r["uncertain_calls"].as_array().unwrap().len(), 1);
            assert!(r["event_generations"].as_array().unwrap().is_empty());
        }
        let (aliases, uncertain) = alias_metadata(
            &json!({"aliases":["CreateEventA","CreateEventW"]}),
            "CreateEventA",
        );
        assert_eq!(aliases.len(), 2);
        assert!(!uncertain);
        assert!(alias_metadata(&json!({}), "CreateEventA").1);
    }

    #[test]
    fn overlap_and_incomplete_trace_are_machine_readable() {
        let calls = vec![
            create(1, 1, 16),
            call(2, 3, Some(6), "CloseHandle", json!({"handle":"0x10"}), 1),
            create(3, 4, 16),
            wait(4, 7, json!(["0x10"])),
        ];
        let r = analyze(&calls, Value::Null).unwrap();
        assert_eq!(r["event_generations"][0]["close_overlap"]["call_id"], 2);
        assert_eq!(
            r["waits"][0]["members"][0]["correlation_status"],
            "ambiguous_reuse"
        );
        let r = analyze(
            &[create(1, 1, 16), wait(2, 3, json!(["0x10"]))],
            Value::Null,
        )
        .unwrap();
        assert_eq!(
            r["waits"][0]["members"][0]["correlation_status"],
            "incomplete_observation"
        );
    }

    #[test]
    fn skipped_possible_close_taints_correlation_even_without_sequence_gaps() {
        let mut close = call(2, 3, Some(4), "CloseHandle", json!({"handle":"0x10"}), 1);
        close.uncertain = true;
        close.aliases.push("ResumeThread".into());
        let quality = json!({"sequence_gaps":0,"limit_markers":0,"agent_errors":0,
            "capture_summary":{"recorder_dropped":0,"instrumentation_errors":0}});
        let r = analyze(
            &[create(1, 1, 16), close, wait(3, 5, json!(["0x10"]))],
            quality,
        )
        .unwrap();
        assert_eq!(
            r["waits"][0]["members"][0]["correlation_status"],
            "incomplete_observation"
        );
    }

    #[test]
    fn wait_during_close_is_ambiguous_and_unknown_name_stays_null() {
        let calls = vec![
            create(1, 1, 16),
            call(2, 3, Some(5), "CloseHandle", json!({"handle":"0x10"}), 0),
            wait(3, 4, json!(["0x10"])),
            wait(4, 6, json!(["0x10"])),
        ];
        let r = analyze(&calls, Value::Null).unwrap();
        assert_eq!(
            r["waits"][0]["members"][0]["correlation_status"],
            "ambiguous_close_interval"
        );
        assert_eq!(
            r["waits"][1]["members"][0]["correlation_status"],
            "incomplete_observation"
        );
        let mut c = create(1, 1, 16);
        c.fields = json!({});
        assert!(analyze(&[c], Value::Null).unwrap()["event_generations"][0]["unnamed"].is_null());
    }

    #[test]
    fn retained_fields_and_total_member_expansion_are_bounded() {
        let fields =
            select_fields(&json!({"unknown":{"large":vec![0;10000]},"handle":"0x10"})).unwrap();
        assert!(fields.get("unknown").is_none());
        assert!(select_fields(&json!({"handle":"x".repeat(100)})).is_err());
        let w = wait(1, 1, json!(vec!["0x10"; 64]));
        assert!(analyze(&vec![w; MAX_WAIT_MEMBERS / 64 + 1], Value::Null).is_err());
        assert!(analyze(&vec![create(1, 1, 16); MAX_CALLS + 1], Value::Null).is_err());
    }

    #[test]
    fn unavailable_array_and_invalid_native_count_are_not_false_successes() {
        let mut w = wait(1, 1, json!(["0x10"]));
        w.fields["array"] = json!({"error":"unreadable"});
        assert!(
            analyze(&[w.clone()], Value::Null).unwrap()["waits"][0]["duplicate_handles"].is_null()
        );
        w.fields["countRaw"] = json!(65);
        assert_eq!(
            analyze(&[w], Value::Null).unwrap()["waits"][0]["diagnostic"],
            "invalid_native_wait_count"
        );
        assert!(caller(&json!({"callerModuleStatus":"lookup_failed",
            "callerModule":{"name":"own.dll","rva":"0x12"}}))
        .is_null());
    }
}
