use std::fs;
use std::path::Path;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};

#[test]
fn hunt_ndjson_preserves_apple_timestamp_and_selects_one_event() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.ndjson");
    let rule = dir.path().join("rule.yml");
    let mapping = Path::new(env!("CARGO_MANIFEST_DIR")).join("mappings/sigma-macos-unified.yml");
    let mut event = json!({
        "eventType": "logEvent",
        "timestamp": "2026-11-27 01:02:03.123456-0500",
        "subsystem": "com.apple.securityd",
        "eventMessage": "fixture audit",
        "processID": 108
    });
    let first = event.to_string();
    event["subsystem"] = json!("com.apple.clock");
    fs::write(&input, format!("{{\"timestamp\":\"not an event timestamp\",\"inventory\":\"batch\"}}\n{first}\n{event}\n{{\"finished\":1}}\n")).unwrap();
    fs::write(&rule, "title: Security subsystem event\ndescription: Select a security subsystem record\nstatus: experimental\nlevel: informational\nlogsource: {product: macos}\ndetection:\n  selection: {subsystem: com.apple.securityd}\n  condition: selection\n").unwrap();

    let result = cargo_bin_cmd!("chainsaw")
        .arg("hunt")
        .arg(&input)
        .arg("--sigma")
        .arg(&rule)
        .arg("--mapping")
        .arg(mapping)
        .arg("--jsonl")
        .assert()
        .success();
    let hits: Vec<Value> = serde_json::Deserializer::from_slice(&result.get_output().stdout)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["name"], "Security subsystem event");
    assert_eq!(hits[0]["document"]["data"]["processID"], 108);
    assert!(
        hits[0]["timestamp"]
            .as_str()
            .unwrap()
            .starts_with("2026-11-27T06:02:03.123456")
    );
}

#[test]
fn a_broken_logarchive_reports_a_decoder_error() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("broken.logarchive");
    fs::create_dir(&archive).unwrap();
    let result = cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg("--jsonl")
        .arg(archive)
        .assert()
        .failure();
    assert!(result.get_output().stdout.is_empty());
}
