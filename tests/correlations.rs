use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use tempfile::TempDir;

const BASE: &str = r#"title: First component
name: first
id: e698ebb6-0a0b-49f0-b212-000000000001
detection:
  selection:
    Event: first
  condition: selection
---
title: Second component
name: second
id: e698ebb6-0a0b-49f0-b212-000000000002
detection:
  selection:
    Event: second
  condition: selection
"#;

fn rule(kind: &str, refs: &str, extra: &str) -> String {
    format!(
        "title: Compound signal\nid: d3307bad-9859-4115-aa76-5566589a8a68\nlevel: high\ncorrelation:\n  type: {kind}\n  rules: [{refs}]\n  group-by: [Host, User]\n  timespan: 10s\n{extra}"
    )
}

fn event(time: &str, component: &str, row: u64) -> Value {
    json!({"time":format!("2025-10-21T00:00:{time}Z"), "type":component, "host":"lab","user":"usr","row":row})
}

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new(base: &str, rule: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("rules")).unwrap();
        fs::write(dir.path().join("rules/compound.yml"), rule).unwrap();
        fs::write(dir.path().join("rules/components.yml"), base).unwrap();
        fs::write(
            dir.path().join("mapping.yml"),
            r#"
kind: json
rules: sigma
groups:
  - name: test
    timestamp: time
    filter:
      type: "*"
    fields:
      - {from: Event, to: type}
      - {from: Host, to: host}
      - {from: User, to: user}
      - {from: Remote, to: remote}
"#,
        )
        .unwrap();
        fs::create_dir(dir.path().join("events")).unwrap();
        Self { dir }
    }

    fn write(&self, path: &str, events: &[Value]) {
        let text = events
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(self.dir.path().join("events").join(path), text).unwrap();
    }

    fn command(&self) -> assert_cmd::Command {
        let mut cmd = cargo_bin_cmd!("chainsaw");
        cmd.current_dir(self.dir.path()).args([
            "hunt",
            "events",
            "-s",
            "rules",
            "--mapping",
            "mapping.yml",
        ]);
        cmd
    }

    fn hits(&self, flags: &[&str]) -> Vec<Value> {
        let out = self.command().arg("--json").args(flags).assert().success();
        serde_json::from_slice(&out.get_output().stdout).unwrap()
    }
}

#[test]
fn temporal_uses_mapped_group_and_cross_file_inclusive_window() {
    for (kind, expected) in [("temporal", true), ("temporal_ordered", false)] {
        let f = Fixture::new(
            BASE,
            &rule(kind, "first, e698ebb6-0a0b-49f0-b212-000000000002", ""),
        );
        f.write("a.jsonl", &[event("20", "first", 4)]);
        f.write("b.jsonl", &[event("10", "second", 8)]);
        let hits = f.hits(&["--preprocess"]);
        assert_eq!(hits.len(), usize::from(expected));
        if expected {
            assert_eq!(hits[0]["name"], "Compound signal");
            assert_eq!(hits[0]["id"], "d3307bad-9859-4115-aa76-5566589a8a68");
            let docs = hits[0]["documents"].as_array().unwrap();
            assert_eq!(docs.len(), 2);
            assert_eq!(docs[0]["data"]["row"], 8);
            assert_eq!(docs[1]["data"]["row"], 4);
            assert_eq!(docs[1]["record_index"], 1);
            assert!(docs[0]["path"].as_str().unwrap().ends_with("b.jsonl"));
            assert!(docs[1]["path"].as_str().unwrap().ends_with("a.jsonl"));
        }
    }
}

#[test]
fn ordered_rejects_missing_split_group_wrong_order_and_outside_window() {
    let f = Fixture::new(BASE, &rule("temporal_ordered", "first, second", ""));
    for (host, user, time) in [
        (None, Some("usr"), "11"),
        (Some("other"), Some("usr"), "11"),
        (Some("lab"), Some("other"), "11"),
        (Some("lab"), None, "11"),
        (Some("lab"), Some("usr"), "20.000001"),
        (Some("lab"), Some("usr"), "10"),
        (Some("lab"), Some("usr"), "09"),
    ] {
        let mut second = event(time, "second", 2);
        second["host"] = json!(host);
        second["user"] = json!(user);
        f.write("records.jsonl", &[event("10", "first", 1), second]);
        assert!(f.hits(&[]).is_empty());
    }
    // File order is reversed. The source clock determines the sequence.
    f.write(
        "records.jsonl",
        &[event("19.999999", "second", 20), event("10", "first", 10)],
    );
    let hits = f.hits(&[]);
    assert_eq!(hits.len(), 1);
    let docs = hits[0]["documents"].as_array().unwrap();
    assert_eq!(docs[0]["record_index"], 2);
    assert_eq!(docs[1]["record_index"], 1);
    let out = f
        .command()
        .args(["--jsonl", "--cache-to-disk"])
        .assert()
        .success();
    let line: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(line["documents"], hits[0]["documents"]);
}

#[test]
fn value_count_tracks_distinct_mapped_values_and_expires_old_records() {
    let f = Fixture::new(
        BASE,
        &rule(
            "value_count",
            "first, second",
            "  condition: {field: Remote, gte: 2}\n",
        ),
    );
    let mut one = event("10", "first", 1);
    one["remote"] = json!("one");
    let mut repeated = event("14", "second", 2);
    repeated["remote"] = json!("one");
    let mut two = event("25", "first", 3);
    two["remote"] = json!("two");
    f.write(
        "records.jsonl",
        &[
            one.clone(),
            repeated.clone(),
            two.clone(),
            event("26", "first", 4),
        ],
    );
    assert!(f.hits(&[]).is_empty());
    two["time"] = json!("2025-10-21T00:00:24Z");
    let mut other = two.clone();
    other["host"] = json!("other");
    f.write("records.jsonl", &[repeated.clone(), other]);
    assert!(f.hits(&[]).is_empty());
    f.write("records.jsonl", &[one, repeated, two]);
    let hits = f.hits(&[]);
    assert_eq!(hits.len(), 1);
    let docs = hits[0]["documents"].as_array().unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0]["data"]["row"], 2);
    assert_eq!(docs[1]["data"]["row"], 3);
}

#[test]
fn multi_document_input_overlapping_predicates_use_distinct_records() {
    let compound = rule("temporal", "first, second", "");
    let both = BASE.replace("Event: second", "Event: [first, second]");
    let f = Fixture::new(&format!("{both}---\n{compound}"), "");
    f.write("records.jsonl", &[event("01", "first", 1)]);
    assert!(f.hits(&[]).is_empty());
    f.write(
        "records.jsonl",
        &[event("01", "first", 1), event("01", "second", 2)],
    );
    assert_eq!(f.hits(&[]).len(), 1);
}

#[test]
fn invalid_correlations_fail_even_alongside_working_base_rules() {
    for (correlation, error) in [
        (
            rule("temporal", "unknown_rule, second", ""),
            "unresolved correlation",
        ),
        (
            rule("event_count", "first", ""),
            "unsupported Sigma correlation type",
        ),
        (
            rule("temporal", "first, second", "  bogus: {invalid: x}\n"),
            "unknown field",
        ),
        (
            rule("value_count", "first", "  condition: {gte: 2}\n"),
            "condition.field",
        ),
        (
            rule("temporal", "first, second", "").replace("10s", "99999999999999999999h"),
            "invalid timespan",
        ),
    ] {
        let f = Fixture::new(BASE, &correlation);
        f.write("events.jsonl", &[event("01", "first", 1)]);
        let result = f.command().arg("--json").assert().failure();
        let stderr = String::from_utf8_lossy(&result.get_output().stderr);
        assert!(stderr.contains(error), "{stderr}");
    }
}

#[test]
fn field_aliases_and_temporal_threshold_require_different_rules() {
    let third = BASE
        .replace("First component", "Third component")
        .replace("name: first", "name: third")
        .replace("000000000001", "000000000003")
        .replace("Event: first", "Event: third");
    let base = format!("{}---\n{}", BASE, third.split("---").next().unwrap());
    let compound = rule(
        "temporal",
        "first, second, third",
        "  condition: {gte: 2}\n  aliases:\n    User: {first: principal, second: actor, third: actor}\n",
    );
    let f = Fixture::new(&base, &compound);
    let mut a = event("01", "first", 1);
    a["principal"] = json!("alice");
    let mut b = event("02", "second", 2);
    b["actor"] = json!("bob");
    f.write("records.jsonl", &[a.clone(), a.clone(), b.clone()]);
    assert!(f.hits(&[]).is_empty());
    b["actor"] = json!("alice");
    f.write("records.jsonl", &[a, b]);
    let hits = f.hits(&["--level", "high"]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["documents"][1]["data"]["actor"], "alice");
}

#[test]
fn independent_rule_files_can_reuse_local_component_names() {
    let a = format!("{}---\n{}", BASE, rule("temporal", "first, second", ""));
    let f = Fixture::new(
        &a,
        &a.replace("Compound signal", "Other compound")
            .replace("Event: first", "Event: never"),
    );
    f.write(
        "records.jsonl",
        &[event("01", "first", 1), event("02", "second", 2)],
    );
    let hits = f.hits(&[]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["name"], "Compound signal");
}

#[test]
fn evtx_correlation_retains_native_record_ids_and_host() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.yml");
    let base = BASE
        .replace("Event: first", "EventID: 5058")
        .replace("Event: second", "EventID: 5061");
    let compound =
        rule("temporal_ordered", "first, second", "").replace("[Host, User]", "[Computer]");
    fs::write(&rules, format!("{base}---\n{compound}")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = cargo_bin_cmd!("chainsaw")
        .arg("hunt")
        .arg(root.join("tests/evtx/security_sample.evtx"))
        .arg("-s")
        .arg(rules)
        .arg("--mapping")
        .arg(root.join("mappings/sigma-event-logs-all.yml"))
        .arg("--json")
        .assert()
        .success();
    let hits: Vec<Value> = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert!(
        hits.iter().any(|hit| {
            let docs = hit["documents"].as_array().unwrap();
            docs[0]["data"]["Event"]["System"]["EventRecordID"] == 31791
                && docs[1]["data"]["Event"]["System"]["EventRecordID"] == 31792
                && docs[1]["data"]["Event"]["System"]["Computer"] == "DESKTOP-JK4Q86I"
        }),
        "{hits:?}"
    );
}

#[test]
fn aggregate_output_displays_mapped_fields_and_source_records() {
    let f = Fixture::new(BASE, &rule("temporal_ordered", "first, second", ""));
    f.write(
        "records.jsonl",
        &[event("01", "first", 1), event("02", "second", 2)],
    );
    for flags in [&[][..], &["--log"][..]] {
        let output = f.command().args(flags).assert().success();
        let displayed = String::from_utf8_lossy(&output.get_output().stdout);
        for value in ["lab", "first, second", "records.jsonl#1", "records.jsonl#2"] {
            assert!(displayed.contains(value), "{displayed}");
        }
    }
    f.command().args(["--csv", "-o", "csv"]).assert().success();
    let csv = fs::read_to_string(f.dir.path().join("csv/test.csv")).unwrap();
    for value in ["lab", "first, second", "records.jsonl#1", "records.jsonl#2"] {
        assert!(csv.contains(value), "{csv}");
    }
}

#[test]
fn legacy_chainsaw_aggregate_displays_nested_and_flat_source_fields() {
    let f = Fixture::new(BASE, "");
    let mut a = event("01", "first", 1);
    a["source"] = json!({"user":"alice"});
    let mut b = event("02", "second", 2);
    b["source"] = json!({"user":"bob"});
    f.write("records.jsonl", &[a, b]);
    fs::write(
        f.dir.path().join("legacy.yml"),
        r#"
title: legacy count
group: Operators
description: smoke test
authors: [test]
kind: json
level: high
status: stable
timestamp: time
fields:
  - {name: System, from: Host, to: host}
  - {name: Person, from: User, to: source.user}
filter: { Host: lab }
aggregate: { count: '>1', fields: [Host] }
"#,
    )
    .unwrap();
    let output = cargo_bin_cmd!("chainsaw")
        .current_dir(f.dir.path())
        .args(["hunt", "events", "-r", "legacy.yml", "--log"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        text.contains("alice, bob") && text.contains("lab"),
        "{text}"
    );
}

#[test]
fn overlapping_mappings_cannot_turn_one_record_into_two_ordered_events() {
    let f = Fixture::new(
        &BASE.replace("Event: second", "Event: [first, second]"),
        &rule("temporal_ordered", "first, second", ""),
    );
    let p = f.dir.path().join("mapping.yml");
    let text = fs::read_to_string(&p).unwrap();
    let extra = text
        .split("groups:\n")
        .nth(1)
        .unwrap()
        .replace("timestamp: time", "timestamp: alt_time");
    fs::write(p, format!("{text}{extra}")).unwrap();
    let mut row = event("01", "first", 1);
    row["alt_time"] = json!("2025-10-21T00:00:02Z");
    f.write("records.jsonl", &[row]);
    let result = f.command().arg("--json").assert().failure();
    assert!(
        String::from_utf8_lossy(&result.get_output().stderr)
            .contains("conflicting mapped timestamps")
    );
}

#[test]
fn distinct_count_emits_one_record_per_value_on_each_threshold_crossing() {
    let f = Fixture::new(
        BASE,
        &rule(
            "value_count",
            "first",
            "  condition: {field: Remote, gte: 2}\n",
        ),
    );
    let mut records = vec![];
    for i in 0..2000 {
        let mut row = event("10", "first", i);
        row["remote"] = json!("a");
        records.push(row);
    }
    for (t, id, key) in [
        ("11", 2000, "b"),
        ("12", 2001, "a"),
        ("32", 2002, "a"),
        ("33", 2003, "c"),
    ] {
        let mut row = event(t, "first", id);
        row["remote"] = json!(key);
        records.push(row);
    }
    f.write("records.jsonl", &records);
    let hits = f.hits(&[]);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0]["documents"].as_array().unwrap().len(), 2);
    assert_eq!(hits[0]["documents"][1]["data"]["row"], 2000);
    assert_eq!(hits[1]["documents"][1]["data"]["row"], 2003);
}
