use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use tempfile::tempdir;

fn hunt(records: &str, mapping: &str, source: &str, selection: &str) -> Vec<Value> {
    let dir = tempdir().unwrap();
    let log = dir.path().join("input.syslog");
    let rule = dir.path().join("rule.yml");
    fs::write(&log, records).unwrap();
    fs::write(&rule, format!(
        "title: Example match\nstatus: test\ndescription: Regression fixture\nauthor: Chainsaw\nlogsource: {source}\ndetection:\n  selection:\n{selection}\n  condition: selection\nlevel: low\n"
    )).unwrap();
    let output = cargo_bin_cmd!("chainsaw")
        .arg("hunt")
        .arg(log)
        .arg("-s")
        .arg(rule)
        .arg("-m")
        .arg(format!("mappings/{mapping}.yml"))
        .arg("-j")
        .assert()
        .success();
    serde_json::from_slice(&output.get_output().stdout).unwrap()
}

#[test]
fn syslog_headers_structured_data_and_timestamps_are_huntable() {
    let lines = concat!(
        "<165>1 2024-03-14T15:09:26.535+02:00 node sshd 243 ID47 [tag@42 note=\"x\\] y\"][timeQuality tzKnown=\"1\"] session opened\n",
        "<165>1 2024-03-14T13:09:27Z node sshd 244 ID47 - session closed\n",
        "<165>Mar 14 13:09:28 node sshd[245]: session opened\n",
    );
    let hits = hunt(
        lines,
        "sigma-syslog",
        "{product: linux}",
        "    Message: session opened",
    );
    assert_eq!(hits.len(), 2);
    let docs: Vec<_> = hits.iter().map(|x| &x["document"]["data"]).collect();
    let rfc = docs
        .iter()
        .find(|d| d["syslog"]["format"] == "rfc5424")
        .unwrap();
    assert_eq!(rfc["raw"], lines.lines().next().unwrap());
    assert_eq!(rfc["timestamp"], "2024-03-14T13:09:26.535Z");
    assert_eq!(rfc["syslog"]["hostname"], "node");
    assert_eq!(rfc["syslog"]["appname"], "sshd");
    assert_eq!(rfc["syslog"]["facility"], 20);
    assert_eq!(rfc["syslog"]["severity"], 5);
    assert_eq!(rfc["syslog"]["structured_data"]["tag@42"]["note"], "x] y");
    assert_eq!(
        rfc["syslog"]["structured_data"]["timeQuality"]["tzKnown"],
        "1"
    );
    let bsd = docs
        .iter()
        .find(|d| d["syslog"]["format"] == "rfc3164")
        .unwrap();
    assert_eq!(bsd["timestamp_source"], "syslog_file_year_assumed_utc");
    assert_eq!(bsd["syslog"]["procid"], "245");
}

#[test]
fn linux_sysmon_process_creation_requires_image_and_event_id() {
    let template = r#"Jan  2 03:04:05 linux sysmon[99]: <Event><System><Provider Name="Linux-Sysmon"/><EventID>ID</EventID><TimeCreated SystemTime="2022-01-02T03:04:05.100Z"/><Computer>linux</Computer></System><EventData><Data Name="Image">IMAGE</Data><Data Name="ProcessId">42</Data><Data Name="CommandLine">COMMAND</Data></EventData></Event>"#;
    let records = [
        (1, "/usr/bin/logger"),
        (1, "/usr/bin/date"),
        (5, "/usr/bin/logger"),
    ]
    .iter()
    .map(|(id, image)| {
        template
            .replace(">ID<", &format!(">{id}<"))
            .replace("IMAGE", image)
            .replace("COMMAND", "write &amp; exit")
    })
    .collect::<Vec<_>>()
    .join("\n");
    let hits = hunt(
        &records,
        "sigma-syslog-linux-sysmon",
        "{product: linux, category: process_creation}",
        "    Image: /usr/bin/logger\n    ProcessId: '42'",
    );
    assert_eq!(hits.len(), 1);
    let doc = &hits[0]["document"]["data"];
    assert_eq!(doc["timestamp"], "2022-01-02T03:04:05.100Z");
    assert_eq!(doc["Event"]["System"]["EventID"], 1);
    assert_eq!(doc["Event"]["EventData"]["CommandLine"], "write & exit");
}

#[test]
fn panos_traffic_csv_keeps_action_and_endpoints_per_record() {
    let row = r#"1,2024/11/30 16:09:07,00012,TRAFFIC,end,2049,2024/11/30 16:09:06,192.0.2.10,198.51.100.20,192.0.2.10,198.51.100.20,"rule,quoted",,,web,vsys1,trust,untrust,eth0,eth1,profile,2024/11/30 16:09:07,11,1,55113,443,55113,443,0x0,tcp,reset both"#;
    let lines = format!(
        "Nov 30 16:09:08 PA-220 {row}\n{}\nNov 30 16:09:08 {row}",
        row.replace("reset both", "allow")
    );
    let hits = hunt(
        &lines,
        "sigma-syslog-panos",
        "{category: firewall}",
        "    Action: reset-both\n    DestinationPort: 443\n    Protocol: tcp",
    );
    assert_eq!(hits.len(), 2);
    for hit in &hits {
        let doc = &hit["document"]["data"];
        assert_eq!(doc["panos"]["action_original"], "reset both");
        assert_eq!(doc["panos"]["rule"], "rule,quoted");
        assert_eq!(doc["panos"]["src"], "192.0.2.10");
        assert_eq!(doc["panos"]["dst"], "198.51.100.20");
        assert_eq!(doc["panos"]["sport"], 55113);
        assert_eq!(doc["timestamp"], "2024-11-30T16:09:06Z");
    }
}

#[test]
fn malformed_syslog_reports_its_line_and_skip_errors_continues() {
    let dir = tempdir().unwrap();
    for name in ["messages.syslog", "mixed.log"] {
        let log = dir.path().join(name);
        fs::write(
            &log,
            "not a syslog record\nJan  2 03:04:05 x svc: a\nJan  2 03:04:05 x svc: b\n",
        )
        .unwrap();
        let failed = cargo_bin_cmd!("chainsaw")
            .arg("dump")
            .arg(&log)
            .arg("--jsonl")
            .assert()
            .failure();
        assert!(String::from_utf8_lossy(&failed.get_output().stderr).contains("syslog line 1"));
        let ok = cargo_bin_cmd!("chainsaw")
            .arg("dump")
            .arg(log)
            .args(["--jsonl", "--skip-errors", "-q"])
            .assert()
            .success();
        let messages: Vec<_> = String::from_utf8(ok.get_output().stdout.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["message"].clone())
            .collect();
        assert_eq!(messages, ["a", "b"]);
    }
}

#[test]
fn rfc5424_preserves_message_whitespace_after_structured_data() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("spaces.syslog");
    let sd = r#"[a note="escaped \] and \" quote"][b param="2"]"#;
    let head = "<14>1 2025-01-01T00:00:00Z host app - ID ";
    let cases = [
        ("-".to_string(), ""),
        ("- ".to_string(), ""),
        ("-    ".to_string(), "   "),
        (format!("{sd}   start  end  "), "  start  end  "),
        (format!("{sd} \ttext\t "), "\ttext\t "),
    ];
    let records = cases
        .iter()
        .map(|(tail, _)| format!("{head}{tail}"))
        .collect::<Vec<_>>();
    fs::write(&log, records.join("\n")).unwrap();
    let out = cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg(log)
        .args(["--jsonl", "-q"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&out.get_output().stdout).unwrap();
    let docs = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(docs.len(), cases.len());
    for (i, (_, expected)) in cases.iter().enumerate() {
        assert_eq!(docs[i]["message"], *expected);
        assert_eq!(docs[i]["raw"], records[i]);
    }
}
