use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;

#[test]
fn sysmon_xml_dump_keeps_named_fields_and_duplicate_values() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("event.xml");
    fs::write(&path, r#"<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID></System><EventData><Data Name="Image">/usr/bin/true</Data><Data Name="Label">a</Data><Data Name="Label">b</Data></EventData></Event>"#).unwrap();
    let result = cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg("--jsonl")
        .arg(path)
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(doc.pointer("/Event/System/EventID"), Some(&json!(1)));
    assert_eq!(
        doc.pointer("/Event/EventData/Image"),
        Some(&json!("/usr/bin/true"))
    );
    assert_eq!(
        doc.pointer("/Event/EventData/Label"),
        Some(&json!(["a", "b"]))
    );
}

#[test]
fn dump_every_wrapped_and_concatenated_sysmon_event_without_field_loss() {
    let root = tempfile::tempdir().unwrap();
    let provider = "Microsoft-Windows-Sysmon";
    let a = format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID Qualifiers="0">1</EventID><Extension code="7"><Item>A</Item><Item>B</Item></Extension></System><EventData><Data Name="Image">a.exe</Data><Data Name="ProcessId">41</Data><Data Name="Image">b.exe</Data><Unknown>extension</Unknown></EventData><RenderingInfo><Message><![CDATA[literal </Event> & payload]]></Message></RenderingInfo></Event>"#
    );
    let b = r#"<Event><System><Provider Name="Linux-Sysmon"/><EventID>5</EventID></System><EventData><Data Name="Image">/usr/bin/true</Data><Data Name="ProcessId">42</Data></EventData></Event>"#;
    for (file, text) in [
        (
            "wrapped.xml",
            format!("<?xml version=\"1.0\"?><Events>\n{a}\n<!--gap-->{b}</Events>"),
        ),
        ("concatenated.xml", format!("{a}\n{b}")),
        ("with-bom.xml", format!("\u{feff}<Events>{a}{b}</Events>")),
    ] {
        let input = root.path().join(file);
        fs::write(&input, text).unwrap();
        let output = cargo_bin_cmd!("chainsaw")
            .arg("dump")
            .arg(input)
            .args(["--jsonl", "-q"])
            .assert()
            .success();
        let docs: Vec<Value> = std::str::from_utf8(&output.get_output().stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0]["Event"]["System"]["EventID"], 1);
        assert_eq!(
            docs[0]["Event"]["System"]["EventID_attributes"]["Qualifiers"],
            "0"
        );
        assert_eq!(
            docs[0]["Event"]["System"]["Extension"]["Item"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            docs[0]["Event"]["System"]["Extension_attributes"]["code"],
            "7"
        );
        assert_eq!(
            docs[0]["Event"]["EventData"]["Image"],
            json!(["a.exe", "b.exe"])
        );
        assert_eq!(docs[0]["Event"]["EventData"]["ProcessId"], "41");
        assert!(
            docs[0]["Event"]["EventData"]["Unknown"]
                .to_string()
                .contains("extension")
        );
        assert!(
            docs[0]["Event"]["RenderingInfo"]["Message"]
                .to_string()
                .contains("literal </Event> & payload")
        );
        assert_eq!(docs[1]["Event"]["System"]["EventID"], 5);
        assert_eq!(docs[1]["Event"]["EventData"]["Image"], "/usr/bin/true");
        assert_eq!(docs[1]["Event"]["EventData"]["ProcessId"], "42");
    }
}

#[test]
fn rejects_unexpected_content_in_a_sysmon_collection_and_retains_generic_shape() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("events.xml");
    let event =
        r#"<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID></System></Event>"#;
    for invalid in [
        format!("<Events>{event}<Unknown/></Events>"),
        format!("{event}<Bad/>"),
        format!("<Other/>{event}"),
        format!("<Events>{event}"),
    ] {
        fs::write(&input, invalid).unwrap();
        cargo_bin_cmd!("chainsaw")
            .arg("dump")
            .arg(&input)
            .arg("--jsonl")
            .assert()
            .failure();
    }
    let generic =
        "<Events><Event><Value>unrelated</Value></Event><Metadata>keep</Metadata></Events>";
    fs::write(&input, generic).unwrap();
    let output = cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg(input)
        .arg("--jsonl")
        .assert()
        .success();
    let value: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(value, quick_xml::de::from_str::<Value>(generic).unwrap());
}
