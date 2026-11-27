use anyhow::{Context, Result, ensure};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) fn looks_like_traffic(msg: &str) -> bool {
    let mut parts = msg.splitn(5, ',');
    let prefix = parts.next().unwrap_or_default();
    !prefix.is_empty()
        && prefix.bytes().all(|c| c.is_ascii_digit())
        && parts.nth(2) == Some("TRAFFIC")
}

// The standard Traffic payload has a stable prefix. Newer PAN-OS releases append
// fields. The parent retains the complete original CSV, including all extensions.
pub(super) fn traffic(msg: &str) -> Result<(Value, DateTime<Utc>, &'static str)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(msg.as_bytes());
    let row = reader.records().next().context("empty PAN-OS record")??;
    ensure!(
        row.len() >= 31,
        "incomplete PAN-OS traffic record ({} fields)",
        row.len()
    );
    let mut fields = Map::new();
    for (i, key) in [
        (1, "receive_time"),
        (2, "serial"),
        (3, "type"),
        (4, "subtype"),
        (6, "time_generated"),
        (7, "src"),
        (8, "dst"),
        (9, "natsrc"),
        (10, "natdst"),
        (11, "rule"),
        (12, "srcuser"),
        (13, "dstuser"),
        (14, "app"),
        (15, "vsys"),
        (16, "from"),
        (17, "to"),
        (18, "inbound_if"),
        (19, "outbound_if"),
        (20, "logset"),
        (28, "flags"),
        (29, "proto"),
        (30, "action_original"),
        (35, "start"),
        (37, "category"),
        (41, "srcloc"),
        (42, "dstloc"),
        (46, "session_end_reason"),
        (52, "device_name"),
    ] {
        if let Some(v) = row.get(i).filter(|v| !v.is_empty()) {
            fields.insert(key.to_string(), json!(v));
        }
    }
    // PAN-OS versions use both space- and hyphen-delimited action names.
    // Keep the native spelling and map the documented aliases for hunts.
    let action = match &row[30] {
        "drop ICMP" => "drop-icmp",
        "reset client" => "reset-client",
        "reset server" => "reset-server",
        "reset both" => "reset-both",
        original => original,
    };
    fields.insert("action".into(), json!(action));
    for (i, key) in [
        (22, "sessionid"),
        (23, "repeatcnt"),
        (24, "sport"),
        (25, "dport"),
        (26, "natsport"),
        (27, "natdport"),
        (31, "bytes"),
        (32, "bytes_sent"),
        (33, "bytes_received"),
        (34, "packets"),
        (36, "elapsed"),
        (39, "seqno"),
        (44, "pkts_sent"),
        (45, "pkts_received"),
    ] {
        if let Some(v) = row.get(i).filter(|v| !v.is_empty()) {
            let n: u64 = v.parse().with_context(|| format!("invalid PAN-OS {key}"))?;
            fields.insert(key.to_string(), json!(n));
        }
    }
    let (ts, source) = if let Ok(dt) = DateTime::parse_from_rfc3339(&row[6]) {
        (dt.to_utc(), "panos_generated")
    } else {
        let dt = NaiveDateTime::parse_from_str(&row[6], "%Y/%m/%d %T%.f")
            .context("invalid PAN-OS generated time")?;
        (dt.and_utc(), "panos_generated_assumed_utc")
    };
    Ok((Value::Object(fields), ts, source))
}
