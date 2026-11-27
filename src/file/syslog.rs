use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, NaiveDateTime, SecondsFormat, Utc};
use regex::Regex;
use serde_json::{Map, Value, json};
use syslog_loose::{Protocol, Variant, parse_message_with_year_exact_tz};

#[path = "syslog/panos.rs"]
mod panos;

pub struct Parser {
    reader: BufReader<File>,
    line_number: usize,
    file_year: i32,
}

impl Parser {
    pub fn open(path: &Path) -> crate::Result<Self> {
        let file = File::open(path)?;
        let file_year = DateTime::<Utc>::from(file.metadata()?.modified()?).year();
        Ok(Self {
            reader: BufReader::new(file),
            line_number: 0,
            file_year,
        })
    }

    /// Probe ambiguous .log inputs without consuming their first record.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let mut parser = Self::open(path)?;
        let recognized = parser
            .reader
            .by_ref()
            .take(256 * 1024)
            .lines()
            .take(32)
            .any(|line| line.is_ok_and(|line| header(&line, parser.file_year).is_ok()));
        ensure!(recognized, "no recognizable syslog header in input prefix");
        parser.reader.rewind()?;
        Ok(parser)
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Value>> + '_ {
        let number = &mut self.line_number;
        let year = self.file_year;
        self.reader.by_ref().lines().filter_map(move |line| {
            *number += 1;
            if line.as_ref().is_ok_and(|line| line.trim().is_empty()) {
                return None;
            }
            Some(
                line.map_err(anyhow::Error::from)
                    .and_then(|line| record(&line, year))
                    .with_context(|| format!("syslog line {}", *number)),
            )
        })
    }
}

struct Header<'a> {
    fields: Value,
    message: &'a str,
    timestamp: Option<DateTime<Utc>>,
    clock: &'static str,
}

// Preserve the full message when BSD records omit the optional tag. This is also
// how PAN-OS sends its default CSV payload, with or without a hostname.
static BSD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"^(?P<time>[A-Za-z]{3} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{4}-[0-9]{2}-[0-9]{2}T\S+) +(?P<body>.+)$"
).unwrap()
});
static TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<app>[^\s:\[\],]+)(?:\[(?P<pid>[^\]]+)\])?: ?(?P<msg>.*)$").unwrap()
});

fn header(line: &str, year: i32) -> Result<Header<'_>> {
    let (priority, rest) = if let Some(pri) = line.strip_prefix('<') {
        let (pri, rest) = pri.split_once('>').context("missing priority delimiter")?;
        ensure!(
            !pri.is_empty() && pri.len() <= 3 && pri.bytes().all(|c| c.is_ascii_digit()),
            "invalid syslog priority"
        );
        let priority: u8 = pri.parse()?;
        ensure!(priority <= 191, "syslog priority exceeds 191");
        (Some(priority), rest)
    } else {
        (None, line)
    };
    let mut result = if panos::looks_like_traffic(rest) {
        Header {
            fields: json!({"format":"panos_csv"}),
            message: rest,
            timestamp: None,
            clock: "",
        }
    } else if priority.is_some() && rest.starts_with("1 ") {
        let parsed = parse_message_with_year_exact_tz(line, |_| year, Some(Utc), Variant::RFC5424)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            matches!(parsed.protocol, Protocol::RFC5424(1)),
            "unsupported syslog version"
        );
        let mut sd = Map::new();
        for element in parsed.structured_data {
            let params = element
                .params()
                .map(|(&k, v)| (k.to_owned(), Value::String(v)))
                .collect();
            sd.insert(element.id.to_owned(), Value::Object(params));
        }
        // syslog_loose returns a borrowed MSG suffix after trimming whitespace.
        // Recover its delimiter from the original input so leading, trailing
        // and whitespace-only messages survive, including SD with escaped ']'.
        let header_end = line
            .trim_end()
            .strip_suffix(parsed.msg)
            .context("invalid RFC 5424 message suffix")?
            .trim_end_matches([' ', '\t'])
            .len();
        let tail = &line[header_end..];
        let message = if tail.is_empty() {
            tail
        } else {
            tail.strip_prefix(' ')
                .context("missing RFC 5424 message separator")?
        };
        Header {
            fields: json!({"format":"rfc5424", "version":1, "hostname":parsed.hostname,
                "appname":parsed.appname, "procid":parsed.procid.map(|p| p.to_string()),
                "msgid":parsed.msgid, "structured_data":sd}),
            message,
            timestamp: parsed.timestamp.map(|t| t.to_utc()),
            clock: "syslog",
        }
    } else {
        let captures = BSD.captures(rest).context("unrecognized syslog header")?;
        let time = &captures["time"];
        let (ts, clock) = if let Ok(ts) = DateTime::parse_from_rfc3339(time) {
            (ts.to_utc(), "syslog")
        } else {
            let ts = NaiveDateTime::parse_from_str(&format!("{year} {time}"), "%Y %b %e %T")?;
            (ts.and_utc(), "syslog_file_year_assumed_utc")
        };
        let body = captures.name("body").unwrap().as_str();
        let (host, payload) = if panos::looks_like_traffic(body) {
            (None, body)
        } else {
            let (host, payload) = body.split_once(' ').context("missing syslog message")?;
            (Some(host), payload.trim_start_matches(' '))
        };
        let tag = TAG.captures(payload);
        Header {
            fields: json!({"format":"rfc3164", "hostname":host,
                "appname":tag.as_ref().and_then(|c| c.name("app")).map(|m| m.as_str()),
                "procid":tag.as_ref().and_then(|c| c.name("pid")).map(|m| m.as_str())}),
            message: tag
                .as_ref()
                .and_then(|c| c.name("msg"))
                .map_or(payload, |m| m.as_str()),
            timestamp: Some(ts),
            clock,
        }
    };
    if let Some(ts) = result.timestamp {
        result.fields["timestamp"] = json!(ts.to_rfc3339_opts(SecondsFormat::AutoSi, true));
    }
    if let Some(p) = priority {
        result.fields["priority"] = json!(p);
        result.fields["facility"] = json!(p / 8);
        result.fields["severity"] = json!(p % 8);
    }
    Ok(result)
}

fn record(raw: &str, year: i32) -> Result<Value> {
    let head = header(raw, year)?;
    let msg = head.message.trim_start_matches('\u{feff}');
    let mut timestamp = head.timestamp;
    let mut clock = head.clock;
    let mut doc = json!({"raw":raw, "message":head.message, "syslog":head.fields});
    if panos::looks_like_traffic(msg) {
        let (fields, generated, source) = panos::traffic(msg)?;
        doc["panos"] = fields;
        timestamp = Some(generated);
        clock = source;
    } else if doc["syslog"]["appname"]
        .as_str()
        .is_some_and(|app| app.eq_ignore_ascii_case("sysmon"))
        && msg.trim_start().starts_with('<')
    {
        let mut xml = super::xml::parse_event(msg.trim())?;
        let event = xml.get_mut("Event").context("missing Sysmon Event")?.take();
        if let Some(ts) = event
            .pointer("/System/TimeCreated_attributes/SystemTime")
            .and_then(Value::as_str)
        {
            timestamp = Some(
                DateTime::parse_from_rfc3339(ts)
                    .context("invalid Sysmon SystemTime")?
                    .to_utc(),
            );
            clock = "sysmon";
        }
        doc["Event"] = event;
    }
    if let Some(ts) = timestamp {
        doc["timestamp"] = json!(ts.to_rfc3339_opts(SecondsFormat::AutoSi, true));
        doc["timestamp_source"] = json!(clock);
    }
    Ok(doc)
}
