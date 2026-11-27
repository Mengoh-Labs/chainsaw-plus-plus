use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

pub struct Parser {
    records: std::io::Lines<BufReader<File>>,
}

impl Parser {
    pub fn load(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            cfg!(target_os = "macos"),
            "reading .logarchive requires macOS; export NDJSON on a Mac for portable hunting"
        );
        anyhow::ensure!(path.is_dir(), "a .logarchive must be an archive directory");
        // Spool the native decoder output to disk to bound memory and observe its
        // final status before returning records from a potentially corrupt archive.
        let mut output = tempfile::tempfile()?;
        let result = std::process::Command::new("/usr/bin/log")
            .args([
                "show",
                "--style",
                "ndjson",
                "--info",
                "--debug",
                "--signpost",
                "--archive",
            ])
            .arg(path)
            .stdout(output.try_clone()?)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("starting Apple's unified log decoder")?
            .wait_with_output()?;
        anyhow::ensure!(
            result.status.success(),
            "log show failed ({}): {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        );
        output.rewind()?;
        Ok(Self {
            records: BufReader::new(output).lines(),
        })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Value>> + '_ {
        self.records.by_ref().filter_map(|line| {
            let result = line
                .map_err(anyhow::Error::from)
                .and_then(|s| Ok(serde_json::from_str::<Value>(&s)?));
            // log show emits a final statistics object after the event stream.
            match result {
                Ok(value)
                    if value.get("finished").is_some() && value.get("eventType").is_none() =>
                {
                    None
                }
                other => Some(other),
            }
        })
    }
}
