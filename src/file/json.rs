use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use anyhow::Error;
use flate2::bufread::MultiGzDecoder;
use regex::RegexSet;
pub use serde_json::Value as Json;

use crate::search::Searchable;

mod cloud;

pub struct Parser {
    pub inner: Option<Json>,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let gzip = reader.fill_buf()?.starts_with(&[0x1f, 0x8b]);
        let json = if gzip {
            read_json(BufReader::new(MultiGzDecoder::new(reader)))?
        } else {
            read_json(reader)?
        };
        Ok(Self { inner: Some(json) })
    }

    /// A bare gzip file can contain any format. Probe its decoded content without
    /// trusting the optional filename in the gzip header.
    pub(super) fn load_gzip(path: &Path) -> crate::Result<Option<Self>> {
        let file = BufReader::new(File::open(path)?);
        let mut decoded = BufReader::new(MultiGzDecoder::new(file));
        let named_json = path
            .file_stem()
            .and_then(|stem| Path::new(stem).extension())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if !named_json && !looks_like_json_documents(&mut decoded)? {
            return Ok(None);
        }
        Ok(Some(Self {
            inner: Some(read_json(decoded)?),
        }))
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        self.inner.take().into_iter().flat_map(documents).map(Ok)
    }
}

fn looks_like_json_documents(reader: &mut impl BufRead) -> std::io::Result<bool> {
    loop {
        let bytes = reader.fill_buf()?;
        if let Some(byte) = bytes
            .iter()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Ok(matches!(byte, b'{' | b'['));
        }
        let consumed = bytes.len();
        if consumed == 0 {
            return Ok(false);
        }
        reader.consume(consumed);
    }
}

fn read_json(reader: impl Read) -> crate::Result<Json> {
    let mut values = serde_json::Deserializer::from_reader(reader).into_iter::<Json>();
    let first = values
        .next()
        .transpose()?
        .ok_or_else(|| anyhow!("empty JSON input"))?;
    let Some(second) = values.next().transpose()? else {
        return Ok(first);
    };
    // Azure Monitor writes newline-delimited Activity Log exports to PT1H.json.
    // Preserve single-root validation for unrelated files and unknown-type probing.
    anyhow::ensure!(
        cloud::azure_export(&first),
        "multiple root values in JSON input"
    );
    let mut records = vec![first];
    for value in std::iter::once(Ok(second)).chain(values) {
        let value = value?;
        anyhow::ensure!(
            cloud::azure_export(&value),
            "unexpected record in Azure Activity Log export"
        );
        records.push(value);
    }
    Ok(Json::Array(records))
}

fn envelope_records(json: &mut Json) -> Option<Vec<Json>> {
    let key = cloud::envelope_key(json)?;
    json[key].as_array_mut().map(std::mem::take)
}

fn documents(mut json: Json) -> Vec<Json> {
    match json {
        Json::Array(records) => records,
        _ => envelope_records(&mut json).unwrap_or_else(|| vec![json]),
    }
}

impl Searchable for Json {
    fn matches(&self, regex: &RegexSet, match_any: &bool) -> bool {
        if *match_any {
            regex.is_match(&self.to_string().replace(r"\\", r"\"))
        } else {
            regex
                .matches(&self.to_string().replace(r"\\", r"\"))
                .into_iter()
                .collect::<Vec<_>>()
                .len()
                == regex.len()
        }
    }
}

pub mod lines {
    use super::*;

    use std::io::Seek;

    pub struct Parser {
        pub inner: Option<BufReader<File>>,
    }

    impl Parser {
        pub fn load(path: &Path) -> crate::Result<Self> {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            // A crude check where we read the first line to see if its JSON, we should probably
            // read more than this?
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let _ = serde_json::from_str::<Json>(&line)?;
            reader.rewind()?;
            Ok(Self {
                inner: Some(reader),
            })
        }

        pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
            self.inner
                .take()
                .into_iter()
                .flat_map(|reader| reader.lines())
                .flat_map(|line| {
                    let mut record = line
                        .map_err(Error::from)
                        .and_then(|line| serde_json::from_str::<Json>(&line).map_err(Error::from));
                    let batch = record.as_mut().ok().and_then(envelope_records);
                    let single = batch.is_none().then_some(record);
                    single
                        .into_iter()
                        .chain(batch.into_iter().flatten().map(Ok))
                })
        }
    }
}
