use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};

use self::esedb::{Esedb, Parser as EsedbParser};
use self::evtx::{Evtx, Parser as EvtxParser};
use self::hve::{Hve, Parser as HveParser};
use self::json::{Json, Parser as JsonParser, lines::Parser as JsonlParser};
use self::mft::{Mft, Parser as MftParser};
use self::xml::{Parser as XmlParser, Xml};

pub mod esedb;
pub mod evtx;
pub mod hve;
pub mod json;
mod macos;
pub mod mft;
mod syslog;
pub mod xml;

#[derive(Clone)]
pub enum Document {
    Evtx(Evtx),
    Hve(Hve),
    Json(Json),
    Mft(Mft),
    Xml(Xml),
    Esedb(Esedb),
}

pub struct Documents<'a> {
    iterator: Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Hash, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Evtx,
    Hve,
    Json,
    Jsonl,
    Mft,
    Xml,
    Esedb,
    Unknown,
}

impl Kind {
    pub fn extensions(&self) -> Option<Vec<String>> {
        match self {
            Kind::Evtx => Some(vec!["evt".to_string(), "evtx".to_string()]),
            Kind::Hve => Some(vec!["hve".to_string()]),
            Kind::Json => Some(
                [
                    "json",
                    "jsonl",
                    "ndjson",
                    "gz",
                    "log",
                    "syslog",
                    "logarchive",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ),
            Kind::Jsonl => Some(vec!["jsonl".to_string(), "ndjson".to_string()]),
            Kind::Mft => Some(vec![
                "mft".to_string(),
                "bin".to_string(),
                "$MFT".to_string(),
            ]),
            Kind::Xml => Some(vec!["xml".to_string()]),
            Kind::Esedb => Some(vec!["dat".to_string(), "edb".to_string()]),
            Kind::Unknown => None,
        }
    }
}

impl Iterator for Documents<'_> {
    type Item = crate::Result<Document>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next()
    }
}

pub struct Unknown;
impl Iterator for Unknown {
    type Item = crate::Result<Document>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Parser {
    Evtx(EvtxParser),
    Hve(HveParser),
    Json(JsonParser),
    Jsonl(JsonlParser),
    Archive(macos::Parser),
    Syslog(syslog::Parser),
    Mft(MftParser),
    Xml(XmlParser),
    Esedb(EsedbParser),
    Unknown,
}

pub struct Reader {
    parser: Parser,
}

impl Reader {
    pub fn load(
        file: &Path,
        load_unknown: bool,
        skip_errors: bool,
        decode_data_streams: bool,
        data_streams_directory: Option<PathBuf>,
    ) -> crate::Result<Self> {
        let name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let extension = file.extension().and_then(|s| s.to_str());
        if extension == Some("logarchive") {
            return Self::from_parser(
                macos::Parser::load(file).map(Parser::Archive),
                file,
                skip_errors,
            );
        }
        if extension == Some("syslog") || matches!(name, "syslog" | "messages" | "secure") {
            return Self::from_parser(
                syslog::Parser::open(file).map(Parser::Syslog),
                file,
                skip_errors,
            );
        }
        if extension == Some("log") {
            match syslog::Parser::load(file) {
                Ok(parser) => {
                    return Ok(Self {
                        parser: Parser::Syslog(parser),
                    });
                }
                Err(_) if !load_unknown => {
                    return Ok(Self {
                        parser: Parser::Unknown,
                    });
                }
                Err(_) => {} // Probe other formats when the caller requests it.
            }
        }
        // NOTE: We don't want to use libmagic because then we have to include databases etc... So
        // for now we assume that the file extensions are correct!
        match file.extension().and_then(|e| e.to_str()) {
            Some(extension) => match extension {
                "evt" | "evtx" => {
                    let parser = match EvtxParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Evtx(parser),
                    })
                }
                "gz" => Self::from_parser(
                    JsonParser::load_gzip(file)
                        .map(|parser| parser.map_or(Parser::Unknown, Parser::Json)),
                    file,
                    skip_errors,
                ),
                "json" => {
                    let parser = match JsonParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Json(parser),
                    })
                }
                "jsonl" | "ndjson" => {
                    let parser = match JsonlParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Jsonl(parser),
                    })
                }
                "bin" | "mft" => {
                    let parser = match MftParser::load(
                        file,
                        data_streams_directory.clone(),
                        decode_data_streams,
                    ) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Mft(parser),
                    })
                }
                "xml" => {
                    let parser = match XmlParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Xml(parser),
                    })
                }
                "hve" => {
                    let parser = match HveParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Hve(parser),
                    })
                }
                "dat" | "edb" => {
                    let parser = match EsedbParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Esedb(parser),
                    })
                }
                _ => {
                    if load_unknown {
                        if let Ok(parser) = EvtxParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Evtx(parser),
                            });
                        } else if let Ok(parser) = MftParser::load(
                            file,
                            data_streams_directory.clone(),
                            decode_data_streams,
                        ) {
                            return Ok(Self {
                                parser: Parser::Mft(parser),
                            });
                        } else if let Ok(parser) = JsonParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Json(parser),
                            });
                        } else if let Ok(parser) = XmlParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Xml(parser),
                            });
                        } else if let Ok(parser) = HveParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Hve(parser),
                            });
                        } else if let Ok(parser) = EsedbParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Esedb(parser),
                            });
                        }
                        if skip_errors {
                            cs_eyellowln!(
                                "[!] file type is not currently supported - {}\n",
                                file.display()
                            );
                            Ok(Self {
                                parser: Parser::Unknown,
                            })
                        } else {
                            anyhow::bail!(
                                "file type is not currently supported - {}, use --skip-errors to continue...",
                                file.display()
                            )
                        }
                    } else {
                        Ok(Self {
                            parser: Parser::Unknown,
                        })
                    }
                }
            },
            None => {
                // Edge cases
                if file.file_name().and_then(|e| e.to_str()) == Some("$MFT")
                    && let Ok(parser) =
                        MftParser::load(file, data_streams_directory.clone(), decode_data_streams)
                {
                    return Ok(Self {
                        parser: Parser::Mft(parser),
                    });
                }
                if load_unknown {
                    if let Ok(parser) = EvtxParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Evtx(parser),
                        });
                    } else if let Ok(parser) =
                        MftParser::load(file, data_streams_directory.clone(), decode_data_streams)
                    {
                        return Ok(Self {
                            parser: Parser::Mft(parser),
                        });
                    } else if let Ok(parser) = JsonParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Json(parser),
                        });
                    } else if let Ok(parser) = XmlParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Xml(parser),
                        });
                    } else if let Ok(parser) = HveParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Hve(parser),
                        });
                    } else if let Ok(parser) = EsedbParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Esedb(parser),
                        });
                    }
                    // NOTE: We don't support the JSONL parser as it is too generic, maybe we are
                    // happy to use it as the fallback...?
                    if skip_errors {
                        cs_eyellowln!("[!] file type is not known - {}\n", file.display());
                        Ok(Self {
                            parser: Parser::Unknown,
                        })
                    } else {
                        anyhow::bail!(
                            "file type is not known - {}, use --skip-errors to continue...",
                            file.display()
                        )
                    }
                } else {
                    Ok(Self {
                        parser: Parser::Unknown,
                    })
                }
            }
        }
    }

    fn from_parser(
        result: crate::Result<Parser>,
        path: &Path,
        skip_errors: bool,
    ) -> crate::Result<Self> {
        match result {
            Ok(parser) => Ok(Self { parser }),
            Err(error) if skip_errors => {
                cs_eyellowln!("[!] failed to load '{}' - {}", path.display(), error);
                Ok(Self {
                    parser: Parser::Unknown,
                })
            }
            Err(error) => {
                Err(error).with_context(|| format!("failed to load '{}'", path.display()))
            }
        }
    }

    pub fn documents<'a>(&'a mut self) -> Documents<'a> {
        let iterator = match &mut self.parser {
            Parser::Evtx(parser) => Box::new(
                parser
                    .parse()
                    .map(|r| r.map(Document::Evtx).map_err(|e| e.into())),
            )
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Hve(parser) => Box::new(parser.parse().map(|r| r.map(Document::Hve)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Json(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Archive(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json))),
            Parser::Syslog(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json))),
            Parser::Jsonl(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Mft(parser) => Box::new(parser.parse().map(|r| r.map(Document::Mft)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Xml(parser) => Box::new(parser.parse().map(|r| r.map(Document::Xml)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Esedb(parser) => Box::new(
                parser
                    .parse()
                    .map(|r| {
                        r.and_then(|v| {
                            serde_json::to_value(v)
                                .with_context(|| "unexpected JSON serialization error")
                        })
                    })
                    .map(|r| r.map(Document::Esedb)),
            )
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>,
            Parser::Unknown => {
                Box::new(Unknown) as Box<dyn Iterator<Item = crate::Result<Document>> + Send + 'a>
            }
        };
        Documents { iterator }
    }

    pub fn kind(&self) -> Kind {
        match self.parser {
            Parser::Evtx(_) => Kind::Evtx,
            Parser::Hve(_) => Kind::Hve,
            Parser::Json(_) => Kind::Json,
            Parser::Jsonl(_) => Kind::Jsonl,
            Parser::Archive(_) | Parser::Syslog(_) => Kind::Json,
            Parser::Mft(_) => Kind::Mft,
            Parser::Xml(_) => Kind::Xml,
            Parser::Esedb(_) => Kind::Esedb,
            Parser::Unknown => Kind::Unknown,
        }
    }
}

pub fn get_files(
    path: &PathBuf,
    extensions: &Option<HashSet<String>>,
    skip_errors: bool,
) -> crate::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![];
    if path.exists() {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) => {
                if skip_errors {
                    cs_eyellowln!("[!] failed to get metadata for file - {}", e);
                    return Ok(files);
                } else {
                    anyhow::bail!(e);
                }
            }
        };
        if metadata.is_dir() && path.extension().is_some_and(|ext| ext == "logarchive") {
            if extensions
                .as_ref()
                .is_none_or(|exts| exts.contains("logarchive"))
            {
                files.push(path.clone());
            }
        } else if metadata.is_dir() {
            let directory = match path.read_dir() {
                Ok(directory) => directory,
                Err(e) => {
                    if skip_errors {
                        cs_eyellowln!("[!] failed to read directory - {}", e);
                        return Ok(files);
                    } else {
                        anyhow::bail!(e);
                    }
                }
            };
            for dir in directory {
                let dir = match dir {
                    Ok(dir) => dir,
                    Err(e) => {
                        if skip_errors {
                            cs_eyellowln!("[!] failed to enter directory - {}", e);
                            return Ok(files);
                        } else {
                            anyhow::bail!(e);
                        }
                    }
                };
                files.extend(get_files(&dir.path(), extensions, skip_errors)?);
            }
        } else if let Some(e) = extensions {
            if let Some(ext) = path.extension()
                && e.contains(&ext.to_string_lossy().into_owned())
            {
                files.push(path.to_path_buf());
            }
            if path.extension().is_none()
                && e.contains("syslog")
                && matches!(
                    path.file_name().and_then(|s| s.to_str()),
                    Some("syslog" | "messages" | "secure")
                )
            {
                files.push(path.clone());
            }
            // Edge cases
            if e.contains("$MFT") && path.file_name().and_then(|e| e.to_str()) == Some("$MFT") {
                files.push(path.to_path_buf());
            }
        } else {
            files.push(path.to_path_buf());
        }
    } else if skip_errors {
        cs_eyellowln!("[!] Specified path does not exist - {}", path.display());
    } else {
        anyhow::bail!("Specified event log path is invalid - {}", path.display());
    }
    Ok(files)
}

pub fn win32_ts_to_datetime(ts_win32: u64) -> crate::Result<DateTime<Utc>> {
    let ts_unix = (ts_win32 / 10_000) as i64 - 11644473600000;
    DateTime::from_timestamp_millis(ts_unix).ok_or(anyhow!("Timestamp out of range!"))
}

/// Event timestamps are returned as UTC for the hunt and search time filters.
pub(crate) fn event_time(text: &str) -> Result<chrono::NaiveDateTime, chrono::ParseError> {
    DateTime::parse_from_rfc3339(text)
        .or_else(|_| DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f%z"))
        .map(|time| time.naive_utc())
}
