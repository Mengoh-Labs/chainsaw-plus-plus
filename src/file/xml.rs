use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use quick_xml::{Reader, events::Event};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value as Json, json, map::Entry};

pub type Xml = Json;

fn insert_field(fields: &mut Map<String, Json>, name: String, value: Json) {
    match fields.entry(name) {
        Entry::Vacant(entry) => {
            entry.insert(value);
        }
        Entry::Occupied(mut entry) => {
            let previous = entry.get_mut();
            if let Some(values) = previous.as_array_mut() {
                values.push(value);
            } else {
                *previous = Json::Array(vec![previous.take(), value]);
            }
        }
    }
}

// A generic JSON object overwrites repeated XML siblings. Preserve multiplicity
// before normalizing known Sysmon fields, including in vendor extension nodes.
struct Element(Json);

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct ElementVisitor;
        impl<'de> Visitor<'de> for ElementVisitor {
            type Value = Element;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an XML element")
            }
            fn visit_str<E>(self, v: &str) -> Result<Element, E> {
                Ok(Element(v.into()))
            }
            fn visit_string<E>(self, v: String) -> Result<Element, E> {
                Ok(Element(v.into()))
            }
            fn visit_unit<E>(self) -> Result<Element, E> {
                Ok(Element(Json::Null))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Element, A::Error> {
                let mut fields = Map::new();
                while let Some((key, Element(value))) = map.next_entry()? {
                    insert_field(&mut fields, key, value);
                }
                Ok(Element(fields.into()))
            }
        }
        de.deserialize_any(ElementVisitor)
    }
}

fn object(node: Json, name: &str) -> Result<Map<String, Json>> {
    if let Json::Object(fields) = node {
        Ok(fields)
    } else {
        anyhow::bail!("invalid Sysmon {name}")
    }
}

fn normalize_event(node: Json) -> Result<Json> {
    let mut event = object(node, "Event")?;
    let system = object(
        event.remove("System").context("missing Sysmon System")?,
        "System",
    )?;
    let mut normalized = Map::new();
    for (name, value) in system {
        if let Json::Object(children) = value {
            let mut attrs = Map::new();
            let mut content = Map::new();
            for (key, child) in children {
                if let Some(attr) = key.strip_prefix('@') {
                    attrs.insert(attr.to_owned(), child);
                } else {
                    content.insert(key, child);
                }
            }
            let empty = attrs.is_empty() && content.is_empty();
            if !attrs.is_empty() {
                insert_field(&mut normalized, format!("{name}_attributes"), attrs.into());
            }
            if content.len() == 1 && content.contains_key("$text") {
                insert_field(&mut normalized, name, content.remove("$text").unwrap());
            } else if empty || !content.is_empty() {
                insert_field(&mut normalized, name, content.into());
            }
        } else {
            insert_field(&mut normalized, name, value);
        }
    }
    let event_id = normalized
        .get("EventID")
        .and_then(Json::as_str)
        .context("invalid or missing Sysmon EventID")?
        .parse::<u32>()?;
    normalized.insert("EventID".into(), event_id.into());
    event.insert("System".into(), normalized.into());

    let mut data = match event.remove("EventData") {
        None => Map::new(),
        Some(data) => object(data, "EventData")?,
    };
    if let Some(entries) = data.remove("Data") {
        let entries = match entries {
            Json::Array(values) => values,
            one => vec![one],
        };
        for entry in entries {
            let Json::Object(mut fields) = entry else {
                insert_field(&mut data, "Data".into(), entry);
                continue;
            };
            let Some(Json::String(name)) = fields.remove("@Name") else {
                insert_field(&mut data, "Data".into(), fields.into());
                continue;
            };
            let value = if fields.is_empty() {
                Json::String(String::new())
            } else if fields.len() == 1 && fields.contains_key("$text") {
                fields.remove("$text").unwrap()
            } else {
                Json::Object(fields)
            };
            insert_field(&mut data, name, value);
        }
    }
    event.insert("EventData".into(), data.into());
    Ok(json!({"Event": event}))
}

/// Decode one embedded Sysmon record into the EVTX field layout.
pub(super) fn parse_event(xml: &str) -> Result<Json> {
    let mut docs = event_documents(xml, |_| true)?.context("expected a Sysmon Event")?;
    ensure!(
        docs.len() == 1,
        "multiple Sysmon events in one syslog record"
    );
    Ok(docs.pop().unwrap())
}

fn sysmon(node: &Json) -> bool {
    node.pointer("/System/Provider/@Name")
        .and_then(Json::as_str)
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("Linux-Sysmon")
                || name.eq_ignore_ascii_case("Microsoft-Windows-Sysmon")
        })
}

/// Read the direct Event children of a Windows Events export or a sequence of
/// complete Event roots. Slicing at token boundaries keeps CDATA, comments and
/// nested elements containing the word 'Event' inside their source record.
fn event_documents(xml: &str, is_sysmon: impl Fn(&Json) -> bool) -> Result<Option<Vec<Json>>> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let mut reader = Reader::from_str(xml);
    let mut roots = 0;
    let mut documents = Vec::new();
    let mut has_sysmon = false;
    let mut wrapper = false;
    let mut closed = false;
    let mut other_content = false;
    loop {
        let start = reader.buffer_position() as usize;
        let token = reader.read_event()?;
        match token {
            Event::Start(ref tag) | Event::Empty(ref tag) => {
                let empty = matches!(token, Event::Empty(_));
                let name = tag.local_name();
                if !wrapper || closed {
                    roots += 1;
                }
                if name.as_ref() == "Events" && roots == 1 && !wrapper && !closed {
                    closed = empty;
                    wrapper = true;
                    for attr in tag.attributes() {
                        let attr = attr?;
                        other_content |= attr.key.as_ref() != "xmlns"
                            && !attr.key.as_ref().starts_with("xmlns:");
                    }
                    continue;
                }
                if !empty {
                    reader.read_to_end(tag.name())?;
                }
                if name.as_ref() != "Event" || closed {
                    other_content = true;
                    continue;
                }
                let end = reader.buffer_position() as usize;
                let record = &xml[start..end];
                let node = quick_xml::de::from_str::<Element>(record)?.0;
                let doc = if is_sysmon(&node) {
                    has_sysmon = true;
                    normalize_event(node)?
                } else {
                    node
                };
                documents.push(doc);
            }
            Event::End(_) => {
                closed = true;
            }
            Event::Text(t) if !t.as_ref().trim().is_empty() => {
                other_content = true;
            }
            Event::CData(_) | Event::GeneralRef(_) => {
                other_content = true;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !has_sysmon {
        ensure!(roots <= 1, "unsupported concatenated non-Sysmon XML roots");
        return Ok(None);
    }
    ensure!(!wrapper || closed, "unterminated Sysmon Events wrapper");
    ensure!(
        !other_content,
        "unexpected content alongside Sysmon Event records"
    );
    Ok(Some(documents))
}

pub struct Parser {
    documents: std::vec::IntoIter<Json>,
}

impl Parser {
    pub fn load(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path)?;
        let documents = match event_documents(&source, sysmon)? {
            Some(documents) => documents,
            None => match quick_xml::de::from_str(&source)? {
                Json::Array(documents) => documents,
                single => vec![single],
            },
        };
        Ok(Self {
            documents: documents.into_iter(),
        })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json>> + '_ {
        self.documents.by_ref().map(Ok)
    }
}
