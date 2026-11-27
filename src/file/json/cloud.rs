//! Identify provider export envelopes without modifying the native records.

use super::Json;
use regex::Regex;
use std::sync::LazyLock;

fn string_at<'a>(record: &'a Json, field: &str) -> Option<&'a str> {
    record.get(field)?.as_str()
}

fn cloudtrail(record: &Json) -> bool {
    string_at(record, "eventVersion").is_some()
        && string_at(record, "eventTime").is_some()
        && (string_at(record, "eventType").is_some_and(|kind| kind.starts_with("Aws"))
            || (string_at(record, "eventName").is_some()
                && string_at(record, "eventSource").is_some()))
}

fn azure_resource(record: &Json) -> bool {
    string_at(record, "resourceId").is_some_and(|id| {
        let scope = id.split('/').nth(1).unwrap_or_default();
        id.starts_with('/')
            && (scope.eq_ignore_ascii_case("subscriptions")
                || scope.eq_ignore_ascii_case("providers"))
    })
}

pub(super) fn azure_export(record: &Json) -> bool {
    string_at(record, "operationName").is_some()
        && string_at(record, "time").is_some()
        && azure_resource(record)
        && string_at(record, "category").is_some()
}

// A REST $select projection can omit resourceId while retaining the Activity Log
// event's own ARM identifier. Never manufacture a resourceId from that identifier.
static AZURE_EVENT_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^/(subscriptions|providers)/.+/events/[^/]+/ticks/[0-9]+$").unwrap()
});

fn azure_rest(record: &Json) -> bool {
    string_at(record, "eventTimestamp").is_some()
        && record
            .pointer("/operationName/value")
            .and_then(Json::as_str)
            .is_some()
        && (azure_resource(record)
            || string_at(record, "id").is_some_and(|id| AZURE_EVENT_ID.is_match(id)))
}

fn google_log_entry(record: &Json) -> bool {
    string_at(record, "logName").is_some_and(|name| name.contains("/logs/"))
        && string_at(record, "timestamp").is_some()
        && (record.get("protoPayload").is_some()
            || record.get("jsonPayload").is_some()
            || record.get("textPayload").is_some())
}

pub(super) fn envelope_key(root: &Json) -> Option<&'static str> {
    let object = root.as_object()?;
    let (key, page_token, recognize): (_, _, fn(&Json) -> bool) = if object.contains_key("Records")
    {
        ("Records", None, cloudtrail)
    } else if object.contains_key("records") {
        ("records", None, azure_export)
    } else if object.contains_key("value") {
        ("value", Some("nextLink"), azure_rest)
    } else {
        ("entries", Some("nextPageToken"), google_log_entry)
    };
    if object
        .keys()
        .any(|field| field != key && Some(field.as_str()) != page_token)
    {
        return None;
    }
    let records = root.get(key)?.as_array()?;
    (!records.is_empty() && records.iter().all(recognize)).then_some(key)
}
