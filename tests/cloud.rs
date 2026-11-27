// Synthetic records follow the provider schemas. No account data or credentials are used.
// AWS: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
// Azure: https://learn.microsoft.com/azure/azure-monitor/platform/activity-log-schema
// Google: https://cloud.google.com/logging/docs/audit and /logging/docs/reference/v2/rest/v2/entries/list
use assert_cmd::cargo::cargo_bin_cmd;
use flate2::{Compression, GzBuilder};
use serde_json::{Value, json};
use std::{fs, io::Write, path::Path};
use tempfile::tempdir;

fn dump(input: &Path) -> Vec<Value> {
    let output = cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg(input)
        .arg("--json")
        .assert()
        .success();
    serde_json::from_slice(&output.get_output().stdout).unwrap()
}

fn hunt(input: &Path, mapping: &str, product: &str, selection: &str, expected: &Value) {
    let rule = input.parent().unwrap().join("rule.yml");
    fs::write(&rule, format!(
        "title: Cloud action fixture\ndescription: Select the expected provider event.\nstatus: test\nlevel: medium\nlogsource:\n  product: {product}\ndetection:\n  selection:\n{selection}\n  condition: selection\n"
    )).unwrap();
    let output = cargo_bin_cmd!("chainsaw")
        .arg("hunt")
        .arg(input)
        .arg("-s")
        .arg(rule)
        .arg("-m")
        .arg(Path::new("mappings").join(mapping))
        .arg("--json")
        .assert()
        .success();
    let hits: Vec<Value> = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["name"], "Cloud action fixture");
    let source = Path::new(hits[0]["document"]["path"].as_str().unwrap());
    if input.is_dir() {
        assert_eq!(source.parent(), Some(input));
    } else {
        assert_eq!(source, input);
    }
    assert_eq!(&hits[0]["document"]["data"], expected);
}

#[test]
fn hunts_cloudtrail_plain_and_gzip_with_optional_filename() {
    let dir = tempdir().unwrap();
    let hit = json!({"eventVersion":"1.10","eventType":"AwsApiCall","eventTime":"2025-01-02T03:04:05Z",
        "eventID":"ef2d5ec0-82b8-4182-970e-00602857ee80","eventName":"CreateUser","eventSource":"iam.amazonaws.com",
        "userIdentity":{"type":"IAMUser","userName":"audit-fixture"}});
    let mut wrong_operation = hit.clone();
    wrong_operation["eventName"] = json!("ListUsers");
    let mut wrong_identity = hit.clone();
    wrong_identity["userIdentity"]["userName"] = json!("other-fixture");
    let bytes =
        serde_json::to_vec(&json!({"Records":[wrong_operation, hit, wrong_identity]})).unwrap();
    for name in ["delivery.json", "named.json.gz", "unnamed.json.gz"] {
        let input = dir.path().join(name);
        if name.ends_with(".gz") {
            let mut builder = GzBuilder::new();
            if name == "named.json.gz" {
                builder = builder.filename("audit.json");
            }
            let mut encoder = builder.write(fs::File::create(&input).unwrap(), Compression::fast());
            encoder.write_all(&bytes).unwrap();
            encoder.finish().unwrap();
        } else {
            fs::write(&input, &bytes).unwrap();
        }
        assert_eq!(
            dump(&input),
            vec![wrong_operation.clone(), hit.clone(), wrong_identity.clone()]
        );
        hunt(
            &input,
            "sigma-cloudtrail-logs-all.yml",
            "aws",
            "    eventName: CreateUser\n    userName: audit-fixture",
            &hit,
        );
    }
}

#[test]
fn hunts_azure_activity_resource_and_rest_formats() {
    let dir = tempdir().unwrap();
    let resource = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/fixture";
    let action = "Microsoft.Resources/subscriptions/resourcegroups/write";
    let selection =
        format!("    operationName: {action}\n    resourceId: {resource}\n    resultType: Success");
    let hit = json!({"time":"2025-01-02T03:04:05.0123456Z","operationName":action,"resourceId":resource,
        "category":"Administrative","resultType":"Success","correlationId":"00000000-0000-0000-0000-000000000002",
        "identity":{"authorization":{"evidence":{"principalId":"00000000-0000-0000-0000-000000000003"}}}});
    let mut control = hit.clone();
    control["resultType"] = json!("Failure");
    let resource_selection =
        format!("{selection}\n    principalId: 00000000-0000-0000-0000-000000000003");
    for (name, data) in [
        (
            "eventhub.json",
            json!({"records":[control,hit]}).to_string(),
        ),
        (
            "eventhub.jsonl",
            json!({"records":[control,hit]}).to_string(),
        ),
        ("PT1H.json", format!("{control}\n{hit}\n")),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, data).unwrap();
        hunt(
            &path,
            "sigma-azure-activity.yml",
            "azure",
            &resource_selection,
            &hit,
        );
    }
    let hit = json!({"eventTimestamp":"2025-01-02T03:04:05Z","operationName":{"value":action},"resourceId":resource,
        "caller":"operator@example.org","status":{"value":"Succeeded"},"eventDataId":"fixture-event","correlationId":"fixture-correlation"});
    let mut control = hit.clone();
    control["caller"] = json!("another@example.org");
    let path = dir.path().join("activity.json");
    fs::write(
        &path,
        json!({"value":[control,hit],"nextLink":"https://example.invalid/page2"}).to_string(),
    )
    .unwrap();
    hunt(
        &path,
        "sigma-azure-activity.yml",
        "azure",
        &format!(
            "    operationName: {action}\n    resourceId: {resource}\n    resultType: Succeeded\n    caller: operator@example.org"
        ),
        &hit,
    );
}

#[test]
fn hunts_google_cloud_audit_entries_and_rejects_other_payloads() {
    let dir = tempdir().unwrap();
    let hit = json!({"timestamp":"2025-01-02T03:04:05.123456789Z","insertId":"fixture-hit",
        "logName":"projects/example/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"gcs_bucket"},
        "protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog",
        "methodName":"storage.buckets.delete","serviceName":"storage.googleapis.com","resourceName":"projects/_/buckets/fixture",
        "authenticationInfo":{"principalEmail":"operator@example.org"}}});
    let mut control = hit.clone();
    control["protoPayload"]["methodName"] = json!("storage.buckets.get");
    let mut other_payload = hit.clone();
    other_payload["protoPayload"]["@type"] = json!("type.googleapis.com/example.Other");
    let entries = json!([other_payload, hit, control]);
    for (name, contents) in [
        ("gcloud.json", entries.to_string()),
        (
            "logging.json",
            json!({"entries":entries,"nextPageToken":"example"}).to_string(),
        ),
        (
            "logging.jsonl",
            format!("{other_payload}\n{hit}\n{control}\n"),
        ),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        hunt(
            &path,
            "sigma-google-cloud-audit.yml",
            "gcp",
            "    gcp.audit.method_name: storage.buckets.delete\n    serviceName: storage.googleapis.com\n    principalEmail: operator@example.org\n    resourceName: projects/_/buckets/fixture",
            &hit,
        );
    }
}

#[test]
fn preserves_ambiguous_and_mixed_json_envelopes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("inventory.json");
    let cloud =
        json!({"eventVersion":"1.09","eventType":"AwsApiCall","eventTime":"2025-01-01T01:00:00Z"});
    for value in [
        json!({"Records":[{"eventType":"AwsApiCall"}]}),
        json!({"Records":[cloud,{"book":"unrelated"}]}),
        json!({"Records":[cloud],"collection":"application inventory"}),
        json!({"records":[{"time":"yesterday","category":"note","resourceId":"42","operationName":"edit"}]}),
        json!({"entries":[]}),
        json!({"value":[1,2,3]}),
    ] {
        fs::write(&path, value.to_string()).unwrap();
        assert_eq!(dump(&path), vec![value]);
    }
}

#[test]
fn rejects_corrupted_gzip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("damaged.json.gz");
    let mut encoder = GzBuilder::new().write(Vec::new(), Compression::fast());
    encoder.write_all(br#"{"Records":[]}"#).unwrap();
    let mut bytes = encoder.finish().unwrap();
    bytes.truncate(bytes.len() - 4);
    fs::write(&path, bytes).unwrap();
    cargo_bin_cmd!("chainsaw")
        .arg("dump")
        .arg(path)
        .arg("--json")
        .assert()
        .failure();
}

fn write_gzip(path: &Path, data: &[u8]) {
    let mut encoder = GzBuilder::new().write(fs::File::create(path).unwrap(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap();
}

#[test]
fn hunts_directory_with_bare_cloudtrail_gzip_and_unrelated_compressed_syslog() {
    let temp = tempdir().unwrap();
    let dir = temp.path().join("events");
    fs::create_dir(&dir).unwrap();
    let event = json!({"eventVersion":"1.10","eventTime":"2025-01-01T00:00:00Z","eventName":"ListBuckets","eventType":"AwsApiCall"});
    let mut padded = vec![b' '; 10_000];
    padded.extend(serde_json::to_vec(&json!({"Records":[event]})).unwrap());
    write_gzip(&dir.join("delivery.gz"), &padded);
    write_gzip(
        &dir.join("messages.1.gz"),
        b"Jan  2 03:04:05 host svc: ordinary log\n",
    );
    hunt(
        &dir,
        "sigma-cloudtrail-logs-all.yml",
        "aws",
        "    eventName: ListBuckets",
        &event,
    );
}

#[test]
fn compressed_json_parse_errors_are_reported() {
    let temp = tempdir().unwrap();
    for (name, contents) in [
        ("delivery.json.gz", "not JSON"),
        ("delivery.gz", "{malformed"),
    ] {
        let file = temp.path().join(name);
        write_gzip(&file, contents.as_bytes());
        cargo_bin_cmd!("chainsaw")
            .arg("dump")
            .arg(file)
            .arg("--json")
            .assert()
            .failure();
    }
}

// Projected Activity Logs List response, based on Microsoft's 2015-04-01 sample:
// https://learn.microsoft.com/rest/api/monitor/activity-logs/list#sample-response
#[test]
fn hunts_azure_rest_projection_with_event_id_and_no_resource_id() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("projected.json");
    let hit = json!({
        "id":"/subscriptions/fixture/resourceGroups/group/providers/microsoft.support/supporttickets/123/events/record-01/ticks/635574752669792776",
        "eventTimestamp":"2015-01-21T22:14:26.9792776Z",
        "operationName":{"value":"microsoft.support/supporttickets/write"},
        "status":{"value":"Succeeded"},
        "correlationId":"fixture-correlation"
    });
    let mut control = hit.clone();
    control["operationName"]["value"] = json!("microsoft.support/supporttickets/read");
    fs::write(
        &input,
        json!({"value":[control,hit],"nextLink":"https://example.invalid/next"}).to_string(),
    )
    .unwrap();
    assert_eq!(dump(&input), vec![control, hit.clone()]);
    hunt(
        &input,
        "sigma-azure-activity.yml",
        "azure",
        "    operationName: microsoft.support/supporttickets/write",
        &hit,
    );

    let mut unrelated = hit;
    unrelated["id"] = json!("/catalogs/example/events/record-01/ticks/123");
    let wrapper = json!({"value":[unrelated]});
    fs::write(&input, wrapper.to_string()).unwrap();
    assert_eq!(dump(&input), vec![wrapper]);
}
