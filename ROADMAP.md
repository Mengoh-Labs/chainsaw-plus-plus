# Chainsaw++ hunting targets

## First milestone

A source is ready for hunting when `chainsaw hunt` can match a rule against a known event, reject a similar control event, and identify the source record. Reading or printing the file is a separate check.

| Target | First acceptance test |
| --- | --- |
| Sigma correlations | Run `temporal`, `temporal_ordered`, and `value_count` from the CLI. Emit the correlation rule and each contributing record. Test different hosts, reversed event order, events just inside and outside the window, repeated values, and missing grouping fields. Report unresolved rule references explicitly. |
| Raw syslog | Read RFC 3164 and RFC 5424 from local files. Verify timestamp, host, application and message. Retain RFC 5424 structured data. Test malformed input and make year and timezone assumptions visible for RFC 3164. |
| Sysmon for Linux | Unwrap a syslog record and parse its Sysmon XML. Preserve every named `EventData` field, including adjacent `Image` and `ProcessId` values. Hunt a process-creation event and verify that an unrelated process fails the rule. |
| Sysmon for Windows | Preserve EVTX hunting on the Sysmon Operational channel. Verify event ID, computer, record ID, timestamp and process GUID. Test a correlation using two events from the same host and a control split across hosts. |
| macOS Unified Log | Hunt exported `log show --style ndjson` output directly, including files named `.ndjson`. Preserve timestamp, process, subsystem, category and message. Test an exported file and a `.logarchive` on macOS separately. Record any dependency on Apple's log utility. |

The 2.18.0 baseline can read Windows Sysmon EVTX and search macOS Unified Log exported as JSONL. It rejects raw RFC 5424 syslog. Its generic XML reader lost the first of two adjacent named Sysmon data elements in a fixture. The temporal correlation test produced component matches only.

## Additional sources

| Target | First format and proof |
| --- | --- |
| AWS CloudTrail | Replay a gzip-compressed delivery file containing multiple entries in `Records`. Count each event once and select one by event name and identity. Evaluate the existing [CloudTrail branch](https://github.com/Mengoh-Labs/chainsaw-plus-plus/tree/feat/cloudtrail_support) before porting it. |
| Azure | Start with Activity Log exports. Verify an operation, caller, resource ID, result and correlation ID against a known event. Track Entra sign-in and audit logs as separate formats. |
| Google Cloud | Start with Cloud Audit Logs. Verify timestamp, service, method, principal, resource and record identifier from a Cloud Logging export. |
| Firewalls | Select the first vendor and export format from available captures. Use allow and deny fixtures to verify action, protocol, source and destination addresses and ports. Keep original fields available alongside mapped ones. |

### CloudTrail branch baseline

At `144bbf6`, the upstream branch split a synthetic two-event delivery into two events. Its Sigma mapping returned only the intended event for plain JSON and for gzip with an embedded filename. The same delivery failed when the optional gzip filename was absent. Cover both gzip variants when porting. On the original 2.18.0 build, the uncompressed delivery remained one document.

### Firewall reference capture

The first candidate is Palo Alto Networks PAN-OS Traffic, using Elastic's [208-line fixture and expected events](https://github.com/elastic/integrations/tree/59f205d0550576c5ff5479bbf82dd6b9a7eac972/packages/panw/data_stream/panos/_dev/test/pipeline). The reference includes 203 allow actions and one each of drop-icmp, drop, reset-client, reset-server, and reset-both. Match the original action and endpoints per record. On the original 2.18.0 build, `dump --load-unknown` exited successfully but collapsed the entire file into one string. Acceptance requires 208 separately addressable events.
