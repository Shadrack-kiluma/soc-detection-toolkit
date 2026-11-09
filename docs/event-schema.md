# Event schema

The input is UTF-8 JSON Lines: one JSON object per line. Blank lines are ignored. Required fields are `timestamp`, `username`, `source_ip`, and `outcome`.

```json
{"timestamp":"2026-11-01T10:12:00Z","username":"alex","source_ip":"198.51.100.22","outcome":"failure","event_id":"evt-004","application":"staff-portal"}
```

| Field | Type | Requirements |
|---|---|---|
| `timestamp` | string | ISO-8601 date and time; timezone offset recommended. `Z` is accepted. Naive values are treated as UTC. |
| `username` | string | Non-empty account identifier. Use a consistent canonical form. |
| `source_ip` | string | Valid IPv4 or IPv6 address. Hostnames are not accepted. |
| `outcome` | string | `failure` or `success`, case-insensitive. |
| Additional fields | any JSON value | Preserved by the loader but not currently used in the detections. Examples: `event_id`, `application`, `auth_method`, `device_id`. |

Malformed JSON is reported with its line number. Missing fields, invalid timestamps, unsupported outcomes, and invalid IP addresses return a clear error and exit code `2`. The analyzer never edits the input file.

## Normalization suggestions

- Convert provider-specific success/failure codes to the two supported outcomes.
- Normalize timestamp offsets and account identifiers consistently.
- Retain event IDs and source-system fields for auditability.
- Remove or pseudonymize personal data before using public or portfolio datasets.
- Keep raw source logs in their governed system of record; do not upload private telemetry to a public repository.
