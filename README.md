# SOC Detection Toolkit

A small, explainable blue-team toolkit for finding suspicious patterns in normalized authentication logs. It demonstrates detection engineering, event validation, analyst-centered alert context, and practical triage guidance with Python's standard library only.

> **Portfolio lab:** all sample records are synthetic and use documentation-only IP ranges. Findings are triage leads, not proof of compromise. The tool reads local files; it does not connect to networks, block users, or modify source logs.

## Quick start

Requires Python 3.10 or newer.

```console
python -m socdetect.cli examples/sample-auth.jsonl
```

Emit machine-readable JSON:

```console
python -m socdetect.cli examples/sample-auth.jsonl --format json
```

Save a triage report without changing the input log:

```console
python -m socdetect.cli examples/sample-auth.jsonl --format json --output triage-report.json
```

Install the `socdetect` command locally:

```console
python -m pip install -e .
socdetect examples/sample-auth.jsonl --failure-threshold 5 --window-minutes 10
```

## Included detections

| Rule | Severity | Detection |
|---|---|---|
| `AUTH-001` | Medium | Repeated authentication failures from a single source in a sliding window. |
| `AUTH-002` | Medium | Repeated failures against one account, even across multiple sources. |
| `AUTH-003` | High | Possible password spray: one source fails against many distinct accounts while staying under a per-account attempt cap. |
| `AUTH-004` | High | Successful login after repeated failures against the same account. |

Every finding includes the event count, time window, source/account context, evidence, and suggested analyst triage steps. Thresholds are configurable from the CLI. Full assumptions and limitations are in [`docs/detections.md`](docs/detections.md); the event schema is in [`docs/event-schema.md`](docs/event-schema.md).

## Example output

```text
SOC Detection Toolkit — 17 events, 5 finding(s)

[MEDIUM] AUTH-001 · Authentication burst from one source
  Time: 2026-11-01T10:14:00Z UTC
  User: alex | Source: 198.51.100.22 | Events: 5
  Evidence: 5 failures from this source in 10 minutes.
  ...
```

Exact counts depend on configured thresholds. Use the sample dataset to explore the detections.

## Project map

- `socdetect/rules.py` — normalized input validation and detection rules
- `socdetect/cli.py` — command-line interface and text/JSON reports
- `examples/sample-auth.jsonl` — synthetic authentication events
- `docs/detections.md` — rule logic, tuning, false positives, and limitations
- `docs/event-schema.md` — input contract and example record
- `docs/triage-playbook.md` — investigation workflow for findings

## Responsible use

Use only telemetry you are authorized to handle. Keep real identity data out of public examples and reports. Review the documentation before operational use and tune thresholds to local baselines. The toolkit does not automatically quarantine accounts or take response actions.

## License

MIT. See [`LICENSE`](LICENSE).
