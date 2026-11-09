# Detection logic and tuning

The toolkit contains four deterministic, explainable authentication detections. All use UTC-normalized timestamps and a configurable sliding window (10 minutes by default). Rules emit once per source or account per input file for burst detections, which reduces alert noise in a batch report.

| ID | Logic | Main tuning knobs | Common benign causes |
|---|---|---|---|
| `AUTH-001` | At least `failure_threshold` failures from one source in the window. | `--failure-threshold`, `--window-minutes` | Shared VPN egress, office NAT, misconfigured clients. |
| `AUTH-002` | At least `failure_threshold` failures against one account in the window, across sources. | `--failure-threshold`, `--window-minutes` | Stale credentials on several devices, user error, IdP integration faults. |
| `AUTH-003` | One source touches at least `spray_account_threshold` distinct accounts while each has no more than `spray_max_attempts_per_account` failures in the window. | `--spray-accounts`, `--spray-max-per-account`, `--window-minutes` | Identity testing, shared gateways, synthetic load or QA activity. |
| `AUTH-004` | A success for an account follows at least `failure_threshold` failures against that account within the window. | `--failure-threshold`, `--window-minutes` | A user eventually types the correct password after mistakes; help-desk resets. |

## Tuning workflow

1. Establish a baseline from representative, authorized logs.
2. Identify shared egress points, service accounts, identity tests, and known automation.
3. Change one threshold at a time and compare alert volume and missed known scenarios.
4. Review the event window and evidence for each alert; do not treat severity as a verdict.
5. Record the reason for every local exception and revisit it periodically.

## Known limitations

- Input must already be normalized; provider-specific parsing is outside this starter.
- No geolocation, threat-intelligence lookup, asset criticality, allowlist, or identity-provider enrichment is performed.
- Events are sorted in memory. This is intended for small investigations and labs, not streaming or multi-gigabyte SIEM ingestion.
- Burst rules emit the first threshold crossing per account/source for the supplied file. Separate incidents from the same entity in one file may be grouped together.
- A spray rule counts distinct usernames exactly as provided. Normalize case and identity aliases upstream if your environment requires it.
- Timestamps without a timezone are interpreted as UTC. Clock skew between sources is not corrected.
- Severity is a starting point for triage, not an incident classification.

## Validation ideas

For an authorized lab dataset, verify the boundary cases: one below threshold, exactly at threshold, just inside and outside the window, a spray with one over-cap account, a success after failures, and a benign success without recent failures. Preserve representative false-positive examples as synthetic records when tuning rules.
