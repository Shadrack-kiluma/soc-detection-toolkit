# Analyst triage playbook

Use this as a starting workflow. Follow your organization's incident-response procedures and escalation paths.

## 1. Validate the alert

- Confirm the timestamp, source, account, event count, and configured time window.
- Check that events came from the expected system and that timestamps are trustworthy.
- Compare the source against known VPN, proxy, NAT, identity testing, and monitoring infrastructure.
- Check whether a maintenance window, rollout, or password rotation explains the pattern.

## 2. Scope the activity

- Search a wider time range in the identity provider and application logs.
- Check whether the same source touched other accounts or services.
- For a targeted account, look for failures from other sources and recent credential or MFA changes.
- For a success-after-failures signal, inspect the successful session, MFA result, device, and follow-on actions.
- Correlate with endpoint and network telemetry using approved tools.

## 3. Assess impact and preserve evidence

- Determine whether any success was unauthorized and what data or actions were reachable.
- Preserve relevant logs and event identifiers according to retention and evidence-handling policy.
- Record the query window, data source, rule parameters, and benign explanations considered.
- Escalate when impact, scope, or confidence meets your organization's criteria.

## 4. Respond through approved processes

Use the incident owner's judgment for containment and account recovery. This toolkit is read-only and does not block logins, disable accounts, or trigger response actions. Document the decision and communicate with the appropriate owner.

## 5. Close the loop

Record the final disposition, confirmed root cause, and detection gaps. Turn useful false-positive examples into synthetic validation data. Adjust thresholds only with a documented reason and review date.
