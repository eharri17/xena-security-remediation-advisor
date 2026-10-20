---
name: triage-demo-offline
description: "Offline demo of the Security Remediation Advisor using sample fixtures (no Wiz or Jira access needed)."
disable-model-invocation: true
argument-hint: "wiz-demo-0001 (new) | wiz-demo-0002 (duplicate) | wiz-demo-0003 (out of scope)"
---
offline demo: triage Wiz finding ${input:wizIssue:wiz-demo-0001}

Run the full advisor workflow in OFFLINE MODE using `demo/fixtures/`. Label all output `OFFLINE DEMO DATA` and finish at the human review checkpoint.
