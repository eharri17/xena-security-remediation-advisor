---
name: triage-wiz-finding
description: "Triage one CRITICAL Wiz finding end-to-end and draft a Jira ticket for human review (live Wiz + Jira via MCP)."
disable-model-invocation: true
argument-hint: "Wiz issue ID or URL"
---
Triage this Wiz finding with the full advisor workflow: ${input:wizIssue:Wiz issue ID or URL}

Use the live Wiz and Atlassian MCP servers. Finish at the human review checkpoint.
