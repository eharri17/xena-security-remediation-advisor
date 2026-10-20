---
name: list-critical-findings
description: "List open CRITICAL Wiz findings for the XENA business unit so you can pick one to triage (read-only)."
disable-model-invocation: true
---
Use only `wiz-finding-analyst` to list up to 10 OPEN CRITICAL Wiz issues or vulnerability findings for the XENA business unit, newest first. Use `discover` to find the right list or search tool.

Return a table with these columns: Wiz issue ID, title, CVE, resource, environment, internet exposed, first seen.

Do not triage or draft anything. End with: "Run /triage-wiz-finding <id> to triage one."
