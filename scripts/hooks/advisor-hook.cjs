#!/usr/bin/env node
'use strict';

// Lifecycle hook for the Security Remediation Advisor agents (VS Code Local harness).
//   PreToolUse      -> enforce least-privilege policy (deny/ask) and audit the decision
//   PostToolUse     -> audit the completed tool call
//   UserPromptSubmit / SessionStart / Stop / SubagentStop -> audit
// Usage: node scripts/hooks/advisor-hook.cjs   (event JSON on stdin)

const fs = require('node:fs');
const path = require('node:path');
const { PROJECT_ROOT, loadConfig, evaluatePreToolUse, summarizeInput } = require('./lib/policy.cjs');

const config = loadConfig();
const agent = process.env.ADVISOR_AGENT || 'unknown-agent';

function audit(record) {
  try {
    const file = path.resolve(PROJECT_ROOT, process.env.ADVISOR_AUDIT_LOG || config.auditLog || 'audit/audit-log.jsonl');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), agent, ...record })}\n`);
  } catch (err) {
    process.stderr.write(`advisor-hook: audit write failed: ${err.message}\n`);
  }
}

function respond(obj) {
  process.stdout.write(JSON.stringify(obj ?? {}));
}

function handle(event) {
  const name = event.hook_event_name;
  const base = { event: name, session_id: event.session_id };

  switch (name) {
    case 'PreToolUse': {
      const result = evaluatePreToolUse(event, config);
      audit({ ...base, tool: event.tool_name, tool_use_id: event.tool_use_id, op: result.op, decision: result.decision, reason: result.reason, input: summarizeInput(event.tool_input) });
      if (result.decision === 'pass') return respond({});
      return respond({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: result.decision,
          permissionDecisionReason: `[Advisor policy] ${result.reason}`,
          additionalContext:
            result.decision === 'deny'
              ? 'This action violates the Security Remediation Advisor policy (read-only, single Jira project, drafts/ only). Do not retry or work around it; continue with read-only research or report the limitation.'
              : undefined,
        },
      });
    }
    case 'PostToolUse': {
      const resp = event.tool_response;
      const size = typeof resp === 'string' ? resp.length : JSON.stringify(resp ?? '').length;
      audit({ ...base, tool: event.tool_name, tool_use_id: event.tool_use_id, input: summarizeInput(event.tool_input), response_chars: size });
      return respond({});
    }
    case 'UserPromptSubmit':
      audit({ ...base, prompt: String(event.prompt || '').slice(0, 300) });
      return respond({});
    case 'SessionStart':
      audit(base);
      return respond({
        hookSpecificOutput: {
          hookEventName: 'SessionStart',
          additionalContext: `Advisor scope: Jira project ${config.jiraProject} (issue keys ${config.jiraProjectKey || config.jiraProject}-<n>); severities ${(config.severityScope || []).join(', ')}; drafts under ${config.draftsDir}/. Every tool call is audited to ${config.auditLog}.`,
        },
      });
    default:
      audit(base);
      return respond({});
  }
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => (raw += chunk));
process.stdin.on('end', () => {
  let event;
  try {
    event = JSON.parse(raw || '{}');
  } catch (err) {
    // Fail closed: exit code 2 blocks the operation and returns stderr to the model.
    process.stderr.write(`[Advisor policy] Could not parse hook input; blocking for safety. ${err.message}\n`);
    process.exit(2);
  }
  try {
    handle(event);
  } catch (err) {
    if (event?.hook_event_name === 'PreToolUse') {
      process.stderr.write(`[Advisor policy] Guard error; blocking for safety. ${err.message}\n`);
      process.exit(2);
    }
    process.stderr.write(`advisor-hook: ${err.message}\n`);
  }
});
