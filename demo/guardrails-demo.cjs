#!/usr/bin/env node
'use strict';

// Live demo of the advisor guardrails: replays realistic tool calls through the real hook
// and prints the decision VS Code would receive. No Wiz or Jira credentials required.
// Usage: npm run demo:guardrails

const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const hook = path.join(__dirname, '..', 'scripts', 'hooks', 'advisor-hook.cjs');
const env = { ...process.env, ADVISOR_AGENT: 'guardrail-demo', ADVISOR_AUDIT_LOG: path.join(os.tmpdir(), 'advisor-guardrail-demo.jsonl') };

const calls = [
  ['Read Wiz finding', 'mcp_advisor-wiz_execute', { tool_name: 'get_issue', parameters: { id: 'wiz-demo-0001' } }],
  ['Change Wiz issue status', 'mcp_advisor-wiz_execute', { tool_name: 'update_issue_status', parameters: { id: 'wiz-demo-0001', status: 'RESOLVED' } }],
  ['Unknown Wiz operation', 'mcp_advisor-wiz_execute', { tool_name: 'run_graph_query', parameters: {} }],
  ['Search JIFA for duplicates', 'mcp_advisor-atlassian_jira_search', { jql: 'project = JIFA AND text ~ "CVE-2021-44228"' }],
  ['Search all projects in Jira', 'mcp_advisor-atlassian_jira_search', { jql: 'text ~ "CVE-2021-44228"' }],
  ['List ASX-XENA repositories', 'mcp_advisor-atlassian_bitbucket_list_repositories', { workspace: 'ASX-XENA' }],
  ['List every Bitbucket repo', 'mcp_advisor-atlassian_bitbucket_list_repositories', {}],
  ['Read pom.xml in xena-api', 'mcp_advisor-atlassian_bitbucket_get_file_content', { workspace: 'ASX-XENA', repository: 'xena-api', file_path: 'pom.xml' }],
  ['Read repo in other project', 'mcp_advisor-atlassian_bitbucket_get_file_content', { workspace: 'OTHER', repository: 'payments', file_path: 'pom.xml' }],
  ['Open a fix branch', 'mcp_advisor-atlassian_bitbucket_create_branch', { workspace: 'ASX-XENA', repository: 'xena-api', name: 'fix/log4j' }],
  ['Auto-create Jira ticket', 'mcp_advisor-atlassian_jira_create_issue', { project_key: 'JIFA', summary: 'Log4Shell' }],
  ['Comment on existing ticket', 'mcp_advisor-atlassian_jira_add_comment', { issue_key: 'JIFA-1311', comment: 'dup' }],
  ['Write ticket draft', 'create_file', { filePath: 'drafts/wiz-demo-0001-20261012.md', content: '...' }],
  ['Edit source code', 'replace_string_in_file', { filePath: 'scripts/hooks/lib/policy.cjs', oldString: 'a', newString: 'b' }],
  ['Run shell command', 'run_in_terminal', { command: 'curl https://example.com' }],
];

const icon = { allow: '✅ ALLOW', pass: '✅ ALLOW', ask: '🟡 ASK  ', deny: '⛔ DENY ' };
console.log('XENA Security Remediation Advisor: guardrail demo\n');
for (const [label, tool_name, tool_input] of calls) {
  const res = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', timestamp: new Date().toISOString(), tool_name, tool_input, tool_use_id: label }),
    env,
    encoding: 'utf8',
  });
  const out = res.stdout ? JSON.parse(res.stdout) : {};
  const decision = out.hookSpecificOutput?.permissionDecision || 'pass';
  const reason = out.hookSpecificOutput?.permissionDecisionReason || '';
  console.log(`${icon[decision]}  ${label.padEnd(28)} ${reason.replace('[Advisor policy] ', '')}`);
}
console.log(`\nAudit trail written to ${env.ADVISOR_AUDIT_LOG}`);
