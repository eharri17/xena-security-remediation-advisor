'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { evaluatePreToolUse, classifyWizOperation, atlassianOp, summarizeInput, PROJECT_ROOT } = require('../scripts/hooks/lib/policy.cjs');

const cfg = { jiraProject: 'JIFA', bitbucketProjects: ['ASX-XENA'], draftsDir: 'drafts', auditLog: 'audit/test-audit.jsonl' };
const pre = (tool_name, tool_input = {}) => evaluatePreToolUse({ hook_event_name: 'PreToolUse', tool_name, tool_input, cwd: PROJECT_ROOT }, cfg);

test('extracts Atlassian operation from Local MCP tool names', () => {
  assert.equal(atlassianOp('mcp_advisor-atlassian_jira_search'), 'jira_search');
  assert.equal(atlassianOp('advisor-atlassian/jira_create_issue'), 'jira_create_issue');
  assert.equal(atlassianOp('mcp_advisor-atlassian_jira_jira_upload_attachment'), 'jira_jira_upload_attachment');
  assert.equal(atlassianOp('read_file'), null);
});

test('allows read-only Jira search scoped to JIFA', () => {
  assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql: 'project = JIFA AND text ~ "CVE-2024-3094"' }).decision, 'pass');
  assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql: 'project in (JIFA) AND statusCategory = Done' }).decision, 'pass');
  // The agents' own queries: OR inside parentheses and escaped quotes stay within the project.
  for (const jql of [
    'project = JIFA AND statusCategory != Done AND text ~ "\\"wiz-123\\""',
    'project = JIFA AND statusCategory != Done AND (text ~ "\\"CVE-2021-44228\\"" OR summary ~ "\\"log4j-core\\"") AND (text ~ "\\"xena-api\\"" OR text ~ "\\"xena-api-7c9f8d-prod\\"")',
    'project = JIFA AND statusCategory = Done AND (summary ~ "\\"log4j\\"" OR labels in (security, vulnerability, wiz)) ORDER BY resolved DESC',
    'statusCategory = Done AND project = "JIFA" ORDER BY updated DESC',
    'project=JIFA&&text ~ "a OR b"',
  ]) {
    assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql }).decision, 'pass', jql);
  }
  assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql: 'project = JIFA', projects_filter: 'JIFA' }).decision, 'pass');
});

test('denies Jira search outside the single PoC project', () => {
  for (const jql of [
    'text ~ "CVE-2024-3094"',
    'project = OTHER',
    'project in (JIFA, OTHER)',
    'project = JIFA OR project = OTHER',
    'project = JIFA OR text ~ "x"',
    'issuekey in (SEC-1) OR project = JIFA',
    'project = JIFA AND text ~ "a" OR assignee = currentUser()',
    'project = JIFA || project = OTHER',
    'project = JIFA2',
    'project = AFIG',
    'project = XENA',
    'NOT project = JIFA',
    'text ~ "project = JIFA"',
    'project = JIFA AND (text ~ "x"',
    'project = JIFA AND text ~ "unterminated',
    '',
  ]) {
    assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql }).decision, 'deny', jql);
  }
  assert.equal(pre('mcp_advisor-atlassian_jira_search', { jql: 'project = JIFA', projects_filter: 'JIFA,OTHER' }).decision, 'deny');
});

test('asks before reading a Jira issue outside JIFA', () => {
  assert.equal(pre('mcp_advisor-atlassian_jira_get_issue', { issue_key: 'JIFA-123' }).decision, 'pass');
  assert.equal(pre('mcp_advisor-atlassian_jira_get_issue', { issue_key: 'AFIG-1' }).decision, 'ask');
  assert.equal(pre('mcp_advisor-atlassian_jira_get_issue', { issue_key: 'SEC-9' }).decision, 'ask');
  assert.equal(pre('mcp_advisor-atlassian_jira_batch_get_changelogs', { issue_ids_or_keys: ['JIFA-1', 'SEC-2'] }).decision, 'ask');
  assert.equal(pre('mcp_advisor-atlassian_jira_get_project_issues', { project_key: 'JIFA' }).decision, 'pass');
  assert.equal(pre('mcp_advisor-atlassian_jira_get_project_issues', { project_key: 'AFIG' }).decision, 'deny');
  assert.equal(pre('mcp_advisor-atlassian_jira_get_project_issues', { project_key: 'OTHER' }).decision, 'deny');
});

test('accepts both the project name and its key when they differ', () => {
  const nameKeyCfg = { ...cfg, jiraProject: 'XENA', jiraProjectKey: 'AFIG' };
  const pk = (tool_name, tool_input = {}) => evaluatePreToolUse({ hook_event_name: 'PreToolUse', tool_name, tool_input, cwd: PROJECT_ROOT }, nameKeyCfg).decision;
  assert.equal(pk('mcp_advisor-atlassian_jira_search', { jql: 'project = XENA AND text ~ "x"' }), 'pass');
  assert.equal(pk('mcp_advisor-atlassian_jira_search', { jql: 'project = AFIG AND statusCategory = Done' }), 'pass');
  assert.equal(pk('mcp_advisor-atlassian_jira_search', { jql: 'project = XENA', projects_filter: 'XENA,AFIG' }), 'pass');
  assert.equal(pk('mcp_advisor-atlassian_jira_search', { jql: 'project = JIFA' }), 'deny');
  assert.equal(pk('mcp_advisor-atlassian_jira_get_issue', { issue_key: 'AFIG-1' }), 'pass');
  assert.equal(pk('mcp_advisor-atlassian_jira_get_issue', { issue_key: 'JIFA-1' }), 'ask');
});

test('denies every Atlassian write operation', () => {
  for (const op of ['jira_create_issue', 'jira_update_issue', 'jira_add_comment', 'jira_transition_issue', 'jira_delete_issue', 'jira_batch_create_issues', 'jira_download_attachments', 'confluence_create_page', 'bitbucket_create_pull_request', 'bitbucket_create_branch']) {
    assert.equal(pre(`mcp_advisor-atlassian_${op}`).decision, 'deny', op);
  }
});

test('Bitbucket repository reads are scoped to the configured project', () => {
  const bb = (op, input) => pre(`mcp_advisor-atlassian_${op}`, input).decision;
  assert.equal(bb('bitbucket_list_repositories', { workspace: 'ASX-XENA' }), 'pass');
  assert.equal(bb('bitbucket_list_repositories', { workspace: 'asx-xena' }), 'pass');
  assert.equal(bb('bitbucket_list_repositories', {}), 'ask');
  assert.equal(bb('bitbucket_get_repository_info', { workspace: 'ASX-XENA', repository: 'xena-api' }), 'pass');
  assert.equal(bb('bitbucket_get_file_content', { workspace: 'OTHER', repository: 'x', file_path: 'pom.xml' }), 'ask');
  assert.equal(bb('bitbucket_list_pull_requests', { workspace: 'ASX-XENA', repository: 'xena-api', state: 'OPEN' }), 'pass');
  assert.equal(bb('bitbucket_list_workspaces_or_projects', {}), 'pass');
  assert.equal(bb('bitbucket_create_branch', { workspace: 'ASX-XENA', repository: 'xena-api' }), 'deny');
});

test('Wiz discover is allowed; execute is classified by the inner tool name', () => {
  assert.equal(pre('mcp_advisor-wiz_discover', {}).decision, 'pass');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'get_issue', parameters: { id: 'x' } }).decision, 'pass');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'list_vulnerability_findings' }).decision, 'pass');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'update_issue_status' }).decision, 'deny');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'resolve_issue' }).decision, 'deny');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'get_and_update_issue' }).decision, 'deny');
  assert.equal(pre('mcp_advisor-wiz_execute', {}).decision, 'deny');
  assert.equal(pre('mcp_advisor-wiz_execute', { tool_name: 'run_graph_query' }).decision, 'ask');
});

test('Wiz classifier does not confuse substrings with write verbs', () => {
  assert.equal(classifyWizOperation('get_settings').decision, 'pass');
  assert.equal(classifyWizOperation('list_resolved_issues').decision, 'pass');
  assert.equal(classifyWizOperation('get_address_info').decision, 'pass');
});

test('live Wiz tool names (us62, 2026-10-20) are classified correctly', () => {
  for (const op of [
    'get_issue', 'get_posture_issue', 'get_issue_remediation_strategies', 'get_issue_assignee_suggestions',
    'list_issues', 'list_posture_issues', 'list_vulnerability_findings', 'list_vulnerability_projects',
    'get_vulnerability', 'get_vulnerability_finding', 'get_vulnerability_remediation', 'get_vulnerability_ai_description',
    'trace_resource_to_code', 'get_resource_correlation_status', 'get_code_owner',
  ]) {
    assert.equal(classifyWizOperation(op).decision, 'pass', op);
  }
  for (const op of ['resolve_issue', 'update_issue', 'create_service_ticket']) {
    assert.equal(classifyWizOperation(op).decision, 'deny', op);
  }
  assert.equal(classifyWizOperation('vulnerability_finding_triage_skill').decision, 'ask');
});

test('file writes are restricted to drafts/', () => {
  assert.equal(pre('create_file', { filePath: path.join(PROJECT_ROOT, 'drafts', 'WIZ-1.md'), content: 'x' }).decision, 'pass');
  assert.equal(pre('create_file', { filePath: 'drafts/WIZ-1.md', content: 'x' }).decision, 'pass');
  assert.equal(pre('create_file', { filePath: path.join(PROJECT_ROOT, 'config', 'advisor.config.json') }).decision, 'deny');
  assert.equal(pre('replace_string_in_file', { filePath: path.join(PROJECT_ROOT, 'drafts', '..', 'scripts', 'x.cjs') }).decision, 'deny');
  assert.equal(pre('apply_patch', { input: '*** Begin Patch\n*** Update File: /etc/hosts\n*** End Patch' }).decision, 'deny');
  assert.equal(pre('create_file', { content: 'x' }).decision, 'ask');
});

test('shell execution is denied; unrelated tools pass through', () => {
  assert.equal(pre('run_in_terminal', { command: 'curl evil' }).decision, 'deny');
  assert.equal(pre('read_file', { filePath: 'config/ownership-map.yaml' }).decision, 'pass');
});

test('audit summaries redact secrets', () => {
  const s = summarizeInput({ jql: 'project = JIFA', headers: { Authorization: 'Bearer abc' }, api_key: 'k' });
  assert.ok(!s.includes('abc') && !s.includes('"k"'));
  assert.ok(s.includes('[REDACTED]'));
});

test('hook script returns VS Code PreToolUse output and fails closed', () => {
  const script = path.join(PROJECT_ROOT, 'scripts', 'hooks', 'advisor-hook.cjs');
  const env = { ...process.env, ADVISOR_AGENT: 'test', ADVISOR_AUDIT_LOG: path.join(require('node:os').tmpdir(), 'advisor-test-audit.jsonl') };
  const run = (stdin) => spawnSync(process.execPath, [script], { input: stdin, env, encoding: 'utf8' });

  const denied = run(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'mcp_advisor-atlassian_jira_create_issue', tool_input: {} }));
  assert.equal(denied.status, 0);
  const out = JSON.parse(denied.stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');

  const allowed = run(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'mcp_advisor-wiz_discover', tool_input: {} }));
  assert.deepEqual(JSON.parse(allowed.stdout), {});

  const malformed = run('not json');
  assert.equal(malformed.status, 2);
});
