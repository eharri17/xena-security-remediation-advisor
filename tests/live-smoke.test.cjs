'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { PROJECT_ROOT, loadConfig } = require('../scripts/hooks/lib/policy.cjs');
const { parseMcpBody, safeSnippet } = require('../scripts/live/mcp-client.cjs');
const { parseJsonc, parseEnvFile, discoverArgs, interpret, agentAtlassianTools } = require('../scripts/live/live-smoke.cjs');

const config = loadConfig();
const project = config.jiraProject;
const keyPrefix = config.jiraProjectKey || project;
const script = path.join(PROJECT_ROOT, 'scripts', 'live', 'live-smoke.cjs');
const scratch = path.join(__dirname, `.live-smoke-test-${process.pid}`);

test.before(() => fs.mkdirSync(scratch, { recursive: true }));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

/** Runs the scenario in --dry-run mode and returns the console output and audit records. */
function dryRun(name, extraArgs = []) {
  const auditLog = path.join(scratch, `${name}.jsonl`);
  const env = { ...process.env, ADVISOR_AUDIT_LOG: auditLog, JIRA_PAT: '', BITBUCKET_PAT: '' };
  const res = spawnSync(process.execPath, [script, '--dry-run', ...extraArgs], { env, encoding: 'utf8', timeout: 30000 });
  const records = fs.readFileSync(auditLog, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const pre = records.filter((r) => r.event === 'PreToolUse').map((r) => ({ ...r, args: JSON.parse(r.input) }));
  return { res, records, pre };
}

const find = (pre, op, predicate = () => true) => pre.filter((r) => r.op === op && predicate(r.args));

test('dry run blocks every negative step locally and sends nothing', () => {
  const { res, records, pre } = dryRun('atlassian');
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /PASS: \d+ passed, 0 failed/);
  assert.match(res.stdout, /0 tool calls sent/);
  assert.equal(records.filter((r) => r.event === 'PostToolUse').length, 0, 'nothing may be sent in --dry-run');
  assert.ok(records.every((r) => r.agent === 'live-smoke' && r.ts));

  assert.equal(find(pre, 'jira_create_issue')[0].decision, 'deny');
  assert.equal(find(pre, 'jira_add_comment')[0].decision, 'deny');
  assert.equal(find(pre, 'bitbucket_create_branch')[0].decision, 'deny');
  assert.equal(find(pre, 'jira_search', (a) => /^text ~/.test(a.jql))[0].decision, 'deny');
  assert.equal(find(pre, 'jira_search', (a) => a.jql.startsWith(`project in (${project}, OTHER) `))[0].decision, 'deny');
  assert.equal(find(pre, 'bitbucket_list_repositories', (a) => !a.workspace)[0].decision, 'ask');
});

test('dry run passes every live read, including jira_get_issue on a configured-project key', () => {
  const { pre } = dryRun('reads', ['--search', 'CVE-2021-44228', '--repo', 'xena-api']);
  const search = find(pre, 'jira_search', (a) => a.jql.startsWith(`project = ${project} AND text ~ "\\"CVE-2021-44228\\""`));
  assert.equal(search.length, 1);
  assert.equal(search[0].decision, 'pass');
  assert.equal(search[0].args.limit, 5);

  const getIssue = find(pre, 'jira_get_issue');
  assert.equal(getIssue.length, 1);
  assert.match(getIssue[0].args.issue_key, new RegExp(`^${keyPrefix}-\\d+$`));
  assert.equal(project, 'JIFA');
  assert.equal(getIssue[0].decision, 'pass');
  assert.equal(getIssue[0].args.update_history, false);

  assert.equal(find(pre, 'bitbucket_list_repositories', (a) => a.workspace === 'ASX-XENA')[0].decision, 'pass');
  for (const op of ['bitbucket_get_default_branch', 'bitbucket_list_directory', 'bitbucket_list_pull_requests', 'bitbucket_get_commits', 'bitbucket_get_file_content']) {
    const calls = find(pre, op);
    assert.ok(calls.length >= 1, op);
    for (const c of calls) {
      assert.equal(c.decision, 'pass', op);
      assert.equal(c.args.workspace, 'ASX-XENA', op);
      assert.equal(c.args.repository, 'xena-api', op);
    }
  }
});

test('dry run Wiz leg: discover passes, write execute is denied, optional execute is gated', () => {
  const read = dryRun('wiz-read', ['--wiz', '--wiz-exec', 'list_issues', '--wiz-args', '{"severity":"CRITICAL"}']);
  assert.equal(read.res.status, 0, read.res.stdout + read.res.stderr);
  assert.equal(find(read.pre, 'discover')[0].decision, 'pass');
  assert.equal(find(read.pre, 'update_issue_status')[0].decision, 'deny');
  assert.equal(find(read.pre, 'list_issues')[0].decision, 'pass');

  const write = dryRun('wiz-write', ['--wiz-exec', 'resolve_issue']);
  assert.equal(write.res.status, 0, write.res.stdout + write.res.stderr);
  assert.equal(find(write.pre, 'resolve_issue')[0].decision, 'deny');
  assert.match(write.res.stdout, /execute resolve_issue\s+execute\s+deny\s+no\s+blocked/);
});

test('rejects unknown flags and invalid --wiz-args', () => {
  const env = { ...process.env, ADVISOR_AUDIT_LOG: path.join(scratch, 'flags.jsonl') };
  assert.equal(spawnSync(process.execPath, [script, '--dry-run', '--bogus'], { env, encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [script, '--dry-run', '--wiz-exec', 'get_issue', '--wiz-args', '{nope'], { env, encoding: 'utf8' }).status, 2);
});

test('MCP client parses JSON and SSE bodies', () => {
  assert.deepEqual(parseMcpBody('{"jsonrpc":"2.0","id":1,"result":{}}', 'application/json'), [{ jsonrpc: '2.0', id: 1, result: {} }]);
  const sse = 'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\nevent: message\ndata: {"jsonrpc":"2.0","id":2,\ndata: "result":{"ok":true}}\n\n';
  const msgs = parseMcpBody(sse, 'text/event-stream');
  assert.equal(msgs.length, 2);
  assert.deepEqual(msgs[1], { jsonrpc: '2.0', id: 2, result: { ok: true } });
  assert.ok(!safeSnippet('Authorization: Bearer abc.def-123 failed').includes('abc.def'));
  assert.ok(!safeSnippet('{"access_token":"s3cr3t"}').includes('s3cr3t'));
});

test('tool results with isError or success:false are failures', () => {
  assert.equal(interpret({ content: [{ type: 'text', text: '[1,2]' }] }).ok, true);
  assert.equal(interpret({ isError: true, content: [{ type: 'text', text: 'HTTP 401 Unauthorized' }] }).error, 'HTTP 401 Unauthorized');
  const r = interpret({ content: [{ type: 'text', text: '{"success":false,"error":"401 Client Error"}' }] });
  assert.equal(r.ok, false);
  assert.equal(r.error, '401 Client Error');
});

test('helpers: JSONC, .env parsing, discover args, agent tool list', () => {
  assert.deepEqual(parseJsonc('{\n // c\n "url": "https://x.io//a", /* b */ "h": [1,],\n}'), { url: 'https://x.io//a', h: [1] });
  const envFile = path.join(scratch, 'sample.env');
  fs.writeFileSync(envFile, '# comment\nJIRA_PAT=abc\nexport BITBUCKET_PAT="d e f"\nEMPTY=\n');
  assert.deepEqual(parseEnvFile(envFile), { JIRA_PAT: 'abc', BITBUCKET_PAT: 'd e f', EMPTY: '' });
  assert.deepEqual(discoverArgs({ properties: { domain: { type: 'string' } } }), { domain: 'issues' });
  assert.deepEqual(discoverArgs({ properties: { query: { type: 'string' } }, required: ['query'] }), { query: 'list open critical issues' });
  assert.ok(agentAtlassianTools().includes('jira_search'));
});
