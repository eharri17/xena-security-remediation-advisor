#!/usr/bin/env node
'use strict';

// Live smoke test of the advisor triage workflow against the REAL MCP servers.
// Every tool call is first passed through evaluatePreToolUse (the same policy the VS Code hook enforces).
// Calls the policy denies or asks about are recorded as "blocked locally" and never reach the server.
// Every step is appended to audit/live-smoke.jsonl in the advisor-hook record shape.
//
// Usage: node scripts/live/live-smoke.cjs [--dry-run] [--repo <slug>] [--search <text>]
//          [--wiz] [--wiz-dc <dc>] [--wiz-exec <innerToolName> --wiz-args '<json>']

const fs = require('node:fs');
const path = require('node:path');
const { PROJECT_ROOT, ATLASSIAN_READ_OPS, loadConfig, evaluatePreToolUse, summarizeInput } = require('../hooks/lib/policy.cjs');
const { McpClient, WIZ_MCP_URL, safeSnippet, wizOAuthLogin } = require('./mcp-client.cjs');

const AGENT = 'live-smoke';
const ATLASSIAN_DEFAULTS = {
  url: 'https://atlassian-mcp.xena.dev/mcp/',
  headers: { 'X-Atlassian-Jira-Url': 'https://jira.jnj.com', 'X-Atlassian-Bitbucket-Url': 'https://sourcecode.jnj.com' },
};
const MANIFESTS = ['pom.xml', 'build.gradle', 'package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Dockerfile'];
const CODEOWNERS = ['CODEOWNERS', '.bitbucket/CODEOWNERS', '.github/CODEOWNERS'];
const WRITE_LIKE = /(^|_)(create|update|delete|remove|add|transition|upload|download|save|clone|link|merge|approve|decline|comment|set|worklog)(_|$)/;
const SECRET_HEADER = /(token|authorization|password|secret|cookie|api[_-]?key)/i;

// ---------------------------------------------------------------------------------------------
// Arguments, .env and server configuration

function parseArgs(argv) {
  const opts = { dryRun: false, repo: null, search: 'log4j', wiz: false, wizDc: 'us62', wizExec: null, wizArgs: '{}' };
  const value = (i, flag) => {
    if (i >= argv.length || argv[i].startsWith('--')) throw new Error(`${flag} requires a value.`);
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') opts.dryRun = true;
    else if (a === '--wiz') opts.wiz = true;
    else if (a === '--repo') opts.repo = value(++i, a);
    else if (a === '--search') opts.search = value(++i, a);
    else if (a === '--wiz-dc') opts.wizDc = value(++i, a);
    else if (a === '--wiz-exec') opts.wizExec = value(++i, a);
    else if (a === '--wiz-args') opts.wizArgs = value(++i, a);
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  try {
    opts.wizParams = JSON.parse(opts.wizArgs);
  } catch (err) {
    throw new Error(`--wiz-args must be JSON: ${err.message}`);
  }
  if (opts.wizExec && !opts.wiz) opts.wiz = true;
  return opts;
}

/** Parses KEY=value lines from a .env file. Values are returned to the caller only; never printed. */
function parseEnvFile(file) {
  const out = {};
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return out;
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, '');
    out[m[1]] = v;
  }
  return out;
}

/** Strips // and /* comments and trailing commas from JSONC, respecting string literals. */
function parseJsonc(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2);
      if (i < 0) break;
      i++;
    } else {
      out += c;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
}

/**
 * URL and non-secret headers of the `advisor-atlassian` server from the workspace MCP config.
 * Credential headers in those files are ignored; tokens come only from .env or the environment.
 */
function loadAtlassianServer(root = PROJECT_ROOT) {
  for (const rel of ['.vscode/mcp.json', '.mcp.json']) {
    let cfg;
    try {
      cfg = parseJsonc(fs.readFileSync(path.join(root, rel), 'utf8'));
    } catch {
      continue;
    }
    const server = (cfg.servers || cfg.mcpServers || {})['advisor-atlassian'];
    if (!server?.url) continue;
    const headers = {};
    for (const [k, v] of Object.entries(server.headers || {})) {
      if (!SECRET_HEADER.test(k) && !/\$\{/.test(String(v))) headers[k] = String(v);
    }
    return { source: rel, url: server.url, headers: { ...ATLASSIAN_DEFAULTS.headers, ...headers } };
  }
  return { source: 'built-in defaults', ...ATLASSIAN_DEFAULTS };
}

/** Tools the advisor agents are allowed to use, from `advisor-atlassian/<name>` entries. */
function agentAtlassianTools(root = PROJECT_ROOT) {
  const dir = path.join(root, '.github', 'agents');
  const names = new Set();
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.agent.md'))) {
    for (const m of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/advisor-atlassian\/([a-z0-9_]+)/g)) names.add(m[1]);
  }
  return [...names].sort();
}

// ---------------------------------------------------------------------------------------------
// Step runner: policy gate -> (send) -> audit -> table row

const config = loadConfig();
const sessionId = `live-smoke-${new Date().toISOString().replace(/[:.]/g, '-')}`;
const auditFile = path.resolve(PROJECT_ROOT, process.env.ADVISOR_AUDIT_LOG || 'audit/live-smoke.jsonl');
const rows = [];

function audit(record) {
  try {
    fs.mkdirSync(path.dirname(auditFile), { recursive: true });
    fs.appendFileSync(auditFile, `${JSON.stringify({ ts: new Date().toISOString(), agent: AGENT, session_id: sessionId, ...record })}\n`);
  } catch (err) {
    process.stderr.write(`live-smoke: audit write failed: ${err.message}\n`);
  }
}

const pad = (s, n) => {
  const t = String(s ?? '');
  return t.length > n ? `${t.slice(0, n - 1)}…` : t.padEnd(n);
};

function printHeader(title) {
  console.log(`\n${title}`);
  console.log(`   ${pad('#', 3)} ${pad('step', 34)} ${pad('tool', 30)} ${pad('policy', 6)} ${pad('sent', 4)} ${pad('result', 8)} summary`);
}

function row(r) {
  r.n = rows.length + 1;
  rows.push(r);
  const mark = r.pass === null ? '➖' : r.pass ? '✅' : '❌';
  console.log(`${mark} ${pad(r.n, 3)} ${pad(r.label, 34)} ${pad(r.tool, 30)} ${pad(r.decision, 6)} ${pad(r.sent ? 'yes' : 'no', 4)} ${pad(r.result, 8)} ${String(r.summary || '').slice(0, 400)}`);
  return r;
}

/** Extracts text from a tools/call result and detects tool-level failures. */
function interpret(result) {
  const text = (result?.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
  let data = result?.structuredContent ?? text;
  try {
    data = JSON.parse(text);
  } catch {
    // Plain text result.
  }
  if (result?.isError) return { ok: false, error: safeSnippet(text || 'isError: true', 160), data, chars: text.length };
  if (data && typeof data === 'object' && !Array.isArray(data) && data.success === false) {
    return { ok: false, error: safeSnippet(data.error || data.message || text, 160), data, chars: text.length };
  }
  return { ok: true, data, chars: text.length };
}

/**
 * Runs one tool step.
 *   expect 'pass'  : policy must pass and the live call must succeed.
 *   expect 'block' : policy-only negative check; never sent, must be deny/ask.
 *   expect 'gate'  : sent only if policy passes; either outcome is acceptable.
 *   optional       : a live tool error (e.g. file not found) is reported but is not a failure.
 */
async function step({ label, server, tool, args = {}, expect = 'pass', optional = false, client, dryRun, summarize = () => '' }) {
  const hookTool = `mcp_advisor-${server}_${tool}`;
  const verdict = evaluatePreToolUse({ hook_event_name: 'PreToolUse', tool_name: hookTool, tool_input: args, cwd: PROJECT_ROOT }, config);
  audit({ event: 'PreToolUse', tool: hookTool, tool_use_id: `${sessionId}-${rows.length + 1}`, op: verdict.op, decision: verdict.decision, reason: verdict.reason, input: summarizeInput(args) });
  const base = { label, tool, decision: verdict.decision, sent: false, expect };

  if (verdict.decision !== 'pass') {
    const ok = expect === 'block' || expect === 'gate';
    row({ ...base, pass: ok, result: 'blocked', summary: ok ? verdict.reason : `UNEXPECTED BLOCK: ${verdict.reason}` });
    return { blocked: true };
  }
  if (expect === 'block') {
    row({ ...base, pass: false, result: 'not-sent', summary: `POLICY GAP: expected deny/ask but policy passed (${verdict.reason})` });
    return { blocked: false };
  }
  if (dryRun) {
    row({ ...base, pass: true, result: 'dry-run', summary: verdict.reason });
    return { dryRun: true };
  }
  if (!client) {
    row({ ...base, pass: false, result: 'error', summary: 'not sent: no server connection' });
    return { error: 'no connection' };
  }

  let outcome;
  try {
    outcome = interpret(await client.callTool(tool, args));
  } catch (err) {
    outcome = { ok: false, error: safeSnippet(err.message, 160), chars: 0 };
  }
  audit({ event: 'PostToolUse', tool: hookTool, tool_use_id: `${sessionId}-${rows.length + 1}`, op: verdict.op, input: summarizeInput(args), response_chars: outcome.chars, ok: outcome.ok });
  if (!outcome.ok) {
    row({ ...base, sent: true, pass: optional ? null : false, result: optional ? 'absent' : 'error', summary: outcome.error });
    return outcome;
  }
  let summary;
  try {
    summary = summarize(outcome.data);
  } catch (err) {
    summary = `(could not summarize: ${err.message})`;
  }
  row({ ...base, sent: true, pass: true, result: 'ok', summary });
  return outcome;
}

/** Records a non-tool step (connect, tools/list, OAuth) in the table and audit log. */
function infoRow({ label, tool, pass, result, summary, chars, sent = false }) {
  audit({ event: 'LiveSmokeStep', tool, op: label, decision: 'n/a', reason: summary, input: '{}', response_chars: chars ?? 0 });
  return row({ label, tool, decision: 'n/a', sent, pass, result, summary });
}

// ---------------------------------------------------------------------------------------------
// Atlassian leg

const issuesOf = (d) => (Array.isArray(d?.issues) ? d.issues : []);
const lines = (s) => (s ? String(s).split(/\r?\n/).length : 0);
const contentOf = (d) => (typeof d === 'string' ? d : String(d?.content ?? ''));

async function atlassianLeg(opts) {
  const ws = config.bitbucketProjects[0] || 'ASX-XENA';
  const project = config.jiraProject;
  const keyPrefix = config.jiraProjectKey || project;
  const term = opts.search;
  const jqlTerm = term.replace(/["\\]/g, '\\$&');
  const server = loadAtlassianServer();
  let client = null;

  printHeader(`Atlassian leg (${server.url}, read-only mode; config from ${server.source})`);

  // a. Agent tool coverage (offline) + tools/list (live)
  const required = agentAtlassianTools();
  const uncovered = required.filter((t) => !ATLASSIAN_READ_OPS.has(t));
  infoRow({
    label: 'agent tools on read allowlist',
    tool: '.github/agents',
    pass: uncovered.length === 0,
    result: uncovered.length ? 'error' : 'ok',
    summary: uncovered.length ? `not in ATLASSIAN_READ_OPS: ${uncovered.join(', ')}` : `${required.length} advisor-atlassian tools, all policy-readable`,
  });

  if (opts.dryRun) {
    infoRow({ label: 'initialize + tools/list', tool: 'tools/list', pass: null, result: 'dry-run', summary: 'skipped (no network)' });
  } else {
    const env = { ...parseEnvFile(path.join(PROJECT_ROOT, '.env')), ...pickEnv(['JIRA_PAT', 'BITBUCKET_PAT']) };
    const missing = ['JIRA_PAT', 'BITBUCKET_PAT'].filter((k) => !env[k]);
    if (missing.length) {
      infoRow({ label: 'credentials', tool: '.env', pass: false, result: 'error', summary: `Missing ${missing.join(', ')}: add them to the git-ignored .env (see .env.example) or export them.` });
    } else {
      client = new McpClient({
        url: server.url,
        headers: {
          ...server.headers,
          'X-Atlassian-Jira-Personal-Token': env.JIRA_PAT,
          'X-Atlassian-Bitbucket-Personal-Token': env.BITBUCKET_PAT,
          'X-Atlassian-Read-Only-Mode': 'true',
          'X-Atlassian-Enable-Xray': 'false',
        },
      });
      try {
        await client.initialize();
        const tools = await client.listTools();
        const names = tools.map((t) => t.name);
        const absent = required.filter((t) => !names.includes(t));
        infoRow({
          label: 'tools/list',
          tool: 'tools/list',
          sent: true,
          pass: absent.length === 0,
          result: absent.length ? 'error' : 'ok',
          summary: `${client.serverInfo?.name || 'server'} ${client.serverInfo?.version || ''}: ${names.length} tools; agent tools ${absent.length ? `MISSING ${absent.join(', ')}` : `all ${required.length} present`}`,
          chars: JSON.stringify(tools).length,
        });
        const writeLike = names.filter((n) => {
          const op = n.replace(/^(jira|confluence|bitbucket)_/, '');
          return !/^(get|list|search)_/.test(op) && WRITE_LIKE.test(op);
        });
        const verdicts = writeLike.map((n) => [n, evaluatePreToolUse({ tool_name: `mcp_advisor-atlassian_${n}`, tool_input: {} }, config).decision]);
        const leaks = verdicts.filter(([, d]) => d === 'pass');
        infoRow({
          label: 'write-like tools exposed',
          tool: 'tools/list',
          pass: leaks.length === 0,
          result: leaks.length ? 'error' : 'ok',
          summary: verdicts.length ? verdicts.map(([n, d]) => `${n}=${d}`).join(', ') : 'none',
        });
        const offList = names.filter((n) => !ATLASSIAN_READ_OPS.has(n));
        infoRow({
          label: 'exposed tools not on allowlist',
          tool: 'tools/list',
          pass: true,
          result: 'ok',
          summary: offList.length ? `${offList.length} (policy denies all): ${offList.join(', ')}` : 'none',
        });
      } catch (err) {
        infoRow({ label: 'initialize + tools/list', tool: 'tools/list', sent: true, pass: false, result: 'error', summary: safeSnippet(err.message, 160) });
        client = null;
      }
    }
  }

  // b. Negative checks: policy only, never sent
  const neg = (label, tool, args) => step({ label, server: 'atlassian', tool, args, expect: 'block', dryRun: opts.dryRun });
  await neg('NEG create Jira issue', 'jira_create_issue', { project_key: project, summary: '[live-smoke] must be blocked', issue_type: 'Task' });
  await neg('NEG comment on Jira issue', 'jira_add_comment', { issue_key: `${keyPrefix}-1`, comment: '[live-smoke] must be blocked' });
  await neg('NEG create Bitbucket branch', 'bitbucket_create_branch', { workspace: ws, repository: opts.repo || 'xena-api', branch_name: 'live-smoke/must-be-blocked' });
  await neg('NEG unscoped JQL', 'jira_search', { jql: `text ~ "${jqlTerm}"` });
  await neg('NEG cross-project JQL', 'jira_search', { jql: `project in (${project}, OTHER) AND text ~ "${jqlTerm}"` });
  await neg('NEG list every Bitbucket repo', 'bitbucket_list_repositories', {});

  // c. Live reads
  const read = (label, tool, args, extra = {}) => step({ label, server: 'atlassian', tool, args, client, dryRun: opts.dryRun, ...extra });

  const search = await read(`Jira search "${term}"`, 'jira_search', {
    jql: `project = ${project} AND text ~ "\\"${jqlTerm}\\"" ORDER BY updated DESC`,
    fields: 'summary,status,assignee,components,labels,resolution,created',
    limit: 5,
  }, { summarize: (d) => `total ${d?.total ?? issuesOf(d).length}; ${issuesOf(d).map((i) => `${i.key} [${i.status?.name || '?'}]`).join(', ') || 'no matches'}` });

  let issueKey = issuesOf(search.data)[0]?.key;
  if (!issueKey && search.ok) {
    const latest = await read('Jira latest issue (fallback)', 'jira_search', { jql: `project = ${project} ORDER BY updated DESC`, fields: 'summary,status', limit: 1 }, {
      summarize: (d) => issuesOf(d).map((i) => i.key).join(', ') || 'no issues',
    });
    issueKey = issuesOf(latest.data)[0]?.key;
  }
  if (opts.dryRun) issueKey = `${keyPrefix}-1`;
  if (issueKey) {
    await read(`Jira get issue ${issueKey}`, 'jira_get_issue', { issue_key: issueKey, fields: 'summary,status,assignee,components,labels,resolution', comment_limit: 0, update_history: false }, {
      summarize: (d) => `${d?.key || issueKey}: status ${d?.status?.name || '?'}; assignee ${d?.assignee?.display_name || d?.assignee?.name || 'Unassigned'}`,
    });
  } else {
    row({ label: 'Jira get issue', tool: 'jira_get_issue', decision: '-', sent: false, pass: false, result: 'error', summary: `no ${keyPrefix} issue key available` });
  }

  const repos = await read(`Bitbucket list repos (${ws})`, 'bitbucket_list_repositories', { workspace: ws }, {
    summarize: (d) => `${Array.isArray(d) ? d.length : 0} repos; first: ${(Array.isArray(d) ? d.slice(0, 3).map((r) => r.slug) : []).join(', ')}`,
  });
  const slugs = Array.isArray(repos.data) ? repos.data.map((r) => r.slug) : [];
  let repo = opts.repo || slugs[0];
  if (opts.dryRun) repo = opts.repo || 'xena-api';
  if (!repo) {
    row({ label: 'choose repository', tool: '-', decision: '-', sent: false, pass: false, result: 'error', summary: `no repositories returned for ${ws}` });
    return;
  }
  if (!opts.dryRun && opts.repo && repos.ok && !slugs.includes(opts.repo)) {
    row({ label: 'choose repository', tool: '-', decision: '-', sent: false, pass: false, result: 'error', summary: `--repo ${opts.repo} is not in ${ws}` });
    return;
  }
  infoRow({ label: 'choose repository', tool: '-', pass: null, result: opts.dryRun ? 'dry-run' : 'ok', summary: `${ws}/${repo}${opts.repo ? ' (--repo)' : opts.dryRun ? ' (placeholder)' : ' (first listed)'}` });

  const rb = { workspace: ws, repository: repo };
  const branch = await read('default branch', 'bitbucket_get_default_branch', rb, { summarize: (d) => `${d?.name || d?.display_id || '?'} @ ${String(d?.latest_commit || '').slice(0, 11)}` });
  const branchName = branch.data?.name || branch.data?.display_id || 'main';

  const listing = await read('list directory (root)', 'bitbucket_list_directory', { ...rb, branch: branchName }, {
    summarize: (d) => {
      const files = Array.isArray(d) ? d.map(String) : [];
      const root = files.filter((f) => !f.includes('/'));
      return `${files.length} paths, ${root.length} at root; manifests: ${MANIFESTS.filter((m) => root.includes(m)).join(', ') || 'none'}`;
    },
  });
  await read('open pull requests', 'bitbucket_list_pull_requests', { ...rb, state: 'OPEN' }, {
    summarize: (d) => `${Array.isArray(d) ? d.length : 0} open; ${(Array.isArray(d) ? d.slice(0, 3).map((p) => `#${p.id}`) : []).join(' ')}`,
  });
  await read('recent commits (limit 5)', 'bitbucket_get_commits', { ...rb, limit: 5 }, {
    summarize: (d) => {
      const n = Array.isArray(d) ? d.length : 0;
      const latest = Array.isArray(d) && d[0] ? `latest ${String(d[0].id_ || d[0].id || d[0].displayId || '').slice(0, 11)}` : '';
      return `${n} returned${n > 5 ? ' (server ignored limit=5)' : ''}; ${latest}`;
    },
  });

  const files = Array.isArray(listing.data) ? listing.data.map(String) : [];
  const manifest = opts.dryRun ? 'pom.xml' : MANIFESTS.find((m) => files.includes(m));
  if (manifest) {
    const termRe = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    await read(`manifest ${manifest}`, 'bitbucket_get_file_content', { ...rb, file_path: manifest, branch: branchName }, {
      summarize: (d) => {
        const body = contentOf(d);
        return `${manifest}: ${lines(body)} lines, ${body.split(/\r?\n/).filter((l) => termRe.test(l)).length} mention "${term}"`;
      },
    });
  } else {
    row({ label: 'manifest', tool: 'bitbucket_get_file_content', decision: '-', sent: false, pass: null, result: 'skip', summary: `no known manifest at root of ${repo} (${MANIFESTS.join(', ')}); try --repo` });
  }

  for (const candidate of CODEOWNERS) {
    const r = await read(`CODEOWNERS ${candidate}`, 'bitbucket_get_file_content', { ...rb, file_path: candidate, branch: branchName }, {
      optional: true,
      summarize: (d) => `${candidate}: ${lines(contentOf(d))} lines`,
    });
    if (r.ok || r.dryRun || r.blocked) break;
  }
}

function pickEnv(keys) {
  return Object.fromEntries(keys.filter((k) => process.env[k]).map((k) => [k, process.env[k]]));
}

// ---------------------------------------------------------------------------------------------
// Wiz leg

/** Builds a read-only discover call from the server's input schema. */
function discoverArgs(schema = {}) {
  const props = schema.properties || {};
  const required = new Set(schema.required || []);
  const args = {};
  for (const [name, def] of Object.entries(props)) {
    const choices = def.enum || def.anyOf?.flatMap((a) => a.enum || []) || [];
    if (/domain/i.test(name)) {
      args[name] = choices.find((c) => /^issues?$/i.test(c)) || choices.find((c) => /issue/i.test(c)) || 'issues';
    } else if (/query|search|question|prompt|intent|text|task/i.test(name)) {
      args[name] = 'list open critical issues';
    } else if (required.has(name) && (def.type === 'string' || !def.type)) {
      args[name] = 'issues';
    }
  }
  return args;
}

async function wizLeg(opts) {
  printHeader(`Wiz leg (${WIZ_MCP_URL}, data center ${opts.wizDc})`);
  let client = null;
  let discoverSchema = {};

  if (opts.dryRun) {
    infoRow({ label: 'OAuth sign-in (read:all)', tool: 'oauth', pass: null, result: 'dry-run', summary: 'skipped (no network)' });
  } else {
    try {
      const token = await wizOAuthLogin({ log: (m) => console.log(`   ${m}`) });
      const granted = String(token.scope || '').split(/\s+/).filter(Boolean);
      const extra = granted.filter((s) => s !== 'read:all' && s !== 'offline_access');
      infoRow({
        label: 'OAuth sign-in (read:all)',
        tool: 'oauth',
        sent: true,
        pass: extra.length === 0,
        result: extra.length ? 'error' : 'ok',
        summary: `granted scope: ${granted.join(' ') || '(not reported)'}${extra.length ? ` - UNEXPECTED ${extra.join(' ')}` : ''}; expires in ${token.expiresIn ?? '?'}s`,
      });
      if (extra.length === 0) {
        client = new McpClient({ url: WIZ_MCP_URL, headers: { Authorization: `${token.tokenType === 'bearer' ? 'Bearer' : token.tokenType} ${token.accessToken}`, 'Wiz-DataCenter': opts.wizDc } });
        await client.initialize();
        const tools = await client.listTools();
        discoverSchema = tools.find((t) => t.name === 'discover')?.inputSchema || {};
        infoRow({
          label: 'tools/list',
          tool: 'tools/list',
          sent: true,
          pass: tools.some((t) => t.name === 'discover'),
          result: 'ok',
          summary: tools.map((t) => `${t.name}(${Object.keys(t.inputSchema?.properties || {}).join(', ')})`).join('; '),
          chars: JSON.stringify(tools).length,
        });
      }
    } catch (err) {
      infoRow({ label: 'OAuth / connect', tool: 'oauth', pass: false, result: 'error', summary: safeSnippet(err.message, 160) });
      client = null;
    }
  }

  const dArgs = opts.dryRun ? { domain: 'issues' } : discoverArgs(discoverSchema);
  await step({
    label: 'discover',
    server: 'wiz',
    tool: 'discover',
    args: dArgs,
    client,
    dryRun: opts.dryRun,
    summarize: (d) => {
      if (Array.isArray(d)) return `${d.length} entries: ${d.slice(0, 6).map((x) => x?.name || x?.tool_name || '?').join(', ')}`;
      if (d && typeof d === 'object') return `keys: ${Object.keys(d).slice(0, 8).join(', ')}`;
      return `${String(d).length} chars of text`;
    },
  });
  await step({ label: 'NEG execute update_issue_status', server: 'wiz', tool: 'execute', args: { tool_name: 'update_issue_status', parameters: { id: 'live-smoke', status: 'RESOLVED' } }, expect: 'block', dryRun: opts.dryRun });

  if (opts.wizExec) {
    await step({
      label: `execute ${opts.wizExec}`,
      server: 'wiz',
      tool: 'execute',
      args: { tool_name: opts.wizExec, parameters: opts.wizParams },
      expect: 'gate',
      client,
      dryRun: opts.dryRun,
      summarize: (d) => (Array.isArray(d) ? `${d.length} items` : d && typeof d === 'object' ? `keys: ${Object.keys(d).slice(0, 8).join(', ')}` : `${String(d).length} chars of text`),
    });
  }
}

// ---------------------------------------------------------------------------------------------

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`live-smoke: ${err.message}`);
    process.exit(2);
  }
  if (opts.help) {
    console.log('Usage: node scripts/live/live-smoke.cjs [--dry-run] [--repo <slug>] [--search <text>] [--wiz] [--wiz-dc <dc>] [--wiz-exec <tool> --wiz-args <json>]');
    return;
  }
  if (opts.dryRun) {
    // Guarantee --dry-run cannot reach any server, even by mistake.
    globalThis.fetch = () => Promise.reject(new Error('network is disabled in --dry-run'));
  }

  console.log(`XENA Security Remediation Advisor: live smoke test${opts.dryRun ? ' (DRY RUN, no network)' : ''}`);
  console.log(`Scope: Jira ${config.jiraProject} (keys ${config.jiraProjectKey || config.jiraProject}-<n>), Bitbucket ${config.bitbucketProjects.join(', ')}. Blocked steps never reach the server.`);
  audit({ event: 'SessionStart', op: opts.dryRun ? 'dry-run' : 'live', input: summarizeInput({ repo: opts.repo, search: opts.search, wiz: opts.wiz, wizDc: opts.wizDc, wizExec: opts.wizExec }) });

  await atlassianLeg(opts);
  if (opts.wiz) await wizLeg(opts);

  const counted = rows.filter((r) => r.pass !== null);
  const failed = counted.filter((r) => !r.pass);
  const blocked = rows.filter((r) => r.result === 'blocked').length;
  const sent = rows.filter((r) => r.sent && r.tool !== 'tools/list' && r.tool !== 'oauth').length;
  console.log(`\n${failed.length ? 'FAIL' : 'PASS'}: ${counted.length - failed.length} passed, ${failed.length} failed, ${rows.length - counted.length} informational/skipped; ${sent} tool calls sent, ${blocked} blocked locally.`);
  console.log(`Audit trail: ${path.relative(PROJECT_ROOT, auditFile) || auditFile}`);
  audit({ event: 'Stop', op: failed.length ? 'FAIL' : 'PASS', reason: `${counted.length - failed.length} passed, ${failed.length} failed`, input: '{}' });
  process.exitCode = failed.length ? 1 : 0;
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`live-smoke: ${safeSnippet(err.stack || err.message, 600)}`);
    process.exit(1);
  });
}

module.exports = { parseArgs, parseEnvFile, parseJsonc, loadAtlassianServer, agentAtlassianTools, discoverArgs, interpret };
