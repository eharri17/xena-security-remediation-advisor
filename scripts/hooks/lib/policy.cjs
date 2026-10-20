'use strict';

// Least-privilege policy for the XENA Security Remediation Advisor.
// Pure functions only, so the policy can be unit tested without VS Code.

const fs = require('node:fs');
const path = require('node:path');

const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');

function loadConfig(root = PROJECT_ROOT) {
  const defaults = { jiraProject: 'JIFA', bitbucketProjects: [], draftsDir: 'drafts', auditLog: 'audit/audit-log.jsonl' };
  try {
    return { ...defaults, ...JSON.parse(fs.readFileSync(path.join(root, 'config', 'advisor.config.json'), 'utf8')) };
  } catch {
    return defaults;
  }
}

// Read-only operations of the Atlassian MCP server (github.com/SharkyND/mcp-atlassian).
// Attachment download/save tools are excluded because they write to disk.
const ATLASSIAN_READ_OPS = new Set([
  'jira_search',
  'jira_get_issue',
  'jira_get_project_issues',
  'jira_batch_get_changelogs',
  'jira_get_issue_related_pull_requests',
  'jira_search_fields',
  'jira_get_user_profile',
  'jira_get_all_projects',
  'jira_get_link_types',
  'jira_get_transitions',
  'jira_get_worklog',
  'jira_get_agile_boards',
  'jira_get_board_issues',
  'jira_get_sprint_issues',
  'jira_get_sprints_from_board',
  'jira_get_project_versions',
  'confluence_search',
  'confluence_get_page',
  'confluence_get_page_children',
  'confluence_get_comments',
  'confluence_get_labels',
  'confluence_search_user',
  'bitbucket_get_file_content',
  'bitbucket_get_repository_info',
  'bitbucket_list_repositories',
  'bitbucket_list_directory',
  'bitbucket_list_branches',
  'bitbucket_get_default_branch',
  'bitbucket_get_commits',
  'bitbucket_get_commit_changes',
  'bitbucket_get_commit_builds',
  'bitbucket_list_workspaces_or_projects',
  'bitbucket_list_pull_requests',
  'bitbucket_get_pull_request',
  'bitbucket_get_pull_request_commits',
  'bitbucket_get_pull_request_diff',
]);

// The remote Wiz MCP server (mcp.app.wiz.io) exposes two meta-tools: `discover` (read-only)
// and `execute`, which runs any Wiz tool by name. `execute` is classified by the inner tool name.
const WIZ_READ_PREFIX = /^(get|list|search|query|find|describe|count|fetch|lookup|read|show|explain|summari[sz]e|trace)(_|$)/i;
const WIZ_WRITE_VERB = /(^|_)(create|update|delete|remove|set|resolve|reject|reopen|close|assign|unassign|add|patch|put|post|modify|mute|ignore|dismiss|remediate|enable|disable|write|upload|import|tag|untag|comment|link|unlink|acknowledge|snooze|approve)(_|$)/i;

const FILE_WRITE_TOOLS = /^(create_file|create_directory|replace_string_in_file|multi_replace_string_in_file|insert_edit_into_file|apply_patch|edit_file|edit_files|write_file|edit_notebook_file|rename_file|delete_file)$/i;
const SHELL_TOOLS = /^(run_in_terminal|run_task|create_and_run_task|run_vscode_command|bash|shell|terminal)$/i;

function toolBaseName(toolName) {
  return String(toolName || '').trim().toLowerCase();
}

/** Returns the Atlassian operation (e.g. "jira_search") embedded in a tool name, or null. */
function atlassianOp(toolName) {
  const m = toolBaseName(toolName).match(/(?:^|[^a-z])((?:jira|confluence|bitbucket)_[a-z0-9_]+)$/);
  return m ? m[1] : null;
}

function isWizTool(toolName, suffix) {
  const n = toolBaseName(toolName);
  return n.includes('wiz') && new RegExp(`(^|[_/.-])${suffix}$`).test(n);
}

function classifyWizOperation(op) {
  const name = String(op || '').trim();
  if (!name) return { decision: 'deny', reason: 'Wiz execute call without a tool_name is not allowed.' };
  if (WIZ_WRITE_VERB.test(name)) {
    return { decision: 'deny', reason: `Wiz operation "${name}" looks like a write. The advisor is read-only (PoC scope).` };
  }
  if (WIZ_READ_PREFIX.test(name)) {
    return { decision: 'pass', reason: `Read-only Wiz operation "${name}".` };
  }
  return { decision: 'ask', reason: `Wiz operation "${name}" is not on the read-only allowlist. Confirm it does not modify Wiz.` };
}

/**
 * Splits JQL into its top-level AND conditions, ignoring ORDER BY, quoted text, and anything in
 * parentheses. Returns null for a top-level OR (`OR` / `||`) or malformed JQL, since either could
 * widen the result set beyond a single project condition.
 */
function topLevelJqlConditions(jql) {
  const text = String(jql || '');
  let masked = '';
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && i + 1 < text.length) {
        masked += '  ';
        i++;
        continue;
      }
      if (c === quote) quote = null;
      masked += ' ';
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      masked += ' ';
      continue;
    }
    if (c === '(') depth++;
    const topLevel = depth === 0;
    if (c === ')' && --depth < 0) return null;
    masked += topLevel ? c : ' ';
  }
  if (quote || depth !== 0) return null;
  const orderBy = masked.search(/\border\s+by\b/i);
  const end = orderBy >= 0 ? orderBy : masked.length;
  const head = masked.slice(0, end);
  if (/\bor\b|\|\|/i.test(head)) return null;
  const conditions = [];
  const sep = /\band\b|&&/gi;
  let start = 0;
  for (let m = sep.exec(head); m; m = sep.exec(head)) {
    conditions.push(text.slice(start, m.index).trim());
    start = m.index + m[0].length;
  }
  conditions.push(text.slice(start, end).trim());
  return conditions;
}

/** True when a JQL condition selects exactly one of `ids`: `project = X` or `project in (X)`. */
function isSingleProjectCondition(condition, ids) {
  const m = String(condition).match(/^project\s*(=|in)\s*(.+)$/i);
  if (!m) return false;
  let value = m[2].trim();
  if (m[1].toLowerCase() === 'in') {
    if (!/^\(.*\)$/.test(value)) return false;
    value = value.slice(1, -1).trim();
  }
  value = value.replace(/^(["'])(.*)\1$/, '$2');
  return ids.includes(value.toUpperCase());
}

/**
 * Enforces the single-Jira-project scope from the use case (one BU, one project).
 * `project` is the name or key used in JQL; `projectKey` is the issue-key prefix, which can
 * differ from the name (e.g. a project named "PLATFORM" with key "PLAT"). JQL may reference either.
 */
function checkJiraScope(op, input, project, projectKey = project) {
  const name = String(project || '').toUpperCase();
  const key = String(projectKey || name).toUpperCase();
  if (!name && !key) return null;
  if (op === 'jira_search') {
    const jql = String(input?.jql || '');
    const ids = [...new Set([name, key].filter(Boolean))];
    const conditions = topLevelJqlConditions(jql);
    if (!conditions || !conditions.some((c) => isSingleProjectCondition(c, ids))) {
      return {
        decision: 'deny',
        reason: `JQL must be limited to the single PoC project: include "project = ${name || key}" as a top-level AND condition, with no top-level OR and no other projects. Got: ${jql || '(empty)'}`,
      };
    }
    const filter = String(input?.projects_filter || '').trim();
    const outside = filter ? filter.split(',').map((p) => p.trim().toUpperCase()).filter((p) => p && !ids.includes(p)) : [];
    if (outside.length) {
      return { decision: 'deny', reason: `projects_filter may only name ${ids.join(' or ')} (got "${filter}").` };
    }
  }
  if (op === 'jira_get_project_issues') {
    const p = String(input?.project_key || '').toUpperCase();
    if (p !== key && p !== name) return { decision: 'deny', reason: `Only Jira project ${name || key} (key ${key}) is in scope (got "${p}").` };
  }
  if (op === 'jira_get_issue' || op === 'jira_get_issue_related_pull_requests') {
    const k = String(input?.issue_key || '').toUpperCase();
    if (k && !k.startsWith(`${key}-`)) {
      return { decision: 'ask', reason: `Issue ${k} is outside the PoC project ${key}. Confirm cross-project read.` };
    }
  }
  if (op === 'jira_batch_get_changelogs') {
    const keys = [].concat(input?.issue_ids_or_keys || []).map((k) => String(k).toUpperCase());
    const outside = keys.filter((k) => /^[A-Z][A-Z0-9]+-\d+$/.test(k) && !k.startsWith(`${key}-`));
    if (outside.length) return { decision: 'ask', reason: `Issues outside ${key}: ${outside.join(', ')}. Confirm cross-project read.` };
  }
  return null;
}

/** Keeps Bitbucket reads inside the configured project(s); other projects require confirmation. */
function checkBitbucketScope(op, input, projects) {
  const allowed = [].concat(projects || []).map((p) => String(p).toUpperCase());
  if (!allowed.length || op === 'bitbucket_list_workspaces_or_projects') return null;
  const ws = String(input?.workspace || '').trim();
  if (!ws) {
    if (op === 'bitbucket_list_repositories') {
      return { decision: 'ask', reason: `Listing all accessible repositories is outside the PoC scope. Pass workspace = ${allowed.join(' or ')} instead.` };
    }
    return null;
  }
  if (!allowed.includes(ws.toUpperCase())) {
    return { decision: 'ask', reason: `Bitbucket project "${ws}" is outside the PoC scope (${allowed.join(', ')}). Confirm the cross-project read.` };
  }
  return null;
}

function collectPaths(toolInput) {
  const found = [];
  const visit = (value, key) => {
    if (typeof value === 'string') {
      if (/(^|[^a-z])(path|paths|filepath|file|uri|dirpath|newpath|oldpath)$/i.test(key || '')) found.push(value);
      if (key === 'input' || key === 'patch') {
        for (const m of value.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)) found.push(m[1].trim());
        for (const m of value.matchAll(/^\*\*\* Move to: (.+)$/gm)) found.push(m[1].trim());
      }
    } else if (Array.isArray(value)) {
      value.forEach((v) => visit(v, key));
    } else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) visit(v, k);
    }
  };
  visit(toolInput, '');
  return found.map((p) => p.replace(/^file:\/\//, ''));
}

function isInsideDir(p, dir, cwd) {
  const abs = path.resolve(cwd || PROJECT_ROOT, p);
  const rel = path.relative(dir, abs);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Evaluates a PreToolUse event.
 * Returns { decision: 'pass' | 'ask' | 'deny', reason, category, op }.
 * 'pass' means "no objection", so VS Code's normal confirmation flow still applies.
 */
function evaluatePreToolUse(event, config = loadConfig()) {
  const toolName = String(event?.tool_name || '');
  const input = event?.tool_input || {};

  if (isWizTool(toolName, 'execute')) {
    const op = input.tool_name;
    return { ...classifyWizOperation(op), category: 'wiz', op };
  }
  if (isWizTool(toolName, 'discover')) {
    return { decision: 'pass', reason: 'Wiz discover is read-only.', category: 'wiz', op: 'discover' };
  }

  const aOp = atlassianOp(toolName);
  if (aOp) {
    if (!ATLASSIAN_READ_OPS.has(aOp)) {
      return {
        decision: 'deny',
        reason: `Atlassian operation "${aOp}" is blocked. The advisor drafts tickets for human review and never writes to Jira, Confluence, or Bitbucket.`,
        category: 'atlassian',
        op: aOp,
      };
    }
    const scope = aOp.startsWith('bitbucket_')
      ? checkBitbucketScope(aOp, input, config.bitbucketProjects)
      : checkJiraScope(aOp, input, config.jiraProject, config.jiraProjectKey);
    if (scope) return { ...scope, category: 'atlassian', op: aOp };
    return { decision: 'pass', reason: `Read-only Atlassian operation "${aOp}".`, category: 'atlassian', op: aOp };
  }

  if (FILE_WRITE_TOOLS.test(toolName)) {
    const draftsDir = path.join(PROJECT_ROOT, config.draftsDir || 'drafts');
    const paths = collectPaths(input);
    if (paths.length === 0) {
      return { decision: 'ask', reason: `File write via "${toolName}" without a detectable path. Confirm the target is under drafts/.`, category: 'file' };
    }
    const outside = paths.filter((p) => !isInsideDir(p, draftsDir, event?.cwd));
    if (outside.length > 0) {
      return { decision: 'deny', reason: `The advisor may only write ticket drafts under drafts/. Blocked: ${outside.join(', ')}`, category: 'file' };
    }
    return { decision: 'pass', reason: 'Write targets drafts/.', category: 'file' };
  }

  if (SHELL_TOOLS.test(toolName)) {
    return { decision: 'deny', reason: 'Shell and command execution are not permitted for the Security Remediation Advisor.', category: 'shell' };
  }

  return { decision: 'pass', reason: 'Not governed by advisor policy.', category: 'other' };
}

const SENSITIVE_KEY = /(token|secret|password|authorization|cookie|api[_-]?key|credential)/i;

/** Compact, redacted summary of tool input for the audit trail. */
function summarizeInput(input, maxLen = 500) {
  const redact = (value, depth = 0) => {
    if (depth > 4) return '[…]';
    if (Array.isArray(value)) return value.slice(0, 10).map((v) => redact(v, depth + 1));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redact(v, depth + 1);
      return out;
    }
    if (typeof value === 'string' && value.length > 200) return `${value.slice(0, 200)}…`;
    return value;
  };
  const text = JSON.stringify(redact(input ?? {}));
  return text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;
}

module.exports = {
  PROJECT_ROOT,
  ATLASSIAN_READ_OPS,
  loadConfig,
  atlassianOp,
  classifyWizOperation,
  checkJiraScope,
  checkBitbucketScope,
  collectPaths,
  isInsideDir,
  evaluatePreToolUse,
  summarizeInput,
};
