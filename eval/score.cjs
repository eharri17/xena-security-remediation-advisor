#!/usr/bin/env node
'use strict';

// Computes PoC success metrics from eval/scorecard.csv:
//   repository accuracy, owner accuracy, priority accuracy, duplicate accuracy,
//   % drafts accepted without rework, and triage time per finding (baseline -> agent).
// Usage: node eval/score.cjs [path/to/scorecard.csv]

const fs = require('node:fs');
const path = require('node:path');

function parseCsv(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/).filter((l) => l.trim())) {
    const cells = [];
    let cur = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"' && line[i + 1] === '"' && quoted) { cur += '"'; i++; }
      else if (c === '"') quoted = !quoted;
      else if (c === ',' && !quoted) { cells.push(cur); cur = ''; }
      else cur += c;
    }
    cells.push(cur);
    rows.push(cells.map((s) => s.trim()));
  }
  const [header, ...data] = rows;
  return data.map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ''])));
}

const norm = (s) => String(s || '').trim().toLowerCase();
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(0)}% (${n}/${d})` : 'n/a (0 scored)');
const avg = (xs) => (xs.length ? (xs.reduce((a, b) => a + b, 0) / xs.length).toFixed(1) : 'n/a');

function score(rows) {
  const scored = rows.filter((r) => r.agent_repository || r.agent_owner || r.agent_priority || r.agent_duplicate);
  const match = (field) => {
    const rs = scored.filter((r) => r[`agent_${field}`]);
    return [rs.filter((r) => norm(r[`agent_${field}`]) === norm(r[`expected_${field}`])).length, rs.length];
  };
  const accepted = scored.filter((r) => r.accepted_without_rework);
  const manual = rows.map((r) => Number(r.manual_triage_minutes)).filter((n) => n > 0);
  const agentTimes = rows.map((r) => Number(r.agent_triage_minutes)).filter((n) => n > 0);
  return {
    findings: rows.length,
    scored: scored.length,
    repositoryAccuracy: pct(...match('repository')),
    ownerAccuracy: pct(...match('owner')),
    priorityAccuracy: pct(...match('priority')),
    duplicateAccuracy: pct(...match('duplicate')),
    acceptedWithoutRework: pct(accepted.filter((r) => /^(y|yes|true|1)$/i.test(r.accepted_without_rework)).length, accepted.length),
    triageMinutes: `${avg(manual)} manual -> ${avg(agentTimes)} with agent`,
  };
}

if (require.main === module) {
  const file = process.argv[2] || path.join(__dirname, 'scorecard.csv');
  const result = score(parseCsv(fs.readFileSync(file, 'utf8')));
  console.log('XENA Security Remediation Advisor - PoC scorecard');
  for (const [k, v] of Object.entries(result)) console.log(`  ${k.padEnd(22)} ${v}`);
}

module.exports = { parseCsv, score };
