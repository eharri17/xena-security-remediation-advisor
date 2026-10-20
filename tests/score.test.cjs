'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCsv, score } = require('../eval/score.cjs');

test('scorecard computes accuracy, acceptance, and triage time', () => {
  const csv = [
    'finding_id,expected_repository,expected_owner,expected_priority,expected_duplicate,agent_repository,agent_owner,agent_priority,agent_duplicate,accepted_without_rework,manual_triage_minutes,agent_triage_minutes',
    'a,P/repo-a,Team A,P1,NONE,p/REPO-A,Team A,P1,NONE,yes,40,5',
    'b,P/repo-b,Team B,P2,"EXACT:XENA-1",P/repo-x,Team C,P2,"EXACT:XENA-1",no,50,7',
    'c,P/repo-c,Team C,P3,NONE,,,,,,30,',
  ].join('\n');
  const r = score(parseCsv(csv));
  assert.equal(r.scored, 2);
  assert.equal(r.repositoryAccuracy, '50% (1/2)');
  assert.equal(r.ownerAccuracy, '50% (1/2)');
  assert.equal(r.priorityAccuracy, '100% (2/2)');
  assert.equal(r.duplicateAccuracy, '100% (2/2)');
  assert.equal(r.acceptedWithoutRework, '50% (1/2)');
  assert.equal(r.triageMinutes, '40.0 manual -> 6.0 with agent');
});
