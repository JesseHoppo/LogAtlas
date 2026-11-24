import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCredentialCurrentnessModel } from '../js/analysis/credentialCurrentness.js';

const captureContext = { date: new Date('2025-03-14T09:15:02Z'), source: 'sysinfo', detail: 'Log date', offsetMinutes: null };

function model(input) {
  return buildCredentialCurrentnessModel({ captureContext, ...input });
}

const rowFor = (result, url) => result.rows.find((row) => row.url === url);

test('a live session cookie for the site makes the credential live', () => {
  const result = model({
    credentials: [{ url: 'https://app.example.com/login', username: 'jordan.tester@example.com', password: 'pw-1', source: 'a' }],
    cookies: [{ host: 'app.example.com', name: 'sessionid', validityStatus: 'valid', sessionType: 'session', hasValue: true }],
  });
  const row = rowFor(result, 'https://app.example.com/login');
  assert.equal(row.actionability, 'live');
  assert.equal(row.hasLiveSession, true);
});

test('a visit within 30 days of capture makes it recent; nothing at all leaves it stored', () => {
  const result = model({
    credentials: [
      { url: 'https://visited.example.com/', username: 'jt@example.net', password: 'pw-1', source: 'a' },
      { url: 'https://forgotten.example.org/', username: 'jt@example.net', password: 'pw-2', source: 'a' },
    ],
    history: [{ url: 'https://visited.example.com/inbox', title: 'Inbox', visitCount: 3, lastVisitDate: new Date('2025-03-10T00:00:00Z') }],
  });
  assert.equal(rowFor(result, 'https://visited.example.com/').actionability, 'recent');
  const stale = rowFor(result, 'https://forgotten.example.org/');
  assert.equal(stale.actionability, 'stored');
  assert.equal(stale.bucket, 'weak');
});

test('live rows sort ahead of recent ones, recent ahead of stored', () => {
  const result = model({
    credentials: [
      { url: 'https://forgotten.example.org/', username: 'jt@example.net', password: 'pw-2', source: 'a' },
      { url: 'https://visited.example.com/', username: 'jt@example.net', password: 'pw-1', source: 'a' },
      { url: 'https://app.example.net/', username: 'jt@example.net', password: 'pw-3', source: 'a' },
    ],
    history: [{ url: 'https://visited.example.com/', lastVisitDate: new Date('2025-03-10T00:00:00Z') }],
    cookies: [{ host: 'app.example.net', name: 'PHPSESSID', validityStatus: 'session', sessionType: 'auth', hasValue: true }],
  });
  assert.deepEqual(result.rows.map((row) => row.actionability), ['live', 'recent', 'stored']);
});

test('one account saved in two browser profiles is one row with both sources', () => {
  const result = model({
    credentials: [
      { url: 'https://app.example.com/login', username: 'Jordan.Tester@example.com', password: 'pw-1', source: 'Chrome/Default/Passwords.txt' },
      { url: 'https://app.example.com/other', username: 'jordan.tester@example.com', password: 'pw-1', source: 'Edge/Default/Passwords.txt' },
    ],
  });
  assert.equal(result.rows.length, 1);
  assert.deepEqual(result.rows[0].sources, ['Chrome/Default/Passwords.txt', 'Edge/Default/Passwords.txt']);
});

test('a corporate account is demoted when another employer is better corroborated', () => {
  const result = model({
    credentials: [
      { url: 'https://portal.oldco.example/', username: 'jt@oldco.example', password: 'pw-old', source: 'a' },
      { url: 'https://portal.newco.example/', username: 'jt@newco.example', password: 'pw-new', source: 'a' },
    ],
    autofillEntries: [{ name: 'email', value: 'jt@newco.example' }],
    accountTokens: [{ accountId: 'jt@newco.example' }],
    cookies: [{ host: 'mail.newco.example', name: 'sessionid', validityStatus: 'valid', sessionType: 'session', hasValue: true }],
  });
  const legacy = rowFor(result, 'https://portal.oldco.example/');
  assert.equal(legacy.conflictDomain, 'newco.example');
  assert.equal(legacy.actionability, 'legacy');
  assert.equal(result.summary.primaryIdentity.email, 'jt@newco.example');
});
