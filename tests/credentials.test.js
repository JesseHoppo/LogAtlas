import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePasswordFile, parseCookieFile } from '../js/transforms/credentials.js';
import { credentialColumnIndices } from '../js/core/shared.js';
import { classifyCookie, isLiveSessionToken } from '../js/analysis/sessionCookies.js';
import { analyseCase } from './helpers/case.js';
import { netscapeCookies, passwordBlocks, redlineLog, unix, DEFAULT_CREDENTIALS } from './helpers/fixtures.js';

function rowsOf(parsed) {
  const { urlIdx, userIdx, passIdx } = credentialColumnIndices(parsed.headers);
  return parsed.rows.map((row) => [row[urlIdx], row[userIdx], row[passIdx]]);
}

test('password files parse in the labelled, combolist and delimited shapes', () => {
  const expected = [['https://mail.example.com/login', 'jordan.tester@example.com', 'Correct-Horse-1']];
  assert.deepEqual(rowsOf(parsePasswordFile(passwordBlocks(DEFAULT_CREDENTIALS.slice(0, 1)))), expected);
  assert.deepEqual(rowsOf(parsePasswordFile('Host: https://mail.example.com/login\nLogin: jordan.tester@example.com\nPassword: Correct-Horse-1\n')), expected);
  assert.deepEqual(rowsOf(parsePasswordFile('https://mail.example.com/login:jordan.tester@example.com:Correct-Horse-1\n')), expected);
  assert.deepEqual(rowsOf(parsePasswordFile('url\tusername\tpassword\nhttps://mail.example.com/login\tjordan.tester@example.com\tCorrect-Horse-1\n')), expected);
});

test('Netscape cookie files keep every column and spell out the expiry', () => {
  const parsed = parseCookieFile(netscapeCookies([{ domain: '.example.com', name: 'sessionid', value: 'abc', expires: 1893456000 }]));
  assert.equal(parsed.rows.length, 1);
  assert.deepEqual(parsed.rows[0], ['.example.com', 'TRUE', '/', 'TRUE', '2030-01-01 00:00:00Z', 'sessionid', 'abc']);
});

test('cookie names classify as auth, session, tracking or nothing', () => {
  assert.equal(classifyCookie('PHPSESSID', 'example.com'), 'auth');
  assert.equal(classifyCookie('__Secure-3PSID', 'google.com'), 'auth');
  assert.equal(classifyCookie('app_session', 'example.com'), 'session');
  assert.equal(classifyCookie('session_id', 'ads.doubleclick.net'), 'tracking');
  assert.equal(classifyCookie('theme', 'example.com'), null);
  assert.equal(isLiveSessionToken({ sessionType: 'auth', validity: 'valid' }), true);
  assert.equal(isLiveSessionToken({ sessionType: 'auth', validity: 'expired' }), false);
  assert.equal(isLiveSessionToken({ sessionType: 'session', validity: 'session' }), true);
});

test('an exact twin of a password file is read once', async () => {
  const files = redlineLog();
  files['Chrome/Default/Passwords.txt'] = files['Passwords.txt'];
  const { events } = await analyseCase(files);
  assert.equal(events.credentials.fileCount, 1);
  assert.equal(events.credentials.totalCredentials, 2);
  assert.equal(events.credentials.uniqueCredentials, 2);
});

test('overlapping files collapse to unique credentials by base domain', async () => {
  const files = redlineLog();
  files['Chrome/Default/Passwords.txt'] = files['Passwords.txt'];
  files['Passwords.txt'] += '\n' + passwordBlocks([{ url: 'https://mail.example.com/other', user: 'jordan.tester@example.com', pass: 'Correct-Horse-1' }]);
  const { events } = await analyseCase(files);
  assert.equal(events.credentials.fileCount, 2);
  assert.equal(events.credentials.totalCredentials, 5);
  assert.equal(events.credentials.uniqueCredentials, 2);
  assert.deepEqual(events.credentials.topDomains.map((d) => d.value).sort(), ['example.com', 'example.org']);
});

test('placeholder usernames and no-password rows stay out of the credential tally', async () => {
  const files = redlineLog({
    credentials: [
      ...DEFAULT_CREDENTIALS,
      { url: 'https://shop.example.net/', user: 'UNKNOWN', pass: 'Another-Pass-3' },
      { url: 'https://news.example.net/', user: 'reader@example.net', pass: '' },
    ],
  });
  const { events } = await analyseCase(files);
  assert.equal(events.credentials.uniqueCredentials, 3);
  assert.equal(events.credentials.accountsWithoutPasswords, 1);
  assert.ok(!events.credentials.topUsernames.some((u) => u.value === 'UNKNOWN'));
});

test('cookie totals split by validity at capture and count live session tokens', async () => {
  const files = redlineLog({
    cookies: [
      { domain: '.example.com', name: 'sessionid', expires: unix('2026-01-01T00:00:00Z') },
      { domain: '.example.com', name: 'theme', expires: unix('2026-01-01T00:00:00Z') },
      { domain: '.example.org', name: 'prefs', expires: unix('2024-01-01T00:00:00Z') },
      { domain: '.example.net', name: 'PHPSESSID', expires: 0 },
    ],
  });
  const { events } = await analyseCase(files);
  assert.equal(events.cookies.totalCookies, 4);
  assert.equal(events.cookies.totalValid, 2);
  assert.equal(events.cookies.totalExpired, 1);
  assert.equal(events.cookies.totalSession, 1);
  assert.equal(events.cookies.sessionTokens, 2);
  assert.equal(events.cookies.validSessionTokens, 2);
});
