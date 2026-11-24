import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { multiLogBannerText } from '../js/app/dashboard.js';
import { analyseCase } from './helpers/case.js';
import { lummaLog, redlineLog } from './helpers/fixtures.js';

function nest(prefix, files) {
  return Object.fromEntries(Object.entries(files).map(([path, content]) => [`${prefix}/${path}`, content]));
}

test('a log is identified from its own folder, not from the archive root above it', async () => {
  const { events } = await analyseCase({
    ...nest('AU[0A1B2C]', lummaLog()),
    'Join our channel.txt': 'Fresh logs daily: t.me/example_channel\n',
  });
  assert.equal(events.fingerprint?.family, 'Lumma');
  assert.equal(events.logRoots.count, 1);
  assert.equal(events.logRoots.logs[0].path, 'AU[0A1B2C]');
});

test('a profile kept in its own System folder places the log above it', async () => {
  const files = redlineLog();
  files['System/UserInformation.txt'] = files['UserInformation.txt'];
  delete files['UserInformation.txt'];
  const { events } = await analyseCase(nest('victim', files));
  assert.equal(events.logRoots.count, 1);
  assert.equal(events.logRoots.logs[0].path, '');
});

test('a grabbed document named like a profile does not start a second log', async () => {
  const files = redlineLog();
  files['Files/Documents/UserInformation.txt'] = 'Build ID: not-a-profile\nUserName: someone else\n';
  const { events } = await analyseCase(files);
  assert.equal(events.logRoots.count, 1);
});

test('several victims in one archive are found, described and flagged', async () => {
  const { events } = await analyseCase({
    ...nest('US[1A2B]', redlineLog({ user: 'alice', country: 'US', logDate: '3/14/2025 9:15:02 AM' })),
    ...nest('DE[9F8E]', redlineLog({ user: 'bernd', country: 'DE', logDate: '7/19/2025 10:40:10 PM', timeZone: '(UTC+01:00) Berlin' })),
  });
  assert.equal(events.logRoots.count, 2);
  const users = events.logRoots.logs.map((log) => log.user).sort();
  assert.deepEqual(users, ['alice', 'bernd']);
  assert.ok(events.logRoots.logs.every((log) => log.family === 'RedLine'));
  // The headline verdict is the first log's, as the merged sysinfo is.
  assert.equal(events.fingerprint.family, 'RedLine');
  assert.equal(events.sysinfo.entries.UserName, events.logRoots.logs[0].user);

  const banner = multiLogBannerText(events.logRoots);
  assert.match(banner, /^This archive holds 2 separate logs: /);
  assert.match(banner, /alice/);
  assert.match(banner, /bernd/);
});

test('one log raises no multi-log banner, and a long list is cut short', () => {
  assert.equal(multiLogBannerText({ count: 1, logs: [{ name: 'a', path: 'a' }] }), '');
  const logs = Array.from({ length: 5 }, (_, i) => ({ name: `log${i}`, path: `log${i}`, user: `u${i}` }));
  assert.match(multiLogBannerText({ count: 5, logs }), /log0 \(u0\), log1 \(u1\), log2 \(u2\), and 2 other logs\./);
});

test('with no profile anywhere the archive layout is still read', async () => {
  const files = lummaLog();
  delete files['System.txt'];
  const { events } = await analyseCase(files);
  assert.equal(events.logRoots.count, 0);
  assert.deepEqual(
    [events.fingerprint.family, events.fingerprint.confidence, events.fingerprint.source],
    ['Lumma', 'low', 'structure-only'],
  );
});
