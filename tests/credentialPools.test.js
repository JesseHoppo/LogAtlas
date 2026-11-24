import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { applyManualType } from '../js/files/extractor.js';
import { analyseCase, findNode, reanalyseCase } from './helpers/case.js';
import { combolist, redlineLog } from './helpers/fixtures.js';

const POOL = '14,4K ULP PRIV.txt';

function victimWithPool() {
  return { ...redlineLog(), [POOL]: combolist(120) };
}

test('a bundled combolist does not count as the victim\'s credentials', async () => {
  const { events } = await analyseCase(victimWithPool());
  assert.equal(events.credentials.uniqueCredentials, 2);
  assert.ok(events.credentials.topDomains.every((d) => !d.value.endsWith('example.net')));
  assert.ok(events.credentials.topUsernames.every((u) => !u.value.startsWith('buyer')));
});

test('the pool is summarised on its own', async () => {
  const { events } = await analyseCase(victimWithPool());
  assert.equal(events.credentialPools.fileCount, 1);
  assert.equal(events.credentialPools.uniqueCredentials, 120);
  assert.equal(events.credentialPools.files[0].path.endsWith(POOL), true);
});

test('a case with no pool publishes none', async () => {
  const { events } = await analyseCase(redlineLog());
  assert.equal(events.credentialPools, null);
});

test('a password file named as one stays the victim\'s, whatever its line shape', async () => {
  const files = redlineLog();
  files['Passwords.txt'] = combolist(30);
  const { events } = await analyseCase(files);
  assert.equal(events.credentials.uniqueCredentials, 30);
  assert.equal(events.credentialPools, null);
});

test('setting the pool\'s type to Credentials claims it for the victim', async () => {
  const { tree } = await analyseCase(victimWithPool());
  applyManualType(findNode(tree, POOL), 'credentials');
  const { events } = await reanalyseCase();
  assert.equal(events.credentials.uniqueCredentials, 122);
  assert.equal(events.credentialPools, null);
});
