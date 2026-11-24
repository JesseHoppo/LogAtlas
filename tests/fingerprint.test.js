import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseCase } from './helpers/case.js';
import { atomicMacLog, lummaLog, redlineLog, vidarLog } from './helpers/fixtures.js';

async function fingerprintOf(files) {
  const { events } = await analyseCase(files);
  return events.fingerprint;
}

test('each family layout is identified with high confidence', async (t) => {
  for (const [family, files] of [
    ['RedLine', redlineLog()],
    ['Lumma', lummaLog()],
    ['Vidar', vidarLog()],
    ['Atomic', atomicMacLog()],
  ]) {
    await t.test(family, async () => {
      const result = await fingerprintOf(files);
      assert.equal(result?.family, family);
      assert.equal(result?.confidence, 'high');
      assert.ok(result.matchedSignals.length > 0);
    });
  }
});

test('a resale banner names the distributor, not the family', async () => {
  const files = redlineLog();
  files['Passwords.txt'] = '( O | T | T | O | M | A | N )\nBuy daily fresh logs\n\n' + files['Passwords.txt'];
  const result = await fingerprintOf(files);
  assert.equal(result.family, 'RedLine');
  assert.equal(result.distributor, 'Ottoman');
});

test('a macOS family is not reported for a log whose OS line says Windows', async () => {
  const files = atomicMacLog();
  files['Sysinfo.txt'] = files['Sysinfo.txt'].replace('ProductName: macOS', 'OS: Windows 10 Pro');
  const result = await fingerprintOf(files);
  assert.notEqual(result?.family, 'Atomic');
});

test('no sysinfo and no layout to speak of gives no verdict', async () => {
  const result = await fingerprintOf({ 'notes about the weekend.txt': 'nothing to see\n' });
  assert.equal(result, null);
});
