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

const WINDOWS_PATH = 'C:\\Users\\Amos\\AppData\\Local\\Temp\\sample.exe';

test('a user named after a stealer does not name the stealer', async () => {
  const result = await fingerprintOf({
    'UserInformation.txt': `IP: 203.0.113.7\nCountry: GB\nUser Name: Amos\nComputer Name: DESKTOP-TEST01\nHWID: 0123456789ABCDEF\nPath: ${WINDOWS_PATH}\n`,
    'Passwords.txt': 'URL: https://mail.example.com/\nUsername: amos@example.com\nPassword: pw-1\n',
  });
  assert.notEqual(result?.family, 'Atomic');
});

test('a self-ID matched inside a longer word does not count', async () => {
  const files = { ...redlineLog(), 'credits.txt': 'Thanks for buying from the Pearl Stealer team\n' };
  assert.equal((await fingerprintOf(files)).family, 'RedLine');
  const branded = await fingerprintOf({ ...redlineLog(), 'credits.txt': 'RL Stealer v2 - private build\n' });
  assert.equal(branded.family, 'RLStealer');
});

const GENERIC_INFO = 'IP: 198.51.100.4\nCountry: RU\nUser Name: Ivan\nComputer Name: DESKTOP-7\nOS: Windows 10 Pro\n';

test('generic sysinfo keys and a passwords file are not enough for a confident verdict', async () => {
  const result = await fingerprintOf({ 'Information.txt': GENERIC_INFO, 'Passwords.txt': 'URL: https://a.example.com/\nUsername: u\nPassword: p\n' });
  assert.ok(!result || result.confidence === 'low', `got ${result?.family} / ${result?.confidence}`);
});

test('the victim\'s script does not change the verdict', async () => {
  const passwords = 'URL: https://a.example.com/\nUsername: u\nPassword: p\n';
  const latin = await fingerprintOf({ 'Information.txt': GENERIC_INFO, 'Passwords.txt': passwords });
  const cyrillic = await fingerprintOf({ 'Information.txt': GENERIC_INFO.replace('Windows 10 Pro', 'Windows 10 Профессиональная').replace('Ivan', 'Иван'), 'Passwords.txt': passwords });
  assert.deepEqual([cyrillic?.family, cyrillic?.confidence], [latin?.family, latin?.confidence]);

  const vidar = vidarLog();
  vidar['information.txt'] = vidar['information.txt'].replace('City: Adelaide', 'City: Москва');
  assert.equal((await fingerprintOf(vidar)).confidence, 'high');
});

test('a close call between two families is reported as one', async () => {
  const result = await fingerprintOf({
    'sysinfo.txt': 'Elevated: false\nNetBIOS: DESKTOP-TEST01\nHWID: 0123456789ABCDEF\nTime: 2025-03-14 09:15:02 (sig:0a1b2c3d.4e5f6a7b)\n',
    'All Passwords.txt': 'URL: https://a.example.com/\nUsername: u\nPassword: p\n',
    'DomainDetect.txt': 'Banks\n',
    'Software.txt': 'Example App [1.0]\n',
    'Processes.txt': 'explorer.exe\n',
    'Chrome/Default/Passwords.txt': 'URL: https://a.example.com/\nUsername: u\nPassword: p\n',
    'Chrome/Debug.txt': 'bps\nfin\n',
    'Cookies/Cookies_Chrome_Default.txt': '.example.com\tTRUE\t/\tTRUE\t1893456000\tprefs\tv\n',
  });
  assert.ok(['Lumma', 'StealC'].includes(result.family));
  assert.equal(result.ambiguous, true);
  assert.equal(result.runnerUp.family, result.family === 'Lumma' ? 'StealC' : 'Lumma');
  assert.notEqual(result.confidence, 'high');
});

test('a clear verdict is not marked as a close call', async () => {
  const result = await fingerprintOf(redlineLog());
  assert.equal(result.ambiguous, false);
});
