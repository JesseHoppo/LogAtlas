import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractIOCs } from '../js/analysis/iocExtraction.js';

const byLabel = (iocs) => Object.fromEntries((iocs || []).map((ioc) => [ioc.label, ioc]));

test('identifier keys become victim IOCs', () => {
  const iocs = byLabel(extractIOCs({
    IP: '203.0.113.10',
    HWID: '0123456789ABCDEF',
    'Build ID': 'TestBuild',
    'Computer Name': 'DESKTOP-TEST01',
  }, ''));
  assert.equal(iocs['IP Address'].value, '203.0.113.10');
  assert.equal(iocs.HWID.value, '0123456789ABCDEF');
  assert.equal(iocs['Build ID'].value, 'TestBuild');
  assert.equal(iocs['Computer Name'].value, 'DESKTOP-TEST01');
  assert.equal(iocs['IP Address'].kind, undefined);
});

test('a dropper path is a loader sample; a stock binary in the system root is the injection host', () => {
  const dropper = byLabel(extractIOCs({ Path: 'C:\\Users\\jtester\\AppData\\Local\\Temp\\sample.exe' }, ''));
  assert.equal(dropper['Loader Sample'].kind, 'stealer-infra');

  const host = byLabel(extractIOCs({ Path: 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe' }, ''));
  assert.equal(host['Injection Host'].value, 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe');
  assert.equal(host['Loader Sample'], undefined);

  const masquerade = byLabel(extractIOCs({ Path: 'C:\\Users\\jtester\\AppData\\Roaming\\dllhost.exe' }, ''));
  assert.ok(masquerade['Loader Sample']);
});

test('stealer infrastructure in the sysinfo text is labelled with its family', () => {
  const iocs = extractIOCs({}, 'Contact: t.me/+AbCdEfGh1234\nPanel: https://panel.vidars.example/admin\n');
  const labels = iocs.map((ioc) => ioc.label);
  assert.ok(labels.includes('Stealer Telegram'));
  assert.ok(iocs.every((ioc) => ioc.kind === 'stealer-infra'));
});

test('a timezone value is shown as an offset with its raw form kept', () => {
  const tz = byLabel(extractIOCs({ TimeZone: '4294967293', Country: 'BR' }, '')).Timezone;
  assert.equal(tz.value, 'UTC-03:00');
  assert.equal(tz.rawValue, '4294967293');
});
