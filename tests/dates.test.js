import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseTimestampValue,
  parseArchiveTimestamp,
  resolveCaptureContext,
  checkCookieValidity,
  normaliseTimeZone,
} from '../js/core/shared.js';
import { captureOrderCheck } from '../js/app/dashboard.js';
import { analyseCase } from './helpers/case.js';
import { redlineLog } from './helpers/fixtures.js';

const iso = (date) => (date ? date.toISOString() : null);
const MARCH_14 = '2025-03-14T09:15:02.000Z';

test('epoch values in every unit the browsers use', () => {
  const ms = Date.parse(MARCH_14);
  const chromeMicros = BigInt(ms) * 1000n + 11644473600000000n;
  assert.equal(iso(parseTimestampValue(String(ms / 1000))), MARCH_14);
  assert.equal(iso(parseTimestampValue(String(ms))), MARCH_14);
  assert.equal(iso(parseTimestampValue(String(ms * 1000))), MARCH_14);
  assert.equal(iso(parseTimestampValue(chromeMicros.toString())), MARCH_14);
  assert.equal(iso(parseTimestampValue(`${ms / 1000}.431387`)), MARCH_14);
});

test('wall-clock strings are read as written and anchored to UTC', () => {
  for (const value of [
    '14.03.2025 09:15:02',
    '2025-03-14 09:15:02',
    '3/14/2025 9:15:02 AM',
    '14/03/2025 09:15:02',
  ]) {
    assert.equal(iso(parseTimestampValue(value)), MARCH_14, value);
  }
  assert.equal(iso(parseTimestampValue('3/14/2025 9:15:02 PM')), '2025-03-14T21:15:02.000Z');
});

test('zoned strings land on the absolute instant', () => {
  assert.equal(iso(parseTimestampValue('2025-03-14T09:15:02+09:30')), '2025-03-13T23:45:02.000Z');
  assert.equal(iso(parseTimestampValue('18 Sep 25 00:32 EDT')), '2025-09-18T04:32:00.000Z');
});

test('placeholders and bare small numbers are not dates', () => {
  for (const value of ['', '0', 'session', 'null', '1', '-1.5']) {
    assert.equal(parseTimestampValue(value), null, JSON.stringify(value));
  }
});

test('archive names carry a capture stamp in several shapes', () => {
  assert.equal(iso(parseArchiveTimestamp('AU[0A1B]_2025-03-14_09-15-02.zip')), MARCH_14);
  assert.equal(iso(parseArchiveTimestamp('log-14-03-2025-09-15-02.zip')), MARCH_14);
  assert.equal(iso(parseArchiveTimestamp('20250314.zip')), '2025-03-14T00:00:00.000Z');
  assert.equal(parseArchiveTimestamp('logs.zip'), null);
});

test('the capture ladder prefers sysinfo, then the archive name, then mtimes, then history', () => {
  const history = new Date('2025-03-10T00:00:00Z');
  const mtime = Date.parse('2025-03-12T00:00:00Z');
  const fromSysinfo = resolveCaptureContext({
    sysinfoEntries: { 'Log date': '14.03.2025 09:15:02' },
    archiveNames: ['AU_2025-03-13.zip'],
    sourceLastModified: mtime,
    historyMaxDate: history,
  });
  assert.deepEqual([fromSysinfo.source, fromSysinfo.detail, iso(fromSysinfo.date)], ['sysinfo', 'Log date', MARCH_14]);

  const fromArchive = resolveCaptureContext({ archiveNames: ['AU_2025-03-13.zip'], sourceLastModified: mtime, historyMaxDate: history });
  assert.equal(fromArchive.source, 'archive name');

  const fromMtime = resolveCaptureContext({ archiveNames: ['logs.zip'], sourceLastModified: mtime, historyMaxDate: history });
  assert.equal(fromMtime.source, 'file modified');

  const fromHistory = resolveCaptureContext({ historyMaxDate: history });
  assert.equal(fromHistory.source, 'history');
});

test('a declared machine offset turns the sysinfo wall clock into UTC', () => {
  const context = resolveCaptureContext({
    sysinfoEntries: { Country: 'AU', TimeZone: '(UTC+09:30) Adelaide', 'Log date': '3/14/2025 9:15:02 AM' },
  });
  assert.equal(context.offsetMinutes, 570);
  assert.equal(iso(context.date), '2025-03-13T23:45:02.000Z');
});

test('an offset the country contradicts is not applied', () => {
  const zone = normaliseTimeZone('13', 'US');
  assert.equal(zone.countryMismatch, true);
  const context = resolveCaptureContext({ sysinfoEntries: { Country: 'US', TimeZone: '13', 'Log date': '3/14/2025 9:15:02 AM' } });
  assert.equal(context.offsetMinutes, null);
  assert.equal(iso(context.date), MARCH_14);
});

test('cookie expiry is judged against the capture instant', () => {
  const capture = new Date(MARCH_14);
  assert.equal(checkCookieValidity(String(Date.parse('2025-06-01T00:00:00Z') / 1000), capture).status, 'valid');
  assert.equal(checkCookieValidity(String(Date.parse('2025-01-01T00:00:00Z') / 1000), capture).status, 'expired');
  assert.equal(checkCookieValidity('0', capture).status, 'session');
  assert.equal(checkCookieValidity('not a date', capture).status, 'unknown');
});

test('the analysis pass publishes one capture instant with its provenance', async () => {
  const { events } = await analyseCase(redlineLog());
  assert.equal(events.capture.source, 'sysinfo');
  assert.equal(events.capture.detail, 'Log date');
  assert.equal(events.capture.iso, '2025-03-13T23:45:02.000Z');
  assert.equal(events.timezone.offsetMinutes, 570);
});

// 5 March or 3 May, depending on who wrote it.
const AMBIGUOUS = '05/03/2025 10:22:11';
const MARCH_5 = '2025-03-05T10:22:11.000Z';
const MAY_3 = '2025-05-03T10:22:11.000Z';

const orderOf = (context) => [iso(context.date), context.dateOrder?.order, context.dateOrder?.settledBy];

test('an ambiguous 24-hour stamp is read the way the victim\'s country writes dates', () => {
  for (const country of ['AU', 'GB', 'BR', 'Germany']) {
    const context = resolveCaptureContext({ sysinfoEntries: { Country: country, Date: AMBIGUOUS } });
    assert.deepEqual(orderOf(context), [MARCH_5, 'day-first', 'country'], country);
    assert.equal(iso(context.dateOrder.alternative), MAY_3);
  }
  const us = resolveCaptureContext({ sysinfoEntries: { Country: 'US', Date: AMBIGUOUS } });
  assert.deepEqual(orderOf(us), [MAY_3, 'month-first', 'country']);
});

test('a sibling date that reads only one way settles the order for the file', () => {
  const dayFirst = resolveCaptureContext({ sysinfoEntries: { Country: 'US', 'Install Date': '25/12/2024 08:00', Date: AMBIGUOUS } });
  assert.deepEqual(orderOf(dayFirst), [MARCH_5, 'day-first', 'sysinfo']);
  const monthFirst = resolveCaptureContext({ sysinfoEntries: { Country: 'AU', 'Install Date': '12/25/2024 08:00', Date: AMBIGUOUS } });
  assert.deepEqual(orderOf(monthFirst), [MAY_3, 'month-first', 'sysinfo']);
});

test('a reading after the archive was packed, or before the newest browsing, is ruled out', () => {
  const byArchive = resolveCaptureContext({ sysinfoEntries: { Country: 'US', Date: AMBIGUOUS }, archiveNames: ['US_2025-03-06_log.zip'] });
  assert.deepEqual(orderOf(byArchive), [MARCH_5, 'day-first', 'archive name']);
  const byHistory = resolveCaptureContext({ sysinfoEntries: { Country: 'GB', Date: AMBIGUOUS }, historyMaxDate: new Date('2025-04-20T00:00:00Z') });
  assert.deepEqual(orderOf(byHistory), [MAY_3, 'month-first', 'history']);
});

test('a 12-hour stamp keeps the US reading whatever the country says', () => {
  const context = resolveCaptureContext({ sysinfoEntries: { Country: 'GB', Date: '5/3/2025 10:22:11 AM' } });
  assert.deepEqual(orderOf(context), [MAY_3, 'month-first', 'default']);
});

test('a stamp that reads only one way carries no date-order note', () => {
  assert.equal(resolveCaptureContext({ sysinfoEntries: { Country: 'AU', Date: '14/03/2025 09:15:02' } }).dateOrder, null);
  assert.equal(resolveCaptureContext({ sysinfoEntries: { Country: 'AU', Date: '05/05/2025 09:15:02' } }).dateOrder, null);
  assert.equal(resolveCaptureContext({ sysinfoEntries: { Country: 'AU', Date: '05.03.2025 10:22:11' } }).dateOrder, null);
});

test('the declared offset applies to both readings', () => {
  const context = resolveCaptureContext({ sysinfoEntries: { Country: 'AU', TimeZone: '(UTC+09:30) Adelaide', Date: AMBIGUOUS } });
  assert.equal(context.offsetMinutes, 570);
  assert.equal(iso(context.date), '2025-03-05T00:52:11.000Z');
  assert.equal(iso(context.dateOrder.alternative), '2025-05-03T00:52:11.000Z');
});

test('an assumed order is published with the capture and flagged on the Overview', async () => {
  const { events } = await analyseCase(redlineLog({ logDate: AMBIGUOUS }));
  assert.deepEqual(events.capture.dateOrder, { order: 'day-first', settledBy: 'country', alternativeIso: '2025-05-03T00:52:11.000Z' });
  const check = captureOrderCheck(events.capture);
  assert.equal(check.variant, 'warn');
  assert.match(check.text, /taken day-first \(2025-03-05 00:52:11 UTC\), as the victim's country writes dates; month-first would make it 2025-05-03 00:52:11 UTC/);
  assert.equal(captureOrderCheck({ ...events.capture, dateOrder: { ...events.capture.dateOrder, settledBy: 'history' } }), null);
});
