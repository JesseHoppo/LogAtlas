// Password, Cookie, Autofill parsing.

import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import { parseTimestampValue } from '../core/shared.js';
import {
  KV_PATTERN,
  AUTOFILL_KV_PATTERN,
  GOOGLE_RESTORE_TOKEN_PATTERN,
  PASSWORD_KV_PATTERN,
  normaliseText,
  normaliseSeparators,
  stripLeadingNoiseLines,
  isSeparatorOnlyLine,
  isPromotionalNoiseLine,
  classifyPasswordFieldKey,
  canonicalisePasswordExtraHeader,
  decodeHtmlEntities,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
  parseWithConfig,
  buildPasswordDataset,
  finaliseCredentialDataset,
} from './delimited.js';

function mostCommonCount(counts) {
  const tally = new Map();
  let best = counts[0];
  let bestN = 0;
  for (const c of counts) {
    const n = (tally.get(c) || 0) + 1;
    tally.set(c, n);
    if (n > bestN) { bestN = n; best = c; }
  }
  return best;
}

// Only an absent, zero or negative expiry means "session". A value we cannot
// read is handed on as it stands, so checkCookieValidity can call it unknown
// rather than promising the analyst an unexpired token.
function convertCookieTimestamp(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed || /^(?:session|null)$/i.test(trimmed)) return 'Session';

  const num = Number(trimmed);
  if (!isNaN(num) && num <= 0) return 'Session';

  const date = parseTimestampValue(trimmed);
  if (!date) return trimmed;
  return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

const URL_SCHEME_KEY = /^[a-z][a-z0-9+.-]*$/i;

function nextContentLineIsIndented(lines, index) {
  for (let i = index + 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    return /^[ \t]/.test(lines[i]);
  }
  return false;
}

function parsePasswordKeyValueRecords(text) {
  const records = [];
  // Field names come from the file: on an object literal a `constructor:` line
  // already reads as set, which splits the record it belongs to.
  let current = Object.create(null);
  let hasCredentialField = false;
  let allowPasswordContinuation = false;

  const flush = () => {
    if (hasCredentialField) records.push({ ...current });
    current = Object.create(null);
    hasCredentialField = false;
    allowPasswordContinuation = false;
  };

  const lines = normaliseText(text).split('\n');
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index].trim();
    if (!line) continue;
    if (isSeparatorOnlyLine(line)) {
      flush();
      continue;
    }

    const kvMatch = line.match(PASSWORD_KV_PATTERN);
    if (!kvMatch) {
      if (allowPasswordContinuation && current.Password) {
        current.Password += '\n' + line;
      }
      continue;
    }

    const rawKey = kvMatch[1].trim();
    const value = kvMatch[2].trim();
    const role = classifyPasswordFieldKey(rawKey);
    // A record that opens with a bare URL: the key/value split reads the scheme
    // as the key, which would file the site under a column named after it. It
    // is the record's site, not a credential of its own — combolists are whole
    // files of these lines and stay with the combo parser.
    const bareUrl = !role && value.startsWith('//') && URL_SCHEME_KEY.test(rawKey);
    const header = bareUrl
      ? 'URL'
      : role
        ? (role === 'url' ? 'URL' : role === 'username' ? 'Username' : 'Password')
        : canonicalisePasswordExtraHeader(rawKey);

    if (line.includes('://') && line.indexOf(':') < line.indexOf('://') && !role && !['Software', 'Browser', 'Profile'].includes(header)) {
      if (allowPasswordContinuation && current.Password) {
        current.Password += '\n' + line;
      }
      continue;
    }

    if (!header) continue;
    // `Site 1:` or `Server 2:` with the fields indented under it labels the
    // record; taking it as a field of its own leaves a column empty on every row.
    if (!value && !bareUrl && nextContentLineIsIndented(lines, index)) {
      flush();
      continue;
    }
    if (hasCredentialField && current[header]) flush();

    current[header] = bareUrl ? line : value;
    if (role) hasCredentialField = true;
    allowPasswordContinuation = header === 'Password' && /^android:\/\//i.test(current.URL || '');
  }

  flush();
  return buildPasswordDataset(records);
}

function findCredentialSeparator(line, afterProtocolStart) {
  const afterProtocol = line.slice(afterProtocolStart);
  const slashPos = afterProtocol.indexOf('/');
  const atPos = afterProtocol.indexOf('@');

  if (slashPos >= 0) {
    const colonAfterPath = afterProtocol.slice(slashPos).indexOf(':');
    return colonAfterPath >= 0 ? afterProtocolStart + slashPos + colonAfterPath : null;
  }

  const colonPositions = [];
  for (let i = 0; i < afterProtocol.length; i++) {
    if (afterProtocol[i] === ':') colonPositions.push(i);
  }

  // `user@host:pass` puts the `@` inside the authority, so the separator is the
  // colon after it. But `site.com:jane@example.com:pw` also has an `@` — after
  // the first colon, where it is part of the username. Taking the userinfo
  // reading there dropped every combolist line whose username is an email and
  // whose site has no path.
  if (atPos >= 0 && (colonPositions.length === 0 || atPos < colonPositions[0])) {
    const colonAfterAt = afterProtocol.slice(atPos + 1).indexOf(':');
    return colonAfterAt >= 0 ? afterProtocolStart + atPos + 1 + colonAfterAt : null;
  }

  if (colonPositions.length < 2) return null;
  if (colonPositions.length === 2) return afterProtocolStart + colonPositions[0];

  const potentialPort = afterProtocol.slice(colonPositions[0] + 1, colonPositions[1]);
  if (/^\d{1,5}$/.test(potentialPort)) {
    return afterProtocolStart + colonPositions[1];
  }
  return afterProtocolStart + colonPositions[0];
}

function parseCredentialComboLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return null;

  const protocolPos = trimmed.indexOf('://');
  if (protocolPos < 0) return null;

  const firstColon = trimmed.indexOf(':');
  if (firstColon >= 0 && firstColon < protocolPos) return null;

  const urlEnd = findCredentialSeparator(trimmed, protocolPos + 3);
  if (urlEnd == null) return null;

  const url = trimmed.slice(0, urlEnd).trim();
  const creds = trimmed.slice(urlEnd + 1);
  const userSeparator = creds.indexOf(':');
  if (userSeparator < 0) return null;

  const username = creds.slice(0, userSeparator).trim();
  const password = creds.slice(userSeparator + 1).trim();
  if (!url || (!username && !password)) return null;

  return {
    URL: url,
    Username: username,
    Password: password,
  };
}

function parseCredentialComboLines(text) {
  const records = [];
  const lines = normaliseText(text).split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || isSeparatorOnlyLine(line)) continue;
    const record = parseCredentialComboLine(line);
    if (record) records.push(record);
  }

  return buildPasswordDataset(records);
}

function parseLoosePasswordBlocks(text) {
  const blocks = text.split(/\n\s*\n/).filter(block => block.trim());
  if (blocks.length === 0) return null;

  const headers = [];
  const rows = [];

  for (const block of blocks) {
    const record = {};
    let kvCount = 0;

    for (const line of block.split('\n')) {
      const match = line.trim().match(KV_PATTERN);
      if (!match) continue;
      const key = match[1].trim();
      record[key] = match[2].trim();
      kvCount++;
      if (!headers.includes(key)) headers.push(key);
    }

    if (kvCount >= 2) {
      rows.push(record);
    }
  }

  if (rows.length === 0 || headers.length < 2) return null;
  return { headers, rows: rows.map(record => headers.map(header => record[header] || '')) };
}

const GENERIC_HEADER = /^Column \d+$/;

function applyPasswordFallbackHeaders(parsed, format) {
  if (!parsed || format?.hasHeaderRow) return parsed;

  const roleIndex = pattern => parsed.headers.findIndex(header => pattern.test(header));
  if (roleIndex(FIELD_PATTERNS.password) >= 0) return parsed;

  const urlIdx = roleIndex(FIELD_PATTERNS.url);
  const userIdx = roleIndex(FIELD_PATTERNS.username);
  const effectiveColumns = format.columns - (format.dropColumns || []).length;

  if (urlIdx < 0 && userIdx < 0) {
    if (effectiveColumns !== 3) return parsed;
    return {
      headers: ['URL', 'Username', 'Password'],
      rows: parsed.rows,
      raggedRows: parsed.raggedRows || 0,
    };
  }

  // Content inference labelled a site/account column but left two or more
  // unnamed ones, so nothing carries a Password role and the whole file is
  // discarded downstream. Claim the first unnamed column past the account.
  if (effectiveColumns < 4) return parsed;
  const unnamed = parsed.headers.reduce((acc, header, i) => {
    if (GENERIC_HEADER.test(header)) acc.push(i);
    return acc;
  }, []);
  if (unnamed.length === 0) return parsed;

  const anchor = userIdx >= 0 ? userIdx : urlIdx;
  const passIdx = unnamed.find(i => i > anchor) ?? unnamed[unnamed.length - 1];
  if (!looksLikeSecretColumn(parsed.rows, passIdx)) return parsed;

  const headers = parsed.headers.slice();
  headers[passIdx] = 'Password';
  return { headers, rows: parsed.rows, raggedRows: parsed.raggedRows || 0 };
}

// Secrets are near-unique down a column; flags and paths repeat. Keeps the
// fallback off Netscape-shaped files that reach the password parser.
function looksLikeSecretColumn(rows, index) {
  const sample = rows.slice(0, 200).map(row => (row[index] || '').trim()).filter(Boolean);
  if (sample.length === 0) return false;
  return new Set(sample).size / sample.length >= 0.5;
}

function finaliseAutofillDataset(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const fieldIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formField.test(h));
  const valueIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formValue.test(h));
  if (fieldIdx < 0 || valueIdx < 0) return null;

  const rows = parsed.rows
    .map(row => [(row[fieldIdx] || '').trim(), (row[valueIdx] || '').trim()])
    .filter(([name, value]) => name && value);

  return rows.length > 0 ? { headers: ['Field', 'Value'], rows, raggedRows: parsed.raggedRows || 0 } : null;
}

const AUTOFILL_BLOCK_MAX_LINES = 6;
const AUTOFILL_BLOCK_MAX_VALUE_LENGTH = 500;
const AUTOFILL_SPACED_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _.$\-[\]]{0,80}?)\s*:\s+(.+)$/;
const AUTOFILL_TOKEN_VALUE_PATTERN = /^([A-Za-z_$][A-Za-z0-9_.$:-]*(?:\[[^\]\n]+\])*)\s+(.+)$/;
const AUTOFILL_NUMERIC_NAME_PATTERN = /^([0-9:][A-Za-z0-9 _.$:/\-[\]]{0,80}?)\s*[:=]?\s+(.+)$/;
const AUTOFILL_RECORD_LABEL_KEYS = new Set(['browser', 'profile', 'name', 'field', 'key', 'label', 'value', 'form']);
const AUTOFILL_RECORD_NAME_KEYS = new Set(['name', 'field', 'key', 'label', 'form']);
const AUTOFILL_RECORD_VALUE_KEYS = new Set(['value']);
const AUTOFILL_INLINE_EXCLUDED_KEYS = new Set(['browser', 'profile', 'value', 'form']);

function normaliseAutofillFieldName(name) {
  return String(name || '')
    .replace(/^(?:form|field|key|label|name)\s*:\s*/i, '')
    .replace(/:+$/, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normaliseAutofillValue(value) {
  return String(value || '')
    .replace(/^(?:value|val)\s*:\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function isLikelyAutofillFieldName(name) {
  const normalised = normaliseAutofillFieldName(name);
  if (!normalised || normalised.length > 120) return false;
  if (!/[A-Za-z]/.test(normalised)) return false;
  if (/^(?:https?|file):/i.test(normalised)) return false;
  if (/telegram/i.test(normalised)) return false;
  if (/[*|\\/]{3,}/.test(normalised)) return false;
  return true;
}

function isLikelyAutofillFieldValue(value) {
  const normalised = String(value || '').trim();
  if (!normalised || normalised.length > AUTOFILL_BLOCK_MAX_VALUE_LENGTH) return false;
  if (/^[*=_~#-]{6,}$/.test(normalised)) return false;
  return true;
}

function normaliseAutofillRecordLabel(key) {
  return String(key || '').trim().toLowerCase().replace(/\s+/g, '');
}

function parseAutofillLabelledRecords(clean) {
  const rows = [];
  let currentName = '';
  let currentValue = '';

  function flush() {
    const name = normaliseAutofillFieldName(currentName);
    const value = String(currentValue || '').trim();
    if (isLikelyAutofillFieldName(name) && isLikelyAutofillFieldValue(value)) {
      rows.push([name, value]);
    }
    currentName = '';
    currentValue = '';
  }

  for (const rawLine of stripLeadingNoiseLines(clean).split('\n')) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      flush();
      continue;
    }

    const match = trimmed.match(AUTOFILL_SPACED_KV_PATTERN) || trimmed.match(AUTOFILL_KV_PATTERN);
    if (!match) continue;

    const label = normaliseAutofillRecordLabel(match[1]);
    const value = match[2].trim();
    if (!AUTOFILL_RECORD_LABEL_KEYS.has(label) || !value) continue;

    if (AUTOFILL_RECORD_NAME_KEYS.has(label)) {
      if (currentName && currentValue) flush();
      currentName = value;
      continue;
    }

    if (AUTOFILL_RECORD_VALUE_KEYS.has(label)) {
      currentValue = value;
      if (currentName && currentValue) flush();
    }
  }

  flush();
  return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
}

function parseAutofillBlocks(clean) {
  const blocks = clean
    .split(/\n\s*\n+/)
    .map(block => block.split('\n').map(line => line.trim()).filter(Boolean))
    .filter(block => block.length > 0);

  if (blocks.length === 0) return null;

  const rows = [];
  let exactTwoLineBlocks = 0;
  let shortBlocks = 0;
  let totalBlockLines = 0;

  for (const block of blocks) {
    if (block.length < 2 || block.length > AUTOFILL_BLOCK_MAX_LINES) continue;

    const name = normaliseAutofillFieldName(block[0]);
    const value = normaliseAutofillValue(block.slice(1).join(' '));
    if (!isLikelyAutofillFieldName(name) || !isLikelyAutofillFieldValue(value)) continue;

    rows.push([name, value]);
    totalBlockLines += block.length;
    if (block.length === 2) exactTwoLineBlocks++;
    if (block.length <= 3) shortBlocks++;
  }

  if (rows.length === 0) return null;

  const exactTwoLineRatio = exactTwoLineBlocks / rows.length;
  const shortBlockRatio = shortBlocks / rows.length;
  const averageBlockLines = totalBlockLines / rows.length;
  const capturedEveryBlock = rows.length === blocks.length;

  if (exactTwoLineRatio >= 0.6 || (capturedEveryBlock && shortBlockRatio >= 0.9 && averageBlockLines <= 3)) {
    return { headers: ['Field', 'Value'], rows };
  }

  return null;
}

function parseLooseAutofillLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return null;

  const tokenMatch = trimmed.match(AUTOFILL_TOKEN_VALUE_PATTERN);
  const spacedKvMatch = trimmed.match(AUTOFILL_SPACED_KV_PATTERN);
  const genericKvMatch = trimmed.match(AUTOFILL_KV_PATTERN);

  const buildRow = (rawName, rawValue) => {
    const name = normaliseAutofillFieldName(rawName);
    // Drop a trailing double-tab count column (name\t\tvalue\t\tcount) without
    // cutting real values that contain tabs.
    const value = String(rawValue || '').replace(/\t\t\d+\s*$/, '').trim();
    if (!name || !value) return null;
    if (AUTOFILL_INLINE_EXCLUDED_KEYS.has(normaliseAutofillRecordLabel(name))) return null;
    return [name, value];
  };

  if (spacedKvMatch && spacedKvMatch[1].includes(' ')) {
    return buildRow(spacedKvMatch[1], spacedKvMatch[2]);
  }

  if (tokenMatch) {
    return buildRow(tokenMatch[1], tokenMatch[2]);
  }

  if (spacedKvMatch && !/^(?:https?|file)$/i.test(spacedKvMatch[1])) {
    return buildRow(spacedKvMatch[1], spacedKvMatch[2]);
  }

  if (genericKvMatch && !/^(?:https?|file)$/i.test(genericKvMatch[1])) {
    return buildRow(genericKvMatch[1], genericKvMatch[2]);
  }

  const numericMatch = trimmed.match(AUTOFILL_NUMERIC_NAME_PATTERN);
  const numericValue = numericMatch ? numericMatch[2].replace(/\t\t\d+\s*$/, '').trim() : '';
  if (numericMatch && isLikelyAutofillFieldValue(numericValue)) {
    const name = normaliseAutofillFieldName(numericMatch[1].replace(/^:+/, ''));
    if (isLikelyAutofillFieldName(name) && !AUTOFILL_INLINE_EXCLUDED_KEYS.has(normaliseAutofillRecordLabel(name))) {
      return [name, numericValue];
    }
  }

  return null;
}

export function parsePasswordFile(text, config) {
  const clean = normaliseSeparators(normaliseText(text));

  if (config) return finaliseCredentialDataset(parseWithConfig(clean, config));

  const format = detectFormat(clean);
  if (format && format.type === 'delimited') {
    const parsed = finaliseCredentialDataset(applyPasswordFallbackHeaders(parseDelimited(clean, format), format));
    if (parsed) return parsed;
  }

  const comboParsed = finaliseCredentialDataset(parseCredentialComboLines(clean));
  const keyValueParsed = finaliseCredentialDataset(parsePasswordKeyValueRecords(clean));

  if (comboParsed && keyValueParsed) {
    return comboParsed.rows.length > keyValueParsed.rows.length ? comboParsed : keyValueParsed;
  }

  return comboParsed || keyValueParsed || finaliseCredentialDataset(parseLoosePasswordBlocks(clean));
}

// FileZilla's ServerProtocol enum. 0 is FTP with opportunistic TLS and 6 is
// FileZilla's explicit "insecure FTP", so both travel as ftp://. An unlisted or
// absent value leaves the scheme off rather than asserting a transport.
const FILEZILLA_PROTOCOLS = { 0: 'ftp', 1: 'sftp', 2: 'http', 3: 'https', 4: 'ftps', 5: 'ftpes', 6: 'ftp' };

function decodeBase64(value) {
  try {
    return decodeURIComponent(escape(atob(value)));
  } catch (_) {
    try { return atob(value); } catch (__) { return value; }
  }
}

export function parseFileZillaSiteManager(xmlText) {
  const text = String(xmlText || '');
  const rows = [];

  const serverBlocks = text.match(/<Server>[\s\S]*?<\/Server>/g) || [];
  for (const block of serverBlocks) {
    const field = (tag) => {
      const m = block.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i'));
      return m ? decodeHtmlEntities(m[1]).trim() : '';
    };

    const host = field('Host');
    if (!host) continue;

    const port = field('Port');
    const user = field('User');
    const proto = FILEZILLA_PROTOCOLS[field('Protocol')];

    let password = '';
    const passMatch = block.match(/<Pass(\s[^>]*)?>([^<]*)<\/Pass>/i);
    if (passMatch) {
      // Entities first: the base64 alphabet carries none, so a payload that is
      // really base64 is untouched and a mislabelled one still comes out clean.
      const stored = decodeHtmlEntities(passMatch[2]).trim();
      password = /encoding="base64"/i.test(passMatch[1] || '') ? decodeBase64(stored) : stored;
    }

    const hostPort = `${host}${port ? `:${port}` : ''}`;
    rows.push([proto ? `${proto}://${hostPort}` : hostPort, user, password]);
  }

  return rows.length > 0 ? { headers: ['URL', 'Username', 'Password'], rows } : null;
}

// Cookie parser

export const COOKIE_HEADERS = ['Domain', 'SubDomain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];
export const JSON_COOKIE_HEADERS = ['Domain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];

function parseGoogleRestoreTokens(lines) {
  const rows = [];

  for (const line of lines) {
    const match = line.match(GOOGLE_RESTORE_TOKEN_PATTERN);
    if (!match) return null;
    const token = match[1];
    const accountId = match[2];
    rows.push(['accounts.google.com', 'FALSE', '/', 'TRUE', 'Session', `restore_token_${accountId}`, token]);
  }

  return rows.length > 0 ? { headers: COOKIE_HEADERS, rows } : null;
}

function parseJSONCookies(text) {
  try {
    const data = JSON.parse(text);
    if (!Array.isArray(data) || data.length === 0) return null;

    const first = data[0];
    const keys = Object.keys(first).map(k => k.toLowerCase());
    const hasDomain = keys.some(k => k === 'domain' || k === 'host' || k === 'host_key');
    const hasName = keys.some(k => k === 'name' || k === 'key');
    const hasValue = keys.some(k => k === 'value');
    if (!hasDomain || !hasName || !hasValue) return null;

    function get(obj, ...candidates) {
      for (const c of candidates) {
        for (const k of Object.keys(obj)) {
          if (k.toLowerCase() === c) return String(obj[k] ?? '');
        }
      }
      return '';
    }

    const rows = data.map(entry => [
      get(entry, 'domain', 'host', 'host_key'),
      get(entry, 'path'),
      get(entry, 'secure', 'issecure', 'is_secure') === 'true' || get(entry, 'secure', 'issecure', 'is_secure') === '1' ? 'TRUE' : 'FALSE',
      convertCookieTimestamp(get(entry, 'expirationdate', 'expiration', 'expires', 'expiry', 'expires_utc')),
      get(entry, 'name', 'key'),
      decodeCookieValue(get(entry, 'value')),
    ]);

    return { headers: JSON_COOKIE_HEADERS, rows };
  } catch (_) {
    return null;
  }
}

function findCookieArrayInObject(text) {
  try {
    const obj = JSON.parse(text);
    const isCookieArray = (arr) =>
      Array.isArray(arr) && arr.length > 0 && typeof arr[0] === 'object' && arr[0] !== null &&
      Object.keys(arr[0]).some(k => /^(domain|host|host_key)$/i.test(k)) &&
      Object.keys(arr[0]).some(k => /^(name|key)$/i.test(k));
    // Search up to 3 levels deep for an array of cookie objects
    function search(val, depth) {
      if (depth > 3 || val === null || typeof val !== 'object') return null;
      if (Array.isArray(val)) return isCookieArray(val) ? val : null;
      for (const v of Object.values(val)) {
        const found = search(v, depth + 1);
        if (found) return found;
      }
      return null;
    }
    return search(obj, 0);
  } catch { return null; }
}

function decodeCookieValue(raw) {
  try {
    return decodeURIComponent(raw);
  } catch (_) {
    return raw;
  }
}

// Count columns on the raw line so a trailing empty value still occupies one;
// files padded with runs of empty columns only resolve once trimmed.
function detectNetscapeLayout(sample) {
  for (const trimFirst of [false, true]) {
    const candidates = trimFirst ? sample.map(l => l.trim()) : sample;
    const columns = mostCommonCount(candidates.map(l => l.split('\t').length));
    if (![5, 6, 7].includes(columns)) continue;
    const matching = candidates.filter(l => l.split('\t').length === columns).length;
    if (matching / candidates.length >= 0.7) return { columns, trimFirst };
  }
  return null;
}

// Lay a row out by the file's column count, not by its own field count: a
// trailing empty value would otherwise shift Name/Value/Expiration left.
function splitNetscapeRow(line, columns) {
  const parts = line.split('\t');
  if (parts.length < 5) return null;

  const fields = parts.slice(0, columns - 1).map(field => field.trim());
  while (fields.length < columns - 1) fields.push('');
  fields.push(parts.slice(columns - 1).join('\t').trim());
  return fields;
}

// Bring manually-mapped cookie rows up to parity with the auto path: normalise
// the Expiration column (epoch -> ISO) and URL-decode the Value column.
function normaliseConfigCookies(parsed) {
  if (!parsed || !parsed.rows) return parsed;
  const expiryIdx = parsed.headers.findIndex(h => h === 'Expiration');
  const valueIdx = parsed.headers.findIndex(h => h === 'Value');
  if (expiryIdx < 0 && valueIdx < 0) return parsed;

  const rows = parsed.rows.map((row) => {
    const next = row.slice();
    if (expiryIdx >= 0) next[expiryIdx] = convertCookieTimestamp(next[expiryIdx] ?? '');
    if (valueIdx >= 0) next[valueIdx] = decodeCookieValue(next[valueIdx] ?? '');
    return next;
  });
  return { headers: parsed.headers, rows };
}

export function parseCookieFile(text, config) {
  const clean = normaliseText(text);

  if (config) return normaliseConfigCookies(parseWithConfig(clean, config));

  const sanitised = stripLeadingNoiseLines(clean).trim();

  const trimmed = sanitised || clean.trim();
  if (trimmed.startsWith('[')) {
    const jsonResult = parseJSONCookies(trimmed);
    if (jsonResult) return jsonResult;
  }
  if (trimmed.startsWith('{')) {
    const arr = findCookieArrayInObject(trimmed);
    if (arr) {
      const jsonResult = parseJSONCookies(JSON.stringify(arr));
      if (jsonResult) return jsonResult;
    }
  }

  const allLines = (sanitised || clean).split('\n').filter(l => l.trim() !== '');
  if (allLines.length === 0) return null;

  const lines = allLines.filter((l) => {
    const trimmedLine = l.trim();
    if (/^#/.test(trimmedLine) && !/^#HttpOnly_/i.test(trimmedLine)) return false;
    return !isPromotionalNoiseLine(trimmedLine);
  });
  if (lines.length === 0) return null;

  const restoreTokens = parseGoogleRestoreTokens(lines.map(l => l.trim()));
  if (restoreTokens) return restoreTokens;

  const layout = detectNetscapeLayout(lines.slice(0, 20));
  if (layout) {
    const { columns: netscapeCols } = layout;
    const rows = [];
    for (const line of lines) {
      const fields = splitNetscapeRow(layout.trimFirst ? line.trim() : line, netscapeCols);
      if (!fields) continue;

      const domain = fields[0].replace(/^#HttpOnly_/i, '');
      let subDomain = '';
      let path = '';
      let secure = '';
      let expiry = '';
      let name = '';
      let rawValue = '';

      if (netscapeCols === 7) {
        [, subDomain, path, secure, expiry, name, rawValue] = fields;
      } else if (netscapeCols === 6) {
        [, path, secure, expiry, name, rawValue] = fields;
      } else {
        [, path, expiry, name, rawValue] = fields;
      }

      rows.push([domain, subDomain, path, secure, convertCookieTimestamp(expiry), name, decodeCookieValue(rawValue)]);
    }

    if (rows.length > 0) return { headers: COOKIE_HEADERS, rows };
  }

  // Fallback: try generic delimited detection (CSV, pipe, etc.)
  const format = detectFormat(sanitised || clean);
  if (format && format.type === 'delimited') {
    return parseDelimited(sanitised || clean, format);
  }

  return null;
}

export function parseAutofillFile(text, config) {
  const clean = normaliseSeparators(normaliseText(text));

  if (config) {
    const parsed = parseWithConfig(clean, config);
    return finaliseAutofillDataset(parsed) || parsed;
  }

  const format = detectFormat(clean);
  if (format && format.type === 'delimited') {
    const parsed = finaliseAutofillDataset(parseDelimited(clean, format));
    if (parsed) return parsed;
  }

  const labelledRecordParsed = parseAutofillLabelledRecords(clean);
  if (labelledRecordParsed) return labelledRecordParsed;

  // Some logs store autofills as repeated short "field-id" + "value" blocks.
  const blockParsed = parseAutofillBlocks(clean);

  const linesList = stripLeadingNoiseLines(clean).split('\n').map(line => line.trim()).filter(Boolean);
  const rows = [];

  for (const line of linesList) {
    const parsedLine = parseLooseAutofillLine(line);
    if (parsedLine) rows.push(parsedLine);
  }

  if (blockParsed && (!rows.length || blockParsed.rows.length >= rows.length)) return blockParsed;

  return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
}
