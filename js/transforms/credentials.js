// Password, Cookie, Autofill parsing.

import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import {
  KV_PATTERN,
  AUTOFILL_KV_PATTERN,
  GOOGLE_RESTORE_TOKEN_PATTERN,
  PASSWORD_KV_PATTERN,
  normaliseText,
  normaliseSeparators,
  stripLeadingNoiseLines,
  isSeparatorOnlyLine,
  classifyPasswordFieldKey,
  canonicalisePasswordExtraHeader,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
  parseWithConfig,
  buildPasswordDataset,
  finaliseCredentialDataset,
} from './delimited.js';

// Chrome stores timestamps as microseconds since 1601-01-01 (Windows epoch).
const CHROME_EPOCH_OFFSET = 11644473600000000n;

function convertCookieTimestamp(raw) {
  const trimmed = raw.trim();
  if (trimmed === '0' || trimmed === '') return 'Session';

  const num = Number(trimmed);
  if (isNaN(num) || num <= 0) return 'Session';

  try {
    let ms;

    if (num > 13000000000000000) {
      // Chrome epoch microseconds since 1601-01-01
      const bigVal = BigInt(trimmed);
      const unixMicro = bigVal - CHROME_EPOCH_OFFSET;
      ms = Number(unixMicro / 1000n);
    } else if (num > 1e12) {
      ms = num; // already milliseconds
    } else {
      ms = num * 1000; // seconds
    }

    const date = new Date(ms);
    if (isNaN(date.getTime())) return trimmed;
    return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  } catch (_) {
    return trimmed;
  }
}

function parsePasswordKeyValueRecords(text) {
  const records = [];
  let current = {};
  let hasCredentialField = false;
  let allowPasswordContinuation = false;

  const flush = () => {
    if (hasCredentialField) records.push({ ...current });
    current = {};
    hasCredentialField = false;
    allowPasswordContinuation = false;
  };

  for (const rawLine of normaliseText(text).split('\n')) {
    const line = rawLine.trim();
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
    const header = role
      ? (role === 'url' ? 'URL' : role === 'username' ? 'Username' : 'Password')
      : canonicalisePasswordExtraHeader(rawKey);

    if (line.includes('://') && line.indexOf(':') < line.indexOf('://') && !role && !['Software', 'Browser', 'Profile'].includes(header)) {
      if (allowPasswordContinuation && current.Password) {
        current.Password += '\n' + line;
      }
      continue;
    }

    if (!header) continue;
    if (hasCredentialField && current[header]) flush();

    current[header] = value;
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

  if (atPos >= 0) {
    const colonAfterAt = afterProtocol.slice(atPos + 1).indexOf(':');
    return colonAfterAt >= 0 ? afterProtocolStart + atPos + 1 + colonAfterAt : null;
  }

  const colonPositions = [];
  for (let i = 0; i < afterProtocol.length; i++) {
    if (afterProtocol[i] === ':') colonPositions.push(i);
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

function applyPasswordFallbackHeaders(parsed, format) {
  if (!parsed || format?.hasHeaderRow) return parsed;
  if (parsed.headers.some(header =>
    FIELD_PATTERNS.url.test(header)
    || FIELD_PATTERNS.username.test(header)
    || FIELD_PATTERNS.password.test(header)
  )) {
    return parsed;
  }

  const effectiveColumns = format.columns - (format.dropColumns || []).length;
  if (effectiveColumns !== 3) return parsed;

  return {
    headers: ['URL', 'Username', 'Password'],
    rows: parsed.rows,
  };
}

function finaliseAutofillDataset(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const fieldIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formField.test(h));
  const valueIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formValue.test(h));
  if (fieldIdx < 0 || valueIdx < 0) return null;

  const rows = parsed.rows
    .map(row => [(row[fieldIdx] || '').trim(), (row[valueIdx] || '').trim()])
    .filter(([name, value]) => name && value);

  return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
}

const AUTOFILL_BLOCK_MAX_LINES = 6;
const AUTOFILL_BLOCK_MAX_VALUE_LENGTH = 500;
const AUTOFILL_SPACED_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _.$\-[\]]{0,80}?)\s*:\s+(.+)$/;
const AUTOFILL_TOKEN_VALUE_PATTERN = /^([A-Za-z_$][A-Za-z0-9_.$:[\]-]*(?:\[[^\]\n]+\])*)\s+(.+)$/;
const AUTOFILL_RECORD_LABEL_KEYS = new Set(['browser', 'profile', 'name', 'field', 'key', 'label', 'value']);
const AUTOFILL_RECORD_NAME_KEYS = new Set(['name', 'field', 'key', 'label']);
const AUTOFILL_RECORD_VALUE_KEYS = new Set(['value']);
const AUTOFILL_INLINE_EXCLUDED_KEYS = new Set(['browser', 'profile', 'value']);

function normaliseAutofillFieldName(name) {
  return String(name || '').replace(/:+$/, '').replace(/\s+/g, ' ').trim();
}

function isLikelyAutofillFieldName(name) {
  const normalised = normaliseAutofillFieldName(name);
  if (!normalised || normalised.length > 120) return false;
  if (/^\d+$/.test(normalised)) return false;
  if (/^[^A-Za-z]+$/.test(normalised)) return false;
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
    const value = block.slice(1).join(' ').trim();
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
    const value = String(rawValue || '').trim();
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

  return null;
}

export function parsePasswordFile(text, config) {
  const clean = normaliseSeparators(normaliseText(text));

  // If explicit config from column mapper, use it directly
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

// Cookie parser

const COOKIE_HEADERS = ['Domain', 'SubDomain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];
const JSON_COOKIE_HEADERS = ['Domain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];

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
      get(entry, 'value'),
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

export function parseCookieFile(text, config) {
  const clean = normaliseText(text);

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  const sanitised = stripLeadingNoiseLines(clean).trim();

  // Try JSON format first
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

  const lines = (sanitised || clean).split('\n').map(l => l.trim()).filter(l => l !== '');
  if (lines.length === 0) return null;

  const restoreTokens = parseGoogleRestoreTokens(lines);
  if (restoreTokens) return restoreTokens;

  // Check for Netscape cookie format (7 tab-separated fields)
  const sample = lines.slice(0, 20);
  if (sample.length === 0) return null;
  const sevenColLines = sample.filter(l => l.split('\t').length === 7);
  if (sevenColLines.length / sample.length >= 0.7) {
    const rows = [];
    for (const line of lines) {
      const fields = line.split('\t');
      if (fields.length < 7) continue;

      const domain = fields[0];
      const subDomain = fields[1];
      const path = fields[2];
      const secure = fields[3];
      const expiration = convertCookieTimestamp(fields[4]);
      const name = fields[5];

      let value = fields[6];
      try {
        value = decodeURIComponent(value);
      } catch (_) {
        // keep raw value
      }

      rows.push([domain, subDomain, path, secure, expiration, name, value]);
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
  if (blockParsed) return blockParsed;

  const linesList = stripLeadingNoiseLines(clean).split('\n').map(line => line.trim()).filter(Boolean);
  const rows = [];

  for (const line of linesList) {
    const parsedLine = parseLooseAutofillLine(line);
    if (parsedLine) rows.push(parsedLine);
  }

  return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
}
