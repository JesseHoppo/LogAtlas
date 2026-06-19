// Parsers for structured data: sysinfo, history, downloads, bookmarks, browser metadata,
// account tokens, service artifacts, domain detections, clipboard.

import {
  KV_PATTERN,
  HISTORY_URL_PATTERN,
  CLIPBOARD_URL_PATTERN,
  BOOKMARK_HTML_PATTERN,
  JWT_TOKEN_PATTERN,
  DISCORD_TOKEN_PATTERN,
  TOKEN_VALUE_FIELD_PATTERN,
  ACCOUNT_ID_FIELD_PATTERN,
  WINDOWS_PATH_PATTERN,
  URL_INDICATOR_PATTERN,
  SYSINFO_KV_PATTERN,
  SYSINFO_CAPTURE_SECTION_PATTERN,
  SYSINFO_STRUCTURED_KEY_PATTERN,
  SYSINFO_MULTILINE_KEY_PATTERN,
  normaliseText,
  normaliseSeparators,
  stripLeadingNoiseLines,
  decodeHtmlEntities,
  isPromotionalNoiseLine,
  LINE_CONTAINS_HOST,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
  parseBlocks,
  parseWithConfig,
} from './delimited.js';
import { LIMITS } from '../core/definitions/patterns.js';

function flattenObjectEntries(value, prefix = '', out = [], depth = 0) {
  if (value == null) return out;
  if (depth > LIMITS.flattenMaxDepth || out.length >= LIMITS.flattenMaxEntries) return out;

  if (Array.isArray(value)) {
    if (value.every(item => item == null || typeof item !== 'object')) {
      out.push([prefix || 'Value', value.map(item => item == null ? '' : String(item)).join(', ')]);
      return out;
    }
    value.forEach((item, index) => flattenObjectEntries(item, prefix ? `${prefix}[${index}]` : `[${index}]`, out, depth + 1));
    return out;
  }

  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const nextPrefix = prefix ? `${prefix}.${key}` : key;
      flattenObjectEntries(child, nextPrefix, out, depth + 1);
    }
    return out;
  }

  out.push([prefix || 'Value', String(value)]);
  return out;
}

function inferTokenKind(value, accountId = '', hint = '') {
  const token = String(value || '').trim();
  const lowerHint = String(hint || '').toLowerCase();

  if (!token && accountId) return 'Account ID';
  if (/^1\/\//.test(token)) return 'Google OAuth refresh token';
  if (token && /restore/.test(lowerHint)) return 'Restore Token';
  if (/^EAAB/i.test(token)) return 'Facebook Token';
  if (/^eyJ/.test(token) && JWT_TOKEN_PATTERN.test(token)) return /steam/i.test(lowerHint) || accountId ? 'Steam JWT' : 'JWT';
  if (DISCORD_TOKEN_PATTERN.test(token)) return 'Discord Token';
  if (accountId) return 'Token + Account ID';
  return 'Token';
}

function sanitiseStructuredValue(value, maxLength = 500) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 1) + '\u2026';
}

function looksLikeHistoryUrl(value) {
  return HISTORY_URL_PATTERN.test(String(value || '').trim());
}

function extractHistoryRowsFromRawUrls(lines) {
  const rows = lines
    .map(line => line.trim())
    .filter(line => line && !isPromotionalNoiseLine(line) && looksLikeHistoryUrl(line))
    .map(url => [url, '', '1', '']);

  return rows.length > 0 ? rows : null;
}

function hasParsedHistoryUrls(parsed) {
  if (!parsed?.rows?.length || !parsed?.headers?.length) return false;
  const urlIdx = parsed.headers.findIndex(header => /^url$/i.test(header));
  if (urlIdx < 0) return false;
  return parsed.rows.some(row => looksLikeHistoryUrl(row[urlIdx] || ''));
}

function isLikelyAccountIdentifier(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(text)) return true;
  if (/^\d{6,}$/.test(text)) return true;
  if (/^(?:fake-)?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(text)) return true;
  return /^fake-[a-z0-9-]{8,}$/i.test(text);
}

function isLikelyStandaloneToken(value) {
  const text = String(value || '').trim();
  if (!text || text.length < 6 || /\s/.test(text)) return false;
  if (DISCORD_TOKEN_PATTERN.test(text) || JWT_TOKEN_PATTERN.test(text) || /^1\/\//.test(text) || /^EAAB/i.test(text)) return true;
  if (/^[A-F0-9]{8,}$/i.test(text)) return true;
  if (/^[A-Za-z0-9._-]{8,}$/.test(text)) return true;
  return /^[A-Za-z0-9._:-]{8,}$/.test(text);
}

function splitGenericTokenPair(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(trimmed)) return null;

  const colonIdx = trimmed.indexOf(':');
  if (colonIdx <= 0 || colonIdx === trimmed.length - 1) return null;
  if (trimmed.indexOf(':', colonIdx + 1) !== -1) return null;

  const left = trimmed.slice(0, colonIdx).trim();
  const right = trimmed.slice(colonIdx + 1).trim();
  if (!left || !right) return null;

  const leftAccount = isLikelyAccountIdentifier(left);
  const rightAccount = isLikelyAccountIdentifier(right);
  const leftToken = isLikelyStandaloneToken(left);
  const rightToken = isLikelyStandaloneToken(right);

  if (left.length <= 4 && !/[A-Za-z0-9]/.test(left) && /^\d{6,}$/.test(right)) {
    return { token: '', accountId: right };
  }
  if (leftAccount && !rightAccount) {
    return { token: right, accountId: left };
  }
  if (rightAccount && !leftAccount) {
    return { token: left, accountId: right };
  }
  if (rightToken && !leftToken) {
    return { token: right, accountId: left };
  }
  if (leftToken && !rightToken) {
    return { token: left, accountId: right };
  }
  return right.length >= left.length
    ? { token: right, accountId: left }
    : { token: left, accountId: right };
}

function removePromotionalNoise(text) {
  return stripLeadingNoiseLines(text)
    .split('\n')
    .filter(line => !line.trim() || !isPromotionalNoiseLine(line) || LINE_CONTAINS_HOST.test(line))
    .join('\n');
}

function normaliseSysinfoLine(rawLine) {
  return String(rawLine || '')
    .trim()
    .replace(/^[\p{So}\p{Sk}\u200d\ufe0f]+\s*/u, '')
    .replace(/^[-*•]\s*/, '');
}

function isStructuredSysinfoSection(line) {
  return SYSINFO_CAPTURE_SECTION_PATTERN.test(line)
    || /^\[(?:Network|System|User|Hardware|Software|Process(?:es)?|Browser(?:es)?|Environment)\]$/i.test(line);
}

function isStructuredSysinfoKey(key) {
  return SYSINFO_STRUCTURED_KEY_PATTERN.test(String(key || '').trim());
}

function parseSystemInfoTextEntries(text, requireStructuredStart = true) {
  const entries = {};
  let collecting = !requireStructuredStart;
  let lastKey = null;
  let pendingKey = null;
  let pendingValues = [];

  const commitPending = () => {
    if (!pendingKey || pendingValues.length === 0) {
      pendingKey = null;
      pendingValues = [];
      return;
    }
    const value = pendingValues.join(', ');
    if (value && !entries[pendingKey]) {
      entries[pendingKey] = value;
    }
    pendingKey = null;
    pendingValues = [];
  };

  for (const rawLine of normaliseText(text).split('\n')) {
    const trimmed = rawLine.trim();
    const clean = normaliseSysinfoLine(rawLine);
    const isIndented = /^[\t ]+/.test(rawLine);

    if (!trimmed) {
      commitPending();
      lastKey = null;
      continue;
    }

    if (isStructuredSysinfoSection(clean)) {
      commitPending();
      collecting = true;
      lastKey = null;
      continue;
    }

    const kvMatch = clean.match(SYSINFO_KV_PATTERN);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      const value = kvMatch[2].trim();
      const structuredKey = isStructuredSysinfoKey(key);

      if (!collecting && requireStructuredStart && !structuredKey) {
        continue;
      }

      if (structuredKey) collecting = true;
      commitPending();

      if (value) {
        if (!entries[key]) entries[key] = value;
        lastKey = key;
      } else if (collecting && (structuredKey || SYSINFO_MULTILINE_KEY_PATTERN.test(key))) {
        pendingKey = key;
        pendingValues = [];
        lastKey = null;
      } else {
        lastKey = null;
      }
      continue;
    }

    if (!collecting) continue;

    if (pendingKey) {
      if (clean && !SYSINFO_KV_PATTERN.test(clean) && !isStructuredSysinfoSection(clean) && (isIndented || /^[-*•]/.test(trimmed))) {
        pendingValues.push(clean);
        continue;
      }
      commitPending();
    }

    if (lastKey && isIndented && clean && !SYSINFO_KV_PATTERN.test(clean) && !isStructuredSysinfoSection(clean)) {
      entries[lastKey] += ', ' + clean;
    }
  }

  commitPending();
  return entries;
}

export function parseSystemInfoFile(text, fileName = '') {
  const clean = normaliseText(text);

  if (/\.json$/i.test(fileName)) {
    try {
      if (clean.length > LIMITS.jsonParseMaxBytes) throw new Error('json too large');
      const entries = {};
      for (const [key, value] of flattenObjectEntries(JSON.parse(clean))) {
        const normalisedKey = String(key || '').trim();
        const normalisedValue = String(value || '').trim();
        if (!normalisedKey || !normalisedValue || normalisedValue === 'null' || normalisedValue === '[]') continue;
        if (!entries[normalisedKey]) entries[normalisedKey] = normalisedValue;
      }
      if (Object.keys(entries).length > 0) {
        return {
          headers: ['Key', 'Value'],
          rows: Object.entries(entries),
          entries,
        };
      }
    } catch {
      /* not JSON */
    }
  }

  let entries = parseSystemInfoTextEntries(clean, true);
  if (Object.keys(entries).length === 0) {
    entries = parseSystemInfoTextEntries(clean, false);
  }

  if (Object.keys(entries).length === 0) return null;

  return {
    headers: ['Key', 'Value'],
    rows: Object.entries(entries),
    entries,
  };
}

export function parseHistoryFile(text, config) {
  const clean = normaliseText(text);

  if (config) return parseWithConfig(clean, config);

  const normalised = removePromotionalNoise(normaliseSeparators(clean));
  const nonNoiseLines = normalised
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !isPromotionalNoiseLine(line));

  const rawUrlRows = extractHistoryRowsFromRawUrls(nonNoiseLines);
  if (rawUrlRows && rawUrlRows.length / nonNoiseLines.length >= 0.6) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows: rawUrlRows };
  }

  const blockRows = [];
  for (const block of normalised.split(/\n\s*\n+/).filter(block => block.trim())) {
    let url = '';
    let title = '';
    let visits = '1';
    let lastVisit = '';

    for (const rawLine of block.split('\n')) {
      const line = rawLine.trim();
      if (!line || isPromotionalNoiseLine(line)) continue;
      const match = line.match(/^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*:\s*(.*)$/);
      if (!match) continue;

      const key = match[1].trim().toLowerCase();
      const value = match[2].trim();
      if (!value) continue;

      if (key === 'url' && looksLikeHistoryUrl(value)) url = value;
      else if (key === 'title' || key === 'page title') title = value;
      else if (/^(?:visit\s*count|visits?|count)$/.test(key)) visits = value;
      else if (/^(?:visit\s*time|last\s*visit|time|date|timestamp)$/.test(key)) lastVisit = value;
    }

    if (url) blockRows.push([url, title, visits || '1', lastVisit]);
  }
  if (blockRows.length > 0) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows: blockRows };
  }

  const format = detectFormat(normalised);
  if (format && format.type === 'delimited') {
    const parsed = parseDelimited(normalised, format);
    if (hasParsedHistoryUrls(parsed)) return parsed;
  }

  if (format && format.type === 'block') {
    const result = parseBlocks(normalised, format.headers);
    if (result && result.rows.length > 0) {
      const indices = {};
      for (let i = 0; i < result.headers.length; i++) {
        if (/^url$/i.test(result.headers[i])) indices.url = i;
        else if (/^title$/i.test(result.headers[i])) indices.title = i;
        else if (/^(?:time|last\s*visit|date)$/i.test(result.headers[i])) indices.time = i;
        else if (/^visit\s*count$/i.test(result.headers[i])) indices.visits = i;
      }
      if (typeof indices.url === 'number') {
        const headers = ['URL', 'Title', 'Visits', 'Last Visit'];
        const rows = result.rows.map(row => [
          row[indices.url] || '',
          row[indices.title ?? -1] || '',
          row[indices.visits ?? -1] || '1',
          row[indices.time ?? -1] || '',
        ]);
        if (rows.some(row => looksLikeHistoryUrl(row[0]))) {
          return { headers, rows };
        }
      }
    }
  }

  const lines = nonNoiseLines;
  const rows = [];
  for (const line of lines) {
    const separatorIndex = line.indexOf(' - ');
    if (separatorIndex > 0) {
      const prefix = line.slice(0, separatorIndex).trim();
      const remainder = line.slice(separatorIndex + 3).trim();
      if (/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?$/.test(prefix) && looksLikeHistoryUrl(remainder)) {
        rows.push([remainder, '', '1', prefix]);
        continue;
      }
    }
    if (looksLikeHistoryUrl(line)) {
      rows.push([line, '', '1', '']);
    }
  }
  if (rows.length > 0) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows };
  }

  return null;
}

export function parseDownloadFile(text) {
  const clean = normaliseText(text);
  const normalised = normaliseSeparators(clean);

  const format = detectFormat(normalised);
  if (format && format.type === 'delimited') {
    return parseDelimited(normalised, format);
  }

  if (format && format.type === 'block') {
    const result = parseBlocks(normalised, format.headers);
    if (result && result.rows.length > 0) {
      const indices = {};
      for (let i = 0; i < result.headers.length; i++) {
        if (/^url$/i.test(result.headers[i])) indices.url = i;
        else if (/^filename$/i.test(result.headers[i])) indices.file = i;
        else if (/^(?:recived|received)\s*bytes$/i.test(result.headers[i])) indices.size = i;
      }
      const headers = ['File Path', 'Source URL', 'File Size'];
      const rows = result.rows.map(row => [
        row[indices.file ?? -1] || '',
        row[indices.url ?? -1] || '',
        row[indices.size ?? -1] || '',
      ]);
      return { headers, rows };
    }
  }

  const lines = normalised.split('\n');
  const rows = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    if (!line) { i++; continue; }

    if (/^[A-Z]:\\|^\/|\\/.test(line)) {
      const nextIdx = i + 1;
      let url = '';
      if (nextIdx < lines.length) {
        const next = lines[nextIdx].trim();
        if (/^https?:\/\//i.test(next)) {
          url = next;
          i = nextIdx + 1;
        } else {
          i++;
        }
      } else {
        i++;
      }
      rows.push([line, url]);
    } else if (/^https?:\/\//i.test(line)) {
      rows.push(['', line]);
      i++;
    } else {
      i++;
    }
  }

  if (rows.length > 0) {
    return { headers: ['File Path', 'Source URL'], rows };
  }
  return null;
}

function normaliseDomainDetectTarget(target) {
  return target
    .replace(/^[-*•]\s+/, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/^[,;]+|[,;]+$/g, '')
    .trim();
}

const DOMAIN_DETECT_TOKEN = /(?:\[([^\]]+)\]\s*)?([^,()[\]]+?)\s*\((\d+)\)/g;

function looksLikeHostTarget(target) {
  const host = target.replace(/^https?:\/\//i, '').replace(/^www\./i, '');
  return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(host);
}

function extractDomainDetectEntries(segment, section) {
  const rows = [];
  const clean = segment.trim();
  if (!clean) return rows;

  let matched = false;
  let lastLabel = '';
  DOMAIN_DETECT_TOKEN.lastIndex = 0;
  let match;
  while ((match = DOMAIN_DETECT_TOKEN.exec(clean)) !== null) {
    if (match[1] != null) lastLabel = match[1].trim();
    const target = normaliseDomainDetectTarget(match[2]);
    const count = match[3] || '1';
    if (!target || isPromotionalNoiseLine(target)) continue;
    rows.push([section || 'General', lastLabel || '', target, count]);
    matched = true;
  }
  if (matched) return rows;

  const plainTargets = clean
    .split(/\s*,\s*/)
    .map(normaliseDomainDetectTarget)
    .filter(target => target && !isPromotionalNoiseLine(target) && looksLikeHostTarget(target));
  for (const target of plainTargets) {
    rows.push([section || 'General', '', target, '1']);
  }
  return rows;
}

function splitDomainDetectSection(line) {
  const colonIdx = line.indexOf(':');
  if (colonIdx < 0) return null;

  const header = line.slice(0, colonIdx).trim();
  const rest = line.slice(colonIdx + 1).trim();
  if (!header) return null;

  if (/^\/\//.test(rest)) return null;
  if (/^[A-Za-z]$/.test(header) && /^[\\/]/.test(rest)) return null;
  if (!/^[A-Za-z][A-Za-z0-9 _/&()[\]-]{0,60}$/.test(header)) return null;

  return { header, rest };
}

export function parseDomainDetectFile(text) {
  const clean = removePromotionalNoise(normaliseSeparators(normaliseText(text)));
  const rows = [];
  let currentSection = 'General';

  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    if (isPromotionalNoiseLine(line) && !LINE_CONTAINS_HOST.test(line)) continue;

    const sectionLine = splitDomainDetectSection(line);
    if (sectionLine) {
      const { header, rest } = sectionLine;
      if (!rest) {
        currentSection = header || currentSection;
        continue;
      }
      currentSection = header || currentSection;
      rows.push(...extractDomainDetectEntries(rest, currentSection));
      continue;
    }

    rows.push(...extractDomainDetectEntries(line, currentSection));
  }

  return rows.length > 0 ? {
    headers: ['Section', 'Label', 'Target', 'Count'],
    rows,
  } : null;
}

function classifyClipboardEntry(text, urls) {
  const compact = text.trim();
  const lower = compact.toLowerCase();

  if (/^(?:[a-z]+(?:\s+[a-z]+){11,23})$/i.test(compact) && compact.split(/\s+/).length >= 12) {
    return 'Seed Phrase';
  }
  if (/^(?:0x[a-f0-9]{40}|bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})$/i.test(compact)) {
    return 'Wallet';
  }
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(compact)) {
    return 'Email';
  }
  if (/^(?:[A-Z]:\\|\\\\|\/)/i.test(compact)) {
    return 'Path';
  }
  if (/\b(?:powershell|pwsh|cmd(?:\.exe)?|mshta|rundll32|regsvr32|wscript|cscript|bitsadmin|curl|start|certutil)\b/i.test(lower)) {
    return 'Command';
  }
  if (urls.length > 0) {
    return 'URL';
  }
  return 'Text';
}

function splitClipboardEntries(clean) {
  const blocks = clean.split(/\n\s*\n/).map(block => block.trim()).filter(Boolean);
  if (blocks.length > 1) return blocks;

  const lines = clean.split('\n').map(line => line.trim()).filter(Boolean);
  if (lines.length > 1 && lines.every(line =>
    /^(?:https?:\/\/|[A-Z]:\\|\\\\|\/|[^@\s]+@[^@\s]+\.[^@\s]+)$/i.test(line)
  )) {
    return lines;
  }

  return blocks.length > 0 ? blocks : lines;
}

export function parseClipboardFile(text) {
  const clean = normaliseText(text).trim();
  if (!clean) return null;

  const rows = [];
  for (const entryText of splitClipboardEntries(clean)) {
    const trimmed = entryText.trim();
    if (!trimmed) continue;
    const urls = trimmed.match(CLIPBOARD_URL_PATTERN) || [];
    const lines = trimmed.split('\n').map(line => line.trim()).filter(Boolean);
    rows.push([
      classifyClipboardEntry(trimmed, urls),
      trimmed,
      urls.join(' '),
      String(lines.length),
      String(trimmed.length),
    ]);
  }

  return rows.length > 0 ? {
    headers: ['Type', 'Text', 'URLs', 'Line Count', 'Length'],
    rows,
  } : null;
}

function parseBookmarkJson(value, folder = '', rows = []) {
  if (!value || typeof value !== 'object') return rows;

  if (Array.isArray(value)) {
    value.forEach((item) => parseBookmarkJson(item, folder, rows));
    return rows;
  }

  const url = value.url || value.href || '';
  const title = value.title || value.name || value.label || '';
  const bookmarkFolder = value.folder || folder;
  const nextFolder = value.folder || (url ? folder : title || folder);
  if (url) {
    rows.push([url, title, bookmarkFolder || '']);
  }

  const childKeys = ['children', 'roots', 'bookmarks', 'items'];
  for (const key of childKeys) {
    if (value[key]) parseBookmarkJson(value[key], nextFolder || folder, rows);
  }

  return rows;
}

export function parseBookmarkFile(text) {
  const clean = normaliseSeparators(normaliseText(text)).trim();
  if (!clean) return null;

  if ((clean.startsWith('{') || clean.startsWith('[')) && clean.length <= LIMITS.jsonParseMaxBytes) {
    try {
      const obj = JSON.parse(clean);
      const rows = parseBookmarkJson(obj);
      if (rows.length > 0) {
        return { headers: ['URL', 'Title', 'Folder'], rows };
      }
    } catch {
      /* not JSON */
    }
  }

  const htmlRows = [];
  let match;
  BOOKMARK_HTML_PATTERN.lastIndex = 0;
  while ((match = BOOKMARK_HTML_PATTERN.exec(clean)) !== null) {
    const url = decodeHtmlEntities(match[1] || match[2] || '').trim();
    const title = decodeHtmlEntities(match[3] || '').replace(/<[^>]+>/g, '').trim();
    if (url) htmlRows.push([url, title, '']);
  }
  if (htmlRows.length > 0) {
    return { headers: ['URL', 'Title', 'Folder'], rows: htmlRows };
  }

  const blockRows = [];
  for (const block of clean.split(/\n\s*\n/).filter(Boolean)) {
    let url = '';
    let title = '';
    let folder = '';
    for (const rawLine of block.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;
      const kv = line.match(KV_PATTERN);
      if (!kv) continue;
      const key = kv[1].trim().toLowerCase();
      const value = kv[2].trim();
      if (key === 'url') {
        if (url) {
          blockRows.push([url, title, folder]);
          title = '';
          folder = '';
        }
        url = value;
      } else if (key === 'title' || key === 'name') title = value;
      else if (key === 'folder' || key === 'path') folder = value;
    }
    if (url) blockRows.push([url, title, folder]);
  }
  if (blockRows.length > 0) {
    return { headers: ['URL', 'Title', 'Folder'], rows: blockRows };
  }

  const fallbackRows = clean.split('\n')
    .map(line => line.trim())
    .filter(line => /^https?:\/\//i.test(line) || /^chrome:\/\//i.test(line))
    .map(url => [url, '', '']);
  return fallbackRows.length > 0 ? { headers: ['URL', 'Title', 'Folder'], rows: fallbackRows } : null;
}

export function parseBrowserMetadataFile(text) {
  const clean = normaliseText(text).trim();
  if (!clean) return null;

  if ((clean.startsWith('{') || clean.startsWith('[')) && clean.length <= LIMITS.jsonParseMaxBytes) {
    try {
      const obj = JSON.parse(clean);
      const rows = flattenObjectEntries(obj)
        .map(([key, value]) => [key, sanitiseStructuredValue(value)])
        .filter(([, value]) => value);
      if (rows.length > 0) return { headers: ['Key', 'Value'], rows };
    } catch {
      /* not JSON */
    }
  }

  const rows = [];
  const lines = clean.split('\n').map(line => line.trim()).filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*(?:=\s*|:\s+)(.*)$/);
    if (match) {
      rows.push([match[1].trim(), sanitiseStructuredValue(match[2])]);
    } else {
      rows.push([rows.length === 0 && lines.length === 1 ? 'Value' : `Entry ${rows.length + 1}`, sanitiseStructuredValue(line)]);
    }
  }

  return rows.length > 0 ? { headers: ['Key', 'Value'], rows } : null;
}

export function parseAccountTokenFile(text, hint = '') {
  const clean = removePromotionalNoise(normaliseSeparators(normaliseText(text)));
  if (!clean) return null;

  const rows = [];
  const note = /restore/i.test(hint) ? 'Restore file'
    : /fbfastcheck/i.test(hint) ? 'FBFastCheck'
    : /googletokens/i.test(hint) ? 'GoogleTokens'
    : /googleaccounts/i.test(hint) ? 'GoogleAccounts'
    : '';

  const appendRow = (tokenValue, accountValue = '', extraNote = '', hintText = '') => {
    const token = sanitiseStructuredValue(tokenValue, 1200);
    const accountId = sanitiseStructuredValue(accountValue, 300);
    const rowNote = [note, extraNote].filter(Boolean).join('; ');

    if (token && (/\s/.test(token) || !/[A-Za-z0-9]/.test(token))) return;
    if (!token && !accountId) return;
    rows.push([
      inferTokenKind(token, accountId, `${hint} ${hintText}`.trim()),
      token,
      accountId,
      rowNote,
    ]);
  };

  const blocks = clean.split(/\n\s*\n+/).filter(block => block.trim());
  for (const block of blocks) {
    let token = '';
    let accountId = '';
    let extraNote = '';
    let headerHint = '';
    const blockTokens = [];

    for (const rawLine of block.split('\n')) {
      const line = rawLine.trim();
      if (!line || isPromotionalNoiseLine(line)) continue;

      const headerMatch = line.match(/^=+\s*(.*?)\s*=+$/);
      if (headerMatch) {
        headerHint = sanitiseStructuredValue(headerMatch[1], 240);
        const userMatch = headerHint.match(/\buser=([^;=\s]+)/i);
        if (userMatch && !accountId) accountId = userMatch[1].trim();
        continue;
      }

      let match = line.match(/^(?:token(?:\s+\d+)?|decrypted)\s*[:=]\s*(\S{6,})$/i);
      if (match) {
        blockTokens.push(match[1].trim());
        token = match[1].trim();
        continue;
      }

      match = line.match(/^(?:username|user|email|account)\s*[:=]\s*(.+)$/i);
      if (match) {
        accountId = match[1].trim();
        continue;
      }

      match = line.match(/^(?:profile|host)\s*[:=]\s*(.+)$/i);
      if (match) {
        const label = /^profile/i.test(line) ? 'Profile' : 'Host';
        extraNote = [extraNote, `${label}: ${sanitiseStructuredValue(match[1], 240)}`].filter(Boolean).join('; ');
      }
    }

    if (blockTokens.length > 1) {
      for (const blockToken of blockTokens) {
        appendRow(blockToken, accountId, extraNote, headerHint);
      }
      continue;
    }

    if (token || accountId) {
      appendRow(token, accountId, extraNote, headerHint);
    }
  }

  if (rows.length > 0) {
    return {
      headers: ['Type', 'Value', 'Account ID', 'Note'],
      rows,
    };
  }

  const lines = clean
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !isPromotionalNoiseLine(line));

  for (const line of lines) {
    let accountId = '';
    let token = '';

    let match = line.match(/^([^:\s]{20,})\s*:\s*(\d{6,})$/);
    if (match) {
      token = match[1].trim();
      accountId = match[2].trim();
    } else {
      match = line.match(/^(\d{6,})\s*:\s*(\S{6,})$/);
      if (match) {
        accountId = match[1].trim();
        token = match[2].trim();
      } else {
        match = line.match(/^(?:token(?:\s+\d+)?|decrypted)\s*[:=]\s*(\S{6,})$/i);
        if (match) {
          token = match[1].trim();
        } else {
          match = line.match(TOKEN_VALUE_FIELD_PATTERN);
          if (match) {
            token = match[1].trim();
          } else {
            match = line.match(ACCOUNT_ID_FIELD_PATTERN);
            if (match) {
              accountId = match[1].trim();
            } else {
              const genericPair = splitGenericTokenPair(line);
              if (genericPair) {
                token = genericPair.token;
                accountId = genericPair.accountId;
              } else {
                match = line.match(/^(?:username|user|email|account)\s*[:=]\s*(.+)$/i);
                if (match) {
                  accountId = match[1].trim();
                } else if (/^\d{6,}$/.test(line)) {
                  accountId = line;
                } else if (DISCORD_TOKEN_PATTERN.test(line) || JWT_TOKEN_PATTERN.test(line) || /^1\/\//.test(line) || /^EAAB/i.test(line)) {
                  token = line;
                }
              }
            }
          }
        }
      }
    }

    appendRow(token, accountId, '', '');
  }

  return rows.length > 0 ? {
    headers: ['Type', 'Value', 'Account ID', 'Note'],
    rows,
  } : null;
}

function parseStructuredServiceBlocks(clean) {
  const rows = [];
  const blocks = clean.split(/\n\s*\n/).filter(block => block.trim());
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const record = {};
    for (const rawLine of block.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;
      const match = line.match(/^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*(?:=\s*|:\s+)(.*)$/);
      if (!match) continue;
      record[match[1].trim()] = sanitiseStructuredValue(match[2]);
    }
    const section = record['Account Name'] || record['Display Name'] || record['Email'] || record.clsid || `Record ${i + 1}`;
    for (const [key, value] of Object.entries(record)) {
      if (!value) continue;
      rows.push([section, key, value]);
    }
  }
  return rows;
}

function parseThunderbirdPrefs(clean) {
  const rows = [];

  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line || isPromotionalNoiseLine(line)) continue;

    const match = line.match(/^user_pref\("([^"]+)",\s*(.+)\);$/);
    if (!match) continue;

    const key = match[1].trim();
    let value = match[2].trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\"/g, '"');
    }

    const parts = key.split('.');
    const section = parts.slice(0, Math.min(parts.length, 3)).join('.');
    rows.push([section || 'Preferences', key, sanitiseStructuredValue(value, 1200)]);
  }

  return rows;
}

export function parseServiceArtifactFile(text) {
  const clean = removePromotionalNoise(normaliseText(text)).trim();
  if (!clean) return null;

  if ((clean.startsWith('{') || clean.startsWith('[')) && clean.length <= LIMITS.jsonParseMaxBytes) {
    try {
      const obj = JSON.parse(clean);
      const rows = flattenObjectEntries(obj)
        .map(([key, value]) => ['JSON', key, sanitiseStructuredValue(value)])
        .filter(([, , value]) => value);
      if (rows.length > 0) return { headers: ['Section', 'Key', 'Value'], rows };
    } catch {
      /* not JSON */
    }
  }

  const thunderbirdRows = parseThunderbirdPrefs(clean);
  if (thunderbirdRows.length > 0) {
    return { headers: ['Section', 'Key', 'Value'], rows: thunderbirdRows };
  }

  const blockRows = parseStructuredServiceBlocks(clean);
  if (blockRows.length > 0) {
    return { headers: ['Section', 'Key', 'Value'], rows: blockRows };
  }

  const kvRows = [];
  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(/^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*(?:=\s*|:\s+)(.*)$/);
    if (match) {
      kvRows.push(['Config', match[1].trim(), sanitiseStructuredValue(match[2])]);
    }
  }
  if (kvRows.length > 0) {
    return { headers: ['Section', 'Key', 'Value'], rows: kvRows };
  }

  const indicatorRows = [];
  const seen = new Set();

  for (const matchText of clean.match(URL_INDICATOR_PATTERN) || []) {
    const value = sanitiseStructuredValue(matchText);
    if (!seen.has(`url:${value}`)) {
      seen.add(`url:${value}`);
      indicatorRows.push(['Indicator', 'URL', value]);
    }
  }

  for (const matchText of clean.match(WINDOWS_PATH_PATTERN) || []) {
    const value = sanitiseStructuredValue(matchText);
    if (!seen.has(`path:${value}`)) {
      seen.add(`path:${value}`);
      indicatorRows.push(['Indicator', 'Path', value]);
    }
  }

  const tokenCandidates = clean.match(/[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{4,}\.[A-Za-z0-9._-]{10,}/g) || [];
  for (const candidate of tokenCandidates.slice(0, 10)) {
    const value = sanitiseStructuredValue(candidate, 300);
    if (!seen.has(`token:${value}`)) {
      seen.add(`token:${value}`);
      indicatorRows.push(['Indicator', inferTokenKind(value), value]);
    }
  }

  return indicatorRows.length > 0 ? {
    headers: ['Section', 'Key', 'Value'],
    rows: indicatorRows,
  } : null;
}
