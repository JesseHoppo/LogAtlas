// Parsers for structured data: sysinfo, history, downloads, bookmarks, browser metadata,
// account tokens, service artifacts, domain detections, clipboard.

import {
  KV_PATTERN,
  HISTORY_URL_PATTERN,
  DOMAIN_DETECT_LABELED_ENTRY,
  DOMAIN_DETECT_UNLABELED_ENTRY,
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
  normalizeText,
  normalizeSeparators,
  stripLeadingNoiseLines,
  decodeHtmlEntities,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
  parseBlocks,
  parseWithConfig,
} from './delimited.js';

function isDecorativeTokenLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return true;
  if (/^telegram\s*:/i.test(trimmed) || /t\.me\/[^\s]+/i.test(trimmed)) return true;
  if (/^[*=_~#-]{3,}$/.test(trimmed) || /^\*+\s*$/.test(trimmed)) return true;

  const inner = trimmed
    .replace(/^\*+\s*/, '')
    .replace(/\s*\*+$/, '')
    .trim();

  if (!inner) return true;
  if (!/[A-Za-z0-9]/.test(inner)) return true;
  if (/^[_\\/|() -]+$/.test(inner)) return true;
  if (inner.includes('|') && /^[A-Za-z|()\s]+$/.test(inner) && inner.replace(/[^A-Za-z]/g, '').length >= 4) {
    return true;
  }

  return false;
}

function flattenObjectEntries(value, prefix = '', out = []) {
  if (value == null) return out;

  if (Array.isArray(value)) {
    if (value.every(item => item == null || typeof item !== 'object')) {
      out.push([prefix || 'Value', value.map(item => item == null ? '' : String(item)).join(', ')]);
      return out;
    }
    value.forEach((item, index) => flattenObjectEntries(item, prefix ? `${prefix}[${index}]` : `[${index}]`, out));
    return out;
  }

  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const nextPrefix = prefix ? `${prefix}.${key}` : key;
      flattenObjectEntries(child, nextPrefix, out);
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
  if (token && /restore/.test(lowerHint)) return 'Restore Token';
  if (/^1\/\//.test(token)) return /restore/i.test(lowerHint) ? 'Restore Token' : 'Google OAuth Token';
  if (/^EAAB/i.test(token)) return 'Facebook Token';
  if (DISCORD_TOKEN_PATTERN.test(token)) return 'Discord Token';
  if (JWT_TOKEN_PATTERN.test(token)) return /steam/i.test(lowerHint) || accountId ? 'Steam JWT' : 'JWT';
  if (accountId) return 'Token + Account ID';
  return 'Token';
}

function sanitizeStructuredValue(value, maxLength = 500) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 1) + '\u2026';
}

function normalizeSysinfoLine(rawLine) {
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

  for (const rawLine of normalizeText(text).split('\n')) {
    const trimmed = rawLine.trim();
    const clean = normalizeSysinfoLine(rawLine);
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
  const clean = normalizeText(text);

  if (/\.json$/i.test(fileName)) {
    try {
      const entries = {};
      for (const [key, value] of flattenObjectEntries(JSON.parse(clean))) {
        const normalizedKey = String(key || '').trim();
        const normalizedValue = String(value || '').trim();
        if (!normalizedKey || !normalizedValue || normalizedValue === 'null' || normalizedValue === '[]') continue;
        if (!entries[normalizedKey]) entries[normalizedKey] = normalizedValue;
      }
      if (Object.keys(entries).length > 0) {
        return {
          headers: ['Key', 'Value'],
          rows: Object.entries(entries),
          entries,
        };
      }
    } catch {
      // fall back to text parsing
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
  const clean = normalizeText(text);

  if (config) return parseWithConfig(clean, config);

  const normalized = normalizeSeparators(clean);

  const format = detectFormat(normalized);
  if (format && format.type === 'delimited') {
    return parseDelimited(normalized, format);
  }

  if (format && format.type === 'block') {
    const result = parseBlocks(normalized, format.headers);
    if (result && result.rows.length > 0) {
      const indices = {};
      for (let i = 0; i < result.headers.length; i++) {
        if (/^url$/i.test(result.headers[i])) indices.url = i;
        else if (/^title$/i.test(result.headers[i])) indices.title = i;
        else if (/^(?:time|last\s*visit|date)$/i.test(result.headers[i])) indices.time = i;
        else if (/^visit\s*count$/i.test(result.headers[i])) indices.visits = i;
      }
      const headers = ['URL', 'Title', 'Visits', 'Last Visit'];
      const rows = result.rows.map(row => [
        row[indices.url ?? -1] || '',
        row[indices.title ?? -1] || '',
        row[indices.visits ?? -1] || '1',
        row[indices.time ?? -1] || '',
      ]);
      return { headers, rows };
    }
  }

  const lines = normalized.split('\n').map(l => l.trim()).filter(l => l);
  const rows = [];
  for (const line of lines) {
    const separatorIndex = line.indexOf(' - ');
    if (separatorIndex > 0) {
      const prefix = line.slice(0, separatorIndex).trim();
      const remainder = line.slice(separatorIndex + 3).trim();
      if (/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?$/.test(prefix) && HISTORY_URL_PATTERN.test(remainder)) {
        rows.push([remainder, '', '1', prefix]);
        continue;
      }
    }
    if (HISTORY_URL_PATTERN.test(line)) {
      rows.push([line, '', '1', '']);
    }
  }
  if (rows.length > 0) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows };
  }

  return null;
}

export function parseDownloadFile(text) {
  const clean = normalizeText(text);
  const normalized = normalizeSeparators(clean);

  const format = detectFormat(normalized);
  if (format && format.type === 'delimited') {
    return parseDelimited(normalized, format);
  }

  if (format && format.type === 'block') {
    const result = parseBlocks(normalized, format.headers);
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

  const lines = normalized.split('\n');
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

function normalizeDomainDetectTarget(target) {
  return target
    .replace(/^[-*•]\s+/, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/^[,;]+|[,;]+$/g, '')
    .trim();
}

function extractDomainDetectEntries(segment, section) {
  const rows = [];
  const clean = segment.trim();
  if (!clean) return rows;

  let matched = false;
  DOMAIN_DETECT_LABELED_ENTRY.lastIndex = 0;
  let match;
  while ((match = DOMAIN_DETECT_LABELED_ENTRY.exec(clean)) !== null) {
    const label = match[1].trim();
    const target = normalizeDomainDetectTarget(match[2]);
    const count = match[3] || '1';
    if (!target) continue;
    rows.push([section || 'General', label, target, count]);
    matched = true;
  }
  if (matched) return rows;

  DOMAIN_DETECT_UNLABELED_ENTRY.lastIndex = 0;
  while ((match = DOMAIN_DETECT_UNLABELED_ENTRY.exec(clean)) !== null) {
    const target = normalizeDomainDetectTarget(match[2]);
    const count = match[3] || '1';
    if (!target) continue;
    rows.push([section || 'General', '', target, count]);
    matched = true;
  }
  if (matched) return rows;

  const plainTargets = clean.split(/\s*,\s*/).map(normalizeDomainDetectTarget).filter(Boolean);
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
  const clean = normalizeSeparators(normalizeText(text));
  const rows = [];
  let currentSection = 'General';

  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

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
  const clean = normalizeText(text).trim();
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
  const clean = normalizeSeparators(normalizeText(text)).trim();
  if (!clean) return null;

  if (clean.startsWith('{') || clean.startsWith('[')) {
    try {
      const obj = JSON.parse(clean);
      const rows = parseBookmarkJson(obj);
      if (rows.length > 0) {
        return { headers: ['URL', 'Title', 'Folder'], rows };
      }
    } catch {
      // try text fallbacks
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
      if (key === 'url') url = value;
      else if (key === 'title' || key === 'name') title = value;
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
  const clean = normalizeText(text).trim();
  if (!clean) return null;

  if (clean.startsWith('{') || clean.startsWith('[')) {
    try {
      const obj = JSON.parse(clean);
      const rows = flattenObjectEntries(obj)
        .map(([key, value]) => [key, sanitizeStructuredValue(value)])
        .filter(([, value]) => value);
      if (rows.length > 0) return { headers: ['Key', 'Value'], rows };
    } catch {
      // fall through
    }
  }

  const rows = [];
  const lines = clean.split('\n').map(line => line.trim()).filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*(?:=\s*|:\s+)(.*)$/);
    if (match) {
      rows.push([match[1].trim(), sanitizeStructuredValue(match[2])]);
    } else {
      rows.push([rows.length === 0 && lines.length === 1 ? 'Value' : `Entry ${rows.length + 1}`, sanitizeStructuredValue(line)]);
    }
  }

  return rows.length > 0 ? { headers: ['Key', 'Value'], rows } : null;
}

export function parseAccountTokenFile(text, hint = '') {
  const clean = normalizeSeparators(normalizeText(text));
  if (!clean) return null;

  const rows = [];
  const note = /restore/i.test(hint) ? 'Restore file'
    : /fbfastcheck/i.test(hint) ? 'FBFastCheck'
    : /googletokens/i.test(hint) ? 'GoogleTokens'
    : /googleaccounts/i.test(hint) ? 'GoogleAccounts'
    : '';
  const lines = stripLeadingNoiseLines(clean)
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !isDecorativeTokenLine(line));

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
        match = line.match(TOKEN_VALUE_FIELD_PATTERN);
        if (match) {
          token = match[1].trim();
        } else {
          match = line.match(ACCOUNT_ID_FIELD_PATTERN);
          if (match) {
            accountId = match[1].trim();
          } else if (/^\d{6,}$/.test(line)) {
            accountId = line;
          } else {
            token = line;
          }
        }
      }
    }

    token = sanitizeStructuredValue(token, 1200);

    if (token && (/\s/.test(token) || !/[A-Za-z0-9]/.test(token))) {
      continue;
    }

    if (!token && !accountId) continue;
    rows.push([
      inferTokenKind(token, accountId, hint),
      token,
      accountId,
      note,
    ]);
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
      record[match[1].trim()] = sanitizeStructuredValue(match[2]);
    }
    const section = record['Account Name'] || record['Display Name'] || record['Email'] || record.clsid || `Record ${i + 1}`;
    for (const [key, value] of Object.entries(record)) {
      if (!value) continue;
      rows.push([section, key, value]);
    }
  }
  return rows;
}

export function parseServiceArtifactFile(text) {
  const clean = normalizeText(text).trim();
  if (!clean) return null;

  if (clean.startsWith('{') || clean.startsWith('[')) {
    try {
      const obj = JSON.parse(clean);
      const rows = flattenObjectEntries(obj)
        .map(([key, value]) => ['JSON', key, sanitizeStructuredValue(value)])
        .filter(([, , value]) => value);
      if (rows.length > 0) return { headers: ['Section', 'Key', 'Value'], rows };
    } catch {
      // fall through
    }
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
      kvRows.push(['Config', match[1].trim(), sanitizeStructuredValue(match[2])]);
    }
  }
  if (kvRows.length > 0) {
    return { headers: ['Section', 'Key', 'Value'], rows: kvRows };
  }

  const indicatorRows = [];
  const seen = new Set();

  for (const matchText of clean.match(URL_INDICATOR_PATTERN) || []) {
    const value = sanitizeStructuredValue(matchText);
    if (!seen.has(`url:${value}`)) {
      seen.add(`url:${value}`);
      indicatorRows.push(['Indicator', 'URL', value]);
    }
  }

  for (const matchText of clean.match(WINDOWS_PATH_PATTERN) || []) {
    const value = sanitizeStructuredValue(matchText);
    if (!seen.has(`path:${value}`)) {
      seen.add(`path:${value}`);
      indicatorRows.push(['Indicator', 'Path', value]);
    }
  }

  const tokenCandidates = clean.match(/[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{4,}\.[A-Za-z0-9._-]{10,}/g) || [];
  for (const candidate of tokenCandidates.slice(0, 10)) {
    const value = sanitizeStructuredValue(candidate, 300);
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
