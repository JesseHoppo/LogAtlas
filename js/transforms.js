// Parsing for password/cookie files (block key:value, delimited, Netscape, JSON) and CSV output.

import { FIELD_PATTERNS } from './definitions.js';

const KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _-]*?)\s*:\s+(.*)/;
const AUTOFILL_KV_PATTERN = /^([A-Za-z_][A-Za-z0-9_.$\-[\]]*)\s*:\s*(.+)$/;
const HISTORY_URL_PATTERN = /^(?:(?:[a-z][a-z0-9+.-]*):\/\/\/?|about:)/i;
const GOOGLE_RESTORE_TOKEN_PATTERN = /^(?!https?:\/\/)(?!file:\/\/)([^:\s]{20,}):(\d{6,})$/;
const DOMAIN_DETECT_LABELED_ENTRY = /\[([^\]]+)\]\s*([^,\n]+?)(?:\s*\((\d+)\))(?=\s*(?:,|\[|$))/g;
const DOMAIN_DETECT_UNLABELED_ENTRY = /(^|,\s*)([^,\[]+?)(?:\s*\((\d+)\))(?=\s*(?:,|$))/g;
const CLIPBOARD_URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
const CREDIT_CARD_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _/-]*?)\s*:\s*(.*)$/;
const BOOKMARK_HTML_PATTERN = /<a\b[^>]*href=(?:"([^"]+)"|'([^']+)')[^>]*>(.*?)<\/a>/ig;
const JWT_TOKEN_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const DISCORD_TOKEN_PATTERN = /^(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{10,}$/;
const WINDOWS_PATH_PATTERN = /[A-Z]:\\[^"\r\n\t]+/g;
const URL_INDICATOR_PATTERN = /https?:\/\/[^\s"'<>]+/g;
const SYSINFO_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()%-]*?)\s*(?:=\s*|:\s*)(.*)$/;
const SYSINFO_CAPTURE_SECTION_PATTERN = /^(?:Network Info|System Summary|System Info(?:rmation)?|User Info(?:rmation)?|Hardware Info|PC Info|Environment|Computer Info|User Agents|Installed (?:Apps|Software|Programs)|Process(?: List|es)?|Browsers?)\s*:$/i;
const SYSINFO_STRUCTURED_KEY_PATTERN = /^(?:ip(?: address)?|country|region|city|postal code|zip|location|hwid|guid|machine guid|machine id|machine name|build(?: id)?|os(?: name)?|os version|platform|architecture|arch|username|user name|computer name|pc name|host(?:name)?|local time|utc|timezone|time zone|language|languages|keyboard(?:s)?|laptop|running path|cpu|processor|cores?|threads?|ram|memory|display(?: resolution)?|screen(?: resolution)?|gpu|video card|mac(?: address)?|bios|antivirus|defender|domain|monitor|board|motherboard|drives?)$/i;
const SYSINFO_MULTILINE_KEY_PATTERN = /^(?:gpu|video card|display adapters?|dns servers?|installed (?:apps|software|programs)|process(?: list|es)|user agents?)$/i;

// Separator lines (e.g. ===============) are normalised to blank lines
const SEPARATOR_LINE = /^[=\-*~_]{3,}\s*$/gm;

function normalizeSeparators(text) {
  return text.replace(SEPARATOR_LINE, '');
}

function normalizeText(text) {
  return text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function decodeHtmlEntities(text) {
  return String(text || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function stripLeadingNoiseLines(text) {
  const lines = text.split('\n');
  let start = 0;

  while (start < lines.length) {
    const trimmed = lines[start].trim();
    if (!trimmed) {
      start++;
      continue;
    }

    if (
      /^\*.*\*$/.test(trimmed) ||
      /^telegram\s*:/i.test(trimmed) ||
      /^[*=_~#-]{3,}$/.test(trimmed) ||
      /^[\\/()|_ \-]{6,}$/.test(trimmed)
    ) {
      start++;
      continue;
    }

    break;
  }

  return lines.slice(start).join('\n');
}

function mostCommon(arr) {
  const counts = {};
  let maxVal = arr[0];
  let maxCount = 0;
  for (const v of arr) {
    counts[v] = (counts[v] || 0) + 1;
    if (counts[v] > maxCount) {
      maxCount = counts[v];
      maxVal = v;
    }
  }
  return maxVal;
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

function parseSystemInfoFile(text, fileName = '') {
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

// RFC 4180-aware CSV line splitter. Handles quoted fields with embedded commas/quotes.
function splitCSVLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { current += '"'; i++; }
      else if (ch === '"') { inQuotes = false; }
      else { current += ch; }
    } else {
      if (ch === '"') { inQuotes = true; }
      else if (ch === ',') { fields.push(current); current = ''; }
      else { current += ch; }
    }
  }
  fields.push(current);
  return fields;
}

// Build a split function for a given delimiter
function makeSplitFn(delimiter) {
  if (delimiter === ',') return splitCSVLine;
  return (line) => line.split(delimiter);
}

// Detect if >80% of non-blank sample lines contain a delimiter, and compute column count
function testDelimiter(nonBlankLines, delimiter) {
  const splitFn = makeSplitFn(delimiter);
  const matching = nonBlankLines.filter(l => {
    if (delimiter === ',') return l.includes(',');
    return l.includes(delimiter);
  });
  if (nonBlankLines.length === 0 || matching.length === 0) return null;
  if (matching.length / nonBlankLines.length < 0.8) return null;

  const colCounts = matching.map(l => splitFn(l).length);
  const columns = mostCommon(colCounts);
  if (columns < 2) return null;
  return columns;
}

// Detect columns that are empty in >90% of rows and should be dropped
function findEmptyColumns(nonBlankLines, delimiter, columns) {
  const splitFn = makeSplitFn(delimiter);
  const emptyCounts = Array.from({ length: columns }, () => 0);
  let total = 0;

  for (const line of nonBlankLines) {
    const fields = splitFn(line);
    total++;
    for (let i = 0; i < columns; i++) {
      if (!(fields[i] ?? '').trim()) emptyCounts[i]++;
    }
  }

  if (total === 0) return [];
  const drop = [];
  for (let i = 0; i < columns; i++) {
    if (emptyCounts[i] / total > 0.9) drop.push(i);
  }
  return drop;
}

// Check if the first row looks like a header (cells match FIELD_PATTERNS)
function detectHeaderRow(firstLine, delimiter) {
  const splitFn = makeSplitFn(delimiter);
  const cells = splitFn(firstLine).map(c => c.trim());
  let matches = 0;
  const allPatterns = [FIELD_PATTERNS.url, FIELD_PATTERNS.username, FIELD_PATTERNS.password];
  for (const cell of cells) {
    if (allPatterns.some(p => p.test(cell))) matches++;
  }
  return matches >= 2;
}

// Content-based column role inference: scans sample data to guess URL/Username/Password columns
function inferColumnRoles(lines, delimiter, hasHeaderRow) {
  const splitFn = makeSplitFn(delimiter);
  const dataLines = hasHeaderRow ? lines.slice(1) : lines;
  const sample = dataLines.filter(l => l.trim()).slice(0, 50);
  if (sample.length === 0) return { columnMap: {}, confidence: 'low' };

  const colCount = splitFn(sample[0]).length;
  const stats = Array.from({ length: colCount }, () => ({ urlLike: 0, emailLike: 0, total: 0 }));

  for (const line of sample) {
    const cells = splitFn(line);
    for (let i = 0; i < Math.min(cells.length, colCount); i++) {
      const val = cells[i].trim();
      if (!val) continue;
      stats[i].total++;
      if (/^https?:\/\//.test(val) || (val.includes('/') && val.includes('.') && !val.includes('@'))) stats[i].urlLike++;
      if (val.includes('@') && val.includes('.')) stats[i].emailLike++;
    }
  }

  const columnMap = {};
  let urlCol = -1, userCol = -1;

  // URL: column with >60% URL-like values
  for (let i = 0; i < stats.length; i++) {
    if (stats[i].total > 0 && stats[i].urlLike / stats[i].total > 0.6) {
      columnMap[i] = 'url'; urlCol = i; break;
    }
  }

  // Username: column with >40% email-like values (lower threshold — many usernames aren't emails)
  for (let i = 0; i < stats.length; i++) {
    if (i === urlCol) continue;
    if (stats[i].total > 0 && stats[i].emailLike / stats[i].total > 0.4) {
      columnMap[i] = 'username'; userCol = i; break;
    }
  }

  // If we found URL but not username via email heuristic, pick the first non-empty, non-URL column
  if (urlCol >= 0 && userCol < 0) {
    for (let i = 0; i < stats.length; i++) {
      if (i === urlCol) continue;
      if (stats[i].total > 0) { columnMap[i] = 'username'; userCol = i; break; }
    }
  }

  // Two-column fallback: common username/password exports without a header row
  if (colCount === 2 && userCol < 0 && urlCol < 0) {
    const populatedCols = stats
      .map((entry, index) => ({ ...entry, index }))
      .filter(entry => entry.total > 0);
    if (populatedCols.length === 2) {
      columnMap[populatedCols[0].index] = 'username';
      columnMap[populatedCols[1].index] = 'password';
      userCol = populatedCols[0].index;
    }
  }

  // Password: if exactly one remaining non-empty column, assign it
  const assigned = new Set(Object.keys(columnMap).map(Number));
  const unassigned = [];
  for (let i = 0; i < colCount; i++) {
    if (!assigned.has(i) && stats[i].total > 0) unassigned.push(i);
  }
  if (unassigned.length === 1 && (userCol >= 0 || urlCol >= 0)) {
    columnMap[unassigned[0]] = 'password';
  }

  const rolesFound = Object.keys(columnMap).length;
  const confidence = rolesFound >= 3 ? 'high' : rolesFound >= 2 ? 'medium' : 'low';
  return { columnMap, confidence };
}

const ROLE_TO_HEADER = {
  url: 'URL', username: 'Username', password: 'Password', email: 'Email', notes: 'Notes',
  domain: 'Domain', name: 'Name', value: 'Value', path: 'Path', secure: 'Secure', expiration: 'Expiration',
  title: 'Title', visitCount: 'Visits', lastVisit: 'Last Visit',
  field: 'Field', // autofill field name
};

// Returns { type: 'block', headers } | { type: 'delimited', delimiter, columns, hasHeaderRow, dropColumns, confidence } | null
function detectFormat(text) {
  const lines = text.split('\n');
  const sample = lines.slice(0, 100);

  // Block-based detection
  let kvLineCount = 0;
  let blankLineCount = 0;
  const headersSeen = new Set();

  for (const line of sample) {
    const trimmed = line.trim();
    if (trimmed === '') { blankLineCount++; continue; }
    const match = trimmed.match(KV_PATTERN);
    if (match) {
      kvLineCount++;
      headersSeen.add(match[1].trim());
    }
  }

  const nonBlank = sample.filter(l => l.trim() !== '').length;
  if (
    nonBlank > 0 &&
    (kvLineCount / nonBlank) > 0.6 &&
    headersSeen.size >= 2 &&
    blankLineCount >= 1
  ) {
    return { type: 'block', headers: [...headersSeen] };
  }

  // Delimited detection — try each delimiter in priority order
  const nonBlankLines = sample.filter(l => l.trim() !== '');
  const delimiters = ['\t', ',', '|', ';'];

  for (const delim of delimiters) {
    const columns = testDelimiter(nonBlankLines, delim);
    if (columns === null) continue;

    const dropColumns = findEmptyColumns(nonBlankLines, delim, columns);
    const effectiveCols = columns - dropColumns.length;
    if (effectiveCols < 2) continue;

    const firstNonBlank = nonBlankLines[0] || '';
    const hasHeaderRow = detectHeaderRow(firstNonBlank, delim);

    // Infer column roles for confidence scoring
    const inference = inferColumnRoles(nonBlankLines, delim, hasHeaderRow);

    // Confidence: high if header row detected or 3 roles inferred, medium if 2 roles, low otherwise
    let confidence;
    if (hasHeaderRow) confidence = 'high';
    else if (inference.confidence === 'high') confidence = 'high';
    else if (inference.confidence === 'medium') confidence = 'medium';
    else if (effectiveCols === 3) confidence = 'medium'; // 3-col default heuristic
    else confidence = 'low';

    return { type: 'delimited', delimiter: delim, columns, hasHeaderRow, dropColumns, confidence };
  }

  return null;
}

// Block parser

function parseBlocks(text, headers) {
  const blocks = text.split(/\n\s*\n/).filter(b => b.trim());
  const rows = [];

  for (const block of blocks) {
    const record = {};
    for (const line of block.split('\n')) {
      const match = line.trim().match(KV_PATTERN);
      if (match) {
        record[match[1].trim()] = match[2].trim();
      }
    }
    if (Object.keys(record).length > 0) {
      rows.push(headers.map(h => record[h] || ''));
    }
  }

  return { headers, rows };
}

// Unified delimited parser (replaces old parseTSV)

function parseDelimited(text, format) {
  const { delimiter, columns, hasHeaderRow, dropColumns } = format;
  const splitFn = makeSplitFn(delimiter);
  const allLines = text.split('\n').map(l => l.trim()).filter(l => l);
  if (allLines.length === 0) return null;

  // Determine which columns to keep
  const drop = new Set(dropColumns || []);
  const keepIndices = [];
  for (let i = 0; i < columns; i++) {
    if (!drop.has(i)) keepIndices.push(i);
  }
  const effectiveCols = keepIndices.length;

  // Determine headers
  let headers;
  let startIdx = 0;

  if (hasHeaderRow) {
    const headerCells = splitFn(allLines[0]);
    headers = keepIndices.map(i => (headerCells[i] ?? '').trim() || `Column ${i + 1}`);
    startIdx = 1;
  } else {
    // Try content-based inference
    const inference = inferColumnRoles(allLines, delimiter, false);
    if (inference.confidence !== 'low') {
      // Map inferred roles to keep-indices
      headers = keepIndices.map((origIdx, _) => {
        const role = inference.columnMap[origIdx];
        return role ? (ROLE_TO_HEADER[role] || `Column ${origIdx + 1}`) : `Column ${origIdx + 1}`;
      });
    } else if (effectiveCols === 3) {
      headers = ['URL', 'Username', 'Password'];
    } else {
      headers = keepIndices.map((_, i) => `Column ${i + 1}`);
    }
  }

  const rows = [];
  for (let i = startIdx; i < allLines.length; i++) {
    const fields = splitFn(allLines[i]);
    rows.push(keepIndices.map(idx => (fields[idx] ?? '').trim()));
  }

  return { headers, rows };
}

// Parse with explicit user-supplied config (from column mapper)
function parseWithConfig(text, config) {
  const { delimiter, hasHeaderRow, columnMap } = config;
  const splitFn = makeSplitFn(delimiter);
  const lines = text.split('\n').map(l => l.trim()).filter(l => l);
  if (lines.length === 0) return null;

  const sampleCols = splitFn(lines[0]).length;
  const startIdx = hasHeaderRow ? 1 : 0;

  // Build headers and determine which columns to keep (skip = excluded)
  const keepIndices = [];
  const headers = [];
  for (let i = 0; i < sampleCols; i++) {
    const role = columnMap[i] || columnMap[String(i)];
    if (role === 'skip') continue;
    keepIndices.push(i);
    headers.push(role ? (ROLE_TO_HEADER[role] || `Column ${i + 1}`) : `Column ${i + 1}`);
  }

  const rows = [];
  for (let i = startIdx; i < lines.length; i++) {
    const cells = splitFn(lines[i]);
    rows.push(keepIndices.map(idx => (cells[idx] ?? '').trim()));
  }

  return { headers, rows };
}

function finalizeCredentialDataset(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
  const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

  if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) return null;

  const rows = parsed.rows.filter((row) => {
    const password = (row[passIdx] || '').trim();
    const username = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
    const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
    return Boolean(password && (username || url));
  });

  if (rows.length === 0) return null;
  return { headers: parsed.headers, rows };
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

function parsePasswordFile(text, config) {
  const clean = normalizeSeparators(normalizeText(text));

  // If explicit config from column mapper, use it directly
  if (config) return finalizeCredentialDataset(parseWithConfig(clean, config));

  const format = detectFormat(clean);
  if (!format) return finalizeCredentialDataset(parseLoosePasswordBlocks(clean));

  if (format.type === 'block') {
    return finalizeCredentialDataset(parseBlocks(clean, format.headers));
  }
  if (format.type === 'delimited') {
    return finalizeCredentialDataset(parseDelimited(clean, format));
  }

  return finalizeCredentialDataset(parseLoosePasswordBlocks(clean));
}

// History parser

function parseHistoryFile(text, config) {
  const clean = normalizeText(text);

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  const normalized = normalizeSeparators(clean);

  // Try structured delimited detection first
  const format = detectFormat(normalized);
  if (format && format.type === 'delimited') {
    return parseDelimited(normalized, format);
  }

  // Block format (URL/TITLE/TIME or URL/Title/Visit Count blocks)
  if (format && format.type === 'block') {
    const result = parseBlocks(normalized, format.headers);
    if (result && result.rows.length > 0) {
      // Normalize header names to standard form
      const headerMap = { headers: [], indices: {} };
      for (let i = 0; i < result.headers.length; i++) {
        const h = result.headers[i].toLowerCase();
        if (/^url$/i.test(result.headers[i])) headerMap.indices.url = i;
        else if (/^title$/i.test(result.headers[i])) headerMap.indices.title = i;
        else if (/^(?:time|last\s*visit|date)$/i.test(result.headers[i])) headerMap.indices.time = i;
        else if (/^visit\s*count$/i.test(result.headers[i])) headerMap.indices.visits = i;
      }
      const headers = ['URL', 'Title', 'Visits', 'Last Visit'];
      const rows = result.rows.map(row => [
        row[headerMap.indices.url ?? -1] || '',
        row[headerMap.indices.title ?? -1] || '',
        row[headerMap.indices.visits ?? -1] || '1',
        row[headerMap.indices.time ?? -1] || '',
      ]);
      return { headers, rows };
    }
  }

  // Fallback: line-by-line URL extraction
  const lines = normalized.split('\n').map(l => l.trim()).filter(l => l);
  const rows = [];
  for (const line of lines) {
    if (HISTORY_URL_PATTERN.test(line)) {
      rows.push([line, '', '1', '']);
    }
  }
  if (rows.length > 0) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows };
  }

  return null;
}

// Download history parser (paired filepath + URL lines)

function parseDownloadFile(text) {
  const clean = normalizeText(text);
  const normalized = normalizeSeparators(clean);

  // Try structured delimited detection first
  const format = detectFormat(normalized);
  if (format && format.type === 'delimited') {
    return parseDelimited(normalized, format);
  }

  // Block format (URL/Filename/Recived bytes blocks)
  if (format && format.type === 'block') {
    const result = parseBlocks(normalized, format.headers);
    if (result && result.rows.length > 0) {
      const headerMap = {};
      for (let i = 0; i < result.headers.length; i++) {
        const h = result.headers[i].toLowerCase();
        if (/^url$/i.test(result.headers[i])) headerMap.url = i;
        else if (/^filename$/i.test(result.headers[i])) headerMap.file = i;
        else if (/^(?:recived|received)\s*bytes$/i.test(result.headers[i])) headerMap.size = i;
      }
      const headers = ['File Path', 'Source URL', 'File Size'];
      const rows = result.rows.map(row => [
        row[headerMap.file ?? -1] || '',
        row[headerMap.url ?? -1] || '',
        row[headerMap.size ?? -1] || '',
      ]);
      return { headers, rows };
    }
  }

  // Paired-line format: filepath on one line, URL on next, separated by blank lines
  const lines = normalized.split('\n');
  const rows = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    if (!line) { i++; continue; }

    // Look for a filepath (starts with drive letter or / or contains backslash)
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

// Cookie timestamp conversion

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

function parseCookieFile(text, config) {
  const clean = normalizeText(text);

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  const sanitized = stripLeadingNoiseLines(clean).trim();

  // Try JSON format first
  const trimmed = sanitized || clean.trim();
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

  const lines = (sanitized || clean).split('\n').map(l => l.trim()).filter(l => l !== '');
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
  const format = detectFormat(sanitized || clean);
  if (format && format.type === 'delimited') {
    return parseDelimited(sanitized || clean, format);
  }

  return null;
}

function parseAutofillFile(text, config) {
  const clean = normalizeSeparators(normalizeText(text));

  if (config) {
    const parsed = parseWithConfig(clean, config);
    if (!parsed || parsed.rows.length === 0) return null;
    const fieldIdx = parsed.headers.findIndex(h => /^field$/i.test(h));
    const valueIdx = parsed.headers.findIndex(h => /^value$/i.test(h));
    if (fieldIdx < 0 || valueIdx < 0) return parsed;
    const rows = parsed.rows
      .map(row => [(row[fieldIdx] || '').trim(), (row[valueIdx] || '').trim()])
      .filter(([name, value]) => name && value);
    return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
  }

  const parsed = parsePasswordFile(clean, null);
  if (parsed && parsed.rows.length > 0) {
    const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formField.test(h));
    const valueIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formValue.test(h));
    if (nameIdx >= 0 && valueIdx >= 0) {
      const rows = parsed.rows
        .map(row => [(row[nameIdx] || '').trim(), (row[valueIdx] || '').trim()])
        .filter(([name, value]) => name && value);
      if (rows.length > 0) return { headers: ['Field', 'Value'], rows };
    }
  }

  const lines = stripLeadingNoiseLines(clean).split('\n').map(line => line.trim()).filter(Boolean);
  const rows = [];

  for (const line of lines) {
    let match = line.match(AUTOFILL_KV_PATTERN);
    if (match && !/^(?:https?|file)$/i.test(match[1])) {
      rows.push([match[1].trim(), match[2].trim()]);
      continue;
    }

    match = line.match(/^([A-Za-z_$][A-Za-z0-9_.$-]*)\s+(.+)$/);
    if (match) {
      rows.push([match[1].trim(), match[2].trim()]);
    }
  }

  return rows.length > 0 ? { headers: ['Field', 'Value'], rows } : null;
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

function parseDomainDetectFile(text) {
  const clean = normalizeSeparators(normalizeText(text));
  const rows = [];
  let currentSection = 'General';

  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    const colonIdx = line.indexOf(':');
    if (colonIdx >= 0) {
      const header = line.slice(0, colonIdx).trim();
      const rest = line.slice(colonIdx + 1).trim();
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

function parseClipboardFile(text) {
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

  const nextFolder = value.folder || value.name || folder;
  const url = value.url || value.href || '';
  const title = value.title || value.name || value.label || '';
  if (url) {
    rows.push([url, title, folder || nextFolder || '']);
  }

  const childKeys = ['children', 'roots', 'bookmarks', 'items'];
  for (const key of childKeys) {
    if (value[key]) parseBookmarkJson(value[key], nextFolder || folder, rows);
  }

  return rows;
}

function parseBookmarkFile(text) {
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

function parseBrowserMetadataFile(text) {
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

function parseAccountTokenFile(text, hint = '') {
  const clean = normalizeText(text).trim();
  if (!clean) return null;

  const rows = [];
  const lines = clean.split('\n').map(line => line.trim()).filter(Boolean);

  for (const line of lines) {
    let accountId = '';
    let token = '';
    let note = /restore/i.test(hint) ? 'Restore file'
      : /fbfastcheck/i.test(hint) ? 'FBFastCheck'
      : /googleaccounts/i.test(hint) ? 'GoogleAccounts'
      : '';

    let match = line.match(/^([^:\s]{20,})\s*:\s*(\d{6,})$/);
    if (match) {
      token = match[1].trim();
      accountId = match[2].trim();
    } else {
      match = line.match(/^(\d{6,})\s*:\s*(.+)$/);
      if (match) {
        accountId = match[1].trim();
        token = match[2].trim();
      } else {
        match = line.match(/^(?:id|user(?:\s*id)?|account(?:\s*id)?)\s*[:=]\s*(\d{6,})$/i);
        if (match) {
          accountId = match[1].trim();
        } else if (/^\d{6,}$/.test(line)) {
          accountId = line;
        } else {
          token = line;
        }
      }
    }

    token = sanitizeStructuredValue(token, 1200);

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

function parseServiceArtifactFile(text) {
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

function buildCreditCardRowsFromBlocks(clean) {
  const blocks = clean.split(/\n\s*\n/).filter(block => block.trim());
  const rows = [];

  for (const block of blocks) {
    const record = {};
    for (const rawLine of block.split('\n')) {
      const match = rawLine.trim().match(CREDIT_CARD_KV_PATTERN);
      if (!match) continue;
      record[match[1].trim().toLowerCase()] = match[2].trim();
    }

    const cardNumber = record.cardnumber || record['card number'] || record.number || record.card || record.cn || record.pan || '';
    const month = record.month || record['exp month'] || record['expiry month'] || '';
    const year = record.year || record['exp year'] || record['expiry year'] || '';
    const nameOnCard = record.nameoncard || record['name on card'] || record.cardholder || record['card holder'] || record.name || record.holder || '';
    const cvc = record.cvc || record.cvv || record.securitycode || record['security code'] || '';
    const expiration = record.expirationdate || record['expiration date'] || record.expiry || record.expires || record.expire || record.date || (month || year ? `${month}/${year}`.replace(/^\/|\/$/g, '') : '');
    const filePath = record.filepath || record['file path'] || record.path || record.target || '';

    if (!cardNumber && !expiration && !nameOnCard && !cvc && !filePath) continue;
    rows.push([cardNumber, nameOnCard, cvc, expiration, filePath]);
  }

  return rows;
}

function mapCreditCardHeaders(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const headerMap = {};
  for (let i = 0; i < parsed.headers.length; i++) {
    const header = parsed.headers[i].toLowerCase();
    if (/^(?:card\s*number|cardnumber|number|pan)$/i.test(header)) headerMap.number = i;
    else if (/^(?:name\s*on\s*card|nameoncard|cardholder|card\s*holder|holder|name)$/i.test(header)) headerMap.name = i;
    else if (/^(?:cvc|cvv|security\s*code)$/i.test(header)) headerMap.cvc = i;
    else if (/^(?:expiration(?:\s*date)?|expiry|expires?|expire|date|month|year)$/i.test(header)) headerMap.expiration = i;
    else if (/^(?:file\s*path|filepath|path|source|target)$/i.test(header)) headerMap.path = i;
  }

  const rows = parsed.rows
    .map(row => [
      row[headerMap.number ?? -1] || '',
      row[headerMap.name ?? -1] || '',
      row[headerMap.cvc ?? -1] || '',
      row[headerMap.expiration ?? -1] || '',
      row[headerMap.path ?? -1] || '',
    ])
    .filter(row => row.some(cell => (cell || '').trim()));

  return rows.length > 0 ? { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows } : null;
}

function mapCreditCardRowsByContent(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const rows = [];
  for (const row of parsed.rows) {
    const cells = row.map(cell => (cell || '').trim());
    if (cells.every(cell => !cell)) continue;

    let cardNumber = '';
    let nameOnCard = '';
    let cvc = '';
    let expiration = '';
    let filePath = '';

    for (const cell of cells) {
      const digits = cell.replace(/\D/g, '');
      if (!cardNumber && digits.length >= 12 && digits.length <= 19) {
        cardNumber = cell;
        continue;
      }
      if (!expiration && /^\d{1,2}[/-]\d{2,4}$/.test(cell)) {
        expiration = cell;
        continue;
      }
      if (!cvc && /^\d{3,4}$/.test(cell)) {
        cvc = cell;
        continue;
      }
      if (!filePath && /[\\/]/.test(cell)) {
        filePath = cell;
        continue;
      }
      if (!nameOnCard && /[A-Za-z]/.test(cell)) {
        nameOnCard = cell;
      }
    }

    if (!cardNumber && !nameOnCard && !expiration && !cvc && !filePath) continue;
    rows.push([cardNumber, nameOnCard, cvc, expiration, filePath]);
  }

  return rows.length > 0 ? { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows } : null;
}

function parseCreditCardFile(text, config) {
  const clean = normalizeSeparators(normalizeText(text));

  if (config) {
    const parsed = parseWithConfig(clean, config);
    return mapCreditCardHeaders(parsed) || mapCreditCardRowsByContent(parsed) || parsed;
  }

  const blockRows = buildCreditCardRowsFromBlocks(clean);
  if (blockRows.length > 0) {
    return { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows: blockRows };
  }

  const format = detectFormat(clean);
  if (format && format.type === 'delimited') {
    const parsed = parseDelimited(clean, format);
    const mapped = mapCreditCardHeaders(parsed) || mapCreditCardRowsByContent(parsed);
    if (mapped) return mapped;
  }

  const rows = [];
  for (const rawLine of clean.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    let match = line.match(/^(\d{1,2}[/-]\d{2,4})\s+([0-9][0-9 -]{8,})$/);
    if (!match) {
      match = line.match(/^([0-9][0-9 -]{8,})\s+(\d{1,2}[/-]\d{2,4})$/);
      if (match) {
        rows.push([match[1].trim(), '', '', match[2].trim(), '']);
      }
      continue;
    }

    rows.push([match[2].trim(), '', '', match[1].trim(), '']);
  }

  return rows.length > 0 ? {
    headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'],
    rows,
  } : null;
}

// CSV generation (RFC 4180)

function toCSV(parsed) {
  const escape = (cell) => `"${String(cell).replace(/"/g, '""')}"`;
  const headerLine = parsed.headers.map(escape).join(',');
  const dataLines = parsed.rows.map(row => row.map(escape).join(','));
  return [headerLine, ...dataLines].join('\n');
}

export {
  detectFormat,
  parsePasswordFile,
  parseAutofillFile,
  parseWithConfig,
  parseCookieFile,
  parseHistoryFile,
  parseDownloadFile,
  parseDomainDetectFile,
  parseClipboardFile,
  parseSystemInfoFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
  parseAccountTokenFile,
  parseServiceArtifactFile,
  parseCreditCardFile,
  toCSV,
  splitCSVLine,
  inferColumnRoles,
  makeSplitFn,
};
