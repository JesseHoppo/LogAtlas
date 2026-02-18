// Parsing for password/cookie files (block key:value, delimited, Netscape, JSON) and CSV output.

import { FIELD_PATTERNS } from './definitions.js';

const KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _-]*?)\s*:\s+(.*)/;

// Separator lines (e.g. ===============) are normalised to blank lines
const SEPARATOR_LINE = /^[=\-*~_]{3,}\s*$/gm;

function normalizeSeparators(text) {
  return text.replace(SEPARATOR_LINE, '');
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

  // Password: if exactly one remaining non-empty column, assign it
  const assigned = new Set(Object.keys(columnMap).map(Number));
  const unassigned = [];
  for (let i = 0; i < colCount; i++) {
    if (!assigned.has(i) && stats[i].total > 0) unassigned.push(i);
  }
  if (unassigned.length === 1 && urlCol >= 0 && userCol >= 0) {
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

function parsePasswordFile(text, config) {
  const clean = normalizeSeparators(text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n'));

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  const format = detectFormat(clean);
  if (!format) return null;

  if (format.type === 'block') {
    return parseBlocks(clean, format.headers);
  }
  if (format.type === 'delimited') {
    return parseDelimited(clean, format);
  }
  return null;
}

// History parser

function parseHistoryFile(text, config) {
  const clean = text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  // Try structured delimited detection first
  const format = detectFormat(clean);
  if (format && format.type === 'delimited') {
    return parseDelimited(clean, format);
  }

  // Fallback: line-by-line URL extraction
  const lines = clean.split('\n').map(l => l.trim()).filter(l => l);
  const rows = [];
  for (const line of lines) {
    if (/^https?:\/\//i.test(line)) {
      rows.push([line, '', '1', '']);
    }
  }
  if (rows.length > 0) {
    return { headers: ['URL', 'Title', 'Visits', 'Last Visit'], rows };
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

function parseCookieFile(text, config) {
  const clean = text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // If explicit config from column mapper, use it directly
  if (config) return parseWithConfig(clean, config);

  // Try JSON format first
  const trimmed = clean.trim();
  if (trimmed.startsWith('[')) {
    const jsonResult = parseJSONCookies(trimmed);
    if (jsonResult) return jsonResult;
  }

  const lines = clean.split('\n').map(l => l.trim()).filter(l => l !== '');
  if (lines.length === 0) return null;

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
  const format = detectFormat(clean);
  if (format && format.type === 'delimited') {
    return parseDelimited(clean, format);
  }

  return null;
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
  parseWithConfig,
  parseCookieFile,
  parseHistoryFile,
  toCSV,
  splitCSVLine,
  inferColumnRoles,
  makeSplitFn,
};
