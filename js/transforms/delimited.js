// Core format detection and delimited parsing (used by password, cookie, card parsers).

import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import { KV_PATTERN } from './shared.js';

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

export function makeSplitFn(delimiter) {
  if (delimiter === ',') return splitCSVLine;
  return (line) => line.split(delimiter);
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

const ROLE_TO_HEADER = {
  url: 'URL', username: 'Username', password: 'Password', email: 'Email', notes: 'Notes',
  domain: 'Domain', name: 'Name', value: 'Value', path: 'Path', secure: 'Secure', expiration: 'Expiration',
  title: 'Title', visitCount: 'Visits', lastVisit: 'Last Visit',
  field: 'Field',
};

const KNOWN_HEADER_NAMES = new Set([
  ...Object.keys(ROLE_TO_HEADER),
  ...Object.values(ROLE_TO_HEADER).map(normaliseHeaderCell),
  'uri',
  'host',
  'hostname',
  'site',
  'origin',
  'website',
  'address',
  'webaddress',
  'loginpage',
  'homepage',
  'user',
  'login',
  'loginname',
  'loginid',
  'emailaddress',
  'mail',
  'account',
  'accountname',
  'userid',
  'pass',
  'passwd',
  'pwd',
  'passcode',
  'pin',
  'pincode',
  'subdomain',
  'hostkey',
  'expires',
  'expiry',
  'visitcount',
  'count',
  'date',
  'time',
  'timestamp',
  'pagetitle',
  'filename',
  'filepath',
  'downloadpath',
  'sourceurl',
  'downloadurl',
  'filesize',
  'bytes',
  'receivedbytes',
  'recivedbytes',
  'cardnumber',
  'number',
  'pan',
  'nameoncard',
  'cardholder',
  'holder',
  'cvc',
  'cvv',
  'securitycode',
  'expmonth',
  'expyear',
  'expirymonth',
  'expiryyear',
  'expirationdate',
  'section',
  'label',
  'target',
  'type',
  'text',
  'urls',
  'linecount',
  'length',
  'key',
]);

function normaliseHeaderCell(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
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

// Check if the first row looks like a header by matching common exported column names.
function detectHeaderRow(firstLine, delimiter) {
  const splitFn = makeSplitFn(delimiter);
  const cells = splitFn(firstLine).map(c => c.trim());
  const filled = cells.filter(Boolean);
  if (filled.length < 2) return false;

  let matches = 0;
  for (const cell of cells) {
    if (cell && KNOWN_HEADER_NAMES.has(normaliseHeaderCell(cell))) matches++;
  }

  return matches >= Math.max(2, Math.ceil(filled.length / 2));
}

// Content-based column role inference: scans sample data to guess URL/Username/Password columns
export function inferColumnRoles(lines, delimiter, hasHeaderRow) {
  const splitFn = makeSplitFn(delimiter);
  const dataLines = hasHeaderRow ? lines.slice(1) : lines;
  const sample = dataLines.filter(l => l.trim()).slice(0, 50);
  if (sample.length === 0) return { columnMap: {}, confidence: 'low' };

  const colCount = mostCommon(sample.map(l => splitFn(l).length));
  const stats = Array.from({ length: colCount }, () => ({ urlLike: 0, emailLike: 0, total: 0 }));

  for (const line of sample) {
    const cells = splitFn(line);
    for (let i = 0; i < Math.min(cells.length, colCount); i++) {
      const val = cells[i].trim();
      if (!val) continue;
      stats[i].total++;
      if (!val.includes('@') && (/^https?:\/\//i.test(val) || /^www\./i.test(val) || /^[a-z0-9.-]+\.[a-z]{2,}(?:[/:?#]|$)/i.test(val))) stats[i].urlLike++;
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

  // Username: column with >40% email-like values (lower threshold, many usernames aren't emails)
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

// Block-vs-delimited sniffing; null when neither shape is confident.
export function detectFormat(text) {
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

  // Delimited detection: try each delimiter in priority order
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

    return { type: 'delimited', delimiter: delim, columns, hasHeaderRow, dropColumns };
  }

  return null;
}

export function parseBlocks(text, headers) {
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

export function parseDelimited(text, format) {
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
    const inference = inferColumnRoles(allLines, delimiter, false);
    if (inference.confidence !== 'low') {
      headers = keepIndices.map((origIdx) => {
        const role = inference.columnMap[origIdx];
        return role ? (ROLE_TO_HEADER[role] || `Column ${origIdx + 1}`) : `Column ${origIdx + 1}`;
      });
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

export function parseWithConfig(text, config) {
  const { delimiter, hasHeaderRow, columnMap } = config;
  const splitFn = makeSplitFn(delimiter);
  const lines = text.split('\n').map(l => l.trim()).filter(l => l);
  if (lines.length === 0) return null;

  const sampleCols = Math.max(...lines.slice(0, 50).map(l => splitFn(l).length));
  // The mapper may have keyed columns off a wider preview sample than the first
  // 50 lines yield, so honour every explicitly mapped index too.
  const mappedKeys = Object.keys(columnMap || {}).map(Number).filter(n => Number.isInteger(n) && n >= 0);
  const maxMappedCol = mappedKeys.length ? Math.max(...mappedKeys) + 1 : 0;
  const totalCols = Math.max(sampleCols, maxMappedCol);
  const startIdx = hasHeaderRow ? 1 : 0;

  // role 'skip' excludes a column
  const keepIndices = [];
  const headers = [];
  for (let i = 0; i < totalCols; i++) {
    const role = columnMap[i];
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

export function buildPasswordDataset(records) {
  if (!records || records.length === 0) return null;

  const extraHeaders = [];
  for (const record of records) {
    for (const key of Object.keys(record)) {
      if (key === 'URL' || key === 'Username' || key === 'Password') continue;
      if (!extraHeaders.includes(key)) extraHeaders.push(key);
    }
  }

  const headers = ['URL', 'Username', 'Password', ...extraHeaders];
  const rows = records.map(record => headers.map(header => record[header] || ''));
  return { headers, rows };
}

export function finaliseCredentialDataset(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
  const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

  if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) return null;

  const rows = parsed.rows.filter((row) => {
    const password = (row[passIdx] || '').trim();
    const username = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
    const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
    return Boolean((password && (username || url)) || (url && !password && !username));
  });

  if (rows.length === 0) return null;
  return { headers: parsed.headers, rows };
}
