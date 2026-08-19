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

const EDGE_WHITESPACE = /^\s|\s$/;

// Physical lines in the index space a format was detected in. Only a trimmed
// layout may shift field positions; blank lines drop out of both.
export function splitLines(text, trimLines) {
  const lines = text.split('\n');
  return trimLines ? lines.map(l => l.trim()).filter(l => l) : lines.filter(l => l.trim());
}

// One pass per candidate: >80% of lines must carry the delimiter, the modal
// field count is the column count, and a column populated in under 10% of
// lines is dropped. Both are measured over every line handed in, because a
// column the stealer only starts filling part-way down the file must not be
// classified as empty on the strength of the opening screenful.
function measureLayout(lines, delimiter, requireCoverage = true) {
  if (lines.length === 0) return null;
  const splitFn = makeSplitFn(delimiter);
  const counts = [];
  const populated = [];

  for (const line of lines) {
    const fields = splitFn(line);
    if (line.includes(delimiter)) counts.push(fields.length);
    for (let i = 0; i < fields.length; i++) {
      if (fields[i].trim()) populated[i] = (populated[i] || 0) + 1;
    }
  }

  if (counts.length === 0) return null;
  if (requireCoverage && counts.length / lines.length < 0.8) return null;
  const columns = mostCommon(counts);
  if (columns < 2) return null;

  // The last column absorbs the surplus of any row wider than the layout, so
  // it is never treated as padding once such a row exists.
  const ragged = counts.some(c => c > columns);
  const dropColumns = [];
  for (let i = 0; i < columns; i++) {
    if (ragged && i === columns - 1) continue;
    if ((populated[i] || 0) / lines.length < 0.1) dropColumns.push(i);
  }
  const agreement = counts.filter(c => c === columns).length / counts.length;
  return { columns, dropColumns, agreement };
}

// Columns are indexed off the raw line so a leading delimiter cannot shift
// every field one place left, and so a trailing empty field still occupies a
// column of its own. Exports padded with delimiter runs sometimes only resolve
// once trimmed, so both index spaces are measured and the one that keeps more
// populated columns wins; whichever it is has to be the space the parser reads.
function chooseLayout(lines, delimiter) {
  // Trimming can only move a field when a line carries whitespace at an edge.
  const candidates = lines.some(l => EDGE_WHITESPACE.test(l)) ? [false, true] : [false];
  let best = null;

  for (const trimLines of candidates) {
    const measured = measureLayout(trimLines ? lines.map(l => l.trim()) : lines, delimiter);
    if (!measured) continue;
    if (!best) { best = { ...measured, trimLines }; continue; }
    const gain = (measured.columns - measured.dropColumns.length) - (best.columns - best.dropColumns.length);
    if (gain > 0 || (gain === 0 && measured.agreement > best.agreement)) best = { ...measured, trimLines };
  }

  return best;
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

  // Delimited detection: the sample picks the delimiter, the whole file sizes it
  const sampleLines = sample.filter(l => l.trim() !== '');
  const allLines = lines.filter(l => l.trim() !== '');
  const delimiters = ['\t', ',', '|', ';'];

  for (const delim of delimiters) {
    const sampled = chooseLayout(sampleLines, delim);
    if (!sampled) continue;

    // The sample settles the delimiter and the index space; the whole file
    // sizes the layout, so a column only filled part-way down still counts.
    const scoped = sampled.trimLines ? allLines.map(l => l.trim()) : allLines;
    const layout = { ...(measureLayout(scoped, delim, false) || sampled), trimLines: sampled.trimLines };
    if (layout.columns - layout.dropColumns.length < 2) continue;

    const firstNonBlank = allLines[0] || '';
    const hasHeaderRow = detectHeaderRow(layout.trimLines ? firstNonBlank.trim() : firstNonBlank, delim);

    return {
      type: 'delimited',
      delimiter: delim,
      columns: layout.columns,
      hasHeaderRow,
      dropColumns: layout.dropColumns,
      trimLines: layout.trimLines,
    };
  }

  return null;
}

// A field carrying the delimiter (a password with a tab in it) makes a row
// wider than the layout. Fold the surplus back into the last column rather
// than cutting it off, so a truncated secret is never shown as a whole one.
function foldOverflow(fields, columns, delimiter) {
  fields.splice(columns - 1, fields.length, fields.slice(columns - 1).join(delimiter));
}

export function parseBlocks(text, headers) {
  const blocks = text.split(/\n\s*\n/).filter(b => b.trim());
  const rows = [];

  for (const block of blocks) {
    // Null prototype: a `constructor:` or `toString:` line in the log must not
    // put an inherited function into every other record's cell.
    const record = Object.create(null);
    for (const line of block.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.includes(':')) continue;
      const match = trimmed.match(KV_PATTERN);
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
  const { delimiter, columns, hasHeaderRow, dropColumns, trimLines } = format;
  const splitFn = makeSplitFn(delimiter);
  const allLines = splitLines(text, trimLines !== false);
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
  let raggedRows = 0;
  for (let i = startIdx; i < allLines.length; i++) {
    const fields = splitFn(allLines[i]);
    if (fields.length > columns) {
      raggedRows++;
      foldOverflow(fields, columns, delimiter);
    }
    rows.push(keepIndices.map(idx => (fields[idx] ?? '').trim()));
  }

  return { headers, rows, raggedRows };
}

// Widest row in the leading sample. The manual mapper has to offer a role
// dropdown for every column the parse will emit, so the preview and the parse
// both take the width from here instead of each measuring its own slice.
export function maxColumnCount(text, delimiter, trimLines) {
  const splitFn = makeSplitFn(delimiter);
  const lines = splitLines(text, trimLines !== false).slice(0, 50);
  if (lines.length === 0) return 0;
  return Math.max(...lines.map(l => splitFn(l).length));
}

export function parseWithConfig(text, config) {
  const { delimiter, hasHeaderRow, columnMap, trimLines } = config;
  const splitFn = makeSplitFn(delimiter);
  const lines = splitLines(text, trimLines !== false);
  if (lines.length === 0) return null;

  const sampleCols = maxColumnCount(text, delimiter, trimLines);
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
  let raggedRows = 0;
  for (let i = startIdx; i < lines.length; i++) {
    const cells = splitFn(lines[i]);
    if (cells.length > totalCols) {
      raggedRows++;
      foldOverflow(cells, totalCols, delimiter);
    }
    rows.push(keepIndices.map(idx => (cells[idx] ?? '').trim()));
  }

  return { headers, rows, raggedRows };
}

// A file whose records share no fields — a combolist read as key/value pairs is
// the usual way in — grows one column per record. The table that builds is
// wider than anything can show and costs a cell per record per column, so stop
// taking new fields once there are more of them than a record could sensibly
// carry.
const EXTRA_FIELD_LIMIT = 256;

export function buildPasswordDataset(records) {
  if (!records || records.length === 0) return null;

  const extraHeaders = [];
  const seen = new Set(['URL', 'Username', 'Password']);
  for (const record of records) {
    for (const key of Object.keys(record)) {
      if (seen.has(key)) continue;
      seen.add(key);
      extraHeaders.push(key);
    }
    if (extraHeaders.length >= EXTRA_FIELD_LIMIT) break;
  }
  extraHeaders.length = Math.min(extraHeaders.length, EXTRA_FIELD_LIMIT);

  const headers = ['URL', 'Username', 'Password', ...extraHeaders];
  const rows = records.map(record => headers.map(header => (
    Object.prototype.hasOwnProperty.call(record, header) ? record[header] || '' : ''
  )));
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
    // A site plus an account name is an exposure even with no stored password.
    // URL-only stubs survive here; the passwords page drops them.
    return Boolean(url || (username && password));
  });

  if (rows.length === 0) return null;
  return { headers: parsed.headers, rows, raggedRows: parsed.raggedRows || 0 };
}
