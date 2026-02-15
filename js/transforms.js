// Parsing for password/cookie files (block key:value, TSV, Netscape, JSON) and CSV output.

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

// Returns { type: 'block', headers } | { type: 'tsv', columns } | null
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

  // TSV detection
  const nonBlankLines = sample.filter(l => l.trim() !== '');
  const tabLines = nonBlankLines.filter(l => l.includes('\t'));
  if (nonBlankLines.length > 0 && tabLines.length > 0 && tabLines.length / nonBlankLines.length > 0.8) {
    const tabCounts = tabLines.map(l => l.split('\t').length);
    const mode = mostCommon(tabCounts);
    return { type: 'tsv', columns: mode };
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

// TSV parser

function parseTSV(text, columnCount) {
  const defaultHeaders = columnCount === 3
    ? ['URL', 'Username', 'Password']
    : Array.from({ length: columnCount }, (_, i) => `Column ${i + 1}`);

  const rows = text.split('\n')
    .map(line => line.trim())
    .filter(line => line !== '')
    .map(line => {
      const fields = line.split('\t');
      return defaultHeaders.map((_, i) => fields[i] ?? '');
    });

  return { headers: defaultHeaders, rows };
}

function parsePasswordFile(text) {
  const clean = normalizeSeparators(text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n'));
  const format = detectFormat(clean);
  if (!format) return null;

  if (format.type === 'block') {
    return parseBlocks(clean, format.headers);
  }
  if (format.type === 'tsv') {
    return parseTSV(clean, format.columns);
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

function parseCookieFile(text) {
  const clean = text.replace(/^\uFEFF/, '');

  // Try JSON format first
  const trimmed = clean.trim();
  if (trimmed.startsWith('[')) {
    const jsonResult = parseJSONCookies(trimmed);
    if (jsonResult) return jsonResult;
  }

  const lines = clean.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').map(l => l.trim()).filter(l => l !== '');
  if (lines.length === 0) return null;

  // Check for Netscape cookie format (7 tab-separated fields)
  const sample = lines.slice(0, 20);
  if (sample.length === 0) return null;
  const sevenColLines = sample.filter(l => l.split('\t').length === 7);
  if (sevenColLines.length / sample.length < 0.7) return null;

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

  if (rows.length === 0) return null;
  return { headers: COOKIE_HEADERS, rows };
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
  parseCookieFile,
  toCSV,
};
