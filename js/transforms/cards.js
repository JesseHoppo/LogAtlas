// Credit card file parsing.

import {
  CREDIT_CARD_KV_PATTERN,
  normaliseText,
  normaliseSeparators,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
} from './delimited.js';

function isPanLength(value) {
  const d = String(value || '').replace(/\D/g, '');
  return d.length >= 12 && d.length <= 19;
}

function isLuhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function isLuhnPan(value) {
  const d = String(value || '').replace(/\D/g, '');
  return isPanLength(d) && isLuhnValid(d);
}

// Unlabelled columns hold epoch milliseconds and record ids in the same shape as
// a PAN, so where more than one cell qualifies on length the Luhn-valid one
// wins. Length alone still decides when nothing checks out, since a labelled or
// lone candidate is evidence even when the capture is partial.
function pickPanIndex(cells) {
  let fallback = -1;
  for (let i = 0; i < cells.length; i++) {
    if (!isPanLength(cells[i])) continue;
    if (isLuhnPan(cells[i])) return i;
    if (fallback === -1) fallback = i;
  }
  return fallback;
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
    const expiration = record.expirationdate || record['expiration date'] || record.expiry || record.expires || record.expire || record.date || buildExpirationValue(month, year);
    const filePath = record.filepath || record['file path'] || record.path || record.target || '';

    const pan = isPanLength(cardNumber) ? cardNumber : '';
    if (!pan && !expiration && !nameOnCard && !cvc && !filePath) continue;
    rows.push([pan, nameOnCard, cvc, expiration, filePath]);
  }

  return rows;
}

function buildExpirationValue(month = '', year = '') {
  if (!month && !year) return '';
  return `${month}/${year}`.replace(/^\/|\/$/g, '');
}

function mapCreditCardHeaders(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const headerMap = {};
  for (let i = 0; i < parsed.headers.length; i++) {
    const header = parsed.headers[i].toLowerCase();
    if (/^(?:card\s*number|cardnumber|number|pan)$/i.test(header)) headerMap.number = i;
    else if (/^(?:name\s*on\s*card|nameoncard|cardholder|card\s*holder|holder|name)$/i.test(header)) headerMap.name = i;
    else if (/^(?:cvc|cvv|security\s*code)$/i.test(header)) headerMap.cvc = i;
    else if (/^(?:expiration(?:\s*date)?|expiry|expires?|expire|date)$/i.test(header)) headerMap.expiration = i;
    else if (/^(?:month|exp\s*month|expiry\s*month)$/i.test(header)) headerMap.expirationMonth = i;
    else if (/^(?:year|exp\s*year|expiry\s*year)$/i.test(header)) headerMap.expirationYear = i;
    else if (/^(?:file\s*path|filepath|path|source|target)$/i.test(header)) headerMap.path = i;
  }

  const rows = parsed.rows
    .map((row) => {
      const expiration = (row[headerMap.expiration ?? -1] || '').trim()
        || buildExpirationValue(
          (row[headerMap.expirationMonth ?? -1] || '').trim(),
          (row[headerMap.expirationYear ?? -1] || '').trim(),
        );
      const rawPan = row[headerMap.number ?? -1] || '';
      const pan = isPanLength(rawPan) ? rawPan : '';
      return [
        pan,
        row[headerMap.name ?? -1] || '',
        row[headerMap.cvc ?? -1] || '',
        expiration,
        row[headerMap.path ?? -1] || '',
      ];
    })
    .filter(row => row.some(cell => (cell || '').trim()));

  return rows.length > 0 ? { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows } : null;
}

function mapCreditCardRowsByContent(parsed) {
  if (!parsed || !parsed.rows || parsed.rows.length === 0) return null;

  const rows = [];
  for (const row of parsed.rows) {
    const cells = row.map(cell => (cell || '').trim());
    if (cells.every(cell => !cell)) continue;

    const panIndex = pickPanIndex(cells);
    const cardNumber = panIndex >= 0 ? cells[panIndex] : '';
    let nameOnCard = '';
    let cvc = '';
    let expiration = '';
    let filePath = '';
    // Position, not value: a month, a year and a CVC can all read "11".
    const numericCandidates = [];

    for (let i = 0; i < cells.length; i++) {
      if (i === panIndex) continue;
      const cell = cells[i];
      if (!expiration && /^\d{1,2}[/-]\d{2,4}$/.test(cell)) {
        expiration = cell;
        continue;
      }
      if (!filePath && /[\\/]/.test(cell)) {
        filePath = cell;
        continue;
      }
      if (/^\d{1,4}$/.test(cell)) {
        numericCandidates.push(cell);
        continue;
      }
      if (!nameOnCard && /[A-Za-z]/.test(cell)) {
        nameOnCard = cell;
      }
    }

    let chosenMonth = '';
    let chosenYear = '';
    if (!expiration) {
      chosenMonth = numericCandidates.find(cell => /^(?:0?[1-9]|1[0-2])$/.test(cell)) || '';
      chosenYear = numericCandidates.find(cell => cell !== chosenMonth && /^(?:\d{2}|\d{4})$/.test(cell)) || '';
      expiration = buildExpirationValue(chosenMonth, chosenYear);
    }

    if (!cvc) {
      const used = new Set([chosenMonth, chosenYear].filter(Boolean));
      cvc = numericCandidates.find(cell => !used.has(cell) && /^\d{3,4}$/.test(cell)) || '';
    }

    if (!cardNumber && !nameOnCard && !expiration && !cvc && !filePath) continue;
    rows.push([cardNumber, nameOnCard, cvc, expiration, filePath]);
  }

  return rows.length > 0 ? { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows } : null;
}

function parsePipeDelimitedCardLine(line) {
  const parts = line.split('|').map(part => part.trim()).filter(Boolean);
  if (parts.length < 4) return null;

  // A short numeric field only reads as a CVC once the PAN is accounted for,
  // so a line with no card number is not this shape at all.
  const panIndex = pickPanIndex(parts);
  if (panIndex < 0) return null;

  let nameOnCard = '';
  let cvc = '';
  let expiration = '';

  for (let i = 0; i < parts.length; i++) {
    if (i === panIndex) continue;
    const part = parts[i];
    if (!expiration && /^\d{1,2}[/-]\d{2,4}$/.test(part)) {
      expiration = part;
      continue;
    }
    if (!cvc && /^\d{3,4}$/.test(part)) {
      cvc = part;
      continue;
    }
    if (!nameOnCard && /[A-Za-z]/.test(part)) {
      nameOnCard = part;
    }
  }

  return [parts[panIndex], nameOnCard, cvc, expiration, ''];
}

export function parseCreditCardFile(text) {
  const clean = normaliseSeparators(normaliseText(text));

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

    const pipeDelimited = parsePipeDelimitedCardLine(line);
    if (pipeDelimited) {
      rows.push(pipeDelimited);
      continue;
    }

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
