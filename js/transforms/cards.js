// Credit card file parsing.

import {
  CREDIT_CARD_KV_PATTERN,
  normalizeText,
  normalizeSeparators,
} from './shared.js';
import {
  detectFormat,
  parseDelimited,
  parseWithConfig,
} from './delimited.js';

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
      return [
        row[headerMap.number ?? -1] || '',
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

    let cardNumber = '';
    let nameOnCard = '';
    let cvc = '';
    let expiration = '';
    let filePath = '';
    const numericCandidates = [];

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

    if (!expiration) {
      const month = numericCandidates.find(cell => /^(?:0?[1-9]|1[0-2])$/.test(cell)) || '';
      const year = numericCandidates.find(cell => cell !== month && /^(?:\d{2}|\d{4})$/.test(cell)) || '';
      expiration = buildExpirationValue(month, year);
    }

    if (!cvc) {
      cvc = numericCandidates.find(cell =>
        cell !== expiration.split('/')[0]
        && cell !== expiration.split('/')[1]
        && /^\d{3,4}$/.test(cell)
      ) || '';
    }

    if (!cardNumber && !nameOnCard && !expiration && !cvc && !filePath) continue;
    rows.push([cardNumber, nameOnCard, cvc, expiration, filePath]);
  }

  return rows.length > 0 ? { headers: ['Card Number', 'Name On Card', 'CVC', 'Expiration', 'File Path'], rows } : null;
}

function parsePipeDelimitedCardLine(line) {
  const parts = line.split('|').map(part => part.trim()).filter(Boolean);
  if (parts.length < 4) return null;

  let cardNumber = '';
  let nameOnCard = '';
  let cvc = '';
  let expiration = '';

  for (const part of parts) {
    const digits = part.replace(/\D/g, '');
    if (!cardNumber && digits.length >= 12 && digits.length <= 19) {
      cardNumber = part;
      continue;
    }
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

  if (!cardNumber) return null;
  return [cardNumber, nameOnCard, cvc, expiration, ''];
}

export function parseCreditCardFile(text, config) {
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
