import { NATIONAL_ID_PATTERNS } from '../core/definitions/patterns.js';
import { BIP39_WORDS } from '../core/definitions/bip39.js';

const PAN_REGEX = /\b(?:\d[ -]?){13,19}\b/g;
const IBAN_REGEX = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
const ETH_ADDRESS_REGEX = /\b0x[a-fA-F0-9]{40}\b/g;
const BTC_ADDRESS_REGEX = /\b(?:bc1[a-z0-9]{25,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const SEED_RUN_REGEX = /\b[a-z]{3,8}(?:\s+[a-z]{3,8}){11,23}\b/g;
const SEED_LENGTHS = new Set([12, 15, 18, 21, 24]);

function isLuhnValid(digits) {
  if (!/^\d+$/.test(digits)) return false;
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

function ibanMod97Valid(iban) {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch >= 'A' && ch <= 'Z' ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const d of code) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

function detectNationalIds(text) {
  const value = String(text || '');
  if (!value) return [];
  const out = [];
  const seen = new Set();
  for (const { rx, label, country, validate } of NATIONAL_ID_PATTERNS) {
    rx.lastIndex = 0;
    let match;
    while ((match = rx.exec(value)) !== null) {
      const raw = match[0];
      if (validate && !validate(raw)) continue;
      const key = `${label}:${raw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ type: label, value: raw, country });
    }
  }
  return out;
}

function detectSeedPhrase(text) {
  const value = String(text || '').toLowerCase();
  if (!value) return false;
  SEED_RUN_REGEX.lastIndex = 0;
  let match;
  while ((match = SEED_RUN_REGEX.exec(value)) !== null) {
    const words = match[0].split(/\s+/);
    for (let start = 0; start < words.length; start++) {
      let len = 0;
      while (start + len < words.length && BIP39_WORDS.has(words[start + len])) len++;
      if (len < 12) { start += len; continue; }
      if (SEED_LENGTHS.has(len)) return true;
      start += len;
    }
  }
  return false;
}

function countMatches(text, regex, filter) {
  const value = String(text || '');
  regex.lastIndex = 0;
  let count = 0;
  let match;
  const seen = new Set();
  while ((match = regex.exec(value)) !== null) {
    const raw = match[0];
    if (filter && !filter(raw)) continue;
    if (seen.has(raw)) continue;
    seen.add(raw);
    count++;
  }
  return count;
}

function detectStructuredPii(text) {
  const value = String(text || '');
  const panCount = countMatches(value, PAN_REGEX, (m) => {
    const d = m.replace(/[ -]/g, '');
    return d.length >= 13 && d.length <= 19 && isLuhnValid(d);
  });
  const ibanCount = countMatches(value.replace(/(?<=[A-Z0-9])[ ]+(?=[A-Z0-9])/g, ''), IBAN_REGEX, (m) => ibanMod97Valid(m));
  const cryptoAddrCount = countMatches(value, ETH_ADDRESS_REGEX) + countMatches(value, BTC_ADDRESS_REGEX);
  const seedPhrase = detectSeedPhrase(value);
  const nationalIds = detectNationalIds(value);

  return {
    seedPhrase,
    panCount,
    ibanCount,
    cryptoAddrCount,
    nationalIdCount: nationalIds.length,
    nationalIds,
  };
}

function hasStructuredPii(pii) {
  if (!pii) return false;
  return Boolean(pii.seedPhrase) || pii.panCount > 0 || pii.ibanCount > 0
    || pii.cryptoAddrCount > 0 || pii.nationalIdCount > 0;
}

export {
  detectNationalIds,
  detectStructuredPii,
  hasStructuredPii,
  isLuhnValid,
};
