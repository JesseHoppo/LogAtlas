import { NATIONAL_ID_PATTERNS } from '../core/definitions/patterns.js';
import { BIP39_WORDS } from '../core/definitions/bip39.js';
import { countMatches } from '../core/shared.js';
import { BTC_ADDRESS_REGEX, ETH_ADDRESS_REGEX, isValidBitcoinAddress } from '../core/cryptoAddress.js';

const PAN_REGEX = /\b(?:\d[ -]?){13,19}\b/g;
const IBAN_REGEX = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
const SEED_WORD_REGEX = /[a-z]+/g;
const MIN_SEED_WORDS = 12;

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

// A seed gets written down however its owner felt like it — commas, numbering, bullets,
// one word per line — so the walk ignores whatever sits between letter tokens. Bridging
// separators that freely also bridges unrelated lines, hence the distinctness test: a
// seed draws its words from 2048 and repeats at most one, while the log noise that
// tokenises into a long BIP39 run (`true, true, ...`, `[enter]`) is a word or two cycling.
// Runs are taken end to end, never overlapping, so a 24-word seed counts once.
function countSeedPhrases(text, limit = Infinity) {
  const value = String(text || '').toLowerCase();
  if (!value) return 0;
  SEED_WORD_REGEX.lastIndex = 0;
  const run = [];
  let found = 0;
  let match;
  while ((match = SEED_WORD_REGEX.exec(value)) !== null) {
    if (!BIP39_WORDS.has(match[0])) {
      run.length = 0;
      continue;
    }
    run.push(match[0]);
    if (run.length > MIN_SEED_WORDS) run.shift();
    if (run.length === MIN_SEED_WORDS && new Set(run).size >= MIN_SEED_WORDS - 1) {
      found++;
      if (found >= limit) return found;
      run.length = 0;
    }
  }
  return found;
}

function detectSeedPhrase(text) {
  return countSeedPhrases(text, 1) > 0;
}

function detectStructuredPii(text) {
  const value = String(text || '');
  const panCount = countMatches(value, PAN_REGEX, { filter: (m) => {
    const d = m.replace(/[ -]/g, '');
    return d.length >= 13 && d.length <= 19 && isLuhnValid(d);
  } });
  const ibanCount = countMatches(value.replace(/(?<=[A-Z0-9])[ ]+(?=[A-Z0-9])/g, ''), IBAN_REGEX, { filter: (m) => ibanMod97Valid(m) });
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
  countSeedPhrases,
  detectNationalIds,
  detectSeedPhrase,
  detectStructuredPii,
  hasStructuredPii,
  isLuhnValid,
};
