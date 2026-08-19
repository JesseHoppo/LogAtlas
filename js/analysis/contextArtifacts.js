import { getFileExtension, formatBytes } from '../core/utils.js';
import { baseDomainFromUrl, parseTimestampValue, normalisePath, truncateText, countMatches } from '../core/shared.js';
import { URL_REGEX, SCAN_EMAIL_REGEX, SCAN_PHONE_REGEX } from '../core/definitions/patterns.js';
import { detectStructuredPii, hasStructuredPii } from './structuredPii.js';

const CREDENTIAL_HINT_REGEX = /(password|passcode|passphrase|pwd\b|username|login|credential|account|token|backup code|recovery code|密码|用户名|账号|登录名|登陆名|口令)/gi;
const WALLET_STRONG_REGEX = /(wallet|seed phrase|mnemonic|private key|secret recovery|metamask|phantom|bitcoin|ethereum|solana|助记词|私钥)/gi;
// Tickers are ordinary words elsewhere — "Costa del Sol", "ETH Zurich" — so they only
// count beside an amount or an address on the same line.
const WALLET_TICKER_REGEX = /\b(?:btc|eth|ltc|xrp|usdt|bch)\b/gi;
const TICKER_AMOUNT_BEFORE_REGEX = /\d(?:[\d.,]*\d)?\s*$/;
const TICKER_AMOUNT_AFTER_REGEX = /^\s*[:=]?\s*\d/;
const IP_LIKE_REGEX = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const DATE_LIKE_REGEX = /\b(?:\d{1,2}[.\-]\d{1,2}[.\-]\d{4}|\d{4}[.\-]\d{1,2}[.\-]\d{1,2})\b/;
// The scan regex also grabs dotted quads, dates and long digit runs, so sieve inside the
// collector: the limit has to apply to accepted phones, not to raw candidates.
const PHONE_LIMIT = 6;
const CANDIDATE_LIMIT = 2000;
const SAMPLE_LIMIT = 6;

const VERSION_LIKE_REGEX = /^\d+(?:\.\d+){2,}$/;
const REFERENCE_PREFIX_REGEX = /([A-Za-z]+)[-/]?$/;
const TRAILING_YEAR_REGEX = /\s(?:19|20)\d{2}$/;
const PHONE_LABELS = new Set([
  'tel', 'telephone', 'ph', 'phone', 'mob', 'mobile', 'cell', 'fax',
  'contact', 'whatsapp', 'no', 'nr', 'num', 'number', 'm', 't', 'p',
]);

function countDigits(value) {
  return String(value).replace(/\D/g, '').length;
}

function looksLikePhone(value) {
  const candidate = String(value).trim();
  if (IP_LIKE_REGEX.test(candidate) || DATE_LIKE_REGEX.test(candidate)) return false;
  if (VERSION_LIKE_REGEX.test(candidate)) return false;
  const digits = countDigits(candidate);
  return digits >= 7 && digits <= 15;
}

// Digits hanging off the end of an identifier — JR-10040381, ab783724587d — are the
// reference, not a number anyone can dial. A phone label in front is the exception.
function isReferenceTail(text, index) {
  if (index === 0) return false;
  const prefix = text.slice(Math.max(0, index - 20), index).match(REFERENCE_PREFIX_REGEX);
  return Boolean(prefix) && !PHONE_LABELS.has(prefix[1].toLowerCase());
}

// A year-shaped final group belongs to the number when the number is written in groups
// (+61 3 9000 2022); on a single run it is the date sitting next to a reference.
function trimTrailingYear(value) {
  if (!TRAILING_YEAR_REGEX.test(value)) return value;
  const head = value.replace(TRAILING_YEAR_REGEX, '').trim();
  if (head.split(/\s+/).length >= 3) return value;
  const digits = countDigits(head);
  return digits >= 7 && digits <= 15 ? head : value;
}

function collectPhones(text) {
  const seen = new Set();
  const phones = [];
  let candidates = 0;
  let match;
  SCAN_PHONE_REGEX.lastIndex = 0;
  while ((match = SCAN_PHONE_REGEX.exec(text)) !== null) {
    if (++candidates > CANDIDATE_LIMIT) break;
    if (isReferenceTail(text, match.index)) continue;
    const value = trimTrailingYear(String(match[0] || '').trim());
    if (!value || !looksLikePhone(value)) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (phones.length < PHONE_LIMIT) phones.push(value);
  }
  return { phones, total: seen.size };
}

// Keeps the display sample and the full unique count in step; the candidate ceiling
// stops a pathological note from being scanned to death.
function sampleUniqueMatches(text, regex, limit = SAMPLE_LIMIT) {
  const seen = new Set();
  const matches = [];
  let candidates = 0;
  let match;
  regex.lastIndex = 0;
  while ((match = regex.exec(text)) !== null) {
    if (++candidates > CANDIDATE_LIMIT) break;
    const value = String(match[0] || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (matches.length < limit) matches.push(value);
  }
  return { matches, total: seen.size };
}

function countWalletHints(text) {
  const strong = countMatches(text, WALLET_STRONG_REGEX, { dedupe: false });
  let tickers = 0;
  for (const line of String(text).split('\n')) {
    let hasAddress = null;
    let match;
    WALLET_TICKER_REGEX.lastIndex = 0;
    while ((match = WALLET_TICKER_REGEX.exec(line)) !== null) {
      const before = line.slice(0, match.index);
      const after = line.slice(match.index + match[0].length);
      if (TICKER_AMOUNT_BEFORE_REGEX.test(before) || TICKER_AMOUNT_AFTER_REGEX.test(after)) {
        tickers++;
        continue;
      }
      if (hasAddress === null) hasAddress = detectStructuredPii(line).cryptoAddrCount > 0;
      if (hasAddress) tickers++;
    }
  }
  return { strong, tickers };
}

function buildNoteTitle(fileName, text) {
  const baseName = String(fileName || '').replace(/\.[^.]+$/, '').trim();
  const firstMeaningfulLine = String(text || '')
    .split('\n')
    .map(line => line.trim())
    .find(line => line && line.length <= 120);

  return firstMeaningfulLine || baseName || 'Untitled note';
}

function buildNoteIndicatorSummary({ urlTotal, emailTotal, phoneTotal, credentialHints, walletTerms, walletTickers, structuredPii }) {
  const parts = [];
  if (structuredPii?.seedPhrase) parts.push('seed phrase');
  if (structuredPii?.panCount > 0) parts.push(`${structuredPii.panCount.toLocaleString()} card number${structuredPii.panCount === 1 ? '' : 's'}`);
  if (structuredPii?.ibanCount > 0) parts.push(`${structuredPii.ibanCount.toLocaleString()} IBAN${structuredPii.ibanCount === 1 ? '' : 's'}`);
  if (structuredPii?.cryptoAddrCount > 0) parts.push(`${structuredPii.cryptoAddrCount.toLocaleString()} crypto address${structuredPii.cryptoAddrCount === 1 ? '' : 'es'}`);
  if (structuredPii?.nationalIdCount > 0) parts.push(`${structuredPii.nationalIdCount.toLocaleString()} national ID${structuredPii.nationalIdCount === 1 ? '' : 's'}`);
  if (urlTotal > 0) parts.push(`${urlTotal.toLocaleString()} URL${urlTotal === 1 ? '' : 's'}`);
  if (emailTotal > 0) parts.push(`${emailTotal.toLocaleString()} email${emailTotal === 1 ? '' : 's'}`);
  if (phoneTotal > 0) parts.push(`${phoneTotal.toLocaleString()} phone${phoneTotal === 1 ? '' : 's'}`);
  if (credentialHints > 0) parts.push('credential terms');
  if (walletTerms > 0) parts.push('wallet terms');
  else if (walletTickers > 0) parts.push('crypto ticker');
  return parts.join(' \u00B7 ') || 'Plain text note';
}

function classifyNoteType({ urlTotal, emailTotal, credentialHints, walletHints, hasPii }) {
  if (hasPii) return 'Structured PII';
  if (walletHints > 0) return 'Wallet / recovery note';
  if (credentialHints > 0 || (emailTotal > 0 && urlTotal > 0)) return 'Credential / account note';
  if (urlTotal > 0 || emailTotal > 0) return 'Web / account reference';
  return 'Personal / reference note';
}

function parseNoteArtifact(text, fileName, sourcePath, lastModified = null) {
  const clean = String(text || '').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  if (!clean) return null;

  const urlMatches = sampleUniqueMatches(clean, URL_REGEX);
  const emailMatches = sampleUniqueMatches(clean, SCAN_EMAIL_REGEX);
  const phoneMatches = collectPhones(clean);
  const credentialHints = countMatches(clean, CREDENTIAL_HINT_REGEX, { dedupe: false });
  const wallet = countWalletHints(clean);
  const walletHints = wallet.strong + wallet.tickers;
  const structuredPii = detectStructuredPii(clean);
  const hasPii = hasStructuredPii(structuredPii);
  const urls = urlMatches.matches;
  const urlTotal = urlMatches.total;
  const emailTotal = emailMatches.total;
  const domains = [];
  for (const url of urls) {
    const domain = baseDomainFromUrl(url);
    if (domain && !domains.includes(domain)) domains.push(domain);
  }

  return {
    title: buildNoteTitle(fileName, clean),
    preview: truncateText(clean, 180),
    text: clean,
    noteType: classifyNoteType({ urlTotal, emailTotal, credentialHints, walletHints, hasPii }),
    indicators: buildNoteIndicatorSummary({
      urlTotal,
      emailTotal,
      phoneTotal: phoneMatches.total,
      credentialHints,
      walletTerms: wallet.strong,
      walletTickers: wallet.tickers,
      structuredPii,
    }),
    urls,
    emails: emailMatches.matches,
    phones: phoneMatches.phones,
    domains,
    urlTotal,
    emailTotal,
    phoneTotal: phoneMatches.total,
    credentialHints,
    walletHints,
    structuredPii,
    hasStructuredPii: hasPii,
    source: normalisePath(sourcePath || fileName),
    modifiedDate: parseTimestampValue(lastModified),
  };
}

function summariseNotes(entries) {
  const list = entries || [];
  const urls = list.reduce((sum, entry) => sum + (entry.urls?.length || 0), 0);
  const emails = list.reduce((sum, entry) => sum + (entry.emails?.length || 0), 0);
  const credentialNotes = list.filter(entry => entry.credentialHints > 0).length;
  const walletNotes = list.filter(entry => entry.walletHints > 0).length;
  const structuredPiiNotes = list.filter(entry => entry.hasStructuredPii).length;
  const seedPhraseNotes = list.filter(entry => entry.structuredPii?.seedPhrase).length;
  return {
    totalNotes: list.length,
    totalUrls: urls,
    totalEmails: emails,
    credentialNotes,
    walletNotes,
    structuredPiiNotes,
    seedPhraseNotes,
  };
}

// Ordered: "Important Files" wins over the bare "Files" root when a log nests both.
const GRAB_COLLECTIONS = [
  { collection: 'Important Files', pattern: /(?:^|\/)important files\/(.+)$/i },
  // tolerate the spaced folder form "File Grabber"
  { collection: 'FileGrabber', pattern: /(?:^|\/)file ?grabber\/(.+)$/i },
  { collection: 'Files', pattern: /(?:^|\/)files\/(.+)$/i },
];

function splitGrabCollection(pathText) {
  const normalised = normalisePath(pathText);
  for (const { collection, pattern } of GRAB_COLLECTIONS) {
    const match = normalised.match(pattern);
    if (match) {
      return { collection, relativePath: match[1] };
    }
  }
  return null;
}

const HIGH_VALUE_PATTERNS = [
  { label: 'KeePass DB', test: /\.kdbx?$/i },
  { label: 'Crypto wallet file', test: /(?:^|\/)wallet\.dat$/i },
  { label: '1Password vault', test: /\.opvault$/i },
  { label: 'OpenVPN profile', test: /\.ovpn$/i },
  { label: 'SSH private key', test: /(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)$|\.pem$|\.ppk$/i },
  { label: 'FileZilla sites', test: /(?:^|\/)sitemanager\.xml$/i },
];

function matchHighValue(relativePath, name) {
  const rel = String(relativePath || '').toLowerCase();
  const file = String(name || '').toLowerCase();
  for (const { label, test } of HIGH_VALUE_PATTERNS) {
    if (test.test(rel) || test.test(file)) return label;
  }
  return '';
}

function classifyGrabbedFile(sourcePath, sizeBytes = 0, lastModified = null) {
  const pathInfo = splitGrabCollection(sourcePath);
  if (!pathInfo) return null;

  const relativePath = pathInfo.relativePath;
  const name = relativePath.split('/').pop() || relativePath;
  const extension = getFileExtension(name);
  const highValue = matchHighValue(relativePath, name);

  return {
    collection: pathInfo.collection,
    name,
    relativePath,
    extension: extension || '(none)',
    sizeBytes: Number(sizeBytes || 0),
    sizeDisplay: formatBytes(Number(sizeBytes || 0)),
    highValue,
    isHighValue: Boolean(highValue),
    source: normalisePath(sourcePath),
    modifiedDate: parseTimestampValue(lastModified),
  };
}

function summariseGrabbedFiles(entries) {
  const list = entries || [];
  const highValue = list.filter(entry => entry.isHighValue);
  const byLabel = new Map();
  for (const entry of highValue) {
    byLabel.set(entry.highValue, (byLabel.get(entry.highValue) || 0) + 1);
  }
  return {
    fileCount: list.length,
    highValueCount: highValue.length,
    highValueBreakdown: [...byLabel.entries()].map(([label, count]) => ({ label, count })),
  };
}

export {
  parseNoteArtifact,
  summariseNotes,
  classifyGrabbedFile,
  summariseGrabbedFiles,
};
