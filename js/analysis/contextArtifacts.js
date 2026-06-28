import { getFileExtension, formatBytes } from '../core/utils.js';
import { baseDomainFromUrl, parseTimestampValue, normalisePath, truncateText, collectUniqueMatches, countMatches } from '../core/shared.js';
import { URL_REGEX, SCAN_EMAIL_REGEX, SCAN_PHONE_REGEX } from '../core/definitions/patterns.js';
import { detectStructuredPii, hasStructuredPii } from './structuredPii.js';

const CREDENTIAL_HINT_REGEX = /(password|passcode|passphrase|pwd\b|username|login|credential|account|token|backup code|recovery code|密码|用户名|账号|登录名|登陆名|口令)/gi;
const WALLET_HINT_REGEX = /(wallet|seed phrase|mnemonic|private key|secret recovery|metamask|phantom|bitcoin|ethereum|solana|助记词|私钥|\b(?:btc|eth|ltc|xrp|sol|usdt|tron|bch)\b)/gi;

function buildNoteTitle(fileName, text) {
  const baseName = String(fileName || '').replace(/\.[^.]+$/, '').trim();
  const firstMeaningfulLine = String(text || '')
    .split('\n')
    .map(line => line.trim())
    .find(line => line && line.length <= 120);

  if (firstMeaningfulLine && /^note(?:\s+\d+)?$/i.test(baseName)) {
    return firstMeaningfulLine;
  }
  return firstMeaningfulLine || baseName || 'Untitled note';
}

function buildNoteIndicatorSummary({ urls, emails, phones, credentialHints, walletHints, structuredPii }) {
  const parts = [];
  if (structuredPii?.seedPhrase) parts.push('seed phrase');
  if (structuredPii?.panCount > 0) parts.push(`${structuredPii.panCount} card number${structuredPii.panCount === 1 ? '' : 's'}`);
  if (structuredPii?.ibanCount > 0) parts.push(`${structuredPii.ibanCount} IBAN${structuredPii.ibanCount === 1 ? '' : 's'}`);
  if (structuredPii?.cryptoAddrCount > 0) parts.push(`${structuredPii.cryptoAddrCount} crypto address${structuredPii.cryptoAddrCount === 1 ? '' : 'es'}`);
  if (structuredPii?.nationalIdCount > 0) parts.push(`${structuredPii.nationalIdCount} national ID${structuredPii.nationalIdCount === 1 ? '' : 's'}`);
  if (urls.length > 0) parts.push(`${urls.length} URL${urls.length === 1 ? '' : 's'}`);
  if (emails.length > 0) parts.push(`${emails.length} email${emails.length === 1 ? '' : 's'}`);
  if (phones.length > 0) parts.push(`${phones.length} phone${phones.length === 1 ? '' : 's'}`);
  if (credentialHints > 0) parts.push('credential terms');
  if (walletHints > 0) parts.push('wallet terms');
  return parts.join(' \u00B7 ') || 'Plain text note';
}

function classifyNoteType({ urls, emails, credentialHints, walletHints, hasPii }) {
  if (hasPii) return 'Structured PII';
  if (walletHints > 0) return 'Wallet / recovery note';
  if (credentialHints > 0 || (emails.length > 0 && urls.length > 0)) return 'Credential / account note';
  if (urls.length > 0 || emails.length > 0) return 'Web / account reference';
  return 'Personal / reference note';
}

function parseNoteArtifact(text, fileName, sourcePath, lastModified = null) {
  const clean = String(text || '').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  if (!clean) return null;

  const urls = collectUniqueMatches(clean, URL_REGEX, 6);
  const emails = collectUniqueMatches(clean, SCAN_EMAIL_REGEX, 6);
  const phones = collectUniqueMatches(clean, SCAN_PHONE_REGEX, 6);
  const credentialHints = countMatches(clean, CREDENTIAL_HINT_REGEX, { dedupe: false });
  const walletHints = countMatches(clean, WALLET_HINT_REGEX, { dedupe: false });
  const structuredPii = detectStructuredPii(clean);
  const hasPii = hasStructuredPii(structuredPii);
  const domains = [];
  for (const url of urls) {
    const domain = baseDomainFromUrl(url);
    if (domain && !domains.includes(domain)) domains.push(domain);
  }

  return {
    title: buildNoteTitle(fileName, clean),
    preview: truncateText(clean, 180),
    text: clean,
    noteType: classifyNoteType({ urls, emails, credentialHints, walletHints, hasPii }),
    indicators: buildNoteIndicatorSummary({ urls, emails, phones, credentialHints, walletHints, structuredPii }),
    urls,
    emails,
    phones,
    domains,
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

function splitGrabCollection(pathText) {
  const normalised = normalisePath(pathText);
  const importantMatch = normalised.match(/^(.*?)(?:\/|^)(Important Files)\/(.+)$/i);
  if (importantMatch) {
    return {
      collection: 'Important Files',
      relativePath: importantMatch[3],
    };
  }

  // tolerate the spaced folder form "File Grabber"
  const grabMatch = normalised.match(/^(.*?)(?:\/|^)(File ?Grabber)\/(.+)$/i);
  if (grabMatch) {
    return {
      collection: 'FileGrabber',
      relativePath: grabMatch[3],
    };
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
