import { getFileExtension, formatBytes } from '../core/utils.js';
import { baseDomainFromUrl, parseTimestampValue, normalisePath, truncateText, collectUniqueMatches } from '../core/shared.js';
import { URL_REGEX, SCAN_EMAIL_REGEX, SCAN_PHONE_REGEX } from '../core/definitions/patterns.js';

const CREDENTIAL_HINT_REGEX = /(password|passcode|passphrase|pwd\b|username|login|credential|account|token|backup code|recovery code|密码|用户名|账号|登录名|登陆名|口令)/gi;
const WALLET_HINT_REGEX = /(wallet|seed phrase|mnemonic|private key|secret recovery|metamask|phantom|bitcoin|btc|ethereum|eth|tron|solana|usdt|助记词|私钥)/gi;

function countMatches(text, regex) {
  let count = 0;
  regex.lastIndex = 0;
  while (regex.exec(text) !== null) count++;
  return count;
}

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

function buildNoteIndicatorSummary({ urls, emails, phones, credentialHints, walletHints }) {
  const parts = [];
  if (urls.length > 0) parts.push(`${urls.length} URL${urls.length === 1 ? '' : 's'}`);
  if (emails.length > 0) parts.push(`${emails.length} email${emails.length === 1 ? '' : 's'}`);
  if (phones.length > 0) parts.push(`${phones.length} phone${phones.length === 1 ? '' : 's'}`);
  if (credentialHints > 0) parts.push('credential terms');
  if (walletHints > 0) parts.push('wallet terms');
  return parts.join(' \u00B7 ') || 'Plain text note';
}

function classifyNoteType({ urls, emails, credentialHints, walletHints }) {
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
  const credentialHints = countMatches(clean, CREDENTIAL_HINT_REGEX);
  const walletHints = countMatches(clean, WALLET_HINT_REGEX);
  const domains = [];
  for (const url of urls) {
    const domain = baseDomainFromUrl(url);
    if (domain && !domains.includes(domain)) domains.push(domain);
  }

  return {
    title: buildNoteTitle(fileName, clean),
    preview: truncateText(clean, 180),
    text: clean,
    noteType: classifyNoteType({ urls, emails, credentialHints, walletHints }),
    indicators: buildNoteIndicatorSummary({ urls, emails, phones, credentialHints, walletHints }),
    urls,
    emails,
    phones,
    domains,
    credentialHints,
    walletHints,
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
  return {
    totalNotes: list.length,
    totalUrls: urls,
    totalEmails: emails,
    credentialNotes,
    walletNotes,
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

  const grabMatch = normalised.match(/^(.*?)(?:\/|^)(FileGrabber)\/(.+)$/i);
  if (grabMatch) {
    return {
      collection: 'FileGrabber',
      relativePath: grabMatch[3],
    };
  }

  return null;
}

function classifyGrabbedFile(sourcePath, sizeBytes = 0, lastModified = null) {
  const pathInfo = splitGrabCollection(sourcePath);
  if (!pathInfo) return null;

  const relativePath = pathInfo.relativePath;
  const name = relativePath.split('/').pop() || relativePath;
  const extension = getFileExtension(name).toLowerCase();

  return {
    collection: pathInfo.collection,
    name,
    relativePath,
    extension: extension || '(none)',
    sizeBytes: Number(sizeBytes || 0),
    sizeDisplay: formatBytes(Number(sizeBytes || 0)),
    source: normalisePath(sourcePath),
    modifiedDate: parseTimestampValue(lastModified),
  };
}

function summariseGrabbedFiles(entries) {
  const list = entries || [];
  return {
    fileCount: list.length,
  };
}

export {
  parseNoteArtifact,
  summariseNotes,
  classifyGrabbedFile,
  summariseGrabbedFiles,
};
