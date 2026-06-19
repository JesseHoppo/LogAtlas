import { inferBrowserFromPath, inferProfileFromPath, normalisePath, collectUniqueMatches, uniqueLimited, summariseList } from '../core/shared.js';
import { URL_REGEX, SCAN_EMAIL_REGEX, JWT_SCAN_REGEX, LIMITS } from '../core/definitions/patterns.js';
import { inferStoreService } from '../core/serviceRegistry.js';

const ETH_ADDRESS_REGEX = /\b0x[a-fA-F0-9]{40}\b/g;
const BTC_ADDRESS_REGEX = /\b(?:bc1[a-z0-9]{25,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const UUID_REGEX = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;


function extractPrintableStrings(bytes, minLength = 6) {
  const values = [];
  let current = '';

  for (const byte of bytes) {
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
      continue;
    }

    if (current.length >= minLength) values.push(current);
    current = '';
  }

  if (current.length >= minLength) values.push(current);
  return values;
}

function maybeDecodeText(content, fileName) {
  if (!content) return '';
  if (/\.(?:json|txt|log|conf|cfg|ini)$/i.test(fileName) || /^(?:current|lock|log(?:\.old)?|manifest-\d+)$/i.test(fileName)) {
    return new TextDecoder('utf-8', { fatal: false }).decode(content);
  }
  return '';
}

function detectStoreType(fileName, sourcePath, content) {
  const normalisedPath = normalisePath(sourcePath).toLowerCase();
  const lowerName = String(fileName || '').toLowerCase();
  const bytes = content instanceof Uint8Array ? content : new Uint8Array(content || []);
  const header = bytes.length >= 16 ? new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 16)) : '';

  if (header.startsWith('SQLite format 3')) return 'SQLite';
  if (/\.(?:sqlite|sqlite3|db)$/i.test(lowerName)) return 'SQLite';
  if (/\.ldb$/i.test(lowerName) || /(?:^|\/)(?:current|lock|log(?:\.old)?|manifest-\d+)$/i.test(normalisedPath)) return 'LevelDB';
  if (/\.json$/i.test(lowerName)) return 'JSON';
  if (/\.txt$/i.test(lowerName)) return 'Text';
  return 'Store';
}

function detectArtifactType(fileName, sourcePath, storeType) {
  const normalisedPath = normalisePath(sourcePath).toLowerCase();
  const lowerName = String(fileName || '').toLowerCase();

  if (/keychain/i.test(lowerName) || /keychain/i.test(normalisedPath)) return 'Keychain Dump';
  if (/seed\.txt$/i.test(lowerName) || /seed|mnemonic|recovery/i.test(normalisedPath)) return 'Seed / Recovery';
  if (/token\.json$/i.test(lowerName)) return 'Token Store';
  if (/data\.json$/i.test(lowerName)) return 'Application Data';
  if (storeType === 'SQLite') return 'SQLite Store';
  if (storeType === 'LevelDB') return 'LevelDB Store';
  if (/\.(?:json|txt)$/i.test(lowerName)) return 'Structured Store';
  return 'Store Artifact';
}


function collectJsonFieldValues(value, results = { emails: [], urls: [], ids: [], tokenCount: 0, seedHints: 0 }, depth = 0) {
  if (value == null) return results;
  if (depth > LIMITS.flattenMaxDepth) return results;

  if (Array.isArray(value)) {
    for (const item of value) collectJsonFieldValues(item, results, depth + 1);
    return results;
  }

  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const lowerKey = key.toLowerCase();
      if (/token/.test(lowerKey) && typeof child === 'string' && child.trim()) results.tokenCount++;
      if (/(?:mnemonic|seed|recovery)/.test(lowerKey) && child) results.seedHints++;
      if (/(?:email|mail)/.test(lowerKey) && typeof child === 'string') results.emails.push(child);
      if (/(?:^|_)(?:url|server|vault|api|identity)(?:$|_|s$)/.test(lowerKey) && typeof child === 'string') results.urls.push(child);
      if ((/(?:^|_)(?:id|uuid)$/i.test(key) || /[a-z](?:Id|Uuid|UUID)$/.test(key)) && typeof child === 'string' && UUID_REGEX.test(child)) results.ids.push(child);
      collectJsonFieldValues(child, results, depth + 1);
    }
    return results;
  }

  if (typeof value === 'string') {
    results.emails.push(...collectUniqueMatches(value, SCAN_EMAIL_REGEX, 6));
    results.urls.push(...collectUniqueMatches(value, URL_REGEX, 6));
  }

  return results;
}

function buildHighlights({ emails, urls, ethAddresses, btcAddresses, tokenCount, seedHints, ids }) {
  const parts = [];
  if (emails.length > 0) parts.push(`email: ${summariseList(emails)}`);
  if (urls.length > 0) parts.push(`url: ${summariseList(urls)}`);
  if (ethAddresses.length > 0) parts.push(`ETH: ${summariseList(ethAddresses, 1)}`);
  if (btcAddresses.length > 0) parts.push(`BTC: ${summariseList(btcAddresses, 1)}`);
  if (ids.length > 0) parts.push(`id: ${summariseList(ids, 1)}`);
  if (tokenCount > 0) parts.push(`${tokenCount} token${tokenCount === 1 ? '' : 's'}`);
  if (seedHints > 0) parts.push('seed indicators');
  return parts.join(' | ') || 'Raw store present';
}

function parseWalletArtifact(content, fileName, sourcePath) {
  if (!content) return null;

  const bytes = content instanceof Uint8Array ? content : new Uint8Array(content);
  const text = maybeDecodeText(bytes, fileName);
  const carvedStrings = text ? [] : extractPrintableStrings(bytes);
  const combinedText = text || carvedStrings.join('\n');
  const service = inferStoreService(sourcePath || fileName, combinedText);
  const normalisedPath = normalisePath(sourcePath || fileName);
  const storeType = detectStoreType(fileName, normalisedPath, bytes);
  const artifactType = detectArtifactType(fileName, normalisedPath, storeType);

  let jsonSignals = { emails: [], urls: [], ids: [], tokenCount: 0, seedHints: 0 };
  if (text && /\.json$/i.test(fileName) && text.length <= LIMITS.jsonParseMaxBytes) {
    try {
      jsonSignals = collectJsonFieldValues(JSON.parse(text), jsonSignals);
    } catch {
      // treat as plain text
    }
  }

  const emails = uniqueLimited([
    ...jsonSignals.emails,
    ...collectUniqueMatches(combinedText, SCAN_EMAIL_REGEX, 6),
  ]);
  const urls = uniqueLimited([
    ...jsonSignals.urls,
    ...collectUniqueMatches(combinedText, URL_REGEX, 6).filter(url => !/chrome-extension:\/\//i.test(url)),
  ]);
  const ethAddresses = collectUniqueMatches(combinedText, ETH_ADDRESS_REGEX, 4);
  const btcAddresses = collectUniqueMatches(combinedText, BTC_ADDRESS_REGEX, 4);
  const ids = uniqueLimited(jsonSignals.ids, 3);

  let tokenCount = jsonSignals.tokenCount;
  const jwtMatches = collectUniqueMatches(combinedText, JWT_SCAN_REGEX, 6);
  tokenCount += jwtMatches.length;

  const seedHints = jsonSignals.seedHints + ((/mnemonic|seed phrase|recovery phrase|secret recovery/i.test(combinedText)) ? 1 : 0);
  const isPasswordManager = service.category === 'Password Manager' || service.category === 'Vault'
    || /bitwarden|1password|keepass|lastpass|dashlane|nordpass|roboform/i.test(service.name);
  const effectiveSeedHints = isPasswordManager ? 0 : seedHints;

  const meaningful = emails.length || urls.length || ethAddresses.length || btcAddresses.length || tokenCount || effectiveSeedHints;
  const pathLooksRelevant = /(wallet|bitwarden|metamask|phantom|trust wallet|exodus|atomic|keplr|tronlink|ronin|rabby|extension|local extension settings|token\.json|seed\.txt|keychain)/i.test(normalisedPath);
  if (!meaningful && !pathLooksRelevant) return null;

  return {
    service: service.name,
    category: service.category,
    artifactType,
    storeType,
    browser: inferBrowserFromPath(normalisedPath),
    profile: inferProfileFromPath(normalisedPath),
    highlights: buildHighlights({ emails, urls, ethAddresses, btcAddresses, tokenCount, seedHints: effectiveSeedHints, ids }),
    emailCount: emails.length,
    addressCount: ethAddresses.length + btcAddresses.length,
    tokenCount,
    seedHints: effectiveSeedHints,
    source: sourcePath,
  };
}

export { parseWalletArtifact };
