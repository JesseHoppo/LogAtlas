import { inferBrowserFromPath, inferProfileFromPath, normalisePath, collectUniqueMatches, uniqueLimited, summariseList } from '../core/shared.js';
import { URL_REGEX, SCAN_EMAIL_REGEX, EMAIL_REGEX, JWT_SCAN_REGEX, LIMITS } from '../core/definitions/patterns.js';
import { inferStoreService } from '../core/serviceRegistry.js';
import { DISCORD_TOKEN_PATTERN } from '../transforms/shared.js';

const ETH_ADDRESS_REGEX = /\b0x[a-fA-F0-9]{40}\b/g;
const BTC_ADDRESS_REGEX = /\b(?:bc1[a-z0-9]{25,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const UUID_REGEX = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;
const DISCORD_ID_SEGMENT = /^\d{17,20}$/;


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
  // A numbered LevelDB write-ahead log is binary despite the extension; decoding
  // it yields replacement-character soup, so it is carved like its .ldb siblings.
  if (/^\d+\.log$/i.test(fileName)) return '';
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
  if (/\.ldb$/i.test(lowerName) || /(?:^|\/)(?:current|lock|log(?:\.old)?|manifest-\d+|\d+\.log)$/i.test(normalisedPath)) return 'LevelDB';
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


function decodeBase64Url(segment) {
  const padding = (4 - (segment.length % 4)) % 4;
  if (padding === 3) return '';
  try {
    return atob(segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padding));
  } catch {
    return '';
  }
}

// The scan regex matches any dot-separated triple, so hostnames, slugs and
// version strings read as tokens. Real ones give themselves away in the leading
// segment: it decodes to a JOSE header (Steam pads its header with whitespace,
// so the encoded form is not always `eyJ`) or to a Discord snowflake id.
function looksLikeToken(value) {
  const decoded = decodeBase64Url(value.slice(0, value.indexOf('.')));
  if (DISCORD_ID_SEGMENT.test(decoded)) return DISCORD_TOKEN_PATTERN.test(value);
  if (!/^\s*\{/.test(decoded)) return false;
  try {
    const header = JSON.parse(decoded);
    return Boolean(header) && typeof header === 'object' && !Array.isArray(header);
  } catch {
    return false;
  }
}

function collectTokens(text, limit = 6) {
  const tokens = [];
  const seen = new Set();
  JWT_SCAN_REGEX.lastIndex = 0;
  let match;
  while ((match = JWT_SCAN_REGEX.exec(text)) !== null) {
    const token = match[0];
    if (seen.has(token) || !looksLikeToken(token)) continue;
    seen.add(token);
    tokens.push(token);
    if (tokens.length >= limit) break;
  }
  return tokens;
}

// A bare word like `atomic`, `exodus`, `steam` or `keychain` reads fine as a
// folder name but also turns up in ordinary prose and in the carve of any
// extension store, so it must not name a service off the blob. The registry
// keeps that line itself — only vendor-unique names carry a content pattern —
// so the bytes go through as they are, capped because a carved LevelDB runs to
// megabytes and the vendor names sit in its head. Validated tokens are appended
// whole: their issuer claim names the service outright wherever it appears.
const SERVICE_EVIDENCE_LIMIT = 262144;

function serviceEvidence(text) {
  if (!text) return '';
  return [String(text).slice(0, SERVICE_EVIDENCE_LIMIT), ...collectTokens(text, 3)].join('\n');
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
      if (/(?:email|mail)/.test(lowerKey) && typeof child === 'string' && EMAIL_REGEX.test(child.trim())) results.emails.push(child.trim());
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

// macOS keychain dumps list many per-service records; parse them so the single
// wallet row reflects the actual record count/contents instead of one opaque entry.
function unwrapByteString(value) {
  const m = String(value || '').trim().match(/^b'(.*)'$/s) || String(value || '').trim().match(/^b"(.*)"$/s);
  return (m ? m[1] : String(value || '')).replace(/\\x[0-9a-f]{2}/gi, '').trim();
}

function parseKeychainRecords(text) {
  const blocks = String(text || '').split(/^\[\+\]\s.*$/m).slice(1);
  const records = [];
  for (const block of blocks) {
    const rec = { service: '', account: '', hasSecret: false };
    for (const line of block.split('\n')) {
      const m = line.match(/^\s*\[-\]\s*([^:]+):\s*(.*)$/);
      if (!m) continue;
      const key = m[1].trim().toLowerCase();
      const val = m[2];
      if (key === 'service') rec.service = unwrapByteString(val);
      else if (key === 'account') rec.account = unwrapByteString(val);
      else if (/password/.test(key) && unwrapByteString(val)) rec.hasSecret = true;
    }
    if (rec.service || rec.account || rec.hasSecret) records.push(rec);
  }
  return records;
}

function parseWalletArtifact(content, fileName, sourcePath) {
  if (!content) return null;

  const bytes = content instanceof Uint8Array ? content : new Uint8Array(content);
  const text = maybeDecodeText(bytes, fileName);
  const carved = !text;
  const carvedStrings = carved ? extractPrintableStrings(bytes) : [];
  const combinedText = text || carvedStrings.join('\n');
  const normalisedPath = normalisePath(sourcePath || fileName);
  const pathService = inferStoreService(normalisedPath);
  const service = pathService.name === 'Unknown'
    ? inferStoreService(normalisedPath, serviceEvidence(combinedText))
    : pathService;
  const storeType = detectStoreType(fileName, normalisedPath, bytes);
  const artifactType = detectArtifactType(fileName, normalisedPath, storeType);

  if (artifactType === 'Keychain Dump' && text) {
    const records = parseKeychainRecords(text);
    if (records.length > 0) {
      const services = uniqueLimited(records.map(r => r.service).filter(Boolean), 6);
      const accounts = uniqueLimited(records.map(r => r.account).filter(Boolean), 6);
      const withSecret = records.filter(r => r.hasSecret).length;
      const parts = [`${records.length} keychain record${records.length === 1 ? '' : 's'}`];
      if (services.length) parts.push(`services: ${summariseList(services)}`);
      if (accounts.length) parts.push(`accounts: ${summariseList(accounts)}`);
      return {
        service: service.name,
        category: service.category,
        artifactType,
        storeType,
        browser: inferBrowserFromPath(normalisedPath),
        profile: inferProfileFromPath(normalisedPath),
        highlights: parts.join(' | '),
        records,
        recordCount: records.length,
        emailCount: 0,
        addressCount: 0,
        tokenCount: withSecret,
        seedHints: 0,
        source: sourcePath,
      };
    }
  }

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

  const tokenCount = jsonSignals.tokenCount + collectTokens(combinedText).length;

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
