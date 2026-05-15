// Shared helpers used across modules.

import { EMAIL_REGEX, FIELD_PATTERNS, SCAN_EMAIL_REGEX } from './definitions/patterns.js';
import { inferServiceFromPath } from './serviceRegistry.js';

// Shared UTF-8 decoder reused across modules.
const SHARED_TEXT_DECODER = new TextDecoder('utf-8');

const MAX_SEARCH_MATCHES_PER_FILE = 5;
const SEARCH_BATCH_SIZE = 20;
const CHROME_EPOCH_OFFSET = 11644473600000000n;
const AUTOFILL_LATIN_VOWEL_PATTERN = /[aeiouy]/i;
const BROWSER_PATH_PATTERNS = [
  { pattern: /\bgoogle chrome\b/i, label: 'Chrome' },
  { pattern: /\bmicrosoft edge\b/i, label: 'Edge' },
  { pattern: /\byandex(?:browser)?\b/i, label: 'YandexBrowser' },
  { pattern: /\bchromium\b/i, label: 'Chromium' },
  { pattern: /\barc\b/i, label: 'Arc' },
  { pattern: /\bchrome\b/i, label: 'Chrome' },
  { pattern: /\bedge\b/i, label: 'Edge' },
  { pattern: /\bfirefox\b/i, label: 'Firefox' },
  { pattern: /\bopera\b/i, label: 'Opera' },
  { pattern: /\bbrave\b/i, label: 'Brave' },
  { pattern: /\bvivaldi\b/i, label: 'Vivaldi' },
  { pattern: /\bsafari\b/i, label: 'Safari' },
];
const AUTOFILL_PHONE_FALSE_POSITIVE_PATTERN = /phonetic/i;
const AUTOFILL_PHONE_FIELD_PATTERN = /phone|mobile|landline|tel|cell|contact(?:number)?|whatsapp|fax/i;
const AUTOFILL_NAME_VALUE_PATTERN = /^[\p{L}][\p{L}' .-]{0,58}[\p{L}.]$/u;
const AUTOFILL_NAME_STRONG_FIELD_PATTERN = /(?:^|[^a-z])(first[\s._-]*name|last[\s._-]*name|full[\s._-]*name|given[\s._-]*name|family[\s._-]*name|middle[\s._-]*name|surname|lastname|firstname|fullname|middlename|cardholder[\s._-]*name|name[\s._-]*on[\s._-]*card|billing[\s._-]*name|shipping[\s._-]*name|recipient[\s._-]*name|contact[\s._-]*name|customer[\s._-]*name|payer[\s._-]*name)(?:$|[^a-z])/i;
const AUTOFILL_NAME_WEAK_FIELD_PATTERN = /(?:^|[^a-z])(name)(?:$|[^a-z])/i;
const AUTOFILL_NAME_FIELD_EXCLUSION_PATTERN = /(?:user(?:name)?|login[\s._-]*name|email[\s._-]*or[\s._-]*username|account[\s._-]*name|screen[\s._-]*name|nick[\s._-]*name|display[\s._-]*name|file[\s._-]*name|domain[\s._-]*name|company[\s._-]*name|business[\s._-]*name|merchant[\s._-]*name|organization[\s._-]*name|organisation[\s._-]*name|device[\s._-]*name|browser[\s._-]*name|service[\s._-]*name|app[\s._-]*name|application[\s._-]*name|page[\s._-]*name|tab[\s._-]*name|client[\s._-]*name|database[\s._-]*name|product[\s._-]*name|project[\s._-]*name|shop[\s._-]*name|store[\s._-]*name|school[\s._-]*name|brand[\s._-]*name|pet[\s._-]*name|pseudonymous[\s._-]*name|pseudo[\s._-]*name|alias[\s._-]*name|api[\s._-]*key[\s._-]*name|key[\s._-]*name)/i;
const AUTOFILL_ADDRESS_STRONG_FIELD_PATTERN = /(?:address|street|city|state|suburb|province|postcode|postal[\s._-]*code|zip|country|address1|address2|address3|address4|line1|line2|suite|house|apartment|apt|building|unit)/i;
const AUTOFILL_NAME_ENTITY_FIELD_TOKENS = new Set([
  'account',
  'alias',
  'api',
  'app',
  'application',
  'brand',
  'browser',
  'business',
  'client',
  'company',
  'database',
  'device',
  'display',
  'domain',
  'email',
  'employer',
  'file',
  'host',
  'key',
  'login',
  'merchant',
  'nickname',
  'nick',
  'organization',
  'organisation',
  'page',
  'pet',
  'product',
  'project',
  'pseudo',
  'pseudonymous',
  'school',
  'screen',
  'server',
  'service',
  'shop',
  'signin',
  'store',
  'subject',
  'tab',
  'title',
  'token',
  'user',
  'username',
]);

// Tree walking

function collectHintedNodes(node, hint, path, results) {
  if (!node) return;
  if (node[hint]) results.push({ node, path });
  if (node.children) {
    for (const child of Object.values(node.children)) {
      collectHintedNodes(child, hint, path + '/' + child.name, results);
    }
  }
}

function collectFileNodes(node, path, results) {
  if (!node) return;
  if (node.type === 'file') results.push({ node, path });
  if (node.children) {
    for (const child of Object.values(node.children)) {
      collectFileNodes(child, path + '/' + child.name, results);
    }
  }
}

// Domain extraction

function normaliseDomain(hostname) {
  const normalised = String(hostname || '').toLowerCase().replace(/^www\./, '');
  if (!normalised || normalised === 'localhost') return null;
  return normalised;
}

// Reverse-DNS Android package (e.g. `com.roblox.client`). Treat as opaque so
// extractBaseDomain doesn't strip parts off the package name.
const ANDROID_PACKAGE_PATTERN = /^(?:com|org)\.[a-z][a-z0-9_]*(?:\.[a-z0-9_][a-z0-9_]*)+$/i;

const HOSTED_SCHEMES = new Set([
  'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s', 'oauth', 'ftp', 'sftp',
]);

function extractDomain(url) {
  if (!url) return null;
  const raw = String(url).trim();
  if (!raw) return null;

  // Non-HTTP schemes — without this branch the fallback below prefixes
  // `https://` and the URL parser swallows the scheme as the hostname.
  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):/i);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme === 'android') {
      // Chrome Smart Lock: `android://<hash>@com.package.name/`.
      const m = raw.match(/^android:\/\/(?:[^@/]*@)?([a-z][a-z0-9_]*(?:\.[a-z0-9_][a-z0-9_]*)+)/i);
      return m ? m[1].toLowerCase() : null;
    }
    if (scheme === 'file') {
      return 'local-file';
    }
    if (HOSTED_SCHEMES.has(scheme)) {
      try {
        return normaliseDomain(new URL(raw).hostname);
      } catch {
        const m = raw.match(/^[a-z]+:\/\/(?:[^@/]*@)?([^/\s:?#]+)/i);
        return m ? normaliseDomain(m[1]) : null;
      }
    }
  }

  try {
    let u = raw;
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    return normaliseDomain(new URL(u).hostname);
  } catch {
    const match = raw.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:]+)/i);
    return normaliseDomain(match ? match[1] : '');
  }
}

function extractBaseDomain(domain) {
  if (!domain) return domain;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return domain;
  if (domain === 'local-file') return domain;
  if (ANDROID_PACKAGE_PATTERN.test(domain)) return domain;
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  const commonSLDs = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && commonSLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function inferBrowserFromPath(pathText) {
  const value = String(pathText || '');
  for (const { pattern, label } of BROWSER_PATH_PATTERNS) {
    if (pattern.test(value)) return label;
  }
  return '';
}

function inferProfileFromPath(pathText) {
  const value = String(pathText || '');
  const explicitMatch = value.match(/\b(?:Default|Guest Profile|Profile\s*\d+|Profile_\d+|Default\[[^\]]+\]|Profile\s*\d+\[[^\]]+\]|[a-z0-9._-]+\.default(?:-release)?)\b/i);
  if (explicitMatch) {
    return explicitMatch[0].replace(/\[[^\]]+\]/g, '').trim();
  }

  const pathProfileMatch = value.match(/(?:Chrome|Edge|Firefox|Opera|Brave|Vivaldi|Chromium|YandexBrowser|Google Chrome|Microsoft Edge|Arc)[_\s/-]+([^/.]+(?:\s+\d+)*)/i);
  return pathProfileMatch ? pathProfileMatch[1].trim() : '';
}

function normaliseAutofillValue(value) {
  return String(value || '')
    .replace(/^value\s*:\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normaliseAutofillFieldName(name) {
  return normaliseAutofillValue(name)
    .replace(/^(?:name|field|label)\s*:\s*/i, '')
    .trim();
}

function isLikelyAutofillEmail(value) {
  return Boolean(extractAutofillEmail(value));
}

function canonicaliseAutofillEmail(value) {
  const normalised = extractAutofillEmail(value) || normaliseAutofillValue(value);
  return normalised ? normalised.toLowerCase() : '';
}

function isLikelyAutofillPhone(value) {
  const normalised = normaliseAutofillValue(value);
  if (!normalised || !/^[+()\d\s-]+$/.test(normalised)) return false;
  if (/^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$/.test(normalised)) return false;

  const digits = normalised.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 15;
}

function canonicaliseAutofillPhone(value) {
  const digits = normaliseAutofillValue(value).replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return '';
  return digits;
}

function normaliseAutofillLetters(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '');
}

function tokenizeAutofillName(value) {
  return normaliseAutofillValue(value)
    .split(/\s+/)
    .map((token) => token.replace(/^[^\p{L}]+|[^\p{L}.']+$/gu, ''))
    .filter(Boolean);
}

function tokenizeAutofillFieldName(name) {
  return normaliseAutofillFieldName(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasExcludedAutofillNameContext(name) {
  if (AUTOFILL_NAME_FIELD_EXCLUSION_PATTERN.test(normaliseAutofillFieldName(name))) return true;
  return tokenizeAutofillFieldName(name).some((token) => AUTOFILL_NAME_ENTITY_FIELD_TOKENS.has(token));
}

function getAutofillNameFieldRole(name) {
  if (hasExcludedAutofillNameContext(name)) return 'excluded';

  const normalised = normaliseAutofillFieldName(name);
  const tokens = tokenizeAutofillFieldName(normalised);

  if (tokens.includes('firstname') || tokens.includes('first') || tokens.includes('given')) return 'given';
  if (tokens.includes('middlename') || tokens.includes('middle')) return 'middle';
  if (tokens.includes('lastname') || tokens.includes('last') || tokens.includes('family') || tokens.includes('surname') || tokens.includes('surname')) return 'family';
  if (tokens.includes('cardholder') || (tokens.includes('name') && tokens.includes('card'))) return 'full';
  if (tokens.includes('fullname') || (tokens.includes('full') && tokens.includes('name'))) return 'full';
  if ((tokens.includes('contact') || tokens.includes('customer') || tokens.includes('recipient') || tokens.includes('payer')) && tokens.includes('name')) return 'full';
  if ((tokens.includes('billing') || tokens.includes('shipping')) && tokens.includes('name')) return 'full';
  if (AUTOFILL_NAME_STRONG_FIELD_PATTERN.test(normalised)) return 'full';
  if (AUTOFILL_NAME_WEAK_FIELD_PATTERN.test(normalised)) return 'generic';
  return 'none';
}

function isRepeatedCharacterToken(token) {
  const letters = normaliseAutofillLetters(token).replace(/[^\p{L}]/gu, '').toLowerCase();
  return letters.length >= 2 && new Set(letters).size === 1;
}

function isLikelyAutofillNameToken(token, allowInitial = false) {
  const letters = normaliseAutofillLetters(token).replace(/[^\p{L}]/gu, '');
  if (!letters) return false;
  if (letters.length === 1) return allowInitial;
  if (letters.length < 2 || letters.length > 24) return false;
  if (isRepeatedCharacterToken(letters)) return false;

  const asciiLetters = letters.replace(/[^\x00-\x7F]/g, '');
  if (asciiLetters.length >= 3 && /[A-Za-z]/.test(asciiLetters) && !AUTOFILL_LATIN_VOWEL_PATTERN.test(asciiLetters)) {
    return false;
  }

  return true;
}

function isLikelyAutofillName(value, { allowSingleToken = true } = {}) {
  const normalised = normaliseAutofillValue(value);
  if (!normalised || normalised.length < 2 || normalised.length > 60) return false;
  if (/@|[_%:/\\]|^\W+$/.test(normalised)) return false;
  if (/www|https?/i.test(normalised)) return false;
  if (/\d/.test(normalised)) return false;
  const tokens = tokenizeAutofillName(normalised);
  if (tokens.length === 0 || tokens.length > 5) return false;
  if (!allowSingleToken && tokens.length === 1) return false;
  const allowInitials = tokens.length > 1;
  if (tokens.some((token) => !isLikelyAutofillNameToken(token, allowInitials))) return false;
  if (tokens.length > 1) {
    const longTokens = tokens.filter((token) => normaliseAutofillLetters(token).replace(/[^\p{L}]/gu, '').length >= 3);
    if (longTokens.length === 0) return false;
  }
  return AUTOFILL_NAME_VALUE_PATTERN.test(normalised);
}

function isStrongAutofillNameField(name) {
  const normalised = normaliseAutofillFieldName(name);
  if (hasExcludedAutofillNameContext(normalised)) return false;
  return AUTOFILL_NAME_STRONG_FIELD_PATTERN.test(normalised);
}

function isWeakAutofillNameField(name) {
  const normalised = normaliseAutofillFieldName(name);
  return AUTOFILL_NAME_WEAK_FIELD_PATTERN.test(normalised)
    && !hasExcludedAutofillNameContext(normalised);
}

function isLikelyAutofillAddressField(name) {
  const normalised = normaliseAutofillFieldName(name);
  return AUTOFILL_ADDRESS_STRONG_FIELD_PATTERN.test(normalised);
}

function isLikelyAutofillAddressValue(value) {
  const normalised = normaliseAutofillValue(value);
  if (!normalised || normalised.length > 140) return false;
  if (isLikelyAutofillEmail(normalised)) return false;
  if (isLikelyAutofillPhone(normalised)) return false;
  if (/^(?:https?|file):/i.test(normalised)) return false;
  if (/^[A-F0-9:-]{12,}$/i.test(normalised)) return false;
  if (normalised.split(/\s+/).length > 16) return false;
  return true;
}

function extractAutofillEmail(value) {
  const normalised = normaliseAutofillValue(value);
  if (!normalised) return '';
  if (EMAIL_REGEX.test(normalised)) return normalised;

  const matches = normalised.match(SCAN_EMAIL_REGEX);
  return matches && matches.length > 0 ? matches[0] : '';
}

function buildAutofillNameSupport(entries) {
  const valueCounts = new Map();
  const singleTokenCounts = new Map();
  const phraseTokenCounts = new Map();

  for (const entry of entries || []) {
    const fieldName = normaliseAutofillFieldName(entry?.name || '');
    const value = normaliseAutofillValue(entry?.value || '');
    if (!value) continue;

    const role = getAutofillNameFieldRole(fieldName);
    if (role === 'excluded' || role === 'none') continue;
    if (!isLikelyAutofillName(value)) continue;

    const normalisedValue = value.toLowerCase();
    valueCounts.set(normalisedValue, (valueCounts.get(normalisedValue) || 0) + 1);

    const tokens = tokenizeAutofillName(value);
    if (tokens.length === 1 && role !== 'generic') {
      const lowered = tokens[0].toLowerCase();
      singleTokenCounts.set(lowered, (singleTokenCounts.get(lowered) || 0) + 1);
    }
    if (tokens.length >= 2 && role !== 'generic') {
      for (const token of tokens) {
        const lowered = token.toLowerCase();
        phraseTokenCounts.set(lowered, (phraseTokenCounts.get(lowered) || 0) + 1);
      }
    }
  }

  return { valueCounts, singleTokenCounts, phraseTokenCounts };
}

function getAutofillNameTokenSupport(token, support) {
  const lowered = token.toLowerCase();
  return Math.max(
    support?.singleTokenCounts?.get(lowered) || 0,
    support?.phraseTokenCounts?.get(lowered) || 0,
  );
}

function isSupportedAutofillName(value, fieldName, support) {
  const normalisedField = normaliseAutofillFieldName(fieldName);
  const role = getAutofillNameFieldRole(normalisedField);
  if (role === 'excluded' || role === 'none') return false;

  const tokens = tokenizeAutofillName(value);
  if (tokens.length === 0) return false;
  if (!isLikelyAutofillName(value, { allowSingleToken: role !== 'generic' })) return false;

  if (tokens.length === 1) {
    if (role === 'generic') return false;
    const letterCount = normaliseAutofillLetters(tokens[0]).replace(/[^\p{L}]/gu, '').length;
    if (letterCount < 3) return false;
    const tokenSupport = support?.phraseTokenCounts?.get(tokens[0].toLowerCase()) || 0;
    return tokenSupport > 0;
  }

  if (role === 'given' && tokens.length > 2) return false;
  if ((role === 'family' || role === 'middle') && tokens.length > 3) return false;
  if (role === 'full') {
    const supportedTokens = tokens.filter((token) => (support?.singleTokenCounts?.get(token.toLowerCase()) || 0) > 0);
    if ((support?.singleTokenCounts?.size || 0) > 0 && supportedTokens.length === 0) return false;
  }
  if (role === 'generic') {
    const supportedTokens = tokens.filter((token) => getAutofillNameTokenSupport(token, support) > 0);
    return supportedTokens.length >= Math.min(2, tokens.length);
  }

  return true;
}

function dedupeAutofillStrings(values, canonicalise) {
  const out = [];
  const seen = new Set();

  for (const raw of values) {
    const display = normaliseAutofillValue(raw);
    if (!display) continue;
    const key = canonicalise ? canonicalise(display) : display.toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(canonicalise === canonicaliseAutofillEmail ? key : display);
  }

  return out;
}

function classifyAutofillEntries(entries, maxOther = 20) {
  const emails = [];
  const phones = [];
  const names = [];
  const addresses = [];
  const other = [];
  const nameSupport = buildAutofillNameSupport(entries);

  for (const entry of entries || []) {
    const name = normaliseAutofillFieldName(entry?.name || '');
    const value = normaliseAutofillValue(entry?.value || '');
    if (!name || !value) continue;

    const lower = name.toLowerCase();
    const isEmailField = FIELD_PATTERNS.email.test(lower);
    const isPhoneField = AUTOFILL_PHONE_FIELD_PATTERN.test(lower) && !AUTOFILL_PHONE_FALSE_POSITIVE_PATTERN.test(lower);
    const isStrongNameField = isStrongAutofillNameField(lower);
    const isWeakNameField = isWeakAutofillNameField(lower);
    const isAddressField = FIELD_PATTERNS.address.test(lower) || isLikelyAutofillAddressField(lower);
    const extractedEmail = extractAutofillEmail(value);
    const isEmailValue = Boolean(extractedEmail);
    const isPhoneValue = isLikelyAutofillPhone(value);

    if (isEmailValue) {
      emails.push(extractedEmail);
    } else if (isPhoneField && isPhoneValue) {
      phones.push(value);
    } else if ((isStrongNameField || isWeakNameField) && isSupportedAutofillName(value, name, nameSupport)) {
      names.push(value);
    } else if (isAddressField && isLikelyAutofillAddressValue(value)) {
      addresses.push(value);
    } else {
      other.push({ name, value });
    }
  }

  const otherAll = other.map((entry) => ({ ...entry }));

  return {
    emails: dedupeAutofillStrings(emails, canonicaliseAutofillEmail),
    phones: dedupeAutofillStrings(phones, canonicaliseAutofillPhone),
    names: dedupeAutofillStrings(names),
    addresses: dedupeAutofillStrings(addresses),
    other: otherAll.slice(0, maxOther),
    otherAll,
    otherTotal: otherAll.length,
    otherTruncated: otherAll.length > maxOther,
  };
}

// Timestamp parsing

function parseTimestampValue(value) {
  if (value instanceof Date) {
    return !isNaN(value.getTime()) ? value : null;
  }
  if (value == null) return null;

  const str = String(value).trim();
  if (!str || str === '0' || /^(?:session|null|undefined|nan)$/i.test(str)) return null;

  if (/^\d+$/.test(str)) {
    try {
      const num = BigInt(str);
      let ms;
      if (num > 13000000000000000n) {
        // Chrome/WebKit epoch microseconds since 1601-01-01.
        ms = Number((num - CHROME_EPOCH_OFFSET) / 1000n);
      } else if (num > 1000000000000n) {
        ms = Number(num); // already ms
      } else {
        ms = Number(num * 1000n); // seconds
      }
      const date = new Date(ms);
      if (!isNaN(date.getTime()) && date.getFullYear() > 1970 && date.getFullYear() < 3000) {
        return date;
      }
    } catch {
      // fall through to string parsing
    }
  }

  const normalised = str.includes('T') ? str : str.replace(' ', 'T');
  const native = new Date(normalised);
  if (!isNaN(native.getTime()) && native.getFullYear() > 1970 && native.getFullYear() < 3000) {
    return native;
  }

  const dmyTime = str.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dmyTime) {
    let year = Number(dmyTime[3]);
    if (year < 100) year += 2000;
    const date = new Date(year, Number(dmyTime[2]) - 1, Number(dmyTime[1]), Number(dmyTime[4]), Number(dmyTime[5]), Number(dmyTime[6] || 0));
    if (!isNaN(date.getTime())) return date;
  }

  const dmy = str.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})$/);
  if (dmy) {
    let year = Number(dmy[3]);
    if (year < 100) year += 2000;
    const date = new Date(year, Number(dmy[2]) - 1, Number(dmy[1]));
    if (!isNaN(date.getTime())) return date;
  }

  const ymd = str.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (ymd) {
    const date = new Date(Number(ymd[1]), Number(ymd[2]) - 1, Number(ymd[3]), Number(ymd[4] || 0), Number(ymd[5] || 0), Number(ymd[6] || 0));
    if (!isNaN(date.getTime())) return date;
  }

  const dMonY = str.match(/^(\d{1,2})\s+(\w{3})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dMonY) {
    let year = dMonY[3];
    if (year.length === 2) year = '20' + year;
    const date = new Date(`${dMonY[2]} ${dMonY[1]} ${year} ${dMonY[4]}:${dMonY[5]}:${dMonY[6] || '00'}`);
    if (!isNaN(date.getTime())) return date;
  }

  return null;
}

// Cookie validity

function checkCookieValidity(expiresValue) {
  if (!expiresValue || expiresValue === '0' || String(expiresValue).toLowerCase() === 'session') {
    return { status: 'session', label: 'Session' };
  }

  const expiryDate = parseTimestampValue(expiresValue);
  if (!expiryDate) {
    return { status: 'unknown', label: 'Unknown expiry' };
  }

  const now = new Date();
  if (expiryDate < now) {
    return { status: 'expired', label: `Expired ${formatRelativeTime(expiryDate)}` };
  }
  return { status: 'valid', label: `Valid until ${formatRelativeTime(expiryDate)}` };
}

function formatRelativeTime(date) {
  const now = new Date();
  const diff = date - now;
  const absDiff = Math.abs(diff);

  if (absDiff < 60000) return 'just now';
  if (absDiff < 3600000) return `${Math.round(absDiff / 60000)}m ${diff > 0 ? 'from now' : 'ago'}`;
  if (absDiff < 86400000) return `${Math.round(absDiff / 3600000)}h ${diff > 0 ? 'from now' : 'ago'}`;
  if (absDiff < 2592000000) return `${Math.round(absDiff / 86400000)}d ${diff > 0 ? 'from now' : 'ago'}`;

  return date.toLocaleDateString();
}

// Random password via rejection sampling (uniform over the 62-char charset).

const PASSWORD_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PASSWORD_REJECT_THRESHOLD = 4 * PASSWORD_CHARSET.length; // 248

function randomPassword(length = 16) {
  const out = [];
  const buf = new Uint8Array(length * 2);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b >= PASSWORD_REJECT_THRESHOLD) continue;
      out.push(PASSWORD_CHARSET[b % PASSWORD_CHARSET.length]);
      if (out.length >= length) break;
    }
  }
  return out.join('');
}

// Download helper

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function topN(arr, n) {
  const counts = new Map();
  for (const item of arr) {
    const normalised = String(item || '').trim();
    if (!normalised) continue;
    counts.set(normalised, (counts.get(normalised) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

// Toast notification

function showNotification(message, type = 'info') {
  const existing = document.getElementById('notification');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.id = 'notification';
  el.className = `notification notification-${type}`;
  el.textContent = message;
  document.body.appendChild(el);

  setTimeout(() => {
    el.classList.add('fade-out');
    el.addEventListener('transitionend', () => el.remove());
  }, 4000);
}

// Clipboard

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      return document.execCommand('copy');
    } catch {
      return false;
    } finally {
      textarea.remove();
    }
  }
}

function normalisePath(value) {
  return String(value || '').replace(/\\/g, '/');
}

function truncateText(value, max = 120) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '\u2026';
}

function collectUniqueMatches(text, regex, limit = 5) {
  const seen = new Set();
  const matches = [];
  let match;
  regex.lastIndex = 0;
  while ((match = regex.exec(text)) !== null) {
    const value = String(match[0] || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push(value);
    if (matches.length >= limit) break;
  }
  return matches;
}

function uniqueLimited(values, limit = 5) {
  const seen = new Set();
  const result = [];
  for (const value of values || []) {
    const normalised = String(value || '').trim();
    if (!normalised) continue;
    const key = normalised.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(normalised);
    if (result.length >= limit) break;
  }
  return result;
}

function summariseList(values, limit = 2) {
  const items = uniqueLimited(values, limit + 1);
  if (items.length === 0) return '';
  if (items.length <= limit) return items.join(', ');
  return `${items.slice(0, limit).join(', ')} +${items.length - limit} more`;
}

// Stealer families store the victim's TimeZone in several different shapes:
// signed integer hour offset, unsigned 32-bit overflow (Vidar v17), Windows
// display string `(UTC±HH:MM) Region`, or pre-formatted `UTC±HH:MM`. Returns
// `{ offset, label, source, raw }` where `offset` is in minutes (null when
// unparseable) and `label` falls back to the original string so the UI always
// has something to render.
function normaliseTimeZone(raw) {
  const out = { offset: null, label: '', source: 'absent', raw };
  if (raw == null) return out;
  const s = String(raw).trim();
  if (!s) return out;
  out.raw = s;
  out.label = s;

  // "(UTC-05:00) Bogotá, Lima, Quito" — Windows display string.
  const winMatch = s.match(/^\(UTC(?:([+-])(\d{1,2})(?::(\d{2}))?)?\)\s*(.*)$/i);
  if (winMatch) {
    const sign = winMatch[1] === '-' ? -1 : 1;
    const h = winMatch[2] ? parseInt(winMatch[2], 10) : 0;
    const m = winMatch[3] ? parseInt(winMatch[3], 10) : 0;
    const offset = sign * (h * 60 + m);
    out.offset = offset;
    out.source = 'windows-display';
    out.label = formatTimeZoneLabel(offset, winMatch[4] && winMatch[4].trim() || null);
    return out;
  }

  // "UTC+5", "UTC-3", "UTC-05:00", "UTC+10:30"
  const cleanMatch = s.match(/^UTC([+-])(\d{1,2})(?::?(\d{2}))?$/i);
  if (cleanMatch) {
    const sign = cleanMatch[1] === '-' ? -1 : 1;
    const h = parseInt(cleanMatch[2], 10);
    const m = cleanMatch[3] ? parseInt(cleanMatch[3], 10) : 0;
    const offset = sign * (h * 60 + m);
    out.offset = offset;
    out.source = 'string-offset';
    out.label = formatTimeZoneLabel(offset);
    return out;
  }

  // Pure integer — Vidar v17. Negative offsets often arrive as unsigned 32-bit
  // overflow (e.g. 4294967293 = -3), positive offsets as small ints (e.g. 8 = UTC+8).
  if (/^-?\d{1,10}$/.test(s)) {
    let n = Number(s);
    let overflowed = false;
    if (n > 2_000_000_000) {
      n -= 0x100000000;
      overflowed = true;
    }
    if (n >= -14 && n <= 14) {
      out.offset = n * 60;
      out.source = overflowed ? 'integer-overflow' : 'integer';
      out.label = formatTimeZoneLabel(out.offset);
      return out;
    }
    out.source = 'invalid-int';
    out.label = `${s} (invalid offset)`;
    return out;
  }

  out.source = 'unknown';
  return out;
}

function formatTimeZoneLabel(minutes, regionLabel) {
  if (minutes == null) return '?';
  const sign = minutes < 0 ? '-' : '+';
  const abs = Math.abs(minutes);
  const h = String(Math.floor(abs / 60)).padStart(2, '0');
  const m = String(abs % 60).padStart(2, '0');
  const base = `UTC${sign}${h}:${m}`;
  return regionLabel ? `${base} (${regionLabel})` : base;
}

export {
  MAX_SEARCH_MATCHES_PER_FILE,
  SEARCH_BATCH_SIZE,
  SHARED_TEXT_DECODER,
  classifyAutofillEntries,
  collectHintedNodes,
  collectFileNodes,
  extractDomain,
  extractBaseDomain,
  inferBrowserFromPath,
  inferProfileFromPath,
  inferServiceFromPath,
  normaliseTimeZone,
  parseTimestampValue,
  checkCookieValidity,
  downloadBlob,
  topN,
  showNotification,
  copyToClipboard,
  normalisePath,
  truncateText,
  collectUniqueMatches,
  uniqueLimited,
  summariseList,
  randomPassword,
};
