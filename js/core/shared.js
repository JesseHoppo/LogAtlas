// Shared helpers used across modules.

import { EMAIL_REGEX, FIELD_PATTERNS, SCAN_EMAIL_REGEX } from './definitions/patterns.js';
import { inferServiceFromPath } from './serviceRegistry.js';

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

function normalizeDomain(hostname) {
  const normalized = String(hostname || '').toLowerCase().replace(/^www\./, '');
  if (!normalized || normalized === 'localhost') return null;
  return normalized;
}

function extractDomain(url) {
  if (!url) return null;
  try {
    let u = url.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    return normalizeDomain(new URL(u).hostname);
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:]+)/i);
    return normalizeDomain(match ? match[1] : '');
  }
}

function extractBaseDomain(domain) {
  if (!domain) return domain;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return domain;
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

function normalizeAutofillValue(value) {
  return String(value || '')
    .replace(/^value\s*:\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeAutofillFieldName(name) {
  return normalizeAutofillValue(name)
    .replace(/^(?:name|field|label)\s*:\s*/i, '')
    .trim();
}

function isLikelyAutofillEmail(value) {
  return Boolean(extractAutofillEmail(value));
}

function canonicalizeAutofillEmail(value) {
  const normalized = extractAutofillEmail(value) || normalizeAutofillValue(value);
  return normalized ? normalized.toLowerCase() : '';
}

function isLikelyAutofillPhone(value) {
  const normalized = normalizeAutofillValue(value);
  if (!normalized || !/^[+()\d\s-]+$/.test(normalized)) return false;
  if (/^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$/.test(normalized)) return false;

  const digits = normalized.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 15;
}

function canonicalizeAutofillPhone(value) {
  const digits = normalizeAutofillValue(value).replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return '';
  return digits;
}

function normalizeAutofillLetters(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '');
}

function tokenizeAutofillName(value) {
  return normalizeAutofillValue(value)
    .split(/\s+/)
    .map((token) => token.replace(/^[^\p{L}]+|[^\p{L}.']+$/gu, ''))
    .filter(Boolean);
}

function tokenizeAutofillFieldName(name) {
  return normalizeAutofillFieldName(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasExcludedAutofillNameContext(name) {
  if (AUTOFILL_NAME_FIELD_EXCLUSION_PATTERN.test(normalizeAutofillFieldName(name))) return true;
  return tokenizeAutofillFieldName(name).some((token) => AUTOFILL_NAME_ENTITY_FIELD_TOKENS.has(token));
}

function getAutofillNameFieldRole(name) {
  if (hasExcludedAutofillNameContext(name)) return 'excluded';

  const normalized = normalizeAutofillFieldName(name);
  const tokens = tokenizeAutofillFieldName(normalized);

  if (tokens.includes('firstname') || tokens.includes('first') || tokens.includes('given')) return 'given';
  if (tokens.includes('middlename') || tokens.includes('middle')) return 'middle';
  if (tokens.includes('lastname') || tokens.includes('last') || tokens.includes('family') || tokens.includes('surname') || tokens.includes('surname')) return 'family';
  if (tokens.includes('cardholder') || (tokens.includes('name') && tokens.includes('card'))) return 'full';
  if (tokens.includes('fullname') || (tokens.includes('full') && tokens.includes('name'))) return 'full';
  if ((tokens.includes('contact') || tokens.includes('customer') || tokens.includes('recipient') || tokens.includes('payer')) && tokens.includes('name')) return 'full';
  if ((tokens.includes('billing') || tokens.includes('shipping')) && tokens.includes('name')) return 'full';
  if (AUTOFILL_NAME_STRONG_FIELD_PATTERN.test(normalized)) return 'full';
  if (AUTOFILL_NAME_WEAK_FIELD_PATTERN.test(normalized)) return 'generic';
  return 'none';
}

function isRepeatedCharacterToken(token) {
  const letters = normalizeAutofillLetters(token).replace(/[^\p{L}]/gu, '').toLowerCase();
  return letters.length >= 2 && new Set(letters).size === 1;
}

function isLikelyAutofillNameToken(token, allowInitial = false) {
  const letters = normalizeAutofillLetters(token).replace(/[^\p{L}]/gu, '');
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
  const normalized = normalizeAutofillValue(value);
  if (!normalized || normalized.length < 2 || normalized.length > 60) return false;
  if (/@|[_%:/\\]|^\W+$/.test(normalized)) return false;
  if (/www|https?/i.test(normalized)) return false;
  if (/\d/.test(normalized)) return false;
  const tokens = tokenizeAutofillName(normalized);
  if (tokens.length === 0 || tokens.length > 5) return false;
  if (!allowSingleToken && tokens.length === 1) return false;
  const allowInitials = tokens.length > 1;
  if (tokens.some((token) => !isLikelyAutofillNameToken(token, allowInitials))) return false;
  if (tokens.length > 1) {
    const longTokens = tokens.filter((token) => normalizeAutofillLetters(token).replace(/[^\p{L}]/gu, '').length >= 3);
    if (longTokens.length === 0) return false;
  }
  return AUTOFILL_NAME_VALUE_PATTERN.test(normalized);
}

function isStrongAutofillNameField(name) {
  const normalized = normalizeAutofillFieldName(name);
  if (hasExcludedAutofillNameContext(normalized)) return false;
  return AUTOFILL_NAME_STRONG_FIELD_PATTERN.test(normalized);
}

function isWeakAutofillNameField(name) {
  const normalized = normalizeAutofillFieldName(name);
  return AUTOFILL_NAME_WEAK_FIELD_PATTERN.test(normalized)
    && !hasExcludedAutofillNameContext(normalized);
}

function isLikelyAutofillAddressField(name) {
  const normalized = normalizeAutofillFieldName(name);
  return AUTOFILL_ADDRESS_STRONG_FIELD_PATTERN.test(normalized);
}

function isLikelyAutofillAddressValue(value) {
  const normalized = normalizeAutofillValue(value);
  if (!normalized || normalized.length > 140) return false;
  if (isLikelyAutofillEmail(normalized)) return false;
  if (isLikelyAutofillPhone(normalized)) return false;
  if (/^(?:https?|file):/i.test(normalized)) return false;
  if (/^[A-F0-9:-]{12,}$/i.test(normalized)) return false;
  if (normalized.split(/\s+/).length > 16) return false;
  return true;
}

function extractAutofillEmail(value) {
  const normalized = normalizeAutofillValue(value);
  if (!normalized) return '';
  if (EMAIL_REGEX.test(normalized)) return normalized;

  const matches = normalized.match(SCAN_EMAIL_REGEX);
  return matches && matches.length > 0 ? matches[0] : '';
}

function buildAutofillNameSupport(entries) {
  const valueCounts = new Map();
  const singleTokenCounts = new Map();
  const phraseTokenCounts = new Map();

  for (const entry of entries || []) {
    const fieldName = normalizeAutofillFieldName(entry?.name || '');
    const value = normalizeAutofillValue(entry?.value || '');
    if (!value) continue;

    const role = getAutofillNameFieldRole(fieldName);
    if (role === 'excluded' || role === 'none') continue;
    if (!isLikelyAutofillName(value)) continue;

    const normalizedValue = value.toLowerCase();
    valueCounts.set(normalizedValue, (valueCounts.get(normalizedValue) || 0) + 1);

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
  const normalizedField = normalizeAutofillFieldName(fieldName);
  const role = getAutofillNameFieldRole(normalizedField);
  if (role === 'excluded' || role === 'none') return false;

  const tokens = tokenizeAutofillName(value);
  if (tokens.length === 0) return false;
  if (!isLikelyAutofillName(value, { allowSingleToken: role !== 'generic' })) return false;

  if (tokens.length === 1) {
    if (role === 'generic') return false;
    const letterCount = normalizeAutofillLetters(tokens[0]).replace(/[^\p{L}]/gu, '').length;
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

function dedupeAutofillStrings(values, canonicalize) {
  const out = [];
  const seen = new Set();

  for (const raw of values) {
    const display = normalizeAutofillValue(raw);
    if (!display) continue;
    const key = canonicalize ? canonicalize(display) : display.toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(canonicalize === canonicalizeAutofillEmail ? key : display);
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
    const name = normalizeAutofillFieldName(entry?.name || '');
    const value = normalizeAutofillValue(entry?.value || '');
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
    emails: dedupeAutofillStrings(emails, canonicalizeAutofillEmail),
    phones: dedupeAutofillStrings(phones, canonicalizeAutofillPhone),
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

  const normalized = str.includes('T') ? str : str.replace(' ', 'T');
  const native = new Date(normalized);
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
    const normalized = String(item || '').trim();
    if (!normalized) continue;
    counts.set(normalized, (counts.get(normalized) || 0) + 1);
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

function normalizePath(value) {
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
    const normalized = String(value || '').trim();
    if (!normalized) continue;
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(normalized);
    if (result.length >= limit) break;
  }
  return result;
}

function summarizeList(values, limit = 2) {
  const items = uniqueLimited(values, limit + 1);
  if (items.length === 0) return '';
  if (items.length <= limit) return items.join(', ');
  return `${items.slice(0, limit).join(', ')} +${items.length - limit} more`;
}

export {
  MAX_SEARCH_MATCHES_PER_FILE,
  SEARCH_BATCH_SIZE,
  classifyAutofillEntries,
  collectHintedNodes,
  collectFileNodes,
  extractDomain,
  extractBaseDomain,
  inferBrowserFromPath,
  inferProfileFromPath,
  inferServiceFromPath,
  parseTimestampValue,
  checkCookieValidity,
  downloadBlob,
  topN,
  showNotification,
  copyToClipboard,
  normalizePath,
  truncateText,
  collectUniqueMatches,
  uniqueLimited,
  summarizeList,
};
