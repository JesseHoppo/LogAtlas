// Shared helpers used across modules.

import { EMAIL_REGEX, FIELD_PATTERNS } from './definitions/patterns.js';
import { inferServiceFromPath } from './serviceRegistry.js';

const MAX_SEARCH_MATCHES_PER_FILE = 5;
const SEARCH_BATCH_SIZE = 20;
const CHROME_EPOCH_OFFSET = 11644473600000000n;
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
const AUTOFILL_NAME_VALUE_PATTERN = /^[\p{L}][\p{L}' .-]{0,58}[\p{L}.]$/u;

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
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function isLikelyAutofillEmail(value) {
  return EMAIL_REGEX.test(normalizeAutofillValue(value));
}

function isLikelyAutofillPhone(value) {
  const normalized = normalizeAutofillValue(value);
  if (!normalized || !/^[+()\d\s-]+$/.test(normalized)) return false;
  if (/^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$/.test(normalized)) return false;

  const digits = normalized.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 15;
}

function isLikelyAutofillName(value) {
  const normalized = normalizeAutofillValue(value);
  if (!normalized || normalized.length < 2 || normalized.length > 60) return false;
  if (/@|[_%:/\\]|^\W+$/.test(normalized)) return false;
  if (/\d/.test(normalized)) return false;
  return AUTOFILL_NAME_VALUE_PATTERN.test(normalized);
}

function classifyAutofillEntries(entries, maxOther = 20) {
  const emails = [];
  const phones = [];
  const names = [];
  const addresses = [];
  const other = [];

  for (const entry of entries || []) {
    const name = String(entry?.name || '');
    const value = normalizeAutofillValue(entry?.value || '');
    if (!name || !value) continue;

    const lower = name.toLowerCase();
    const isEmailField = FIELD_PATTERNS.email.test(lower);
    const isPhoneField = FIELD_PATTERNS.phone.test(lower) && !AUTOFILL_PHONE_FALSE_POSITIVE_PATTERN.test(lower);
    const isNameField = FIELD_PATTERNS.name.test(lower);
    const isAddressField = FIELD_PATTERNS.address.test(lower);

    if (isLikelyAutofillEmail(value)) {
      emails.push(value);
    } else if (isPhoneField && isLikelyAutofillPhone(value)) {
      phones.push(value);
    } else if (isNameField && isLikelyAutofillName(value)) {
      names.push(value);
    } else if (isAddressField) {
      addresses.push(value);
    } else {
      other.push({ name, value });
    }
  }

  return {
    emails: [...new Set(emails)],
    phones: [...new Set(phones)],
    names: [...new Set(names)],
    addresses: [...new Set(addresses)],
    other: other.slice(0, maxOther),
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
