// Shared normalisation/utility functions and regex constants used across transform parsers.

export { JWT_TOKEN_PATTERN } from '../core/definitions/patterns.js';

export const KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _-]*?)\s*:\s+(.*)/;
export const AUTOFILL_KV_PATTERN = /^([A-Za-z_][A-Za-z0-9_.$\-[\]]*)\s*:\s*(.+)$/;
export const HISTORY_URL_PATTERN = /^(?:(?:[a-z][a-z0-9+.-]*):\/\/\/?|(?:about|blob|chrome|chrome-extension|data|devtools|edge|file|javascript|moz-extension|opera|view-source|vivaldi):)/i;
export const GOOGLE_RESTORE_TOKEN_PATTERN = /^(?!https?:\/\/)(?!file:\/\/)([^:\s]{20,}):(\d{6,})$/;
export const CLIPBOARD_URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
export const CREDIT_CARD_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _/-]*?)\s*:\s*(.*)$/;
// `[^>]` runs are length-bounded so a malformed anchor with no closing `>`
// cannot drive quadratic backtracking on multi-MB attacker-controlled bookmark HTML.
export const BOOKMARK_HTML_PATTERN = /<a\b[^>]{0,2000}href=(?:"([^"]+)"|'([^']+)')[^>]{0,2000}>(.*?)<\/a>/ig;
export const DISCORD_TOKEN_PATTERN = /^(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{10,}$/;
export const TOKEN_VALUE_FIELD_PATTERN = /^(?:(?:access|refresh|auth|oauth|bearer|session|restore|google|discord|facebook|steam)\s+)?token(?:\s+value)?\s*[:=]\s*(\S{6,})$/i;
export const ACCOUNT_ID_FIELD_PATTERN = /^(?:id|uid|user(?:\s*id)?|account(?:\s*id)?|profile(?:\s*id)?)\s*[:=]\s*(\d{6,})$/i;
export const PASSWORD_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*:\s*(.*)$/;
export const WINDOWS_PATH_PATTERN = /[A-Z]:\\[^"\r\n\t]+/g;
export const URL_INDICATOR_PATTERN = /https?:\/\/[^\s"'<>]+/g;
export const SYSINFO_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()%-]*?)\s*(?:=\s*|:\s*)(.*)$/;
export const SYSINFO_CAPTURE_SECTION_PATTERN = /^(?:Network Info|System Summary|System Info(?:rmation)?|User Info(?:rmation)?|Hardware Info|PC Info|Environment|Computer Info|User Agents|Installed (?:Apps|Software|Programs)|Process(?: List|es)?|Browsers?)\s*:$/i;
export const SYSINFO_STRUCTURED_KEY_PATTERN = /^(?:ip(?: address)?|country|region|city|postal code|zip|location|hwid|guid|machine guid|machine id|machine name|build(?: id)?|os(?: name)?|os version|platform|architecture|arch|username|user name|computer name|pc name|host(?:name)?|(?:log |user |local |capture )?date|user time|local time|utc|timezone|time zone|traffic|geo|seller|bot id|language|languages|keyboard(?:s)?|laptop|running path|cpu|processor|cores?|threads?|ram|memory|display(?: resolution)?|screen(?: resolution)?|gpu|video card|mac(?: address)?|bios|antivirus|defender|domain|monitor|board|motherboard|drives?)$/i;
export const SYSINFO_MULTILINE_KEY_PATTERN = /^(?:gpu|video card|display adapters?|dns servers?|installed (?:apps|software|programs)|process(?: list|es)|user agents?)$/i;
export const LINE_CONTAINS_HOST = /[a-z0-9-]+\.[a-z]{2,}/i;

const PASSWORD_SITE_KEYS = new Set([
  'url', 'uri', 'link', 'originurl', 'host', 'hostname', 'site', 'website',
  'domain', 'address', 'webaddress', 'page', 'loginpage', 'homepage',
]);
const PASSWORD_USER_KEYS = new Set([
  'user', 'username', 'login', 'usernameemail', 'email', 'emailaddress',
  'mail', 'account', 'accountname', 'acc', 'loginname', 'loginid',
  'userid', 'useridname', 'userlogin',
]);
const PASSWORD_PASS_KEYS = new Set([
  'password', 'pass', 'passwd', 'pwd', 'pin', 'pincode', 'passcode',
  'userpassword', 'loginpassword',
]);

// Separator lines (e.g. ===============) are normalised to blank lines
const SEPARATOR_LINE = /^[=\-*~_]{3,}\s*$/gm;

export function normaliseSeparators(text) {
  return text.replace(SEPARATOR_LINE, '');
}

export function normaliseText(text) {
  return text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
}

export function decodeHtmlEntities(text) {
  return String(text || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

export function isPromotionalNoiseLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return true;
  if (/^telegram\s*:/i.test(trimmed) || /t\.me\/[^\s]+/i.test(trimmed)) return true;
  if (/^[*=_~#-]{3,}$/.test(trimmed) || /^\*+\s*$/.test(trimmed)) return true;
  if (/^[\\/()|_ \-]{6,}$/.test(trimmed)) return true;
  if (/ottoman|cloudbot/i.test(trimmed)) return true;
  if (/daisy\s*cloud/i.test(trimmed)) return true;
  if (/\b(?:price|priced|sold|seller|shop|store)\b.*\$\d/i.test(trimmed)) return true;
  if (/these logs belong to/i.test(trimmed)) return true;
  if (/buy daily fresh logs/i.test(trimmed)) return true;
  if (/subscribe today for fresh daily logs/i.test(trimmed)) return true;
  if (/^\|[_-]{10,}\|?$/.test(trimmed)) return true;
  if (/^\|\s*[A-Z]\s+.+\s+[A-Z]\s*\|$/.test(trimmed) && /join:/i.test(trimmed)) return true;

  const inner = trimmed
    .replace(/^\*+\s*/, '')
    .replace(/\s*\*+$/, '')
    .trim();

  if (!inner) return true;
  if (!/[A-Za-z0-9]/.test(inner)) return true;
  if (/^[_\\/|() -]+$/.test(inner)) return true;
  if (inner.includes('|') && /^[A-Za-z|()\s]+$/.test(inner) && inner.replace(/[^A-Za-z]/g, '').length >= 4) {
    return true;
  }

  return false;
}

export function stripLeadingNoiseLines(text) {
  const lines = text.split('\n');
  let start = 0;

  while (start < lines.length) {
    const trimmed = lines[start].trim();
    if (!trimmed) {
      start++;
      continue;
    }

    if (isPromotionalNoiseLine(trimmed) && !LINE_CONTAINS_HOST.test(trimmed)) {
      start++;
      continue;
    }

    break;
  }

  return lines.slice(start).join('\n');
}

export function isSeparatorOnlyLine(line) {
  return /^[=\-*~_]{3,}\s*$/.test(String(line || '').trim());
}

function normalisePasswordFieldKey(key) {
  return String(key || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function classifyPasswordFieldKey(key) {
  const normalised = normalisePasswordFieldKey(key);
  if (PASSWORD_SITE_KEYS.has(normalised)) return 'url';
  if (PASSWORD_USER_KEYS.has(normalised)) return 'username';
  if (PASSWORD_PASS_KEYS.has(normalised)) return 'password';
  return '';
}

export function canonicalisePasswordExtraHeader(key) {
  const raw = String(key || '').trim().replace(/\s+/g, ' ');
  const normalised = normalisePasswordFieldKey(raw);
  if (!normalised) return '';
  if (['soft', 'software', 'application', 'app', 'program', 'client'].includes(normalised)) return 'Software';
  if (['browser', 'webbrowser'].includes(normalised)) return 'Browser';
  if (normalised === 'profile') return 'Profile';
  return raw;
}

// CSV generation (RFC 4180)
export function toCSV(parsed) {
  const escape = (cell) => {
    let s = String(cell);
    // Neutralise spreadsheet formula/DDE injection on attacker-controlled cells.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return `"${s.replace(/"/g, '""')}"`;
  };
  const headerLine = parsed.headers.map(escape).join(',');
  const dataLines = parsed.rows.map(row => row.map(escape).join(','));
  return [headerLine, ...dataLines].join('\n');
}
