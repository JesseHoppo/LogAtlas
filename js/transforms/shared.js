// Shared normalization/utility functions and regex constants used across transform parsers.

export { JWT_TOKEN_PATTERN } from '../core/definitions/patterns.js';

export const KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _-]*?)\s*:\s+(.*)/;
export const AUTOFILL_KV_PATTERN = /^([A-Za-z_][A-Za-z0-9_.$\-[\]]*)\s*:\s*(.+)$/;
export const HISTORY_URL_PATTERN = /^(?:(?:[a-z][a-z0-9+.-]*):\/\/\/?|about:)/i;
export const GOOGLE_RESTORE_TOKEN_PATTERN = /^(?!https?:\/\/)(?!file:\/\/)([^:\s]{20,}):(\d{6,})$/;
export const DOMAIN_DETECT_LABELED_ENTRY = /\[([^\]]+)\]\s*([^,\n]+?)(?:\s*\((\d+)\))(?=\s*(?:,|\[|$))/g;
export const DOMAIN_DETECT_UNLABELED_ENTRY = /(^|,\s*)([^,\[]+?)(?:\s*\((\d+)\))(?=\s*(?:,|$))/g;
export const CLIPBOARD_URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
export const CREDIT_CARD_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _/-]*?)\s*:\s*(.*)$/;
export const BOOKMARK_HTML_PATTERN = /<a\b[^>]*href=(?:"([^"]+)"|'([^']+)')[^>]*>(.*?)<\/a>/ig;
export const DISCORD_TOKEN_PATTERN = /^(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{10,}$/;
export const TOKEN_VALUE_FIELD_PATTERN = /^(?:(?:access|refresh|auth|oauth|bearer|session|restore|google|discord|facebook|steam)\s+)?token(?:\s+value)?\s*[:=]\s*(\S{6,})$/i;
export const ACCOUNT_ID_FIELD_PATTERN = /^(?:id|uid|user(?:\s*id)?|account(?:\s*id)?|profile(?:\s*id)?)\s*[:=]\s*(\d{6,})$/i;
export const PASSWORD_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()[\]-]*?)\s*:\s*(.*)$/;
export const WINDOWS_PATH_PATTERN = /[A-Z]:\\[^"\r\n\t]+/g;
export const URL_INDICATOR_PATTERN = /https?:\/\/[^\s"'<>]+/g;
export const SYSINFO_KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()%-]*?)\s*(?:=\s*|:\s*)(.*)$/;
export const SYSINFO_CAPTURE_SECTION_PATTERN = /^(?:Network Info|System Summary|System Info(?:rmation)?|User Info(?:rmation)?|Hardware Info|PC Info|Environment|Computer Info|User Agents|Installed (?:Apps|Software|Programs)|Process(?: List|es)?|Browsers?)\s*:$/i;
export const SYSINFO_STRUCTURED_KEY_PATTERN = /^(?:ip(?: address)?|country|region|city|postal code|zip|location|hwid|guid|machine guid|machine id|machine name|build(?: id)?|os(?: name)?|os version|platform|architecture|arch|username|user name|computer name|pc name|host(?:name)?|local time|utc|timezone|time zone|language|languages|keyboard(?:s)?|laptop|running path|cpu|processor|cores?|threads?|ram|memory|display(?: resolution)?|screen(?: resolution)?|gpu|video card|mac(?: address)?|bios|antivirus|defender|domain|monitor|board|motherboard|drives?)$/i;
export const SYSINFO_MULTILINE_KEY_PATTERN = /^(?:gpu|video card|display adapters?|dns servers?|installed (?:apps|software|programs)|process(?: list|es)|user agents?)$/i;

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

export function normalizeSeparators(text) {
  return text.replace(SEPARATOR_LINE, '');
}

export function normalizeText(text) {
  return text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

export function decodeHtmlEntities(text) {
  return String(text || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
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

    if (
      /^\*.*\*$/.test(trimmed) ||
      /^telegram\s*:/i.test(trimmed) ||
      /^[*=_~#-]{3,}$/.test(trimmed) ||
      /^[\\/()|_ \-]{6,}$/.test(trimmed)
    ) {
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

function normalizePasswordFieldKey(key) {
  return String(key || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function classifyPasswordFieldKey(key) {
  const normalized = normalizePasswordFieldKey(key);
  if (PASSWORD_SITE_KEYS.has(normalized)) return 'url';
  if (PASSWORD_USER_KEYS.has(normalized)) return 'username';
  if (PASSWORD_PASS_KEYS.has(normalized)) return 'password';
  return '';
}

export function canonicalizePasswordExtraHeader(key) {
  const raw = String(key || '').trim().replace(/\s+/g, ' ');
  const normalized = normalizePasswordFieldKey(raw);
  if (!normalized) return '';
  if (['soft', 'software', 'application', 'app', 'program', 'client'].includes(normalized)) return 'Software';
  if (['browser', 'webbrowser'].includes(normalized)) return 'Browser';
  if (normalized === 'profile') return 'Profile';
  return raw;
}

// CSV generation (RFC 4180)
export function toCSV(parsed) {
  const escape = (cell) => `"${String(cell).replace(/"/g, '""')}"`;
  const headerLine = parsed.headers.map(escape).join(',');
  const dataLines = parsed.rows.map(row => row.map(escape).join(','));
  return [headerLine, ...dataLines].join('\n');
}
