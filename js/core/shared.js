import { EMAIL_REGEX, FIELD_PATTERNS, SCAN_EMAIL_REGEX } from './definitions/patterns.js';
import { inferServiceFromPath } from './serviceRegistry.js';

const SHARED_TEXT_DECODER = new TextDecoder('utf-8');
const WIN1252_TEXT_DECODER = new TextDecoder('windows-1252');

// Some logs ship sysinfo / software lists as Windows-1252 instead of UTF-8;
// the unmarked accented bytes land as U+FFFD. If the UTF-8 attempt contains
// replacement chars, retry as Windows-1252 and keep whichever has fewer.
function decodeBufferWithFallback(buffer) {
  const utf8 = SHARED_TEXT_DECODER.decode(buffer);
  if (!utf8.includes('�')) return utf8;
  const win = WIN1252_TEXT_DECODER.decode(buffer);
  const utf8Bad = (utf8.match(/�/g) || []).length;
  const winBad = (win.match(/�/g) || []).length;
  return winBad < utf8Bad ? win : utf8;
}

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
const AUTOFILL_NAME_STRONG_FIELD_PATTERN = /(?:^|[^a-z])(first[\s._-]*name|last[\s._-]*name|full[\s._-]*name|given[\s._-]*name|family[\s._-]*name|middle[\s._-]*name|surname|lastname|firstname|fullname|middlename|cardholder[\s._-]*name|name[\s._-]*on[\s._-]*card|billing[\s._-]*name|shipping[\s._-]*name|recipient[\s._-]*name|contact[\s._-]*name|customer[\s._-]*name|payer[\s._-]*name|nombre(?:[\s._-]*completo)?|prenom|prénom|vorname|voornaam|nome(?:[\s._-]*completo)?|navn|apellidos?|nachname|achternaam|cognome|sobrenome)(?:$|[^a-z])/i;
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

function normaliseDomain(hostname) {
  const normalised = String(hostname || '').toLowerCase().replace(/^www\./, '');
  if (!normalised || normalised === 'localhost') return null;
  return normalised;
}

// Reverse-DNS Android packages (e.g. `com.roblox.client`); treat as opaque so
// extractBaseDomain doesn't strip parts off the package name.
const ANDROID_PACKAGE_PATTERN = /^(?:com|org)\.[a-z][a-z0-9_]*(?:\.[a-z0-9_][a-z0-9_]*)+$/i;

const ANDROID_APP_DOMAINS = new Map([
  ['com.roblox.client', 'roblox.com'],
  ['com.netflix.mediaclient', 'netflix.com'],
  ['com.spotify.music', 'spotify.com'],
  ['com.instagram.android', 'instagram.com'],
  ['com.facebook.katana', 'facebook.com'],
  ['com.google.android.gm', 'google.com'],
  ['com.amazon.mshop.android.shopping', 'amazon.com'],
  ['com.paypal.android.p2pmobile', 'paypal.com'],
  ['com.discord', 'discord.com'],
  ['org.telegram.messenger', 'telegram.org'],
]);

const HOSTED_SCHEMES = new Set([
  'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s', 'oauth', 'ftp', 'sftp',
]);

// Browser-internal schemes (settings, extension storage, about: pages). Drop
// them entirely rather than bucket them under the scheme name.
const BROWSER_INTERNAL_SCHEMES = new Set([
  'chrome', 'chrome-extension', 'chrome-search', 'chrome-untrusted',
  'edge', 'edge-extension',
  'moz-extension', 'firefox',
  'brave', 'opera', 'vivaldi', 'arc',
  'about', 'view-source', 'devtools',
]);

function extractDomain(url) {
  if (!url) return null;
  const raw = String(url).trim();
  if (!raw) return null;

  // Non-HTTP schemes need their own branch. Without it the fallback below
  // prefixes `https://` and the parser swallows the scheme as the hostname.
  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):/i);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (BROWSER_INTERNAL_SCHEMES.has(scheme)) {
      return null;
    }
    if (scheme === 'android') {
      // Chrome Smart Lock: `android://<hash>@com.package.name/`.
      const m = raw.match(/^android:\/\/(?:[^@/]*@)?([a-z][a-z0-9_]*(?:\.[a-z0-9_][a-z0-9_]*)+)/i);
      if (!m) return null;
      const pkg = m[1].toLowerCase();
      return ANDROID_APP_DOMAINS.get(pkg) || pkg;
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
    if (scheme === 'blob') {
      const inner = raw.slice(5);
      return inner ? extractDomain(inner) : null;
    }
    if (scheme !== 'http' && scheme !== 'https') {
      return null;
    }
  }

  try {
    let u = raw;
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const host = normaliseDomain(new URL(u).hostname);
    return isAcceptableHost(host) ? host : null;
  } catch {
    const match = raw.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:]+)/i);
    const host = normaliseDomain(match ? match[1] : '');
    return isAcceptableHost(host) ? host : null;
  }
}

// Reject single-label tokens (`macos`, `intranet`) that aren't IPs or known
// local-network hosts; those carry no real domain.
function isAcceptableHost(host) {
  if (!host) return false;
  if (host.includes('.')) return true;
  return isLocalNetworkHost(host);
}

const MULTI_LEVEL_SUFFIXES = new Set([
  'gov.au', 'com.au', 'net.au', 'org.au', 'edu.au', 'asn.au', 'id.au',
  'vic.gov.au', 'nsw.gov.au', 'qld.gov.au', 'wa.gov.au', 'sa.gov.au',
  'tas.gov.au', 'act.gov.au', 'nt.gov.au',
  'go.id', 'co.id', 'or.id', 'ac.id', 'web.id',
  'go.th', 'co.th', 'ac.th', 'or.th',
  'gob.ec', 'gob.mx', 'gob.pe', 'gob.cl', 'gob.ar',
  'com.br', 'gov.br',
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk',
  'co.jp', 'co.kr', 'co.za', 'co.nz',
]);

function extractBaseDomain(domain) {
  if (!domain) return domain;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return domain;
  if (domain === 'local-file') return domain;
  if (ANDROID_PACKAGE_PATTERN.test(domain)) return domain;
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  for (let i = 0; i <= parts.length - 3; i++) {
    const suffix = parts.slice(i + 1).join('.');
    if (MULTI_LEVEL_SUFFIXES.has(suffix)) return parts.slice(i).join('.');
  }
  const commonSLDs = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (commonSLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function baseDomainFromUrl(url) {
  const host = extractDomain(url);
  return host ? (extractBaseDomain(host) || host) : null;
}

const ROUTER_HOSTNAMES = new Set([
  'fritz.box', 'router.asus.com', 'routerlogin.net', 'routerlogin.com',
  'tplinkwifi.net', 'tplinkmodem.net', 'tplinklogin.net', 'tendawifi.com',
  'mywifiext.net', 'orbilogin.com', 'orbilogin.net', 'dlinkrouter.local',
  'netgear.com', 'miwifi.com', 'huaweimobilewifi.com', 'router.local',
  'gateway.local', 'unifi.local', 'router.home', 'console.gl-inet.com'
]);

function isLocalNetworkHost(host) {
  if (!host) return false;
  const h = String(host).trim().toLowerCase();
  if (!h) return false;
  if (ROUTER_HOSTNAMES.has(h)) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some(n => n > 255)) return false;
  if (o[0] === 10) return true;
  if (o[0] === 127) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  return false;
}

function isOnionHost(host) {
  return /\.onion$/i.test(String(host || '').trim());
}

function ipToInt(octets) {
  return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
}

function inCidr(value, base, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) >>> 0 === (base & mask) >>> 0;
}

const PUBLIC_DNS_IPS = new Set([
  '8.8.8.8', '8.8.4.4', '9.9.9.9', '1.1.1.1', '1.0.0.1',
  '208.67.222.222', '208.67.220.220',
]);

// Classify an IPv4 literal so anycast/DNS/private addresses are never mistaken
// for the victim's own IP. `synthetic` flags anything that isn't a plain
// routable public address.
function classifyIpAddress(ip) {
  const s = String(ip || '').trim();
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  if (octets.some((n) => n > 255)) return null;
  const synthetic = (kind, label) => ({ kind, synthetic: true, label });
  const value = ipToInt(octets);

  if (inCidr(value, ipToInt([127, 0, 0, 0]), 8)) return synthetic('loopback', 'Loopback');
  if (inCidr(value, ipToInt([10, 0, 0, 0]), 8)
    || inCidr(value, ipToInt([172, 16, 0, 0]), 12)
    || inCidr(value, ipToInt([192, 168, 0, 0]), 16)) return synthetic('rfc1918', 'Private (RFC1918)');
  if (inCidr(value, ipToInt([169, 254, 0, 0]), 16)) return synthetic('rfc1918', 'Link-local');
  if (inCidr(value, ipToInt([100, 64, 0, 0]), 10)) return synthetic('cgnat', 'CGNAT');
  if (s === '1.1.1.1' || s === '1.0.0.1'
    || inCidr(value, ipToInt([104, 16, 0, 0]), 12)
    || inCidr(value, ipToInt([172, 64, 0, 0]), 13)) return synthetic('cloudflare-anycast', 'Cloudflare anycast');
  if (PUBLIC_DNS_IPS.has(s)) return synthetic('public-dns', 'Public DNS resolver');
  return { kind: 'public', synthetic: false, label: 'Public' };
}

// Domains worth ranking in topDomains: real public hosts and bare public IPs.
// Drops local-file, RFC1918/router hosts, and single-label junk.
function isRankableDomain(domain) {
  if (!domain) return false;
  if (domain === 'local-file') return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return !isLocalNetworkHost(domain);
  if (isLocalNetworkHost(domain)) return false;
  if (ANDROID_PACKAGE_PATTERN.test(domain)) return true;
  return domain.includes('.');
}

// Same as baseDomainFromUrl but falls back to the raw URL when nothing parses.
// Use for dedupe keys where unparseable URLs should still group themselves.
function dedupeDomainKey(url) {
  if (!url) return '';
  return (baseDomainFromUrl(url) || url).toLowerCase();
}

function inferBrowserFromPath(pathText) {
  const value = String(pathText || '');
  for (const { pattern, label } of BROWSER_PATH_PATTERNS) {
    if (pattern.test(value)) return label;
  }
  return '';
}

function inferBrowserFromContent(text) {
  const value = String(text || '').slice(0, 4000);
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
    .replace(/^(?:value|val)\s*:\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normaliseAutofillFieldName(name) {
  return normaliseAutofillValue(name)
    .replace(/^(?:name|field|label|form|key)\s*:\s*/i, '')
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
  // Drop trunk-zero(s) and any country-code prefix so `+61491570156` and
  // `0491570156` collapse to the same key. Eight trailing digits is enough
  // signal to dedup within a single victim's autofill set without colliding
  // across distinct numbers.
  const stripped = digits.replace(/^0+/, '');
  return stripped.length > 8 ? stripped.slice(-8) : stripped || digits;
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
  return normaliseAutofillLetters(normaliseAutofillFieldName(name))
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

  if (tokens.includes('firstname') || tokens.includes('first') || tokens.includes('given')
    || tokens.includes('nombre') || tokens.includes('prenom') || tokens.includes('vorname')
    || tokens.includes('voornaam') || tokens.includes('nome') || tokens.includes('navn')) return 'given';
  if (tokens.includes('middlename') || tokens.includes('middle')) return 'middle';
  if (tokens.includes('lastname') || tokens.includes('last') || tokens.includes('family') || tokens.includes('surname')
    || tokens.includes('apellido') || tokens.includes('apellidos') || tokens.includes('nachname')
    || tokens.includes('achternaam') || tokens.includes('cognome') || tokens.includes('sobrenome')) return 'family';
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
  // State codes ("CA", "VIC") and form-field abbreviations ("EA", "HR") aren't
  // useful address content on their own.
  if (normalised.length <= 3) return false;
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
  // A scheme/path means this is a URL whose `user@host` is not an address.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(normalised) || /[\/\\]/.test(normalised)) return '';
  if (!/[:,]/.test(normalised) && EMAIL_REGEX.test(normalised)) return normalised;

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
    if (isStrongAutofillNameField(normalisedField)) return true;
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

  const otherAll = other;

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

function buildLocalDate(year, month, day, hour = 0, minute = 0, second = 0) {
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (isNaN(date.getTime())) return null;
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  return date;
}

// Disambiguate DD/MM vs MM/DD when both slots are <= 12. The corpus is
// predominantly DD/MM and a capture timestamp cannot be in the future, so if the
// US-default MM/DD reading lands ahead of now, fall back to DD/MM.
function resolveDayMonth(a, b, year) {
  if (a > 12) return { month: b, day: a };
  if (b > 12) return { month: a, day: b };
  if (a !== b) {
    const mmdd = buildLocalDate(year, a, b);
    if (mmdd && mmdd.getTime() > Date.now()) return { month: b, day: a };
  }
  return { month: a, day: b };
}

function parseTimestampValue(value) {
  if (value instanceof Date) {
    return !isNaN(value.getTime()) ? value : null;
  }
  if (value == null) return null;

  const str = String(value).trim();
  if (!str || str === '0' || /^(?:session|null|undefined|nan)$/i.test(str)) return null;

  // Epoch numbers, including fractional-second forms (e.g. CDP-JSON cookie
  // `expires` like 1742510427.431387) — truncate to the integer part.
  const epochMatch = str.match(/^(\d+)(?:\.\d+)?$/);
  if (epochMatch) {
    try {
      const num = BigInt(epochMatch[1]);
      let ms;
      if (num > CHROME_EPOCH_OFFSET) {
        // Chrome/WebKit epoch microseconds since 1601-01-01.
        ms = Number((num - CHROME_EPOCH_OFFSET) / 1000n);
      } else if (num > 1000000000000000n) {
        ms = Number(num / 1000n); // Unix microseconds (Firefox places.sqlite)
      } else if (num > 1000000000000n) {
        ms = Number(num); // already ms
      } else {
        ms = Number(num * 1000n); // seconds
      }
      const date = new Date(ms);
      if (!isNaN(date.getTime()) && date.getUTCFullYear() > 1970 && date.getUTCFullYear() <= 9999) {
        return date;
      }
    } catch {
      // fall through
    }
  }

  // Dot-separated dates: run these ahead of `new Date()` so V8's US-default
  // doesn't flip day and month on `DD.MM.YYYY`.
  const dotDmyTime = str.match(/^(\d{1,2})\.(\d{1,2})\.(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dotDmyTime) {
    let year = Number(dotDmyTime[3]);
    if (year < 100) year += 2000;
    const date = buildLocalDate(year, Number(dotDmyTime[2]), Number(dotDmyTime[1]), Number(dotDmyTime[4]), Number(dotDmyTime[5]), Number(dotDmyTime[6] || 0));
    if (date) return date;
  }
  const dotDmy = str.match(/^(\d{1,2})\.(\d{1,2})\.(\d{2,4})$/);
  if (dotDmy) {
    let year = Number(dotDmy[3]);
    if (year < 100) year += 2000;
    const date = buildLocalDate(year, Number(dotDmy[2]), Number(dotDmy[1]));
    if (date) return date;
  }

  // Slash-separated dates: parse explicitly so V8's US-default doesn't flip the
  // slots, and so AM/PM is honoured. First slot <= 12 reads as MM/DD, else DD/MM.
  const slashTime = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?/);
  if (slashTime) {
    let year = Number(slashTime[3]);
    if (year < 100) year += 2000;
    const { month, day } = resolveDayMonth(Number(slashTime[1]), Number(slashTime[2]), year);
    let hour = Number(slashTime[4]);
    const meridiem = (slashTime[7] || '').toLowerCase();
    if (meridiem === 'pm' && hour < 12) hour += 12;
    if (meridiem === 'am' && hour === 12) hour = 0;
    const date = buildLocalDate(year, month, day, hour, Number(slashTime[5]), Number(slashTime[6] || 0));
    if (date) return date;
  }

  const slash = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})$/);
  if (slash) {
    let year = Number(slash[3]);
    if (year < 100) year += 2000;
    const { month, day } = resolveDayMonth(Number(slash[1]), Number(slash[2]), year);
    const date = buildLocalDate(year, month, day);
    if (date) return date;
  }

  // Bare yyyy-mm-dd[ HH:MM] without a timezone suffix: anchor to UTC. ISO
  // strings carrying an offset/Z fall through to the native parser below.
  const hasExplicitZone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(str);
  const ymd = hasExplicitZone ? null : str.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?)?/);
  if (ymd) {
    let hour = Number(ymd[4] || 0);
    const meridiem = (ymd[7] || '').toLowerCase();
    if (meridiem === 'pm' && hour < 12) hour += 12;
    if (meridiem === 'am' && hour === 12) hour = 0;
    const date = buildLocalDate(Number(ymd[1]), Number(ymd[2]), Number(ymd[3]), hour, Number(ymd[5] || 0), Number(ymd[6] || 0));
    if (date) return date;
  }

  const isoLike = /^\d{4}-\d{2}-\d{2}[ T]/.test(str);
  const normalised = isoLike ? str.replace(' ', 'T') : str;
  const native = new Date(normalised);
  if (!isNaN(native.getTime()) && native.getUTCFullYear() > 1970 && native.getUTCFullYear() <= 9999) {
    return native;
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

// `\b` doesn't fire between `_` and a digit (underscore is a word char), so
// `_2025-10-21` needs a non-digit anchor instead.
function parseArchiveTimestamp(name) {
  const source = String(name || '');
  if (!source) return null;

  const ymd = source.match(/(?:^|[^0-9])(20\d{2})[-_.](\d{1,2})[-_.](\d{1,2})(?:[ T_-](\d{1,2})[-_.:](\d{1,2})(?:[-_.:](\d{1,2}))?)?(?:$|[^0-9])/);
  if (ymd) {
    const [, year, month, day, hour = '0', minute = '0', second = '0'] = ymd;
    const date = buildLocalDate(Number(year), Number(month), Number(day), Number(hour), Number(minute), Number(second));
    if (date) return date;
  }

  const dmy = source.match(/(?:^|[^0-9])(\d{1,2})[-_.](\d{1,2})[-_.](20\d{2})(?:[ T_-](\d{1,2})[-_.:](\d{1,2})(?:[-_.:](\d{1,2}))?)?(?:$|[^0-9])/);
  if (dmy) {
    const [, day, month, year, hour = '0', minute = '0', second = '0'] = dmy;
    const date = buildLocalDate(Number(year), Number(month), Number(day), Number(hour), Number(minute), Number(second));
    if (date) return date;
  }

  const compact = source.match(/(?:^|[^0-9])(20\d{2})(\d{2})(\d{2})[_-]?(\d{2})(\d{2})(\d{2})(?:$|[^0-9])/);
  if (compact) {
    const [, year, month, day, hour, minute, second] = compact;
    const date = buildLocalDate(Number(year), Number(month), Number(day), Number(hour), Number(minute), Number(second));
    if (date) return date;
  }

  return null;
}

function checkCookieValidity(expiresValue, referenceDate) {
  if (!expiresValue || expiresValue === '0' || String(expiresValue).toLowerCase() === 'session') {
    return { status: 'session', label: 'Session' };
  }

  const expiryDate = parseTimestampValue(expiresValue);
  if (!expiryDate) {
    return { status: 'unknown', label: 'Unknown expiry' };
  }

  const now = (referenceDate instanceof Date && !isNaN(referenceDate.getTime())) ? referenceDate : new Date();
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

const COUNTRY_OFFSET_RANGES = {
  US: [-600, -240], CA: [-480, -150], MX: [-480, -360], BR: [-300, -120],
  AR: [-180, -180], CL: [-360, -180], CO: [-300, -300], PE: [-300, -300],
  GB: [0, 60], IE: [0, 60], PT: [-60, 60], ES: [0, 120], FR: [0, 60],
  DE: [60, 120], NL: [60, 120], BE: [60, 120], IT: [60, 120], CH: [60, 120],
  PL: [60, 120], SE: [60, 120], NO: [60, 120], DK: [60, 120], AT: [60, 120],
  CZ: [60, 120], FI: [120, 180], GR: [120, 180], RO: [120, 180], UA: [120, 180],
  TR: [180, 180], RU: [120, 720], SA: [180, 180], AE: [240, 240], IL: [120, 180],
  IN: [300, 330], PK: [300, 300], BD: [360, 360], TH: [420, 420], VN: [420, 420],
  ID: [420, 540], CN: [480, 480], SG: [480, 480], MY: [480, 480], PH: [480, 480],
  HK: [480, 480], TW: [480, 480], JP: [540, 540], KR: [540, 540],
  AU: [480, 660], NZ: [720, 780], ZA: [120, 120], EG: [120, 180], NG: [60, 60]
};

function isOffsetPlausibleForCountry(offset, country) {
  if (offset == null) return null;
  const code = String(country || '').trim().toUpperCase();
  const range = COUNTRY_OFFSET_RANGES[code];
  if (!range) return null;
  return offset >= range[0] - 90 && offset <= range[1] + 90;
}

// TimeZone arrives in four shapes: signed integer hour offset, unsigned 32-bit
// overflow, Windows display string `(UTC±HH:MM) Region`, or `UTC±HH:MM`.
// Returns `{ offset (minutes, null if unparseable), label, source, raw }`.
function normaliseTimeZone(raw, country) {
  const out = { offset: null, label: '', source: 'absent', countryMismatch: false, raw };
  if (raw == null) return out;
  const s = String(raw).trim();
  if (!s) return out;
  out.raw = s;
  out.label = s;

  function flagCountry() {
    const plausible = isOffsetPlausibleForCountry(out.offset, country);
    if (plausible === false) {
      out.countryMismatch = true;
      out.label = `${out.label} (offset atypical for ${String(country).trim().toUpperCase()})`;
    }
  }

  // "(UTC-05:00) Bogotá, Lima, Quito" Windows display string.
  const winMatch = s.match(/^\(UTC(?:([+-])(\d{1,2})(?::(\d{2}))?)?\)\s*(.*)$/i);
  if (winMatch) {
    const sign = winMatch[1] === '-' ? -1 : 1;
    const h = winMatch[2] ? parseInt(winMatch[2], 10) : 0;
    const m = winMatch[3] ? parseInt(winMatch[3], 10) : 0;
    const offset = sign * (h * 60 + m);
    out.offset = offset;
    out.source = 'windows-display';
    out.label = formatTimeZoneLabel(offset, winMatch[4] && winMatch[4].trim() || null);
    flagCountry();
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
    flagCountry();
    return out;
  }

  // Integer hour offset. Some builds write negative offsets as unsigned 32-bit
  // overflow (4294967293 = -3); positives arrive as small ints.
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
      flagCountry();
      return out;
    }
    out.source = 'invalid-int';
    out.label = `${s} (invalid offset)`;
    return out;
  }

  out.source = 'unknown';
  return out;
}

// Installed-software entries arrive as `Name [version] - vendor`,
// `Name (version)`, `Name - version`, or `Name v1.2.3`. The bracket form runs
// first so a trailing `- vendor` doesn't get pulled into the dash form.
const SOFTWARE_PATTERNS = [
  /^(.+?)\s*\[(\d[\w.+-]*)\]\s*(?:[-–]\s*.*)?$/,
  /^(.+?)\s*\((v?\d+(?:\.\d+)+[\w.+-]*)\)\s*$/i,
  /^(.+?)\s+[-–]\s+(v?\d+(?:\.\d+)+[\w.+-]*)\s*$/i,
  /^(.+?)\s+(v?\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?)\s*$/i,
];

function parseSoftwareLine(rawLine) {
  if (!rawLine) return null;
  // Some logs truncate entries mid-suffix (`Mozilla Firefox (x64 en`); drop
  // the dangling open-paren tail.
  let line = String(rawLine).trim()
    .replace(/^[-_\s]+/, '')
    .replace(/[-_\s]+$/, '')
    .replace(/^\d+\)\s*/, '')
    .replace(/\s*\([^)]*$/, '');
  if (!line) return null;

  let name = line;
  let version = null;
  for (const pattern of SOFTWARE_PATTERNS) {
    const match = line.match(pattern);
    if (match) {
      name = match[1].trim();
      const verStr = match[2].trim();
      if (/\d/.test(verStr)) version = verStr;
      break;
    }
  }
  if (!version) {
    const embedded = name.match(/^(.+?)\s*\[(\d[\w.+-]*)\]\s*$/);
    if (embedded) {
      name = embedded[1].trim();
      version = embedded[2].trim();
    }
  }
  return name ? { name, version } : null;
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

// User-field values the stealer wrote that don't represent a real human:
// OEM-default vendor names (Dell, HP), Windows account placeholders
// (Administrator, Guest), OS names that snuck into the User field, and the
// generic UNKNOWN/UNK/N/A sentinels.
const OEM_USER_PATTERN = /^(?:dell|hp|hewlett[-\s]*packard|lenovo|acer|asus|msi|samsung|toshiba|fujitsu|ibm|apple|microsoft|sony|panasonic|huawei|alienware|gigabyte|razer|surface)$/i;
const PLACEHOLDER_USER_PATTERN = /^(?:user|users|admin|administrator|administrador|administrateur|usuario|usuari|utilisateur|utente|benutzer|nutzer|gebruiker|brugare|brukar|brukare|guest|gast|default|defaultuser|owner|operator|operador|home|family|familia|familie|public|publico|publik|test|tester|sample|demo|root|customer|kunde|cliente|client|none|null|undefined|unknown|unk|n[/\\-_]?a|nobody|anonymous|temp|tmp|pc|computer|laptop|notebook|workstation)$/i;
const OS_NAME_USER_PATTERN = /^(?:windows\s*(?:\d+|xp|vista|7|8|10|11|server|home|pro|enterprise)?|win\s*\d+|microsoft\s*windows|macos|mac\s*os(?:\s*x)?|osx|linux|ubuntu|debian|fedora|arch|gentoo|centos|redhat|red\s*hat|suse|opensuse|kali|mint)$/i;

function isPlaceholderUserName(value) {
  const v = String(value || '').trim();
  if (!v) return false;
  return OEM_USER_PATTERN.test(v) || PLACEHOLDER_USER_PATTERN.test(v) || OS_NAME_USER_PATTERN.test(v);
}

function isValidCountryCode(value) {
  return /^[A-Za-z]{2}$/.test(String(value || '').trim());
}

// Full country name (`France`, `Australia`, `United States`); used so the
// sanitiser keeps a written-out Country value instead of blanking it.
function isLikelyCountryName(value) {
  return /^[A-Za-z][A-Za-z .'-]{2,40}$/.test(String(value || '').trim());
}

// A placeholder-looking user value is real if it also names a profile/home
// directory in the same record (`C:\Users\Lenovo`, `/home/admin`).
function userNameAppearsInPath(name, entries) {
  const target = String(name || '').trim().toLowerCase();
  if (!target) return false;
  const re = new RegExp(`(?:users[\\\\/]|home[\\\\/])${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[\\\\/]|$)`, 'i');
  for (const entry of entries || []) {
    const value = String(entry?.value || '');
    if (re.test(value)) return true;
  }
  return false;
}

// Hand control back to the event loop so a long synchronous row loop over a
// very large file can paint. Order-independent accumulation only — never use
// where a yield could let observers see partial state.
function yieldToEventLoop() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

// Memoise a parser's output on the tree node so the analysis pass and the
// page loader don't both re-parse the same file. Keyed by parser name and
// validated against the current `_parseConfig` reference: the Adjust-columns
// flow assigns a fresh config object and applyManualType deletes it, so a
// reference mismatch re-parses. Decoded content is already cached upstream.
function parseNodeCached(node, parserName, parser, text, config) {
  const cfg = config ?? null;
  if (node) {
    const store = node._parsedRows;
    if (store) {
      const hit = store[parserName];
      if (hit && hit.config === cfg) return hit.parsed;
    }
  }
  const parsed = parser(text, cfg);
  if (node) {
    if (!node._parsedRows) node._parsedRows = {};
    node._parsedRows[parserName] = { config: cfg, parsed };
  }
  return parsed;
}

// Two-letter country prefix dropped into log filenames by resale markets:
// `[PE]_…`, `_AU_…`, `[BR]_…`. Used as a fallback when sysinfo Country
// fails IP-geo and lands as an IP literal or empty.
function extractCountryFromFilename(name) {
  const s = String(name || '');
  const bracket = s.match(/\[([A-Z]{2})\]/);
  if (bracket) return bracket[1];
  const prefix = s.match(/^([A-Z]{2})[_-]/);
  if (prefix) return prefix[1];
  const underscore = s.match(/_([A-Z]{2})_/);
  if (underscore) return underscore[1];
  return null;
}

export {
  SHARED_TEXT_DECODER,
  decodeBufferWithFallback,
  canonicaliseAutofillPhone,
  classifyAutofillEntries,
  collectHintedNodes,
  collectFileNodes,
  extractDomain,
  extractBaseDomain,
  baseDomainFromUrl,
  isLocalNetworkHost,
  isRankableDomain,
  isOnionHost,
  classifyIpAddress,
  dedupeDomainKey,
  inferBrowserFromPath,
  inferBrowserFromContent,
  inferProfileFromPath,
  inferServiceFromPath,
  extractCountryFromFilename,
  isLikelyAutofillPhone,
  isPlaceholderUserName,
  isValidCountryCode,
  isLikelyCountryName,
  userNameAppearsInPath,
  normaliseTimeZone,
  parseSoftwareLine,
  parseTimestampValue,
  parseArchiveTimestamp,
  parseNodeCached,
  yieldToEventLoop,
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
