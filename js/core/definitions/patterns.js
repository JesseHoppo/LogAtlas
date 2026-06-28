// Session cookies (exact match → 'auth', regex → 'session')

export const AUTH_COOKIE_NAMES = new Set([
  // Generic framework session cookies
  'jsessionid', 'phpsessid', 'asp.net_sessionid', 'connect.sid',
  'laravel_session', '_rails_session', 'ci_session', 'djangosessionid',

  // Google
  'sid', 'ssid', 'hsid', 'apisid', 'sapisid',
  '__secure-1psid', '__secure-3psid',

  // Microsoft / Azure
  'estsauthpersistent', 'estsauth',

  // Facebook / Meta
  'xs', 'c_user',

  // GitHub
  'user_session', '__host-user_session_same_site', 'dotcom_user', 'logged_in',

  // Twitter / X
  'auth_token', 'ct0', 'twid',

  // Reddit
  'reddit_session', 'token_v2',

  // Amazon
  'at-main',

  // Cloudflare
  'cf_authorization',

  // Okta
  'okta-oauth-state',

  // Atlassian
  'cloud.session.token', 'tenant.session.token',

  // Generic
  'jwt', 'access_token', 'bearer_token',
]);

export const SESSION_PATTERNS = [
  /session[_-]?id$/i,
  /^session[_-]/i,
  /_session$/i,
  /^sess[_-]/i,
  /^auth[_-]?token/i,
  /^access[_-]?token/i,
  /^oauth[_-]/i,
  /^sso[_-]/i,
  /^login[_-]token/i,
];

// Ad-tech / RTB / analytics hosts whose `session_id`-shaped cookies are
// tracking IDs, not login sessions. Used to demote SESSION_PATTERNS matches
// when the cookie's domain is in this set so the dashboard's
// "session tokens detected" line stays honest.
export const AD_TRACKER_DOMAINS = new Set([
  '3lift.com', 'adnxs.com', 'aniview.com', 'casalemedia.com',
  'contextweb.com', 'creativecdn.com', 'criteo.com', 'criteo.net',
  'doubleclick.net', 'google-analytics.com', 'googleadservices.com',
  'googlesyndication.com', 'googletagmanager.com', 'html-load.com',
  'intentiq.com', 'lijit.com', 'mediavine.com', 'openx.net',
  'outbrain.com', 'pubmatic.com', 'quantserve.com', 'rubiconproject.com',
  'scorecardresearch.com', 'servenobid.com', 'sharethrough.com',
  'smaato.com', 'sonobi.com', 'sparteo.com', 'stickyadstv.com',
  'taboola.com', 'tremorhub.com', 'yieldmo.com',
]);


// Field name patterns

export const FIELD_PATTERNS = {
  url:        /^(url|uri|link|domain|host(?:name)?|site|origin|website|address|web\s*address|login\s*page|homepage)$/i,
  username:   /^(user(?:name)?|login(?:\s*(?:name|id))?|email(?:\s*address)?|mail|account(?:\s*name)?|user\s*id)$/i,
  password:   /^(pass(?:word)?|passwd|pwd|passcode|pin(?:code)?)$/i,
  expires:    /^expir/i,
  cookieDomain: /^(domain|host)$/i,
  cookieName: /^name$/i,
  email:      /email|e-mail/i,
  address:    /address|street|city|state|zip|postcode|country|suburb/i,
  formField:  /^(name|form|field)$/i,
  formValue:  /^(value)$/i,
};

export const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// Global scanning variants (for extracting matches from text blocks)
export const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
export const SCAN_EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
export const SCAN_PHONE_REGEX = /\+?\d[\d().\- \t]{7,}\d/g;
const JWT_TOKEN_PATTERN_SOURCE = '[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+';
export const JWT_TOKEN_PATTERN = new RegExp(`^${JWT_TOKEN_PATTERN_SOURCE}$`);
export const JWT_SCAN_REGEX = new RegExp(`\\b${JWT_TOKEN_PATTERN_SOURCE}\\b`, 'g');


// Sysinfo keys that hold the malware-capture timestamp. Different builds
// label it variously: `Date`, `Local Time`, `Log date`, `System time`, etc.
export const CAPTURE_TIME_KEYS = [
  /^date$/i,
  /^log\s*date$/i,
  /^system\s*date$/i,
  /^system\s*time$/i,
  /^local\s*date$/i,
  /^local\s*time$/i,
  /^current\s*time$/i,
  /^time$/i,
  /^timestamp$/i,
  /^infection\s*date$/i,
  /^stolen\s*time$/i,
  /^capture\s*date$/i,
];

// IOC extraction from sysinfo. `kind` routes the IOC to a dashboard panel:
// 'victim' for identifiers, 'stealer-infra' for IR-pivot infrastructure
// (panel URLs, loader staging paths, forum links). Default is 'victim'.

export const IOC_KEY_MAP = [
  { label: 'IP Address', patterns: [/^ip$/i, /^ip\s*address$/i] },
  { label: 'Country', patterns: [/^country$/i, /^geo$/i] },
  { label: 'City', patterns: [/^city$/i] },
  { label: 'HWID', patterns: [/^hwid$/i, /^hardware\s*uuid$/i] },
  { label: 'Machine ID', patterns: [/^machine\s*id$/i, /^machineid$/i] },
  { label: 'GUID', patterns: [/^guid$/i] },
  { label: 'Computer Name', patterns: [/^computer\s*name$/i, /^computer$/i, /^hostname$/i, /^netbios\s*name$/i, /^netbios$/i, /^pc$/i, /^pc\s*name$/i] },
  { label: 'User Name', patterns: [/^user\s*name$/i, /^username$/i, /^user$/i] },
  { label: 'Log ID', patterns: [/^lid$/i] },
  { label: 'OS', patterns: [/^os$/i, /^windows$/i, /^system\s*version$/i, /^os\s*version$/i, /^mac\s*os\s*version$/i] },
  { label: 'Loader URL', kind: 'stealer-infra', patterns: [/^download\s*link$/i, /^drop\s*url$/i, /^panel\s*url$/i, /^c2\s*url$/i, /^panel$/i] },
  { label: 'Loader Sample', kind: 'stealer-infra', patterns: [/^running\s*path$/i, /^execution\s*path$/i, /^path$/i, /^work\s*dir$/i, /^malware\s*path$/i, /^build\s*path$/i] },
  { label: 'Build ID', patterns: [/^build$/i, /^build\s*id$/i, /^build\s*tag$/i, /^version\s*build$/i, /^version$/i, /^lummac2\s*build$/i, /^build\s*date$/i] },
  { label: 'Log Date', patterns: CAPTURE_TIME_KEYS },
  { label: 'Antivirus', patterns: [/^antivirus$/i, /^anti\s*virus$/i, /^av$/i, /^installed\s*av$/i] },
  { label: 'Product Key', patterns: [/^product\s*key$/i] },
  { label: 'Display Resolution', patterns: [/^display\s*resolution$/i, /^resolution$/i, /^screen\s*resolution$/i] },
  { label: 'Timezone', patterns: [/^time\s*zone$/i, /^timezone$/i, /^utc$/i] },
  { label: 'Language', patterns: [/^language$/i, /^system\s*language$/i, /^keyboard\s*layout$/i, /^keyboard\s*languages?$/i, /^display\s*language$/i] },
  { label: 'Tracker', patterns: [/^traffic$/i, /^tracker$/i, /^tag$/i] },
  { label: 'Processor', patterns: [/^processor$/i, /^cpu$/i] },
  { label: 'RAM', patterns: [/^ram$/i, /^memory$/i, /^total\s*memory$/i] },
  { label: 'GPU', patterns: [/^video\s*card$/i, /^gpu$/i, /^graphics$/i, /^display\s*adapter$/i] },
];

// Stealer-own infrastructure surfaced from sysinfo content. Scanned before
// CONTENT_IOC_PATTERNS so the more specific label wins when both match.
// `family` is shown as a chip when present.
export const STEALER_INFRA_PATTERNS = [
  { label: 'Stealer Panel', family: 'Vidar', pattern: /https?:\/\/(?:[a-z0-9-]+\.)*vidars\.[a-z]{2,6}\/[^\s"'<>]*/gi },
  { label: 'Stealer Panel', family: 'Lumma', pattern: /(?:@?lummanowork|@?lummamarketplace_bot|lumma\s*market)/gi },
  { label: 'Stealer Telegram', pattern: /t\.me\/\+[A-Za-z0-9_-]{8,}/g },
  { label: 'Forum URL', pattern: /\b(?:xss\.is|forum\.exploit\.in|exploit\.in|bhf\.im)\/[^\s"'<>]*/gi },
  { label: 'Loader URL', pattern: /https?:\/\/(?:[a-z0-9-]+\.)*(?:gofile|anonfiles|mediafire|transfer\.sh|file\.io|pixeldrain|catbox\.moe|temp\.sh|workupload)\.[a-z]{2,4}\/[^\s"'<>]+/gi },
  { label: 'Loader Sample', pattern: /['"]?[A-Z]:\\Users\\[^\\'"<>\s]+\\AppData\\Local\\Temp\\[^\\'"<>\s]+\.(?:bat|ps1|exe|dll|cmd|vbs|hta)['"]?/gi },
];

// Content-based IOC patterns (applied to raw sysinfo text). Generic catch-all
// for URLs / Telegram refs / malware signatures — anything matched by a more
// specific STEALER_INFRA_PATTERNS entry is suppressed at extraction time.
export const CONTENT_IOC_PATTERNS = [
  { label: 'C2/Panel URL', kind: 'stealer-infra', pattern: /https?:\/\/[^\s"'<>]{5,}/gi },
  { label: 'Telegram Contact', kind: 'stealer-infra', pattern: /(?<![a-zA-Z0-9._%+-])@[a-zA-Z_]\w{3,}/g },
  { label: 'Telegram Channel', kind: 'stealer-infra', pattern: /t\.me\/[a-zA-Z_]\w{3,}/gi },
  { label: 'Malware Signature', kind: 'stealer-infra', pattern: /\(sig:[0-9a-f]+\.[0-9a-f]+\)/gi },
];

// Government / national identifiers. Counts surfaced only; values masked in UI.
// Each entry validates where a cheap checksum exists to suppress false hits.

function digits(value) {
  return value.replace(/\D/g, '');
}

function validateCpf(value) {
  const d = digits(value);
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  for (let len = 9; len <= 10; len++) {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += Number(d[i]) * (len + 1 - i);
    let check = (sum * 10) % 11;
    if (check === 10) check = 0;
    if (check !== Number(d[len])) return false;
  }
  return true;
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

function validateAadhaar(value) {
  const d = digits(value);
  if (d.length !== 12 || d[0] === '0' || d[0] === '1') return false;
  let c = 0;
  const reversed = d.split('').reverse();
  for (let i = 0; i < reversed.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(reversed[i])]];
  }
  return c === 0;
}

function validateSsn(value) {
  const m = value.match(/(\d{3})-(\d{2})-(\d{4})/);
  if (!m) return false;
  const area = m[1];
  if (area === '000' || area === '666' || area[0] === '9') return false;
  if (m[2] === '00' || m[3] === '0000') return false;
  return true;
}

export const NATIONAL_ID_PATTERNS = [
  { label: 'CPF', country: 'BR', rx: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, validate: validateCpf },
  { label: 'Aadhaar', country: 'IN', rx: /\b\d{4}\s?\d{4}\s?\d{4}\b/g, validate: validateAadhaar },
  { label: 'PAN', country: 'IN', rx: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { label: 'CUIT/DNI', country: 'AR', rx: /\b(?:20|23|24|27|30|33|34)-?\d{8}-?\d\b/g },
  { label: 'SSN', country: 'US', rx: /\b\d{3}-\d{2}-\d{4}\b/g, validate: validateSsn },
];

// Clipboard lure / clipper classification. First matching category wins;
// order matters (more specific social-engineering lures before raw blobs).
export const CLIPBOARD_LURE_PATTERNS = [
  { category: 'clickfix', rx: /win[\s+]*r|⊞\s*r|press\s+win|verify\s+you\s+are\s+human|i\s+am\s+not\s+a\s+robot/i },
  { category: 'powershell', rx: /powershell|iex\s*\(|invoke-(?:expression|webrequest)|\biwr\b/i },
  { category: 'mshta', rx: /\bmshta\b/i },
  { category: 'certutil', rx: /\bcertutil\b/i },
  { category: 'crypto-swap', rx: /^(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})$/ },
  { category: 'base64-blob', rx: /[A-Za-z0-9+/]{120,}={0,2}/ },
];

export const IGNORE_DATE_KEYS = [
  /^build\s*date$/i,
  /^install\s*date$/i,
];


// Sysinfo → identity mapping

export const IDENTITY_SYSINFO_KEYS = {
  osUsername:    [/^user\s*name$/i, /^username$/i, /^user$/i],
  computerName: [/^computer\s*name$/i, /^computer$/i, /^hostname$/i, /^netbios/i, /^pc$/i],
  country:      [/^country$/i],
  os:           [/^operating\s*system$/i, /^os$/i, /^os\s*version$/i, /^system\s*version$/i],
};


// Limits

export const LIMITS = {
  topDomains: 15,
  topUsernames: 15,
  topCookieDomains: 15,
  topTimelineCookieDomains: 20,
  topHistoryDomainsPerDay: 5,
  maxAutofillOther: 20,
  previewLineCap: 5000,
  previewRowCap: 500,
  previewMaxBytes: 5 * 1024 * 1024,
  looksLikeTextSampleBytes: 4096,
  autoLoadMaxBytes: 500 * 1024 * 1024,
  maxRecoveredPasswords: 5000,
  iocMaxItems: 50,
  stealerInfraMaxItems: 25,
  stealerInfraValueScanBytes: 4000,
  searchMatchesPerFile: 5,
  searchBatchSize: 20,
  maxDecompressedBytes: 2 * 1024 * 1024 * 1024,
  maxEntries: 200000,
  jsonParseMaxBytes: 8 * 1024 * 1024,
  flattenMaxDepth: 32,
  flattenMaxEntries: 50000,
  ooxmlInnerMemberMaxBytes: 50 * 1024 * 1024,
  ooxmlTotalMaxBytes: 100 * 1024 * 1024,
};
