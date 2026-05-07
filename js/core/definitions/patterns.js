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


// Field name patterns

export const FIELD_PATTERNS = {
  url:        /^(url|uri|link|domain|host(?:name)?|site|origin|website|address|web\s*address|login\s*page|homepage)$/i,
  username:   /^(user(?:name)?|login(?:\s*(?:name|id))?|email(?:\s*address)?|mail|account(?:\s*name)?|user\s*id)$/i,
  password:   /^(pass(?:word)?|passwd|pwd|passcode|pin(?:code)?)$/i,
  expires:    /^(expires?|expir)/i,
  cookieDomain: /^(domain|host)$/i,
  cookieName: /^name$/i,
  email:      /email|e-mail/i,
  phone:      /phone|mobile|landline|tel/i,
  name:       /first\s*name|last\s*name|^name$|full\s*name|given|family|surname/i,
  address:    /address|street|city|state|zip|postcode|country|suburb/i,
  formField:  /^(name|form|field)$/i,
  formValue:  /^(value)$/i,
};

export const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// Global scanning variants (for extracting matches from text blocks)
export const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
export const SCAN_EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
export const SCAN_PHONE_REGEX = /\+?\d[\d\s().-]{7,}\d/g;
const JWT_TOKEN_PATTERN_SOURCE = '[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+';
export const JWT_TOKEN_PATTERN = new RegExp(`^${JWT_TOKEN_PATTERN_SOURCE}$`);
export const JWT_SCAN_REGEX = new RegExp(`\\b${JWT_TOKEN_PATTERN_SOURCE}\\b`, 'g');


// IOC extraction from sysinfo

export const IOC_KEY_MAP = [
  { label: 'IP Address', patterns: [/^ip$/i, /^ip\s*address$/i] },
  { label: 'Country', patterns: [/^country$/i] },
  { label: 'City', patterns: [/^city$/i] },
  { label: 'HWID', patterns: [/^hwid$/i, /^machine\s*id$/i, /^machineid$/i, /^hardware\s*uuid$/i] },
  { label: 'GUID', patterns: [/^guid$/i] },
  { label: 'Computer Name', patterns: [/^computer\s*name$/i, /^computer$/i, /^hostname$/i, /^netbios\s*name$/i, /^netbios$/i, /^pc$/i] },
  { label: 'User Name', patterns: [/^user\s*name$/i, /^username$/i, /^user$/i] },
  { label: 'Log ID', patterns: [/^lid$/i] },
  { label: 'OS', patterns: [/^os$/i, /^windows$/i, /^system\s*version$/i, /^os\s*version$/i, /^mac\s*os\s*version$/i] },
  { label: 'Malware Path', patterns: [/^running\s*path$/i, /^execution\s*path$/i, /^path$/i, /^work\s*dir$/i] },
  { label: 'Build ID', patterns: [/^build$/i, /^build\s*id$/i, /^build\s*tag$/i, /^version\s*build$/i, /^version$/i, /^lummac2\s*build$/i, /^build\s*date$/i] },
  { label: 'Log Date', patterns: [/^date$/i, /^log\s*date$/i, /^system\s*date$/i, /^local\s*date$/i, /^local\s*time$/i, /^current\s*time$/i, /^time$/i] },
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

// Content-based IOC patterns (applied to raw sysinfo text)
export const CONTENT_IOC_PATTERNS = [
  { label: 'C2/Panel URL', pattern: /https?:\/\/[^\s"'<>]{5,}/gi },
  { label: 'Telegram Contact', pattern: /(?<![a-zA-Z0-9._%+-])@[a-zA-Z_]\w{3,}/g },
  { label: 'Telegram Channel', pattern: /t\.me\/[a-zA-Z_]\w{3,}/gi },
  { label: 'Malware Signature', pattern: /\(sig:[0-9a-f]+\.[0-9a-f]+\)/gi },
];

export const CAPTURE_TIME_KEYS = [
  /^date$/i,
  /^log\s*date$/i,
  /^system\s*date$/i,
  /^local\s*date$/i,
  /^local\s*time$/i,
  /^current\s*time$/i,
  /^time$/i,
  /^timestamp$/i,
  /^infection\s*date$/i,
  /^stolen\s*time$/i,
  /^capture\s*date$/i,
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
  iocMaxItems: 50,
};
