import { extractBaseDomain, extractDomain, dedupeDomainKey, classifyAutofillEntries, parseTimestampValue, resolveCaptureContext, getCaptureContext, usernameDedupeKey } from '../core/shared.js';
import { EMAIL_REGEX, SCAN_EMAIL_REGEX } from '../core/definitions/patterns.js';
import { classifySiteDomain } from '../core/domainCategories.js';
import { isLiveSessionToken } from './sessionCookies.js';

const PUBLIC_EMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'yahoo.co.uk',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'proton.me',
  'protonmail.com',
  'pm.me',
  'gmx.com',
  'gmx.de',
  'mail.com',
  'zoho.com',
  'qq.com',
  '163.com',
  '126.com',
  'web.de',
  'comcast.net',
  'verizon.net',
  'att.net',
  'cox.net',
  'yandex.com',
  'yandex.ru',
  'mail.ru',
]);

const PUBLIC_EMAIL_ROOTS = new Set(
  [...PUBLIC_EMAIL_DOMAINS]
    .map((domain) => domain.split('.')[0] || '')
    .filter(Boolean)
);

const COMMON_DOMAIN_LABELS = new Set([
  'www',
  'mail',
  'webmail',
  'app',
  'portal',
  'login',
  'auth',
  'signin',
  'sso',
  'account',
  'accounts',
  'id',
  'api',
  'cdn',
  'img',
  'static',
  'assets',
  'com',
  'co',
  'org',
  'net',
  'gov',
  'edu',
  'ac',
]);

const PROVIDER_DEFINITIONS = [
  {
    key: 'microsoft',
    label: 'Microsoft',
    genericHostPatterns: [
      /(^|\.)microsoftonline\.com$/i,
      /(^|\.)office\.com$/i,
      /(^|\.)office365\.com$/i,
      /(^|\.)live\.com$/i,
      /(^|\.)outlook\.com$/i,
      /(^|\.)officeapps\.live\.com$/i,
      /(^|\.)teams\.microsoft\.com$/i,
      /(^|\.)login\.microsoftonline\.com$/i,
    ],
    tenantHostPatterns: [
      /.+\.sharepoint\.com$/i,
      /.+\.onmicrosoft\.com$/i,
      /.+\.outlook\.office\.com$/i,
      /.+-my\.sharepoint\.com$/i,
    ],
  },
  {
    key: 'google',
    label: 'Google Workspace',
    genericHostPatterns: [
      /(^|\.)accounts\.google\.com$/i,
      /(^|\.)mail\.google\.com$/i,
      /(^|\.)drive\.google\.com$/i,
      /(^|\.)admin\.google\.com$/i,
      /(^|\.)workspace\.google\.com$/i,
      /(^|\.)google\.com$/i,
    ],
    tenantHostPatterns: [],
  },
  {
    key: 'okta',
    label: 'Okta',
    genericHostPatterns: [
      /^okta\.com$/i,
      /(^|\.)okta\.com$/i,
      /(^|\.)okta-emea\.com$/i,
    ],
    tenantHostPatterns: [
      /.+\.okta\.com$/i,
      /.+\.okta-emea\.com$/i,
      /.+\.oktapreview\.com$/i,
    ],
  },
  {
    key: 'auth0',
    label: 'Auth0',
    genericHostPatterns: [/(^|\.)auth0\.com$/i],
    tenantHostPatterns: [/.+\.auth0\.com$/i, /.+\.us\.auth0\.com$/i, /.+\.eu\.auth0\.com$/i],
  },
  {
    key: 'onelogin',
    label: 'OneLogin',
    genericHostPatterns: [/(^|\.)onelogin\.com$/i],
    tenantHostPatterns: [/.+\.onelogin\.com$/i],
  },
  {
    key: 'duo',
    label: 'Duo',
    genericHostPatterns: [/(^|\.)duosecurity\.com$/i, /(^|\.)duo\.com$/i],
    tenantHostPatterns: [/.+\.duosecurity\.com$/i],
  },
  {
    key: 'ping',
    label: 'Ping Identity',
    genericHostPatterns: [/(^|\.)pingone\.com$/i, /(^|\.)pingidentity\.cloud$/i],
    tenantHostPatterns: [/.+\.pingone\.com$/i, /.+\.pingidentity\.cloud$/i],
  },
  {
    key: 'jumpcloud',
    label: 'JumpCloud',
    genericHostPatterns: [/(^|\.)jumpcloud\.com$/i],
    tenantHostPatterns: [/.+\.jumpcloud\.com$/i],
  },
  {
    key: 'atlassian',
    label: 'Atlassian',
    genericHostPatterns: [/(^|\.)id\.atlassian\.com$/i, /(^|\.)bitbucket\.org$/i, /(^|\.)atlassian\.com$/i],
    tenantHostPatterns: [/.+\.atlassian\.net$/i, /.+\.jira\.com$/i],
  },
  {
    key: 'slack',
    label: 'Slack',
    genericHostPatterns: [/(^|\.)slack\.com$/i],
    tenantHostPatterns: [/.+\.slack\.com$/i],
  },
  {
    key: 'salesforce',
    label: 'Salesforce',
    genericHostPatterns: [/(^|\.)salesforce\.com$/i, /(^|\.)force\.com$/i],
    tenantHostPatterns: [
      /.+\.lightning\.force\.com$/i,
      /.+\.my\.salesforce\.com$/i,
      /.+\.my\.site\.com$/i,
    ],
  },
  {
    key: 'aws',
    label: 'AWS',
    genericHostPatterns: [/(^|\.)signin\.aws\.amazon\.com$/i, /(^|\.)console\.aws\.amazon\.com$/i],
    tenantHostPatterns: [/.+\.signin\.aws\.amazon\.com$/i, /.+\.awsapps\.com$/i],
  },
  {
    key: 'github',
    label: 'GitHub',
    genericHostPatterns: [/^github\.com$/i, /(^|\.)github\.com$/i],
    tenantHostPatterns: [/.+\.ghe\.com$/i, /.+\.githubenterprise\.com$/i],
  },
  {
    key: 'zendesk',
    label: 'Zendesk',
    genericHostPatterns: [/(^|\.)zendesk\.com$/i],
    tenantHostPatterns: [/.+\.zendesk\.com$/i],
  },
  {
    key: 'box',
    label: 'Box',
    genericHostPatterns: [/(^|\.)box\.com$/i],
    tenantHostPatterns: [/.+\.app\.box\.com$/i],
  },
  {
    key: 'dropbox',
    label: 'Dropbox',
    genericHostPatterns: [/(^|\.)dropbox\.com$/i],
    tenantHostPatterns: [/.+\.dropboxbusiness\.com$/i],
  },
  {
    key: 'zoom',
    label: 'Zoom',
    genericHostPatterns: [/(^|\.)zoom\.us$/i],
    tenantHostPatterns: [/.+\.zoom\.us$/i],
  },
  {
    key: 'notion',
    label: 'Notion',
    genericHostPatterns: [/(^|\.)notion\.so$/i],
    tenantHostPatterns: [/.+\.notion\.site$/i],
  },
  {
    key: 'freshdesk',
    label: 'Freshworks',
    genericHostPatterns: [/(^|\.)freshdesk\.com$/i, /(^|\.)freshworks\.com$/i],
    tenantHostPatterns: [/.+\.freshdesk\.com$/i, /.+\.myfreshworks\.com$/i],
  },
];

// Sites where a corporate email login is unusual and worth flagging. These
// are checked against the credential's base domain to surface "shadow IT" or
// reused-corp-email-on-consumer-account cases for the analyst.
const CONSUMER_SITE_BASE_DOMAINS = new Set([
  'facebook.com',
  'instagram.com',
  'tiktok.com',
  'snapchat.com',
  'pinterest.com',
  'reddit.com',
  'x.com',
  'twitter.com',
  'linkedin.com',
  'youtube.com',
  'twitch.tv',
  'discord.com',
  'telegram.org',
  'whatsapp.com',
  'netflix.com',
  'spotify.com',
  'hulu.com',
  'disneyplus.com',
  'hbomax.com',
  'max.com',
  'primevideo.com',
  'paramountplus.com',
  'amazon.com',
  'ebay.com',
  'etsy.com',
  'aliexpress.com',
  'temu.com',
  'walmart.com',
  'target.com',
  'paypal.com',
  'venmo.com',
  'cashapp.com',
  'coinbase.com',
  'binance.com',
  'kraken.com',
  'robinhood.com',
  'roblox.com',
  'epicgames.com',
  'steampowered.com',
  'playstation.com',
  'xbox.com',
  'nintendo.com',
  'booking.com',
  'airbnb.com',
  'expedia.com',
  'tripadvisor.com',
  'uber.com',
  'lyft.com',
  'doordash.com',
  'grubhub.com',
]);

// Passwords this short or this generic shouldn't count for reuse analysis;
// the same string showing up on 3 sites by coincidence is meaningless.
const COMMON_WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password!', 'p@ssword', 'p@ssw0rd',
  '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
  'qwerty', 'qwerty123', 'asdfgh', 'abc123', 'letmein', 'iloveyou',
  'welcome', 'welcome1', 'welcome123', 'changeme', 'changeme1',
  'admin', 'admin1', 'admin123', 'administrator',
  'test', 'test1', 'test123', 'demo', 'guest',
  '1234', '0000', '1111', '2222',
  '', '-', '--', '*', '*****',
]);

// SaaS hosts where multiple tenants share a base domain (`*.atlassian.net`,
// `*.sharepoint.com` etc). Cookies/history for one tenant must NOT spill into
// another's currentness score. The engine already classifies these as 'tenant'
// providers; this set just gates the per-host vs per-base lookup.
const TENANT_FULL_HOST_PROVIDER_KEYS = new Set([
  'atlassian', 'slack', 'salesforce', 'okta', 'auth0', 'onelogin',
  'duo', 'ping', 'jumpcloud', 'zendesk', 'freshdesk',
  'microsoft', // sharepoint.com, onmicrosoft.com tenants
]);

const LOGIN_HINT_PATTERN = /(login|log in|signin|sign in|auth|sso|oauth|account|portal|dashboard|mail|webmail|workspace|okta|adfs|saml|office|outlook)/i;

function normaliseText(value) {
  return String(value || '').trim().toLowerCase();
}

function getRootLabel(domain) {
  return normaliseText(domain).split('.').filter(Boolean)[0] || '';
}

function levenshteinDistance(a, b) {
  const left = normaliseText(a);
  const right = normaliseText(b);
  if (left === right) return 0;
  if (!left) return right.length;
  if (!right) return left.length;

  const rows = Array.from({ length: left.length + 1 }, () => new Array(right.length + 1).fill(0));
  for (let i = 0; i <= left.length; i += 1) rows[i][0] = i;
  for (let j = 0; j <= right.length; j += 1) rows[0][j] = j;

  for (let i = 1; i <= left.length; i += 1) {
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + cost
      );
    }
  }

  return rows[left.length][right.length];
}

function looksLikePublicEmailTypo(domain) {
  const normalised = normaliseText(domain);
  if (!normalised || PUBLIC_EMAIL_DOMAINS.has(normalised)) return false;

  const labels = normalised.split('.').filter(Boolean);
  const rootLabel = getRootLabel(normalised);
  if (!rootLabel) return false;

  if (PUBLIC_EMAIL_ROOTS.has(rootLabel)) return true;

  const strippedRoot = rootLabel.replace(/\d+$/g, '');
  if (strippedRoot !== rootLabel && PUBLIC_EMAIL_ROOTS.has(strippedRoot)) return true;

  const noisyTail = labels.slice(1).some((label) => /\d/.test(label) || /(?:comm|coom|c0m|con|cm)$/.test(label));
  if (noisyTail && PUBLIC_EMAIL_ROOTS.has(strippedRoot)) return true;

  return [...PUBLIC_EMAIL_ROOTS].some((candidate) => (
    candidate.length >= 4
    && Math.abs(candidate.length - rootLabel.length) <= 2
    && levenshteinDistance(rootLabel, candidate) === 1
  ));
}

function isLikelyWebHost(host) {
  const normalised = normaliseText(host).replace(/^\.+|\.+$/g, '');
  if (!normalised) return false;
  if (normalised.includes('/') || normalised.includes('\\') || normalised.includes('@') || /\s/.test(normalised)) return false;
  if (normalised === 'localhost' || normalised.endsWith('.local')) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalised)) return true;
  return normalised.includes('.') && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(normalised);
}

function getEmailDomain(email) {
  const value = normaliseText(email);
  if (!EMAIL_REGEX.test(value)) return '';
  return value.split('@')[1] || '';
}

function getEmailLocal(email) {
  const value = normaliseText(email);
  if (!EMAIL_REGEX.test(value)) return '';
  return value.split('@')[0] || '';
}

// Strip plus-tags and trailing digits, lowercase. Keeps separators so the
// token-split below can use them.
function normaliseEmailLocal(local) {
  return String(local || '')
    .toLowerCase()
    .split('+')[0]
    .replace(/\d+$/g, '');
}

function emailLocalTokens(local) {
  return normaliseEmailLocal(local)
    .split(/[._-]+/)
    .filter((token) => token.length >= 4);
}

// Strip all separators and trailing digits, so 'tobias.schimps' matches
// 'tobiasschimps' and 'tschimps21' matches 'tschimps'.
function canonicaliseEmailLocal(local) {
  return normaliseEmailLocal(local).replace(/[._-]/g, '');
}

// Two emails are alias-equivalent when their domains match AND either:
//   - their canonical locals are equal,
//   - one canonical local contains the other (>= 4 chars), or
//   - they share a 4+ char token (e.g. 'schimps' between 't.schimps' and 'tobias.schimps').
function emailAliasMatches(emailA, emailB) {
  const domainA = getEmailDomain(emailA);
  const domainB = getEmailDomain(emailB);
  if (!domainA || domainA !== domainB) return false;

  const localA = canonicaliseEmailLocal(getEmailLocal(emailA));
  const localB = canonicaliseEmailLocal(getEmailLocal(emailB));
  if (!localA || !localB) return false;
  if (localA === localB) return true;
  if (localA.length >= 4 && localB.includes(localA)) return true;
  if (localB.length >= 4 && localA.includes(localB)) return true;

  const tokensA = emailLocalTokens(getEmailLocal(emailA));
  const tokensB = new Set(emailLocalTokens(getEmailLocal(emailB)));
  return tokensA.some((token) => tokensB.has(token));
}

function findEmailAliasMatch(targetEmail, emailSet) {
  if (!targetEmail || !emailSet || emailSet.size === 0) return '';
  for (const candidate of emailSet) {
    if (emailAliasMatches(targetEmail, candidate)) return candidate;
  }
  return '';
}

function isPublicEmailDomain(domain) {
  const normalised = normaliseText(domain);
  return PUBLIC_EMAIL_DOMAINS.has(normalised) || looksLikePublicEmailTypo(normalised);
}

function isCorporateEmailDomain(domain) {
  return Boolean(domain) && !isPublicEmailDomain(domain);
}

function collectEmailsFromText(text) {
  const matches = String(text || '').match(SCAN_EMAIL_REGEX) || [];
  return [...new Set(matches.map((value) => value.toLowerCase()))];
}

function getDomainTokens(domain) {
  if (!domain) return [];
  const labels = normaliseText(domain)
    .split('.')
    .map((label) => label.trim())
    .filter((label) => label && label.length >= 4 && !COMMON_DOMAIN_LABELS.has(label) && !/^\d+$/.test(label));
  return [...new Set(labels)].sort((a, b) => b.length - a.length);
}

function tokenPattern(token) {
  return new RegExp(`(^|[^a-z0-9])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`, 'i');
}

function hostMatchesIdentityDomain(host, identityDomain) {
  const normalisedHost = normaliseText(host);
  const normalisedDomain = normaliseText(identityDomain);
  if (!normalisedHost || !normalisedDomain) return false;
  if (normalisedHost.includes(normalisedDomain)) return true;
  return getDomainTokens(normalisedDomain).some((token) => tokenPattern(token).test(normalisedHost));
}

function getProviderDescriptor(host) {
  const lowerHost = normaliseText(host);
  if (!lowerHost) return null;

  for (const provider of PROVIDER_DEFINITIONS) {
    if (provider.tenantHostPatterns.some((pattern) => pattern.test(lowerHost))) {
      return { ...provider, kind: 'tenant' };
    }
    if (provider.genericHostPatterns.some((pattern) => pattern.test(lowerHost))) {
      return { ...provider, kind: 'generic' };
    }
  }

  return null;
}

function daysBetween(laterDate, earlierDate) {
  if (!(laterDate instanceof Date) || !(earlierDate instanceof Date)) return null;
  return Math.round((laterDate.getTime() - earlierDate.getTime()) / 86400000);
}

function summariseEvidence(parts) {
  return parts.filter(Boolean).join(' | ');
}

function addScore(target, amount, label, type = 'direct') {
  if (!amount || !label) return;
  target.score += amount;
  if (type === 'tenant') target.tenantScore += amount;
  else if (type === 'platform') target.platformScore += amount;
  else if (type === 'competition') target.competitionPenalty += Math.abs(amount);
  else if (type === 'identity') {
    target.identityScore += amount;
    target.directScore += amount;
  } else if (type === 'site') {
    target.siteScore += amount;
    target.directScore += amount;
  } else target.directScore += amount;
  target.evidence.push(label);
}

function buildIdentityFitMeta({ usernameDomain, targetIdentityDomain, dominant, conflictDomain, tenantScore, siteScore, siteHost, siteBase }) {
  if (!usernameDomain) {
    return {
      key: 'no-email',
      label: 'No email identity',
      note: 'Credential row has no email-style username to correlate.',
      tone: 'neutral',
    };
  }

  if (isPublicEmailDomain(usernameDomain)) {
    return {
      key: 'public',
      label: 'Personal / public email',
      note: 'Public-email identities can still be active, but they do not indicate employer alignment.',
      tone: 'public',
    };
  }

  if (conflictDomain) {
    return {
      key: 'legacy-competing',
      label: 'Competes with corroborated employer',
      note: `Current-case evidence is stronger for ${conflictDomain} than for ${usernameDomain}.`,
      tone: 'danger',
    };
  }

  if (targetIdentityDomain?.strong && dominant?.domain === usernameDomain) {
    return {
      key: 'aligned-corroborated',
      label: 'Matches corroborated employer',
      note: `${usernameDomain} is the strongest corroborated corporate identity in the case.`,
      tone: 'success',
    };
  }

  if (targetIdentityDomain?.strong) {
    return {
      key: 'corroborated',
      label: 'Corroborated corporate identity',
      note: `${usernameDomain} is backed by web, token, note, or clipboard evidence.`,
      tone: 'success',
    };
  }

  const serviceBacked = Boolean(
    usernameDomain
    && (
      tenantScore > 0
      || (siteScore >= 18 && (hostMatchesIdentityDomain(siteHost, usernameDomain) || normaliseText(siteBase) === normaliseText(usernameDomain)))
    )
  );

  if (serviceBacked) {
    return {
      key: 'service-backed',
      label: 'Service-backed corporate identity',
      note: `${usernameDomain} is supported by tenant-specific or aligned service activity in this case.`,
      tone: 'accent',
    };
  }

  if (targetIdentityDomain) {
    return {
      key: 'candidate',
      label: 'Tentative corporate identity',
      note: `${usernameDomain} appears in identity artifacts, but it is not yet corroborated.`,
      tone: 'warning',
    };
  }

  return {
    key: 'orphaned',
    label: 'Unsupported corporate identity',
    note: `${usernameDomain} does not have supporting identity artifacts in this case.`,
    tone: 'danger',
  };
}

function buildDispositionMeta(result) {
  // Legacy employer first: a competing dominant domain is a stronger signal
  // than the consumer-site reuse pattern, and the latter only matters once
  // we've already disambiguated the user's current employer.
  if (result.conflictDomain) {
    return {
      key: 'legacy-employer',
      label: 'Legacy employer candidate',
      note: `Another corroborated corporate identity (${result.conflictDomain}) looks more current.`,
      tone: 'danger',
      priority: true,
    };
  }

  if (result.isCorpEmailOnConsumerSite) {
    return {
      key: 'corp-on-consumer',
      label: 'Corp email on consumer service',
      note: `${result.usernameDomain} credential reused on ${result.siteDomain || 'a consumer site'}; possible password-reuse or shadow-IT signal.`,
      tone: 'warning',
      priority: true,
    };
  }

  if (result.bucket === 'likely-current' && (result.siteScore >= 18 || result.tenantScore >= 10)) {
    return {
      key: 'priority-active',
      label: 'Priority active candidate',
      note: 'Fresh site or tenant evidence makes this worth immediate review.',
      tone: 'success',
      priority: true,
    };
  }

  if (result.bucket === 'likely-current' && result.identityFitKey === 'public') {
    return {
      key: 'personal-active',
      label: 'Personal account, active',
      note: 'Public-email account with strong identity evidence in this case.',
      tone: 'accent',
      priority: false,
    };
  }

  if (result.bucket === 'likely-current') {
    return {
      key: 'high-confidence',
      label: 'High-confidence currentness',
      note: 'Identity and service evidence align strongly at capture time.',
      tone: 'success',
      priority: true,
    };
  }

  if (result.bucket === 'review' && result.identityFitKey === 'aligned-corroborated') {
    return {
      key: 'aligned-review',
      label: 'Aligned to current employer',
      note: 'Employer evidence is strong, but the service-specific proof is incomplete.',
      tone: 'accent',
      priority: true,
    };
  }

  if (result.bucket === 'review' && result.identityFitKey === 'public') {
    return {
      key: 'personal-review',
      label: 'Personal account candidate',
      note: 'Public-email identity is active elsewhere in the case, but site proof is moderate.',
      tone: 'accent',
      priority: false,
    };
  }

  if (result.identityFitKey === 'orphaned' && result.bucket === 'weak') {
    return {
      key: 'likely-historical',
      label: 'Likely historical',
      note: 'Corporate identity appears isolated or stale relative to capture time.',
      tone: 'danger',
      priority: false,
    };
  }

  if (isCorporateEmailDomain(result.usernameDomain) && result.bucket === 'review') {
    return {
      key: 'corporate-review',
      label: 'Corporate review needed',
      note: 'There is some employer evidence, but not enough to treat this credential as current.',
      tone: 'warning',
      priority: false,
    };
  }

  if (result.bucket === 'review') {
    return {
      key: 'manual-review',
      label: 'Manual review',
      note: 'Signals are mixed or partial.',
      tone: 'warning',
      priority: false,
    };
  }

  return {
    key: 'low-confidence',
    label: 'Low-confidence / historical',
    note: 'Not enough supporting evidence was recovered around capture time.',
    tone: 'neutral',
    priority: false,
  };
}

function summariseIdentityDomainRows(identityDomains, rows) {
  return identityDomains.corporateDomains.slice(0, 8).map((entry) => {
    const relatedRows = rows.filter((row) => row.usernameDomain === entry.domain);
    const priorityCount = relatedRows.filter((row) => row.isPriority).length;
    const likelyCurrent = relatedRows.filter((row) => row.bucket === 'likely-current').length;
    const review = relatedRows.filter((row) => row.bucket === 'review').length;
    const weak = relatedRows.filter((row) => row.bucket === 'weak').length;
    const influencedRows = rows.filter((row) => row.conflictDomain === entry.domain).length;

    let status = 'tentative';
    let statusLabel = 'Tentative';
    let statusTone = 'warning';

    const hasServiceBackedRows = relatedRows.some((row) => row.identityFitKey === 'service-backed' || row.tenantScore > 0);

    if (entry.strong) {
      status = 'corroborated';
      statusLabel = 'Corroborated';
      statusTone = 'success';
    } else if (hasServiceBackedRows) {
      status = 'service-backed';
      statusLabel = 'Service-backed';
      statusTone = 'accent';
    } else if (relatedRows.length > 0 && likelyCurrent === 0 && review === 0) {
      status = 'legacy-suspect';
      statusLabel = 'Likely legacy';
      statusTone = 'danger';
    }

    return {
      domain: entry.domain,
      score: entry.score,
      strong: entry.strong,
      webSignals: entry.webSignals,
      sources: [...entry.sources],
      status,
      statusLabel,
      statusTone,
      rowCount: relatedRows.length,
      priorityCount,
      likelyCurrent,
      review,
      weak,
      influencedRows,
    };
  });
}

// Map password -> Set of distinct base domains it's used on (>=2 sites).
// Reuse signals active use of a password: typing it on multiple services is
// strong evidence the user remembers it and uses it currently.
function buildPasswordReuseMap(credentials) {
  const usage = new Map();
  for (const entry of credentials || []) {
    const pwd = String(entry.password || '').trim();
    if (!pwd || pwd.length < 4) continue;
    if (COMMON_WEAK_PASSWORDS.has(pwd.toLowerCase())) continue;
    const host = normaliseText(extractDomain(entry.url));
    const base = normaliseText(extractBaseDomain(host) || host);
    if (!base) continue;
    if (!usage.has(pwd)) usage.set(pwd, new Set());
    usage.get(pwd).add(base);
  }
  const reuse = new Map();
  for (const [pwd, sites] of usage) {
    if (sites.size >= 2) reuse.set(pwd, sites);
  }
  return reuse;
}

function buildExactIdentitySets({ autofillEntries, notes, accountTokens, clipboardEntries, credentials }) {
  const autofillClassified = classifyAutofillEntries(autofillEntries || [], 50);
  const autofillEmails = new Set((autofillClassified.emails || []).map((value) => value.toLowerCase()));
  const noteEmails = new Set((notes || []).flatMap((entry) => (entry.emails || []).map((value) => value.toLowerCase())));
  const tokenEmails = new Set(
    (accountTokens || [])
      .map((entry) => normaliseText(entry.accountId))
      .filter((value) => EMAIL_REGEX.test(value))
  );
  const clipboardEmails = new Set(
    (clipboardEntries || [])
      .flatMap((entry) => collectEmailsFromText(`${entry.text || ''}\n${entry.urls || ''}`))
  );
  const credentialEmails = new Set(
    (credentials || [])
      .map((entry) => normaliseText(entry.username))
      .filter((value) => EMAIL_REGEX.test(value))
  );

  return {
    autofillEmails,
    noteEmails,
    tokenEmails,
    clipboardEmails,
    credentialEmails,
  };
}

function getHostSubdomainLabels(host) {
  const parts = normaliseText(host).split('.').filter(Boolean);
  // Strip the eTLD+1; whatever's left are subdomain labels we can match
  // against identity-domain tokens.
  if (parts.length <= 2) return [];
  return parts.slice(0, parts.length - 2);
}

function buildIdentityDomainScores(identitySets, siteIndexes, providerArtifacts) {
  const domainScores = new Map();

  function addEmails(iterable, amount, sourceLabel) {
    for (const email of iterable) {
      const domain = getEmailDomain(email);
      if (!domain) continue;
      if (!domainScores.has(domain)) {
        domainScores.set(domain, { domain, score: 0, sources: new Set(), emails: new Set(), webSignals: 0, strong: false });
      }
      const entry = domainScores.get(domain);
      entry.score += amount;
      entry.sources.add(sourceLabel);
      entry.emails.add(email);
    }
  }

  addEmails(identitySets.autofillEmails, 8, 'autofill');
  addEmails(identitySets.noteEmails, 6, 'notes');
  addEmails(identitySets.tokenEmails, 10, 'tokens');
  addEmails(identitySets.clipboardEmails, 6, 'clipboard');
  addEmails(identitySets.credentialEmails, 2, 'credentials');

  for (const entry of domainScores.values()) {
    const baseDomain = normaliseText(extractBaseDomain(entry.domain) || entry.domain);
    if (!baseDomain) continue;

    const cookieSummary = siteIndexes.cookieByBase.get(baseDomain);
    if (cookieSummary?.liveSessions || cookieSummary?.validCookies) {
      entry.score += 4;
      entry.webSignals += 1;
      entry.sources.add('cookies');
    }

    const historySummary = siteIndexes.historyByBase.get(baseDomain);
    if (historySummary?.latestVisitDate || historySummary?.totalEntries) {
      entry.score += 4;
      entry.webSignals += 1;
      entry.sources.add('history');
    }

    const downloadCount = siteIndexes.downloadByBase.get(baseDomain) || 0;
    if (downloadCount > 0) {
      entry.score += 3;
      entry.webSignals += 1;
      entry.sources.add('downloads');
    }

    const noteCount = siteIndexes.noteByBase.get(baseDomain)?.count || 0;
    if (noteCount > 0) {
      entry.score += 3;
      entry.webSignals += 1;
      entry.sources.add('notes-domain');
    }

    // Tenant subdomain match (e.g. acme.atlassian.net → acme.com): credit the
    // identity domain when a provider tenant artifact carries the domain's token.
    if (providerArtifacts && isCorporateEmailDomain(entry.domain)) {
      const tokens = getDomainTokens(entry.domain);
      if (tokens.length > 0) {
        const matched = providerArtifacts.some((artifact) => {
          if (artifact.kind !== 'tenant') return false;
          const labels = getHostSubdomainLabels(artifact.host);
          return labels.some((label) => tokens.includes(label));
        });
        if (matched) {
          entry.score += 6;
          entry.webSignals += 1;
          entry.sources.add('tenant');
        }
      }
    }

    entry.strong = entry.webSignals > 0
      || entry.sources.has('tokens')
      || entry.sources.has('notes')
      || entry.sources.has('clipboard');
  }

  const corporateDomains = [...domainScores.values()]
    .filter((entry) => isCorporateEmailDomain(entry.domain))
    .sort((a, b) => b.score - a.score || a.domain.localeCompare(b.domain));

  const strongCorporateDomains = corporateDomains.filter((entry) => entry.strong);

  return {
    byDomain: domainScores,
    corporateDomains,
    strongCorporateDomains,
    dominantCorporateDomain: strongCorporateDomains[0] || null,
    leadingCorporateCandidate: corporateDomains[0] || null,
  };
}

function emptyCookieSummary() {
  return { liveSessions: 0, validCookies: 0, expiredCookies: 0 };
}
function emptyHistorySummary() {
  return { latestVisitDate: null, totalEntries: 0, totalVisitCount: 0, loginHits: 0 };
}

function buildSiteIndexes({ cookies, history, notes, downloads, bookmarks }) {
  const cookieByBase = new Map();
  const cookieByHost = new Map();
  const historyByBase = new Map();
  const historyByHost = new Map();
  const noteByBase = new Map();
  const downloadByBase = new Map();
  const bookmarkByBase = new Map();

  for (const entry of cookies || []) {
    const host = normaliseText(entry.host).replace(/^\.+/, '');
    if (!isLikelyWebHost(host)) continue;
    const baseDomain = extractBaseDomain(host) || host;
    if (!baseDomain) continue;
    const live = isLiveSessionToken({ sessionType: entry.sessionType, validity: entry.validityStatus });
    for (const [map, key] of [[cookieByBase, baseDomain], [cookieByHost, host]]) {
      if (!map.has(key)) map.set(key, emptyCookieSummary());
      const summary = map.get(key);
      if (live) summary.liveSessions += 1;
      if (entry.validityStatus === 'valid') summary.validCookies += 1;
      else if (entry.validityStatus === 'expired') summary.expiredCookies += 1;
    }
  }

  for (const entry of history || []) {
    const host = normaliseText(extractDomain(entry.url));
    if (!isLikelyWebHost(host)) continue;
    const baseDomain = extractBaseDomain(host) || host;
    if (!baseDomain) continue;
    for (const [map, key] of [[historyByBase, baseDomain], [historyByHost, host]]) {
      if (!map.has(key)) map.set(key, emptyHistorySummary());
      const summary = map.get(key);
      summary.totalEntries += 1;
      summary.totalVisitCount += Math.max(Number(entry.visitCount) || 1, 1);
      if (entry.lastVisitDate instanceof Date && !isNaN(entry.lastVisitDate.getTime())) {
        if (!summary.latestVisitDate || entry.lastVisitDate > summary.latestVisitDate) {
          summary.latestVisitDate = entry.lastVisitDate;
        }
      }
      if (LOGIN_HINT_PATTERN.test(`${entry.url || ''} ${entry.title || ''}`)) {
        summary.loginHits += 1;
      }
    }
  }

  for (const entry of notes || []) {
    for (const domain of entry.domains || []) {
      if (!isLikelyWebHost(domain)) continue;
      const baseDomain = extractBaseDomain(domain) || domain;
      if (!baseDomain) continue;
      if (!noteByBase.has(baseDomain)) {
        noteByBase.set(baseDomain, { count: 0 });
      }
      const summary = noteByBase.get(baseDomain);
      summary.count += 1;
    }
  }

  for (const entry of downloads || []) {
    const resolved = normaliseText(entry.domain || extractDomain(entry.sourceUrl));
    if (!isLikelyWebHost(resolved)) continue;
    const baseDomain = extractBaseDomain(resolved) || resolved;
    if (!baseDomain) continue;
    downloadByBase.set(baseDomain, (downloadByBase.get(baseDomain) || 0) + 1);
  }

  for (const entry of bookmarks || []) {
    const resolved = normaliseText(entry.domain || extractDomain(entry.url));
    if (!isLikelyWebHost(resolved)) continue;
    const baseDomain = extractBaseDomain(resolved) || resolved;
    if (!baseDomain) continue;
    bookmarkByBase.set(baseDomain, (bookmarkByBase.get(baseDomain) || 0) + 1);
  }

  return {
    cookieByBase,
    cookieByHost,
    historyByBase,
    historyByHost,
    noteByBase,
    downloadByBase,
    bookmarkByBase,
  };
}

// `host` and `text` are stored already lower-cased: collectTenantSignal scans
// every artifact once per credential, so re-normalising there is O(n*m).
function buildProviderArtifacts({ cookies, history, downloads, notes }) {
  const artifacts = [];

  for (const entry of cookies || []) {
    const host = normaliseText(entry.host);
    if (!isLikelyWebHost(host)) continue;
    const provider = getProviderDescriptor(host);
    if (!provider) continue;
    artifacts.push({
      source: 'cookie',
      providerKey: provider.key,
      providerLabel: provider.label,
      kind: provider.kind,
      host,
      text: normaliseText(`${host} ${entry.name || ''}`),
      date: null,
      recentWeight: entry.validityStatus === 'valid' ? 2 : 1,
    });
  }

  for (const entry of history || []) {
    const host = normaliseText(extractDomain(entry.url));
    if (!isLikelyWebHost(host)) continue;
    const provider = getProviderDescriptor(host);
    if (!provider) continue;
    artifacts.push({
      source: 'history',
      providerKey: provider.key,
      providerLabel: provider.label,
      kind: provider.kind,
      host,
      text: normaliseText(`${entry.url || ''} ${entry.title || ''}`),
      date: entry.lastVisitDate || null,
      recentWeight: Math.max(1, Number(entry.visitCount) || 1),
    });
  }

  for (const entry of downloads || []) {
    const host = normaliseText(entry.domain || extractDomain(entry.sourceUrl));
    if (!isLikelyWebHost(host)) continue;
    const provider = getProviderDescriptor(host);
    if (!provider) continue;
    artifacts.push({
      source: 'download',
      providerKey: provider.key,
      providerLabel: provider.label,
      kind: provider.kind,
      host,
      text: normaliseText(`${entry.sourceUrl || ''} ${entry.filePath || ''}`),
      date: null,
      recentWeight: 1,
    });
  }

  for (const entry of notes || []) {
    const joinedDomains = (entry.domains || []).join(' ');
    const joinedText = normaliseText(`${entry.title || ''} ${entry.text || ''} ${joinedDomains}`);
    for (const domain of entry.domains || []) {
      if (!isLikelyWebHost(domain)) continue;
      const provider = getProviderDescriptor(domain);
      if (!provider) continue;
      artifacts.push({
        source: 'note',
        providerKey: provider.key,
        providerLabel: provider.label,
        kind: provider.kind,
        host: normaliseText(domain),
        text: joinedText,
        date: entry.modifiedDate || null,
        recentWeight: 1,
      });
    }
  }

  return artifacts;
}

function getRecentStrength(date, captureDate) {
  if (!(captureDate instanceof Date) || isNaN(captureDate.getTime())) return 1;
  if (!(date instanceof Date) || isNaN(date.getTime())) return 1;
  const deltaDays = Math.abs(daysBetween(captureDate, date));
  if (deltaDays <= 30) return 3;
  if (deltaDays <= 180) return 2;
  if (deltaDays <= 365) return 1;
  return 0;
}

function collectTenantSignal({ usernameEmail, usernameDomain, providerArtifacts, captureDate }) {
  if (!usernameDomain) {
    return { score: 0, evidence: [] };
  }

  const tokens = getDomainTokens(usernameDomain);
  const tokenPatterns = tokens.map(tokenPattern);
  const exactEmail = normaliseText(usernameEmail);
  const evidence = [];
  let score = 0;
  let exactDomainMatched = false;
  let tokenMatched = false;

  for (const artifact of providerArtifacts) {
    const artifactText = artifact.text;

    if (!exactDomainMatched && artifact.kind === 'tenant' && (artifactText.includes(usernameDomain) || artifact.host.includes(usernameDomain))) {
      const amount = getRecentStrength(artifact.date, captureDate) >= 2 ? 14 : 9;
      score += amount;
      evidence.push({ amount, label: `${artifact.providerLabel} tenant activity mentions ${usernameDomain}` });
      exactDomainMatched = true;
      continue;
    }

    if (!tokenMatched && artifact.kind === 'tenant' && tokenPatterns.some((pattern) => pattern.test(artifactText))) {
      const amount = getRecentStrength(artifact.date, captureDate) >= 2 ? 10 : 6;
      score += amount;
      evidence.push({ amount, label: `${artifact.providerLabel} tenant activity matches ${tokens[0]}` });
      tokenMatched = true;
    }

    if (exactEmail && artifactText.includes(exactEmail)) {
      score += 8;
      evidence.push({ amount: 8, label: `${artifact.providerLabel} activity mentions ${exactEmail}` });
      break;
    }
  }

  return { score, evidence };
}

function collectGenericProviderSupport({ providerArtifacts, captureDate }) {
  const genericCounts = new Map();

  for (const artifact of providerArtifacts) {
    if (artifact.kind !== 'generic') continue;
    const recency = getRecentStrength(artifact.date, captureDate);
    if (recency <= 0) continue;
    genericCounts.set(
      artifact.providerLabel,
      (genericCounts.get(artifact.providerLabel) || 0) + recency * artifact.recentWeight
    );
  }

  return [...genericCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([label, count]) => ({ label, count }));
}

function classifyBucket(score) {
  if (score >= 45) return 'likely-current';
  if (score >= 25) return 'review';
  return 'weak';
}

function classifyBucketLabel(bucket) {
  if (bucket === 'likely-current') return 'Likely Current';
  if (bucket === 'review') return 'Needs Review';
  return 'Weak / Historical';
}

function scoreCredential(entry, context) {
  const rawUrl = String(entry.url || '');
  const isAppCredential = /^android:\/\//i.test(rawUrl) || /^ios:\/\//i.test(rawUrl);
  const rawSiteHost = normaliseText(extractDomain(entry.url));
  const siteHost = isLikelyWebHost(rawSiteHost) ? rawSiteHost : '';
  const siteBase = normaliseText(extractBaseDomain(siteHost) || siteHost);
  const username = String(entry.username || '').trim();
  const usernameEmail = normaliseText(username);
  const usernameDomain = getEmailDomain(usernameEmail);
  const siteProvider = getProviderDescriptor(siteHost);
  const isConsumerSite = Boolean(siteBase) && CONSUMER_SITE_BASE_DOMAINS.has(siteBase);
  const siteMatchesUsernameDomain = Boolean(usernameDomain && siteBase && siteBase === usernameDomain);
  // Don't flag a credential as "corp email on consumer site" when the user
  // actually works at that company (e.g., jane@etsy.com signing into etsy.com).
  const isCorpEmailOnConsumerSite = isConsumerSite
    && isCorporateEmailDomain(usernameDomain)
    && !siteMatchesUsernameDomain;

  const result = {
    url: entry.url || '',
    username,
    siteHost,
    siteDomain: siteBase,
    usernameDomain,
    isConsumerSite,
    isCorpEmailOnConsumerSite,
    isAppCredential,
    score: 0,
    directScore: 0,
    identityScore: 0,
    siteScore: 0,
    tenantScore: 0,
    platformScore: 0,
    competitionPenalty: 0,
    evidence: [],
    conflictDomain: '',
    hasLiveSession: false,
    hasRecentVisit: false,
  };

  const {
    captureDate,
    identitySets,
    identityDomains,
    siteIndexes,
    providerArtifacts,
    genericProviderSupport,
  } = context;

  if (usernameEmail) {
    if (identitySets.autofillEmails.has(usernameEmail)) {
      addScore(result, 22, `Autofill contains ${usernameEmail}`, 'identity');
    } else {
      const alias = findEmailAliasMatch(usernameEmail, identitySets.autofillEmails);
      if (alias) addScore(result, 14, `Autofill contains alias ${alias}`, 'identity');
    }

    if (identitySets.tokenEmails.has(usernameEmail)) {
      addScore(result, 24, `Token/account material contains ${usernameEmail}`, 'identity');
    } else {
      const alias = findEmailAliasMatch(usernameEmail, identitySets.tokenEmails);
      if (alias) addScore(result, 16, `Token/account material contains alias ${alias}`, 'identity');
    }

    if (identitySets.noteEmails.has(usernameEmail)) {
      addScore(result, 12, `Notes mention ${usernameEmail}`, 'identity');
    } else if (findEmailAliasMatch(usernameEmail, identitySets.noteEmails)) {
      addScore(result, 6, `Notes mention an alias of ${usernameEmail}`, 'identity');
    }

    if (identitySets.clipboardEmails.has(usernameEmail)) {
      addScore(result, 12, `Clipboard mentions ${usernameEmail}`, 'identity');
    } else if (findEmailAliasMatch(usernameEmail, identitySets.clipboardEmails)) {
      addScore(result, 6, `Clipboard mentions an alias of ${usernameEmail}`, 'identity');
    }
  }

  const targetIdentityDomain = usernameDomain && identityDomains.byDomain.has(usernameDomain)
    ? identityDomains.byDomain.get(usernameDomain)
    : null;
  if (targetIdentityDomain?.strong) {
    addScore(result, 10, `${usernameDomain} is supported as an active identity domain`, 'identity');
  } else if (targetIdentityDomain && targetIdentityDomain.score >= 12 && targetIdentityDomain.sources.size >= 2) {
    addScore(result, 4, `${usernameDomain} appears across multiple identity artifacts`, 'identity');
  }

  if (siteMatchesUsernameDomain && isCorporateEmailDomain(usernameDomain)) {
    addScore(result, 8, `Credential site is the user's email domain (${usernameDomain})`, 'identity');
  }

  if (isAppCredential && isCorporateEmailDomain(usernameDomain)) {
    addScore(result, 6, 'App-stored credential (mobile app actively signed in)', 'site');
  }

  let siteSignalCount = 0;
  // Multi-tenant SaaS hosts (acme.atlassian.net, contoso.sharepoint.com, etc.)
  // share a base domain across unrelated organisations. Score those by full
  // host so one tenant's cookies don't bless another tenant's credential.
  const useFullHost = Boolean(
    siteHost
    && siteProvider?.kind === 'tenant'
    && siteProvider.key
    && TENANT_FULL_HOST_PROVIDER_KEYS.has(siteProvider.key)
  );
  const cookieKey = useFullHost ? siteHost : siteBase;
  const historyKey = useFullHost ? siteHost : siteBase;
  const cookieMap = useFullHost ? siteIndexes.cookieByHost : siteIndexes.cookieByBase;
  const historyMap = useFullHost ? siteIndexes.historyByHost : siteIndexes.historyByBase;

  const isGenericProviderSite = siteProvider?.kind === 'generic';

  // Own-site evidence always counts, generic providers included: a valid
  // session cookie for github.com is direct proof for a github.com credential.
  // Generic de-crediting applies only where an artifact would lend credit to a
  // credential on a different host (see genericProviderSupport below).
  if (siteBase) {
    const cookieSummary = cookieMap.get(cookieKey);
    const cookieLabel = useFullHost ? siteHost : siteBase;
    if (cookieSummary?.liveSessions) {
      addScore(result, 28, `${cookieSummary.liveSessions} live session cookie${cookieSummary.liveSessions === 1 ? '' : 's'} for ${cookieLabel}`, 'site');
      result.hasLiveSession = true;
      siteSignalCount += 1;
    } else if (cookieSummary?.validCookies) {
      addScore(result, 16, `${cookieSummary.validCookies} valid cookie${cookieSummary.validCookies === 1 ? '' : 's'} for ${cookieLabel}`, 'site');
      siteSignalCount += 1;
    } else if (cookieSummary?.expiredCookies && !isGenericProviderSite) {
      // Shared generic hosts (accounts.google.com, github.com...) accumulate
      // stale cookies from any browser profile; that says nothing about this
      // credential.
      addScore(result, -4, `Only expired cookies recovered for ${cookieLabel}`, 'competition');
    }

    const historySummary = historyMap.get(historyKey);
    const siteLabel = useFullHost ? siteHost : siteBase;
    if (historySummary?.latestVisitDate) {
      if (captureDate instanceof Date) {
        const deltaDays = Math.abs(daysBetween(captureDate, historySummary.latestVisitDate));
        if (deltaDays <= 30) {
          addScore(result, 18, `History hit for ${siteLabel} within 30d of capture`, 'site');
          result.hasRecentVisit = true;
        } else if (deltaDays <= 180) {
          addScore(result, 12, `History hit for ${siteLabel} within 180d of capture`, 'site');
        } else if (deltaDays <= 365) {
          addScore(result, 6, `History hit for ${siteLabel} within 1y of capture`, 'site');
        }
      } else {
        addScore(result, 6, `History activity for ${siteLabel} (no capture anchor for recency)`, 'site');
      }
      if (historySummary.loginHits > 0) addScore(result, 6, `${historySummary.loginHits} login-like history hit${historySummary.loginHits === 1 ? '' : 's'} for ${siteLabel}`, 'site');
      if (historySummary.totalVisitCount >= 5) addScore(result, 4, `${historySummary.totalVisitCount} total visits to ${siteLabel}`, 'site');
      siteSignalCount += 1;
    }

    const noteCount = siteIndexes.noteByBase.get(siteBase)?.count || 0;
    if (noteCount > 0) {
      addScore(result, 6, `${noteCount} note reference${noteCount === 1 ? '' : 's'} to ${siteBase}`, 'site');
      siteSignalCount += 1;
    }

    const downloadCount = siteIndexes.downloadByBase.get(siteBase) || 0;
    if (downloadCount > 0) {
      addScore(result, 6, `${downloadCount} download reference${downloadCount === 1 ? '' : 's'} to ${siteBase}`, 'site');
      siteSignalCount += 1;
    }

    const bookmarkCount = siteIndexes.bookmarkByBase.get(siteBase) || 0;
    if (bookmarkCount > 0) {
      addScore(result, 3, `${bookmarkCount} bookmark${bookmarkCount === 1 ? '' : 's'} for ${siteBase}`, 'site');
      siteSignalCount += 1;
    }
  }

  if (isCorporateEmailDomain(usernameDomain) && targetIdentityDomain?.strong && siteSignalCount > 0) {
    addScore(result, 6, `${usernameDomain} aligns with corroborated identity and service activity`, 'identity');
  }

  const tenantSignal = collectTenantSignal({
    usernameEmail,
    usernameDomain,
    providerArtifacts,
    captureDate,
  });
  for (const { amount, label } of tenantSignal.evidence) {
    addScore(result, amount, label, 'tenant');
  }

  const dominant = identityDomains.dominantCorporateDomain;
  const hasAlignedServiceEvidence = Boolean(
    usernameDomain
    && (
      result.tenantScore > 0
      || (result.siteScore >= 18 && (hostMatchesIdentityDomain(siteHost, usernameDomain) || siteBase === usernameDomain))
    )
  );
  if (dominant?.strong && usernameDomain && dominant.domain !== usernameDomain && isCorporateEmailDomain(usernameDomain)) {
    const ownScore = targetIdentityDomain?.score || 0;
    if (!hasAlignedServiceEvidence && dominant.score >= ownScore + 8) {
      result.conflictDomain = dominant.domain;
      addScore(result, -18, `Stronger recent corporate identity exists for ${dominant.domain}`, 'competition');
    }
  }

  const canUseGenericProviderSupport = Boolean(
    genericProviderSupport.length > 0
    && !result.conflictDomain
    && (
      siteProvider
      || result.tenantScore > 0
      || (targetIdentityDomain?.strong && result.directScore >= 18)
    )
  );
  if (canUseGenericProviderSupport) {
    const topProvider = genericProviderSupport[0];
    addScore(result, 4, `Generic ${topProvider.label} activity seen elsewhere in the case`, 'platform');
  }

  if (isCorporateEmailDomain(usernameDomain) && result.score < 12 && !result.conflictDomain) {
    // Small nudge so thin-evidence corp credentials stay visible but ranked
    // low.
    addScore(result, -3, `${usernameDomain} has little corroborating evidence beyond the credential row`, 'competition');
  }

  // Password reuse is a strong "this password is current" signal. Cap the bonus
  // so a 30-site reuse doesn't drown out cookie / token evidence.
  const reuseSites = context.passwordReuse.get(entry.password);
  if (reuseSites && reuseSites.size >= 2) {
    const sitesCount = reuseSites.size;
    const bonus = Math.min(10, 4 + sitesCount);
    addScore(result, bonus, `Password reused across ${sitesCount} sites in this case`, 'identity');
    result.reuseCount = sitesCount;
    result.reuseSites = [...reuseSites].slice(0, 8);
  } else {
    result.reuseCount = 0;
    result.reuseSites = [];
  }

  const identityFit = buildIdentityFitMeta({
    usernameDomain,
    targetIdentityDomain,
    dominant,
    conflictDomain: result.conflictDomain,
    tenantScore: result.tenantScore,
    siteScore: result.siteScore,
    siteHost,
    siteBase,
  });
  result.identityFitKey = identityFit.key;
  result.identityFitLabel = identityFit.label;
  result.identityFitNote = identityFit.note;
  result.identityFitTone = identityFit.tone;

  result.bucket = classifyBucket(result.score);
  result.bucketLabel = classifyBucketLabel(result.bucket);
  const disposition = buildDispositionMeta(result);
  result.dispositionKey = disposition.key;
  result.dispositionLabel = disposition.label;
  result.dispositionNote = disposition.note;
  result.dispositionTone = disposition.tone;
  result.isPriority = disposition.priority;
  result.evidenceSummary = summariseEvidence(result.evidence);

  result.actionability = classifyActionability(result);
  result.displayLabel = shortDispositionLabel(result);

  // Domain category from the vendored Tranco / Wikidata / Matomo lists.
  // `unknown` here is the analyst-priority bucket.
  const cat = classifySiteDomain(result.siteHost || result.siteDomain);
  result.categoryKey = cat.primaryKey || 'unknown';
  result.categoryLabel = cat.primaryLabel || 'Uncategorised';
  result.categories = cat.categories;

  return result;
}

// Actionability classifies a credential by how takeover-ready it is at capture
// time, independent of confidence score. Live > recent > stored > legacy.
const ACTIONABILITY_RANK = { live: 0, recent: 1, stored: 2, legacy: 3 };

// Live = the credential's site is provably accessible right now (cookie session
// or app-stored). A token email match is identity-level evidence and feeds the
// score, but doesn't make a non-token site "live": having a Google token
// doesn't mean the user is signed in to Netflix. A live session is takeover-ready
// regardless of a competing employer identity, so it outranks the conflict demotion.
function classifyActionability(result) {
  if (result.hasLiveSession) return 'live';
  if (result.isAppCredential) return 'live';
  if (result.conflictDomain) return 'legacy';
  if (result.hasRecentVisit) return 'recent';
  return 'stored';
}

// A table-friendly short label. The full disposition label still rides along
// for the expanded detail row.
function shortDispositionLabel(result) {
  switch (result.dispositionKey) {
    case 'priority-active': return 'Active session';
    case 'high-confidence': return 'Aligned, current';
    case 'aligned-review': return 'Aligned';
    case 'corp-on-consumer': return 'Reused on consumer site';
    case 'legacy-employer': return 'Legacy employer';
    case 'personal-active': return 'Personal, active';
    case 'personal-review': return 'Personal, recent';
    case 'corporate-review': return 'Possibly current';
    case 'manual-review': return 'Mixed signals';
    case 'likely-historical': return 'Historical';
    case 'low-confidence': return 'Low signal';
    default: return result.bucketLabel || '';
  }
}

function sortScoredRows(rows) {
  return [...rows].sort((a, b) => {
    const ra = ACTIONABILITY_RANK[a.actionability] ?? 9;
    const rb = ACTIONABILITY_RANK[b.actionability] ?? 9;
    if (ra !== rb) return ra - rb;
    if (b.score !== a.score) return b.score - a.score;
    return (a.url || '').localeCompare(b.url || '');
  });
}

// Primary identity = the most useful one-line "who are we looking at".
// Prefers the corroborated corporate identity, then the most-frequent
// personal email, then the OS username from sysinfo. Always returns
// something so the analyst sees a name/email even on personal-only logs.
function buildPrimaryIdentity({ rows, identityDomains, identitySets, sysinfoEntries }) {
  const sysinfo = sysinfoEntries || {};
  const sysGet = (patterns) => {
    for (const [key, value] of Object.entries(sysinfo)) {
      if (!value) continue;
      if (patterns.some((p) => p.test(key))) return String(value).trim();
    }
    return '';
  };
  const osUsername = sysGet([/^user\s*name$/i, /^username$/i, /^user$/i]);
  const computerName = sysGet([/^computer\s*name$/i, /^pc$/i, /^hostname$/i, /^netbios/i]);
  const country = sysGet([/^country$/i, /^region$/i]);

  const dominant = identityDomains.dominantCorporateDomain;

  if (dominant) {
    const counts = new Map();
    for (const row of rows) {
      if (row.usernameDomain !== dominant.domain) continue;
      const norm = normaliseText(row.username);
      if (!norm) continue;
      counts.set(norm, (counts.get(norm) || 0) + 1);
    }
    const topEmail = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
      || [...dominant.emails][0] || '';
    return {
      kind: 'corporate',
      label: topEmail || dominant.domain,
      domain: dominant.domain,
      osUsername,
      computerName,
      country,
    };
  }

  // No corp identity: fall back to most-frequent personal email
  const personalCounts = new Map();
  for (const row of rows) {
    if (!row.usernameDomain) continue;
    if (!isPublicEmailDomain(row.usernameDomain)) continue;
    const norm = normaliseText(row.username);
    if (!norm) continue;
    personalCounts.set(norm, (personalCounts.get(norm) || 0) + 1);
  }
  const topPersonal = [...personalCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  if (topPersonal) {
    return {
      kind: 'personal',
      label: topPersonal,
      domain: getEmailDomain(topPersonal),
      osUsername,
      computerName,
      country,
    };
  }

  // Last resort: any autofill email, or just OS username.
  const autofillEmail = [...identitySets.autofillEmails][0] || '';
  if (autofillEmail) {
    return {
      kind: 'autofill',
      label: autofillEmail,
      domain: getEmailDomain(autofillEmail),
      osUsername,
      computerName,
      country,
    };
  }
  return {
    kind: 'unknown',
    label: osUsername || '',
    domain: '',
    osUsername,
    computerName,
    country,
  };
}

function summariseResults(rows, identityDomains, captureContext, identitySets, sysinfoEntries) {
  const identityDomainRows = summariseIdentityDomainRows(identityDomains, rows);
  const summary = {
    // Rows scored here, not the case's credential count: these collapse by base
    // domain and keep accounts with no captured password, which the dashboard's
    // and the report's unique-credential tally excludes.
    rankedRows: rows.length,
    priorityQueue: rows.filter((row) => row.isPriority).length,
    likelyCurrent: rows.filter((row) => row.bucket === 'likely-current').length,
    review: rows.filter((row) => row.bucket === 'review').length,
    weak: rows.filter((row) => row.bucket === 'weak').length,
    liveCount: rows.filter((row) => row.actionability === 'live').length,
    recentCount: rows.filter((row) => row.actionability === 'recent').length,
    storedCount: rows.filter((row) => row.actionability === 'stored').length,
    legacyCount: rows.filter((row) => row.actionability === 'legacy').length,
    appCount: rows.filter((row) => row.isAppCredential).length,
    reuseGroups: countReuseGroups(rows),
    conflicts: rows.filter((row) => row.conflictDomain).length,
    legacyEmployerSuspects: rows.filter((row) => row.dispositionKey === 'legacy-employer').length,
    orphanedCorporate: rows.filter((row) => row.identityFitKey === 'orphaned').length,
    corroboratedDomainCount: identityDomains.strongCorporateDomains.length,
    tenantSupported: rows.filter((row) => row.tenantScore > 0).length,
    platformSupported: rows.filter((row) => row.platformScore > 0).length,
    dominantCorporateDomain: identityDomains.dominantCorporateDomain || null,
    leadingCorporateCandidate: identityDomains.leadingCorporateCandidate || null,
    identityDomains: identityDomainRows,
    primaryIdentity: buildPrimaryIdentity({ rows, identityDomains, identitySets, sysinfoEntries }),
    captureDate: captureContext.date,
    captureSource: captureContext.source,
    captureDetail: captureContext.detail,
  };

  return summary;
}

function countReuseGroups(rows) {
  const groups = new Set();
  for (const r of rows) {
    if (r.reuseCount && r.reuseCount >= 2) {
      // Count distinct reuse-site sets as a proxy for the shared password.
      const sig = (r.reuseSites || []).slice().sort().join('|');
      groups.add(sig);
    }
  }
  return groups.size;
}

function dedupeCredentials(credentials) {
  // Key = base-domain + username key + raw password. Cross-profile and
  // cross-path entries collapse; emails and phone-shaped usernames fold on the
  // same rule analysis uses, so the ranked rows and the credential totals agree
  // on what counts as one account. Entries with no username AND no password are
  // dropped (URL-only stub rows).
  const SEP = '\u0000';
  const seen = new Map(); // key -> index in out
  const out = [];

  for (const entry of credentials || []) {
    const url = String(entry.url || '').trim();
    const user = String(entry.username || '').trim();
    const pass = String(entry.password || '').trim();

    if (!user && !pass) continue;

    const domainPart = dedupeDomainKey(url);
    const key = domainPart + SEP + usernameDedupeKey(user) + SEP + pass;

    if (seen.has(key)) {
      // Accumulate sources so cross-profile spread is visible in the Lab detail row.
      const existing = out[seen.get(key)];
      if (entry.source) {
        const sources = existing.sources || (existing.source ? [existing.source] : []);
        if (!sources.includes(entry.source)) sources.push(entry.source);
        existing.sources = sources;
      }
      continue;
    }
    seen.set(key, out.length);
    out.push({ ...entry, sources: entry.source ? [entry.source] : [] });
  }

  return out;
}

function buildCredentialCurrentnessModel(input) {
  const credentials = dedupeCredentials(input.credentials || []);

  let historyMaxDate = null;
  for (const entry of input.history || []) {
    const candidate = entry?.lastVisitDate instanceof Date
      ? entry.lastVisitDate
      : parseTimestampValue(entry?.lastVisitDate || entry?.lastVisit);
    if (candidate && (!historyMaxDate || candidate > historyMaxDate)) historyMaxDate = candidate;
  }

  // Score against the instant the rest of the case is judged by. Resolving one
  // here as well is how the Lab used to drift from the dashboard and timeline;
  // the ladder below only runs when nothing has been published yet.
  const published = input.captureContext?.date ? input.captureContext : getCaptureContext();
  const captureContext = published.date ? published : resolveCaptureContext({
    sysinfoEntries: input.sysinfoEntries || null,
    archiveNames: input.rootZipName || '',
    sourceLastModified: input.sourceLastModified || null,
    historyMaxDate,
  });

  const identitySets = buildExactIdentitySets({
    autofillEntries: input.autofillEntries || [],
    notes: input.notes || [],
    accountTokens: input.accountTokens || [],
    clipboardEntries: input.clipboardEntries || [],
    credentials,
  });
  const siteIndexes = buildSiteIndexes({
    cookies: input.cookies || [],
    history: input.history || [],
    notes: input.notes || [],
    downloads: input.downloads || [],
    bookmarks: input.bookmarks || [],
  });
  const providerArtifacts = buildProviderArtifacts({
    cookies: input.cookies || [],
    history: input.history || [],
    downloads: input.downloads || [],
    notes: input.notes || [],
  });
  const identityDomains = buildIdentityDomainScores(identitySets, siteIndexes, providerArtifacts);
  const passwordReuse = buildPasswordReuseMap(credentials);

  const context = {
    captureDate: captureContext.date,
    identitySets,
    identityDomains,
    siteIndexes,
    providerArtifacts,
    genericProviderSupport: collectGenericProviderSupport({
      providerArtifacts,
      captureDate: captureContext.date,
    }),
    passwordReuse,
  };

  const rows = sortScoredRows(credentials.map((entry) => scoreCredential(entry, context)));
  return {
    summary: summariseResults(rows, identityDomains, captureContext, identitySets, input.sysinfoEntries || null),
    rows,
  };
}

export { buildCredentialCurrentnessModel };
