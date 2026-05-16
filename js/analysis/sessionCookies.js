import { AD_TRACKER_DOMAINS, AUTH_COOKIE_NAMES, SESSION_PATTERNS } from '../core/definitions/patterns.js';
import { extractBaseDomain } from '../core/shared.js';

// 'auth' for explicit auth cookies, 'session' for SESSION_PATTERNS matches
// that aren't on an ad-tracker domain, 'tracking' if they are, else null.
// Without a domain, the ad-tracker demotion is skipped.
function classifyCookie(cookieName, cookieDomain) {
  if (!cookieName) return null;
  const lower = cookieName.toLowerCase().trim();

  if (AUTH_COOKIE_NAMES.has(lower)) return 'auth';

  for (const pattern of SESSION_PATTERNS) {
    if (pattern.test(lower)) {
      if (cookieDomain) {
        const base = extractBaseDomain(String(cookieDomain).replace(/^\./, '').toLowerCase());
        if (base && AD_TRACKER_DOMAINS.has(base)) return 'tracking';
      }
      return 'session';
    }
  }

  return null;
}

export { classifyCookie };
