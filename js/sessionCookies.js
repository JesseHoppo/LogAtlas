// Session cookie classification.

import { AUTH_COOKIE_NAMES, SESSION_PATTERNS } from './definitions.js';

// Returns 'auth' for known auth cookies, 'session' for pattern matches, or null.
function classifyCookie(cookieName) {
  if (!cookieName) return null;
  const lower = cookieName.toLowerCase().trim();

  if (AUTH_COOKIE_NAMES.has(lower)) return 'auth';

  for (const pattern of SESSION_PATTERNS) {
    if (pattern.test(lower)) return 'session';
  }

  return null;
}

export { classifyCookie };
