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

// The one test for "this token would still have logged someone in". A cookie
// that was unexpired at capture qualifies, and so does a browser-session cookie:
// it carried no expiry at all, so it was live in the running browser the moment
// the log was taken. Expired cookies and unreadable expiries do not.
function isLiveSessionToken({ sessionType, validity } = {}) {
  if (sessionType !== 'auth' && sessionType !== 'session') return false;
  const status = typeof validity === 'string' ? validity : validity?.status;
  return status === 'valid' || status === 'session';
}

// Whether the row hands over anything an attacker could send back. Bulk
// decryption failure empties the value column for whole cookie sets, and a file
// mapped without a value column never had one, so those rows evidence a
// logged-in account and nothing more. Callers holding a resolved index (or the
// value itself) pass `value`; the rest pass the row and its headers.
function hasReplayableValue({ row, headers, value } = {}) {
  if (value !== undefined) return String(value ?? '').trim() !== '';
  if (!Array.isArray(row)) return false;
  const index = (headers || []).findIndex(header => /^value$/i.test(header));
  return index >= 0 && String(row[index] ?? '').trim() !== '';
}

// The escalating form: live at capture and replayable. Anything that raises an
// alarm or drives a triage state uses this; a plain count of what was live uses
// isLiveSessionToken.
function isReplayableSessionToken(rowData) {
  return isLiveSessionToken(rowData) && hasReplayableValue(rowData);
}

export { classifyCookie, hasReplayableValue, isLiveSessionToken, isReplayableSessionToken };
