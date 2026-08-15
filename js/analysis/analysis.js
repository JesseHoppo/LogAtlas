// Post-extraction analysis

import { emit, state } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { HINT_KEYS } from '../files/fileTypeRegistry.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
  parseFileZillaSiteManager,
} from '../transforms/credentials.js';
import {
  parseSystemInfoFile,
  parseHistoryFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
  parseAccountTokenFile,
  parseServiceArtifactFile,
  parseDownloadFile,
  parseDomainDetectFile,
  parseClipboardFile,
} from '../transforms/structured.js';
import { parseCreditCardFile } from '../transforms/cards.js';
import { isPromotionalNoiseLine, stripLeadingNoiseLines, brandingHeaderRegion } from '../transforms/shared.js';
import { parseSoftwareLines, parseProcessLines, evaluateInlineSections } from './logEvaluators.js';
import { parseWalletArtifact } from './walletArtifacts.js';
import { parseNoteArtifact, summariseNotes, classifyGrabbedFile, summariseGrabbedFiles } from './contextArtifacts.js';
import {
  canonicaliseAutofillPhone,
  classifyAutofillEntries,
  credentialColumnIndices,
  extractBaseDomain,
  baseDomainFromUrl,
  extractDomain,
  isLocalNetworkHost,
  isRankableDomain,
  isOnionHost,
  dedupeDomainKey,
  extractCountryFromFilename,
  inferBrowserFromPath,
  inferBrowserFromContent,
  isLikelyAutofillPhone,
  isPlaceholderUserName,
  isValidCountryCode,
  isLikelyCountryName,
  userNameAppearsInPath,
  parseTimestampValue,
  newestNodeModified,
  isPlausibleCaptureDate,
  resolveCaptureContext,
  setCaptureContext,
  decodeNodeCached,
  parseNodeCached,
  yieldToEventLoop,
  checkCookieValidity,
  cookieColumnMap,
  cookieDedupeKey,
  collapseSingleWrapper,
  topN,
} from '../core/shared.js';

// Rows between event-loop yields inside the heaviest per-row loops, so a
// single very large file doesn't block paint. High enough that ordinary files
// never yield.
const ROW_YIELD_INTERVAL = 5000;

// Total clipboard text the family matcher may see, across all clipboard files.
// A banner is a handful of short lines; anything larger is what the victim
// copied, and must not be able to name the stealer.
const CLIPBOARD_BRANDING_BUDGET = 1536;
import { inferServiceFromPath, serviceFromTokenType } from '../core/serviceRegistry.js';
import { classifyCookie, isLiveSessionToken } from './sessionCookies.js';
import { collectContext, fingerprintStealer } from './stealerFingerprint.js';
import { classifySiteDomain } from '../core/domainCategories.js';
import { detectNationalIds } from './structuredPii.js';
import { FIELD_PATTERNS, CLIPBOARD_LURE_PATTERNS, LIMITS } from '../core/definitions/patterns.js';
import { extractIOCs } from './iocExtraction.js';

// NUL: never present in real credential fields, so safe as a dedupe separator.
const DEDUPE_KEY_SEP = '\u0000';

const BUCKET_HINT_KEYS = [...HINT_KEYS, '_ftpCredentialHint'];

// Walk the tree once, bucketing file nodes by hint key.
function bucketHintedNodes(fileTree, rootName) {
  const buckets = Object.fromEntries(BUCKET_HINT_KEYS.map(k => [k, []]));

  function walk(node, path) {
    if (!node) return;
    for (const key of BUCKET_HINT_KEYS) {
      if (node[key]) buckets[key].push({ node, path });
    }
    if (node.children) {
      for (const child of Object.values(node.children)) {
        walk(child, path + '/' + child.name);
      }
    }
  }

  walk(fileTree, rootName);
  return buckets;
}

let readFailures = [];
function recordReadFailure(node, path) {
  readFailures.push({ path: path || node?.name || '(unknown)', reason: 'Unreadable or empty file' });
}

async function decodeNodeText(node, path, record = true) {
  const content = await loadFileContent(node);
  if (!content) { if (record) recordReadFailure(node, path); return null; }
  return decodeNodeCached(node, content);
}

// Sentinels stealers emit when no username was captured. Filtered from
// topUsernames so they don't outrank real accounts.
const PLACEHOLDER_USERNAMES = new Set(['unknown', 'unk', 'n/a', 'none', 'null', '-', '?']);

// Dumps that are bare password lists with no account context.
const RECOVERED_PASSWORD_FILE = /(?:unique[_-]?passwords|brute|all[_-]?passwords|passwords?[_-]?only|wordlist)/i;

// Recovered-password dumps from resale brands (OTTOMAN, Daisy Cloud, …) prepend
// an ASCII/FIGlet/box-drawing banner; those decorative lines must not count as
// recovered passwords. ASCII-bearing lines defer to the corpus-tuned classifier;
// lines with no ASCII alphanumerics are kept only when they are mostly letters,
// so genuine non-Latin passwords (Arabic/CJK/Thai/…) survive while pure
// box-drawing/FIGlet art is dropped.
function isRecoveredPasswordNoise(line) {
  const t = String(line || '').trim();
  if (!t) return true;
  if (/[A-Za-z0-9]/.test(t)) return isPromotionalNoiseLine(t);
  if (/[─-▟]/.test(t)) return true;
  let letters = 0;
  let nonSpace = 0;
  for (const ch of t) {
    if (/\s/.test(ch)) continue;
    nonSpace++;
    if (/\p{L}/u.test(ch)) letters++;
  }
  if (letters >= 2 && letters * 2 >= nonSpace) return false;
  // No Latin/CJK letters: keep a single dense symbol token (no internal
  // whitespace, 4-32 chars, not a repeated divider) as a plausible symbolic
  // password. Box/FIGlet art carries internal spaces, box glyphs or repeats.
  if (!/\s/.test(t) && t.length >= 4 && t.length <= 32 && !/^(.)\1*$/.test(t)) return false;
  return true;
}

function isPlaceholderTopUsername(value) {
  const v = String(value || '').trim().toLowerCase();
  return v === '' || PLACEHOLDER_USERNAMES.has(v);
}

// Dedupe key only. Lowercase emails so case variants merge; phone-shaped
// usernames collapse to their trunk-stripped suffix so `+61491570156` and
// `0491570156` key to the same account. Never used as a display value —
// numeric national-IDs / bank accounts must surface verbatim.
function usernameDedupeKey(value) {
  const v = String(value || '');
  if (v.includes('@')) return v.toLowerCase();
  if (isLikelyAutofillPhone(v)) {
    const canonical = canonicaliseAutofillPhone(v);
    if (canonical) return `+${canonical}`;
  }
  return v;
}

async function analyseCredentials(nodes) {
  if (nodes.length === 0) {
    emit('analysis:credentials', {
      fileCount: 0,
      candidateFileCount: 0,
      totalCredentials: 0,
      uniqueCredentials: 0,
      urlsWithoutCredentials: 0,
      accountsWithoutPasswords: 0,
      topDomains: [],
      localNetwork: [],
      onionCredentials: 0,
      onionDomains: [],
      nationalIds: [],
      topUsernames: [],
      recoveredPasswords: null,
      failedFiles: [],
    });
    return;
  }

  const allDomains = [];
  const localDomains = [];
  const onionDomains = new Set();
  const nationalIdHits = [];
  const allUsernames = [];
  const seen = new Set();
  const urlOnlySeen = new Set();
  const emptyPasswordSeen = new Set();
  const recordExposure = (url, user) => {
    const base = baseDomainFromUrl(url);
    if (base) {
      const host = extractDomain(url) || base;
      if (isOnionHost(host) || isOnionHost(base)) onionDomains.add(base);
      else if (isLocalNetworkHost(host) || isLocalNetworkHost(base)) localDomains.push(host);
      else allDomains.push(base);
    }
    if (user && !isPlaceholderTopUsername(user)) {
      allUsernames.push(user);
      for (const id of detectNationalIds(user)) {
        nationalIdHits.push({ type: id.type, country: id.country, last2: id.value.replace(/\D/g, '').slice(-2) });
      }
    }
  };
  const fileHashes = new Set();
  const recoveredSeen = new Set();
  let recoveredFileCount = 0;
  let recoveredTotal = 0;
  const recoveredSample = [];
  const failedFiles = [];
  let totalCredentials = 0;
  let uniqueCredentials = 0;
  let urlsWithoutCredentials = 0;
  let accountsWithoutPasswords = 0;
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await loadFileContent(node).then(c => c == null ? null : decodeNodeCached(node, c));
      if (text == null) {
        // Surface on the global read-error channel like every other analyser,
        // while keeping the local list for the credentials page's parse reasons.
        recordReadFailure(node, path);
        failedFiles.push({ path, reason: 'Unreadable or empty file' });
        continue;
      }
      const parsed = parseNodeCached(node, 'password', parsePasswordFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) {
        if (RECOVERED_PASSWORD_FILE.test(node.name || '')) {
          let any = false;
          for (const line of text.split('\n')) {
            const pass = line.trim();
            if (!pass || pass.startsWith('#') || /^[-=*#]{3,}$/.test(pass) || recoveredSeen.has(pass)) continue;
            if (isRecoveredPasswordNoise(pass)) continue;
            any = true;
            recoveredSeen.add(pass);
            recoveredTotal++;
            if (recoveredSample.length < 50) recoveredSample.push(pass);
            if (recoveredSeen.size >= LIMITS.maxRecoveredPasswords) break;
          }
          if (any) { recoveredFileCount++; continue; }
        }
        failedFiles.push({ path, reason: 'No credentials parsed' });
        continue;
      }

      const { urlIdx, userIdx, passIdx } = credentialColumnIndices(parsed.headers);

      // Passwords-only dumps (unique_passwords.txt / Brute.txt): no account
      // context, so surface them as recovered plaintext rather than dropping.
      if (passIdx >= 0 && urlIdx < 0 && userIdx < 0) {
        let any = false;
        for (const row of parsed.rows) {
          const pass = (row[passIdx] || '').trim();
          if (!pass || recoveredSeen.has(pass)) continue;
          if (isRecoveredPasswordNoise(pass)) continue;
          any = true;
          recoveredSeen.add(pass);
          recoveredTotal++;
          if (recoveredSample.length < 50) recoveredSample.push(pass);
          if (recoveredSeen.size >= LIMITS.maxRecoveredPasswords) break;
        }
        if (any) recoveredFileCount++;
        continue;
      }

      if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) {
        failedFiles.push({ path, reason: 'Missing credential columns after parsing' });
        continue;
      }

      // Skip a file whose normalised row set is identical to one already seen
      // (passwords.txt + passwords.tsv format twins).
      const fileHash = parsed.rows
        .map(r => `${(r[urlIdx] || '')}\t${(r[userIdx] || '')}\t${(r[passIdx] || '')}`)
        .sort()
        .join('\n');
      if (fileHashes.has(fileHash)) continue;
      fileHashes.add(fileHash);

      parsedCount++;

      let rowIndex = 0;
      for (const row of parsed.rows) {
        if (++rowIndex % ROW_YIELD_INTERVAL === 0) await yieldToEventLoop();
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
        const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
        const pass = passIdx >= 0 ? (row[passIdx] || '').trim() : '';

        // Rows with no captured password stay out of the credential counts:
        // named accounts and bare saved sites each get their own tally. A named
        // account still exposes the site and the username, so it feeds those.
        if (!pass) {
          if (user) {
            const acctKey = dedupeDomainKey(url) + DEDUPE_KEY_SEP + usernameDedupeKey(user);
            if (!emptyPasswordSeen.has(acctKey)) {
              emptyPasswordSeen.add(acctKey);
              accountsWithoutPasswords++;
              recordExposure(url, user);
            }
          } else if (url) {
            const urlKey = dedupeDomainKey(url);
            if (!urlOnlySeen.has(urlKey)) {
              urlOnlySeen.add(urlKey);
              urlsWithoutCredentials++;
            }
          }
          continue;
        }

        totalCredentials++;

        // Dedupe on (base domain, username, password) so the same credential
        // saved across profiles or sibling subdomains collapses to one row.
        const userKey = usernameDedupeKey(user);
        const key = dedupeDomainKey(url) + DEDUPE_KEY_SEP + userKey + DEDUPE_KEY_SEP + pass;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueCredentials++;
          recordExposure(url, user);
        }
      }
    } catch (err) {
      failedFiles.push({ path, reason: err?.message || 'Failed to read or parse file' });
    }
  }

  const nationalIdGroups = {};
  for (const hit of nationalIdHits) {
    const k = `${hit.type}${DEDUPE_KEY_SEP}${hit.country}`;
    if (!nationalIdGroups[k]) nationalIdGroups[k] = { type: hit.type, country: hit.country, count: 0 };
    nationalIdGroups[k].count++;
  }
  const nationalIds = Object.values(nationalIdGroups).sort((a, b) => b.count - a.count);

  emit('analysis:credentials', {
    fileCount: parsedCount,
    candidateFileCount: nodes.length,
    totalCredentials,
    uniqueCredentials,
    urlsWithoutCredentials,
    accountsWithoutPasswords,
    topDomains: topN(allDomains, LIMITS.topDomains),
    localNetwork: topN(localDomains, LIMITS.topDomains),
    onionCredentials: onionDomains.size,
    onionDomains: [...onionDomains],
    nationalIds,
    topUsernames: topN(allUsernames, LIMITS.topUsernames),
    recoveredPasswords: recoveredTotal > 0
      ? { fileCount: recoveredFileCount, total: recoveredTotal, unique: recoveredSeen.size, sample: recoveredSample }
      : null,
    failedFiles,
  });
}

// Cookies

async function analyseCookies(nodes, captureDate = null) {
  if (nodes.length === 0) {
    emit('analysis:cookies', {
      fileCount: 0, totalCookies: 0, uniqueDomains: 0, topDomains: [],
      totalValid: 0, totalExpired: 0, totalSession: 0, totalUnknown: 0, totalNoDomain: 0,
      sessionTokens: 0, validSessionTokens: 0,
      trackingTokens: 0, validTrackingTokens: 0,
    });
    return;
  }

  const domainStats = {};
  const cookieSeen = new Set();
  // Every counted cookie lands in exactly one bucket, whether or not it carried
  // a domain, so the buckets always add up to the total printed above them.
  const totals = { valid: 0, expired: 0, session: 0, unknown: 0 };
  let totalCookies = 0;
  let parsedCount = 0;
  let totalNoDomain = 0;
  let sessionTokens = 0;
  let validSessionTokens = 0;
  let trackingTokens = 0;
  let validTrackingTokens = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'cookie', parseCookieFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;

      const columnMap = cookieColumnMap(parsed.headers, parsed.rows[0]?.length || 0);

      let rowIndex = 0;
      for (const row of parsed.rows) {
        if (++rowIndex % ROW_YIELD_INTERVAL === 0) await yieldToEventLoop();
        const domain = (columnMap.domain >= 0 ? (row[columnMap.domain] || '') : (row[0] || '')).replace(/^\./, '').toLowerCase();
        const cookieName = columnMap.name >= 0 ? row[columnMap.name] : '';
        const expiresVal = columnMap.expires >= 0 ? row[columnMap.expires] : null;

        const dedupeKey = cookieDedupeKey(row, columnMap);
        if (cookieSeen.has(dedupeKey)) continue;
        cookieSeen.add(dedupeKey);

        totalCookies++;

        const validity = checkCookieValidity(expiresVal, captureDate);
        const bucket = validity.status === 'valid' || validity.status === 'expired' || validity.status === 'session'
          ? validity.status
          : 'unknown';
        totals[bucket]++;

        if (!domain) { totalNoDomain++; continue; }

        if (!domainStats[domain]) {
          domainStats[domain] = { total: 0, valid: 0, expired: 0, session: 0, unknown: 0 };
        }
        domainStats[domain].total++;
        domainStats[domain][bucket]++;

        const sessionType = classifyCookie(cookieName, domain);
        if (sessionType === 'auth' || sessionType === 'session') {
          sessionTokens++;
          if (isLiveSessionToken({ sessionType, validity })) validSessionTokens++;
        } else if (sessionType === 'tracking') {
          trackingTokens++;
          if (isLiveSessionToken({ sessionType: 'session', validity })) validTrackingTokens++;
        }
      }
    } catch {
      // skip
    }
  }

  const uniqueDomains = Object.keys(domainStats).length;

  // Roll per-host stats up to eTLD+1 for the headline list; per-host detail
  // stays available on the cookies page.
  const baseStats = {};
  for (const [host, stats] of Object.entries(domainStats)) {
    const base = extractBaseDomain(host) || host;
    if (!isRankableDomain(base)) continue;
    if (!baseStats[base]) {
      baseStats[base] = { total: 0, valid: 0, expired: 0, session: 0, unknown: 0 };
    }
    baseStats[base].total += stats.total;
    baseStats[base].valid += stats.valid;
    baseStats[base].expired += stats.expired;
    baseStats[base].session += stats.session;
    baseStats[base].unknown += stats.unknown;
  }

  const topDomains = Object.entries(baseStats)
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, LIMITS.topCookieDomains)
    .map(([domain, stats]) => ({
      value: domain,
      count: stats.total,
      valid: stats.valid,
      expired: stats.expired,
      session: stats.session,
      unknown: stats.unknown,
    }));

  emit('analysis:cookies', {
    fileCount: parsedCount,
    totalCookies,
    uniqueDomains,
    totalValid: totals.valid,
    totalExpired: totals.expired,
    totalSession: totals.session,
    totalUnknown: totals.unknown,
    totalNoDomain,
    topDomains,
    sessionTokens,
    validSessionTokens,
    trackingTokens,
    validTrackingTokens,
  });
}

// History

// Returns the newest plausible visit date, the last-resort capture evidence.
async function analyseHistory(nodes) {
  if (nodes.length === 0) {
    emit('analysis:history', null);
    return null;
  }

  const entries = [];
  const domains = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'history', parseHistoryFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const titleIdx = parsed.headers.findIndex(h => /^(title|page.?title)$/i.test(h));
      const visitsIdx = parsed.headers.findIndex(h => /^(visit.?count|visits?|count)$/i.test(h));
      const lastIdx = parsed.headers.findIndex(h => /^(last.?visit|date|time|timestamp)$/i.test(h));

      let rowIndex = 0;
      for (const row of parsed.rows) {
        if (++rowIndex % ROW_YIELD_INTERVAL === 0) await yieldToEventLoop();
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
        if (!url) continue;
        const title = titleIdx >= 0 ? (row[titleIdx] || '').trim() : '';
        const visitCount = visitsIdx >= 0 ? (parseInt(row[visitsIdx], 10) || 1) : 1;
        const lastVisit = lastIdx >= 0 ? (row[lastIdx] || '').trim() : '';
        const lastVisitDate = parseTimestampValue(lastVisit);
        const domain = baseDomainFromUrl(url);
        if (domain && isRankableDomain(domain)) domains.push(domain);
        entries.push({ url, title, visitCount, lastVisit, lastVisitDate });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:history', null);
    return null;
  }

  const datedEntries = entries
    .filter(entry => entry.lastVisitDate)
    .sort((a, b) => b.lastVisitDate - a.lastVisitDate);
  const mostRecent = datedEntries.slice(0, 10).map(entry => ({
    url: entry.url,
    title: entry.title,
    lastVisit: entry.lastVisit,
    lastVisitDate: entry.lastVisitDate ? entry.lastVisitDate.toISOString() : null,
  }));
  const latestVisit = datedEntries[0]?.lastVisitDate || null;
  // The reported latest visit is whatever the log says, mis-parsed outliers
  // included. Capture evidence takes the newest visit that could actually be
  // one, so a single far-future row doesn't discard the whole fallback.
  const latestPlausibleVisit = datedEntries.find(entry => isPlausibleCaptureDate(entry.lastVisitDate))?.lastVisitDate || null;

  emit('analysis:history', {
    fileCount,
    totalEntries: entries.length,
    uniqueDomains: new Set(domains).size,
    topDomains: topN(domains, LIMITS.topDomains),
    mostRecent,
    latestVisitDate: latestVisit ? latestVisit.toISOString() : null,
  });

  return latestPlausibleVisit;
}

// System info

// Returns the merged sysinfo entries, which carry the capture timestamp.
async function analyseSystemInfo(nodes, rootZipName = '') {
  if (nodes.length === 0) {
    emit('analysis:sysinfo', null);
    extractInlineSections('');
    return null;
  }

  const merged = {};
  const sourceFiles = [];
  const decoded = [];

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      // Environment.txt is an env-var dump (OS=Windows_NT, etc.) — keep it out
      // of the system profile and IOC scan so it can't shadow the real OS.
      if (/environment/i.test(node.name || '')) continue;
      decoded.push(text);
      const parsed = parseSystemInfoFile(text, node.name);
      if (!parsed || !parsed.entries) continue;
      node._parsedSysinfo = { entries: parsed.entries, text };

      for (const [key, value] of Object.entries(parsed.entries)) {
        if (value && !merged[key]) {
          merged[key] = value;
        }
      }
      sourceFiles.push(node.name);
    } catch {
      // skip
    }
  }

  if (Object.keys(merged).length === 0) {
    emit('analysis:sysinfo', null);
    extractInlineSections('');
    return null;
  }

  const identityNotes = sanitiseIdentityEntries(merged, rootZipName);
  const combinedText = decoded.length > 0 ? decoded.join('\n') + '\n' : '';
  const iocs = extractIOCs(merged, combinedText) || [];
  const fields = structuredFieldsFromIocs(iocs);

  emit('analysis:sysinfo', { entries: merged, fields, sourceFiles, sysinfoText: combinedText, identityNotes, iocs });

  extractInlineSections(combinedText);

  return merged;
}

const IOC_FIELD_KEYS = {
  'IP Address': 'ip',
  'Country': 'country',
  'City': 'city',
  'Computer Name': 'computerName',
  'User Name': 'userName',
  'OS': 'os',
  'HWID': 'hwid',
  'Machine ID': 'machineId',
  'Timezone': 'timezone',
  'Language': 'language',
  'Log Date': 'captureDate',
};

function structuredFieldsFromIocs(iocs) {
  const fields = {};
  for (const ioc of iocs) {
    const key = IOC_FIELD_KEYS[ioc.label];
    if (!key || fields[key]) continue;
    if (key === 'captureDate') {
      const dt = parseTimestampValue(ioc.value);
      fields[key] = dt ? dt.toISOString() : ioc.value;
    } else {
      fields[key] = ioc.value;
    }
  }
  return fields;
}

// Strip placeholder / OEM / OS-name garbage from identity-bearing sysinfo
// fields and substitute fallbacks where we can. Every override is logged to
// `identityNotes` so the UI can still surface the stealer's original value.
function sanitiseIdentityEntries(entries, rootZipName) {
  const notes = [];
  const valueEntries = Object.values(entries).map(value => ({ value }));

  for (const key of ['User Name', 'UserName', 'User', 'username']) {
    if (entries[key] && isPlaceholderUserName(entries[key])
        && !userNameAppearsInPath(entries[key], valueEntries)) {
      notes.push({ field: key, rawValue: entries[key], reason: 'placeholder/oem/os-name' });
      entries[key] = '';
    }
  }

  for (const key of ['Country', 'country']) {
    const raw = entries[key];
    if (!raw || isValidCountryCode(raw) || isLikelyCountryName(raw)) continue;
    const fromGeo = entries.GEO || entries.geo;
    if (fromGeo && (isValidCountryCode(fromGeo) || isLikelyCountryName(fromGeo))) {
      notes.push({ field: key, rawValue: raw, reason: 'invalid-code', resolvedTo: fromGeo, resolvedSource: 'geo' });
      entries[key] = fromGeo;
      continue;
    }
    const fromFilename = extractCountryFromFilename(rootZipName);
    if (fromFilename) {
      notes.push({ field: key, rawValue: raw, reason: 'invalid-code', resolvedTo: fromFilename, resolvedSource: 'filename' });
      entries[key] = fromFilename;
    } else {
      notes.push({ field: key, rawValue: raw, reason: 'invalid-code' });
      entries[key] = '';
    }
  }

  return notes;
}

function extractInlineSections(text) {
  // Both slots publish even when empty: a reanalyse whose sysinfo has lost a
  // section must clear the rows the previous run left behind.
  const { softwareEntries, processEntries } = evaluateInlineSections(text);

  emit('analysis:software', { fileCount: softwareEntries.length ? 1 : 0, entries: softwareEntries, totalCount: softwareEntries.length, inline: true });

  const uniqueCount = new Set(processEntries.map(e => (e.name || e.commandLine || '').toLowerCase())).size;
  emit('analysis:processList', { fileCount: processEntries.length ? 1 : 0, entries: processEntries, totalCount: processEntries.length, uniqueCount, inline: true });
}

// Clipboard

function detectClipboardLure(text) {
  const s = String(text || '');
  if (!s) return null;
  for (const { category, rx } of CLIPBOARD_LURE_PATTERNS) {
    rx.lastIndex = 0;
    if (rx.test(s.trim())) return category;
  }
  return null;
}

async function analyseClipboard(nodes) {
  if (nodes.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  const entries = [];
  const lureCounts = {};
  let fileCount = 0;
  let urlCount = 0;
  let commandCount = 0;
  let pathCount = 0;
  let lureCount = 0;
  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'clipboard', parseClipboardFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const type = (row[0] || 'Text').trim() || 'Text';
        const entryText = (row[1] || '').trim();
        const urls = (row[2] || '').trim() ? row[2].trim().split(/\s+/).filter(Boolean) : [];
        if (!entryText) continue;

        if (urls.length > 0) urlCount += urls.length;
        if (type === 'Command') commandCount++;
        if (type === 'Path') pathCount++;
        const lure = detectClipboardLure(entryText);
        if (lure) { lureCount++; lureCounts[lure] = (lureCounts[lure] || 0) + 1; }
        entries.push({ type, text: entryText, urls, lure });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  emit('analysis:clipboard', { entries, fileCount, urlCount, commandCount, pathCount, lureCount, lureCategories: lureCounts });
}

// Autofill

async function analyseAutofills(nodes) {
  if (nodes.length === 0) {
    emit('analysis:autofill', null);
    return;
  }

  const entries = [];
  const files = [];
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'autofill', parseAutofillFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      const fileEntries = [];
      let rowIndex = 0;
      for (const row of parsed.rows) {
        if (++rowIndex % ROW_YIELD_INTERVAL === 0) await yieldToEventLoop();
        const name = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        if (!name || !value) continue;
        const entry = {
          name,
          value,
          sourceFile: path || node.name || '',
        };
        entries.push(entry);
        fileEntries.push(entry);
      }

      if (fileEntries.length > 0) {
        parsedCount++;
        files.push({
          path: path || node.name || '',
          entryCount: fileEntries.length,
          sampleEntries: fileEntries.slice(0, 10).map((entry) => ({
            name: entry.name,
            value: entry.value,
          })),
        });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:autofill', null);
    return;
  }

  const highlights = classifyAutofillEntries(entries, LIMITS.maxAutofillOther);

  emit('analysis:autofill', {
    fileCount: parsedCount,
    totalEntries: entries.length,
    entries,
    files,
    emails: highlights.emails,
    phones: highlights.phones,
    names: highlights.names,
    addresses: highlights.addresses,
    other: highlights.other,
    otherAll: highlights.otherAll,
    otherTotal: highlights.otherTotal,
    otherTruncated: highlights.otherTruncated,
    categoryCounts: {
      emails: highlights.emails.length,
      phones: highlights.phones.length,
      names: highlights.names.length,
      addresses: highlights.addresses.length,
      other: highlights.otherTotal,
    },
  });
}

async function analyseNotes(nodes) {
  if (nodes.length === 0) {
    emit('analysis:notes', null);
    return;
  }

  const entries = [];

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const entry = parseNoteArtifact(text, node.name || '', path, node.lastModified);
      if (entry) entries.push(entry);
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:notes', null);
    return;
  }

  emit('analysis:notes', {
    ...summariseNotes(entries),
    entries,
  });
}

// Domain detect

async function analyseDomainDetect(nodes, credCookieNodes = []) {
  const categories = {};
  const entries = [];
  let fileCount = 0;
  let totalHits = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'domainDetect', parseDomainDetectFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const section = (row[0] || 'General').trim() || 'General';
        const label = (row[1] || '').trim();
        const target = (row[2] || '').trim();
        const count = Math.max(parseInt(row[3], 10) || 1, 1);
        if (!target) continue;

        const cat = classifySiteDomain(target);
        const key = cat.primaryLabel || section;
        if (!categories[key]) categories[key] = [];
        categories[key].push({ domain: target, count, label, section, base: cat.base, ourCategory: cat.primaryLabel });
        entries.push({ section, label, target, count, base: cat.base, ourCategory: cat.primaryLabel });
        totalHits += count;
      }
    } catch {
      // skip
    }
  }

  if (Object.keys(categories).length > 0) {
    emit('analysis:domainDetect', { fileCount, totalHits, categories, entries });
    return;
  }

  // No domain-detect file shipped: synthesise an equivalent by classifying
  // the credential/cookie hosts so the same panel still renders.
  const synth = await synthesiseDomainDetect(credCookieNodes);
  emit('analysis:domainDetect', synth);
}

async function synthesiseDomainDetect(nodes) {
  if (!nodes || nodes.length === 0) return null;
  const counts = new Map();
  for (const { node, path, kind } of nodes) {
    try {
      const text = await decodeNodeText(node, path, false);
      if (text == null) continue;
      const parsed = kind === 'cookie'
        ? parseNodeCached(node, 'cookie', parseCookieFile, text, node._parseConfig || null)
        : parseNodeCached(node, 'password', parsePasswordFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      let hosts = [];
      if (kind === 'cookie') {
        const domainIdx = cookieColumnMap(parsed.headers, parsed.rows[0]?.length || 0).domain;
        hosts = parsed.rows.map(r => (domainIdx >= 0 ? (r[domainIdx] || '') : (r[0] || '')).replace(/^\./, ''));
      } else {
        const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
        if (urlIdx < 0) continue;
        hosts = parsed.rows.map(r => extractDomain(r[urlIdx] || ''));
      }
      for (const host of hosts) {
        if (!host) continue;
        const cat = classifySiteDomain(host);
        if (!cat.primaryLabel) continue;
        const base = cat.base || host;
        const k = `${cat.primaryLabel}${DEDUPE_KEY_SEP}${base}`;
        if (!counts.has(k)) counts.set(k, { ourCategory: cat.primaryLabel, base, count: 0 });
        counts.get(k).count++;
      }
    } catch {
      // skip
    }
  }

  if (counts.size === 0) return null;
  const categories = {};
  const entries = [];
  let totalHits = 0;
  for (const { ourCategory, base, count } of counts.values()) {
    if (!categories[ourCategory]) categories[ourCategory] = [];
    categories[ourCategory].push({ domain: base, count, label: '', section: ourCategory, base, ourCategory });
    entries.push({ section: ourCategory, label: '', target: base, count, base, ourCategory });
    totalHits += count;
  }
  return { fileCount: 0, totalHits, categories, entries, synthesized: true };
}

async function analyseCreditCards(nodes) {
  if (nodes.length === 0) {
    emit('analysis:creditCards', null);
    return;
  }

  const last4 = new Set();
  let fileCount = 0;
  let totalCards = 0;
  let withHolder = 0;
  let withCvc = 0;
  let withExpiry = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'card', parseCreditCardFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const cardNumber = (row[0] || '').trim();
        const nameOnCard = (row[1] || '').trim();
        const cvc = (row[2] || '').trim();
        const expiration = (row[3] || '').trim();
        const panDigits = cardNumber.replace(/\D/g, '');
        const validPan = panDigits.length >= 12 && panDigits.length <= 19;
        const hasExpiry = /\b(0?[1-9]|1[0-2])\s*[\/-]\s*(\d{2}|\d{4})\b/.test(expiration);
        if (!validPan && !nameOnCard && !hasExpiry && !cvc) continue;
        totalCards++;
        if (validPan) last4.add(panDigits.slice(-4));
        if (nameOnCard) withHolder++;
        if (cvc) withCvc++;
        if (hasExpiry) withExpiry++;
      }
    } catch {
      // skip
    }
  }

  if (totalCards === 0) {
    emit('analysis:creditCards', null);
    return;
  }

  emit('analysis:creditCards', {
    fileCount,
    totalCards,
    withHolder,
    withCvc,
    withExpiry,
    uniqueLast4: last4.size,
  });
}

async function analyseBookmarks(nodes) {
  if (nodes.length === 0) {
    emit('analysis:bookmarks', null);
    return;
  }

  const allDomains = [];
  const browserCounts = [];
  let fileCount = 0;
  let totalBookmarks = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'bookmark', parseBookmarkFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalBookmarks += parsed.rows.length;

      const browser = inferBrowserFromPath(path || node.name);
      if (browser) browserCounts.push(browser);

      for (const row of parsed.rows) {
        const url = (row[0] || '').trim();
        if (!url) continue;
        const base = baseDomainFromUrl(url);
        if (base && isRankableDomain(base)) allDomains.push(base);
      }
    } catch {
      // skip
    }
  }

  if (totalBookmarks === 0) {
    emit('analysis:bookmarks', null);
    return;
  }

  emit('analysis:bookmarks', {
    fileCount,
    totalBookmarks,
    uniqueDomains: new Set(allDomains).size,
    topDomains: topN(allDomains, LIMITS.topDomains),
    browsers: topN(browserCounts, 10),
  });
}

async function analyseBrowserMetadata(nodes) {
  if (nodes.length === 0) {
    emit('analysis:browserMetadata', null);
    return;
  }

  const categories = {};
  const browsers = [];
  let fileCount = 0;
  let totalEntries = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'browserMetadata', parseBrowserMetadataFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      const browser = inferBrowserFromPath(path || node.name) || inferBrowserFromContent(text) || 'Unknown browser';
      browsers.push(browser);

      const category = /\/path\//i.test(path) ? 'Path'
        : /\/ua\//i.test(path) ? 'User Agent'
        : /\/version\//i.test(path) ? 'Version'
        : /debug\.txt$/i.test(node.name) ? 'Debug'
        : 'Metadata';
      categories[category] = (categories[category] || 0) + parsed.rows.length;
    } catch {
      // skip
    }
  }

  if (totalEntries === 0) {
    emit('analysis:browserMetadata', null);
    return;
  }

  emit('analysis:browserMetadata', {
    fileCount,
    totalEntries,
    categories,
    browsers: topN(browsers, 10),
  });
}

// Restore-token files hold bare opaque base64url blobs with no key:value
// structure, so the keyed parser returns nothing. Recover them here.
function parseBareTokenFile(text) {
  const lines = stripLeadingNoiseLines(text).split('\n')
    .map(line => line.trim())
    .filter(line => line && !isPromotionalNoiseLine(line));
  if (lines.length === 0) return null;

  const rows = [];
  for (const line of lines) {
    if (!/^[A-Za-z0-9_-]{40,}$/.test(line)) return null;
    rows.push(['Restore Token', line, '', '']);
  }

  return rows.length > 0 ? { rows } : null;
}

async function analyseAccountTokens(nodes) {
  if (nodes.length === 0) {
    emit('analysis:accountTokens', null);
    return;
  }

  const services = [];
  const types = [];
  const accounts = new Set();
  let fileCount = 0;
  let totalEntries = 0;
  let withValue = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const hint = path || node.name;
      const parsed = parseNodeCached(node, 'token', parseAccountTokenFile, text, hint) || parseBareTokenFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      const pathService = inferServiceFromPath(path || node.name);

      for (const row of parsed.rows) {
        const type = (row[0] || 'Token').trim();
        const value = (row[1] || '').trim();
        const accountId = (row[2] || '').trim();
        const service = pathService || serviceFromTokenType(type) || 'Unknown';
        services.push(service);
        if (type) types.push(type);
        if (value) withValue++;
        if (accountId) accounts.add(`${service}:${accountId}`);
      }
    } catch {
      // skip
    }
  }

  if (totalEntries === 0) {
    emit('analysis:accountTokens', null);
    return;
  }

  emit('analysis:accountTokens', {
    fileCount,
    totalEntries,
    withValue,
    uniqueAccounts: accounts.size,
    services: topN(services, 10),
    tokenTypes: topN(types, 10),
  });
}

async function analyseServiceArtifacts(nodes, ftpNodes = []) {
  if (nodes.length === 0 && ftpNodes.length === 0) {
    emit('analysis:serviceArtifacts', null);
    return;
  }

  const services = [];
  const keys = [];
  let fileCount = 0;
  let totalEntries = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'service', parseServiceArtifactFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';
      services.push(service);
      for (const row of parsed.rows) {
        const key = (row[1] || '').trim();
        if (key) keys.push(key);
      }
    } catch {
      // skip
    }
  }

  for (const { node, path } of ftpNodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'filezilla', parseFileZillaSiteManager, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      for (const [url, user, password] of parsed.rows) {
        services.push('FileZilla');
        const host = String(url || '').replace(/^[a-z]+:\/\//i, '');
        const label = [host, user].filter(Boolean).join(' / ');
        if (label) keys.push(password ? `${label} (password recovered)` : label);
      }
    } catch {
      // skip
    }
  }

  if (totalEntries === 0) {
    emit('analysis:serviceArtifacts', null);
    return;
  }

  emit('analysis:serviceArtifacts', {
    fileCount,
    totalEntries,
    services: topN(services, 10),
    topKeys: topN(keys, 10),
  });
}

async function analyseWalletArtifacts(nodes) {
  if (nodes.length === 0) {
    emit('analysis:wallets', null);
    return;
  }

  const entries = [];
  const services = [];
  let signalHits = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) { recordReadFailure(node, path); continue; }
      // Keyed on the source path, as the assets page keys it: the path lands in
      // the parsed entry, and the two sides walk different roots, so a shared
      // entry built from the other side's path would relabel this row's source.
      const entry = parseNodeCached(node, 'wallet',
        (bytes, sourcePath) => parseWalletArtifact(bytes, node.name || '', sourcePath),
        content, path || node.name || '');
      if (!entry) continue;
      entries.push(entry);
      services.push(entry.service || 'Unknown');
      signalHits += (entry.emailCount || 0) + (entry.addressCount || 0) + (entry.tokenCount || 0) + (entry.seedHints || 0);
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:wallets', null);
    return;
  }

  emit('analysis:wallets', {
    fileCount: entries.length,
    totalEntries: entries.length,
    services: topN(services, 10),
    withSeedHints: entries.filter(entry => entry.seedHints > 0).length,
    withTokenSignals: entries.filter(entry => entry.tokenCount > 0).length,
    signalHits,
  });
}

// Download history

async function analyseDownloads(nodes) {
  if (nodes.length === 0) {
    emit('analysis:downloads', null);
    return;
  }

  const allDomains = [];
  let totalDownloads = 0;
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const parsed = parseNodeCached(node, 'download', parseDownloadFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      totalDownloads += parsed.rows.length;

      const urlIdx = parsed.headers.findIndex(h => /url/i.test(h));
      for (const row of parsed.rows) {
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : (row[1] || '').trim();
        if (!url) continue;
        const base = baseDomainFromUrl(url);
        if (base && isRankableDomain(base)) allDomains.push(base);
      }
    } catch {
      // skip
    }
  }

  if (totalDownloads === 0) {
    emit('analysis:downloads', null);
    return;
  }

  emit('analysis:downloads', {
    fileCount: parsedCount,
    totalDownloads,
    topDomains: topN(allDomains, LIMITS.topDomains),
  });
}

async function analyseGrabbedFiles(nodes) {
  if (nodes.length === 0) {
    emit('analysis:grabbedFiles', null);
    return;
  }

  const entries = [];

  for (const { node, path } of nodes) {
    const entry = classifyGrabbedFile(path, node.size || 0, node.lastModified);
    if (entry) entries.push(entry);
  }

  if (entries.length === 0) {
    emit('analysis:grabbedFiles', null);
    return;
  }

  emit('analysis:grabbedFiles', {
    ...summariseGrabbedFiles(entries),
    entries,
  });
}

// Screenshot detection

function findScreenshot(nodes) {
  if (nodes.length === 0) {
    emit('analysis:screenshot', null);
    return;
  }
  emit('analysis:screenshot', { node: nodes[0].node, path: nodes[0].path, entries: nodes });
}

// Stealer fingerprinting

async function runFingerprint(fileTree, rootName) {
  const ctx = { dirs: [], files: [], sysinfoNodes: [], sysinfoCandidates: [], creditsNodes: [], creditsText: null, clipboardNodes: [], clipboardText: null, passwordNode: null, passwordHeaderText: null };

  // If the archive has a single top-level dir, start inside it so paths match signatures
  let startNode = fileTree;
  if (fileTree.children) {
    const children = Object.values(fileTree.children);
    if (children.length === 1 && children[0].type === 'directory') {
      startNode = children[0];
    }
  }
  collectContext(startNode, '', ctx);

  if (ctx.sysinfoNodes.length > 0) {
    const allTexts = [];
    for (const node of ctx.sysinfoNodes) {
      // Environment.txt dumps OS=Windows_NT; excluded from the merged profile
      // too, so it must not skew the fingerprint's OS-class veto either.
      if (/environment/i.test(node.name || '')) continue;
      try {
        let cached = node._parsedSysinfo;
        if (!cached) {
          const text = await decodeNodeText(node, null, false);
          if (text == null) continue;
          const parsed = parseSystemInfoFile(text, node.name);
          cached = { entries: parsed && parsed.entries ? parsed.entries : {}, text };
          node._parsedSysinfo = cached;
        }
        allTexts.push(cached.text);
        ctx.sysinfoCandidates.push({
          sysinfoFilename: node.name,
          sysinfoText: cached.text,
          sysinfoKeys: Object.keys(cached.entries),
        });
      } catch {
        // skip unreadable sysinfo candidates
      }
    }
    if (allTexts.length > 0) ctx.combinedSysinfoText = allTexts.join('\n');
  }

  // Load credits/copyright files for ASCII banner detection
  if (ctx.creditsNodes.length > 0) {
    const creditsTexts = [];
    for (const node of ctx.creditsNodes) {
      try {
        const text = await decodeNodeText(node, null, false);
        if (text != null) creditsTexts.push(text);
      } catch {
        // skip
      }
    }
    if (creditsTexts.length > 0) {
      ctx.creditsText = creditsTexts.join('\n');
    }
  }

  // Clipboard text — some families paste a self-id banner (e.g. Raccoon
  // OTTOMAN) as their calling card. There is no record shape to cut on here, so
  // a tight cap is the only defence: branding is stamped at the top.
  if (ctx.clipboardNodes.length > 0) {
    const clipTexts = [];
    let budget = CLIPBOARD_BRANDING_BUDGET;
    for (const node of ctx.clipboardNodes) {
      if (budget <= 0) break;
      try {
        const text = await decodeNodeText(node, null, false);
        if (text == null) continue;
        const slice = brandingHeaderRegion(text, Math.min(budget, 512), 12);
        if (!slice) continue;
        clipTexts.push(slice);
        budget -= slice.length;
      } catch {
        // skip
      }
    }
    if (clipTexts.length > 0) {
      ctx.clipboardText = clipTexts.join('\n');
    }
  }

  // Password file header (some stealers embed branding here)
  if (ctx.passwordNode) {
    try {
      const text = await decodeNodeText(ctx.passwordNode, null, false);
      if (text != null) ctx.passwordHeaderText = brandingHeaderRegion(text);
    } catch {
      // skip
    }
  }

  // Cookie/autofill headers — resale brands (e.g. OTTOMAN) stamp a self-id
  // banner at the top of every exported browser-data file.
  if (ctx.browserHeaderNodes && ctx.browserHeaderNodes.length > 0) {
    const headerTexts = [];
    let budget = 8192;
    for (const node of ctx.browserHeaderNodes) {
      if (budget <= 0) break;
      try {
        const text = await decodeNodeText(node, null, false);
        if (text == null) continue;
        const slice = brandingHeaderRegion(text);
        if (!slice) continue;
        headerTexts.push(slice);
        budget -= slice.length;
      } catch {
        // skip
      }
    }
    if (headerTexts.length > 0) ctx.browserHeaderText = headerTexts.join('\n');
  }

  const result = fingerprintStealer(ctx);
  emit('analysis:fingerprint', result);
}

// Installed software

async function analyseSoftware(nodes) {
  if (nodes.length === 0) {
    emit('analysis:software', null);
    return;
  }

  const entries = [];
  const seen = new Set();
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node, path);
      if (text == null) continue;
      const before = entries.length;
      // Strip a leading ASCII banner so it doesn't leak in as a fake app.
      parseSoftwareLines(stripLeadingNoiseLines(text).split('\n'), entries, seen);
      if (entries.length > before) parsedCount++;
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:software', null);
    return;
  }

  emit('analysis:software', { fileCount: parsedCount, entries, totalCount: entries.length });
}

// Process list

async function analyseProcessList(nodes) {
  if (nodes.length === 0) {
    emit('analysis:processList', null);
    return;
  }

  const entryMap = new Map();
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const decoded = await decodeNodeText(node, path);
      if (decoded == null) continue;
      const before = entryMap.size;
      parseProcessLines(stripLeadingNoiseLines(decoded).split('\n'), entryMap);
      if (entryMap.size > before) parsedCount++;
    } catch {
      // skip
    }
  }

  const entries = [...entryMap.values()];

  if (entries.length === 0) {
    emit('analysis:processList', null);
    return;
  }

  const uniqueCount = new Set(entries.map(e => (e.name || e.commandLine || '').toLowerCase())).size;
  emit('analysis:processList', { fileCount: parsedCount, entries, totalCount: entries.length, uniqueCount });
}

// Resolve the case's capture instant once, here, where the collapsed root name
// is known, and publish it so cookie validity, the dashboard and the pages all
// judge expiry against the same moment with the same provenance.
function publishCaptureContext({ sysinfoEntries, historyMaxDate, archiveNames, nodes }) {
  const context = resolveCaptureContext({
    sysinfoEntries,
    archiveNames,
    sourceLastModified: [newestNodeModified(nodes), state.sourceFile?.lastModified || null],
    historyMaxDate,
  });
  setCaptureContext(context);
  emit('analysis:capture', {
    date: context.date,
    iso: context.date ? context.date.toISOString() : null,
    source: context.source,
    detail: context.detail,
  });
  return context;
}

function reportRejections(results) {
  return results.map((result) => {
    if (result.status === 'rejected') {
      console.error('Analysis task failed:', result.reason);
      return null;
    }
    return result.value;
  });
}

async function runAnalysis(fileTree, rootName) {
  const root = collapseSingleWrapper(fileTree) || fileTree;
  const treeRootName = root === fileTree ? rootName : (root.name || rootName);
  const buckets = bucketHintedNodes(root, treeRootName);
  readFailures = [];

  findScreenshot(buckets._screenshotHint);

  const credCookieNodes = [
    ...buckets._passwordFileHint.map(n => ({ ...n, kind: 'password' })),
    ...buckets._cookieFileHint.map(n => ({ ...n, kind: 'cookie' })),
  ];

  // Sysinfo and history hold the capture evidence, so they run before the
  // analysers whose numbers depend on the capture instant. Their parses are
  // cached on the nodes, so nothing is read or parsed twice.
  const [sysinfoEntries, historyMaxDate] = reportRejections(await Promise.allSettled([
    analyseSystemInfo(buckets._sysInfoHint, treeRootName),
    analyseHistory(buckets._historyHint),
  ]));

  const capture = publishCaptureContext({
    sysinfoEntries,
    historyMaxDate,
    archiveNames: [treeRootName, rootName, state.rootZipName, state.sourceFile?.name],
    nodes: Object.values(buckets).flat(),
  });

  const tasks = [
    analyseCredentials(buckets._passwordFileHint),
    analyseCookies(buckets._cookieFileHint, capture.date),
    analyseAutofills(buckets._autofillHint),
    analyseNotes(buckets._notesHint),
    analyseBookmarks(buckets._bookmarkHint),
    analyseBrowserMetadata(buckets._browserMetadataHint),
    analyseAccountTokens(buckets._accountTokenHint),
    analyseServiceArtifacts(buckets._serviceArtifactHint, buckets._ftpCredentialHint),
    analyseWalletArtifacts(buckets._cryptoWalletHint),
    analyseDownloads(buckets._downloadHint),
    analyseCreditCards(buckets._creditCardHint),
    analyseDomainDetect(buckets._domainDetectHint, credCookieNodes),
    analyseSoftware(buckets._softwareFileHint),
    analyseProcessList(buckets._processListHint),
    analyseClipboard(buckets._clipboardHint),
    analyseGrabbedFiles(buckets._grabbedFileHint),
    runFingerprint(root, treeRootName),
  ];

  reportRejections(await Promise.allSettled(tasks));

  const seen = new Set();
  const dedupedFailures = readFailures.filter(f => { if (seen.has(f.path)) return false; seen.add(f.path); return true; });
  emit('analysis:readErrors', { failedFiles: dedupedFailures });
  emit('analysis:complete');
}

export { runAnalysis };
