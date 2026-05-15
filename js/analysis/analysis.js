// Post-extraction analysis

import { emit } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { HINT_KEYS } from '../files/fileTypeRegistry.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
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
import { isPromotionalNoiseLine, stripLeadingNoiseLines } from '../transforms/shared.js';
import { parseWalletArtifact } from './walletArtifacts.js';
import { parseNoteArtifact, summariseNotes, classifyGrabbedFile, summariseGrabbedFiles } from './contextArtifacts.js';
import {
  SHARED_TEXT_DECODER,
  classifyAutofillEntries,
  extractDomain,
  extractBaseDomain,
  inferBrowserFromPath,
  inferServiceFromPath,
  normaliseTimeZone,
  parseTimestampValue,
  checkCookieValidity,
  topN,
} from '../core/shared.js';
import { classifyCookie } from './sessionCookies.js';
import { collectContext, fingerprintStealer } from './stealerFingerprint.js';
import { FIELD_PATTERNS, IOC_KEY_MAP, CONTENT_IOC_PATTERNS, LIMITS } from '../core/definitions/patterns.js';

// NUL: never present in real credential fields, so safe as a dedupe separator.
const DEDUPE_KEY_SEP = '\u0000';

// Walk the tree once, bucketing file nodes by hint key.
function bucketHintedNodes(fileTree, rootName) {
  const buckets = Object.fromEntries(HINT_KEYS.map(k => [k, []]));

  function walk(node, path) {
    if (!node) return;
    for (const key of HINT_KEYS) {
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

async function decodeNodeText(node) {
  const content = await loadFileContent(node);
  if (!content) return null;
  return SHARED_TEXT_DECODER.decode(content);
}

// Credentials

// Emails are case-insensitive per RFC; lowercase them so case variants merge.
// Non-email usernames keep their original casing.
function normaliseUsername(value) {
  const v = String(value || '');
  return v.includes('@') ? v.toLowerCase() : v;
}

async function analyseCredentials(nodes) {
  if (nodes.length === 0) {
    emit('analysis:credentials', {
      fileCount: 0,
      candidateFileCount: 0,
      totalCredentials: 0,
      uniqueCredentials: 0,
      urlsWithoutCredentials: 0,
      topDomains: [],
      topUsernames: [],
      failedFiles: [],
    });
    return;
  }

  const allDomains = [];
  const allUsernames = [];
  const seen = new Set();
  const failedFiles = [];
  let totalCredentials = 0;
  let uniqueCredentials = 0;
  let urlsWithoutCredentials = 0;
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) {
        failedFiles.push({ path, reason: 'Unreadable or empty file' });
        continue;
      }
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) {
        failedFiles.push({ path, reason: 'No credentials parsed' });
        continue;
      }

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
      const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

      if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) {
        failedFiles.push({ path, reason: 'Missing credential columns after parsing' });
        continue;
      }

      parsedCount++;

      for (const row of parsed.rows) {
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
        const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
        const pass = passIdx >= 0 ? (row[passIdx] || '').trim() : '';

        // Chrome's saved-URL index leaks rows with no credentials into Vidar's
        // password dump. Bucket them separately so they don't inflate counts.
        if (!user && !pass) {
          urlsWithoutCredentials++;
          continue;
        }

        totalCredentials++;

        // Dedupe on (base domain, username, password) so the same credential
        // saved across profiles or under sibling subdomains collapses to one row.
        const domainPart = url
          ? (extractBaseDomain(extractDomain(url) || '') || extractDomain(url) || url).toLowerCase()
          : '';
        const userPart = normaliseUsername(user);
        const key = domainPart + DEDUPE_KEY_SEP + userPart + DEDUPE_KEY_SEP + pass;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueCredentials++;
          if (url) allDomains.push(extractDomain(url));
          if (user) allUsernames.push(userPart);
        }
      }
    } catch (err) {
      failedFiles.push({ path, reason: err?.message || 'Failed to read or parse file' });
    }
  }

  emit('analysis:credentials', {
    fileCount: parsedCount,
    candidateFileCount: nodes.length,
    totalCredentials,
    uniqueCredentials,
    urlsWithoutCredentials,
    topDomains: topN(allDomains, LIMITS.topDomains),
    topUsernames: topN(allUsernames, LIMITS.topUsernames),
    failedFiles,
  });
}

// Cookies

async function analyseCookies(nodes) {
  if (nodes.length === 0) {
    emit('analysis:cookies', {
      fileCount: 0, totalCookies: 0, uniqueDomains: 0, topDomains: [],
      totalValid: 0, totalExpired: 0, totalSession: 0, totalUnknown: 0, totalNoDomain: 0,
      sessionTokens: 0, validSessionTokens: 0,
    });
    return;
  }

  const domainStats = {};
  let totalCookies = 0;
  let parsedCount = 0;
  let totalNoDomain = 0;
  let sessionTokens = 0;
  let validSessionTokens = 0;

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseCookieFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      totalCookies += parsed.rows.length;

      const domainIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
      const expiresIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
      const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));

      for (const row of parsed.rows) {
        const domain = (domainIdx >= 0 ? (row[domainIdx] || '') : (row[0] || '')).replace(/^\./, '').toLowerCase();
        if (!domain) { totalNoDomain++; continue; }

        if (!domainStats[domain]) {
          domainStats[domain] = { total: 0, valid: 0, expired: 0, session: 0, unknown: 0 };
        }
        domainStats[domain].total++;

        const expiresVal = expiresIdx >= 0 ? row[expiresIdx] : null;
        const validity = checkCookieValidity(expiresVal);
        if (validity.status === 'valid') domainStats[domain].valid++;
        else if (validity.status === 'expired') domainStats[domain].expired++;
        else if (validity.status === 'session') domainStats[domain].session++;
        else domainStats[domain].unknown++;

        const cookieName = nameIdx >= 0 ? row[nameIdx] : '';
        const sessionType = classifyCookie(cookieName);
        if (sessionType) {
          sessionTokens++;
          if (validity.status === 'valid') validSessionTokens++;
        }
      }
    } catch {
      // skip
    }
  }

  const uniqueDomains = Object.keys(domainStats).length;

  let totalValid = 0;
  let totalExpired = 0;
  let totalSession = 0;
  let totalUnknown = 0;
  for (const stats of Object.values(domainStats)) {
    totalValid += stats.valid;
    totalExpired += stats.expired;
    totalSession += stats.session;
    totalUnknown += stats.unknown;
  }

  const topDomains = Object.entries(domainStats)
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
    totalValid,
    totalExpired,
    totalSession,
    totalUnknown,
    totalNoDomain,
    topDomains,
    sessionTokens,
    validSessionTokens,
  });
}

// History

async function analyseHistory(nodes) {
  if (nodes.length === 0) {
    emit('analysis:history', null);
    return;
  }

  const entries = [];
  const domains = [];
  let fileCount = 0;

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseHistoryFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const titleIdx = parsed.headers.findIndex(h => /^(title|page.?title)$/i.test(h));
      const visitsIdx = parsed.headers.findIndex(h => /^(visit.?count|visits?|count)$/i.test(h));
      const lastIdx = parsed.headers.findIndex(h => /^(last.?visit|date|time|timestamp)$/i.test(h));

      for (const row of parsed.rows) {
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
        if (!url) continue;
        const title = titleIdx >= 0 ? (row[titleIdx] || '').trim() : '';
        const visitCount = visitsIdx >= 0 ? (parseInt(row[visitsIdx], 10) || 1) : 1;
        const lastVisit = lastIdx >= 0 ? (row[lastIdx] || '').trim() : '';
        const lastVisitDate = parseTimestampValue(lastVisit);
        const domain = extractBaseDomain(extractDomain(url)) || '';
        if (domain) domains.push(domain);
        entries.push({ url, title, visitCount, lastVisit, lastVisitDate });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:history', null);
    return;
  }

  const datedEntries = entries.filter(entry => entry.lastVisitDate);
  const mostRecent = datedEntries.length > 0
    ? datedEntries.reduce((latest, entry) => (!latest || entry.lastVisitDate > latest.lastVisitDate ? entry : latest), null)
    : null;

  emit('analysis:history', {
    fileCount,
    totalEntries: entries.length,
    uniqueDomains: new Set(domains).size,
    topDomains: topN(domains, LIMITS.topDomains),
    mostRecent: mostRecent
      ? { url: mostRecent.url, title: mostRecent.title, lastVisit: mostRecent.lastVisit }
      : null,
  });
}

// System info

async function analyseSystemInfo(nodes) {
  if (nodes.length === 0) {
    emit('analysis:sysinfo', null);
    return;
  }

  const merged = {};
  const sourceFiles = [];
  const decoded = [];

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      decoded.push(text);
      const parsed = parseSystemInfoFile(text, node.name);
      if (!parsed || !parsed.entries) continue;

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
    return;
  }

  // Reuse the already-decoded sysinfo text rather than re-loading and re-decoding.
  const combinedText = decoded.length > 0 ? decoded.join('\n') + '\n' : '';

  emit('analysis:sysinfo', { entries: merged, sourceFiles, sysinfoText: combinedText });

  // Extract inline software/process sections from sysinfo text
  extractInlineSections(combinedText);
}

function extractInlineSections(text) {
  if (!text) return;
  const lines = text.split('\n');

  const SOFTWARE_HEADER = /^Installed (?:Apps|Software|Programs)\s*:/i;
  const PROCESS_HEADER = /^Process (?:List|es)\s*:/i;
  const BRACKET_SOFTWARE = /^\[Software\]/i;
  const BRACKET_PROCESS = /^\[Process(?:es)?\](?:\[\d+\])?/i;
  const BRACKET_SECTION = /^\[[A-Za-z][A-Za-z ]*\](?:\[\d+\])?$/;
  const SECTION_HEADER = /^[A-Z][A-Za-z ]+:$/;
  const SUB_HEADER = /^(?:All Users|Current User)\s*:/i;
  const KV_LINE = /^[A-Za-z][A-Za-z0-9 _./()%-]*?\s*(?:=\s*|:\s+)/;

  const VERSION_PATTERNS = [
    /^(.+?)\s*-\s*(.+)$/,
    /^(.+?)\s*\(([^)]+)\)$/,
    /^(.+?)\s+(v?\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?)$/i,
    /^(.+?)\s*\[([^\]]+)\]$/,
  ];

  let softwareLines = null;
  let processLines = null;
  let currentTarget = null;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    if (SOFTWARE_HEADER.test(trimmed) || BRACKET_SOFTWARE.test(trimmed)) {
      softwareLines = [];
      currentTarget = softwareLines;
      continue;
    }
    if (PROCESS_HEADER.test(trimmed) || BRACKET_PROCESS.test(trimmed)) {
      processLines = [];
      currentTarget = processLines;
      continue;
    }

    // A new section header ends the current section (bracket, colon, or KV line)
    if (currentTarget && trimmed) {
      if (BRACKET_SECTION.test(trimmed) || (!rawLine.startsWith('\t') && SECTION_HEADER.test(trimmed) && !SUB_HEADER.test(trimmed))) {
        currentTarget = null;
        continue;
      }
      // KV lines (e.g. "Processor: Intel...") end the section too
      if (KV_LINE.test(trimmed)) {
        currentTarget = null;
        continue;
      }
    }

    // Skip sub-headers
    if (currentTarget && SUB_HEADER.test(trimmed)) continue;

    if (currentTarget && trimmed && !isPromotionalNoiseLine(trimmed)) {
      currentTarget.push(trimmed);
    }
  }

  // Parse software entries
  if (softwareLines && softwareLines.length > 0) {
    const entries = [];
    const seen = new Set();
    for (const line of softwareLines) {
      if (line.length > 120) continue;
      let name = line;
      let version = null;
      for (const pattern of VERSION_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          name = match[1].trim();
          const verStr = match[2].trim();
          if (/\d/.test(verStr)) version = verStr;
          break;
        }
      }
      if (name && !seen.has(name.toLowerCase())) {
        seen.add(name.toLowerCase());
        entries.push({ name, version });
      }
    }
    if (entries.length > 0) {
      emit('analysis:software', { fileCount: 1, entries, totalCount: entries.length, inline: true });
    }
  }

  // Parse process list entries
  if (processLines && processLines.length > 0) {
    const entries = [];
    const seen = new Set();
    for (const line of processLines) {
      if (isPromotionalNoiseLine(line) || /^===\s*running processes\s*===$/i.test(line)) continue;
      const cleaned = line.replace(/^[-*•]\s+/, '').trim();
      if (!cleaned || cleaned.length > 200) continue;

      let name = cleaned;
      let pid = null;
      // Vidar v1.5 writes `[pid] name`; other families write `name [pid]` /
      // `name (pid)`.
      const bracketPrefix = cleaned.match(/^\[(\d+)\]\s+(.+)$/);
      if (bracketPrefix) {
        pid = bracketPrefix[1];
        name = bracketPrefix[2].trim();
      } else {
        const bracketSuffix = cleaned.match(/^(.+?)\s*[\[(](\d+)[\])]\s*$/);
        if (bracketSuffix) {
          name = bracketSuffix[1].trim();
          pid = bracketSuffix[2];
        }
      }
      if (!name) continue;

      const key = name.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        entries.push({ name, pid });
      } else if (pid) {
        const existing = entries.find((entry) => entry.name.toLowerCase() === key);
        if (existing && !existing.pid) existing.pid = pid;
      }
    }
    if (entries.length > 0) {
      emit('analysis:processList', { fileCount: 1, entries, uniqueCount: entries.length, inline: true });
    }
  }
}

// Clipboard

async function analyseClipboard(nodes) {
  if (nodes.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  const entries = [];
  let fileCount = 0;
  let urlCount = 0;
  let commandCount = 0;
  let pathCount = 0;
  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseClipboardFile(text);
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
        entries.push({ type, text: entryText, urls });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  emit('analysis:clipboard', { entries, fileCount, urlCount, commandCount, pathCount });
}

function extractIOCs(sysinfoEntries, sysinfoText) {
  if (!sysinfoEntries) return null;
  const iocs = [];
  const seen = new Set();

  // Key-value based IOC extraction
  for (const { label, patterns } of IOC_KEY_MAP) {
    for (const [key, value] of Object.entries(sysinfoEntries)) {
      if (patterns.some(rx => rx.test(key))) {
        // Canonicalise Vidar / RedLine TZ encodings to `UTC±HH:MM`; keep the
        // raw form on the IOC so exports can still reach the original string.
        let displayValue = value;
        let rawValue;
        if (label === 'Timezone') {
          const tz = normaliseTimeZone(value);
          if (tz.offset != null || tz.source === 'unknown') {
            displayValue = tz.label;
            if (tz.label !== String(value).trim()) rawValue = String(value);
          }
        }
        const k = `${label}:${displayValue}`;
        if (!seen.has(k)) {
          seen.add(k);
          const ioc = { label, value: displayValue };
          if (rawValue) ioc.rawValue = rawValue;
          iocs.push(ioc);
        }
        break;
      }
    }
  }

  // Content-based IOC extraction. The labelled break enforces the global cap
  // — a plain break would only exit the inner while.
  if (sysinfoText) {
    outer: for (const { label, pattern } of CONTENT_IOC_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(sysinfoText)) !== null) {
        const value = match[0];
        const k = `${label}:${value}`;
        if (!seen.has(k)) {
          seen.add(k);
          iocs.push({ label, value });
        }
        if (iocs.length >= LIMITS.iocMaxItems) break outer;
      }
    }
  }

  return iocs.length > 0 ? iocs : null;
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
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseAutofillFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      const fileEntries = [];
      for (const row of parsed.rows) {
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
      const text = await decodeNodeText(node);
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

async function analyseDomainDetect(nodes) {
  if (nodes.length === 0) {
    emit('analysis:domainDetect', null);
    return;
  }

  const categories = {};
  const entries = [];
  let fileCount = 0;
  let totalHits = 0;

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseDomainDetectFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const section = (row[0] || 'General').trim() || 'General';
        const label = (row[1] || '').trim();
        const target = (row[2] || '').trim();
        const count = Math.max(parseInt(row[3], 10) || 1, 1);
        if (!target) continue;

        if (!categories[section]) categories[section] = [];
        categories[section].push({ domain: target, count, label });
        entries.push({ section, label, target, count });
        totalHits += count;
      }
    } catch {
      // skip
    }
  }

  if (Object.keys(categories).length === 0) {
    emit('analysis:domainDetect', null);
    return;
  }

  emit('analysis:domainDetect', { fileCount, totalHits, categories, entries });
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

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseCreditCardFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalCards += parsed.rows.length;
      for (const row of parsed.rows) {
        const cardNumber = (row[0] || '').trim();
        const nameOnCard = (row[1] || '').trim();
        const cvc = (row[2] || '').trim();
        const expiration = (row[3] || '').trim();
        const tail = cardNumber.replace(/\D/g, '').slice(-4);
        if (tail) last4.add(tail);
        if (nameOnCard) withHolder++;
        if (cvc) withCvc++;
        if (expiration && expiration !== '/') withExpiry++;
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
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseBookmarkFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalBookmarks += parsed.rows.length;

      const browser = inferBrowserFromPath(path || node.name);
      if (browser) browserCounts.push(browser);

      for (const row of parsed.rows) {
        const url = (row[0] || '').trim();
        if (!url) continue;
        const domain = extractDomain(url);
        if (domain) allDomains.push(domain);
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
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseBrowserMetadataFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      const browser = inferBrowserFromPath(path || node.name);
      if (browser) browsers.push(browser);

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
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseAccountTokenFile(text, path || node.name);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      totalEntries += parsed.rows.length;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';

      for (const row of parsed.rows) {
        const type = (row[0] || 'Token').trim();
        const value = (row[1] || '').trim();
        const accountId = (row[2] || '').trim();
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

async function analyseServiceArtifacts(nodes) {
  if (nodes.length === 0) {
    emit('analysis:serviceArtifacts', null);
    return;
  }

  const services = [];
  const keys = [];
  let fileCount = 0;
  let totalEntries = 0;

  for (const { node, path } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseServiceArtifactFile(text);
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
      if (!content) continue;
      const entry = parseWalletArtifact(content, node.name || '', path || node.name || '');
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

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const parsed = parseDownloadFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      totalDownloads += parsed.rows.length;

      // Extract domains from URL column
      const urlIdx = parsed.headers.findIndex(h => /url/i.test(h));
      for (const row of parsed.rows) {
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : (row[1] || '').trim();
        if (url) allDomains.push(extractDomain(url));
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
  const ctx = { dirs: [], files: [], sysinfoNodes: [], sysinfoCandidates: [], creditsNodes: [], creditsText: null, passwordNode: null, passwordHeaderText: null };

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
    for (const node of ctx.sysinfoNodes) {
      try {
        const text = await decodeNodeText(node);
        if (text == null) continue;
        const parsed = parseSystemInfoFile(text, node.name);
        ctx.sysinfoCandidates.push({
          sysinfoFilename: node.name,
          sysinfoText: text,
          sysinfoKeys: parsed && parsed.entries ? Object.keys(parsed.entries) : [],
        });
      } catch {
        // skip unreadable sysinfo candidates
      }
    }
  }

  // Load credits/copyright files for ASCII banner detection
  if (ctx.creditsNodes.length > 0) {
    const creditsTexts = [];
    for (const node of ctx.creditsNodes) {
      try {
        const text = await decodeNodeText(node);
        if (text != null) creditsTexts.push(text);
      } catch {
        // skip
      }
    }
    if (creditsTexts.length > 0) {
      ctx.creditsText = creditsTexts.join('\n');
    }
  }

  // Password file header (some stealers embed branding here)
  if (ctx.passwordNode) {
    try {
      const text = await decodeNodeText(ctx.passwordNode);
      if (text != null) ctx.passwordHeaderText = text.slice(0, 2000);
    } catch {
      // skip
    }
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

  const VERSION_PATTERNS = [
    /^(.+?)\s*-\s*(.+)$/,                          // Name - Version
    /^(.+?)\s*\(([^)]+)\)$/,                        // Name (Version)
    /^(.+?)\s+(v?\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?)$/i, // Name v1.2.3
    /^(.+?)\s*\[([^\]]+)\]$/,                        // Name [Version]
  ];

  for (const { node } of nodes) {
    try {
      const text = await decodeNodeText(node);
      if (text == null) continue;
      const lines = text.split('\n');
      let found = false;

      for (const rawLine of lines) {
        const line = rawLine.trim()
          .replace(/^[-_\s]+/, '')
          .replace(/[-_\s]+$/, '')
          .replace(/^\d+\)\s*/, '');

        if (!line) continue;
        if (line.includes('   ')) continue;  // skip lines with 3+ consecutive spaces
        if (/https?:\/\//i.test(line) || /www\./i.test(line)) continue;  // skip URLs
        if (/(===|\*\*\*|###|\$\$\$)/.test(line)) continue;  // skip separators
        if (line.length > 120) continue;
        if (/^[-=*#]{3,}$/.test(line)) continue;  // pure separator lines

        let name = line;
        let version = null;

        for (const pattern of VERSION_PATTERNS) {
          const match = line.match(pattern);
          if (match) {
            name = match[1].trim();
            const verStr = match[2].trim();
            if (/\d/.test(verStr)) {
              version = verStr;
            }
            break;
          }
        }

        if (name && !seen.has(name.toLowerCase())) {
          seen.add(name.toLowerCase());
          entries.push({ name, version });
          found = true;
        }
      }
      if (found) parsedCount++;
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

  for (const { node } of nodes) {
    try {
      const decoded = await decodeNodeText(node);
      if (decoded == null) continue;
      const text = stripLeadingNoiseLines(decoded);
      const lines = text.split('\n');
      let found = false;

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        if (isPromotionalNoiseLine(line)) continue;
        if (/^[-=*#]{3,}$/.test(line)) continue;  // separators
        if (/^===\s*running processes\s*===$/i.test(line)) continue;
        if (/^(Process|Name|PID|Image)/i.test(line) && /\t/.test(line)) continue;  // header row

        let name = line;
        let pid = null;
        let sessionId = null;
        let commandLine = '';

        const labelled = line.match(/^PID:\s*(\d+)\s*,\s*SessionID:\s*([^,]+)\s*,\s*Name:\s*([^,]+)(?:\s*,\s*CommandLine:\s*(.*))?$/i);
        if (labelled) {
          pid = labelled[1];
          sessionId = labelled[2].trim();
          name = labelled[3].trim();
          commandLine = (labelled[4] || '').trim();
        } else {
          const pidDashMatch = line.match(/^PID:\s*(\d+)\s*-\s*(.+)$/i);
          if (pidDashMatch) {
            pid = pidDashMatch[1];
            name = pidDashMatch[2].trim();
          } else {
            const bracketPrefix = line.match(/^\[(\d+)\]\s+(.+)$/);
            if (bracketPrefix) {
              pid = bracketPrefix[1];
              name = bracketPrefix[2].trim();
            } else {
              const bracketMatch = line.match(/^(.+?)\s*[\[(](\d+)[\])]\s*$/);
              if (bracketMatch) {
                name = bracketMatch[1].trim();
                pid = bracketMatch[2];
              } else {
                const parts = line.split('\t').map(p => p.trim()).filter(Boolean);
                if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
                  name = parts[0];
                  pid = parts[1];
                  if (parts.length >= 3) commandLine = parts.slice(2).join(' ');
                } else if (parts.length === 1) {
                  name = parts[0];
                }
              }
            }
          }
        }

        name = name.replace(/^[-*•]\s+/, '').trim();
        if (!name || name.length > 200) continue;

        const key = name.toLowerCase();
        if (!entryMap.has(key)) {
          entryMap.set(key, { name, pid, sessionId, commandLine });
        } else {
          const existing = entryMap.get(key);
          if (!existing.pid && pid) existing.pid = pid;
          if (!existing.sessionId && sessionId) existing.sessionId = sessionId;
          if (!existing.commandLine && commandLine) existing.commandLine = commandLine;
        }
        found = true;
      }
      if (found) parsedCount++;
    } catch {
      // skip
    }
  }

  const entries = [...entryMap.values()];

  if (entries.length === 0) {
    emit('analysis:processList', null);
    return;
  }

  emit('analysis:processList', { fileCount: parsedCount, entries, uniqueCount: entries.length });
}

// Kick off all analyses. Returns a promise resolved once every task settles;
// `analysis:complete` fires from the resolution.

function runAnalysis(fileTree, rootName) {
  const buckets = bucketHintedNodes(fileTree, rootName);

  findScreenshot(buckets._screenshotHint);

  const tasks = [
    analyseCredentials(buckets._passwordFileHint),
    analyseCookies(buckets._cookieFileHint),
    analyseHistory(buckets._historyHint),
    analyseSystemInfo(buckets._sysInfoHint),
    analyseAutofills(buckets._autofillHint),
    analyseNotes(buckets._notesHint),
    analyseBookmarks(buckets._bookmarkHint),
    analyseBrowserMetadata(buckets._browserMetadataHint),
    analyseAccountTokens(buckets._accountTokenHint),
    analyseServiceArtifacts(buckets._serviceArtifactHint),
    analyseWalletArtifacts(buckets._cryptoWalletHint),
    analyseDownloads(buckets._downloadHint),
    analyseCreditCards(buckets._creditCardHint),
    analyseDomainDetect(buckets._domainDetectHint),
    analyseSoftware(buckets._softwareFileHint),
    analyseProcessList(buckets._processListHint),
    analyseClipboard(buckets._clipboardHint),
    analyseGrabbedFiles(buckets._grabbedFileHint),
    runFingerprint(fileTree, rootName),
  ];

  return Promise.allSettled(tasks).then((results) => {
    for (const result of results) {
      if (result.status === 'rejected') {
        console.error('Analysis task failed:', result.reason);
      }
    }
    emit('analysis:complete');
  });
}

export { runAnalysis, extractIOCs };
