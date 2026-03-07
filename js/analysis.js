// Post-extraction analysis

import { emit } from './state.js';
import { loadFileContent } from './extractor.js';
import { parsePasswordFile, parseCookieFile, parseAutofillFile, parseDownloadFile } from './transforms.js';
import { collectHintedNodes, extractDomain, checkCookieValidity, topN } from './shared.js';
import { classifyCookie } from './sessionCookies.js';
import { collectContext, fingerprintStealer } from './stealerFingerprint.js';
import { FIELD_PATTERNS, EMAIL_REGEX, PHONE_REGEX, IOC_KEY_MAP, CONTENT_IOC_PATTERNS, LIMITS } from './definitions.js';

// Credentials

async function analyzeCredentials(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_passwordFileHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:credentials', { fileCount: 0, totalCredentials: 0, uniqueCredentials: 0, topDomains: [], topUsernames: [] });
    return;
  }

  const allDomains = [];
  const allUsernames = [];
  const seen = new Set();
  let totalCredentials = 0;
  let uniqueCredentials = 0;
  let parsedCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      totalCredentials += parsed.rows.length;

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
      const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

      for (const row of parsed.rows) {
        const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
        const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
        const pass = passIdx >= 0 ? (row[passIdx] || '').trim() : '';

        const key = `${url}\t${user}\t${pass}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueCredentials++;
          if (url) allDomains.push(extractDomain(url));
          if (user) allUsernames.push(user);
        }
      }
    } catch {
      // skip files that fail
    }
  }

  emit('analysis:credentials', {
    fileCount: parsedCount,
    totalCredentials,
    uniqueCredentials,
    topDomains: topN(allDomains, LIMITS.topDomains),
    topUsernames: topN(allUsernames, LIMITS.topUsernames),
  });
}

// Cookies

async function analyzeCookies(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_cookieFileHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:cookies', { fileCount: 0, totalCookies: 0, uniqueDomains: 0, topDomains: [], sessionTokens: 0, validSessionTokens: 0 });
    return;
  }

  const domainStats = {};
  let totalCookies = 0;
  let parsedCount = 0;
  let sessionTokens = 0;
  let validSessionTokens = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseCookieFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      totalCookies += parsed.rows.length;

      const domainIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
      const expiresIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
      const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));

      for (const row of parsed.rows) {
        const domain = (domainIdx >= 0 ? (row[domainIdx] || '') : (row[0] || '')).replace(/^\./, '').toLowerCase();
        if (!domain) continue;

        if (!domainStats[domain]) {
          domainStats[domain] = { total: 0, valid: 0, expired: 0 };
        }
        domainStats[domain].total++;

        const expiresVal = expiresIdx >= 0 ? row[expiresIdx] : null;
        const validity = checkCookieValidity(expiresVal);
        if (validity.status === 'valid') domainStats[domain].valid++;
        else if (validity.status === 'expired') domainStats[domain].expired++;

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
  for (const stats of Object.values(domainStats)) {
    totalValid += stats.valid;
    totalExpired += stats.expired;
  }

  const topDomains = Object.entries(domainStats)
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, LIMITS.topCookieDomains)
    .map(([domain, stats]) => ({
      value: domain,
      count: stats.total,
      valid: stats.valid,
      expired: stats.expired
    }));

  emit('analysis:cookies', {
    fileCount: parsedCount,
    totalCookies,
    uniqueDomains,
    totalValid,
    totalExpired,
    topDomains,
    sessionTokens,
    validSessionTokens,
  });
}

// System info

const KV_PATTERN = /^([A-Za-z][A-Za-z0-9 _./()%-]*?)\s*(?:=\s*|:\s+)(.*)/;

async function analyzeSystemInfo(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_sysInfoHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:sysinfo', null);
    return;
  }

  const merged = {};
  const sourceFiles = [];

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      let found = false;

      // JSON sysinfo
      if (/\.json$/i.test(node.name)) {
        try {
          const obj = JSON.parse(text);
          for (const [key, value] of Object.entries(obj)) {
            const str = Array.isArray(value) ? value.join(', ') : String(value);
            if (str && str !== 'null' && str !== '[]' && !merged[key]) {
              merged[key] = str;
              found = true;
            }
          }
        } catch { /* not valid JSON, try KV */ }
      }

      // KV text parsing
      if (!found) {
        const lines = text.split('\n');
        let lastKey = null;
        for (const line of lines) {
          const clean = line.trim().replace(/^[\p{So}\p{Sk}\u200d\ufe0f]+\s*/u, '').replace(/^[-*•]\s+/, '');
          // Tab-indented continuation lines append to previous key
          if (/^\t/.test(line) && lastKey && merged[lastKey] && clean) {
            merged[lastKey] += ', ' + clean;
            continue;
          }
          const match = clean.match(KV_PATTERN);
          if (match) {
            const key = match[1].trim();
            const value = match[2].trim();
            if (value && !merged[key]) {
              merged[key] = value;
              lastKey = key;
              found = true;
            }
          }
        }
      }
      if (found) sourceFiles.push(node.name);
    } catch {
      // skip
    }
  }

  if (Object.keys(merged).length === 0) {
    emit('analysis:sysinfo', null);
    return;
  }

  // Combine all sysinfo source text for content-based IOC extraction
  let combinedText = '';
  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (content) {
        combinedText += new TextDecoder('utf-8').decode(content) + '\n';
      }
    } catch {
      // skip
    }
  }

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

    if (currentTarget && trimmed) {
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
      const name = line.replace(/^[-*•]\s+/, '').trim();
      if (!name || name.length > 200) continue;
      const key = name.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        entries.push({ name, pid: null });
      }
    }
    if (entries.length > 0) {
      emit('analysis:processList', { fileCount: 1, entries, uniqueCount: entries.length, inline: true });
    }
  }
}

// Clipboard

async function analyzeClipboard(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_clipboardHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  const entries = [];
  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content).trim();
      if (!text) continue;
      // Extract URLs from clipboard content
      const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
      entries.push({ text, urls });
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:clipboard', null);
    return;
  }

  emit('analysis:clipboard', { entries });
}

function extractIOCs(sysinfoEntries, sysinfoText) {
  if (!sysinfoEntries) return null;
  const iocs = [];
  const seen = new Set();

  // Key-value based IOC extraction
  for (const { label, patterns } of IOC_KEY_MAP) {
    for (const [key, value] of Object.entries(sysinfoEntries)) {
      if (patterns.some(rx => rx.test(key))) {
        const k = `${label}:${value}`;
        if (!seen.has(k)) {
          seen.add(k);
          iocs.push({ label, value });
        }
        break;
      }
    }
  }

  // Content-based IOC extraction from sysinfo text body
  if (sysinfoText) {
    for (const { label, pattern } of CONTENT_IOC_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(sysinfoText)) !== null) {
        const value = match[0];
        const k = `${label}:${value}`;
        if (!seen.has(k)) {
          seen.add(k);
          iocs.push({ label, value });
        }
        if (iocs.length > 50) break; // safety cap
      }
    }
  }

  return iocs.length > 0 ? iocs : null;
}

// Autofill

async function analyzeAutofills(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_autofillHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:autofill', null);
    return;
  }

  const entries = [];
  let parsedCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseAutofillFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      parsedCount++;
      for (const row of parsed.rows) {
        const name = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        if (name && value) entries.push({ name, value });
      }
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:autofill', null);
    return;
  }

  const emails = [];
  const phones = [];
  const names = [];
  const addresses = [];
  const other = [];

  for (const { name, value } of entries) {
    const lower = name.toLowerCase();
    if (FIELD_PATTERNS.email.test(lower) || EMAIL_REGEX.test(value)) {
      emails.push(value);
    } else if (FIELD_PATTERNS.phone.test(lower) || PHONE_REGEX.test(value)) {
      phones.push(value);
    } else if (FIELD_PATTERNS.name.test(lower)) {
      names.push(value);
    } else if (FIELD_PATTERNS.address.test(lower)) {
      addresses.push(value);
    } else {
      other.push({ name, value });
    }
  }

  emit('analysis:autofill', {
    fileCount: parsedCount,
    totalEntries: entries.length,
    emails: [...new Set(emails)],
    phones: [...new Set(phones)],
    names: [...new Set(names)],
    addresses: [...new Set(addresses)],
    other: other.slice(0, LIMITS.maxAutofillOther),
  });
}

// Domain detect

async function analyzeDomainDetect(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_domainDetectHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:domainDetect', null);
    return;
  }

  const ENTRY_PATTERN = /(?:^|\s)(?:\d+\)\s*)?\[([^\]]+)\]\s+([^\s(]+)\s*\((\d+)\)/g;
  const categories = {};

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      let currentCategory = 'General';

      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        const colonIdx = trimmed.indexOf(':');
        const header = colonIdx >= 0 ? trimmed.slice(0, colonIdx).trim() : '';
        const rest = (colonIdx >= 0 ? trimmed.slice(colonIdx + 1) : trimmed).trim();

        if (colonIdx >= 0 && !rest) {
          currentCategory = header || currentCategory;
          continue;
        }

        let match;
        let matchedEntry = false;
        ENTRY_PATTERN.lastIndex = 0;
        while ((match = ENTRY_PATTERN.exec(rest)) !== null) {
          const label = match[1];
          const domain = match[2];
          const count = parseInt(match[3], 10);
          if (!categories[label]) categories[label] = [];
          categories[label].push({ domain, count });
          currentCategory = label;
          matchedEntry = true;
        }

        if (!matchedEntry && rest && !/\s/.test(rest) && /[A-Za-z]/.test(rest)) {
          const label = header || currentCategory || 'General';
          if (!categories[label]) categories[label] = [];
          categories[label].push({ domain: rest, count: 1 });
        }
      }
    } catch {
      // skip
    }
  }

  if (Object.keys(categories).length === 0) {
    emit('analysis:domainDetect', null);
    return;
  }

  emit('analysis:domainDetect', { categories });
}

// Download history

async function analyzeDownloads(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_downloadHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:downloads', null);
    return;
  }

  const allDomains = [];
  let totalDownloads = 0;
  let parsedCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
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

// Screenshot detection

function findScreenshot(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_screenshotHint', rootName, nodes);
  if (nodes.length === 0) {
    emit('analysis:screenshot', null);
    return;
  }
  emit('analysis:screenshot', { node: nodes[0].node, path: nodes[0].path });
}

// Stealer fingerprinting

const SYSINFO_KV = /^([A-Za-z][A-Za-z0-9 _\/-]*?)\s*[:=]\s+(.*)/;

async function runFingerprint(fileTree, rootName) {
  const ctx = { dirs: [], files: [], sysinfoFilename: null, sysinfoNode: null, sysinfoKeys: [], sysinfoText: null, creditsNodes: [], creditsText: null, passwordNode: null, passwordHeaderText: null };

  // If the archive has a single top-level dir, start inside it so paths match signatures
  let startNode = fileTree;
  if (fileTree.children) {
    const children = Object.values(fileTree.children);
    if (children.length === 1 && children[0].type === 'directory') {
      startNode = children[0];
    }
  }
  collectContext(startNode, '', ctx);

  if (ctx.sysinfoNode) {
    try {
      const content = await loadFileContent(ctx.sysinfoNode);
      if (content) {
        const text = new TextDecoder('utf-8').decode(content);
        ctx.sysinfoText = text;

        // JSON sysinfo
        if (/\.json$/i.test(ctx.sysinfoNode.name)) {
          try {
            const obj = JSON.parse(text);
            for (const key of Object.keys(obj)) ctx.sysinfoKeys.push(key);
          } catch { /* try KV */ }
        }

        // KV text parsing
        if (ctx.sysinfoKeys.length === 0) {
          for (const line of text.split('\n')) {
            const clean = line.trim().replace(/^[\p{So}\p{Sk}\u200d\ufe0f]+\s*/u, '').replace(/^[-*•]\s+/, '');
            const match = clean.match(SYSINFO_KV);
            if (match) ctx.sysinfoKeys.push(match[1].trim());
          }
        }
      }
    } catch {
      // proceed without sysinfo content
    }
  }

  // Load credits/copyright files for ASCII banner detection
  if (ctx.creditsNodes.length > 0) {
    const creditsTexts = [];
    for (const node of ctx.creditsNodes) {
      try {
        const content = await loadFileContent(node);
        if (content) {
          creditsTexts.push(new TextDecoder('utf-8').decode(content));
        }
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
      const content = await loadFileContent(ctx.passwordNode);
      if (content) {
        const text = new TextDecoder('utf-8').decode(content);
        ctx.passwordHeaderText = text.slice(0, 2000);
      }
    } catch {
      // skip
    }
  }

  const result = fingerprintStealer(ctx);
  emit('analysis:fingerprint', result);
}

// Installed software

async function analyzeSoftware(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_softwareFileHint', rootName, nodes);

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
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
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

async function analyzeProcessList(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_processListHint', rootName, nodes);

  if (nodes.length === 0) {
    emit('analysis:processList', null);
    return;
  }

  const entries = [];
  const seen = new Set();
  let parsedCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const lines = text.split('\n');
      let found = false;

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        if (/^[-=*#]{3,}$/.test(line)) continue;  // separators
        if (/^(Process|Name|PID|Image)/i.test(line) && /\t/.test(line)) continue;  // header row

        let name = line;
        let pid = null;

        const bracketMatch = line.match(/^(.+?)\s*[\[(](\d+)[\])]\s*$/);
        if (bracketMatch) {
          name = bracketMatch[1].trim();
          pid = bracketMatch[2];
        } else {
          const parts = line.split('\t').map(p => p.trim()).filter(Boolean);
          if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
            name = parts[0];
            pid = parts[1];
          } else if (parts.length === 1) {
            name = parts[0];
          }
        }

        name = name.replace(/^[-*•]\s+/, '').trim();
        if (!name || name.length > 200) continue;

        const key = name.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          entries.push({ name, pid });
          found = true;
        }
      }
      if (found) parsedCount++;
    } catch {
      // skip
    }
  }

  if (entries.length === 0) {
    emit('analysis:processList', null);
    return;
  }

  emit('analysis:processList', { fileCount: parsedCount, entries, uniqueCount: entries.length });
}

// Kick off all analyses

function runAnalysis(fileTree, rootName) {
  analyzeCredentials(fileTree, rootName);
  analyzeCookies(fileTree, rootName);
  analyzeSystemInfo(fileTree, rootName);
  analyzeAutofills(fileTree, rootName);
  analyzeDownloads(fileTree, rootName);
  analyzeDomainDetect(fileTree, rootName);
  analyzeSoftware(fileTree, rootName);
  analyzeProcessList(fileTree, rootName);
  analyzeClipboard(fileTree, rootName);
  findScreenshot(fileTree, rootName);
  runFingerprint(fileTree, rootName);
}

export { runAnalysis, extractIOCs };
