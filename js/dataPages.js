// Data pages, Passwords, Cookies, Autofills, History.

import { state, on, emit } from './state.js';
import { loadFileContent } from './extractor.js';
import { escapeHtml, getFileExtension, formatBytes } from './utils.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
  parseHistoryFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
  parseAccountTokenFile,
  parseServiceArtifactFile,
  parseDownloadFile,
  parseDomainDetectFile,
  parseClipboardFile,
  parseCreditCardFile,
} from './transforms.js';
import { collectHintedNodes, checkCookieValidity, extractDomain, extractBaseDomain, downloadBlob, parseTimestampValue } from './shared.js';
import { classifyCookie } from './sessionCookies.js';
import { FIELD_PATTERNS } from './definitions.js';
import { openColumnMapper } from './columnMapper.js';

// Per-type data stores

let passwordsData = { rows: [], headers: [], fileCount: 0 };
let cookiesData = { rows: [], headers: [], fileCount: 0 };
let autofillsData = { entries: [], fileCount: 0 };
let historyData = { entries: [], fileCount: 0 };
let bookmarksData = { entries: [], fileCount: 0 };
let browserMetadataData = { entries: [], fileCount: 0 };
let accountTokensData = { entries: [], fileCount: 0 };
let serviceArtifactsData = { entries: [], fileCount: 0 };
let downloadsData = { entries: [], fileCount: 0 };
let domainDetectionsData = { entries: [], fileCount: 0, totalHits: 0 };
let clipboardData = { entries: [], fileCount: 0 };
let creditCardsData = { entries: [], fileCount: 0 };
let screenshotsData = { entries: [], fileCount: 0, totalBytes: 0 };
let softwareData = { entries: [], fileCount: 0, totalCount: 0 };
let processListData = { entries: [], fileCount: 0, uniqueCount: 0 };

let historySort = { key: 'none', order: 'none' };
let hideCardNumbers = true;
let hideTokenValues = true;

const PAGE_SIZE = 200;

// Per-page filtered data + visible row count
let passwordsFiltered = [];
let passwordsShown = 0;

let cookiesFiltered = [];
let cookiesShown = 0;

let autofillsFiltered = [];
let autofillsShown = 0;

let historyFiltered = [];
let historyShown = 0;

let bookmarksFiltered = [];
let bookmarksShown = 0;

let browserMetadataFiltered = [];
let browserMetadataShown = 0;

let accountTokensFiltered = [];
let accountTokensShown = 0;

let serviceArtifactsFiltered = [];
let serviceArtifactsShown = 0;

let downloadsFiltered = [];
let downloadsShown = 0;

let domainDetectionsFiltered = [];
let domainDetectionsShown = 0;

let clipboardFiltered = [];
let clipboardShown = 0;

let creditCardsFiltered = [];
let creditCardsShown = 0;

let screenshotsFiltered = [];
let screenshotsShown = 0;

let softwareFiltered = [];
let softwareShown = 0;

let processesFiltered = [];
let processesShown = 0;

// Progressive loading helpers

function buildShowMoreButton(remaining, pageId) {
  return `<button class="data-show-more" data-page="${pageId}">Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)</button>`;
}

function buildRowsHtml(rowBuilder, items, start, end) {
  let html = '';
  const limit = Math.min(end, items.length);
  for (let i = start; i < limit; i++) {
    html += rowBuilder(items[i], i);
  }
  return html;
}

function formatTimestampDisplay(date) {
  if (!date) return '';
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function getImageMimeFromName(name) {
  const ext = getFileExtension(name);
  const mimeMap = {
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    bmp: 'image/bmp',
    gif: 'image/gif',
    webp: 'image/webp',
  };
  return mimeMap[ext] || 'image/png';
}

function measureImage(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve({ width: img.naturalWidth, height: img.naturalHeight });
    img.onerror = () => resolve({ width: null, height: null });
    img.src = url;
  });
}

function revokeScreenshotUrls() {
  for (const entry of screenshotsData.entries) {
    if (entry.blobUrl) URL.revokeObjectURL(entry.blobUrl);
  }
}

function extractCardLast4(cardNumber) {
  return String(cardNumber || '').replace(/\D/g, '').slice(-4);
}

function maskCardNumber(cardNumber) {
  const raw = String(cardNumber || '').trim();
  if (!raw) return '';
  const last4 = extractCardLast4(raw);
  if (last4) return `\u2022\u2022\u2022\u2022 ${last4}`;
  if (raw.length <= 4) return raw;
  return `${raw[0]}\u2022\u2022\u2022${raw[raw.length - 1]}`;
}

function maskTokenValue(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.length <= 10) return '\u2022'.repeat(raw.length);
  return `${raw.slice(0, 4)}\u2022\u2022\u2022\u2022${raw.slice(-4)}`;
}

function inferBrowserFromPath(pathText) {
  const value = String(pathText || '');
  const match = value.match(/\b(Chrome|Edge|Firefox|Opera|Brave|Vivaldi|Safari)\b/i);
  return match ? match[1] : '';
}

function inferProfileFromPath(pathText) {
  const value = String(pathText || '');
  const bracketMatch = value.match(/\b(?:Default|Profile\s*\d+|Profile_\d+|Default\[[^\]]+\]|Profile\s*\d+\[[^\]]+\])\b/i);
  if (bracketMatch) return bracketMatch[0].replace(/\[[^\]]+\]/g, '').trim();

  const fileMatch = value.match(/(?:Chrome|Edge|Firefox|Opera|Brave|Vivaldi|Chromium|Google Chrome|Microsoft Edge)[_\s-]+([^/.]+(?:\s+\d+)*)/i);
  return fileMatch ? fileMatch[1].trim() : '';
}

function inferServiceFromPath(pathText) {
  const value = String(pathText || '');
  if (/googleaccounts/i.test(value)) return 'Google';
  if (/accounttokens?/i.test(value)) return 'Google';
  if (/discord/i.test(value)) return 'Discord';
  if (/steam/i.test(value)) return 'Steam';
  if (/fbfastcheck/i.test(value)) return 'Facebook';
  if (/telegram/i.test(value)) return 'Telegram';
  if (/anydesk/i.test(value)) return 'AnyDesk';
  if (/outlook/i.test(value)) return 'Outlook';
  return '';
}

function inferMetadataCategory(pathText) {
  const value = String(pathText || '');
  if (/\/path\//i.test(value)) return 'Path';
  if (/\/ua\//i.test(value)) return 'User Agent';
  if (/\/version\//i.test(value)) return 'Version';
  if (/debug\.txt$/i.test(value)) return 'Debug';
  return 'Metadata';
}

function inferServiceArtifactType(pathText) {
  const value = String(pathText || '');
  if (/leveldb/i.test(value)) return 'Local Storage';
  if (/accounts\.txt$/i.test(value)) return 'Accounts';
  if (/usersettings\.json$/i.test(value)) return 'Settings';
  if (/token\.txt$/i.test(value)) return 'Token Config';
  if (/\.(?:conf|cfg|ini)$/i.test(value)) return 'Config';
  return 'Artifact';
}

function truncateText(value, max = 120) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '\u2026';
}

function extractDownloadExtension(filePath, sourceUrl) {
  const candidates = [filePath, sourceUrl];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const clean = candidate.split('?')[0].split('#')[0];
    const segment = clean.split(/[\\/]/).pop() || '';
    const ext = getFileExtension(segment);
    if (ext) return ext;
  }
  return '';
}

function parseDownloadSize(rawValue) {
  if (rawValue == null) return { raw: '', bytes: null, display: '' };

  const raw = String(rawValue).trim();
  if (!raw) return { raw: '', bytes: null, display: '' };

  const normalized = raw.replace(/,/g, '');
  const match = normalized.match(/^(\d+(?:\.\d+)?)\s*(bytes?|b|kb|mb|gb|tb)?$/i);
  if (!match) {
    return { raw, bytes: null, display: raw };
  }

  const value = Number(match[1]);
  if (!Number.isFinite(value) || value < 0) {
    return { raw, bytes: null, display: raw };
  }

  const unit = (match[2] || 'bytes').toLowerCase();
  const multipliers = {
    b: 1,
    byte: 1,
    bytes: 1,
    kb: 1024,
    mb: 1024 ** 2,
    gb: 1024 ** 3,
    tb: 1024 ** 4,
  };
  const bytes = Math.round(value * (multipliers[unit] || 1));
  return { raw, bytes, display: formatBytes(bytes) };
}

// Data loading

async function loadPasswordsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_passwordFileHint', rootName, nodes);

  if (nodes.length === 0) {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  // Pass 1: parse all files and build column mappings
  const canonicalHeaders = ['URL', 'Username', 'Password'];
  const extraHeaders = [];
  const parsedFiles = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
      const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

      if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) continue;

      const colMap = new Map();
      if (urlIdx >= 0)  colMap.set(urlIdx, 0);
      if (userIdx >= 0) colMap.set(userIdx, 1);
      if (passIdx >= 0) colMap.set(passIdx, 2);

      for (let i = 0; i < parsed.headers.length; i++) {
        if (colMap.has(i)) continue;
        const hdr = parsed.headers[i];
        if (/^Column \d+$/.test(hdr)) continue;
        let extraIdx = extraHeaders.indexOf(hdr);
        if (extraIdx < 0) { extraIdx = extraHeaders.length; extraHeaders.push(hdr); }
        colMap.set(i, canonicalHeaders.length + extraIdx);
      }

      fileCount++;
      parsedFiles.push({ path, parsed, colMap });
    } catch {
      // skip
    }
  }

  // Pass 2: build unified rows with final column count
  const totalCols = canonicalHeaders.length + extraHeaders.length;
  const dedupedRows = new Map();
  for (const { path, parsed, colMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const unified = new Array(totalCols).fill('');
      for (const [src, dest] of colMap) {
        unified[dest] = row[src] || '';
      }
      const key = [unified[0], unified[1], unified[2]]
        .map(cell => String(cell || '').trim().toLowerCase())
        .join('\u0000');
      if (!key.replace(/\u0000/g, '')) continue;

      if (!dedupedRows.has(key)) {
        dedupedRows.set(key, { row: unified, source: path });
        continue;
      }

      const existing = dedupedRows.get(key);
      for (let i = 0; i < unified.length; i++) {
        if (!existing.row[i] && unified[i]) existing.row[i] = unified[i];
      }
    }
  }

  const headers = [...canonicalHeaders, ...extraHeaders];
  passwordsData = { rows: [...dedupedRows.values()], headers, fileCount };
}

async function loadCookiesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_cookieFileHint', rootName, nodes);

  if (nodes.length === 0) {
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  const allRows = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseCookieFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const expiresIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
        const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));
        for (const row of parsed.rows) {
          const expiresVal = expiresIdx >= 0 ? row[expiresIdx] : null;
          const validity = checkCookieValidity(expiresVal);
          const cookieName = nameIdx >= 0 ? row[nameIdx] : '';
          const sessionType = classifyCookie(cookieName);
          allRows.push({ row, source: path, validity, sessionType, headers: parsed.headers });
        }
      }
    } catch {
      // skip
    }
  }

  const headers = allRows.length > 0 ? allRows[0].headers : ['Host', 'Name', 'Value', 'Expires'];
  cookiesData = { rows: allRows, headers, fileCount };
}

async function loadAutofillsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_autofillHint', rootName, nodes);

  if (nodes.length === 0) {
    autofillsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseAutofillFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        for (const row of parsed.rows) {
          const name = (row[0] || '').trim();
          const value = (row[1] || '').trim();
          if (name && value) {
            entries.push({ name, value, source: path });
          }
        }
        fileCount++;
      }
    } catch {
      // skip
    }
  }

  autofillsData = { entries, fileCount };
}

async function loadHistoryData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_historyHint', rootName, nodes);

  if (nodes.length === 0) {
    historyData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseHistoryFile(text, node._parseConfig || null);

      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
        const titleIdx = parsed.headers.findIndex(h => /^(title|page.?title)$/i.test(h));
        const visitsIdx = parsed.headers.findIndex(h => /^(visit.?count|visits?|count)$/i.test(h));
        const lastIdx = parsed.headers.findIndex(h => /^(last.?visit|date|time|timestamp)$/i.test(h));

        for (const row of parsed.rows) {
          const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
          if (!url) continue;
          const lastVisit = lastIdx >= 0 ? (row[lastIdx] || '').trim() : '';
          entries.push({
            url,
            title: titleIdx >= 0 ? (row[titleIdx] || '').trim() : '',
            visitCount: visitsIdx >= 0 ? (parseInt(row[visitsIdx], 10) || 1) : 1,
            lastVisit,
            lastVisitDate: parseTimestampValue(lastVisit),
            source: path
          });
        }
      }
    } catch {
      // skip
    }
  }

  historyData = { entries, fileCount };
}

async function loadBookmarksData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_bookmarkHint', rootName, nodes);

  if (nodes.length === 0) {
    bookmarksData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseBookmarkFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);
      for (const row of parsed.rows) {
        const url = (row[0] || '').trim();
        const title = (row[1] || '').trim();
        const folder = (row[2] || '').trim();
        if (!url) continue;

        entries.push({
          url,
          title,
          folder,
          browser,
          profile,
          domain: extractDomain(url) || '',
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  bookmarksData = { entries, fileCount };
}

async function loadBrowserMetadataData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_browserMetadataHint', rootName, nodes);

  if (nodes.length === 0) {
    browserMetadataData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseBrowserMetadataFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);
      const category = inferMetadataCategory(path || node.name);

      for (const row of parsed.rows) {
        const key = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        if (!key && !value) continue;
        entries.push({
          browser,
          profile,
          category,
          key,
          value,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  browserMetadataData = { entries, fileCount };
}

async function loadAccountTokensData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_accountTokenHint', rootName, nodes);

  if (nodes.length === 0) {
    accountTokensData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseAccountTokenFile(text, path || node.name);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);

      for (const row of parsed.rows) {
        const type = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        const accountId = (row[2] || '').trim();
        const note = (row[3] || '').trim();
        if (!value && !accountId) continue;

        entries.push({
          service,
          type,
          value,
          accountId,
          browser,
          profile,
          note,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  accountTokensData = { entries, fileCount };
}

async function loadServiceArtifactsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_serviceArtifactHint', rootName, nodes);

  if (nodes.length === 0) {
    serviceArtifactsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseServiceArtifactFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      const service = inferServiceFromPath(path || node.name) || 'Unknown';
      const artifactType = inferServiceArtifactType(path || node.name);

      for (const row of parsed.rows) {
        const section = (row[0] || '').trim();
        const key = (row[1] || '').trim();
        const value = (row[2] || '').trim();
        if (!key && !value) continue;
        entries.push({
          service,
          artifactType,
          section,
          key,
          value,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  serviceArtifactsData = { entries, fileCount };
}

async function loadDownloadsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_downloadHint', rootName, nodes);

  if (nodes.length === 0) {
    downloadsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseDownloadFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;

      const fileIdx = parsed.headers.findIndex(h => /^(?:file(?:\s*path)?|filename|path|download(?:\s*path)?)$/i.test(h));
      const urlIdx = parsed.headers.findIndex(h => /^(?:source\s*url|url|download\s*url)$/i.test(h));
      const sizeIdx = parsed.headers.findIndex(h => /^(?:file\s*size|size|bytes|received\s*bytes|recived\s*bytes)$/i.test(h));

      for (const row of parsed.rows) {
        const filePath = (fileIdx >= 0 ? row[fileIdx] : row[0]) || '';
        const sourceUrl = (urlIdx >= 0 ? row[urlIdx] : row[1]) || '';
        const sizeInfo = parseDownloadSize(sizeIdx >= 0 ? row[sizeIdx] : '');
        const domain = extractDomain(sourceUrl) || '';
        const extension = extractDownloadExtension(filePath, sourceUrl);

        if (!filePath && !sourceUrl) continue;
        entries.push({
          filePath: filePath.trim(),
          sourceUrl: sourceUrl.trim(),
          fileSizeRaw: sizeInfo.raw,
          fileSizeBytes: sizeInfo.bytes,
          fileSizeDisplay: sizeInfo.display,
          domain,
          extension,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  downloadsData = { entries, fileCount };
}

async function loadDomainDetectionsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_domainDetectHint', rootName, nodes);

  if (nodes.length === 0) {
    domainDetectionsData = { entries: [], fileCount: 0, totalHits: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;
  let totalHits = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseDomainDetectFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const section = (row[0] || 'General').trim() || 'General';
        const label = (row[1] || '').trim();
        const target = (row[2] || '').trim();
        const count = Math.max(parseInt(row[3], 10) || 1, 1);
        if (!target) continue;

        totalHits += count;
        entries.push({
          section,
          label,
          target,
          count,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  domainDetectionsData = { entries, fileCount, totalHits };
}

async function loadClipboardData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_clipboardHint', rootName, nodes);

  if (nodes.length === 0) {
    clipboardData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseClipboardFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const type = (row[0] || 'Text').trim() || 'Text';
        const entryText = (row[1] || '').trim();
        const urls = (row[2] || '').trim();
        const lineCount = parseInt(row[3], 10) || 1;
        const length = parseInt(row[4], 10) || entryText.length;
        if (!entryText) continue;

        entries.push({
          type,
          text: entryText,
          preview: truncateText(entryText, 140),
          urls,
          lineCount,
          length,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  clipboardData = { entries, fileCount };
}

async function loadCreditCardsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_creditCardHint', rootName, nodes);

  if (nodes.length === 0) {
    creditCardsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseCreditCardFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;
      for (const row of parsed.rows) {
        const cardNumber = (row[0] || '').trim();
        const nameOnCard = (row[1] || '').trim();
        const cvc = (row[2] || '').trim();
        const expiration = (row[3] || '').trim();
        const filePath = (row[4] || '').trim();
        if (!cardNumber && !nameOnCard && !cvc && !expiration && !filePath) continue;

        entries.push({
          cardNumber,
          last4: extractCardLast4(cardNumber),
          nameOnCard,
          cvc,
          expiration,
          filePath,
          browser: inferBrowserFromPath(filePath || path),
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  creditCardsData = { entries, fileCount };
}

async function loadScreenshotsData(fileTree, rootName) {
  revokeScreenshotUrls();

  const nodes = [];
  collectHintedNodes(fileTree, '_screenshotHint', rootName, nodes);

  if (nodes.length === 0) {
    screenshotsData = { entries: [], fileCount: 0, totalBytes: 0 };
    return;
  }

  const entries = [];
  let totalBytes = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;

      const blob = new Blob([content], { type: getImageMimeFromName(node.name) });
      const blobUrl = URL.createObjectURL(blob);
      const dimensions = await measureImage(blobUrl);
      const sizeBytes = node.size || content.byteLength || 0;
      totalBytes += sizeBytes;

      entries.push({
        name: node.name,
        path,
        node,
        blobUrl,
        width: dimensions.width,
        height: dimensions.height,
        sizeBytes,
        sizeDisplay: formatBytes(sizeBytes),
      });
    } catch {
      // skip
    }
  }

  screenshotsData = { entries, fileCount: entries.length, totalBytes };
}

// Password visibility

let hidePasswords = true;
let passwordColumnIdx = -1;

function maskValue(val) {
  if (!val || val.length === 0) return '';
  if (val.length <= 2) return '\u2022\u2022\u2022\u2022';
  return val[0] + '\u2022'.repeat(Math.min(val.length - 2, 8)) + val[val.length - 1];
}

// Rendering

function passwordRowBuilder({ row }) {
  let html = '<tr>';
  for (let i = 0; i < row.length; i++) {
    const cell = row[i];
    if (hidePasswords && i === passwordColumnIdx) {
      html += `<td class="password-cell masked" title="Click to reveal">${escapeHtml(maskValue(cell))}</td>`;
    } else {
      html += `<td title="${escapeHtml(cell)}">${escapeHtml(cell)}</td>`;
    }
  }
  html += '</tr>';
  return html;
}

function trimRootPath(path) {
  if (!path) return '';
  if (state.rootZipName && path.startsWith(state.rootZipName + '/')) {
    return path.slice(state.rootZipName.length + 1);
  }
  return path;
}

function chooseMapperNode(nodes, fileType) {
  if (nodes.length === 1) return Promise.resolve(nodes[0]);

  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay visible';
    overlay.innerHTML = `
      <div class="modal modal-filetype">
        <h3>Choose File</h3>
        <p>Select the ${escapeHtml(fileType)} file to remap.</p>
        <div class="filetype-options">
          ${nodes.map(({ node, path }, index) => `
            <button class="filetype-option" data-idx="${index}">
              <span class="filetype-icon">${escapeHtml(node.name || `File ${index + 1}`)}</span>
              <span class="filetype-desc">${escapeHtml(trimRootPath(path))}</span>
            </button>
          `).join('')}
        </div>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="mapperChooseCancel">Cancel</button>
        </div>
      </div>
    `;

    const cleanup = (selection) => {
      overlay.remove();
      resolve(selection);
    };

    overlay.querySelector('.filetype-options').addEventListener('click', (ev) => {
      const btn = ev.target.closest('.filetype-option');
      if (!btn) return;
      cleanup(nodes[parseInt(btn.dataset.idx, 10)] || null);
    });

    overlay.querySelector('#mapperChooseCancel').addEventListener('click', () => cleanup(null));
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) cleanup(null);
    });

    document.body.appendChild(overlay);
  });
}

// Generic column mapper opener for any file type
async function openMapperForHint(hintKey, fileType) {
  const nodes = [];
  collectHintedNodes(state.fileTree, hintKey, state.rootZipName, nodes);
  if (nodes.length === 0) return;

  const selected = await chooseMapperNode(nodes, fileType);
  if (!selected) return;

  const content = await loadFileContent(selected.node);
  if (!content) return;
  const text = new TextDecoder('utf-8').decode(content);
  const fileName = selected.path || selected.node.name || 'Unknown file';

  const config = await openColumnMapper(text, fileName, fileType);
  if (!config) return;

  selected.node._parseConfig = config;
  emit('reanalyze');
}

function addAdjustColumnsBtn(summaryEl, hintKey, fileType) {
  const actionsArea = summaryEl.parentNode.querySelector('.data-page-actions');
  if (actionsArea && !actionsArea.querySelector('.mapper-adjust-btn')) {
    const adjustBtn = document.createElement('button');
    adjustBtn.className = 'mapper-adjust-btn';
    adjustBtn.textContent = 'Adjust columns\u2026';
    adjustBtn.addEventListener('click', () => openMapperForHint(hintKey, fileType));
    actionsArea.insertBefore(adjustBtn, actionsArea.firstChild);
  }
}

function renderPasswordsPage(searchQuery = '') {
  const summary = document.getElementById('passwordsSummary');
  const content = document.getElementById('passwordsContent');

  if (passwordsData.rows.length === 0) {
    summary.textContent = 'No passwords found';
    content.innerHTML = '<div class="no-data">No password data available.</div>';
    return;
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    passwordsFiltered = passwordsData.rows.filter(({ row }) =>
      row.some(cell => cell.toLowerCase().includes(q))
    );
  } else {
    passwordsFiltered = passwordsData.rows;
  }

  passwordsShown = Math.min(PAGE_SIZE, passwordsFiltered.length);

  const total = passwordsData.rows.length;
  const showing = passwordsFiltered.length;
  summary.textContent = showing !== total
    ? `Showing ${showing.toLocaleString()} of ${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`
    : `${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');

  // Detect password column index for masking
  passwordColumnIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr>';
  for (const h of passwordsData.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '</tr></thead><tbody>';
  html += buildRowsHtml(passwordRowBuilder, passwordsFiltered, 0, passwordsShown);
  html += '</tbody></table></div>';

  const remaining = passwordsFiltered.length - passwordsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'passwords');
  }

  content.innerHTML = html;
}

function cookieRowBuilder({ row, validity, sessionType }) {
  let html = '<tr>';
  for (const cell of row) {
    html += `<td title="${escapeHtml(cell)}">${escapeHtml(cell)}</td>`;
  }
  html += `<td><span class="validity-badge validity-badge-${validity.status}">${escapeHtml(validity.label)}</span></td>`;
  if (sessionType) {
    const label = sessionType === 'auth' ? 'Auth' : 'Session';
    html += `<td><span class="session-badge session-badge-${sessionType}">${label}</span></td>`;
  } else {
    html += '<td></td>';
  }
  html += '</tr>';
  return html;
}

function renderCookiesPage(validOnly = false, sessionOnly = false, searchQuery = '') {
  const summary = document.getElementById('cookiesSummary');
  const stats = document.getElementById('cookiesStats');
  const content = document.getElementById('cookiesContent');

  if (cookiesData.rows.length === 0) {
    summary.textContent = 'No cookies found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No cookie data available.</div>';
    return;
  }

  let filtered = cookiesData.rows;
  if (validOnly) filtered = filtered.filter(r => r.validity.status === 'valid');
  if (sessionOnly) filtered = filtered.filter(r => r.sessionType);
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(r => r.row.some(cell => cell.toLowerCase().includes(q)));
  }

  cookiesFiltered = filtered;
  cookiesShown = Math.min(PAGE_SIZE, filtered.length);

  const validCount = filtered.filter(r => r.validity.status === 'valid').length;
  const expiredCount = filtered.filter(r => r.validity.status === 'expired').length;
  const browserSessionCount = filtered.filter(r => r.validity.status === 'session').length;
  const authTokenCount = filtered.filter(r => r.sessionType === 'auth').length;
  const sessionTokenCount = filtered.filter(r => r.sessionType === 'session').length;
  const totalSessionTokens = authTokenCount + sessionTokenCount;
  const validAuthCount = filtered.filter(r => r.sessionType && r.validity.status === 'valid').length;

  const totalCookies = cookiesData.rows.length;
  const showingFiltered = filtered.length !== totalCookies;
  summary.textContent = showingFiltered
    ? `Showing ${filtered.length.toLocaleString()} of ${totalCookies.toLocaleString()} cookies from ${cookiesData.fileCount} file(s)`
    : `${totalCookies.toLocaleString()} cookies from ${cookiesData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_cookieFileHint', 'cookies');

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-valid">${validCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Valid</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-expired">${expiredCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Expired</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-session">${browserSessionCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Browser Session</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth">${totalSessionTokens.toLocaleString()}</div>
      <div class="data-page-stat-label">Session Tokens</div>
    </div>
    ${validAuthCount > 0 ? `<div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth-valid">${validAuthCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Valid Sessions</div>
    </div>` : ''}
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr>';
  for (const h of cookiesData.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '<th>Status</th><th>Type</th></tr></thead><tbody>';
  html += buildRowsHtml(cookieRowBuilder, cookiesFiltered, 0, cookiesShown);
  html += '</tbody></table></div>';

  const remaining = cookiesFiltered.length - cookiesShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'cookies');
  }

  content.innerHTML = html;
}

function autofillRowBuilder({ name, value }) {
  return `<tr><td>${escapeHtml(name)}</td><td title="${escapeHtml(value)}">${escapeHtml(value)}</td></tr>`;
}

function renderAutofillsPage(searchQuery = '') {
  const summary = document.getElementById('autofillsSummary');
  const content = document.getElementById('autofillsContent');

  if (autofillsData.entries.length === 0) {
    summary.textContent = 'No autofill data found';
    content.innerHTML = '<div class="no-data">No autofill data available.</div>';
    return;
  }

  let filtered = autofillsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q) || e.value.toLowerCase().includes(q));
  }

  autofillsFiltered = filtered;
  autofillsShown = Math.min(PAGE_SIZE, filtered.length);

  const total = autofillsData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} entries from ${autofillsData.fileCount} file(s)`
    : `${total.toLocaleString()} entries from ${autofillsData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_autofillHint', 'autofill');

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>';
  html += buildRowsHtml(autofillRowBuilder, autofillsFiltered, 0, autofillsShown);
  html += '</tbody></table></div>';

  const remaining = autofillsFiltered.length - autofillsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'autofills');
  }

  content.innerHTML = html;
}

function historyRowBuilder({ url, title, visitCount, lastVisit, lastVisitDate }) {
  const displayLastVisit = lastVisitDate ? formatTimestampDisplay(lastVisitDate) : lastVisit;
  return `<tr><td title="${escapeHtml(url)}">${escapeHtml(url)}</td><td title="${escapeHtml(title)}">${escapeHtml(title)}</td><td>${visitCount}</td><td title="${escapeHtml(lastVisit || displayLastVisit || '')}">${escapeHtml(displayLastVisit || '')}</td></tr>`;
}

function renderHistoryPage(searchQuery = '') {
  const summary = document.getElementById('historySummary');
  const stats = document.getElementById('historyStats');
  const content = document.getElementById('historyContent');

  if (historyData.entries.length === 0) {
    summary.textContent = 'No history found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No history data available.</div>';
    return;
  }

  let filtered = [...historyData.entries];
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e =>
      e.url.toLowerCase().includes(q) ||
      e.title.toLowerCase().includes(q) ||
      e.lastVisit.toLowerCase().includes(q)
    );
  }

  if (historySort.key === 'visits') {
    filtered.sort((a, b) => historySort.order === 'desc' ? b.visitCount - a.visitCount : a.visitCount - b.visitCount);
  } else if (historySort.key === 'lastVisit') {
    filtered.sort((a, b) => {
      const aTime = a.lastVisitDate ? a.lastVisitDate.getTime() : -Infinity;
      const bTime = b.lastVisitDate ? b.lastVisitDate.getTime() : -Infinity;
      return historySort.order === 'desc' ? bTime - aTime : aTime - bTime;
    });
  }

  historyFiltered = filtered;
  historyShown = Math.min(PAGE_SIZE, filtered.length);

  const domainCounts = {};
  for (const { url } of historyData.entries) {
    const domain = extractBaseDomain(extractDomain(url));
    if (!domain) continue;
    domainCounts[domain] = (domainCounts[domain] || 0) + 1;
  }
  const topDomains = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const uniqueDomains = Object.keys(domainCounts).length;
  const datedEntries = historyData.entries.filter(entry => entry.lastVisitDate);
  const mostRecent = datedEntries.length > 0
    ? datedEntries.reduce((latest, entry) => !latest || entry.lastVisitDate > latest.lastVisitDate ? entry : latest, null)
    : null;

  summary.textContent = filtered.length !== historyData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`
    : `${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_historyHint', 'history');

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueDomains.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Domains</div>
    </div>
    ${mostRecent ? `<div class="data-page-stat">
      <div class="data-page-stat-value" style="font-size:0.95rem">${escapeHtml(formatTimestampDisplay(mostRecent.lastVisitDate))}</div>
      <div class="data-page-stat-label">Most Recent Visit</div>
    </div>` : ''}
  `;

  let html = '';
  if (topDomains.length > 0) {
    const maxCount = topDomains[0][1];
    html += '<div class="domain-bars">';
    for (const [domain, count] of topDomains) {
      const pct = Math.round((count / maxCount) * 100);
      html += `<div class="domain-bar-row">
        <span class="domain-bar-label">${escapeHtml(domain)}</span>
        <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
        <span class="domain-bar-count">${count}</span>
      </div>`;
    }
    html += '</div>';
  }

  const visitsSortClass = historySort.key === 'visits' ? `sortable sort-${historySort.order}` : 'sortable';
  const lastVisitSortClass = historySort.key === 'lastVisit' ? `sortable sort-${historySort.order}` : 'sortable';
  html += '<div class="data-table-container"><table class="data-table" id="historyTable">';
  html += `<thead><tr><th>URL</th><th>Title</th><th class="${visitsSortClass}" id="historyVisitsHeader">Visits</th><th class="${lastVisitSortClass}" id="historyLastVisitHeader">Last Visit</th></tr></thead><tbody>`;
  html += buildRowsHtml(historyRowBuilder, historyFiltered, 0, historyShown);
  html += '</tbody></table></div>';

  const remaining = historyFiltered.length - historyShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'history');
  }

  content.innerHTML = html;
}

function bookmarkRowBuilder({ url, title, folder, browser, profile, domain, source }) {
  return `<tr>
    <td title="${escapeHtml(url)}">${escapeHtml(url)}</td>
    <td title="${escapeHtml(title)}">${escapeHtml(title)}</td>
    <td>${escapeHtml(folder || '')}</td>
    <td>${escapeHtml(browser || '')}</td>
    <td>${escapeHtml(profile || '')}</td>
    <td>${escapeHtml(domain || '')}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function renderBookmarksPage(searchQuery = '') {
  const summary = document.getElementById('bookmarksSummary');
  const stats = document.getElementById('bookmarksStats');
  const content = document.getElementById('bookmarksContent');

  if (bookmarksData.entries.length === 0) {
    summary.textContent = 'No bookmarks found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No bookmark data available.</div>';
    return;
  }

  let filtered = bookmarksData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.url.toLowerCase().includes(q) ||
      entry.title.toLowerCase().includes(q) ||
      entry.folder.toLowerCase().includes(q) ||
      entry.browser.toLowerCase().includes(q) ||
      entry.profile.toLowerCase().includes(q) ||
      entry.domain.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  bookmarksFiltered = filtered;
  bookmarksShown = Math.min(PAGE_SIZE, filtered.length);

  const uniqueDomains = new Set(bookmarksData.entries.map(entry => entry.domain).filter(Boolean));
  const withTitles = bookmarksData.entries.filter(entry => entry.title).length;
  const withFolders = bookmarksData.entries.filter(entry => entry.folder).length;
  const browsers = new Set(bookmarksData.entries.map(entry => entry.browser).filter(Boolean));

  summary.textContent = filtered.length !== bookmarksData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${bookmarksData.entries.length.toLocaleString()} bookmarks from ${bookmarksData.fileCount} file(s)`
    : `${bookmarksData.entries.length.toLocaleString()} bookmarks from ${bookmarksData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueDomains.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Domains</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withTitles.toLocaleString()}</div>
      <div class="data-page-stat-label">With Title</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withFolders.toLocaleString()}</div>
      <div class="data-page-stat-label">With Folder</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${browsers.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Browsers</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>URL</th><th>Title</th><th>Folder</th><th>Browser</th><th>Profile</th><th>Domain</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(bookmarkRowBuilder, bookmarksFiltered, 0, bookmarksShown);
  html += '</tbody></table></div>';

  const remaining = bookmarksFiltered.length - bookmarksShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'bookmarks');
  }

  content.innerHTML = html;
}

function browserMetadataRowBuilder({ browser, profile, category, key, value, source }) {
  return `<tr>
    <td>${escapeHtml(browser || '')}</td>
    <td>${escapeHtml(profile || '')}</td>
    <td>${escapeHtml(category || '')}</td>
    <td title="${escapeHtml(key)}">${escapeHtml(key)}</td>
    <td title="${escapeHtml(value)}">${escapeHtml(value)}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function renderBrowserMetaPage(searchQuery = '') {
  const summary = document.getElementById('browserMetaSummary');
  const stats = document.getElementById('browserMetaStats');
  const content = document.getElementById('browserMetaContent');

  if (browserMetadataData.entries.length === 0) {
    summary.textContent = 'No browser metadata found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No browser metadata available.</div>';
    return;
  }

  let filtered = browserMetadataData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.browser.toLowerCase().includes(q) ||
      entry.profile.toLowerCase().includes(q) ||
      entry.category.toLowerCase().includes(q) ||
      entry.key.toLowerCase().includes(q) ||
      entry.value.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  browserMetadataFiltered = filtered;
  browserMetadataShown = Math.min(PAGE_SIZE, filtered.length);

  const categories = new Set(browserMetadataData.entries.map(entry => entry.category).filter(Boolean));
  const browsers = new Set(browserMetadataData.entries.map(entry => entry.browser).filter(Boolean));
  const profiles = new Set(browserMetadataData.entries.map(entry => entry.profile).filter(Boolean));
  const withValues = browserMetadataData.entries.filter(entry => entry.value).length;

  summary.textContent = filtered.length !== browserMetadataData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${browserMetadataData.entries.length.toLocaleString()} metadata rows from ${browserMetadataData.fileCount} file(s)`
    : `${browserMetadataData.entries.length.toLocaleString()} metadata rows from ${browserMetadataData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${browsers.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Browsers</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${profiles.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Profiles</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${categories.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Categories</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withValues.toLocaleString()}</div>
      <div class="data-page-stat-label">With Value</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Browser</th><th>Profile</th><th>Category</th><th>Key</th><th>Value</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(browserMetadataRowBuilder, browserMetadataFiltered, 0, browserMetadataShown);
  html += '</tbody></table></div>';

  const remaining = browserMetadataFiltered.length - browserMetadataShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'browsermeta');
  }

  content.innerHTML = html;
}

function accountTokenRowBuilder({ service, type, value, accountId, browser, profile, note, source }) {
  const displayValue = hideTokenValues ? maskTokenValue(value) : value;
  return `<tr>
    <td>${escapeHtml(service || '')}</td>
    <td>${escapeHtml(type || '')}</td>
    <td title="${escapeHtml(value)}">${escapeHtml(displayValue)}</td>
    <td>${escapeHtml(accountId || '')}</td>
    <td>${escapeHtml(browser || '')}</td>
    <td>${escapeHtml(profile || '')}</td>
    <td title="${escapeHtml(note || '')}">${escapeHtml(note || '')}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function renderTokensPage(searchQuery = '') {
  const summary = document.getElementById('tokensSummary');
  const stats = document.getElementById('tokensStats');
  const content = document.getElementById('tokensContent');

  if (accountTokensData.entries.length === 0) {
    summary.textContent = 'No account tokens found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No account-token data available.</div>';
    return;
  }

  let filtered = accountTokensData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.service.toLowerCase().includes(q) ||
      entry.type.toLowerCase().includes(q) ||
      entry.value.toLowerCase().includes(q) ||
      entry.accountId.toLowerCase().includes(q) ||
      entry.browser.toLowerCase().includes(q) ||
      entry.profile.toLowerCase().includes(q) ||
      entry.note.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  accountTokensFiltered = filtered;
  accountTokensShown = Math.min(PAGE_SIZE, filtered.length);

  const services = new Set(accountTokensData.entries.map(entry => entry.service).filter(Boolean));
  const withValue = accountTokensData.entries.filter(entry => entry.value).length;
  const withAccountId = accountTokensData.entries.filter(entry => entry.accountId).length;
  const tokenTypes = new Set(accountTokensData.entries.map(entry => entry.type).filter(Boolean));

  summary.textContent = filtered.length !== accountTokensData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)`
    : `${accountTokensData.entries.length.toLocaleString()} token rows from ${accountTokensData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${services.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Services</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withValue.toLocaleString()}</div>
      <div class="data-page-stat-label">With Token</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withAccountId.toLocaleString()}</div>
      <div class="data-page-stat-label">With Account ID</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${tokenTypes.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Token Types</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Service</th><th>Type</th><th>Value</th><th>Account ID</th><th>Browser</th><th>Profile</th><th>Note</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(accountTokenRowBuilder, accountTokensFiltered, 0, accountTokensShown);
  html += '</tbody></table></div>';

  const remaining = accountTokensFiltered.length - accountTokensShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'tokens');
  }

  content.innerHTML = html;
}

function serviceArtifactRowBuilder({ service, artifactType, section, key, value, source }) {
  return `<tr>
    <td>${escapeHtml(service || '')}</td>
    <td>${escapeHtml(artifactType || '')}</td>
    <td>${escapeHtml(section || '')}</td>
    <td title="${escapeHtml(key)}">${escapeHtml(key)}</td>
    <td title="${escapeHtml(value)}">${escapeHtml(value)}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function renderServicesPage(searchQuery = '') {
  const summary = document.getElementById('servicesSummary');
  const stats = document.getElementById('servicesStats');
  const content = document.getElementById('servicesContent');

  if (serviceArtifactsData.entries.length === 0) {
    summary.textContent = 'No service artifacts found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No service artifact data available.</div>';
    return;
  }

  let filtered = serviceArtifactsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.service.toLowerCase().includes(q) ||
      entry.artifactType.toLowerCase().includes(q) ||
      entry.section.toLowerCase().includes(q) ||
      entry.key.toLowerCase().includes(q) ||
      entry.value.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  serviceArtifactsFiltered = filtered;
  serviceArtifactsShown = Math.min(PAGE_SIZE, filtered.length);

  const services = new Set(serviceArtifactsData.entries.map(entry => entry.service).filter(Boolean));
  const artifactTypes = new Set(serviceArtifactsData.entries.map(entry => entry.artifactType).filter(Boolean));
  const sections = new Set(serviceArtifactsData.entries.map(entry => entry.section).filter(Boolean));
  const withValue = serviceArtifactsData.entries.filter(entry => entry.value).length;

  summary.textContent = filtered.length !== serviceArtifactsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)`
    : `${serviceArtifactsData.entries.length.toLocaleString()} service rows from ${serviceArtifactsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${services.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Services</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${artifactTypes.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Artifact Types</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${sections.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Sections</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withValue.toLocaleString()}</div>
      <div class="data-page-stat-label">With Value</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Service</th><th>Artifact Type</th><th>Section</th><th>Key</th><th>Value</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(serviceArtifactRowBuilder, serviceArtifactsFiltered, 0, serviceArtifactsShown);
  html += '</tbody></table></div>';

  const remaining = serviceArtifactsFiltered.length - serviceArtifactsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'services');
  }

  content.innerHTML = html;
}

function downloadsRowBuilder({ filePath, sourceUrl, fileSizeDisplay, domain, extension }) {
  return `<tr>
    <td title="${escapeHtml(filePath)}">${escapeHtml(filePath)}</td>
    <td title="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</td>
    <td title="${escapeHtml(fileSizeDisplay || '')}">${escapeHtml(fileSizeDisplay || '')}</td>
    <td>${escapeHtml(extension || '')}</td>
    <td>${escapeHtml(domain || '')}</td>
  </tr>`;
}

function renderDownloadsPage(searchQuery = '') {
  const summary = document.getElementById('downloadsSummary');
  const stats = document.getElementById('downloadsStats');
  const content = document.getElementById('downloadsContent');

  if (downloadsData.entries.length === 0) {
    summary.textContent = 'No downloads found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No download data available.</div>';
    return;
  }

  let filtered = downloadsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e =>
      e.filePath.toLowerCase().includes(q) ||
      e.sourceUrl.toLowerCase().includes(q) ||
      e.fileSizeRaw.toLowerCase().includes(q) ||
      e.fileSizeDisplay.toLowerCase().includes(q) ||
      e.domain.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q)
    );
  }

  downloadsFiltered = filtered;
  downloadsShown = Math.min(PAGE_SIZE, filtered.length);

  const extensionCounts = {};
  let withSourceUrl = 0;
  let withFileSize = 0;
  let totalKnownBytes = 0;
  let knownSizeCount = 0;

  for (const entry of downloadsData.entries) {
    if (entry.extension) extensionCounts[entry.extension] = (extensionCounts[entry.extension] || 0) + 1;
    if (entry.sourceUrl) withSourceUrl++;
    if (entry.fileSizeDisplay) withFileSize++;
    if (entry.fileSizeBytes != null) {
      totalKnownBytes += entry.fileSizeBytes;
      knownSizeCount++;
    }
  }

  const topExtension = Object.entries(extensionCounts).sort((a, b) => b[1] - a[1])[0];
  const totalKnownSizeDisplay = knownSizeCount > 0 ? formatBytes(totalKnownBytes) : '-';

  summary.textContent = filtered.length !== downloadsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`
    : `${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withSourceUrl.toLocaleString()}</div>
      <div class="data-page-stat-label">With Source URL</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withFileSize.toLocaleString()}</div>
      <div class="data-page-stat-label">With File Size</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(topExtension ? topExtension[0] : '-')}</div>
      <div class="data-page-stat-label">Top Extension</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(totalKnownSizeDisplay)}</div>
      <div class="data-page-stat-label">Known Total Size</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>File Path</th><th>Source URL</th><th>File Size</th><th>Extension</th><th>Domain</th></tr></thead><tbody>';
  html += buildRowsHtml(downloadsRowBuilder, downloadsFiltered, 0, downloadsShown);
  html += '</tbody></table></div>';

  const remaining = downloadsFiltered.length - downloadsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'downloads');
  }

  content.innerHTML = html;
}

function detectionRowBuilder({ section, label, target, count }) {
  return `<tr>
    <td>${escapeHtml(section)}</td>
    <td>${escapeHtml(label || '')}</td>
    <td title="${escapeHtml(target)}">${escapeHtml(target)}</td>
    <td>${count}</td>
  </tr>`;
}

function renderDetectionsPage(searchQuery = '') {
  const summary = document.getElementById('detectionsSummary');
  const stats = document.getElementById('detectionsStats');
  const content = document.getElementById('detectionsContent');

  if (domainDetectionsData.entries.length === 0) {
    summary.textContent = 'No domain detections found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No domain-detection data available.</div>';
    return;
  }

  let filtered = domainDetectionsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.section.toLowerCase().includes(q) ||
      entry.label.toLowerCase().includes(q) ||
      entry.target.toLowerCase().includes(q)
    );
  }

  domainDetectionsFiltered = filtered;
  domainDetectionsShown = Math.min(PAGE_SIZE, filtered.length);

  const uniqueTargets = new Set(domainDetectionsData.entries.map(entry => entry.target.toLowerCase()));
  const uniqueSections = new Set(domainDetectionsData.entries.map(entry => entry.section));
  const labelledEntries = domainDetectionsData.entries.filter(entry => entry.label).length;
  const sectionCounts = {};
  for (const entry of domainDetectionsData.entries) {
    sectionCounts[entry.section] = (sectionCounts[entry.section] || 0) + entry.count;
  }
  const topSections = Object.entries(sectionCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  summary.textContent = filtered.length !== domainDetectionsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${domainDetectionsData.entries.length.toLocaleString()} detections from ${domainDetectionsData.fileCount} file(s)`
    : `${domainDetectionsData.entries.length.toLocaleString()} detections from ${domainDetectionsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueTargets.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Targets</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueSections.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Sections</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${labelledEntries.toLocaleString()}</div>
      <div class="data-page-stat-label">Tagged Entries</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${domainDetectionsData.totalHits.toLocaleString()}</div>
      <div class="data-page-stat-label">Total Hits</div>
    </div>
  `;

  let html = '';
  if (topSections.length > 0) {
    const maxCount = topSections[0][1];
    html += '<div class="domain-bars">';
    for (const [sectionName, count] of topSections) {
      const pct = Math.round((count / maxCount) * 100);
      html += `<div class="domain-bar-row">
        <span class="domain-bar-label">${escapeHtml(sectionName)}</span>
        <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
        <span class="domain-bar-count">${count}</span>
      </div>`;
    }
    html += '</div>';
  }

  html += '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Section</th><th>Label</th><th>Target</th><th>Count</th></tr></thead><tbody>';
  html += buildRowsHtml(detectionRowBuilder, domainDetectionsFiltered, 0, domainDetectionsShown);
  html += '</tbody></table></div>';

  const remaining = domainDetectionsFiltered.length - domainDetectionsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'detections');
  }

  content.innerHTML = html;
}

function clipboardRowBuilder({ type, preview, text, urls, lineCount, source }) {
  return `<tr>
    <td>${escapeHtml(type)}</td>
    <td title="${escapeHtml(text)}">${escapeHtml(preview)}</td>
    <td title="${escapeHtml(urls)}">${escapeHtml(urls)}</td>
    <td>${lineCount}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function renderClipboardPage(searchQuery = '') {
  const summary = document.getElementById('clipboardSummary');
  const stats = document.getElementById('clipboardStats');
  const content = document.getElementById('clipboardContent');

  if (clipboardData.entries.length === 0) {
    summary.textContent = 'No clipboard entries found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No clipboard data available.</div>';
    return;
  }

  let filtered = clipboardData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.type.toLowerCase().includes(q) ||
      entry.text.toLowerCase().includes(q) ||
      entry.urls.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  clipboardFiltered = filtered;
  clipboardShown = Math.min(PAGE_SIZE, filtered.length);

  const withUrls = clipboardData.entries.filter(entry => entry.urls).length;
  const commandCount = clipboardData.entries.filter(entry => entry.type === 'Command').length;
  const pathCount = clipboardData.entries.filter(entry => entry.type === 'Path').length;
  const longest = clipboardData.entries.reduce((max, entry) => Math.max(max, entry.length), 0);

  summary.textContent = filtered.length !== clipboardData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${clipboardData.entries.length.toLocaleString()} clipboard entr${clipboardData.entries.length === 1 ? 'y' : 'ies'} from ${clipboardData.fileCount} file(s)`
    : `${clipboardData.entries.length.toLocaleString()} clipboard entr${clipboardData.entries.length === 1 ? 'y' : 'ies'} from ${clipboardData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withUrls.toLocaleString()}</div>
      <div class="data-page-stat-label">With URLs</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${commandCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Commands</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${pathCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Paths</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${longest.toLocaleString()}</div>
      <div class="data-page-stat-label">Longest Entry</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Type</th><th>Content</th><th>URLs</th><th>Lines</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(clipboardRowBuilder, clipboardFiltered, 0, clipboardShown);
  html += '</tbody></table></div>';

  const remaining = clipboardFiltered.length - clipboardShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'clipboard');
  }

  content.innerHTML = html;
}

function creditCardRowBuilder({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) {
  const cardDisplay = hideCardNumbers ? maskCardNumber(cardNumber) : cardNumber;
  const cvcDisplay = hideCardNumbers && cvc ? '\u2022\u2022\u2022' : cvc;
  return `<tr>
    <td title="${escapeHtml(cardNumber)}">${escapeHtml(cardDisplay)}</td>
    <td>${escapeHtml(last4)}</td>
    <td title="${escapeHtml(nameOnCard)}">${escapeHtml(nameOnCard)}</td>
    <td>${escapeHtml(expiration)}</td>
    <td>${escapeHtml(cvcDisplay)}</td>
    <td>${escapeHtml(browser)}</td>
    <td title="${escapeHtml(filePath || source)}">${escapeHtml(trimRootPath(filePath || source))}</td>
  </tr>`;
}

function renderCardsPage(searchQuery = '') {
  const summary = document.getElementById('cardsSummary');
  const stats = document.getElementById('cardsStats');
  const content = document.getElementById('cardsContent');

  if (creditCardsData.entries.length === 0) {
    summary.textContent = 'No credit cards found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No credit-card data available.</div>';
    return;
  }

  let filtered = creditCardsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.cardNumber.toLowerCase().includes(q) ||
      entry.last4.toLowerCase().includes(q) ||
      entry.nameOnCard.toLowerCase().includes(q) ||
      entry.expiration.toLowerCase().includes(q) ||
      entry.cvc.toLowerCase().includes(q) ||
      entry.browser.toLowerCase().includes(q) ||
      entry.filePath.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  creditCardsFiltered = filtered;
  creditCardsShown = Math.min(PAGE_SIZE, filtered.length);

  const withHolder = creditCardsData.entries.filter(entry => entry.nameOnCard).length;
  const withCvc = creditCardsData.entries.filter(entry => entry.cvc).length;
  const withExpiry = creditCardsData.entries.filter(entry => entry.expiration && entry.expiration !== '/').length;
  const uniqueLast4 = new Set(creditCardsData.entries.map(entry => entry.last4).filter(Boolean));

  summary.textContent = filtered.length !== creditCardsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)`
    : `${creditCardsData.entries.length.toLocaleString()} cards from ${creditCardsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueLast4.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Last4</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withHolder.toLocaleString()}</div>
      <div class="data-page-stat-label">With Cardholder</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withCvc.toLocaleString()}</div>
      <div class="data-page-stat-label">With CVC</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withExpiry.toLocaleString()}</div>
      <div class="data-page-stat-label">With Expiry</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Card Number</th><th>Last4</th><th>Name On Card</th><th>Expiration</th><th>CVC</th><th>Browser</th><th>Recovered From</th></tr></thead><tbody>';
  html += buildRowsHtml(creditCardRowBuilder, creditCardsFiltered, 0, creditCardsShown);
  html += '</tbody></table></div>';

  const remaining = creditCardsFiltered.length - creditCardsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'cards');
  }

  content.innerHTML = html;
}

function screenshotCardBuilder(entry, index) {
  const dimensions = entry.width && entry.height ? `${entry.width}×${entry.height}` : 'Unknown size';
  return `<article class="screenshot-card">
    <button class="screenshot-card-thumb" data-screenshot-idx="${index}" title="Open screenshot">
      <img src="${entry.blobUrl}" alt="${escapeHtml(entry.name)}">
    </button>
    <div class="screenshot-card-meta">
      <div class="screenshot-card-name" title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</div>
      <div class="screenshot-card-info">${escapeHtml(dimensions)} · ${escapeHtml(entry.sizeDisplay)}</div>
      <div class="screenshot-card-path" title="${escapeHtml(entry.path)}">${escapeHtml(trimRootPath(entry.path))}</div>
    </div>
  </article>`;
}

function openScreenshotLightbox(entry) {
  if (!entry || !entry.blobUrl) return;
  const lightbox = document.createElement('div');
  lightbox.className = 'screenshot-lightbox';
  lightbox.innerHTML = `<img src="${entry.blobUrl}" alt="${escapeHtml(entry.name)}">`;
  lightbox.addEventListener('click', () => lightbox.remove());
  document.body.appendChild(lightbox);
}

function renderScreenshotsPage(searchQuery = '') {
  const summary = document.getElementById('screenshotsSummary');
  const stats = document.getElementById('screenshotsStats');
  const content = document.getElementById('screenshotsContent');

  if (screenshotsData.entries.length === 0) {
    summary.textContent = 'No screenshots found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No screenshots available.</div>';
    return;
  }

  let filtered = screenshotsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.name.toLowerCase().includes(q) ||
      entry.path.toLowerCase().includes(q) ||
      `${entry.width || ''}x${entry.height || ''}`.toLowerCase().includes(q)
    );
  }

  screenshotsFiltered = filtered;
  screenshotsShown = Math.min(PAGE_SIZE, filtered.length);

  const knownDimensions = screenshotsData.entries.filter(entry => entry.width && entry.height).length;
  const largest = screenshotsData.entries.reduce((max, entry) => !max || entry.sizeBytes > max.sizeBytes ? entry : max, null);
  const highestResolution = screenshotsData.entries.reduce((max, entry) => {
    const area = (entry.width || 0) * (entry.height || 0);
    const maxArea = max ? (max.width || 0) * (max.height || 0) : 0;
    return area > maxArea ? entry : max;
  }, null);

  summary.textContent = filtered.length !== screenshotsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${screenshotsData.entries.length.toLocaleString()} screenshots`
    : `${screenshotsData.entries.length.toLocaleString()} screenshots`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${screenshotsData.entries.length.toLocaleString()}</div>
      <div class="data-page-stat-label">Images</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${knownDimensions.toLocaleString()}</div>
      <div class="data-page-stat-label">With Dimensions</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(formatBytes(screenshotsData.totalBytes))}</div>
      <div class="data-page-stat-label">Total Size</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(highestResolution && highestResolution.width ? `${highestResolution.width}×${highestResolution.height}` : (largest ? largest.sizeDisplay : '-'))}</div>
      <div class="data-page-stat-label">${highestResolution && highestResolution.width ? 'Top Resolution' : 'Largest File'}</div>
    </div>
  `;

  let html = '<div class="screenshot-grid">';
  html += buildRowsHtml(screenshotCardBuilder, screenshotsFiltered, 0, screenshotsShown);
  html += '</div>';

  const remaining = screenshotsFiltered.length - screenshotsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'screenshots');
  }

  content.innerHTML = html;
}

// Software rendering

function softwareRowBuilder({ name, version }) {
  return `<tr><td title="${escapeHtml(name)}">${escapeHtml(name)}</td><td>${escapeHtml(version || '')}</td></tr>`;
}

function renderSoftwarePage(searchQuery = '') {
  const summary = document.getElementById('softwareSummary');
  const content = document.getElementById('softwareContent');

  if (softwareData.entries.length === 0) {
    summary.textContent = 'No software data found';
    content.innerHTML = '<div class="no-data">No software data available.</div>';
    return;
  }

  let filtered = softwareData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q) || (e.version && e.version.toLowerCase().includes(q)));
  }

  softwareFiltered = filtered;
  softwareShown = Math.min(PAGE_SIZE, filtered.length);

  const total = softwareData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} programs from ${softwareData.fileCount} file(s)`
    : `${total.toLocaleString()} programs from ${softwareData.fileCount} file(s)`;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Software Name</th><th>Version</th></tr></thead><tbody>';
  html += buildRowsHtml(softwareRowBuilder, softwareFiltered, 0, softwareShown);
  html += '</tbody></table></div>';

  const remaining = softwareFiltered.length - softwareShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'software');
  }

  content.innerHTML = html;
}

// Process list rendering

function processRowBuilder({ name, pid }) {
  return `<tr><td title="${escapeHtml(name)}">${escapeHtml(name)}</td><td>${pid ? escapeHtml(String(pid)) : ''}</td></tr>`;
}

function renderProcessesPage(searchQuery = '') {
  const summary = document.getElementById('processesSummary');
  const content = document.getElementById('processesContent');

  if (processListData.entries.length === 0) {
    summary.textContent = 'No process data found';
    content.innerHTML = '<div class="no-data">No process data available.</div>';
    return;
  }

  let filtered = processListData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q));
  }

  processesFiltered = filtered;
  processesShown = Math.min(PAGE_SIZE, filtered.length);

  const total = processListData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`
    : `${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Process Name</th><th>PID</th></tr></thead><tbody>';
  html += buildRowsHtml(processRowBuilder, processesFiltered, 0, processesShown);
  html += '</tbody></table></div>';

  const remaining = processesFiltered.length - processesShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'processes');
  }

  content.innerHTML = html;
}

// CSV export

function escapeCSV(str) {
  if (str == null) return '';
  const s = String(str);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function exportPasswordsCSV() {
  if (passwordsData.rows.length === 0) return;
  let csv = passwordsData.headers.map(escapeCSV).join(',') + '\n';
  for (const { row } of passwordsData.rows) {
    csv += row.map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'passwords.csv', 'text/csv');
}

function exportCookiesCSV() {
  if (cookiesData.rows.length === 0) return;
  const headers = [...cookiesData.headers, 'Status', 'Session Type'];
  let csv = headers.map(escapeCSV).join(',') + '\n';
  for (const { row, validity, sessionType } of cookiesData.rows) {
    const typeLabel = sessionType === 'auth' ? 'Auth' : sessionType === 'session' ? 'Session' : '';
    csv += [...row, validity.label, typeLabel].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'cookies.csv', 'text/csv');
}

function exportAutofillsCSV() {
  if (autofillsData.entries.length === 0) return;
  let csv = 'Field,Value\n';
  for (const { name, value } of autofillsData.entries) {
    csv += [name, value].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'autofills.csv', 'text/csv');
}

function exportHistoryCSV() {
  if (historyData.entries.length === 0) return;
  let csv = 'URL,Title,Visits,Last Visit\n';
  for (const { url, title, visitCount, lastVisit, lastVisitDate } of historyData.entries) {
    csv += [url, title, visitCount, lastVisitDate ? lastVisitDate.toISOString() : lastVisit].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'history.csv', 'text/csv');
}

function exportBookmarksCSV() {
  if (bookmarksData.entries.length === 0) return;
  let csv = 'URL,Title,Folder,Browser,Profile,Domain,Source\n';
  for (const { url, title, folder, browser, profile, domain, source } of bookmarksData.entries) {
    csv += [url, title, folder, browser, profile, domain, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'bookmarks.csv', 'text/csv');
}

function exportBrowserMetadataCSV() {
  if (browserMetadataData.entries.length === 0) return;
  let csv = 'Browser,Profile,Category,Key,Value,Source\n';
  for (const { browser, profile, category, key, value, source } of browserMetadataData.entries) {
    csv += [browser, profile, category, key, value, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'browser_metadata.csv', 'text/csv');
}

function exportTokensCSV() {
  if (accountTokensData.entries.length === 0) return;
  let csv = 'Service,Type,Value,Account ID,Browser,Profile,Note,Source\n';
  for (const { service, type, value, accountId, browser, profile, note, source } of accountTokensData.entries) {
    csv += [service, type, value, accountId, browser, profile, note, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'account_tokens.csv', 'text/csv');
}

function exportServicesCSV() {
  if (serviceArtifactsData.entries.length === 0) return;
  let csv = 'Service,Artifact Type,Section,Key,Value,Source\n';
  for (const { service, artifactType, section, key, value, source } of serviceArtifactsData.entries) {
    csv += [service, artifactType, section, key, value, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'service_artifacts.csv', 'text/csv');
}

function exportDownloadsCSV() {
  if (downloadsData.entries.length === 0) return;
  let csv = 'File Path,Source URL,File Size,Extension,Domain\n';
  for (const { filePath, sourceUrl, fileSizeRaw, fileSizeDisplay, extension, domain } of downloadsData.entries) {
    csv += [filePath, sourceUrl, fileSizeRaw || fileSizeDisplay, extension, domain].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'downloads.csv', 'text/csv');
}

function exportDetectionsCSV() {
  if (domainDetectionsData.entries.length === 0) return;
  let csv = 'Section,Label,Target,Count,Source\n';
  for (const { section, label, target, count, source } of domainDetectionsData.entries) {
    csv += [section, label, target, count, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'domain_detections.csv', 'text/csv');
}

function exportClipboardCSV() {
  if (clipboardData.entries.length === 0) return;
  let csv = 'Type,Text,URLs,Line Count,Length,Source\n';
  for (const { type, text, urls, lineCount, length, source } of clipboardData.entries) {
    csv += [type, text, urls, lineCount, length, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'clipboard.csv', 'text/csv');
}

function exportCardsCSV() {
  if (creditCardsData.entries.length === 0) return;
  let csv = 'Card Number,Last4,Name On Card,Expiration,CVC,Browser,Recovered From,Source\n';
  for (const { cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source } of creditCardsData.entries) {
    csv += [cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'credit_cards.csv', 'text/csv');
}

function exportScreenshotsCSV() {
  if (screenshotsData.entries.length === 0) return;
  let csv = 'Name,Path,Width,Height,Size Bytes\n';
  for (const { name, path, width, height, sizeBytes } of screenshotsData.entries) {
    csv += [name, path, width || '', height || '', sizeBytes].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'screenshots.csv', 'text/csv');
}

function exportSoftwareCSV() {
  if (softwareData.entries.length === 0) return;
  let csv = 'Software Name,Version\n';
  for (const { name, version } of softwareData.entries) {
    csv += [name, version || ''].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'software.csv', 'text/csv');
}

function exportProcessesCSV() {
  if (processListData.entries.length === 0) return;
  let csv = 'Process Name,PID\n';
  for (const { name, pid } of processListData.entries) {
    csv += [name, pid || ''].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'processes.csv', 'text/csv');
}

// Show-more handler appends rows to existing tbody

function handleShowMore(pageId, contentEl) {
  let filtered, shown, rowBuilder;

  if (pageId === 'passwords') {
    filtered = passwordsFiltered; shown = passwordsShown; rowBuilder = passwordRowBuilder;
  } else if (pageId === 'cookies') {
    filtered = cookiesFiltered; shown = cookiesShown; rowBuilder = cookieRowBuilder;
  } else if (pageId === 'autofills') {
    filtered = autofillsFiltered; shown = autofillsShown; rowBuilder = autofillRowBuilder;
  } else if (pageId === 'history') {
    filtered = historyFiltered; shown = historyShown; rowBuilder = historyRowBuilder;
  } else if (pageId === 'bookmarks') {
    filtered = bookmarksFiltered; shown = bookmarksShown; rowBuilder = bookmarkRowBuilder;
  } else if (pageId === 'browsermeta') {
    filtered = browserMetadataFiltered; shown = browserMetadataShown; rowBuilder = browserMetadataRowBuilder;
  } else if (pageId === 'tokens') {
    filtered = accountTokensFiltered; shown = accountTokensShown; rowBuilder = accountTokenRowBuilder;
  } else if (pageId === 'services') {
    filtered = serviceArtifactsFiltered; shown = serviceArtifactsShown; rowBuilder = serviceArtifactRowBuilder;
  } else if (pageId === 'downloads') {
    filtered = downloadsFiltered; shown = downloadsShown; rowBuilder = downloadsRowBuilder;
  } else if (pageId === 'detections') {
    filtered = domainDetectionsFiltered; shown = domainDetectionsShown; rowBuilder = detectionRowBuilder;
  } else if (pageId === 'clipboard') {
    filtered = clipboardFiltered; shown = clipboardShown; rowBuilder = clipboardRowBuilder;
  } else if (pageId === 'cards') {
    filtered = creditCardsFiltered; shown = creditCardsShown; rowBuilder = creditCardRowBuilder;
  } else if (pageId === 'screenshots') {
    filtered = screenshotsFiltered; shown = screenshotsShown; rowBuilder = screenshotCardBuilder;
  } else if (pageId === 'software') {
    filtered = softwareFiltered; shown = softwareShown; rowBuilder = softwareRowBuilder;
  } else if (pageId === 'processes') {
    filtered = processesFiltered; shown = processesShown; rowBuilder = processRowBuilder;
  } else {
    return;
  }

  const nextEnd = Math.min(shown + PAGE_SIZE, filtered.length);
  const newRowsHtml = buildRowsHtml(rowBuilder, filtered, shown, nextEnd);

  const tbody = contentEl.querySelector('tbody');
  const screenshotGrid = contentEl.querySelector('.screenshot-grid');
  if (tbody) {
    tbody.insertAdjacentHTML('beforeend', newRowsHtml);
  } else if (screenshotGrid && pageId === 'screenshots') {
    screenshotGrid.insertAdjacentHTML('beforeend', newRowsHtml);
  }

  if (pageId === 'passwords') passwordsShown = nextEnd;
  else if (pageId === 'cookies') cookiesShown = nextEnd;
  else if (pageId === 'autofills') autofillsShown = nextEnd;
  else if (pageId === 'history') historyShown = nextEnd;
  else if (pageId === 'bookmarks') bookmarksShown = nextEnd;
  else if (pageId === 'browsermeta') browserMetadataShown = nextEnd;
  else if (pageId === 'tokens') accountTokensShown = nextEnd;
  else if (pageId === 'services') serviceArtifactsShown = nextEnd;
  else if (pageId === 'downloads') downloadsShown = nextEnd;
  else if (pageId === 'detections') domainDetectionsShown = nextEnd;
  else if (pageId === 'clipboard') clipboardShown = nextEnd;
  else if (pageId === 'cards') creditCardsShown = nextEnd;
  else if (pageId === 'screenshots') screenshotsShown = nextEnd;
  else if (pageId === 'software') softwareShown = nextEnd;
  else if (pageId === 'processes') processesShown = nextEnd;

  const btn = contentEl.querySelector('.data-show-more');
  const remaining = filtered.length - nextEnd;
  if (remaining > 0 && btn) {
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
  } else if (btn) {
    btn.remove();
  }
}

// Init

function initDataPages() {
  const passwordsSearch = document.getElementById('passwordsSearch');
  const passwordsHideCb = document.getElementById('passwordsHidePasswords');
  let pwDebounce = null;
  passwordsSearch?.addEventListener('input', () => {
    clearTimeout(pwDebounce);
    pwDebounce = setTimeout(() => {
      renderPasswordsPage(passwordsSearch.value);
    }, 150);
  });

  passwordsHideCb?.addEventListener('change', () => {
    hidePasswords = passwordsHideCb.checked;
    renderPasswordsPage(passwordsSearch?.value || '');
  });

  // Click-to-reveal individual masked passwords
  document.getElementById('passwordsContent')?.addEventListener('click', (e) => {
    const cell = e.target.closest('.password-cell.masked');
    if (!cell) return;
    // Find which row this is in the table
    const tr = cell.closest('tr');
    if (!tr) return;
    const tbody = tr.closest('tbody');
    if (!tbody) return;
    const rowIdx = Array.from(tbody.rows).indexOf(tr);
    if (rowIdx >= 0 && rowIdx < passwordsFiltered.length) {
      const realValue = passwordsFiltered[rowIdx].row[passwordColumnIdx];
      cell.textContent = realValue;
      cell.title = realValue;
      cell.classList.remove('masked');
      cell.classList.add('revealed');
      // Re-mask after 5 seconds
      setTimeout(() => {
        if (hidePasswords && cell.classList.contains('revealed')) {
          cell.textContent = maskValue(realValue);
          cell.title = 'Click to reveal';
          cell.classList.remove('revealed');
          cell.classList.add('masked');
        }
      }, 5000);
    }
  });

  const cookiesSearch = document.getElementById('cookiesSearch');
  const cookiesValidOnly = document.getElementById('cookiesValidOnly');
  const cookiesSessionOnly = document.getElementById('cookiesSessionOnly');
  let ckDebounce = null;

  const updateCookies = () => {
    clearTimeout(ckDebounce);
    ckDebounce = setTimeout(() => {
      renderCookiesPage(
        cookiesValidOnly?.checked || false,
        cookiesSessionOnly?.checked || false,
        cookiesSearch?.value || ''
      );
    }, 150);
  };

  cookiesSearch?.addEventListener('input', updateCookies);
  cookiesValidOnly?.addEventListener('change', updateCookies);
  cookiesSessionOnly?.addEventListener('change', updateCookies);

  const autofillsSearch = document.getElementById('autofillsSearch');
  let afDebounce = null;
  autofillsSearch?.addEventListener('input', () => {
    clearTimeout(afDebounce);
    afDebounce = setTimeout(() => {
      renderAutofillsPage(autofillsSearch.value);
    }, 150);
  });

  const historySearch = document.getElementById('historySearch');
  let hsDebounce = null;
  historySearch?.addEventListener('input', () => {
    clearTimeout(hsDebounce);
    hsDebounce = setTimeout(() => {
      renderHistoryPage(historySearch.value);
    }, 150);
  });

  const bookmarksSearch = document.getElementById('bookmarksSearch');
  let bmDebounce = null;
  bookmarksSearch?.addEventListener('input', () => {
    clearTimeout(bmDebounce);
    bmDebounce = setTimeout(() => {
      renderBookmarksPage(bookmarksSearch.value);
    }, 150);
  });

  const browserMetaSearch = document.getElementById('browserMetaSearch');
  let metaDebounce = null;
  browserMetaSearch?.addEventListener('input', () => {
    clearTimeout(metaDebounce);
    metaDebounce = setTimeout(() => {
      renderBrowserMetaPage(browserMetaSearch.value);
    }, 150);
  });

  const tokensSearch = document.getElementById('tokensSearch');
  const tokensHideSensitive = document.getElementById('tokensHideSensitive');
  let tokDebounce = null;
  tokensSearch?.addEventListener('input', () => {
    clearTimeout(tokDebounce);
    tokDebounce = setTimeout(() => {
      renderTokensPage(tokensSearch.value);
    }, 150);
  });
  tokensHideSensitive?.addEventListener('change', () => {
    hideTokenValues = tokensHideSensitive.checked;
    renderTokensPage(tokensSearch?.value || '');
  });

  const servicesSearch = document.getElementById('servicesSearch');
  let svcDebounce = null;
  servicesSearch?.addEventListener('input', () => {
    clearTimeout(svcDebounce);
    svcDebounce = setTimeout(() => {
      renderServicesPage(servicesSearch.value);
    }, 150);
  });

  const downloadsSearch = document.getElementById('downloadsSearch');
  let dlDebounce = null;
  downloadsSearch?.addEventListener('input', () => {
    clearTimeout(dlDebounce);
    dlDebounce = setTimeout(() => {
      renderDownloadsPage(downloadsSearch.value);
    }, 150);
  });

  const detectionsSearch = document.getElementById('detectionsSearch');
  let ddDebounce = null;
  detectionsSearch?.addEventListener('input', () => {
    clearTimeout(ddDebounce);
    ddDebounce = setTimeout(() => {
      renderDetectionsPage(detectionsSearch.value);
    }, 150);
  });

  const clipboardSearch = document.getElementById('clipboardSearch');
  let cbDebounce = null;
  clipboardSearch?.addEventListener('input', () => {
    clearTimeout(cbDebounce);
    cbDebounce = setTimeout(() => {
      renderClipboardPage(clipboardSearch.value);
    }, 150);
  });

  const cardsSearch = document.getElementById('cardsSearch');
  const cardsHideSensitive = document.getElementById('cardsHideSensitive');
  let cardsDebounce = null;
  cardsSearch?.addEventListener('input', () => {
    clearTimeout(cardsDebounce);
    cardsDebounce = setTimeout(() => {
      renderCardsPage(cardsSearch.value);
    }, 150);
  });
  cardsHideSensitive?.addEventListener('change', () => {
    hideCardNumbers = cardsHideSensitive.checked;
    renderCardsPage(cardsSearch?.value || '');
  });

  const screenshotsSearch = document.getElementById('screenshotsSearch');
  let ssDebounce = null;
  screenshotsSearch?.addEventListener('input', () => {
    clearTimeout(ssDebounce);
    ssDebounce = setTimeout(() => {
      renderScreenshotsPage(screenshotsSearch.value);
    }, 150);
  });

  // Sort toggle on History headers
  document.getElementById('historyContent')?.addEventListener('click', (e) => {
    const header = e.target.closest('#historyVisitsHeader, #historyLastVisitHeader');
    if (!header) return;
    const nextKey = header.id === 'historyLastVisitHeader' ? 'lastVisit' : 'visits';
    if (historySort.key !== nextKey) {
      historySort = { key: nextKey, order: 'desc' };
    } else if (historySort.order === 'desc') {
      historySort = { key: nextKey, order: 'asc' };
    } else {
      historySort = { key: 'none', order: 'none' };
    }
    renderHistoryPage(historySearch?.value || '');
  });

  // Software search
  const softwareSearch = document.getElementById('softwareSearch');
  let swDebounce = null;
  softwareSearch?.addEventListener('input', () => {
    clearTimeout(swDebounce);
    swDebounce = setTimeout(() => {
      renderSoftwarePage(softwareSearch.value);
    }, 150);
  });

  // Process search
  const processesSearch = document.getElementById('processesSearch');
  let prDebounce = null;
  processesSearch?.addEventListener('input', () => {
    clearTimeout(prDebounce);
    prDebounce = setTimeout(() => {
      renderProcessesPage(processesSearch.value);
    }, 150);
  });

  // Delegated show-more handlers
  for (const id of ['passwordsContent', 'cookiesContent', 'autofillsContent', 'historyContent', 'bookmarksContent', 'browserMetaContent', 'tokensContent', 'servicesContent', 'downloadsContent', 'detectionsContent', 'clipboardContent', 'cardsContent', 'screenshotsContent', 'softwareContent', 'processesContent']) {
    const el = document.getElementById(id);
    el?.addEventListener('click', (e) => {
      const screenshotBtn = e.target.closest('[data-screenshot-idx]');
      if (screenshotBtn && id === 'screenshotsContent') {
        const idx = parseInt(screenshotBtn.dataset.screenshotIdx, 10);
        if (idx >= 0 && idx < screenshotsFiltered.length) openScreenshotLightbox(screenshotsFiltered[idx]);
        return;
      }
      const btn = e.target.closest('.data-show-more');
      if (!btn) return;
      handleShowMore(btn.dataset.page, el);
    });
  }

  // Export buttons
  document.getElementById('exportPasswordsCsv')?.addEventListener('click', exportPasswordsCSV);
  document.getElementById('exportCookiesCsv')?.addEventListener('click', exportCookiesCSV);
  document.getElementById('exportAutofillsCsv')?.addEventListener('click', exportAutofillsCSV);
  document.getElementById('exportHistoryCsv')?.addEventListener('click', exportHistoryCSV);
  document.getElementById('exportBookmarksCsv')?.addEventListener('click', exportBookmarksCSV);
  document.getElementById('exportBrowserMetaCsv')?.addEventListener('click', exportBrowserMetadataCSV);
  document.getElementById('exportTokensCsv')?.addEventListener('click', exportTokensCSV);
  document.getElementById('exportServicesCsv')?.addEventListener('click', exportServicesCSV);
  document.getElementById('exportDownloadsCsv')?.addEventListener('click', exportDownloadsCSV);
  document.getElementById('exportDetectionsCsv')?.addEventListener('click', exportDetectionsCSV);
  document.getElementById('exportClipboardCsv')?.addEventListener('click', exportClipboardCSV);
  document.getElementById('exportCardsCsv')?.addEventListener('click', exportCardsCSV);
  document.getElementById('exportScreenshotsCsv')?.addEventListener('click', exportScreenshotsCSV);
  document.getElementById('exportSoftwareCsv')?.addEventListener('click', exportSoftwareCSV);
  document.getElementById('exportProcessesCsv')?.addEventListener('click', exportProcessesCSV);

  async function reloadData() {
    if (!state.fileTree) return;

    await Promise.all([
      loadPasswordsData(state.fileTree, state.rootZipName),
      loadCookiesData(state.fileTree, state.rootZipName),
      loadAutofillsData(state.fileTree, state.rootZipName),
      loadHistoryData(state.fileTree, state.rootZipName),
      loadBookmarksData(state.fileTree, state.rootZipName),
      loadBrowserMetadataData(state.fileTree, state.rootZipName),
      loadAccountTokensData(state.fileTree, state.rootZipName),
      loadServiceArtifactsData(state.fileTree, state.rootZipName),
      loadDownloadsData(state.fileTree, state.rootZipName),
      loadDomainDetectionsData(state.fileTree, state.rootZipName),
      loadClipboardData(state.fileTree, state.rootZipName),
      loadCreditCardsData(state.fileTree, state.rootZipName),
      loadScreenshotsData(state.fileTree, state.rootZipName),
    ]);
    emit('data:loaded');

    document.getElementById('navPasswords').disabled = passwordsData.rows.length === 0;
    document.getElementById('navCookies').disabled = cookiesData.rows.length === 0;
    document.getElementById('navAutofills').disabled = autofillsData.entries.length === 0;
    document.getElementById('navHistory').disabled = historyData.entries.length === 0;
    document.getElementById('navBookmarks').disabled = bookmarksData.entries.length === 0;
    document.getElementById('navBrowserMeta').disabled = browserMetadataData.entries.length === 0;
    document.getElementById('navTokens').disabled = accountTokensData.entries.length === 0;
    document.getElementById('navServices').disabled = serviceArtifactsData.entries.length === 0;
    document.getElementById('navDownloads').disabled = downloadsData.entries.length === 0;
    document.getElementById('navDetections').disabled = domainDetectionsData.entries.length === 0;
    document.getElementById('navClipboard').disabled = clipboardData.entries.length === 0;
    document.getElementById('navCards').disabled = creditCardsData.entries.length === 0;
    document.getElementById('navScreenshots').disabled = screenshotsData.entries.length === 0;
  }

  on('extracted', reloadData);
  on('reanalyze', reloadData);

  on('page:passwords', () => renderPasswordsPage(passwordsSearch?.value || ''));
  on('page:cookies', () => renderCookiesPage(cookiesValidOnly?.checked || false, cookiesSessionOnly?.checked || false, cookiesSearch?.value || ''));
  on('page:autofills', () => renderAutofillsPage(autofillsSearch?.value || ''));
  on('page:history', () => renderHistoryPage(historySearch?.value || ''));
  on('page:bookmarks', () => renderBookmarksPage(bookmarksSearch?.value || ''));
  on('page:browsermeta', () => renderBrowserMetaPage(browserMetaSearch?.value || ''));
  on('page:tokens', () => renderTokensPage(tokensSearch?.value || ''));
  on('page:services', () => renderServicesPage(servicesSearch?.value || ''));
  on('page:downloads', () => renderDownloadsPage(downloadsSearch?.value || ''));
  on('page:detections', () => renderDetectionsPage(detectionsSearch?.value || ''));
  on('page:clipboard', () => renderClipboardPage(clipboardSearch?.value || ''));
  on('page:cards', () => renderCardsPage(cardsSearch?.value || ''));
  on('page:screenshots', () => renderScreenshotsPage(screenshotsSearch?.value || ''));
  on('page:software', () => renderSoftwarePage(softwareSearch?.value || ''));
  on('page:processes', () => renderProcessesPage(processesSearch?.value || ''));

  on('analysis:software', (data) => {
    if (data && data.entries.length > 0) {
      softwareData = data;
      document.getElementById('navSoftware').disabled = false;
    }
  });

  on('analysis:processList', (data) => {
    if (data && data.entries.length > 0) {
      processListData = data;
      document.getElementById('navProcesses').disabled = false;
    }
  });

  on('reset', () => {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    autofillsData = { entries: [], fileCount: 0 };
    historyData = { entries: [], fileCount: 0 };
    bookmarksData = { entries: [], fileCount: 0 };
    browserMetadataData = { entries: [], fileCount: 0 };
    accountTokensData = { entries: [], fileCount: 0 };
    serviceArtifactsData = { entries: [], fileCount: 0 };
    downloadsData = { entries: [], fileCount: 0 };
    domainDetectionsData = { entries: [], fileCount: 0, totalHits: 0 };
    clipboardData = { entries: [], fileCount: 0 };
    creditCardsData = { entries: [], fileCount: 0 };
    revokeScreenshotUrls();
    screenshotsData = { entries: [], fileCount: 0, totalBytes: 0 };
    historySort = { key: 'none', order: 'none' };
    passwordsFiltered = []; passwordsShown = 0;
    cookiesFiltered = []; cookiesShown = 0;
    autofillsFiltered = []; autofillsShown = 0;
    historyFiltered = []; historyShown = 0;
    bookmarksFiltered = []; bookmarksShown = 0;
    browserMetadataFiltered = []; browserMetadataShown = 0;
    accountTokensFiltered = []; accountTokensShown = 0;
    serviceArtifactsFiltered = []; serviceArtifactsShown = 0;
    downloadsFiltered = []; downloadsShown = 0;
    domainDetectionsFiltered = []; domainDetectionsShown = 0;
    clipboardFiltered = []; clipboardShown = 0;
    creditCardsFiltered = []; creditCardsShown = 0;
    screenshotsFiltered = []; screenshotsShown = 0;
    softwareData = { entries: [], fileCount: 0, totalCount: 0 };
    processListData = { entries: [], fileCount: 0, uniqueCount: 0 };
    softwareFiltered = []; softwareShown = 0;
    processesFiltered = []; processesShown = 0;

    document.getElementById('navPasswords').disabled = true;
    document.getElementById('navCookies').disabled = true;
    document.getElementById('navAutofills').disabled = true;
    document.getElementById('navHistory').disabled = true;
    document.getElementById('navBookmarks').disabled = true;
    document.getElementById('navBrowserMeta').disabled = true;
    document.getElementById('navTokens').disabled = true;
    document.getElementById('navServices').disabled = true;
    document.getElementById('navDownloads').disabled = true;
    document.getElementById('navDetections').disabled = true;
    document.getElementById('navClipboard').disabled = true;
    document.getElementById('navCards').disabled = true;
    document.getElementById('navScreenshots').disabled = true;
    document.getElementById('navSoftware').disabled = true;
    document.getElementById('navProcesses').disabled = true;

    if (passwordsSearch) passwordsSearch.value = '';
    if (softwareSearch) softwareSearch.value = '';
    if (processesSearch) processesSearch.value = '';
    if (cookiesSearch) cookiesSearch.value = '';
    if (autofillsSearch) autofillsSearch.value = '';
    if (historySearch) historySearch.value = '';
    if (bookmarksSearch) bookmarksSearch.value = '';
    if (browserMetaSearch) browserMetaSearch.value = '';
    if (tokensSearch) tokensSearch.value = '';
    if (servicesSearch) servicesSearch.value = '';
    if (downloadsSearch) downloadsSearch.value = '';
    if (detectionsSearch) detectionsSearch.value = '';
    if (clipboardSearch) clipboardSearch.value = '';
    if (cardsSearch) cardsSearch.value = '';
    if (screenshotsSearch) screenshotsSearch.value = '';
    if (cookiesValidOnly) cookiesValidOnly.checked = false;
    if (cookiesSessionOnly) cookiesSessionOnly.checked = false;
    if (passwordsHideCb) passwordsHideCb.checked = true;
    if (cardsHideSensitive) cardsHideSensitive.checked = true;
    if (tokensHideSensitive) tokensHideSensitive.checked = true;
    hidePasswords = true;
    hideCardNumbers = true;
    hideTokenValues = true;
    passwordColumnIdx = -1;
  });
}

// Getters for cross-module access

function getPasswordsData() { return passwordsData; }
function getCookiesData() { return cookiesData; }
function getAutofillsData() { return autofillsData; }
function getHistoryData() { return historyData; }
function getBookmarksData() { return bookmarksData; }
function getBrowserMetadataData() { return browserMetadataData; }
function getAccountTokensData() { return accountTokensData; }
function getServiceArtifactsData() { return serviceArtifactsData; }
function getDownloadsData() { return downloadsData; }
function getDomainDetectionsData() { return domainDetectionsData; }
function getClipboardData() { return clipboardData; }
function getCreditCardsData() { return creditCardsData; }
function getScreenshotsData() { return screenshotsData; }
function getSoftwareData() { return softwareData; }
function getProcessListData() { return processListData; }

export {
  initDataPages,
  getPasswordsData,
  getCookiesData,
  getAutofillsData,
  getHistoryData,
  getBookmarksData,
  getBrowserMetadataData,
  getAccountTokensData,
  getServiceArtifactsData,
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getCreditCardsData,
  getScreenshotsData,
  getSoftwareData,
  getProcessListData,
  escapeCSV
};
