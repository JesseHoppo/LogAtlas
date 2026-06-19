// Activity pages: Downloads, Detections, Clipboard, Grabbed Files, Screenshots, Software, Processes

import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parseDownloadFile,
  parseDomainDetectFile,
  parseClipboardFile,
} from '../transforms/structured.js';
import { classifyGrabbedFile, summariseGrabbedFiles } from '../analysis/contextArtifacts.js';
import { CLIPBOARD_LURE_PATTERNS } from '../core/definitions/patterns.js';
import {
  collectHintedNodes,
  extractDomain,
  truncateText,
  parseTimestampValue,
  SHARED_TEXT_DECODER,
} from '../core/shared.js';
import {
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  bindDebouncedInput,
  formatOptionalDate,
  openSourcePreview,
  getImageMimeFromName,
  measureImage,
  revokeScreenshotUrls,
  extractDownloadExtension,
  parseDownloadSize,
  trimRootPath,
  formatBytes,
  downloadCsvRows,
  createPagedCollectionRegistry,
} from './shared.js';

// Data stores

let downloadsData = { entries: [], fileCount: 0 };
let domainDetectionsData = { entries: [], fileCount: 0, totalHits: 0 };
let clipboardData = { entries: [], fileCount: 0 };
let grabbedFilesData = { entries: [] };
let screenshotsData = { entries: [], totalBytes: 0 };
let softwareData = { entries: [], fileCount: 0 };
let processListData = { entries: [], fileCount: 0 };
let softwareSlots = { inline: null, file: null };
let processListSlots = { inline: null, file: null };

let downloadsFiltered = [];
let downloadsShown = 0;
let domainDetectionsFiltered = [];
let domainDetectionsShown = 0;
let clipboardFiltered = [];
let clipboardShown = 0;
let grabbedFiltered = [];
let grabbedShown = 0;
let screenshotsFiltered = [];
let screenshotsShown = 0;
let softwareFiltered = [];
let softwareShown = 0;
let processesFiltered = [];
let processesShown = 0;

const pageRegistry = createPagedCollectionRegistry({
  downloads: {
    navId: 'navDownloads',
    rowBuilder: downloadsRowBuilder,
    getFiltered: () => downloadsFiltered,
    getShown: () => downloadsShown,
    setShown: (value) => { downloadsShown = value; },
    isEmpty: () => downloadsData.entries.length === 0,
    reset: () => {
      downloadsData = { entries: [], fileCount: 0 };
      downloadsFiltered = [];
      downloadsShown = 0;
    },
  },
  detections: {
    navId: 'navDetections',
    rowBuilder: detectionRowBuilder,
    getFiltered: () => domainDetectionsFiltered,
    getShown: () => domainDetectionsShown,
    setShown: (value) => { domainDetectionsShown = value; },
    isEmpty: () => domainDetectionsData.entries.length === 0,
    reset: () => {
      domainDetectionsData = { entries: [], fileCount: 0, totalHits: 0 };
      domainDetectionsFiltered = [];
      domainDetectionsShown = 0;
    },
  },
  clipboard: {
    navId: 'navClipboard',
    rowBuilder: clipboardRowBuilder,
    getFiltered: () => clipboardFiltered,
    getShown: () => clipboardShown,
    setShown: (value) => { clipboardShown = value; },
    isEmpty: () => clipboardData.entries.length === 0,
    reset: () => {
      clipboardData = { entries: [], fileCount: 0 };
      clipboardFiltered = [];
      clipboardShown = 0;
    },
  },
  grabbed: {
    navId: 'navGrabbed',
    rowBuilder: grabbedFileRowBuilder,
    getFiltered: () => grabbedFiltered,
    getShown: () => grabbedShown,
    setShown: (value) => { grabbedShown = value; },
    isEmpty: () => grabbedFilesData.entries.length === 0,
    reset: () => {
      grabbedFilesData = { entries: [] };
      grabbedFiltered = [];
      grabbedShown = 0;
    },
  },
  screenshots: {
    navId: 'navScreenshots',
    rowBuilder: screenshotCardBuilder,
    getFiltered: () => screenshotsFiltered,
    getShown: () => screenshotsShown,
    setShown: (value) => { screenshotsShown = value; },
    isEmpty: () => screenshotsData.entries.length === 0,
    reset: () => {
      revokeScreenshotUrls(screenshotsData);
      screenshotsData = { entries: [], totalBytes: 0 };
      screenshotsFiltered = [];
      screenshotsShown = 0;
    },
  },
  software: {
    navId: 'navSoftware',
    rowBuilder: softwareRowBuilder,
    getFiltered: () => softwareFiltered,
    getShown: () => softwareShown,
    setShown: (value) => { softwareShown = value; },
    isEmpty: () => softwareData.entries.length === 0,
    reset: () => {
      softwareData = { entries: [], fileCount: 0 };
      softwareSlots = { inline: null, file: null };
      softwareFiltered = [];
      softwareShown = 0;
    },
  },
  processes: {
    navId: 'navProcesses',
    rowBuilder: processRowBuilder,
    getFiltered: () => processesFiltered,
    getShown: () => processesShown,
    setShown: (value) => { processesShown = value; },
    isEmpty: () => processListData.entries.length === 0,
    reset: () => {
      processListData = { entries: [], fileCount: 0 };
      processListSlots = { inline: null, file: null };
      processesFiltered = [];
      processesShown = 0;
    },
  },
});

const LURE_LABELS = {
  clickfix: 'ClickFix',
  powershell: 'PowerShell',
  mshta: 'mshta',
  certutil: 'certutil',
  'crypto-swap': 'Clipper swap',
  'base64-blob': 'Base64 blob',
};

function detectClipboardLure(text) {
  const s = String(text || '').trim();
  if (!s) return '';
  for (const { category, rx } of CLIPBOARD_LURE_PATTERNS) {
    rx.lastIndex = 0;
    if (rx.test(s)) return category;
  }
  return '';
}

// Load functions

async function loadDownloadsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_downloadHint', rootName, nodes);

  if (nodes.length === 0) {
    downloadsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
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
        });
      }
    } catch {
      // skip
    }
  }

  const extensionCounts = {};
  let withSourceUrl = 0, withFileSize = 0, totalKnownBytes = 0, knownSizeCount = 0;
  for (const entry of entries) {
    if (entry.extension) extensionCounts[entry.extension] = (extensionCounts[entry.extension] || 0) + 1;
    if (entry.sourceUrl) withSourceUrl++;
    if (entry.fileSizeDisplay) withFileSize++;
    if (entry.fileSizeBytes != null) { totalKnownBytes += entry.fileSizeBytes; knownSizeCount++; }
  }
  const topExt = Object.entries(extensionCounts).sort((a, b) => b[1] - a[1])[0];

  downloadsData = {
    entries,
    fileCount,
    stats: {
      withSourceUrl,
      withFileSize,
      topExtension: topExt ? topExt[0] : '-',
      totalKnownSizeDisplay: knownSizeCount > 0 ? formatBytes(totalKnownBytes) : '-',
    },
  };
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
      const text = SHARED_TEXT_DECODER.decode(content);
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
        entries.push({ section, label, target, count, source: path });
      }
    } catch {
      // skip
    }
  }

  const uniqueTargets = new Set();
  const uniqueSections = new Set();
  let labelledEntries = 0;
  const sectionCounts = {};
  for (const entry of entries) {
    uniqueTargets.add(entry.target.toLowerCase());
    uniqueSections.add(entry.section);
    if (entry.label) labelledEntries++;
    sectionCounts[entry.section] = (sectionCounts[entry.section] || 0) + entry.count;
  }
  const topSections = Object.entries(sectionCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  domainDetectionsData = {
    entries,
    fileCount,
    totalHits,
    stats: {
      uniqueTargets: uniqueTargets.size,
      uniqueSections: uniqueSections.size,
      labelledEntries,
      topSections,
    },
  };
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
      const text = SHARED_TEXT_DECODER.decode(content);
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
          lure: detectClipboardLure(entryText),
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  let withUrls = 0, commandCount = 0, pathCount = 0, lureCount = 0;
  const lureCategories = {};
  for (const e of entries) {
    if (e.urls) withUrls++;
    if (e.type === 'Command') commandCount++;
    if (e.type === 'Path') pathCount++;
    if (e.lure) { lureCount++; lureCategories[e.lure] = (lureCategories[e.lure] || 0) + 1; }
  }

  clipboardData = {
    entries,
    fileCount,
    stats: { withUrls, commandCount, pathCount, lureCount, lureCategories },
  };
}

async function loadGrabbedFilesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_grabbedFileHint', rootName, nodes);

  if (nodes.length === 0) {
    grabbedFilesData = { entries: [] };
    return;
  }

  const entries = [];

  for (const { node, path } of nodes) {
    const entry = classifyGrabbedFile(path, node.size || 0, node.lastModified);
    if (!entry) continue;
    entries.push(entry);
  }

  entries.sort((a, b) =>
    (b.isHighValue ? 1 : 0) - (a.isHighValue ? 1 : 0)
    || (b.sizeBytes || 0) - (a.sizeBytes || 0)
    || a.relativePath.localeCompare(b.relativePath));
  const { highValueCount, highValueBreakdown } = summariseGrabbedFiles(entries);
  grabbedFilesData = { entries, stats: { highValueCount, highValueBreakdown } };
}

async function loadScreenshotsData(fileTree, rootName) {
  revokeScreenshotUrls(screenshotsData);

  const nodes = [];
  collectHintedNodes(fileTree, '_screenshotHint', rootName, nodes);

  if (nodes.length === 0) {
    screenshotsData = { entries: [], totalBytes: 0 };
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
        modifiedDate: parseTimestampValue(node.lastModified),
      });
    } catch {
      // skip
    }
  }

  screenshotsData = { entries, totalBytes };
}

// Row builders

function downloadsRowBuilder({ filePath, sourceUrl, fileSizeDisplay, domain, extension }) {
  return `<tr>
    <td title="${escapeHtml(filePath)}">${escapeHtml(filePath)}</td>
    <td title="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</td>
    <td title="${escapeHtml(fileSizeDisplay || '')}">${escapeHtml(fileSizeDisplay || '')}</td>
    <td>${escapeHtml(extension || '')}</td>
    <td>${escapeHtml(domain || '')}</td>
  </tr>`;
}

function detectionRowBuilder({ section, label, target, count }) {
  return `<tr>
    <td>${escapeHtml(section)}</td>
    <td>${escapeHtml(label || '')}</td>
    <td title="${escapeHtml(target)}">${escapeHtml(target)}</td>
    <td>${count}</td>
  </tr>`;
}

function clipboardRowBuilder({ type, preview, text, urls, lineCount, lure, source }) {
  const lureChip = lure ? `<span class="dash-ioc-family">${escapeHtml(LURE_LABELS[lure] || lure)}</span>` : '';
  return `<tr>
    <td>${escapeHtml(type)}</td>
    <td>${lureChip}</td>
    <td title="${escapeHtml(text)}">${escapeHtml(preview)}</td>
    <td title="${escapeHtml(urls)}">${escapeHtml(urls)}</td>
    <td>${lineCount}</td>
    <td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>
  </tr>`;
}

function grabbedFileRowBuilder(entry, index) {
  const modified = formatOptionalDate(entry.modifiedDate);
  const flag = entry.isHighValue ? ` <span class="dash-ioc-family">${escapeHtml(entry.highValue)}</span>` : '';
  return `<tr>
    <td>${escapeHtml(entry.collection)}</td>
    <td title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}${flag}</td>
    <td title="${escapeHtml(entry.relativePath)}">${escapeHtml(entry.relativePath)}</td>
    <td>${escapeHtml(entry.extension || '')}</td>
    <td>${escapeHtml(entry.sizeDisplay)}</td>
    <td>${modified ? escapeHtml(modified) : '<span style="color:var(--text-muted)">&#8212;</span>'}</td>
    <td>
      <button class="table-action-btn" data-grabbed-view="${index}">View</button>
    </td>
  </tr>`;
}

function screenshotCardBuilder(entry, index) {
  const dimensions = entry.width && entry.height ? `${entry.width}\u00d7${entry.height}` : 'Unknown size';
  return `<article class="screenshot-card">
    <button class="screenshot-card-thumb" data-screenshot-idx="${index}" title="Open screenshot">
      <img src="${entry.blobUrl}" alt="${escapeHtml(entry.name)}">
    </button>
    <div class="screenshot-card-meta">
      <div class="screenshot-card-name" title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</div>
      <div class="screenshot-card-info">${escapeHtml(dimensions)} \u00b7 ${escapeHtml(entry.sizeDisplay)}</div>
      <div class="screenshot-card-path" title="${escapeHtml(entry.path)}">${escapeHtml(trimRootPath(entry.path))}</div>
    </div>
  </article>`;
}

function softwareRowBuilder({ name, version }) {
  return `<tr><td title="${escapeHtml(name)}">${escapeHtml(name)}</td><td>${escapeHtml(version || '')}</td></tr>`;
}

function processRowBuilder({ name, pid, sessionId, commandLine }) {
  return `<tr>
    <td title="${escapeHtml(name)}">${escapeHtml(name)}</td>
    <td>${pid ? escapeHtml(String(pid)) : ''}</td>
    <td>${sessionId ? escapeHtml(String(sessionId)) : ''}</td>
    <td title="${escapeHtml(commandLine || '')}">${escapeHtml(truncateText(commandLine || '', 120))}</td>
  </tr>`;
}

function openScreenshotLightbox(entry) {
  if (!entry || !entry.blobUrl) return;
  const lightbox = document.createElement('div');
  lightbox.className = 'screenshot-lightbox';
  lightbox.innerHTML = `<img src="${entry.blobUrl}" alt="${escapeHtml(entry.name)}">`;
  lightbox.addEventListener('click', () => lightbox.remove());
  document.body.appendChild(lightbox);
}

// Render functions

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

  const cached = downloadsData.stats || { withSourceUrl: 0, withFileSize: 0, topExtension: '-', totalKnownSizeDisplay: '-' };

  summary.textContent = filtered.length !== downloadsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`
    : `${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.withSourceUrl.toLocaleString()}</div>
      <div class="data-page-stat-label">With Source URL</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.withFileSize.toLocaleString()}</div>
      <div class="data-page-stat-label">With File Size</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(cached.topExtension)}</div>
      <div class="data-page-stat-label">Top Extension</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(cached.totalKnownSizeDisplay)}</div>
      <div class="data-page-stat-label">Known Total Size</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>File Path</th><th>Source URL</th><th>File Size</th><th>Extension</th><th>Domain</th></tr></thead><tbody>';
  html += buildRowsHtml(downloadsRowBuilder, downloadsFiltered, 0, downloadsShown);
  html += '</tbody></table></div>';

  const remaining = downloadsFiltered.length - downloadsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'downloads');

  content.innerHTML = html;
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

  const cached = domainDetectionsData.stats || { uniqueTargets: 0, uniqueSections: 0, labelledEntries: 0, topSections: [] };
  const topSections = cached.topSections;

  summary.textContent = filtered.length !== domainDetectionsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${domainDetectionsData.entries.length.toLocaleString()} detections from ${domainDetectionsData.fileCount} file(s)`
    : `${domainDetectionsData.entries.length.toLocaleString()} detections from ${domainDetectionsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.uniqueTargets.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Targets</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.uniqueSections.toLocaleString()}</div>
      <div class="data-page-stat-label">Sections</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.labelledEntries.toLocaleString()}</div>
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
  if (remaining > 0) html += buildShowMoreButton(remaining, 'detections');

  content.innerHTML = html;
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
      (entry.lure && (LURE_LABELS[entry.lure] || entry.lure).toLowerCase().includes(q)) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  clipboardFiltered = filtered;
  clipboardShown = Math.min(PAGE_SIZE, filtered.length);

  const cached = clipboardData.stats || { withUrls: 0, commandCount: 0, pathCount: 0, lureCount: 0, lureCategories: {} };

  summary.textContent = filtered.length !== clipboardData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${clipboardData.entries.length.toLocaleString()} clipboard entr${clipboardData.entries.length === 1 ? 'y' : 'ies'} from ${clipboardData.fileCount} file(s)`
    : `${clipboardData.entries.length.toLocaleString()} clipboard entr${clipboardData.entries.length === 1 ? 'y' : 'ies'} from ${clipboardData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.withUrls.toLocaleString()}</div>
      <div class="data-page-stat-label">With URLs</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.commandCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Commands</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.pathCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Paths</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.lureCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Lures</div>
    </div>
  `;

  let html = '';
  const lureCats = Object.entries(cached.lureCategories || {}).sort((a, b) => b[1] - a[1]);
  if (lureCats.length > 0) {
    const chips = lureCats.map(([cat, count]) => `<span class="dash-ioc-family">${escapeHtml(LURE_LABELS[cat] || cat)} ${count}</span>`).join(' ');
    html += `<div class="data-page-warning"><div class="data-page-warning-title">Clipboard social-engineering / clipper activity</div><div class="data-page-warning-more">Clipboard captures match known lure patterns.</div><div class="identity-service-tags">${chips}</div></div>`;
  }

  html += '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Type</th><th>Lure</th><th>Content</th><th>URLs</th><th>Lines</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(clipboardRowBuilder, clipboardFiltered, 0, clipboardShown);
  html += '</tbody></table></div>';

  const remaining = clipboardFiltered.length - clipboardShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'clipboard');

  content.innerHTML = html;
}

function renderGrabbedPage(searchQuery = '') {
  const summary = document.getElementById('grabbedSummary');
  const stats = document.getElementById('grabbedStats');
  const content = document.getElementById('grabbedContent');

  if (grabbedFilesData.entries.length === 0) {
    summary.textContent = 'No grabbed files found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No grabbed-file data available.</div>';
    return;
  }

  let filtered = grabbedFilesData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.collection.toLowerCase().includes(q) ||
      entry.name.toLowerCase().includes(q) ||
      entry.relativePath.toLowerCase().includes(q) ||
      entry.extension.toLowerCase().includes(q)
    );
  }

  grabbedFiltered = filtered;
  grabbedShown = Math.min(PAGE_SIZE, filtered.length);

  const fileGrabberCount = filtered.filter(entry => entry.collection === 'FileGrabber').length;
  const uniqueExtensions = new Set(filtered.map(entry => entry.extension).filter(Boolean));
  const cached = grabbedFilesData.stats || { highValueCount: 0, highValueBreakdown: [] };
  summary.textContent = filtered.length !== grabbedFilesData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${grabbedFilesData.entries.length.toLocaleString()} grabbed files`
    : `${grabbedFilesData.entries.length.toLocaleString()} grabbed files`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.highValueCount.toLocaleString()}</div>
      <div class="data-page-stat-label">High-Value Files</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${fileGrabberCount.toLocaleString()}</div>
      <div class="data-page-stat-label">FileGrabber</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueExtensions.size.toLocaleString()}</div>
      <div class="data-page-stat-label">File Types</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${formatBytes(filtered.reduce((sum, entry) => sum + (entry.sizeBytes || 0), 0))}</div>
      <div class="data-page-stat-label">Total Size</div>
    </div>
  `;

  let html = '';
  if (cached.highValueCount > 0) {
    const chips = (cached.highValueBreakdown || []).map(({ label, count }) => `<span class="dash-ioc-family">${escapeHtml(label)} ${count}</span>`).join(' ');
    html += `<div class="data-page-warning"><div class="data-page-warning-title">${cached.highValueCount.toLocaleString()} high-value file(s) grabbed</div><div class="data-page-warning-more">Password databases, wallet files, VPN profiles, or SSH keys were collected.</div>${chips ? `<div class="identity-service-tags">${chips}</div>` : ''}</div>`;
  }
  html += '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Collection</th><th>Name</th><th>Path</th><th>Ext</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead><tbody>';
  html += buildRowsHtml(grabbedFileRowBuilder, grabbedFiltered, 0, grabbedShown);
  html += '</tbody></table></div>';

  const remaining = grabbedFiltered.length - grabbedShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'grabbed');

  content.innerHTML = html;
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
      <div class="data-page-stat-value">${escapeHtml(highestResolution && highestResolution.width ? `${highestResolution.width}\u00d7${highestResolution.height}` : (largest ? largest.sizeDisplay : '-'))}</div>
      <div class="data-page-stat-label">${highestResolution && highestResolution.width ? 'Top Resolution' : 'Largest File'}</div>
    </div>
  `;

  let html = '<div class="screenshot-grid">';
  html += buildRowsHtml(screenshotCardBuilder, screenshotsFiltered, 0, screenshotsShown);
  html += '</div>';

  const remaining = screenshotsFiltered.length - screenshotsShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'screenshots');

  content.innerHTML = html;
}

function renderSoftwarePage(searchQuery = '') {
  const summary = document.getElementById('softwareSummary');
  const stats = document.getElementById('softwareStats');
  const content = document.getElementById('softwareContent');

  if (softwareData.entries.length === 0) {
    summary.textContent = 'No software data found';
    stats.innerHTML = '';
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

  const remoteTools = filtered.filter(entry => /(anydesk|teamviewer|rustdesk|supremo|parsec|mobaxtterm|ultraviewer|vnc|remote desktop)/i.test(entry.name)).length;
  const walletApps = filtered.filter(entry => /(metamask|bitwarden|keepass|exodus|phantom|atomic wallet|electrum|ledger live)/i.test(entry.name)).length;
  const browsers = filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|chromium)/i.test(entry.name)).length;
  const developerTools = filtered.filter(entry => /(python|visual studio|code|git|docker|node\.js|java|composer|npm)/i.test(entry.name)).length;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${remoteTools.toLocaleString()}</div>
      <div class="data-page-stat-label">Remote Tools</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${walletApps.toLocaleString()}</div>
      <div class="data-page-stat-label">Wallet / Vault Apps</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${browsers.toLocaleString()}</div>
      <div class="data-page-stat-label">Browsers</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${developerTools.toLocaleString()}</div>
      <div class="data-page-stat-label">Developer Tools</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Software Name</th><th>Version</th></tr></thead><tbody>';
  html += buildRowsHtml(softwareRowBuilder, softwareFiltered, 0, softwareShown);
  html += '</tbody></table></div>';

  const remaining = softwareFiltered.length - softwareShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'software');

  content.innerHTML = html;
}

function renderProcessesPage(searchQuery = '') {
  const summary = document.getElementById('processesSummary');
  const stats = document.getElementById('processesStats');
  const content = document.getElementById('processesContent');

  if (processListData.entries.length === 0) {
    summary.textContent = 'No process data found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No process data available.</div>';
    return;
  }

  let filtered = processListData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e =>
      e.name.toLowerCase().includes(q) ||
      String(e.pid || '').includes(q) ||
      String(e.sessionId || '').includes(q) ||
      String(e.commandLine || '').toLowerCase().includes(q)
    );
  }

  processesFiltered = filtered;
  processesShown = Math.min(PAGE_SIZE, filtered.length);

  const total = processListData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`
    : `${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`;

  const browserCount = filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|iexplore|msedge)/i.test(entry.name)).length;
  const remoteCount = filtered.filter(entry => /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.name) || /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.commandLine || '')).length;
  const securityCount = filtered.filter(entry => /(defender|avast|kaspersky|mcafee|crowdstrike|sentinel|eset|norton|bitdefender)/i.test(entry.name)).length;
  const withCommandLine = filtered.filter(entry => entry.commandLine).length;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${browserCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Browsers</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${remoteCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Remote Access</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${securityCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Security Tools</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withCommandLine.toLocaleString()}</div>
      <div class="data-page-stat-label">With Command Line</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Process Name</th><th>PID</th><th>Session</th><th>Command Line</th></tr></thead><tbody>';
  html += buildRowsHtml(processRowBuilder, processesFiltered, 0, processesShown);
  html += '</tbody></table></div>';

  const remaining = processesFiltered.length - processesShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'processes');

  content.innerHTML = html;
}

// CSV export

function exportDownloadsCSV() {
  if (downloadsData.entries.length === 0) return;
  downloadCsvRows('downloads.csv', ['File Path', 'Source URL', 'File Size', 'Extension', 'Domain'], downloadsData.entries.map(
    ({ filePath, sourceUrl, fileSizeRaw, fileSizeDisplay, extension, domain }) => [filePath, sourceUrl, fileSizeRaw || fileSizeDisplay, extension, domain]
  ));
}

function exportDetectionsCSV() {
  if (domainDetectionsData.entries.length === 0) return;
  downloadCsvRows('domain_detections.csv', ['Section', 'Label', 'Target', 'Count', 'Source'], domainDetectionsData.entries.map(
    ({ section, label, target, count, source }) => [section, label, target, count, source]
  ));
}

function exportClipboardCSV() {
  if (clipboardData.entries.length === 0) return;
  downloadCsvRows('clipboard.csv', ['Type', 'Lure', 'Text', 'URLs', 'Line Count', 'Length', 'Source'], clipboardData.entries.map(
    ({ type, lure, text, urls, lineCount, length, source }) => [type, lure ? (LURE_LABELS[lure] || lure) : '', text, urls, lineCount, length, source]
  ));
}

function exportGrabbedCSV() {
  if (grabbedFilesData.entries.length === 0) return;
  downloadCsvRows('grabbed_files.csv', ['Collection', 'Name', 'High Value', 'Path', 'Extension', 'Size Bytes', 'Modified', 'Source'], grabbedFilesData.entries.map(
    (entry) => [entry.collection, entry.name, entry.highValue || '', entry.relativePath, entry.extension, entry.sizeBytes, formatOptionalDate(entry.modifiedDate), entry.source]
  ));
}

function exportScreenshotsCSV() {
  if (screenshotsData.entries.length === 0) return;
  downloadCsvRows('screenshots.csv', ['Name', 'Path', 'Width', 'Height', 'Size Bytes'], screenshotsData.entries.map(
    ({ name, path, width, height, sizeBytes }) => [name, path, width || '', height || '', sizeBytes]
  ));
}

function exportSoftwareCSV() {
  if (softwareData.entries.length === 0) return;
  downloadCsvRows('software.csv', ['Software Name', 'Version'], softwareData.entries.map(
    ({ name, version }) => [name, version || '']
  ));
}

function exportProcessesCSV() {
  if (processListData.entries.length === 0) return;
  downloadCsvRows('processes.csv', ['Process Name', 'PID', 'Session ID', 'Command Line'], processListData.entries.map(
    ({ name, pid, sessionId, commandLine }) => [name, pid || '', sessionId || '', commandLine || '']
  ));
}

// Module interface

export function loadAll(fileTree, rootName) {
  return Promise.all([
    loadDownloadsData(fileTree, rootName),
    loadDomainDetectionsData(fileTree, rootName),
    loadClipboardData(fileTree, rootName),
    loadGrabbedFilesData(fileTree, rootName),
    loadScreenshotsData(fileTree, rootName),
  ]);
}

export function handleShowMore(pageId) {
  return pageRegistry.handleShowMore(pageId);
}

export function updateShown(pageId, newShown) {
  pageRegistry.updateShown(pageId, newShown);
}

export function updateNav() {
  pageRegistry.updateNav();
}

export function reset() {
  pageRegistry.reset();
}

function mergeSoftware(slots) {
  const seen = new Set();
  const entries = [];
  let fileCount = 0;
  for (const slot of [slots.file, slots.inline]) {
    if (!slot) continue;
    fileCount += slot.fileCount || 0;
    for (const e of slot.entries) {
      const key = e.name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push(e);
    }
  }
  return { entries, fileCount };
}

function mergeProcessList(slots) {
  const map = new Map();
  let fileCount = 0;
  for (const slot of [slots.file, slots.inline]) {
    if (!slot) continue;
    fileCount += slot.fileCount || 0;
    for (const e of slot.entries) {
      const key = [e.name, e.pid || '', e.sessionId || '', e.commandLine || ''].join(' ').toLowerCase();
      if (!map.has(key)) map.set(key, { ...e });
    }
  }
  return { entries: [...map.values()], fileCount };
}

export function setSoftwareData(data) {
  const slot = data === null ? 'file' : (data.inline ? 'inline' : 'file');
  const hasEntries = Array.isArray(data?.entries) && data.entries.length > 0;
  softwareSlots[slot] = hasEntries ? { entries: data.entries, fileCount: data.fileCount || 0 } : null;
  softwareData = mergeSoftware(softwareSlots);

  const nav = document.getElementById('navSoftware');
  if (nav) nav.disabled = softwareData.entries.length === 0;
  if (document.getElementById('pageSoftware')?.classList.contains('active')) {
    renderSoftwarePage(document.getElementById('softwareSearch')?.value || '');
  }
}

export function setProcessListData(data) {
  const slot = data === null ? 'file' : (data.inline ? 'inline' : 'file');
  const hasEntries = Array.isArray(data?.entries) && data.entries.length > 0;
  processListSlots[slot] = hasEntries ? { entries: data.entries, fileCount: data.fileCount || 0 } : null;
  processListData = mergeProcessList(processListSlots);

  const nav = document.getElementById('navProcesses');
  if (nav) nav.disabled = processListData.entries.length === 0;
  if (document.getElementById('pageProcesses')?.classList.contains('active')) {
    renderProcessesPage(document.getElementById('processesSearch')?.value || '');
  }
}

export function initActivityPages() {
  const searchInputs = {
    downloads: document.getElementById('downloadsSearch'),
    detections: document.getElementById('detectionsSearch'),
    clipboard: document.getElementById('clipboardSearch'),
    grabbed: document.getElementById('grabbedSearch'),
    screenshots: document.getElementById('screenshotsSearch'),
    software: document.getElementById('softwareSearch'),
    processes: document.getElementById('processesSearch'),
  };
  const renderers = {
    downloads: renderDownloadsPage,
    detections: renderDetectionsPage,
    clipboard: renderClipboardPage,
    grabbed: renderGrabbedPage,
    screenshots: renderScreenshotsPage,
    software: renderSoftwarePage,
    processes: renderProcessesPage,
  };
  for (const [pageName, input] of Object.entries(searchInputs)) {
    bindDebouncedInput(input, (value) => renderers[pageName](value));
  }

  document.getElementById('grabbedContent')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-grabbed-view]');
    if (!button) return;

    const entry = grabbedFiltered[Number(button.dataset.grabbedView)];
    if (entry) openSourcePreview(entry.source);
  });

  for (const [id, handler] of Object.entries({
    exportDownloadsCsv: exportDownloadsCSV,
    exportDetectionsCsv: exportDetectionsCSV,
    exportClipboardCsv: exportClipboardCSV,
    exportGrabbedCsv: exportGrabbedCSV,
    exportScreenshotsCsv: exportScreenshotsCSV,
    exportSoftwareCsv: exportSoftwareCSV,
    exportProcessesCsv: exportProcessesCSV,
  })) {
    document.getElementById(id)?.addEventListener('click', handler);
  }

  return {
    renders: Object.fromEntries(
      Object.entries(renderers).map(([pageName, render]) => [
        pageName,
        (q) => render(q || searchInputs[pageName]?.value || ''),
      ])
    ),
    openScreenshotLightbox,
    getScreenshotsFiltered: () => screenshotsFiltered,
    resetSearches: () => {
      for (const input of Object.values(searchInputs)) {
        if (input) input.value = '';
      }
    },
  };
}

// Getters

function getDownloadsData() { return downloadsData; }
function getDomainDetectionsData() { return domainDetectionsData; }
function getClipboardData() { return clipboardData; }
function getGrabbedFilesData() { return grabbedFilesData; }
function getScreenshotsData() { return screenshotsData; }

export {
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getGrabbedFilesData,
  getScreenshotsData,
};
