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
  decodeBufferWithFallback,
  extractDomain,
  truncateText,
  parseNodeCached,
  parseTimestampValue,
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

const SCREENSHOT_MEASURE_BATCH = 16;

const LURE_LABELS = {
  clickfix: 'ClickFix',
  powershell: 'PowerShell',
  mshta: 'mshta',
  certutil: 'certutil',
  'crypto-swap': 'Clipper swap',
  'base64-blob': 'Base64 blob',
};

let softwareSlots = { inline: null, file: null };
let processListSlots = { inline: null, file: null };

// One definition per page. Element ids follow the page key as registry.js
// names them (`<key>Summary/Stats/Content/Search`, `export<Key>Csv`). What a
// page does differently — search fields, stat tiles, the block above the
// table, the table itself, the CSV shape — hangs off its entry here, so a
// change to the shared scaffold cannot reach one page and miss the other six.
const pages = {
  downloads: {
    navId: 'navDownloads',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    emptySummary: 'No downloads found',
    emptyMessage: 'No download data available.',
    label: (data) => `downloads from ${data.fileCount} file(s)`,
    matches: (e, q) =>
      e.filePath.toLowerCase().includes(q) ||
      e.sourceUrl.toLowerCase().includes(q) ||
      e.fileSizeRaw.toLowerCase().includes(q) ||
      e.fileSizeDisplay.toLowerCase().includes(q) ||
      e.domain.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q),
    stats: (data) => {
      const cached = data.stats || { withSourceUrl: 0, withFileSize: 0, topExtension: '-', totalKnownSizeDisplay: '-' };
      return [
        { value: cached.withSourceUrl.toLocaleString(), label: 'With Source URL' },
        { value: cached.withFileSize.toLocaleString(), label: 'With File Size' },
        { value: escapeHtml(cached.topExtension), label: 'Top Extension' },
        { value: escapeHtml(cached.totalKnownSizeDisplay), label: 'Known Total Size' },
      ];
    },
    columns: ['File Path', 'Source URL', 'File Size', 'Extension', 'Domain'],
    rowBuilder: downloadsRowBuilder,
    csv: {
      file: 'downloads.csv',
      headers: ['File Path', 'Source URL', 'File Size', 'Extension', 'Domain'],
      row: ({ filePath, sourceUrl, fileSizeRaw, fileSizeDisplay, extension, domain }) =>
        [filePath, sourceUrl, fileSizeRaw || fileSizeDisplay, extension, domain],
    },
  },

  detections: {
    navId: 'navDetections',
    emptyData: () => ({ entries: [], fileCount: 0, totalHits: 0 }),
    emptySummary: 'No domain detections found',
    emptyMessage: 'No domain-detection data available.',
    label: (data) => `detections from ${data.fileCount} file(s)`,
    matches: (e, q) =>
      e.section.toLowerCase().includes(q) ||
      e.label.toLowerCase().includes(q) ||
      e.target.toLowerCase().includes(q),
    stats: (data) => {
      const cached = data.stats || { uniqueTargets: 0, uniqueSections: 0, labelledEntries: 0 };
      return [
        { value: cached.uniqueTargets.toLocaleString(), label: 'Unique Targets' },
        { value: cached.uniqueSections.toLocaleString(), label: 'Sections' },
        { value: cached.labelledEntries.toLocaleString(), label: 'Tagged Entries' },
        { value: data.totalHits.toLocaleString(), label: 'Total Hits' },
      ];
    },
    prelude: (data) => {
      const topSections = data.stats?.topSections || [];
      if (topSections.length === 0) return '';
      const maxCount = topSections[0][1];
      let html = '<div class="domain-bars">';
      for (const [sectionName, count] of topSections) {
        const pct = Math.round((count / maxCount) * 100);
        html += `<div class="domain-bar-row">
        <span class="domain-bar-label">${escapeHtml(sectionName)}</span>
        <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
        <span class="domain-bar-count">${count}</span>
      </div>`;
      }
      return html + '</div>';
    },
    columns: ['Section', 'Label', 'Target', 'Count'],
    rowBuilder: detectionRowBuilder,
    csv: {
      file: 'domain_detections.csv',
      headers: ['Section', 'Label', 'Target', 'Count', 'Source'],
      row: ({ section, label, target, count, source }) => [section, label, target, count, source],
    },
  },

  clipboard: {
    navId: 'navClipboard',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    emptySummary: 'No clipboard entries found',
    emptyMessage: 'No clipboard data available.',
    label: (data) => `clipboard entr${data.entries.length === 1 ? 'y' : 'ies'} from ${data.fileCount} file(s)`,
    matches: (e, q) =>
      e.type.toLowerCase().includes(q) ||
      e.text.toLowerCase().includes(q) ||
      e.urls.toLowerCase().includes(q) ||
      (e.lure && (LURE_LABELS[e.lure] || e.lure).toLowerCase().includes(q)) ||
      e.source.toLowerCase().includes(q),
    stats: (data) => {
      const cached = data.stats || { withUrls: 0, commandCount: 0, pathCount: 0, lureCount: 0 };
      return [
        { value: cached.withUrls.toLocaleString(), label: 'With URLs' },
        { value: cached.commandCount.toLocaleString(), label: 'Commands' },
        { value: cached.pathCount.toLocaleString(), label: 'Paths' },
        { value: cached.lureCount.toLocaleString(), label: 'Lures' },
      ];
    },
    prelude: (data) => {
      const lureCats = Object.entries(data.stats?.lureCategories || {}).sort((a, b) => b[1] - a[1]);
      if (lureCats.length === 0) return '';
      const chips = lureCats.map(([cat, count]) => `<span class="dash-ioc-family">${escapeHtml(LURE_LABELS[cat] || cat)} ${count}</span>`).join(' ');
      return `<div class="data-page-warning"><div class="data-page-warning-title">Clipboard social-engineering / clipper activity</div><div class="data-page-warning-more">Matches known lure patterns.</div><div class="identity-service-tags">${chips}</div></div>`;
    },
    columns: ['Type', 'Lure', 'Content', 'URLs', 'Lines', 'Source'],
    rowBuilder: clipboardRowBuilder,
    csv: {
      file: 'clipboard.csv',
      headers: ['Type', 'Lure', 'Text', 'URLs', 'Line Count', 'Length', 'Source'],
      row: ({ type, lure, text, urls, lineCount, length, source }) =>
        [type, lure ? (LURE_LABELS[lure] || lure) : '', text, urls, lineCount, length, source],
    },
  },

  grabbed: {
    navId: 'navGrabbed',
    emptyData: () => ({ entries: [] }),
    emptySummary: 'No grabbed files found',
    emptyMessage: 'No grabbed-file data available.',
    label: () => 'grabbed files',
    matches: (e, q) =>
      e.collection.toLowerCase().includes(q) ||
      e.name.toLowerCase().includes(q) ||
      e.relativePath.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q),
    stats: (data) => {
      const cached = data.stats || { highValueCount: 0, fileGrabberCount: 0, extensionCount: 0, totalSizeDisplay: '-' };
      return [
        { value: cached.highValueCount.toLocaleString(), label: 'High-Value Files' },
        { value: cached.fileGrabberCount.toLocaleString(), label: 'FileGrabber' },
        { value: cached.extensionCount.toLocaleString(), label: 'File Types' },
        { value: escapeHtml(cached.totalSizeDisplay), label: 'Total Size' },
      ];
    },
    prelude: (data) => {
      const cached = data.stats || {};
      if (!cached.highValueCount) return '';
      const chips = (cached.highValueBreakdown || []).map(({ label, count }) => `<span class="dash-ioc-family">${escapeHtml(label)} ${count}</span>`).join(' ');
      return `<div class="data-page-warning"><div class="data-page-warning-title">${cached.highValueCount.toLocaleString()} high-value file(s) grabbed</div><div class="data-page-warning-more">Password databases, wallet files, VPN profiles, or SSH keys were collected.</div>${chips ? `<div class="identity-service-tags">${chips}</div>` : ''}</div>`;
    },
    columns: ['Collection', 'Name', 'Path', 'Ext', 'Size', 'Modified', 'Actions'],
    rowBuilder: grabbedFileRowBuilder,
    csv: {
      file: 'grabbed_files.csv',
      headers: ['Collection', 'Name', 'High Value', 'Path', 'Extension', 'Size Bytes', 'Modified', 'Source'],
      row: (entry) => [entry.collection, entry.name, entry.highValue || '', entry.relativePath, entry.extension, entry.sizeBytes, formatOptionalDate(entry.modifiedDate), entry.source],
    },
  },

  screenshots: {
    navId: 'navScreenshots',
    emptyData: () => ({ entries: [], totalBytes: 0 }),
    emptySummary: 'No screenshots found',
    emptyMessage: 'No screenshots available.',
    label: () => 'screenshots',
    matches: (e, q) =>
      e.name.toLowerCase().includes(q) ||
      e.path.toLowerCase().includes(q) ||
      `${e.width || ''}x${e.height || ''}`.toLowerCase().includes(q),
    stats: (data) => {
      const knownDimensions = data.entries.filter(entry => entry.width && entry.height).length;
      const largest = data.entries.reduce((max, entry) => !max || entry.sizeBytes > max.sizeBytes ? entry : max, null);
      const highestResolution = data.entries.reduce((max, entry) => {
        const area = (entry.width || 0) * (entry.height || 0);
        const maxArea = max ? (max.width || 0) * (max.height || 0) : 0;
        return area > maxArea ? entry : max;
      }, null);
      return [
        { value: data.entries.length.toLocaleString(), label: 'Images' },
        { value: knownDimensions.toLocaleString(), label: 'With Dimensions' },
        { value: escapeHtml(formatBytes(data.totalBytes)), label: 'Total Size' },
        {
          value: escapeHtml(highestResolution && highestResolution.width ? `${highestResolution.width}\u00d7${highestResolution.height}` : (largest ? largest.sizeDisplay : '-')),
          label: highestResolution && highestResolution.width ? 'Top Resolution' : 'Largest File',
        },
      ];
    },
    gridClass: 'screenshot-grid',
    rowBuilder: screenshotCardBuilder,
    onReset: (data) => revokeScreenshotUrls(data),
    csv: {
      file: 'screenshots.csv',
      headers: ['Name', 'Path', 'Width', 'Height', 'Size Bytes'],
      row: ({ name, path, width, height, sizeBytes }) => [name, path, width || '', height || '', sizeBytes],
    },
  },

  software: {
    navId: 'navSoftware',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    emptySummary: 'No software data found',
    emptyMessage: 'No software data available.',
    label: (data) => `programs from ${data.fileCount} file(s)`,
    matches: (e, q) => e.name.toLowerCase().includes(q) || (e.version && e.version.toLowerCase().includes(q)),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => [
      { value: filtered.filter(entry => /(anydesk|teamviewer|rustdesk|supremo|parsec|mobaxtterm|ultraviewer|vnc|remote desktop)/i.test(entry.name)).length.toLocaleString(), label: 'Remote Tools' },
      { value: filtered.filter(entry => /(metamask|bitwarden|keepass|exodus|phantom|atomic wallet|electrum|ledger live)/i.test(entry.name)).length.toLocaleString(), label: 'Wallet / Vault Apps' },
      { value: filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|chromium)/i.test(entry.name)).length.toLocaleString(), label: 'Browsers' },
      { value: filtered.filter(entry => /(python|visual studio|code|git|docker|node\.js|java|composer|npm)/i.test(entry.name)).length.toLocaleString(), label: 'Developer Tools' },
    ],
    columns: ['Software Name', 'Version'],
    rowBuilder: softwareRowBuilder,
    onReset: () => { softwareSlots = { inline: null, file: null }; },
    csv: {
      file: 'software.csv',
      headers: ['Software Name', 'Version'],
      row: ({ name, version }) => [name, version || ''],
    },
  },

  processes: {
    navId: 'navProcesses',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    emptySummary: 'No process data found',
    emptyMessage: 'No process data available.',
    label: (data) => `processes from ${data.fileCount} file(s)`,
    matches: (e, q) =>
      e.name.toLowerCase().includes(q) ||
      String(e.pid || '').includes(q) ||
      String(e.sessionId || '').includes(q) ||
      String(e.commandLine || '').toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => [
      { value: filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|iexplore|msedge)/i.test(entry.name)).length.toLocaleString(), label: 'Browsers' },
      { value: filtered.filter(entry => /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.name) || /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.commandLine || '')).length.toLocaleString(), label: 'Remote Access' },
      { value: filtered.filter(entry => /(defender|avast|kaspersky|mcafee|crowdstrike|sentinel|eset|norton|bitdefender)/i.test(entry.name)).length.toLocaleString(), label: 'Security Tools' },
      { value: filtered.filter(entry => entry.commandLine).length.toLocaleString(), label: 'With Command Line' },
    ],
    columns: ['Process Name', 'PID', 'Session', 'Command Line'],
    rowBuilder: processRowBuilder,
    onReset: () => { processListSlots = { inline: null, file: null }; },
    csv: {
      file: 'processes.csv',
      headers: ['Process Name', 'PID', 'Session ID', 'Command Line'],
      row: ({ name, pid, sessionId, commandLine }) => [name, pid || '', sessionId || '', commandLine || ''],
    },
  },
};

for (const page of Object.values(pages)) {
  page.data = page.emptyData();
  page.filtered = [];
  page.shown = 0;
}

const pageRegistry = createPagedCollectionRegistry(Object.fromEntries(
  Object.entries(pages).map(([pageId, page]) => [pageId, {
    navId: page.navId,
    rowBuilder: page.rowBuilder,
    getFiltered: () => page.filtered,
    getShown: () => page.shown,
    setShown: (value) => { page.shown = value; },
    isEmpty: () => page.data.entries.length === 0,
    reset: () => {
      page.onReset?.(page.data);
      page.data = page.emptyData();
      page.filtered = [];
      page.shown = 0;
    },
  }])
));

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
    pages.downloads.data = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'download', parseDownloadFile, text, null);
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

  pages.downloads.data = {
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
    pages.detections.data = { entries: [], fileCount: 0, totalHits: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;
  let totalHits = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'domainDetect', parseDomainDetectFile, text, null);
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

  pages.detections.data = {
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
    pages.clipboard.data = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'clipboard', parseClipboardFile, text, null);
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

  pages.clipboard.data = {
    entries,
    fileCount,
    stats: { withUrls, commandCount, pathCount, lureCount, lureCategories },
  };
}

async function loadGrabbedFilesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_grabbedFileHint', rootName, nodes);

  if (nodes.length === 0) {
    pages.grabbed.data = { entries: [] };
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

  const extensions = new Set();
  let fileGrabberCount = 0, totalBytes = 0;
  for (const entry of entries) {
    if (entry.collection === 'FileGrabber') fileGrabberCount++;
    if (entry.extension) extensions.add(entry.extension);
    totalBytes += entry.sizeBytes || 0;
  }

  pages.grabbed.data = {
    entries,
    stats: {
      highValueCount,
      highValueBreakdown,
      fileGrabberCount,
      extensionCount: extensions.size,
      totalSizeDisplay: formatBytes(totalBytes),
    },
  };
}

async function loadScreenshotsData(fileTree, rootName) {
  revokeScreenshotUrls(pages.screenshots.data);

  const nodes = [];
  collectHintedNodes(fileTree, '_screenshotHint', rootName, nodes);

  if (nodes.length === 0) {
    pages.screenshots.data = { entries: [], totalBytes: 0 };
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
      const sizeBytes = node.size || content.byteLength || 0;
      totalBytes += sizeBytes;

      entries.push({
        name: node.name,
        path,
        node,
        blobUrl,
        width: null,
        height: null,
        sizeBytes,
        sizeDisplay: formatBytes(sizeBytes),
        modifiedDate: parseTimestampValue(node.lastModified),
      });
    } catch {
      // skip
    }
  }

  for (let start = 0; start < entries.length; start += SCREENSHOT_MEASURE_BATCH) {
    const batch = entries.slice(start, start + SCREENSHOT_MEASURE_BATCH);
    const dimensions = await Promise.all(batch.map(entry => measureImage(entry.blobUrl)));
    batch.forEach((entry, index) => {
      entry.width = dimensions[index].width;
      entry.height = dimensions[index].height;
    });
  }

  pages.screenshots.data = { entries, totalBytes };
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

// Rendering

function statCardsHtml(cards) {
  return `
${cards.map(({ value, label }) => `    <div class="data-page-stat">
      <div class="data-page-stat-value">${value}</div>
      <div class="data-page-stat-label">${label}</div>
    </div>`).join('\n')}
  `;
}

function renderPage(pageId, searchQuery = '') {
  const page = pages[pageId];
  const summary = document.getElementById(`${pageId}Summary`);
  const stats = document.getElementById(`${pageId}Stats`);
  const content = document.getElementById(`${pageId}Content`);
  const { data } = page;

  if (data.entries.length === 0) {
    summary.textContent = page.emptySummary;
    stats.innerHTML = '';
    content.innerHTML = `<div class="no-data">${page.emptyMessage}</div>`;
    return;
  }

  let filtered = data.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry => page.matches(entry, q));
  }
  page.filtered = filtered;
  page.shown = Math.min(PAGE_SIZE, filtered.length);

  const label = page.label(data);
  summary.textContent = filtered.length !== data.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${data.entries.length.toLocaleString()} ${label}`
    : `${data.entries.length.toLocaleString()} ${label}`;

  stats.innerHTML = statCardsHtml(page.stats(data, filtered));

  const rows = buildRowsHtml(page.rowBuilder, filtered, 0, page.shown);
  let html = page.prelude ? page.prelude(data) : '';
  html += page.gridClass
    ? `<div class="${page.gridClass}">${rows}</div>`
    : '<div class="data-table-container"><table class="data-table">'
      + `<thead><tr>${page.columns.map(column => `<th>${column}</th>`).join('')}</tr></thead>`
      + `<tbody>${rows}</tbody></table></div>`;

  const remaining = filtered.length - page.shown;
  if (remaining > 0) html += buildShowMoreButton(remaining, pageId);

  content.innerHTML = html;
}

function exportCsv(pageId) {
  const { data, csv } = pages[pageId];
  if (data.entries.length === 0) return;
  downloadCsvRows(csv.file, csv.headers, data.entries.map(csv.row));
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
  pages.software.data = mergeSoftware(softwareSlots);

  const nav = document.getElementById('navSoftware');
  if (nav) nav.disabled = pages.software.data.entries.length === 0;
  if (document.getElementById('pageSoftware')?.classList.contains('active')) {
    renderPage('software', document.getElementById('softwareSearch')?.value || '');
  }
}

export function setProcessListData(data) {
  const slot = data === null ? 'file' : (data.inline ? 'inline' : 'file');
  const hasEntries = Array.isArray(data?.entries) && data.entries.length > 0;
  processListSlots[slot] = hasEntries ? { entries: data.entries, fileCount: data.fileCount || 0 } : null;
  pages.processes.data = mergeProcessList(processListSlots);

  const nav = document.getElementById('navProcesses');
  if (nav) nav.disabled = pages.processes.data.entries.length === 0;
  if (document.getElementById('pageProcesses')?.classList.contains('active')) {
    renderPage('processes', document.getElementById('processesSearch')?.value || '');
  }
}

export function initActivityPages() {
  const pageIds = Object.keys(pages);
  const searchInputs = Object.fromEntries(
    pageIds.map(pageId => [pageId, document.getElementById(`${pageId}Search`)])
  );

  for (const pageId of pageIds) {
    bindDebouncedInput(searchInputs[pageId], (value) => renderPage(pageId, value));
    const exportId = `export${pageId[0].toUpperCase()}${pageId.slice(1)}Csv`;
    document.getElementById(exportId)?.addEventListener('click', () => exportCsv(pageId));
  }

  document.getElementById('grabbedContent')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-grabbed-view]');
    if (!button) return;

    const entry = pages.grabbed.filtered[Number(button.dataset.grabbedView)];
    if (entry) openSourcePreview(entry.source);
  });

  return {
    renders: Object.fromEntries(
      pageIds.map(pageId => [
        pageId,
        (q) => renderPage(pageId, q || searchInputs[pageId]?.value || ''),
      ])
    ),
    openScreenshotLightbox,
    getScreenshotsFiltered: () => pages.screenshots.filtered,
    resetSearches: () => {
      for (const input of Object.values(searchInputs)) {
        if (input) input.value = '';
      }
    },
  };
}

// Getters

function getDownloadsData() { return pages.downloads.data; }
function getDomainDetectionsData() { return pages.detections.data; }
function getClipboardData() { return pages.clipboard.data; }
function getGrabbedFilesData() { return pages.grabbed.data; }
function getScreenshotsData() { return pages.screenshots.data; }

export {
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getGrabbedFilesData,
  getScreenshotsData,
};
