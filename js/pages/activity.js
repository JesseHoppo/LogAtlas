// Activity pages: Downloads, Detections, Clipboard, Grabbed files, Screenshots, Software, Processes

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
  inferBrowserFromPath,
  truncateText,
  parseNodeCached,
  parseTimestampValue,
  showNotification,
} from '../core/shared.js';
import {
  countLabel,
  datasetSummary,
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  buildNoMatchesHtml,
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
  createTableSort,
  bindTableSort,
  openTransientModal,
} from './shared.js';
import { DATA_PAGE_EMPTY_TEXT } from './registry.js';

const SCREENSHOT_MEASURE_BATCH = 16;

const EMPTY_CELL = '<span class="cell-empty">\u2014</span>';

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

// A column carries the whole value in its title so that a cell too narrow to
// show it is still readable on hover, and so that a click copies the value
// rather than the truncation.
function fullCell(read) {
  return (entry) => {
    const value = String(read(entry) ?? '');
    return `<td title="${escapeHtml(value)}">${escapeHtml(value)}</td>`;
  };
}

function plainCell(read) {
  return (entry) => `<td>${escapeHtml(String(read(entry) ?? ''))}</td>`;
}

// One definition per page. Element ids follow the page key as registry.js
// names them (`<key>Summary/Stats/Content/Search`, `export<Key>Csv`). What a
// page does differently — search fields, stat tiles, the block above the
// table, the table itself, the CSV shape — hangs off its entry here, so a
// change to the shared scaffold cannot reach one page and miss the other six.
//
// `columns` is the single description of a column: `label` puts it in the
// table, `csv` puts it in the export, `value` is what it holds — used to sort
// it, to write it to the CSV, and to decide whether the dataset fills it at
// all. `cell` overrides the markup, `sort` and `csvValue` override the value
// where the two differ. A column with neither `label` nor `csv` would be
// invisible; one with no `value` (the Actions button) is structure, not data,
// and is always kept.
const pages = {
  downloads: {
    navId: 'navDownloads',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    noun: 'download',
    matches: (e, q) =>
      e.filePath.toLowerCase().includes(q) ||
      e.sourceUrl.toLowerCase().includes(q) ||
      e.fileSizeRaw.toLowerCase().includes(q) ||
      e.fileSizeDisplay.toLowerCase().includes(q) ||
      e.domain.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q) ||
      e.browser.toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => {
      const extensionCounts = {};
      let withSourceUrl = 0, withFileSize = 0, totalKnownBytes = 0, knownSizeCount = 0;
      for (const entry of filtered) {
        if (entry.extension) extensionCounts[entry.extension] = (extensionCounts[entry.extension] || 0) + 1;
        if (entry.sourceUrl) withSourceUrl++;
        if (entry.fileSizeDisplay) withFileSize++;
        if (entry.fileSizeBytes != null) { totalKnownBytes += entry.fileSizeBytes; knownSizeCount++; }
      }
      const topExtension = Object.entries(extensionCounts).sort((a, b) => b[1] - a[1])[0];
      return [
        { value: withSourceUrl.toLocaleString(), label: 'With source URL' },
        { value: withFileSize.toLocaleString(), label: 'With file size' },
        { value: escapeHtml(topExtension ? topExtension[0] : '-'), label: 'Top extension' },
        { value: escapeHtml(knownSizeCount > 0 ? formatBytes(totalKnownBytes) : '-'), label: 'Known total size' },
      ];
    },
    csvFile: 'downloads.csv',
    columns: [
      { label: 'File Path', csv: 'File Path', value: (e) => e.filePath, cell: fullCell((e) => e.filePath) },
      { label: 'Source URL', csv: 'Source URL', value: (e) => e.sourceUrl, cell: fullCell((e) => e.sourceUrl) },
      // Size sorts on the parsed byte count, so "9 KB" lands below "1 MB", and
      // exports the log's own wording rather than the reformatted label.
      {
        label: 'File Size', csv: 'File Size',
        value: (e) => e.fileSizeDisplay,
        csvValue: (e) => e.fileSizeRaw || e.fileSizeDisplay,
        sort: (e) => e.fileSizeBytes,
        cell: fullCell((e) => e.fileSizeDisplay),
      },
      { label: 'Extension', csv: 'Extension', value: (e) => e.extension },
      { label: 'Domain', csv: 'Domain', value: (e) => e.domain },
      { label: 'Browser', csv: 'Browser', value: (e) => e.browser },
    ],
  },

  detections: {
    navId: 'navDetections',
    emptyData: () => ({ entries: [], fileCount: 0, totalHits: 0 }),
    noun: 'detection',
    matches: (e, q) =>
      e.section.toLowerCase().includes(q) ||
      e.label.toLowerCase().includes(q) ||
      e.target.toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => {
      const targets = new Set();
      const sections = new Set();
      let labelled = 0, hits = 0;
      for (const entry of filtered) {
        targets.add(entry.target.toLowerCase());
        sections.add(entry.section);
        if (entry.label) labelled++;
        hits += entry.count;
      }
      return [
        { value: targets.size.toLocaleString(), label: 'Unique targets' },
        { value: sections.size.toLocaleString(), label: 'Sections' },
        { value: labelled.toLocaleString(), label: 'Tagged entries' },
        { value: hits.toLocaleString(), label: 'Total hits' },
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
        <span class="domain-bar-count">${count.toLocaleString()}</span>
      </div>`;
      }
      return html + '</div>';
    },
    csvFile: 'domain_detections.csv',
    columns: [
      { label: 'Section', csv: 'Section', value: (e) => e.section },
      { label: 'Label', csv: 'Label', value: (e) => e.label },
      { label: 'Target', csv: 'Target', value: (e) => e.target, cell: fullCell((e) => e.target) },
      { label: 'Count', csv: 'Count', value: (e) => e.count },
      { csv: 'Source', value: (e) => e.source },
    ],
  },

  clipboard: {
    navId: 'navClipboard',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    noun: 'clipboard entry', nounPlural: 'clipboard entries',
    matches: (e, q) =>
      e.type.toLowerCase().includes(q) ||
      e.text.toLowerCase().includes(q) ||
      e.urls.toLowerCase().includes(q) ||
      (e.lure && (LURE_LABELS[e.lure] || e.lure).toLowerCase().includes(q)) ||
      e.evidence.toLowerCase().includes(q) ||
      e.source.toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => [
      { value: filtered.filter(entry => entry.urls).length.toLocaleString(), label: 'With URLs' },
      { value: filtered.filter(entry => entry.type === 'Command').length.toLocaleString(), label: 'Commands' },
      { value: filtered.filter(entry => entry.type === 'Path').length.toLocaleString(), label: 'Paths' },
      { value: filtered.filter(entry => entry.lure).length.toLocaleString(), label: 'Lures' },
    ],
    prelude: (data) => {
      const lureCats = Object.entries(data.stats?.lureCategories || {}).sort((a, b) => b[1] - a[1]);
      if (lureCats.length === 0) return '';
      const chips = lureCats.map(([cat, count]) => `<span class="dash-ioc-family">${escapeHtml(LURE_LABELS[cat] || cat)} ${count.toLocaleString()}</span>`).join(' ');
      return `<div class="data-page-warning"><div class="data-page-warning-title">Clipboard social-engineering / clipper activity</div><div class="data-page-warning-more">Matches known lure patterns.</div><div class="identity-service-tags">${chips}</div></div>`;
    },
    csvFile: 'clipboard.csv',
    columns: [
      // A "Seed Phrase" verdict is the most consequential thing this table
      // says, so the word count it rests on rides in the same cell rather than
      // in a column every other row leaves blank.
      {
        label: 'Type', csv: 'Type', value: (e) => e.type,
        cell: ({ type, evidence }) =>
          `<td>${escapeHtml(type)}${evidence ? ` <span class="dash-ioc-family">${escapeHtml(evidence)}</span>` : ''}</td>`,
      },
      {
        label: 'Lure', csv: 'Lure', value: (e) => e.lure,
        csvValue: (e) => (e.lure ? LURE_LABELS[e.lure] || e.lure : ''),
        cell: ({ lure }) =>
          `<td>${lure ? `<span class="dash-ioc-family">${escapeHtml(LURE_LABELS[lure] || lure)}</span>` : ''}</td>`,
      },
      { csv: 'Evidence', value: (e) => e.evidence },
      {
        label: 'Content', csv: 'Text', value: (e) => e.text,
        cell: ({ text, preview }) => `<td title="${escapeHtml(text)}">${escapeHtml(preview)}</td>`,
      },
      { label: 'URLs', csv: 'URLs', value: (e) => e.urls, cell: fullCell((e) => e.urls) },
      { label: 'Lines', csv: 'Line Count', value: (e) => e.lineCount },
      { csv: 'Length', value: (e) => e.length },
      {
        label: 'Source', csv: 'Source', value: (e) => e.source,
        cell: ({ source }) => `<td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td>`,
      },
    ],
  },

  grabbed: {
    navId: 'navGrabbed',
    emptyData: () => ({ entries: [] }),
    noun: 'grabbed file',
    matches: (e, q) =>
      e.collection.toLowerCase().includes(q) ||
      e.name.toLowerCase().includes(q) ||
      e.relativePath.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => {
      const extensions = new Set();
      let highValue = 0, fileGrabber = 0, totalBytes = 0;
      for (const entry of filtered) {
        if (entry.isHighValue) highValue++;
        if (entry.collection === 'FileGrabber') fileGrabber++;
        if (entry.extension) extensions.add(entry.extension);
        totalBytes += entry.sizeBytes || 0;
      }
      return [
        { value: highValue.toLocaleString(), label: 'High-value files' },
        { value: fileGrabber.toLocaleString(), label: 'FileGrabber' },
        { value: extensions.size.toLocaleString(), label: 'File types' },
        { value: escapeHtml(formatBytes(totalBytes)), label: 'Total size' },
      ];
    },
    prelude: (data) => {
      const cached = data.stats || {};
      if (!cached.highValueCount) return '';
      const chips = (cached.highValueBreakdown || []).map(({ label, count }) => `<span class="dash-ioc-family">${escapeHtml(label)} ${count.toLocaleString()}</span>`).join(' ');
      return `<div class="data-page-warning"><div class="data-page-warning-title">${countLabel(cached.highValueCount, 'high-value file')} grabbed</div><div class="data-page-warning-more">Password databases, wallet files, VPN profiles, or SSH keys were collected.</div>${chips ? `<div class="identity-service-tags">${chips}</div>` : ''}</div>`;
    },
    csvFile: 'grabbed_files.csv',
    columns: [
      { label: 'Collection', csv: 'Collection', value: (e) => e.collection },
      {
        label: 'Name', csv: 'Name', value: (e) => e.name,
        cell: ({ name, isHighValue, highValue }) =>
          `<td title="${escapeHtml(name)}">${escapeHtml(name)}${isHighValue ? ` <span class="dash-ioc-family">${escapeHtml(highValue)}</span>` : ''}</td>`,
      },
      { csv: 'High Value', value: (e) => e.highValue },
      { label: 'Path', csv: 'Path', value: (e) => e.relativePath, cell: fullCell((e) => e.relativePath) },
      { label: 'Ext', csv: 'Extension', value: (e) => e.extension },
      // Size and Modified sort on the raw byte count and Date, not their labels.
      {
        label: 'Size', csv: 'Size Bytes', value: (e) => e.sizeDisplay,
        csvValue: (e) => e.sizeBytes, sort: (e) => e.sizeBytes,
      },
      {
        label: 'Modified', csv: 'Modified',
        value: (e) => formatOptionalDate(e.modifiedDate),
        sort: (e) => e.modifiedDate,
        cell: ({ modifiedDate }) => {
          const modified = formatOptionalDate(modifiedDate);
          return `<td>${modified ? escapeHtml(modified) : EMPTY_CELL}</td>`;
        },
      },
      {
        label: 'Actions',
        cell: (entry, index) => `<td><button class="table-action-btn" data-grabbed-view="${index}">View</button></td>`,
      },
      { csv: 'Source', value: (e) => e.source },
    ],
  },

  screenshots: {
    navId: 'navScreenshots',
    emptyData: () => ({ entries: [] }),
    noun: 'screenshot',
    matches: (e, q) =>
      e.name.toLowerCase().includes(q) ||
      e.path.toLowerCase().includes(q) ||
      `${e.width || ''}x${e.height || ''}`.toLowerCase().includes(q),
    // Counted over the filtered cards on screen, not the whole dataset.
    stats: (data, filtered) => {
      const knownDimensions = filtered.filter(entry => entry.width && entry.height).length;
      const largest = filtered.reduce((max, entry) => !max || entry.sizeBytes > max.sizeBytes ? entry : max, null);
      const highestResolution = filtered.reduce((max, entry) => {
        const area = (entry.width || 0) * (entry.height || 0);
        const maxArea = max ? (max.width || 0) * (max.height || 0) : 0;
        return area > maxArea ? entry : max;
      }, null);
      return [
        { value: filtered.length.toLocaleString(), label: 'Images' },
        { value: knownDimensions.toLocaleString(), label: 'With dimensions' },
        { value: escapeHtml(formatBytes(filtered.reduce((sum, entry) => sum + (entry.sizeBytes || 0), 0))), label: 'Total size' },
        {
          value: escapeHtml(highestResolution && highestResolution.width ? `${highestResolution.width}\u00d7${highestResolution.height}` : (largest ? largest.sizeDisplay : '-')),
          label: highestResolution && highestResolution.width ? 'Top resolution' : 'Largest file',
        },
      ];
    },
    gridClass: 'screenshot-grid',
    card: screenshotCardBuilder,
    onReset: (data) => revokeScreenshotUrls(data),
    csvFile: 'screenshots.csv',
    // Cards, not a table, so every column here is export-only.
    columns: [
      { csv: 'Name', value: (e) => e.name },
      { csv: 'Path', value: (e) => e.path },
      { csv: 'Width', value: (e) => e.width },
      { csv: 'Height', value: (e) => e.height },
      { csv: 'Size Bytes', value: (e) => e.sizeBytes },
    ],
  },

  software: {
    navId: 'navSoftware',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    noun: 'program',
    matches: (e, q) => e.name.toLowerCase().includes(q) || (e.version && e.version.toLowerCase().includes(q)),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => [
      { value: filtered.filter(entry => /(anydesk|teamviewer|rustdesk|supremo|parsec|mobaxtterm|ultraviewer|vnc|remote desktop)/i.test(entry.name)).length.toLocaleString(), label: 'Remote tools' },
      { value: filtered.filter(entry => /(metamask|bitwarden|keepass|exodus|phantom|atomic wallet|electrum|ledger live)/i.test(entry.name)).length.toLocaleString(), label: 'Wallet / vault apps' },
      { value: filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|chromium)/i.test(entry.name)).length.toLocaleString(), label: 'Browsers' },
      { value: filtered.filter(entry => /(python|visual studio|code|git|docker|node\.js|java|composer|npm)/i.test(entry.name)).length.toLocaleString(), label: 'Developer tools' },
    ],
    onReset: () => { softwareSlots = { inline: null, file: null }; },
    csvFile: 'software.csv',
    columns: [
      { label: 'Software Name', csv: 'Software Name', value: (e) => e.name, cell: fullCell((e) => e.name) },
      { label: 'Version', csv: 'Version', value: (e) => e.version },
    ],
  },

  processes: {
    navId: 'navProcesses',
    emptyData: () => ({ entries: [], fileCount: 0 }),
    noun: 'process', nounPlural: 'processes',
    matches: (e, q) =>
      e.name.toLowerCase().includes(q) ||
      String(e.pid || '').includes(q) ||
      String(e.sessionId || '').includes(q) ||
      String(e.commandLine || '').toLowerCase().includes(q),
    // Counted over the filtered rows on screen, not the whole dataset.
    stats: (data, filtered) => [
      { value: filtered.filter(entry => /(chrome|edge|firefox|opera|brave|vivaldi|iexplore|msedge)/i.test(entry.name)).length.toLocaleString(), label: 'Browsers' },
      { value: filtered.filter(entry => /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.name) || /(anydesk|teamviewer|rustdesk|parsec|mobaxtterm|mstsc|vnc)/i.test(entry.commandLine || '')).length.toLocaleString(), label: 'Remote access' },
      { value: filtered.filter(entry => /(defender|avast|kaspersky|mcafee|crowdstrike|sentinel|eset|norton|bitdefender)/i.test(entry.name)).length.toLocaleString(), label: 'Security tools' },
      { value: filtered.filter(entry => entry.commandLine).length.toLocaleString(), label: 'With command line' },
    ],
    onReset: () => { processListSlots = { inline: null, file: null }; },
    csvFile: 'processes.csv',
    columns: [
      { label: 'Process Name', csv: 'Process Name', value: (e) => e.name, cell: fullCell((e) => e.name) },
      { label: 'PID', csv: 'PID', value: (e) => e.pid, sort: (e) => (e.pid ? Number(e.pid) : null) },
      { label: 'Session', csv: 'Session ID', value: (e) => e.sessionId },
      {
        label: 'Command Line', csv: 'Command Line', value: (e) => e.commandLine,
        cell: ({ commandLine }) =>
          `<td title="${escapeHtml(commandLine || '')}">${escapeHtml(truncateText(commandLine || '', 120))}</td>`,
      },
    ],
  },
};

// A column orders by its own value unless it declared something else to order
// by; `sort: null` opts out, which is what an Actions cell has to do.
function sortAccessor(column) {
  return column.sort === undefined ? column.value : column.sort;
}

// The key is the column's position in the page's full list, so it survives a
// column being dropped from the table for holding nothing.
for (const page of Object.values(pages)) {
  page.data = page.emptyData();
  page.filtered = [];
  page.shown = 0;
  page.renderRow = page.card || (() => '');
  page.sort = createTableSort((key) => {
    const match = /^col(\d+)$/.exec(key);
    if (!match) return null;
    const column = page.columns[Number(match[1])];
    return column?.label ? sortAccessor(column) : null;
  });
}

const pageRegistry = createPagedCollectionRegistry(Object.fromEntries(
  Object.entries(pages).map(([pageId, page]) => [pageId, {
    navId: page.navId,
    rowBuilder: (entry, index) => page.renderRow(entry, index),
    getFiltered: () => page.filtered,
    getShown: () => page.shown,
    setShown: (value) => { page.shown = value; },
    isEmpty: () => page.data.entries.length === 0,
    reset: () => {
      page.onReset?.(page.data);
      page.data = page.emptyData();
      page.filtered = [];
      page.shown = 0;
      page.sort.reset();
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

  for (const { node, path } of nodes) {
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
      const browserIdx = parsed.headers.findIndex(h => /^browser$/i.test(h));
      // Only a pooled dump names the browser per row; a per-browser dump names
      // it in the file name. `Chrome_Default[9a1f].txt` joins the two with an
      // underscore, a word character, so the name is separated before matching.
      const pathBrowser = inferBrowserFromPath(String(path || node.name).replace(/_/g, ' '));

      for (const row of parsed.rows) {
        const filePath = (fileIdx >= 0 ? row[fileIdx] : row[0]) || '';
        const sourceUrl = (urlIdx >= 0 ? row[urlIdx] : row[1]) || '';
        const sizeInfo = parseDownloadSize(sizeIdx >= 0 ? row[sizeIdx] : '');
        const domain = extractDomain(sourceUrl) || '';
        const extension = extractDownloadExtension(filePath, sourceUrl);
        const rowBrowser = browserIdx >= 0 ? (row[browserIdx] || '').trim() : '';

        if (!filePath && !sourceUrl) continue;
        entries.push({
          filePath: filePath.trim(),
          sourceUrl: sourceUrl.trim(),
          fileSizeRaw: sizeInfo.raw,
          fileSizeBytes: sizeInfo.bytes,
          fileSizeDisplay: sizeInfo.display,
          domain,
          extension,
          browser: rowBrowser || pathBrowser,
        });
      }
    } catch {
      // skip
    }
  }

  pages.downloads.data = { entries, fileCount };
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

  const sectionCounts = {};
  for (const entry of entries) {
    sectionCounts[entry.section] = (sectionCounts[entry.section] || 0) + entry.count;
  }

  pages.detections.data = {
    entries,
    fileCount,
    totalHits,
    stats: {
      topSections: Object.entries(sectionCounts).sort((a, b) => b[1] - a[1]).slice(0, 8),
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
          // The word count behind a seed-phrase verdict. The classifier vouches
          // for nothing else, so every other row leaves this empty.
          evidence: (row[5] || '').trim(),
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  const lureCategories = {};
  for (const e of entries) {
    if (e.lure) lureCategories[e.lure] = (lureCategories[e.lure] || 0) + 1;
  }

  pages.clipboard.data = {
    entries,
    fileCount,
    stats: { lureCategories },
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

  pages.grabbed.data = {
    entries,
    stats: { highValueCount, highValueBreakdown },
  };
}

async function loadScreenshotsData(fileTree, rootName) {
  revokeScreenshotUrls(pages.screenshots.data);

  const nodes = [];
  collectHintedNodes(fileTree, '_screenshotHint', rootName, nodes);

  if (nodes.length === 0) {
    pages.screenshots.data = { entries: [] };
    return;
  }

  const entries = [];

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;

      const blob = new Blob([content], { type: getImageMimeFromName(node.name) });
      const blobUrl = URL.createObjectURL(blob);
      const sizeBytes = node.size || content.byteLength || 0;

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

  pages.screenshots.data = { entries };
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

// The Overview shows the first screenshot too and opens this same viewer.
// A click anywhere dismisses it, which is what the zoom-out cursor promises.
export function openScreenshotLightbox(src, alt) {
  if (!src) return;
  const modal = openTransientModal(
    `<img src="${escapeHtml(src)}" alt="${escapeHtml(alt || 'Screenshot')}">`,
    { label: alt || 'Screenshot' }
  );
  if (!modal) return;
  modal.overlay.classList.add('screenshot-lightbox');
  modal.overlay.addEventListener('click', () => modal.close());
}

// Rendering

// A column no row in the dataset fills is noise, and it pushes the columns
// that do carry evidence off the screen: half the process dumps record a name
// and nothing else, and plenty of download dumps record a URL without ever
// naming the file it landed in. The judgement is made over the whole dataset
// rather than the rows currently on screen, so a search that happens to
// exclude every row with a source URL does not take the column away with it.
// Recomputed only when the dataset itself is replaced.
function filledColumns(page) {
  if (page.filledFor === page.data) return page.filled;

  const filled = new Set();
  let pending = [];
  page.columns.forEach((column, index) => {
    if (column.value) pending.push({ index, read: column.value });
    else filled.add(index);
  });

  for (const entry of page.data.entries) {
    if (pending.length === 0) break;
    pending = pending.filter(({ index, read }) => {
      const value = read(entry);
      if (value == null || String(value).trim() === '') return true;
      filled.add(index);
      return false;
    });
  }

  page.filled = filled;
  page.filledFor = page.data;
  return filled;
}

// The column being sorted on stays whatever it holds: having it disappear
// under the analyst who just clicked it is worse than an empty column.
function keptColumns(page) {
  const filled = filledColumns(page);
  const sorted = /^col(\d+)$/.exec(page.sort.key);
  const sortedIndex = sorted ? Number(sorted[1]) : -1;
  return page.columns
    .map((column, index) => ({ column, index }))
    .filter(({ index }) => filled.has(index) || index === sortedIndex);
}

function tableRowBuilder(columns) {
  const cells = columns.map(({ column }) => column.cell || plainCell(column.value));
  return (entry, index) => `<tr>${cells.map((cell) => cell(entry, index)).join('')}</tr>`;
}

function tableHtml(page, columns, rows) {
  const headings = columns.map(({ column, index }) => (
    sortAccessor(column) ? page.sort.th(`col${index}`, column.label) : `<th>${escapeHtml(column.label)}</th>`
  )).join('');
  return `<div class="data-table-container"><table class="data-table"><thead><tr>${headings}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

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
    summary.textContent = '';
    stats.innerHTML = '';
    content.innerHTML = `<div class="no-data">${DATA_PAGE_EMPTY_TEXT[pageId]}</div>`;
    return;
  }

  let filtered = data.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry => page.matches(entry, q));
  }
  filtered = page.sort.apply(filtered);
  page.filtered = filtered;
  page.shown = Math.min(PAGE_SIZE, filtered.length);

  summary.textContent = datasetSummary({
    shown: filtered.length,
    total: data.entries.length,
    singular: page.noun,
    plural: page.nounPlural,
    fileCount: data.fileCount,
  });

  // Rendering the table anyway would leave bare column headings — or, on the
  // screenshot grid, nothing at all — which reads as a failed load. The stat
  // tiles go with it: a row of zeroes adds nothing to the message above it.
  if (filtered.length === 0) {
    stats.innerHTML = '';
    content.innerHTML = buildNoMatchesHtml(page.nounPlural || `${page.noun}s`);
    return;
  }

  stats.innerHTML = statCardsHtml(page.stats(data, filtered));

  const tableColumns = page.card ? [] : keptColumns(page).filter(({ column }) => column.label);
  page.renderRow = page.card || tableRowBuilder(tableColumns);

  const rows = buildRowsHtml(page.renderRow, filtered, 0, page.shown);
  let html = page.prelude ? page.prelude(data) : '';
  html += page.gridClass
    ? `<div class="${page.gridClass}">${rows}</div>`
    : tableHtml(page, tableColumns, rows);

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
    bindTableSort(`${pageId}Content`, pages[pageId].sort, () =>
      renderPage(pageId, searchInputs[pageId]?.value || ''));
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
    openScreenshotLightbox: (entry) => openScreenshotLightbox(entry?.blobUrl, entry?.name),
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
