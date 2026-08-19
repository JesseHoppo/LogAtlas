// Browser pages: History, Bookmarks, Browser metadata

import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parseHistoryFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
} from '../transforms/structured.js';
import {
  collectHintedNodes,
  decodeBufferWithFallback,
  extractDomain,
  baseDomainFromUrl,
  isRankableDomain,
  inferBrowserFromPath,
  inferProfileFromPath,
  parseNodeCached,
  parseTimestampValue,
  applyBrowserClock,
  browserClockLabel,
  UNKNOWN_BROWSER_CLOCK,
} from '../core/shared.js';
import { browserClockReady } from '../analysis/analysis.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import {
  datasetSummary,
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  buildNoMatchesHtml,
  bindDebouncedInput,
  formatDateTimeLabel,
  trimRootPath,
  inferMetadataCategory,
  addAdjustColumnsBtn,
  exportRows,
  createPagedCollectionRegistry,
  createTableSort,
  bindTableSort,
} from './shared.js';
import { DATA_PAGE_EMPTY_TEXT } from './registry.js';

let historyData = { entries: [], fileCount: 0, clock: UNKNOWN_BROWSER_CLOCK };
let bookmarksData = { entries: [], fileCount: 0 };
let browserMetadataData = { entries: [], fileCount: 0 };

let historyFiltered = [];
let historyShown = 0;
let bookmarksFiltered = [];
let bookmarksShown = 0;

const historySort = createTableSort({
  url: (entry) => entry.url,
  title: (entry) => entry.title,
  visits: (entry) => entry.visitCount,
  lastVisit: (entry) => entry.lastVisitDate,
});
const bookmarksSort = createTableSort({
  url: (entry) => entry.url,
  title: (entry) => entry.title,
  folder: (entry) => entry.folder,
  browser: (entry) => entry.browser,
  profile: (entry) => entry.profile,
  domain: (entry) => entry.domain,
  source: (entry) => entry.source,
});

const pageRegistry = createPagedCollectionRegistry({
  history: {
    navId: 'navHistory',
    rowBuilder: historyRowBuilder,
    getFiltered: () => historyFiltered,
    getShown: () => historyShown,
    setShown: (value) => { historyShown = value; },
    isEmpty: () => historyData.entries.length === 0,
    reset: () => {
      historyData = { entries: [], fileCount: 0, clock: UNKNOWN_BROWSER_CLOCK };
      historyFiltered = [];
      historyShown = 0;
      historySort.reset();
    },
  },
  bookmarks: {
    navId: 'navBookmarks',
    rowBuilder: bookmarkRowBuilder,
    getFiltered: () => bookmarksFiltered,
    getShown: () => bookmarksShown,
    setShown: (value) => { bookmarksShown = value; },
    isEmpty: () => bookmarksData.entries.length === 0,
    reset: () => {
      bookmarksData = { entries: [], fileCount: 0 };
      bookmarksFiltered = [];
      bookmarksShown = 0;
      bookmarksSort.reset();
    },
  },
});

async function loadHistoryData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_historyHint', rootName, nodes);
  if (nodes.length === 0) { historyData = { entries: [], fileCount: 0, clock: UNKNOWN_BROWSER_CLOCK }; return; }

  // A visit time is a bare wall clock with no zone on it, and the frame it was
  // written in is not the victim's — analysis resolves it from the rows and this
  // page reads that answer rather than deriving a second one.
  const clock = await browserClockReady();
  const entries = [];
  let fileCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'history', parseHistoryFile, text, node._parseConfig || null);
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
          // Most stealers record no visit count at all; an absent count stays
          // absent rather than defaulting to a 1 an analyst reads as evidence
          // the site was visited once.
          const parsedVisitCount = visitsIdx >= 0 ? Number.parseInt(row[visitsIdx], 10) : NaN;
          entries.push({
            url,
            title: titleIdx >= 0 ? (row[titleIdx] || '').trim() : '',
            visitCount: Number.isNaN(parsedVisitCount) ? null : parsedVisitCount,
            lastVisit,
            lastVisitDate: applyBrowserClock(parseTimestampValue(lastVisit), clock),
          });
        }
      }
    } catch { /* skip */ }
  }

  historyData = {
    entries,
    fileCount,
    clock,
    hasVisitCounts: entries.some(entry => entry.visitCount !== null),
    stats: historyStats(entries),
  };
}

function historyStats(entries) {
  const domainCounts = new Map();
  let mostRecent = null;
  for (const entry of entries) {
    const domain = baseDomainFromUrl(entry.url);
    if (domain && isRankableDomain(domain)) domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
    if (entry.lastVisitDate && (!mostRecent || entry.lastVisitDate > mostRecent.lastVisitDate)) mostRecent = entry;
  }
  return {
    topDomains: [...domainCounts].sort((a, b) => b[1] - a[1]).slice(0, 10),
    uniqueDomains: domainCounts.size,
    mostRecentDate: mostRecent?.lastVisitDate || null,
    mostRecentRaw: mostRecent?.lastVisit || '',
  };
}

// With the frame resolved the visit time is a real instant and reads as UTC like
// every other timestamp in the case. Without one it is still only the log's own
// wall clock, so it is shown exactly as written rather than dressed as UTC.
function historyClockKnown() {
  return historyData.clock?.offsetMinutes != null;
}

function historyVisitLabel(lastVisit, lastVisitDate) {
  if (!lastVisitDate || !historyClockKnown()) return lastVisit;
  return formatDateTimeLabel(lastVisitDate);
}

function historyClockNote() {
  if (historyClockKnown()) {
    return ` \u00b7 visit times converted to UTC from the log clock ${browserClockLabel(historyData.clock)}`;
  }
  return ' \u00b7 visit times as the log wrote them; clock zone unresolved, not comparable with UTC';
}

async function loadBookmarksData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_bookmarkHint', rootName, nodes);
  if (nodes.length === 0) { bookmarksData = { entries: [], fileCount: 0 }; return; }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'bookmark', parseBookmarkFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);
      for (const row of parsed.rows) {
        const url = (row[0] || '').trim();
        if (!url) continue;
        entries.push({ url, title: (row[1] || '').trim(), folder: (row[2] || '').trim(), browser, profile, domain: extractDomain(url) || '', source: path });
      }
    } catch { /* skip */ }
  }
  bookmarksData = { entries, fileCount };
}

async function loadBrowserMetadataData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_browserMetadataHint', rootName, nodes);
  if (nodes.length === 0) { browserMetadataData = { entries: [], fileCount: 0 }; return; }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = decodeBufferWithFallback(content);
      const parsed = parseNodeCached(node, 'browserMetadata', parseBrowserMetadataFile, text, null);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;
      const browser = inferBrowserFromPath(path || node.name);
      const profile = inferProfileFromPath(path || node.name);
      const category = inferMetadataCategory(path || node.name);
      for (const row of parsed.rows) {
        const key = (row[0] || '').trim();
        const value = (row[1] || '').trim();
        if (!key && !value) continue;
        entries.push({ browser, profile, category, key, value, source: path });
      }
    } catch { /* skip */ }
  }
  browserMetadataData = { entries, fileCount };
}

const EMPTY_CELL = '<span class="cell-empty">\u2014</span>';

function historyRowBuilder({ url, title, visitCount, lastVisit, lastVisitDate }) {
  const displayLastVisit = historyVisitLabel(lastVisit, lastVisitDate);
  const visitsCell = historyData.hasVisitCounts
    ? `<td>${visitCount == null ? EMPTY_CELL : visitCount.toLocaleString()}</td>`
    : '';
  return `<tr><td title="${escapeHtml(url)}">${escapeHtml(url)}</td><td title="${escapeHtml(title)}">${escapeHtml(title)}</td>${visitsCell}<td title="${escapeHtml(lastVisit || '')}">${escapeHtml(displayLastVisit || '')}</td></tr>`;
}

function renderHistoryPage(searchQuery = '') {
  const summary = document.getElementById('historySummary');
  const stats = document.getElementById('historyStats');
  const content = document.getElementById('historyContent');

  if (historyData.entries.length === 0) {
    historyFiltered = [];
    historyShown = 0;
    summary.textContent = 'No history found';
    summary.parentNode?.querySelector('.mapper-adjust-btn')?.remove();
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No history data available.</div>';
    return;
  }

  let filtered = [...historyData.entries];
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.url.toLowerCase().includes(q) || e.title.toLowerCase().includes(q) || e.lastVisit.toLowerCase().includes(q));
  }

  historyFiltered = historySort.apply(filtered);
  historyShown = Math.min(PAGE_SIZE, filtered.length);

  const cached = historyData.stats || { topDomains: [], uniqueDomains: 0, mostRecentDate: null };
  const topDomains = cached.topDomains;

  summary.textContent = filtered.length !== historyData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`
    : `${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_historyHint', 'history');

  stats.innerHTML = `
    <div class="data-page-stat"><div class="data-page-stat-value">${cached.uniqueDomains.toLocaleString()}</div><div class="data-page-stat-label">Unique Domains</div></div>
    ${cached.mostRecentDate ? `<div class="data-page-stat"><div class="data-page-stat-value" style="font-size:0.95rem">${escapeHtml(formatDateTimeLabel(cached.mostRecentDate))}</div><div class="data-page-stat-label">Most Recent Visit</div></div>` : ''}
  `;

  let html = '';
  if (topDomains.length > 0) {
    const maxCount = topDomains[0][1];
    html += '<div class="domain-bars">';
    for (const [domain, count] of topDomains) {
      const pct = Math.round((count / maxCount) * 100);
      html += `<div class="domain-bar-row"><span class="domain-bar-label">${escapeHtml(domain)}</span><div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div><span class="domain-bar-count">${count.toLocaleString()}</span></div>`;
    }
    html += '</div>';
  }

  html += '<div class="data-table-container"><table class="data-table">';
  html += `<thead><tr>${historySort.th('url', 'URL')}${historySort.th('title', 'Title')}${
    historyData.hasVisitCounts ? historySort.th('visits', 'Visits') : ''}${historySort.th('lastVisit', historyClockKnown() ? 'Last Visit (UTC)' : 'Last Visit (log clock)')}</tr></thead><tbody>`;
  html += buildRowsHtml(historyRowBuilder, historyFiltered, 0, historyShown);
  html += '</tbody></table></div>';

  const remaining = historyFiltered.length - historyShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'history');
  content.innerHTML = html;
}

function bookmarkRowBuilder({ url, title, folder, browser, profile, domain, source }) {
  return `<tr><td title="${escapeHtml(url)}">${escapeHtml(url)}</td><td title="${escapeHtml(title)}">${escapeHtml(title)}</td><td>${escapeHtml(folder || '')}</td><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td>${escapeHtml(domain || '')}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderBookmarksPage(searchQuery = '') {
  const summary = document.getElementById('bookmarksSummary');
  const stats = document.getElementById('bookmarksStats');
  const content = document.getElementById('bookmarksContent');

  if (bookmarksData.entries.length === 0) {
    bookmarksFiltered = [];
    bookmarksShown = 0;
    summary.textContent = 'No bookmarks found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No bookmark data available.</div>';
    return;
  }

  let filtered = bookmarksData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry => entry.url.toLowerCase().includes(q) || entry.title.toLowerCase().includes(q) || entry.folder.toLowerCase().includes(q) || entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.domain.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q));
  }

  bookmarksFiltered = bookmarksSort.apply(filtered);
  bookmarksShown = Math.min(PAGE_SIZE, filtered.length);

  const uniqueDomains = new Set(bookmarksData.entries.map(entry => entry.domain).filter(Boolean));
  const withTitles = bookmarksData.entries.filter(entry => entry.title).length;
  const withFolders = bookmarksData.entries.filter(entry => entry.folder).length;
  const browsers = new Set(bookmarksData.entries.map(entry => entry.browser).filter(Boolean));

  summary.textContent = filtered.length !== bookmarksData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${bookmarksData.entries.length.toLocaleString()} bookmarks from ${bookmarksData.fileCount} file(s)`
    : `${bookmarksData.entries.length.toLocaleString()} bookmarks from ${bookmarksData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat"><div class="data-page-stat-value">${uniqueDomains.size.toLocaleString()}</div><div class="data-page-stat-label">Unique Domains</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withTitles.toLocaleString()}</div><div class="data-page-stat-label">With Title</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withFolders.toLocaleString()}</div><div class="data-page-stat-label">With Folder</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${browsers.size.toLocaleString()}</div><div class="data-page-stat-label">Browsers</div></div>
  `;

  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${
    bookmarksSort.th('url', 'URL')}${bookmarksSort.th('title', 'Title')}${bookmarksSort.th('folder', 'Folder')}${
    bookmarksSort.th('browser', 'Browser')}${bookmarksSort.th('profile', 'Profile')}${bookmarksSort.th('domain', 'Domain')}${
    bookmarksSort.th('source', 'Source')}</tr></thead><tbody>`;
  html += buildRowsHtml(bookmarkRowBuilder, bookmarksFiltered, 0, bookmarksShown);
  html += '</tbody></table></div>';
  const remaining = bookmarksFiltered.length - bookmarksShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'bookmarks');
  content.innerHTML = html;
}

function browserMetadataRowBuilder({ browser, profile, category, key, value, source }) {
  return `<tr><td>${escapeHtml(browser || '')}</td><td>${escapeHtml(profile || '')}</td><td>${escapeHtml(category || '')}</td><td title="${escapeHtml(key)}">${escapeHtml(key)}</td><td title="${escapeHtml(value)}">${escapeHtml(value)}</td><td title="${escapeHtml(source)}">${escapeHtml(trimRootPath(source))}</td></tr>`;
}

function renderBrowserMetaPage(searchQuery = '') {
  const summary = document.getElementById('browserMetaSummary');
  const stats = document.getElementById('browserMetaStats');
  const content = document.getElementById('browserMetaContent');

  if (browserMetadataData.entries.length === 0) {
    browserMetadataFiltered = [];
    browserMetadataShown = 0;
    summary.textContent = 'No browser metadata found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No browser metadata available.</div>';
    return;
  }

  let filtered = browserMetadataData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry => entry.browser.toLowerCase().includes(q) || entry.profile.toLowerCase().includes(q) || entry.category.toLowerCase().includes(q) || entry.key.toLowerCase().includes(q) || entry.value.toLowerCase().includes(q) || entry.source.toLowerCase().includes(q));
  }

  browserMetadataFiltered = browserMetaSort.apply(filtered);
  browserMetadataShown = Math.min(PAGE_SIZE, filtered.length);

  const categories = new Set(browserMetadataData.entries.map(entry => entry.category).filter(Boolean));
  const browsers = new Set(browserMetadataData.entries.map(entry => entry.browser).filter(Boolean));
  const profiles = new Set(browserMetadataData.entries.map(entry => entry.profile).filter(Boolean));
  const withValues = browserMetadataData.entries.filter(entry => entry.value).length;

  summary.textContent = filtered.length !== browserMetadataData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${browserMetadataData.entries.length.toLocaleString()} metadata rows from ${browserMetadataData.fileCount} file(s)`
    : `${browserMetadataData.entries.length.toLocaleString()} metadata rows from ${browserMetadataData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat"><div class="data-page-stat-value">${browsers.size.toLocaleString()}</div><div class="data-page-stat-label">Browsers</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${profiles.size.toLocaleString()}</div><div class="data-page-stat-label">Profiles</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${categories.size.toLocaleString()}</div><div class="data-page-stat-label">Categories</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withValues.toLocaleString()}</div><div class="data-page-stat-label">With Value</div></div>
  `;

  let html = `<div class="data-table-container"><table class="data-table"><thead><tr>${
    browserMetaSort.th('browser', 'Browser')}${browserMetaSort.th('profile', 'Profile')}${browserMetaSort.th('category', 'Category')}${
    browserMetaSort.th('key', 'Key')}${browserMetaSort.th('value', 'Value')}${browserMetaSort.th('source', 'Source')}</tr></thead><tbody>`;
  html += buildRowsHtml(browserMetadataRowBuilder, browserMetadataFiltered, 0, browserMetadataShown);
  html += '</tbody></table></div>';
  const remaining = browserMetadataFiltered.length - browserMetadataShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'browsermeta');
  content.innerHTML = html;
}

function exportHistoryCSV() {
  if (historyData.entries.length === 0) return;
  downloadCsvRows('history.csv', ['URL', 'Title', 'Visits', 'Last Visit'], historyData.entries.map(
    ({ url, title, visitCount, lastVisit }) => [url, title, visitCount, lastVisit]
  ));
}

function exportBookmarksCSV() {
  if (bookmarksData.entries.length === 0) return;
  downloadCsvRows('bookmarks.csv', ['URL', 'Title', 'Folder', 'Browser', 'Profile', 'Domain', 'Source'], bookmarksData.entries.map(
    ({ url, title, folder, browser, profile, domain, source }) => [url, title, folder, browser, profile, domain, source]
  ));
}

function exportBrowserMetadataCSV() {
  if (browserMetadataData.entries.length === 0) return;
  downloadCsvRows('browser_metadata.csv', ['Browser', 'Profile', 'Category', 'Key', 'Value', 'Source'], browserMetadataData.entries.map(
    ({ browser, profile, category, key, value, source }) => [browser, profile, category, key, value, source]
  ));
}

export function loadAll(fileTree, rootName) {
  return Promise.all([
    loadHistoryData(fileTree, rootName),
    loadBookmarksData(fileTree, rootName),
    loadBrowserMetadataData(fileTree, rootName),
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

// Browser metadata has no page of its own — it is parsed for the packaged
// report only — so it is cleared here rather than through the page registry.
export function reset() {
  pageRegistry.reset();
  browserMetadataData = { entries: [], fileCount: 0 };
}

export function initBrowserPages() {
  const searchInputs = {
    history: document.getElementById('historySearch'),
    bookmarks: document.getElementById('bookmarksSearch'),
  };
  const renderers = {
    history: renderHistoryPage,
    bookmarks: renderBookmarksPage,
  };
  for (const [pageName, input] of Object.entries(searchInputs)) {
    bindDebouncedInput(input, (value) => renderers[pageName](value));
  }

  bindTableSort('historyContent', historySort, () => renderHistoryPage(searchInputs.history?.value || ''));
  bindTableSort('bookmarksContent', bookmarksSort, () => renderBookmarksPage(searchInputs.bookmarks?.value || ''));

  for (const [id, handler] of Object.entries({
    exportHistoryCsv: exportHistoryCSV,
    exportBookmarksCsv: exportBookmarksCSV,
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
    resetSearches: () => {
      for (const input of Object.values(searchInputs)) {
        if (input) input.value = '';
      }
    },
  };
}

export function getHistoryData() { return historyData; }
export function getBookmarksData() { return bookmarksData; }
export function getBrowserMetadataData() { return browserMetadataData; }
