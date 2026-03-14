// Browser pages: History, Bookmarks, Browser Metadata

import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parseHistoryFile,
  parseBookmarkFile,
  parseBrowserMetadataFile,
} from '../transforms/structured.js';
import {
  collectHintedNodes,
  extractDomain,
  extractBaseDomain,
  inferBrowserFromPath,
  inferProfileFromPath,
  parseTimestampValue,
} from '../core/shared.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import {
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  bindDebouncedInput,
  formatTimestampDisplay,
  trimRootPath,
  inferMetadataCategory,
  addAdjustColumnsBtn,
  downloadCsvRows,
  createPagedCollectionRegistry,
} from './shared.js';

let historyData = { entries: [], fileCount: 0 };
let bookmarksData = { entries: [], fileCount: 0 };
let browserMetadataData = { entries: [], fileCount: 0 };

let historyFiltered = [];
let historyShown = 0;
let bookmarksFiltered = [];
let bookmarksShown = 0;
let browserMetadataFiltered = [];
let browserMetadataShown = 0;

let historySort = { key: 'none', order: 'none' };

const pageRegistry = createPagedCollectionRegistry({
  history: {
    navId: 'navHistory',
    rowBuilder: historyRowBuilder,
    getFiltered: () => historyFiltered,
    getShown: () => historyShown,
    setShown: (value) => { historyShown = value; },
    isEmpty: () => historyData.entries.length === 0,
    reset: () => {
      historyData = { entries: [], fileCount: 0 };
      historyFiltered = [];
      historyShown = 0;
      historySort = { key: 'none', order: 'none' };
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
    },
  },
  browsermeta: {
    navId: 'navBrowserMeta',
    rowBuilder: browserMetadataRowBuilder,
    getFiltered: () => browserMetadataFiltered,
    getShown: () => browserMetadataShown,
    setShown: (value) => { browserMetadataShown = value; },
    isEmpty: () => browserMetadataData.entries.length === 0,
    reset: () => {
      browserMetadataData = { entries: [], fileCount: 0 };
      browserMetadataFiltered = [];
      browserMetadataShown = 0;
    },
  },
});

async function loadHistoryData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_historyHint', rootName, nodes);
  if (nodes.length === 0) { historyData = { entries: [], fileCount: 0 }; return; }

  const entries = [];
  let fileCount = 0;

  for (const { node } of nodes) {
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
          const parsedVisitCount = visitsIdx >= 0 ? Number.parseInt(row[visitsIdx], 10) : NaN;
          entries.push({
            url,
            title: titleIdx >= 0 ? (row[titleIdx] || '').trim() : '',
            visitCount: Number.isNaN(parsedVisitCount) ? 1 : parsedVisitCount,
            lastVisit,
            lastVisitDate: parseTimestampValue(lastVisit),
          });
        }
      }
    } catch { /* skip */ }
  }
  historyData = { entries, fileCount };
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
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseBookmarkFile(text);
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
        entries.push({ browser, profile, category, key, value, source: path });
      }
    } catch { /* skip */ }
  }
  browserMetadataData = { entries, fileCount };
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
  const topDomains = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const uniqueDomains = Object.keys(domainCounts).length;
  const datedEntries = historyData.entries.filter(entry => entry.lastVisitDate);
  const mostRecent = datedEntries.length > 0 ? datedEntries.reduce((latest, entry) => !latest || entry.lastVisitDate > latest.lastVisitDate ? entry : latest, null) : null;

  summary.textContent = filtered.length !== historyData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`
    : `${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_historyHint', 'history');

  stats.innerHTML = `
    <div class="data-page-stat"><div class="data-page-stat-value">${uniqueDomains.toLocaleString()}</div><div class="data-page-stat-label">Unique Domains</div></div>
    ${mostRecent ? `<div class="data-page-stat"><div class="data-page-stat-value" style="font-size:0.95rem">${escapeHtml(formatTimestampDisplay(mostRecent.lastVisitDate))}</div><div class="data-page-stat-label">Most Recent Visit</div></div>` : ''}
  `;

  let html = '';
  if (topDomains.length > 0) {
    const maxCount = topDomains[0][1];
    html += '<div class="domain-bars">';
    for (const [domain, count] of topDomains) {
      const pct = Math.round((count / maxCount) * 100);
      html += `<div class="domain-bar-row"><span class="domain-bar-label">${escapeHtml(domain)}</span><div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div><span class="domain-bar-count">${count}</span></div>`;
    }
    html += '</div>';
  }

  const visitsSortClass = historySort.key === 'visits' ? `sortable sort-${historySort.order}` : 'sortable';
  const lastVisitSortClass = historySort.key === 'lastVisit' ? `sortable sort-${historySort.order}` : 'sortable';
  html += '<div class="data-table-container"><table class="data-table">';
  html += `<thead><tr><th>URL</th><th>Title</th><th class="${visitsSortClass}" id="historyVisitsHeader">Visits</th><th class="${lastVisitSortClass}" id="historyLastVisitHeader">Last Visit</th></tr></thead><tbody>`;
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
    <div class="data-page-stat"><div class="data-page-stat-value">${uniqueDomains.size.toLocaleString()}</div><div class="data-page-stat-label">Unique Domains</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withTitles.toLocaleString()}</div><div class="data-page-stat-label">With Title</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withFolders.toLocaleString()}</div><div class="data-page-stat-label">With Folder</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${browsers.size.toLocaleString()}</div><div class="data-page-stat-label">Browsers</div></div>
  `;

  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>URL</th><th>Title</th><th>Folder</th><th>Browser</th><th>Profile</th><th>Domain</th><th>Source</th></tr></thead><tbody>';
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
    <div class="data-page-stat"><div class="data-page-stat-value">${browsers.size.toLocaleString()}</div><div class="data-page-stat-label">Browsers</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${profiles.size.toLocaleString()}</div><div class="data-page-stat-label">Profiles</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${categories.size.toLocaleString()}</div><div class="data-page-stat-label">Categories</div></div>
    <div class="data-page-stat"><div class="data-page-stat-value">${withValues.toLocaleString()}</div><div class="data-page-stat-label">With Value</div></div>
  `;

  let html = '<div class="data-table-container"><table class="data-table"><thead><tr><th>Browser</th><th>Profile</th><th>Category</th><th>Key</th><th>Value</th><th>Source</th></tr></thead><tbody>';
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

export function reset() {
  pageRegistry.reset();
}

export function initBrowserPages() {
  const searchInputs = {
    history: document.getElementById('historySearch'),
    bookmarks: document.getElementById('bookmarksSearch'),
    browsermeta: document.getElementById('browserMetaSearch'),
  };
  const renderers = {
    history: renderHistoryPage,
    bookmarks: renderBookmarksPage,
    browsermeta: renderBrowserMetaPage,
  };
  for (const [pageName, input] of Object.entries(searchInputs)) {
    bindDebouncedInput(input, (value) => renderers[pageName](value));
  }

  document.getElementById('historyContent')?.addEventListener('click', (e) => {
    const header = e.target.closest('#historyVisitsHeader, #historyLastVisitHeader');
    if (!header) return;
    const nextKey = header.id === 'historyLastVisitHeader' ? 'lastVisit' : 'visits';
    if (historySort.key !== nextKey) historySort = { key: nextKey, order: 'desc' };
    else if (historySort.order === 'desc') historySort = { key: nextKey, order: 'asc' };
    else historySort = { key: 'none', order: 'none' };
    renderHistoryPage(searchInputs.history?.value || '');
  });

  for (const [id, handler] of Object.entries({
    exportHistoryCsv: exportHistoryCSV,
    exportBookmarksCsv: exportBookmarksCSV,
    exportBrowserMetaCsv: exportBrowserMetadataCSV,
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

function getHistoryData() { return historyData; }
function getBookmarksData() { return bookmarksData; }
function getBrowserMetadataData() { return browserMetadataData; }

export {
  getHistoryData,
  getBookmarksData,
  getBrowserMetadataData,
};
