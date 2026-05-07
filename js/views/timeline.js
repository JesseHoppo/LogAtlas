// Timeline

import { state, on } from '../core/state.js';
import { bindDebouncedInput, downloadCsvRows } from '../pages/shared.js';
import { getCookiesData, getNotesData } from '../pages/credentials.js';
import { getHistoryData } from '../pages/browser.js';
import { getGrabbedFilesData, getScreenshotsData } from '../pages/activity.js';
import { extractBaseDomain, extractDomain, collectFileNodes, parseTimestampValue } from '../core/shared.js';
import { escapeHtml } from '../core/utils.js';
import { CAPTURE_TIME_KEYS, IGNORE_DATE_KEYS, FIELD_PATTERNS, LIMITS } from '../core/definitions/patterns.js';

let sysinfoEntries = null;
let timelineEvents = [];
let timelineBuilt = false;
let activeCategories = new Set(['stealer', 'file', 'cookie', 'history', 'notes', 'screenshots']);

const CATEGORIES = {
  stealer: { label: 'Stealer', badgeClass: 'timeline-event-badge-stealer' },
  file:    { label: 'Files',   badgeClass: 'timeline-event-badge-file' },
  cookie:  { label: 'Cookies', badgeClass: 'timeline-event-badge-cookie' },
  history: { label: 'History', badgeClass: 'timeline-event-badge-history' },
  notes: { label: 'Notes', badgeClass: 'timeline-event-badge-cookie' },
  screenshots: { label: 'Screenshots', badgeClass: 'timeline-event-badge-history' },
};

function getCookieField({ row, headers }, pattern) {
  const index = headers.findIndex(h => pattern.test(h));
  return index >= 0 ? (row[index] || '') : '';
}

function formatDate(date) {
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatDateTime(date) {
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function dateKey(date) {
  return date.toISOString().slice(0, 10); // YYYY-MM-DD for grouping
}


function extractStealerEvents(entries) {
  if (!entries) return [];
  const events = [];

  // Look for timezone to annotate capture time
  let timezone = '';
  for (const [key, value] of Object.entries(entries)) {
    if (/^(time\s*zone|timezone|utc)$/i.test(key) && value) {
      timezone = value.trim();
      break;
    }
  }

  for (const [key, value] of Object.entries(entries)) {
    if (IGNORE_DATE_KEYS.some(rx => rx.test(key))) continue;
    if (CAPTURE_TIME_KEYS.some(rx => rx.test(key))) {
      const date = parseTimestampValue(value);
      if (date) {
        let detail = `${key}: ${value}`;
        if (timezone) detail += ` (${timezone})`;
        events.push({
          time: date,
          category: 'stealer',
          title: `Log captured`,
          detail,
        });
      }
    }
  }
  return events;
}

function extractFileEvents(fileTree, rootName) {
  if (!fileTree) return [];
  const nodes = [];
  collectFileNodes(fileTree, rootName, nodes);

  let earliest = Infinity;
  let latest = -Infinity;
  let count = 0;

  for (const { node } of nodes) {
    if (node.lastModified && node.lastModified > 0) {
      const ms = node.lastModified;
      if (ms < earliest) earliest = ms;
      if (ms > latest) latest = ms;
      count++;
    }
  }

  if (count === 0) return [];

  const events = [];
  const earlyDate = new Date(earliest);
  const lateDate = new Date(latest);

  if (dateKey(earlyDate) === dateKey(lateDate)) {
    // Same day = single event
    events.push({
      time: earlyDate,
      category: 'file',
      title: `${count} files modified`,
      detail: formatDate(earlyDate),
    });
  } else {
    events.push({
      time: earlyDate,
      category: 'file',
      title: `Earliest file modification`,
      detail: `${count} files span ${formatDate(earlyDate)} to ${formatDate(lateDate)}`,
    });
    events.push({
      time: lateDate,
      category: 'file',
      title: `Latest file modification`,
      detail: `${count} files span ${formatDate(earlyDate)} to ${formatDate(lateDate)}`,
    });
  }

  return events;
}

function extractCookieEvents(cookiesData) {
  if (!cookiesData || cookiesData.rows.length === 0) return [];

  // Group by base domain
  const domainMap = {};

  for (const rowData of cookiesData.rows) {
    const { validity, sessionType } = rowData;
    const domain = getCookieField(rowData, FIELD_PATTERNS.cookieDomain).replace(/^\./, '').toLowerCase();
    const baseDomain = extractBaseDomain(domain) || domain;
    if (!baseDomain) continue;

    if (!domainMap[baseDomain]) {
      domainMap[baseDomain] = { valid: 0, expired: 0, validSessions: 0, latestExpiry: null };
    }
    const entry = domainMap[baseDomain];

    if (validity.status === 'valid') entry.valid++;
    else if (validity.status === 'expired') entry.expired++;
    if (sessionType && validity.status === 'valid') entry.validSessions++;

    // Parse expiration date
    const expiresDate = parseTimestampValue(getCookieField(rowData, FIELD_PATTERNS.expires));
    if (expiresDate && (!entry.latestExpiry || expiresDate > entry.latestExpiry)) {
      entry.latestExpiry = expiresDate;
    }
  }

  // Create events for top domains with valid cookies
  const sorted = Object.entries(domainMap)
    .filter(([, stats]) => stats.valid > 0 && stats.latestExpiry)
    .sort((a, b) => b[1].valid - a[1].valid)
    .slice(0, LIMITS.topTimelineCookieDomains);

  const events = [];
  for (const [domain, stats] of sorted) {
    let detail = `${stats.valid} valid, ${stats.expired} expired`;
    if (stats.validSessions > 0) {
      detail += ` - ${stats.validSessions} active session token${stats.validSessions !== 1 ? 's' : ''}`;
    }
    if (stats.latestExpiry) {
      detail += ` - latest expiry: ${formatDate(stats.latestExpiry)}`;
    }
    events.push({
      time: stats.latestExpiry,
      category: 'cookie',
      title: domain,
      detail,
    });
  }

  return events;
}

function extractHistoryEvents(historyData) {
  if (!historyData || historyData.entries.length === 0) return [];

  // Collect entries that have parseable timestamps
  const dated = [];
  for (const entry of historyData.entries) {
    const d = entry.lastVisitDate || parseTimestampValue(entry.lastVisit);
    if (d) {
      dated.push({ ...entry, _date: d });
    }
  }

  if (dated.length === 0) return [];

  // Aggregate by day
  const dayMap = {};
  for (const entry of dated) {
    const key = dateKey(entry._date);
    if (!dayMap[key]) {
      dayMap[key] = { date: entry._date, domains: {}, count: 0 };
    }
    dayMap[key].count++;
    const domain = extractBaseDomain(extractDomain(entry.url)) || 'unknown';
    dayMap[key].domains[domain] = (dayMap[key].domains[domain] || 0) + 1;
  }

  const events = [];
  for (const [, day] of Object.entries(dayMap)) {
    const topDomains = Object.entries(day.domains)
      .sort((a, b) => b[1] - a[1])
      .slice(0, LIMITS.topHistoryDomainsPerDay)
      .map(([d]) => d);

    events.push({
      time: day.date,
      category: 'history',
      title: `${day.count} site${day.count !== 1 ? 's' : ''} visited`,
      detail: topDomains.join(', '),
    });
  }

  return events;
}

function extractNoteEvents(notesData) {
  if (!notesData || notesData.entries.length === 0) return [];
  return notesData.entries
    .filter(entry => entry.modifiedDate instanceof Date && !isNaN(entry.modifiedDate.getTime()))
    .sort((a, b) => b.modifiedDate - a.modifiedDate)
    .slice(0, 12)
    .map(entry => ({
      time: entry.modifiedDate,
      category: 'notes',
      title: entry.title,
      detail: entry.indicators,
    }));
}

function extractGrabbedFileEvents(grabbedData) {
  if (!grabbedData || grabbedData.entries.length === 0) return [];
  return grabbedData.entries
    .filter(entry => entry.modifiedDate instanceof Date && !isNaN(entry.modifiedDate.getTime()))
    .sort((a, b) => b.modifiedDate - a.modifiedDate)
    .slice(0, 12)
    .map(entry => ({
      time: entry.modifiedDate,
      category: 'file',
      title: entry.name,
      detail: entry.relativePath,
    }));
}

function extractScreenshotEvents(screenshotsData) {
  if (!screenshotsData || screenshotsData.entries.length === 0) return [];
  return screenshotsData.entries
    .filter(entry => entry.modifiedDate instanceof Date && !isNaN(entry.modifiedDate.getTime()))
    .sort((a, b) => b.modifiedDate - a.modifiedDate)
    .slice(0, 8)
    .map(entry => ({
      time: entry.modifiedDate,
      category: 'screenshots',
      title: entry.name,
      detail: entry.width && entry.height ? `${entry.width}x${entry.height}` : entry.sizeDisplay,
    }));
}

function buildTimeline() {
  if (timelineBuilt) return;

  const events = [];

  // Stealer dates from sysinfo
  events.push(...extractStealerEvents(sysinfoEntries));

  // File modification times
  events.push(...extractFileEvents(state.fileTree, state.rootZipName));

  // Cookie domain events
  events.push(...extractCookieEvents(getCookiesData()));

  // History events
  events.push(...extractHistoryEvents(getHistoryData()));

  // Notes, grabbed files, screenshots
  events.push(...extractNoteEvents(getNotesData()));
  events.push(...extractGrabbedFileEvents(getGrabbedFilesData()));
  events.push(...extractScreenshotEvents(getScreenshotsData()));

  // Sort newest first
  events.sort((a, b) => b.time - a.time);

  timelineEvents = events;
  timelineBuilt = true;
}

function getFilteredTimelineEvents(searchQuery = '') {
  buildTimeline();

  let filtered = timelineEvents.filter(e => activeCategories.has(e.category));
  if (!searchQuery) return filtered;

  const q = searchQuery.toLowerCase();
  return filtered.filter(e =>
    e.title.toLowerCase().includes(q) ||
    (e.detail && e.detail.toLowerCase().includes(q)) ||
    e.category.toLowerCase().includes(q)
  );
}

function renderStats(events) {
  const el = document.getElementById('timelineStats');
  if (events.length === 0) {
    el.innerHTML = '';
    return;
  }

  let earliest = Infinity;
  let latest = -Infinity;

  for (const ev of events) {
    const t = ev.time.getTime();
    if (t < earliest) earliest = t;
    if (t > latest) latest = t;
  }

  const span = latest !== -Infinity && earliest !== Infinity
    ? `${formatDate(new Date(earliest))} - ${formatDate(new Date(latest))}`
    : '';

  let html = '';

  // Log capture time
  const captureEvent = events.find(e => e.category === 'stealer');
  if (captureEvent) {
    html += `<div class="data-page-stat"><div class="data-page-stat-value" style="font-size:1.3rem;color:var(--error)">${formatDateTime(captureEvent.time)}</div><div class="data-page-stat-label">Log Captured</div></div>`;
  }

  // Valid session count
  const cookies = getCookiesData();
  if (cookies.rows.length > 0) {
    const validSessions = cookies.rows.filter(r => r.sessionType && r.validity.status === 'valid').length;
    if (validSessions > 0) {
      html += `<div class="data-page-stat"><div class="data-page-stat-value cookie-auth-valid">${validSessions}</div><div class="data-page-stat-label">Active Sessions</div></div>`;
    }
  }

  html += `<div class="data-page-stat"><div class="data-page-stat-value">${events.length}</div><div class="data-page-stat-label">Events</div></div>`;

  if (span) {
    html += `<div class="data-page-stat"><div class="data-page-stat-value" style="font-size:0.85rem">${span}</div><div class="data-page-stat-label">Date Range</div></div>`;
  }

  el.innerHTML = html;
}

function renderFilters() {
  const el = document.getElementById('timelineFilters');
  let html = '<div class="timeline-filters">';
  for (const [cat, info] of Object.entries(CATEGORIES)) {
    const count = timelineEvents.filter(e => e.category === cat).length;
    if (count === 0) continue;
    const active = activeCategories.has(cat) ? ' active' : '';
    html += `<button class="timeline-filter-btn${active}" data-cat="${cat}">${info.label} (${count})</button>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

function renderVisualTimeline(events) {
  const el = document.getElementById('timelineVisual');
  if (events.length === 0) {
    el.innerHTML = '';
    return;
  }

  let html = '<div class="timeline-track">';
  let currentGroup = '';

  for (const ev of events) {
    const group = formatDate(ev.time);
    if (group !== currentGroup) {
      currentGroup = group;
      html += `<div class="timeline-date-group">${escapeHtml(group)}</div>`;
    }

    const info = CATEGORIES[ev.category] || CATEGORIES.file;
    html += `<div class="timeline-event tl-${ev.category}">`;
    html += `<div class="timeline-event-header">`;
    html += `<span class="timeline-event-badge ${info.badgeClass}">${info.label}</span>`;
    html += `<span class="timeline-event-title">${escapeHtml(ev.title)}</span>`;
    html += `<span class="timeline-event-time">${formatDateTime(ev.time)}</span>`;
    html += `</div>`;
    if (ev.detail) {
      html += `<div class="timeline-event-detail">${escapeHtml(ev.detail)}</div>`;
    }
    html += `</div>`;
  }

  html += '</div>';
  el.innerHTML = html;
}

function renderTable(events) {
  const el = document.getElementById('timelineContent');
  if (events.length === 0) {
    el.innerHTML = '<div class="no-data">No timeline events match the current filters.</div>';
    return;
  }

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th style="width:160px">Date</th><th style="width:80px">Category</th><th style="width:200px">Event</th><th>Detail</th></tr></thead><tbody>';

  for (const ev of events) {
    const info = CATEGORIES[ev.category] || CATEGORIES.file;
    html += '<tr>';
    html += `<td>${escapeHtml(formatDateTime(ev.time))}</td>`;
    html += `<td><span class="timeline-event-badge ${info.badgeClass}">${info.label}</span></td>`;
    html += `<td title="${escapeHtml(ev.title)}">${escapeHtml(ev.title)}</td>`;
    html += `<td title="${escapeHtml(ev.detail || '')}">${escapeHtml(ev.detail || '')}</td>`;
    html += '</tr>';
  }

  html += '</tbody></table></div>';
  el.innerHTML = html;
}

function renderTimelinePage(searchQuery = '') {
  buildTimeline();

  const summary = document.getElementById('timelineSummary');

  if (timelineEvents.length === 0) {
    summary.textContent = 'No timeline data could be reconstructed from this archive.';
    document.getElementById('timelineStats').innerHTML = '';
    document.getElementById('timelineFilters').innerHTML = '';
    document.getElementById('timelineVisual').innerHTML = '';
    document.getElementById('timelineContent').innerHTML = '<div class="no-data">No timestamp data found in cookies, history, system info, or file metadata.</div>';
    return;
  }

  const filtered = getFilteredTimelineEvents(searchQuery);

  const total = timelineEvents.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length} of ${total} events`
    : `${total} events reconstructed from archive data`;

  renderStats(filtered);
  renderFilters();
  renderVisualTimeline(filtered);
  renderTable(filtered);
}

function exportTimelineCSV() {
  const searchInput = document.getElementById('timelineSearch');
  const filteredEvents = getFilteredTimelineEvents(searchInput?.value || '');
  if (filteredEvents.length === 0) return;
  downloadCsvRows('timeline.csv', ['Timestamp', 'Category', 'Event', 'Detail'], filteredEvents.map((event) => [
    event.time.toISOString(),
    CATEGORIES[event.category]?.label || event.category,
    event.title,
    event.detail || '',
  ]));
}

function isTimelinePageActive() {
  return document.querySelector('.sidebar-nav-item.active')?.dataset.page === 'timeline';
}

function refreshTimelineNav() {
  const navBtn = document.getElementById('navTimeline');
  if (!navBtn) return;
  navBtn.disabled = timelineEvents.length === 0;
}

function invalidateTimeline() {
  timelineBuilt = false;
  // Build now so nav gating reflects whether there's anything to show.
  buildTimeline();
  refreshTimelineNav();
  if (!isTimelinePageActive()) return;
  const search = document.getElementById('timelineSearch');
  renderTimelinePage(search?.value || '');
}

function initTimeline() {
  // analysis:sysinfo keeps sysinfoEntries in sync; data:loaded covers the
  // cookie/history/notes/screenshot getters. Both fire on extract and on
  // reanalyze, so we don't need separate listeners for those events.
  on('analysis:sysinfo', (data) => {
    sysinfoEntries = data?.entries || null;
    invalidateTimeline();
  });

  on('data:loaded', invalidateTimeline);

  on('page:timeline', () => {
    const search = document.getElementById('timelineSearch');
    renderTimelinePage(search?.value || '');
  });

  const search = document.getElementById('timelineSearch');
  bindDebouncedInput(search, (value) => renderTimelinePage(value));

  document.getElementById('timelineFilters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.timeline-filter-btn');
    if (!btn) return;
    const cat = btn.dataset.cat;
    if (activeCategories.has(cat)) {
      activeCategories.delete(cat);
    } else {
      activeCategories.add(cat);
    }
    const searchEl = document.getElementById('timelineSearch');
    renderTimelinePage(searchEl?.value || '');
  });

  document.getElementById('exportTimelineCsv')?.addEventListener('click', exportTimelineCSV);

  on('reset', () => {
    sysinfoEntries = null;
    timelineEvents = [];
    timelineBuilt = false;
    activeCategories = new Set(['stealer', 'file', 'cookie', 'history', 'notes', 'screenshots']);
    document.getElementById('navTimeline').disabled = true;
    const search = document.getElementById('timelineSearch');
    if (search) search.value = '';
  });
}

export { initTimeline };
