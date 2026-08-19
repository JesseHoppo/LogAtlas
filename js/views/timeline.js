import { state, on } from '../core/state.js';
import { bindDebouncedInput, bindTableSort, countLabel, createTableSort, downloadCsvRows, formatDateLabel, formatDateTimeLabel, formatInstantLabel } from '../pages/shared.js';
import { getCookiesData, getNotesData } from '../pages/credentials.js';
import { getHistoryData } from '../pages/browser.js';
import { getGrabbedFilesData, getScreenshotsData } from '../pages/activity.js';
import { extractBaseDomain, baseDomainFromUrl, collectFileNodes, isPlausibleCaptureDate, normaliseTimeZone, parseTimestampValue, parseSysinfoDate, sysinfoWritesDayFirst } from '../core/shared.js';
import { isLiveSessionToken } from '../analysis/sessionCookies.js';
import { escapeHtml } from '../core/utils.js';
import { CAPTURE_TIME_KEYS, FIELD_PATTERNS, LIMITS } from '../core/definitions/patterns.js';

let sysinfoEntries = null;
let capture = null;
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

function dateKey(date) {
  return date.toISOString().slice(0, 10);
}

function localTimeZoneLabel(entries) {
  for (const [key, value] of Object.entries(entries || {})) {
    if (/^(time\s*zone|timezone|utc)$/i.test(key) && value) {
      return normaliseTimeZone(value).label || value.trim();
    }
  }
  return '';
}

// The capture instant comes from the analysis pass, so the timeline anchors on
// the same moment the dashboard and Credential triage show. Rival capture-time
// keys stay in the detail rather than becoming rival events.
function extractStealerEvents(entries, captureContext) {
  if (!captureContext?.date) return [];

  const fromSysinfo = captureContext.source === 'sysinfo';
  const captureValue = fromSysinfo ? (entries?.[captureContext.detail] || '') : '';
  const timezone = localTimeZoneLabel(entries);
  let detail = fromSysinfo
    ? `${captureContext.detail}: ${captureValue}`
    : `Inferred from ${captureContext.source}${captureContext.detail ? `: ${captureContext.detail}` : ''}`;
  if (timezone) detail += ` (${timezone})`;

  // A key only conflicts when it names a different instant: the same moment
  // written in a second format is not a rival capture time.
  const captureMs = captureContext.date.getTime();
  const dayFirst = sysinfoWritesDayFirst(entries);
  const others = [];
  for (const [key, value] of Object.entries(entries || {})) {
    if (!value || value === captureValue) continue;
    if (fromSysinfo && key === captureContext.detail) continue;
    if (!CAPTURE_TIME_KEYS.some(rx => rx.test(key))) continue;
    const date = parseSysinfoDate(value, dayFirst);
    if (date && date.getTime() === captureMs) continue;
    others.push(`${key}: ${value}`);
  }
  if (others.length) detail += ` - also reported: ${others.join('; ')}`;

  return [{
    time: captureContext.date,
    source: captureContext.source,
    category: 'stealer',
    title: 'Log captured',
    detail,
  }];
}

function extractFileEvents(fileTree, rootName) {
  if (!fileTree) return [];
  const nodes = [];
  collectFileNodes(fileTree, rootName, nodes);

  let earliest = Infinity;
  let latest = -Infinity;
  let count = 0;

  for (const { node } of nodes) {
    const modifiedDate = node.lastModified ? new Date(node.lastModified) : null;
    if (isPlausibleCaptureDate(modifiedDate)) {
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
    events.push({
      time: earlyDate,
      category: 'file',
      title: `${count} files modified`,
      detail: formatDateLabel(earlyDate),
    });
  } else {
    events.push({
      time: earlyDate,
      category: 'file',
      title: `Earliest file modification`,
      detail: `${count} files span ${formatDateLabel(earlyDate)} to ${formatDateLabel(lateDate)}`,
    });
    events.push({
      time: lateDate,
      category: 'file',
      title: `Latest file modification`,
      detail: `${count} files span ${formatDateLabel(earlyDate)} to ${formatDateLabel(lateDate)}`,
    });
  }

  return events;
}

function extractCookieEvents(cookiesData, captureTime) {
  if (!cookiesData || cookiesData.rows.length === 0) return [];

  const headers = cookiesData.headers;
  const domainIdx = headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
  const expiresIdx = headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
  const domainMap = {};

  for (const rowData of cookiesData.rows) {
    const { row, validity } = rowData;
    const domain = (domainIdx >= 0 ? (row[domainIdx] || '') : '').replace(/^\./, '').toLowerCase();
    const baseDomain = extractBaseDomain(domain) || domain;
    if (!baseDomain) continue;

    if (!domainMap[baseDomain]) {
      domainMap[baseDomain] = { valid: 0, expired: 0, liveSessions: 0, latestExpiry: null };
    }
    const entry = domainMap[baseDomain];

    if (validity.status === 'valid') entry.valid++;
    else if (validity.status === 'expired') entry.expired++;
    if (isLiveSessionToken(rowData)) entry.liveSessions++;

    const expiresDate = parseTimestampValue(expiresIdx >= 0 ? row[expiresIdx] : '');
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
  if (!captureTime) return events;
  for (const [domain, stats] of sorted) {
    let detail = `${stats.valid} valid, ${stats.expired} expired`;
    if (stats.liveSessions > 0) {
      detail += ` - ${stats.liveSessions} live session token${stats.liveSessions !== 1 ? 's' : ''}`;
    }
    if (stats.latestExpiry) {
      detail += ` - latest expiry: ${formatDateLabel(stats.latestExpiry)}`;
    }
    events.push({
      time: captureTime,
      category: 'cookie',
      title: domain,
      detail,
    });
  }

  return events;
}

function extractHistoryEvents(historyData) {
  if (!historyData || historyData.entries.length === 0) return [];

  const dated = [];
  for (const entry of historyData.entries) {
    const d = entry.lastVisitDate;
    if (isPlausibleCaptureDate(d)) {
      dated.push({ ...entry, _date: d });
    }
  }

  if (dated.length === 0) return [];

  const dayMap = {};
  for (const entry of dated) {
    const key = dateKey(entry._date);
    if (!dayMap[key]) {
      dayMap[key] = { date: entry._date, domains: {}, count: 0 };
    }
    dayMap[key].count++;
    const domain = baseDomainFromUrl(entry.url) || 'unknown';
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

function extractModifiedEvents(data, category, limit, pickTitle, pickDetail) {
  if (!data || !data.entries || !data.entries.length) return [];
  return data.entries
    .filter(e => isPlausibleCaptureDate(e.modifiedDate))
    .sort((a, b) => b.modifiedDate - a.modifiedDate)
    .slice(0, limit)
    .map(e => ({ time: e.modifiedDate, category, title: pickTitle(e), detail: pickDetail(e) }));
}

function extractNoteEvents(notesData) {
  return extractModifiedEvents(notesData, 'notes', 12, e => e.title, e => e.indicators);
}

function extractGrabbedFileEvents(grabbedData) {
  return extractModifiedEvents(grabbedData, 'file', 12, e => e.name, e => e.relativePath);
}

function extractScreenshotEvents(screenshotsData) {
  return extractModifiedEvents(screenshotsData, 'screenshots', 8, e => e.name,
    e => (e.width && e.height ? `${e.width}x${e.height}` : e.sizeDisplay));
}

function buildTimeline() {
  if (timelineBuilt) return;

  const events = [];

  // The published capture instant
  events.push(...extractStealerEvents(sysinfoEntries, capture));

  // File modification times
  events.push(...extractFileEvents(state.fileTree, state.rootZipName));

  // Cookie domain events
  events.push(...extractCookieEvents(getCookiesData(), capture?.date || null));

  // History events
  events.push(...extractHistoryEvents(getHistoryData()));

  // Notes, grabbed files, screenshots
  events.push(...extractNoteEvents(getNotesData()));
  events.push(...extractGrabbedFileEvents(getGrabbedFilesData()));
  events.push(...extractScreenshotEvents(getScreenshotsData()));

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
  const now = Date.now();

  for (const ev of events) {
    if (!isPlausibleCaptureDate(ev.time)) continue;
    const t = ev.time.getTime();
    if (t < earliest) earliest = t;
    if (t > latest && t <= now) latest = t;
  }
  if (latest === -Infinity && earliest !== Infinity) latest = earliest;

  const span = latest !== -Infinity && earliest !== Infinity
    ? `${formatDateLabel(new Date(earliest))} - ${formatDateLabel(new Date(latest))}`
    : '';

  let html = '';

  // Log capture time, with the provenance when it isn't the stealer's own stamp
  const captureEvent = events.find(e => e.category === 'stealer');
  if (captureEvent) {
    const label = captureEvent.source && captureEvent.source !== 'sysinfo'
      ? `Log Captured (${captureEvent.source})`
      : 'Log Captured';
    html += `<div class="data-page-stat"><div class="data-page-stat-value timeline-capture-value">${formatDateTimeLabel(captureEvent.time)}</div><div class="data-page-stat-label">${escapeHtml(label)}</div></div>`;
  }

  const cookies = getCookiesData();
  if (cookies.rows.length > 0) {
    const liveSessions = cookies.rows.filter(isLiveSessionToken).length;
    if (liveSessions > 0) {
      html += `<div class="data-page-stat" title="Session tokens live at capture: unexpired, or browser-session cookies carrying no expiry. Confirm before relying on access."><div class="data-page-stat-value cookie-auth-valid">${liveSessions}</div><div class="data-page-stat-label">Live Sessions At Capture</div></div>`;
    }
  }

  html += `<div class="data-page-stat"><div class="data-page-stat-value">${events.length}</div><div class="data-page-stat-label">Events</div></div>`;

  if (span) {
    html += `<div class="data-page-stat"><div class="data-page-stat-value timeline-range-value">${span}</div><div class="data-page-stat-label">Date Range</div></div>`;
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

// Cookie events all carry the capture timestamp: they describe the state of
// the log at collection time, not a sequence of events. Keep them out of the
// chronology and show them as a snapshot table instead.
const CAPTURE_STATE_CATEGORIES = new Set(['cookie']);

function renderChronology(events) {
  const el = document.getElementById('timelineVisual');
  if (events.length === 0) {
    el.innerHTML = '<div class="timeline-note">No events with distinct timestamps. See the capture snapshot below for the state of the log at collection time.</div>';
    return;
  }

  let html = '<div class="dash-section-title">Activity Chronology</div><div class="timeline-track">';
  let currentGroup = '';

  for (const ev of events) {
    const group = formatDateLabel(ev.time);
    if (group !== currentGroup) {
      currentGroup = group;
      html += `<div class="timeline-date-group">${escapeHtml(group)}</div>`;
    }

    const info = CATEGORIES[ev.category] || CATEGORIES.file;
    html += `<div class="timeline-event tl-${ev.category}">`;
    html += `<div class="timeline-event-header">`;
    html += `<span class="timeline-event-badge ${info.badgeClass}">${info.label}</span>`;
    html += `<span class="timeline-event-title">${escapeHtml(ev.title)}</span>`;
    html += `<span class="timeline-event-time">${formatDateTimeLabel(ev.time)}</span>`;
    html += `</div>`;
    if (ev.detail) {
      html += `<div class="timeline-event-detail">${escapeHtml(ev.detail)}</div>`;
    }
    html += `</div>`;
  }

  html += '</div>';
  el.innerHTML = html;
}

function renderCaptureSnapshot(events) {
  const el = document.getElementById('timelineContent');
  if (events.length === 0) {
    el.innerHTML = '';
    return;
  }

  const captureLabel = formatDateTimeLabel(events[0].time);
  let html = `<div class="dash-section-title">Capture Snapshot</div>`;
  html += `<div class="dash-section-subtitle">State of the log at collection time${captureLabel ? ` (${escapeHtml(captureLabel)})` : ''}. These share the capture instant and are not a chronology.</div>`;
  html += '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Domain</th><th>Cookie state at capture</th></tr></thead><tbody>';
  for (const ev of events) {
    html += `<tr><td>${escapeHtml(ev.title)}</td><td title="${escapeHtml(ev.detail || '')}">${escapeHtml(ev.detail || '')}</td></tr>`;
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
    : `${total} events`;

  renderStats(filtered);
  renderFilters();
  renderChronology(filtered.filter(e => !CAPTURE_STATE_CATEGORIES.has(e.category)));
  renderCaptureSnapshot(filtered.filter(e => CAPTURE_STATE_CATEGORIES.has(e.category)));
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

  on('analysis:capture', (data) => {
    capture = data;
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
    capture = null;
    timelineEvents = [];
    timelineBuilt = false;
    activeCategories = new Set(['stealer', 'file', 'cookie', 'history', 'notes', 'screenshots']);
    document.getElementById('navTimeline').disabled = true;
    const search = document.getElementById('timelineSearch');
    if (search) search.value = '';
  });
}

export { initTimeline };
