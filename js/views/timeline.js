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
  notes:   { label: 'Notes',   badgeClass: 'timeline-event-badge-notes' },
  screenshots: { label: 'Screenshots', badgeClass: 'timeline-event-badge-screenshots' },
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
      // The snapshot table gives each of these its own column; `detail` stays
      // the one-line form the CSV export and the search box read.
      cookieStats: stats,
    });
  }

  return events;
}

function extractHistoryEvents(historyData) {
  if (!historyData || historyData.entries.length === 0) return [];

  // Every other band on this axis is an absolute instant. A visit time only
  // joins them once its frame is resolved; until then it is a wall clock in an
  // unknown zone, and the day it lands on is said to be the log's, not UTC.
  const framed = historyData.clock?.offsetMinutes != null;

  const dated = [];
  for (const entry of historyData.entries) {
    const d = entry.lastVisitDate;
    if (isPlausibleCaptureDate(d)) {
      dated.push({ ...entry, _date: d });
    }
  }

  if (dated.length === 0) return [];

  // History files come out of the browser ordered by url id, not by time, so a
  // day's rows arrive shuffled. The bucket keeps the day's real span rather
  // than whichever visit happened to be parsed first.
  const dayMap = {};
  for (const entry of dated) {
    const key = dateKey(entry._date);
    if (!dayMap[key]) {
      dayMap[key] = { first: entry._date, last: entry._date, domains: {}, count: 0 };
    }
    const day = dayMap[key];
    day.count++;
    if (entry._date < day.first) day.first = entry._date;
    if (entry._date > day.last) day.last = entry._date;
    const domain = baseDomainFromUrl(entry.url) || 'unknown';
    day.domains[domain] = (day.domains[domain] || 0) + 1;
  }

  const events = [];
  for (const [, day] of Object.entries(dayMap)) {
    const topDomains = Object.entries(day.domains)
      .sort((a, b) => b[1] - a[1])
      .slice(0, LIMITS.topHistoryDomainsPerDay)
      .map(([d]) => d);

    events.push({
      time: day.first,
      endTime: day.last,
      dayLevel: true,
      category: 'history',
      title: `${countLabel(day.count, 'site')} visited`,
      detail: framed ? topDomains.join(', ') : `${topDomains.join(', ')} - log clock, zone unresolved`,
    });
  }

  return events;
}

function extractModifiedEvents(data, category, bucket, pickTitle, pickDetail) {
  if (!data || !data.entries || !data.entries.length) return [];
  return data.entries
    .filter(e => isPlausibleCaptureDate(e.modifiedDate))
    .sort((a, b) => b.modifiedDate - a.modifiedDate)
    .map(e => ({ time: e.modifiedDate, category, bucket, title: pickTitle(e), detail: pickDetail(e) }));
}

function extractNoteEvents(notesData) {
  return extractModifiedEvents(notesData, 'notes', 'notes', e => e.title, e => e.indicators);
}

function extractGrabbedFileEvents(grabbedData) {
  return extractModifiedEvents(grabbedData, 'file', 'grabbed', e => e.name, e => e.relativePath);
}

function extractScreenshotEvents(screenshotsData) {
  return extractModifiedEvents(screenshotsData, 'screenshots', 'screenshots', e => e.name,
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
    const end = ev.endTime ? ev.endTime.getTime() : t;
    if (end > latest && end <= now) latest = end;
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
      ? `Log captured (${captureEvent.source})`
      : 'Log captured';
    html += `<div class="data-page-stat"><div class="data-page-stat-value timeline-capture-value">${formatInstantLabel(captureEvent.time)}</div><div class="data-page-stat-label">${escapeHtml(label)}</div></div>`;
  }

  const cookies = getCookiesData();
  if (cookies.rows.length > 0) {
    const liveSessions = cookies.rows.filter(isLiveSessionToken).length;
    if (liveSessions > 0) {
      html += `<div class="data-page-stat" title="Unexpired at capture, or session cookies with no expiry. Counted over the whole case, not the filtered view."><div class="data-page-stat-value cookie-auth-valid">${liveSessions.toLocaleString()}</div><div class="data-page-stat-label">Live sessions at capture (whole case)</div></div>`;
    }
  }

  html += `<div class="data-page-stat"><div class="data-page-stat-value">${events.length.toLocaleString()}</div><div class="data-page-stat-label">Events</div></div>`;

  if (span) {
    html += `<div class="data-page-stat"><div class="data-page-stat-value timeline-range-value">${span}</div><div class="data-page-stat-label">Date range</div></div>`;
  }

  el.innerHTML = html;
}

function renderFilters() {
  const el = document.getElementById('timelineFilters');
  let html = '<div class="timeline-filters">';
  for (const [cat, info] of Object.entries(CATEGORIES)) {
    const count = timelineEvents.filter(e => e.category === cat).length;
    if (count === 0) continue;
    const isActive = activeCategories.has(cat);
    html += `<button class="timeline-filter-btn${isActive ? ' active' : ''}" data-cat="${cat}" aria-pressed="${isActive}">${info.label} (${count.toLocaleString()})</button>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

// Toggling a category re-renders the whole strip, which throws away the button
// that was clicked; without this, focus lands back on the body every time.
function focusFilterButton(cat) {
  if (!cat) return;
  document.querySelector(`#timelineFilters .timeline-filter-btn[data-cat="${cat}"]`)?.focus();
}

// Cookie events all carry the capture timestamp: they describe the state of
// the log at collection time, not a sequence of events. Keep them out of the
// chronology and show them as a snapshot table instead.
const CAPTURE_STATE_CATEGORIES = new Set(['cookie']);

const EMPTY_CELL = '<span class="cell-empty">\u2014</span>';

// Clicking a header sorts by that column; cycling back returns the table to
// the ranking the snapshot is built on. Latest expiry sorts on the instant, so
// two dates written a day apart never collate as text.
const SNAPSHOT_CAPTION = 'Ordered by cookies still valid at capture.';

const snapshotSort = createTableSort({
  domain: (ev) => ev.title,
  valid: (ev) => ev.cookieStats?.valid,
  expired: (ev) => ev.cookieStats?.expired,
  live: (ev) => ev.cookieStats?.liveSessions,
  expiry: (ev) => ev.cookieStats?.latestExpiry,
});

// A case that grabs hundreds of documents would bury every other event, so
// these buckets render their most recent entries and declare the rest. The
// filter counts, the search and the CSV export all still see every event.
const CHRONOLOGY_CAPS = { notes: 12, grabbed: 12, screenshots: 8 };
const BUCKET_NOUNS = { notes: 'note', grabbed: 'grabbed file', screenshots: 'screenshot' };

// A day aggregate has no single observation instant. Printing the earliest
// visit to the minute would read as the time the browsing happened, so these
// events carry the span they actually cover.
function eventTimeLabel(ev) {
  if (!ev.dayLevel || !ev.endTime || ev.endTime.getTime() === ev.time.getTime()) {
    return formatDateTimeLabel(ev.time);
  }
  const hhmm = (date) => `${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}`;
  return `${hhmm(ev.time)} - ${hhmm(ev.endTime)} UTC`;
}

function renderChronology(events) {
  const el = document.getElementById('timelineVisual');
  if (events.length === 0) {
    el.innerHTML = '<div class="timeline-note">No events with distinct timestamps. See the capture snapshot below.</div>';
    return;
  }

  let html = '<h3 class="dash-section-title">Activity chronology</h3><div class="timeline-track">';
  let currentGroup = '';
  const remaining = { ...CHRONOLOGY_CAPS };
  const hidden = {};

  for (const ev of events) {
    if (ev.bucket && remaining[ev.bucket] !== undefined) {
      if (remaining[ev.bucket] === 0) {
        hidden[ev.bucket] = (hidden[ev.bucket] || 0) + 1;
        continue;
      }
      remaining[ev.bucket]--;
    }

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
    html += `<span class="timeline-event-time">${eventTimeLabel(ev)}</span>`;
    html += `</div>`;
    if (ev.detail) {
      html += `<div class="timeline-event-detail">${escapeHtml(ev.detail)}</div>`;
    }
    html += `</div>`;
  }

  html += '</div>';

  const withheld = Object.entries(hidden).map(([bucket, count]) => countLabel(count, BUCKET_NOUNS[bucket]));
  if (withheld.length) {
    html += `<div class="timeline-note">Showing the most recent only - ${withheld.join(', ')} not listed. Search and the CSV export cover every event.</div>`;
  }

  el.innerHTML = html;
}

function renderCaptureSnapshot(events) {
  const el = document.getElementById('timelineContent');
  if (events.length === 0) {
    el.innerHTML = '';
    return;
  }

  const rows = snapshotSort.apply(events);
  const captureLabel = formatInstantLabel(capture?.date);
  let html = `<h3 class="dash-section-title">Capture snapshot</h3>`;
  html += `<div class="dash-section-subtitle">Log state at capture${captureLabel ? ` (${escapeHtml(captureLabel)})` : ''}. Not a chronology.</div>`;
  if (snapshotSort.order === 'none') html += `<div class="data-table-caption">${SNAPSHOT_CAPTION}</div>`;
  html += '<div class="data-table-container"><table class="data-table">';
  html += `<thead><tr>${snapshotSort.th('domain', 'Domain')}${snapshotSort.th('valid', 'Valid')}${
    snapshotSort.th('expired', 'Expired')}${snapshotSort.th('live', 'Live Sessions')}${
    snapshotSort.th('expiry', 'Latest Expiry')}</tr></thead><tbody>`;
  for (const ev of rows) {
    const stats = ev.cookieStats || {};
    const expiry = formatDateLabel(stats.latestExpiry);
    html += `<tr><td title="${escapeHtml(ev.title)}">${escapeHtml(ev.title)}</td>`;
    html += `<td>${(stats.valid || 0).toLocaleString()}</td>`;
    html += `<td>${(stats.expired || 0).toLocaleString()}</td>`;
    html += `<td>${(stats.liveSessions || 0).toLocaleString()}</td>`;
    html += `<td>${expiry ? escapeHtml(expiry) : EMPTY_CELL}</td></tr>`;
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
  downloadCsvRows('timeline.csv', ['Timestamp', 'End', 'Category', 'Event', 'Detail'], filteredEvents.map((event) => [
    event.time.toISOString(),
    event.endTime ? event.endTime.toISOString() : '',
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
    focusFilterButton(cat);
  });

  bindTableSort('timelineContent', snapshotSort, () => renderTimelinePage(search?.value || ''));

  document.getElementById('exportTimelineCsv')?.addEventListener('click', exportTimelineCSV);

  on('reset', () => {
    sysinfoEntries = null;
    capture = null;
    timelineEvents = [];
    timelineBuilt = false;
    snapshotSort.reset();
    activeCategories = new Set(['stealer', 'file', 'cookie', 'history', 'notes', 'screenshots']);
    document.getElementById('navTimeline').disabled = true;
    const search = document.getElementById('timelineSearch');
    if (search) search.value = '';
  });
}

export { initTimeline };
