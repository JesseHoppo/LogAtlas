// Timeline

import { state, on } from './state.js';
import { getCookiesData, getHistoryData, escapeCSV } from './dataPages.js';
import { extractBaseDomain, extractDomain, collectFileNodes, downloadBlob } from './shared.js';
import { escapeHtml } from './utils.js';
import { CAPTURE_TIME_KEYS, IGNORE_DATE_KEYS, FIELD_PATTERNS, LIMITS } from './definitions.js';

let sysinfoEntries = null;
let timelineEvents = [];
let timelineBuilt = false;
let activeCategories = new Set(['stealer', 'file', 'cookie', 'history']);

const CATEGORIES = {
  stealer: { label: 'Stealer', badgeClass: 'timeline-event-badge-stealer' },
  file:    { label: 'Files',   badgeClass: 'timeline-event-badge-file' },
  cookie:  { label: 'Cookies', badgeClass: 'timeline-event-badge-cookie' },
  history: { label: 'History', badgeClass: 'timeline-event-badge-history' },
};

// Best-effort parser for loose date strings from sysinfo.
function parseLooseDate(str) {
  if (!str) return null;
  const trimmed = str.trim();

  // Try native Date parse first (handles ISO, RFC 2822, "Jan 18 2026", etc.)
  const d = new Date(trimmed);
  if (!isNaN(d.getTime()) && d.getFullYear() > 1970) return d;

  // DD/MM/YYYY HH:MM:SS or DD.MM.YYYY HH:MM:SS or DD-MM-YYYY HH:MM:SS
  const dmyTime = trimmed.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dmyTime) {
    let year = +dmyTime[3];
    if (year < 100) year += 2000;
    const test = new Date(year, +dmyTime[2] - 1, +dmyTime[1], +dmyTime[4], +dmyTime[5], +(dmyTime[6] || 0));
    if (!isNaN(test.getTime())) return test;
  }

  // DD/MM/YYYY (date only)
  const dmy = trimmed.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})$/);
  if (dmy) {
    let year = +dmy[3];
    if (year < 100) year += 2000;
    const test = new Date(year, +dmy[2] - 1, +dmy[1]);
    if (!isNaN(test.getTime())) return test;
  }

  // YYYY/MM/DD or YYYY-MM-DD (with optional time)
  const ymd = trimmed.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (ymd) {
    const test = new Date(+ymd[1], +ymd[2] - 1, +ymd[3], +(ymd[4] || 0), +(ymd[5] || 0), +(ymd[6] || 0));
    if (!isNaN(test.getTime())) return test;
  }

  // "07 Jan 26 15:03" - DD Mon YY HH:MM
  const dMonY = trimmed.match(/^(\d{1,2})\s+(\w{3})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dMonY) {
    let yearStr = dMonY[3];
    if (yearStr.length === 2) yearStr = '20' + yearStr;
    const test = new Date(`${dMonY[2]} ${dMonY[1]} ${yearStr} ${dMonY[4]}:${dMonY[5]}:${dMonY[6] || '00'}`);
    if (!isNaN(test.getTime())) return test;
  }

  return null;
}

// Parse lastVisit handles epoch seconds, ms, or ISO strings.
function parseTimestamp(val) {
  if (!val) return null;
  const str = String(val).trim();
  if (!str) return null;

  // ISO string
  if (str.includes('-') || str.includes('T') || str.includes('Z')) {
    const d = new Date(str.replace(' ', 'T'));
    if (!isNaN(d.getTime()) && d.getFullYear() > 1970) return d;
  }

  // Numeric
  const num = Number(str);
  if (!isNaN(num) && num > 0) {
    let ms;
    if (num > 13000000000000000) {
      // Chrome epoch (microseconds since 1601)
      const offset = 11644473600000000;
      ms = (num - offset) / 1000;
    } else if (num > 1e12) {
      ms = num; // already ms
    } else {
      ms = num * 1000; // seconds
    }
    const d = new Date(ms);
    if (!isNaN(d.getTime()) && d.getFullYear() > 1970) return d;
  }

  return null;
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
      const date = parseLooseDate(value);
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

  for (const { row, validity, sessionType, headers } of cookiesData.rows) {
    const domain = (row[0] || '').replace(/^\./, '').toLowerCase();
    const baseDomain = extractBaseDomain(domain) || domain;
    if (!baseDomain) continue;

    if (!domainMap[baseDomain]) {
      domainMap[baseDomain] = { total: 0, valid: 0, expired: 0, sessions: 0, validSessions: 0, earliestExpiry: null, latestExpiry: null };
    }
    const entry = domainMap[baseDomain];
    entry.total++;

    if (validity.status === 'valid') entry.valid++;
    else if (validity.status === 'expired') entry.expired++;
    if (sessionType) {
      entry.sessions++;
      if (validity.status === 'valid') entry.validSessions++;
    }

    // Parse expiration date
    const expiresIdx = headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
    if (expiresIdx >= 0) {
      const expiresDate = parseTimestamp(row[expiresIdx]);
      if (expiresDate) {
        if (!entry.earliestExpiry || expiresDate < entry.earliestExpiry) entry.earliestExpiry = expiresDate;
        if (!entry.latestExpiry || expiresDate > entry.latestExpiry) entry.latestExpiry = expiresDate;
      }
    }
  }

  // Create events for top domains with valid cookies
  const sorted = Object.entries(domainMap)
    .filter(([, stats]) => stats.valid > 0)
    .sort((a, b) => b[1].valid - a[1].valid)
    .slice(0, LIMITS.topTimelineCookieDomains);

  const events = [];
  for (const [domain, stats] of sorted) {
    const time = stats.latestExpiry || new Date();
    let detail = `${stats.valid} valid, ${stats.expired} expired`;
    if (stats.validSessions > 0) {
      detail += ` - ${stats.validSessions} active session token${stats.validSessions !== 1 ? 's' : ''}`;
    }
    if (stats.latestExpiry) {
      detail += ` - latest expiry: ${formatDate(stats.latestExpiry)}`;
    }
    events.push({
      time,
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
    const d = parseTimestamp(entry.lastVisit);
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

  // Sort newest first
  events.sort((a, b) => b.time - a.time);

  timelineEvents = events;
  timelineBuilt = true;
}

function renderStats(events) {
  const el = document.getElementById('timelineStats');
  if (events.length === 0) {
    el.innerHTML = '';
    return;
  }

  const cats = {};
  let earliest = Infinity;
  let latest = -Infinity;

  for (const ev of events) {
    const t = ev.time.getTime();
    if (t < earliest) earliest = t;
    if (t > latest) latest = t;
    cats[ev.category] = (cats[ev.category] || 0) + 1;
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

  // Filter by active categories
  let filtered = timelineEvents.filter(e => activeCategories.has(e.category));

  // Filter by search
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e =>
      e.title.toLowerCase().includes(q) ||
      (e.detail && e.detail.toLowerCase().includes(q)) ||
      e.category.toLowerCase().includes(q)
    );
  }

  const total = timelineEvents.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length} of ${total} events`
    : `${total} events reconstructed from archive data`;

  renderStats(timelineEvents);
  renderFilters();
  renderVisualTimeline(filtered);
  renderTable(filtered);
}

function exportTimelineCSV() {
  if (timelineEvents.length === 0) return;
  let csv = 'Timestamp,Category,Event,Detail\n';
  for (const ev of timelineEvents) {
    csv += [
      ev.time.toISOString(),
      CATEGORIES[ev.category]?.label || ev.category,
      ev.title,
      ev.detail || '',
    ].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'timeline.csv', 'text/csv');
}

function initTimeline() {
  on('analysis:sysinfo', (data) => {
    if (data && data.entries) {
      sysinfoEntries = data.entries;
    }
  });

  on('extracted', () => {
    document.getElementById('navTimeline').disabled = false;
    timelineBuilt = false;
  });

  on('page:timeline', () => {
    const search = document.getElementById('timelineSearch');
    renderTimelinePage(search?.value || '');
  });

  const search = document.getElementById('timelineSearch');
  let debounce = null;
  search?.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      renderTimelinePage(search.value);
    }, 150);
  });

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
    activeCategories = new Set(['stealer', 'file', 'cookie', 'history']);
    document.getElementById('navTimeline').disabled = true;
    const search = document.getElementById('timelineSearch');
    if (search) search.value = '';
  });
}

export { initTimeline };
