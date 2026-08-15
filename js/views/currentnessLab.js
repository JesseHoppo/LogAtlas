import { state, on } from '../core/state.js';
import { escapeHtml, escapeAttr } from '../core/utils.js';
import { bindDebouncedInput, buildShowMoreButton, buildRowsHtml, downloadCsvRows, formatDateTimeLabel, getFieldByPattern, PAGE_SIZE } from '../pages/shared.js';
import { getPasswordsData, getCookiesData, getAutofillsData, getNotesData } from '../pages/credentials.js';
import { getHistoryData, getBookmarksData } from '../pages/browser.js';
import { getDownloadsData, getClipboardData } from '../pages/activity.js';
import { getAccountTokensData } from '../pages/assets.js';
import { buildCredentialCurrentnessModel } from '../analysis/credentialCurrentness.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import { getCategoryLabel } from '../core/domainCategories.js';

let currentnessModel = null;
let currentnessFiltered = [];
let currentnessShown = 0;
let sysinfoEntries = null;
let currentnessActiveFilter = 'all';

const CURRENTNESS_FILTERS = [
  { key: 'all', label: 'All Credentials', predicate: () => true },
  { key: 'priority', label: 'Priority Queue', predicate: (row) => row.isPriority },
  { key: 'uncategorised', label: 'Uncategorised', predicate: (row) => row.categoryKey === 'unknown' },
  { key: 'active', label: 'Likely Current', predicate: (row) => row.bucket === 'likely-current' },
  { key: 'aligned', label: 'Corroborated Employer', predicate: (row) => row.identityFitKey === 'aligned-corroborated' || row.identityFitKey === 'corroborated' },
  { key: 'legacy', label: 'Legacy Employer', predicate: (row) => row.dispositionKey === 'legacy-employer' },
  { key: 'orphaned', label: 'Orphaned Corporate', predicate: (row) => row.identityFitKey === 'orphaned' },
  { key: 'corp-on-consumer', label: 'Corp Email on Consumer Site', predicate: (row) => row.dispositionKey === 'corp-on-consumer' },
  { key: 'app', label: 'App-stored', predicate: (row) => row.isAppCredential },
  { key: 'personal', label: 'Personal Email', predicate: (row) => row.identityFitKey === 'public' },
];

// Order categories by analyst usefulness: "unknown" first (priority bucket),
// then specific consumer categories, popular last (broadest/least informative).
const CATEGORY_BREAKDOWN_ORDER = [
  'unknown', 'bank', 'socialMedia', 'searchEngine', 'aiAssistant',
  'airline', 'news', 'university', 'retailer', 'popular',
];

function getCredentialIndex(headers, matcher) {
  return headers.findIndex((header) => matcher.test(header));
}

function normaliseCredentials() {
  const data = getPasswordsData();
  if (!data?.rows?.length) return [];

  const urlIdx = getCredentialIndex(data.headers, FIELD_PATTERNS.url);
  const userIdx = getCredentialIndex(data.headers, FIELD_PATTERNS.username);
  const passIdx = getCredentialIndex(data.headers, FIELD_PATTERNS.password);

  return data.rows.map((entry) => ({
    url: urlIdx >= 0 ? (entry.row[urlIdx] || '').trim() : '',
    username: userIdx >= 0 ? (entry.row[userIdx] || '').trim() : '',
    password: passIdx >= 0 ? (entry.row[passIdx] || '').trim() : '',
    source: entry.source || '',
  }));
}

function normaliseCookies() {
  const data = getCookiesData();
  if (!data?.rows?.length) return [];

  return data.rows.map((entry) => ({
    host: getFieldByPattern(entry, FIELD_PATTERNS.cookieDomain).replace(/^\./, '').trim().toLowerCase(),
    name: getFieldByPattern(entry, FIELD_PATTERNS.cookieName).trim(),
    validityStatus: entry.validity?.status || '',
    validityLabel: entry.validity?.label || '',
    sessionType: entry.sessionType || '',
  })).filter((entry) => entry.host);
}

function normaliseHistory() {
  return (getHistoryData()?.entries || []).map((entry) => ({
    url: entry.url || '',
    title: entry.title || '',
    visitCount: entry.visitCount || 1,
    lastVisit: entry.lastVisit || '',
    lastVisitDate: entry.lastVisitDate || null,
  }));
}

function normaliseBookmarks() {
  return (getBookmarksData()?.entries || []).map((entry) => ({
    url: entry.url || '',
    title: entry.title || '',
    folder: entry.folder || '',
    domain: entry.domain || '',
  }));
}

function normaliseDownloads() {
  return (getDownloadsData()?.entries || []).map((entry) => ({
    filePath: entry.filePath || '',
    sourceUrl: entry.sourceUrl || '',
    domain: entry.domain || '',
  }));
}

function normaliseCurrentnessInput() {
  return {
    credentials: normaliseCredentials(),
    cookies: normaliseCookies(),
    history: normaliseHistory(),
    autofillEntries: getAutofillsData()?.entries || [],
    notes: getNotesData()?.entries || [],
    downloads: normaliseDownloads(),
    bookmarks: normaliseBookmarks(),
    accountTokens: getAccountTokensData()?.entries || [],
    clipboardEntries: getClipboardData()?.entries || [],
    sysinfoEntries,
    rootZipName: state.rootZipName || '',
    sourceLastModified: state.sourceFile?.lastModified || null,
  };
}

function isCurrentnessPageActive() {
  return document.querySelector('.sidebar-nav-item.active')?.dataset.page === 'currentnesslab';
}

function getCurrentnessFilterDefinition(key) {
  return CURRENTNESS_FILTERS.find((entry) => entry.key === key) || CURRENTNESS_FILTERS[0];
}

function applyCurrentnessFilters(rows, searchQuery = '') {
  const filterDef = getCurrentnessFilterDefinition(currentnessActiveFilter);
  const baseRows = (rows || []).filter((row) => filterDef.predicate(row));
  const q = searchQuery.trim().toLowerCase();
  if (!q) return baseRows;
  return baseRows.filter((row) => buildSearchText(row).includes(q));
}

function buildSearchText(row) {
  return [
    row.url,
    row.username,
    row.siteHost,
    row.siteDomain,
    row.usernameDomain,
    row.bucketLabel,
    row.conflictDomain,
    row.dispositionLabel,
    row.dispositionNote,
    row.identityFitLabel,
    row.identityFitNote,
    row.evidenceSummary,
  ].join(' ').toLowerCase();
}

function buildHeroLine(summary) {
  const id = summary.primaryIdentity || { kind: 'unknown', label: '', domain: '' };

  // Headline: primary identity. Adapts to corp / personal / unknown so even a
  // personal-only victim shows a useful "who" line.
  let headlineHtml;
  if (id.kind === 'corporate') {
    headlineHtml = `<strong>${escapeHtml(id.label)}</strong> <span class="lab-hero-tag lab-hero-tag-success">corroborated employer · ${escapeHtml(id.domain)}</span>`;
  } else if (id.kind === 'personal') {
    headlineHtml = `<strong>${escapeHtml(id.label)}</strong> <span class="lab-hero-tag lab-hero-tag-muted">personal-only victim</span>`;
  } else if (id.kind === 'autofill') {
    headlineHtml = `<strong>${escapeHtml(id.label)}</strong> <span class="lab-hero-tag lab-hero-tag-muted">tentative identity</span>`;
  } else {
    headlineHtml = `<strong>${escapeHtml(id.osUsername || 'Unknown victim')}</strong> <span class="lab-hero-tag lab-hero-tag-muted">no usable identity signal</span>`;
  }

  const idMeta = [
    id.osUsername ? `OS user <code>${escapeHtml(id.osUsername)}</code>` : '',
    id.computerName ? `host <code>${escapeHtml(id.computerName)}</code>` : '',
    id.country ? `country ${escapeHtml(id.country)}` : '',
  ].filter(Boolean).join(' · ');

  // Live evidence: the most actionable summary on the page.
  const liveBits = [
    summary.liveCount > 0
      ? `<span class="lab-hero-live"><strong>${summary.liveCount}</strong> live-access evidence</span>`
      : '',
    summary.recentCount > 0 ? `<span><strong>${summary.recentCount}</strong> recent</span>` : '',
    summary.appCount > 0 ? `<span><strong>${summary.appCount}</strong> app-stored</span>` : '',
    summary.reuseGroups > 0 ? `<span><strong>${summary.reuseGroups}</strong> reused passwords</span>` : '',
  ].filter(Boolean);

  const captureBit = summary.captureDate
    ? `Captured ${escapeHtml(formatDateTimeLabel(summary.captureDate))} <span class="lab-hero-tag-muted">(${escapeHtml(summary.captureSource || '')})</span>`
    : `<span class="lab-hero-warn">No capture anchor; recency disabled</span>`;

  return `
    <div class="lab-hero">
      <div class="lab-hero-headline">${headlineHtml}</div>
      ${idMeta ? `<div class="lab-hero-meta">${idMeta}</div>` : ''}
      <div class="lab-hero-facts">
        <span><strong>${summary.totalCredentials.toLocaleString()}</strong> credentials</span>
        ${liveBits.join('')}
        <span class="lab-hero-capture">${captureBit}</span>
      </div>
    </div>
  `;
}

function buildFilterChips(rows) {
  return CURRENTNESS_FILTERS
    .map((entry) => {
      const count = (rows || []).filter((row) => entry.predicate(row)).length;
      // Hide noise: zero-count filters never fire and just clutter the bar.
      // 'all' is always shown so the analyst can reset.
      if (count === 0 && entry.key !== 'all') return '';
      const active = entry.key === currentnessActiveFilter ? ' active' : '';
      return `<button class="lab-chip${active}" data-filter="${escapeHtml(entry.key)}">${escapeHtml(entry.label)} <em>${count.toLocaleString()}</em></button>`;
    })
    .filter(Boolean)
    .join('');
}

function buildCategoryBreakdown(rows) {
  if (!rows?.length) return '';
  const counts = new Map();
  for (const row of rows) {
    const key = row.categoryKey || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  if (counts.size <= 1 && counts.has('unknown')) return ''; // categories haven't loaded yet

  const segments = CATEGORY_BREAKDOWN_ORDER
    .map((key) => {
      const count = counts.get(key) || 0;
      if (!count) return '';
      const label = key === 'unknown' ? 'Uncategorised' : getCategoryLabel(key);
      const tone = key === 'unknown' ? ' lab-cat-unknown' : '';
      return `<span class="lab-cat-pill${tone}"><strong>${count.toLocaleString()}</strong> ${escapeHtml(label)}</span>`;
    })
    .filter(Boolean)
    .join('');

  return `<div class="lab-cat-breakdown" title="Domain categories from data/site-domains/">${segments}</div>`;
}

function buildCandidatesPanel(summary) {
  if (!summary.identityDomains?.length) return '';

  const corroborated = summary.identityDomains.filter((entry) => entry.statusTone === 'success' || entry.statusTone === 'accent');
  const legacy = summary.identityDomains.filter((entry) => !corroborated.includes(entry));

  const summaryParts = [`${summary.identityDomains.length} candidate${summary.identityDomains.length === 1 ? '' : 's'}`];
  if (corroborated.length) summaryParts.push(`${corroborated.length} corroborated`);
  if (legacy.length) summaryParts.push(`${legacy.length} likely legacy`);

  const items = [...corroborated, ...legacy].map((entry) => {
    const tone = escapeAttr(entry.statusTone || 'neutral');
    const counts = [
      entry.likelyCurrent ? `${entry.likelyCurrent} likely` : '',
      entry.review ? `${entry.review} review` : '',
      entry.weak ? `${entry.weak} weak` : '',
    ].filter(Boolean).join(' · ') || `${entry.credentialCount} cred`;
    const sourceTags = [...entry.sources]
      .filter((src) => src !== 'credentials')
      .map((src) => `<span class="lab-tag">${escapeHtml(src)}</span>`)
      .join('');
    return `
      <li class="lab-candidate">
        <span class="lab-candidate-domain">${escapeHtml(entry.domain)}</span>
        <span class="lab-candidate-status lab-tone-${tone}">${escapeHtml(entry.statusLabel)}</span>
        <span class="lab-candidate-counts">${escapeHtml(counts)}</span>
        <span class="lab-candidate-sources">${sourceTags}</span>
      </li>
    `;
  }).join('');

  return `
    <details class="lab-candidates">
      <summary>${escapeHtml(summaryParts.join(' · '))}</summary>
      <ul class="lab-candidate-list">${items}</ul>
    </details>
  `;
}

function renderCurrentnessMeta(summary, rows) {
  const metaEl = document.getElementById('currentnessLabMeta');
  if (!metaEl) return;

  if (!summary || summary.totalCredentials === 0) {
    metaEl.innerHTML = '';
    return;
  }

  metaEl.innerHTML = `
    ${buildHeroLine(summary)}
    ${buildCategoryBreakdown(rows)}
    <div class="lab-filters">${buildFilterChips(rows)}</div>
    ${buildCandidatesPanel(summary)}
  `;
}

function renderMiniSignalBar(row) {
  const segments = [
    { key: 'identity', value: Math.max(row.identityScore, 0) },
    { key: 'site', value: Math.max(row.siteScore, 0) },
    { key: 'tenant', value: Math.max(row.tenantScore, 0) },
    { key: 'platform', value: Math.max(row.platformScore, 0) },
  ].filter((seg) => seg.value > 0);
  if (segments.length === 0) return '<div class="lab-bar lab-bar-empty"></div>';
  const tooltip = `Identity ${row.identityScore} · Service ${row.siteScore} · Tenant ${row.tenantScore} · Platform ${row.platformScore}` +
    (row.competitionPenalty ? ` · Penalty ${row.competitionPenalty}` : '');
  const html = segments.map((seg) =>
    `<span class="lab-bar-seg lab-bar-${seg.key}" style="flex:${seg.value}"></span>`
  ).join('');
  return `<div class="lab-bar" title="${escapeHtml(tooltip)}">${html}</div>`;
}

function renderCredDetail(row) {
  const evidenceHtml = row.evidence.length
    ? row.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
    : '<li class="lab-detail-empty">No evidence captured.</li>';

  const actionLabel = {
    live: 'Live-access evidence (valid session or app-stored)',
    recent: 'Used recently (history within 30 days)',
    stored: 'Stored in browser, no live evidence',
    legacy: 'Legacy / conflicting',
  }[row.actionability] || row.actionability;

  const identityTags = [
    row.usernameDomain ? `<span class="lab-tag">${escapeHtml(row.usernameDomain)}</span>` : '',
    row.identityFitLabel
      ? `<span class="lab-tag lab-tone-${escapeAttr(row.identityFitTone || 'neutral')}">${escapeHtml(row.identityFitLabel)}</span>`
      : '',
    row.conflictDomain ? `<span class="lab-tag lab-tone-danger">vs ${escapeHtml(row.conflictDomain)}</span>` : '',
    row.isAppCredential ? '<span class="lab-tag">app-stored</span>' : '',
    row.isConsumerSite ? '<span class="lab-tag">consumer site</span>' : '',
    row.reuseCount > 1
      ? `<span class="lab-tag lab-tone-warning">password reused × ${row.reuseCount}</span>`
      : '',
  ].filter(Boolean).join('');

  const breakdown = [
    row.identityScore !== 0 ? `<span class="lab-tag lab-bar-identity">Identity ${row.identityScore}</span>` : '',
    row.siteScore !== 0 ? `<span class="lab-tag lab-bar-site">Service ${row.siteScore}</span>` : '',
    row.tenantScore !== 0 ? `<span class="lab-tag lab-bar-tenant">Tenant ${row.tenantScore}</span>` : '',
    row.platformScore !== 0 ? `<span class="lab-tag lab-bar-platform">Platform ${row.platformScore}</span>` : '',
    row.competitionPenalty ? `<span class="lab-tag lab-tone-danger">−${row.competitionPenalty}</span>` : '',
  ].filter(Boolean).join('');

  const reuseList = row.reuseSites?.length
    ? `<p class="lab-detail-note">Same password seen on: ${row.reuseSites.map((s) => `<code>${escapeHtml(s)}</code>`).join(', ')}</p>`
    : '';

  return `
    <div class="lab-detail">
      <div class="lab-detail-row">
        <span class="lab-detail-label">URL</span>
        <code class="lab-detail-url">${escapeHtml(row.url || '—')}</code>
      </div>
      <div class="lab-detail-row">
        <span class="lab-detail-label">Status</span>
        <div class="lab-detail-body">
          <p class="lab-detail-note"><strong>${escapeHtml(actionLabel)}.</strong> ${escapeHtml(row.dispositionLabel || '')}</p>
          ${row.dispositionNote ? `<p class="lab-detail-note">${escapeHtml(row.dispositionNote)}</p>` : ''}
        </div>
      </div>
      <div class="lab-detail-row">
        <span class="lab-detail-label">Identity</span>
        <div class="lab-detail-body">
          <div class="lab-tag-row">${identityTags}</div>
          ${row.identityFitNote ? `<p class="lab-detail-note">${escapeHtml(row.identityFitNote)}</p>` : ''}
          ${reuseList}
        </div>
      </div>
      <div class="lab-detail-row">
        <span class="lab-detail-label">Signals</span>
        <div class="lab-detail-body">
          <div class="lab-tag-row">${breakdown}</div>
        </div>
      </div>
      <div class="lab-detail-row">
        <span class="lab-detail-label">Evidence</span>
        <ul class="lab-detail-evidence">${evidenceHtml}</ul>
      </div>
    </div>
  `;
}

function currentnessRowBuilder(row) {
  const action = row.actionability || 'stored';
  const dispositionTone = escapeAttr(row.dispositionTone || 'neutral');
  const priorityClass = row.isPriority ? ' lab-cred-priority' : '';

  const reuseMarker = row.reuseCount > 1
    ? ` <span class="lab-reuse-tag" title="${escapeAttr('Password reused across ' + row.reuseCount + ' sites')}">reused × ${row.reuseCount}</span>`
    : '';

  const actionDotTitle = `Actionability: ${action}`;
  const display = row.displayLabel || row.dispositionLabel || row.bucketLabel || '';

  const catKey = row.categoryKey || 'unknown';
  const catBadge = catKey === 'unknown'
    ? '<span class="lab-cat-tag lab-cat-unknown" title="Not in any reference list">Uncategorised</span>'
    : `<span class="lab-cat-tag" title="Matched data/site-domains/${escapeAttr(catKey)}.txt">${escapeHtml(getCategoryLabel(catKey))}</span>`;

  return `<tr class="lab-cred${priorityClass}" tabindex="0" aria-expanded="false">
    <td class="lab-cred-site" title="${escapeHtml(row.url)}"><span class="lab-cred-site-host">${escapeHtml(row.siteHost || row.siteDomain || '—')}</span> ${catBadge}</td>
    <td class="lab-cred-user" title="${escapeHtml(row.username)}">${escapeHtml(row.username || '—')}${reuseMarker}</td>
    <td class="lab-cred-action" title="${escapeAttr(actionDotTitle)}"><span class="lab-cred-score-num lab-score-${escapeAttr(action)}">${row.score}</span></td>
    <td class="lab-cred-disp lab-tone-${dispositionTone}">${escapeHtml(display)}</td>
    <td class="lab-cred-bar">${renderMiniSignalBar(row)}</td>
  </tr>
  <tr class="lab-cred-detail-row" aria-hidden="true"><td colspan="5">${renderCredDetail(row)}</td></tr>`;
}

function renderCurrentnessPage(searchQuery = '') {
  const summaryEl = document.getElementById('currentnessLabSummary');
  const statsEl = document.getElementById('currentnessLabStats');
  const contentEl = document.getElementById('currentnessLabContent');

  // Stats row is redundant with the filter chip counts in the meta section.
  if (statsEl) statsEl.innerHTML = '';

  if (!currentnessModel || currentnessModel.rows.length === 0) {
    summaryEl.textContent = 'No credential currentness data available';
    renderCurrentnessMeta(null);
    contentEl.innerHTML = '<div class="no-data">No credential currentness data available.</div>';
    return;
  }

  const summary = currentnessModel.summary;
  const activeFilter = getCurrentnessFilterDefinition(currentnessActiveFilter);
  currentnessFiltered = applyCurrentnessFilters(currentnessModel.rows, searchQuery);
  currentnessShown = Math.min(PAGE_SIZE, currentnessFiltered.length);
  const filterText = activeFilter.key !== 'all' ? ` · ${activeFilter.label}` : '';
  summaryEl.textContent = currentnessFiltered.length !== currentnessModel.rows.length
    ? `${currentnessFiltered.length.toLocaleString()} of ${currentnessModel.rows.length.toLocaleString()} credentials${filterText}`
    : `${currentnessModel.rows.length.toLocaleString()} credentials${filterText}`;

  renderCurrentnessMeta(summary, currentnessModel.rows);

  if (currentnessFiltered.length === 0) {
    contentEl.innerHTML = '<div class="no-data">No credential rows match the current search and analyst filters.</div>';
    return;
  }

  let html = '<div class="data-table-container"><table class="lab-creds-table">';
  html += '<thead><tr><th class="lab-col-site">Site</th><th class="lab-col-user">User</th><th class="lab-col-score">Status</th><th class="lab-col-disp">Triage</th><th class="lab-col-bar">Signals</th></tr></thead><tbody>';
  html += buildRowsHtml(currentnessRowBuilder, currentnessFiltered, 0, currentnessShown);
  html += '</tbody></table></div>';

  const remaining = currentnessFiltered.length - currentnessShown;
  if (remaining > 0) html += buildShowMoreButton(remaining, 'currentnesslab');
  contentEl.innerHTML = html;
}

function rebuildCurrentnessModel() {
  const input = normaliseCurrentnessInput();
  if (!input.credentials.length) {
    currentnessModel = null;
    document.getElementById('navCurrentnessLab').disabled = true;
    if (isCurrentnessPageActive()) renderCurrentnessPage(document.getElementById('currentnessLabSearch')?.value || '');
    return;
  }

  currentnessModel = buildCredentialCurrentnessModel(input);
  document.getElementById('navCurrentnessLab').disabled = currentnessModel.rows.length === 0;

  if (isCurrentnessPageActive()) {
    renderCurrentnessPage(document.getElementById('currentnessLabSearch')?.value || '');
  }
}

function exportCurrentnessCsv() {
  if (!currentnessModel || currentnessModel.rows.length === 0) return;
  const searchValue = document.getElementById('currentnessLabSearch')?.value || '';
  const rows = applyCurrentnessFilters(currentnessModel.rows, searchValue);
  downloadCsvRows(
    'credential_currentness_lab.csv',
    ['URL', 'Username', 'Score', 'Band', 'Disposition', 'Identity Fit', 'Site Domain', 'Site Host', 'Domain Category', 'Identity Domain', 'Conflict Domain', 'Identity Score', 'Site Score', 'Tenant Score', 'Platform Score', 'Penalty', 'Priority', 'App Credential', 'Consumer Site', 'Evidence'],
    rows.map((row) => [
      row.url,
      row.username,
      row.score,
      row.bucketLabel,
      row.dispositionLabel,
      row.identityFitLabel,
      row.siteDomain,
      row.siteHost,
      row.categoryLabel || 'Uncategorised',
      row.usernameDomain,
      row.conflictDomain,
      row.identityScore,
      row.siteScore,
      row.tenantScore,
      row.platformScore,
      row.competitionPenalty,
      row.isPriority ? 'Yes' : 'No',
      row.isAppCredential ? 'Yes' : 'No',
      row.isConsumerSite ? 'Yes' : 'No',
      row.evidence.join('; '),
    ])
  );
}

function initCurrentnessLab() {
  const searchInput = document.getElementById('currentnessLabSearch');
  const contentEl = document.getElementById('currentnessLabContent');
  const metaEl = document.getElementById('currentnessLabMeta');

  let dataReady = false;
  let sysinfoReady = false;
  let modelReady = false;

  function resetInputs() {
    sysinfoEntries = null;
    dataReady = false;
    sysinfoReady = false;
    modelReady = false;
  }

  // Datasets and sysinfo land in either order; scoring the whole credential set
  // is expensive, so wait for both and build once per case.
  function buildWhenReady() {
    if (modelReady || !dataReady || !sysinfoReady) return;
    modelReady = true;
    rebuildCurrentnessModel();
  }

  bindDebouncedInput(searchInput, (value) => renderCurrentnessPage(value));

  metaEl?.addEventListener('click', (event) => {
    const btn = event.target.closest('.lab-chip');
    if (!btn) return;
    currentnessActiveFilter = btn.dataset.filter || 'all';
    renderCurrentnessPage(searchInput?.value || '');
  });

  function toggleCredRow(tr) {
    if (!tr) return;
    const expanded = tr.classList.toggle('lab-cred-expanded');
    tr.setAttribute('aria-expanded', String(expanded));
    const detail = tr.nextElementSibling;
    if (detail?.classList.contains('lab-cred-detail-row')) {
      detail.setAttribute('aria-hidden', String(!expanded));
    }
  }

  contentEl?.addEventListener('click', (event) => {
    const showMore = event.target.closest('.data-show-more');
    if (showMore && showMore.dataset.page === 'currentnesslab') {
      const nextEnd = Math.min(currentnessShown + PAGE_SIZE, currentnessFiltered.length);
      const tbody = contentEl.querySelector('tbody');
      if (!tbody) return;
      tbody.insertAdjacentHTML('beforeend', buildRowsHtml(currentnessRowBuilder, currentnessFiltered, currentnessShown, nextEnd));
      currentnessShown = nextEnd;
      const remaining = currentnessFiltered.length - currentnessShown;
      if (remaining > 0) {
        showMore.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
      } else {
        showMore.remove();
      }
      return;
    }

    const tr = event.target.closest('tr.lab-cred');
    if (tr) toggleCredRow(tr);
  });

  contentEl?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const tr = event.target.closest('tr.lab-cred');
    if (!tr) return;
    event.preventDefault();
    toggleCredRow(tr);
  });

  document.getElementById('exportCurrentnessLabCsv')?.addEventListener('click', exportCurrentnessCsv);

  on('analysis:sysinfo', (data) => {
    sysinfoEntries = data?.entries || null;
    sysinfoReady = true;
    // Only reachable when the backstop below built without sysinfo.
    if (modelReady) rebuildCurrentnessModel();
    else buildWhenReady();
  });

  on('data:loaded', () => {
    dataReady = true;
    buildWhenReady();
  });

  // A sysinfo task that throws never emits, which would otherwise leave the
  // page stranded for the whole case.
  on('analysis:complete', () => {
    sysinfoReady = true;
    buildWhenReady();
  });

  // Domain category lists arrive asynchronously after first paint. If they land
  // after the model, rebuild so credential rows pick up category labels;
  // earlier and the pending build already sees them.
  on('domains:categoriesLoaded', () => {
    if (modelReady) rebuildCurrentnessModel();
  });

  on('page:currentnesslab', () => {
    renderCurrentnessPage(searchInput?.value || '');
  });

  on('reanalyze', resetInputs);

  on('reset', () => {
    resetInputs();
    currentnessModel = null;
    currentnessFiltered = [];
    currentnessShown = 0;
    currentnessActiveFilter = 'all';
    document.getElementById('navCurrentnessLab').disabled = true;
    const metaEl = document.getElementById('currentnessLabMeta');
    if (metaEl) metaEl.innerHTML = '';
    if (searchInput) searchInput.value = '';
  });
}

export { initCurrentnessLab };
