import { state, on } from '../core/state.js';
import { escapeHtml } from '../core/utils.js';
import { bindDebouncedInput, bindTableSort, buildShowMoreButton, buildRowsHtml, captureProvenance, countLabel, createTableSort, downloadCsvRows, formatInstantLabel, trimRootPath, PAGE_SIZE } from '../pages/shared.js';
import { getPasswordsData, getCookiesData, getAutofillsData, getNotesData } from '../pages/credentials.js';
import { getHistoryData, getBookmarksData } from '../pages/browser.js';
import { getDownloadsData, getClipboardData } from '../pages/activity.js';
import { getAccountTokensData } from '../pages/assets.js';
import { buildCredentialCurrentnessModel } from '../analysis/credentialCurrentness.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import { getCategoryLabel, getCategorySource, isGenericCategory, SITE_CATEGORY_PRIORITY } from '../core/domainCategories.js';

let currentnessModel = null;
let currentnessFiltered = [];
let currentnessShown = 0;
let sysinfoEntries = null;
let capture = null;
let currentnessActiveFilter = 'all';
let credentialsAnalysis = null;

const CURRENTNESS_FILTERS = [
  { key: 'all', label: 'All rows', predicate: () => true },
  { key: 'priority', label: 'Priority queue', predicate: (row) => row.isPriority },
  { key: 'sensitive', label: 'Sensitive sites', predicate: (row) => !!row.categories?.includes('sensitive') },
  { key: 'uncategorised', label: 'Uncategorised', predicate: (row) => row.categoryKey === 'unknown' },
  { key: 'active', label: 'Likely current', predicate: (row) => row.bucket === 'likely-current' },
  { key: 'aligned', label: 'Corroborated employer', predicate: (row) => row.identityFitKey === 'aligned-corroborated' || row.identityFitKey === 'corroborated' },
  { key: 'legacy', label: 'Legacy employer', predicate: (row) => row.dispositionKey === 'legacy-employer' },
  { key: 'orphaned', label: 'Orphaned corporate', predicate: (row) => row.identityFitKey === 'orphaned' },
  { key: 'corp-on-consumer', label: 'Corp email on consumer site', predicate: (row) => row.dispositionKey === 'corp-on-consumer' },
  { key: 'app', label: 'App-stored', predicate: (row) => row.isAppCredential },
  { key: 'personal', label: 'Personal email', predicate: (row) => row.identityFitKey === 'public' },
];

// Some categories come from a list under data/site-domains/, others from a
// domain-suffix rule. The classifier names the one that matched; this stands in
// for the handful of keys it has no single source for.
const CATEGORY_SOURCE_NOTE = 'Matched a domain reference list or suffix rule';

// The classifier's escalation, and the reason these four keep a badge while the
// broad "people use this site" categories lose theirs.
const SENSITIVE_CATEGORY_NOTE = 'Sensitive site: government, military, banking or finance';

// Candidate statuses ordered by how bad the news is; the tone is the only
// severity signal the model publishes.
const CANDIDATE_TONE_ORDER = ['success', 'accent', 'warning', 'danger'];

// Clicking a header sorts by that column; clicking back through the cycle
// returns the table to the ranking the engine published, which is the ordering
// the page exists to show.
const RANK_CAPTION = 'Ordered by triage rank: live access first, then confidence score.';

const currentnessSort = createTableSort({
  site: (row) => row.siteHost || row.siteDomain,
  user: (row) => row.username,
  score: (row) => row.score,
  triage: (row) => row.displayLabel || row.dispositionLabel || row.bucketLabel,
});

// The shared sorter renders a bare header cell; these columns carry their width
// and their small-screen behaviour as classes, so the markup is assembled here
// from the same sort state.
function labTh(key, label, columnClass) {
  const active = currentnessSort.key === key && currentnessSort.order !== 'none';
  const classes = ['sortable', columnClass, active ? `sort-${currentnessSort.order}` : ''].filter(Boolean).join(' ');
  const aria = active ? (currentnessSort.order === 'asc' ? 'ascending' : 'descending') : 'none';
  return `<th class="${classes}" data-sort-key="${key}" tabindex="0" aria-sort="${aria}">${escapeHtml(label)}</th>`;
}

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

  const hostIdx = data.headers.findIndex((header) => FIELD_PATTERNS.cookieDomain.test(header));
  const nameIdx = data.headers.findIndex((header) => FIELD_PATTERNS.cookieName.test(header));

  return data.rows.map((entry) => ({
    host: (hostIdx >= 0 ? (entry.row[hostIdx] || '') : '').replace(/^\./, '').trim().toLowerCase(),
    name: (nameIdx >= 0 ? (entry.row[nameIdx] || '') : '').trim(),
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
    captureContext: capture,
  };
}

function isCurrentnessPageActive() {
  return document.querySelector('.sidebar-nav-item.active')?.dataset.page === 'currentnesslab';
}

function getCurrentnessFilterDefinition(key) {
  return CURRENTNESS_FILTERS.find((entry) => entry.key === key) || CURRENTNESS_FILTERS[0];
}

// The search box narrows the case; the chips narrow the search. Keeping the two
// passes separate lets the chip counts and the category strip describe the same
// set the table is drawn from.
function applySearch(rows, searchQuery = '') {
  const q = searchQuery.trim().toLowerCase();
  if (!q) return rows || [];
  return (rows || []).filter((row) => buildSearchText(row).includes(q));
}

function applyCurrentnessFilters(rows, searchQuery = '') {
  const filterDef = getCurrentnessFilterDefinition(currentnessActiveFilter);
  return currentnessSort.apply(applySearch(rows, searchQuery).filter((row) => filterDef.predicate(row)));
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

// How sure the resolver is of the address it put in the headline. Corporate is
// the only one that carries the success tone: an employer is a finding, a
// webmail address is a fact.
function identityTag(id) {
  if (id.kind === 'unknown') return { tone: 'muted', text: 'no email identity recovered' };
  if (id.tentative) return { tone: 'muted', text: 'tentative identity' };
  if (id.kind === 'corporate') return { tone: 'success', text: `corporate identity · ${id.domain}` };
  return { tone: 'muted', text: 'personal identity' };
}

// The dashboard counts credentials unique by domain, username and password;
// this table also ranks accounts whose password was never captured, so it is
// always the larger figure. Printing the two parts is what stops them reading
// as a contradiction. They come from separate passes over the credential files,
// so the split is only shown when it adds up.
function rankedRowsFact(summary) {
  const analysed = credentialsAnalysis;
  const split = analysed
    && analysed.accountsWithoutPasswords > 0
    && analysed.uniqueCredentials + analysed.accountsWithoutPasswords === summary.rankedRows;
  const detail = split
    ? ` \u2014 ${countLabel(analysed.uniqueCredentials, 'unique credential')} plus ${countLabel(analysed.accountsWithoutPasswords, 'account with no captured password', 'accounts with no captured password')}`
    : '';
  const title = detail
    ? ''
    : ' title="One row per site, username and password, including accounts whose password was never captured."';
  return `<span${title}><strong>${summary.rankedRows.toLocaleString()}</strong> ranked rows${detail}</span>`;
}

function buildHeroLine(summary) {
  const id = summary.primaryIdentity || { kind: 'unknown', label: '', domain: '', evidence: [] };

  // Headline: the primary identity, ranked the same way the Identity page ranks
  // it, with the evidence for the pick on the line below so it can be argued
  // with rather than taken on trust.
  const tag = identityTag(id);
  const headlineHtml = `<strong>${escapeHtml(id.label || id.osUsername || 'Unknown victim')}</strong> <span class="lab-hero-tag lab-hero-tag-${tag.tone}">${escapeHtml(tag.text)}</span>`;

  const idEvidence = (id.evidence || []).map((item) => escapeHtml(item)).join(' · ');

  // The employer is a separate claim from the primary identity — the busiest
  // address in a case is often the victim's personal one — so it sits with the
  // host facts rather than inside the evidence for the pick.
  const employer = summary.dominantCorporateDomain?.domain || '';
  const idMeta = [
    employer && employer !== id.domain ? `corroborated employer <code>${escapeHtml(employer)}</code>` : '',
    id.osUsername ? `OS user <code>${escapeHtml(id.osUsername)}</code>` : '',
    id.computerName ? `host <code>${escapeHtml(id.computerName)}</code>` : '',
    id.country ? `country ${escapeHtml(id.country)}` : '',
  ].filter(Boolean).join(' · ');

  // Live evidence: the most actionable summary on the page. App-stored rows are
  // live by definition, so they ride inside the live figure rather than beside
  // it — added up as siblings they double-count the same credentials.
  const appNote = summary.appCount > 0 ? ` (${summary.appCount.toLocaleString()} app-stored)` : '';
  const liveBits = [
    summary.liveCount > 0
      ? `<span class="lab-hero-live" title="Valid session or app-stored"><strong>${summary.liveCount.toLocaleString()}</strong> live-access evidence${appNote}</span>`
      : '',
    summary.recentCount > 0 ? `<span><strong>${summary.recentCount.toLocaleString()}</strong> recent</span>` : '',
    summary.reuseGroups > 0 ? `<span><strong>${summary.reuseGroups.toLocaleString()}</strong> reused passwords</span>` : '',
  ].filter(Boolean);

  // Read the anchor off the model so the line cannot contradict the rows it
  // sits above; the model resolves it from the same published context.
  const anchor = summary.captureDate
    ? { date: summary.captureDate, source: summary.captureSource, detail: summary.captureDetail, offsetMinutes: summary.captureOffsetMinutes }
    : null;
  const captureBit = anchor
    ? `Captured ${escapeHtml(formatInstantLabel(anchor.date))} <span class="lab-hero-tag-muted">(${escapeHtml(captureProvenance(anchor))})</span>`
    : `<span class="lab-hero-warn">No capture anchor; recency disabled</span>`;

  return `
    <div class="lab-hero">
      <div class="lab-hero-headline">${headlineHtml}</div>
      ${idEvidence ? `<div class="lab-hero-meta">${idEvidence}</div>` : ''}
      ${idMeta ? `<div class="lab-hero-meta">${idMeta}</div>` : ''}
      <div class="lab-hero-facts">
        ${rankedRowsFact(summary)}
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

function categoryPillLabel(key) {
  if (key === 'unknown') return 'Uncategorised';
  return getCategoryLabel(key) || key;
}

// Every category the rows actually carry earns a pill, so the strip always sums
// to the ranked-row count. Order follows the classifier's own precision ranking
// — "unknown" leads as the analyst-priority bucket, the ranked keys run
// high-value to generic — and anything the classifier grows later lands at the
// end by size rather than vanishing.
function orderCategoryKeys(counts) {
  const ranked = ['unknown', ...SITE_CATEGORY_PRIORITY].filter((key) => counts.has(key));
  const seen = new Set(ranked);
  const rest = [...counts.keys()]
    .filter((key) => !seen.has(key))
    .sort((a, b) => counts.get(b) - counts.get(a));
  return [...ranked, ...rest];
}

function buildCategoryBreakdown(rows) {
  if (!rows?.length) return '';
  const counts = new Map();
  for (const row of rows) {
    const key = row.categoryKey || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  if (counts.size <= 1 && counts.has('unknown')) return ''; // categories haven't loaded yet

  const segments = orderCategoryKeys(counts)
    .map((key) => {
      const tone = key === 'unknown' ? ' lab-cat-unknown' : '';
      return `<span class="lab-cat-pill${tone}"><strong>${counts.get(key).toLocaleString()}</strong> ${escapeHtml(categoryPillLabel(key))}</span>`;
    })
    .join('');

  return `<div class="lab-cat-breakdown" title="Domain categories across the rows on screen">${segments}</div>`;
}

// Each candidate carries the engine's own verdict; group on that rather than on
// tone so "tentative" is not reported as a currentness judgement it never made.
function groupCandidatesByStatus(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const key = entry.status || 'unknown';
    if (!groups.has(key)) {
      groups.set(key, { label: entry.statusLabel || key, tone: entry.statusTone || 'neutral', entries: [] });
    }
    groups.get(key).entries.push(entry);
  }
  const rank = (tone) => {
    const at = CANDIDATE_TONE_ORDER.indexOf(tone);
    return at < 0 ? CANDIDATE_TONE_ORDER.length : at;
  };
  return [...groups.values()].sort((a, b) => rank(a.tone) - rank(b.tone));
}

function buildCandidatesPanel(summary) {
  if (!summary.identityDomains?.length) return '';

  const groups = groupCandidatesByStatus(summary.identityDomains);
  const summaryParts = [
    countLabel(summary.identityDomains.length, 'candidate'),
    ...groups.map((group) => `${group.entries.length.toLocaleString()} ${group.label.toLowerCase()}`),
  ];

  const items = groups.flatMap((group) => group.entries).map((entry) => {
    const tone = escapeHtml(entry.statusTone || 'neutral');
    const counts = [
      entry.likelyCurrent ? `${entry.likelyCurrent.toLocaleString()} likely` : '',
      entry.review ? `${entry.review.toLocaleString()} review` : '',
      entry.weak ? `${entry.weak.toLocaleString()} weak` : '',
    ].filter(Boolean).join(' · ') || countLabel(entry.rowCount, 'row');
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

// The rest of the identity ranking. The headline names one address; this says
// which others were considered and on what, so an analyst who disagrees can see
// the second-placed one without leaving the page.
function buildIdentityRankingPanel(summary) {
  const id = summary.primaryIdentity;
  const candidates = id?.candidates || [];
  if (candidates.length < 2) return '';

  const CAP = 8;
  const shown = candidates.slice(0, CAP);
  const items = shown.map((entry, index) => {
    const isPick = index === 0;
    const tone = isPick ? (entry.tentative ? 'warning' : 'success') : 'neutral';
    const counts = [
      entry.services > 0 ? countLabel(entry.services, 'service') : 'no service in this case',
      `score ${entry.score}`,
    ].join(' · ');
    const sourceTags = entry.sources
      .filter((src) => src !== 'credentials')
      .map((src) => `<span class="lab-tag">${escapeHtml(src)}</span>`)
      .join('');
    return `
      <li class="lab-candidate">
        <span class="lab-candidate-domain">${escapeHtml(entry.email)}</span>
        <span class="lab-candidate-status lab-tone-${tone}">${isPick ? 'Primary' : 'Considered'}</span>
        <span class="lab-candidate-counts">${escapeHtml(counts)}</span>
        <span class="lab-candidate-sources">${sourceTags}</span>
      </li>
    `;
  }).join('');

  const heading = [
    `Identity ranking: ${id.label}`,
    `${countLabel(candidates.length, 'address', 'addresses')} considered`,
    candidates.length > CAP ? `top ${CAP} shown` : '',
  ].filter(Boolean).join(' · ');

  return `
    <details class="lab-candidates">
      <summary>${escapeHtml(heading)}</summary>
      <ul class="lab-candidate-list">${items}</ul>
    </details>
  `;
}

function renderCurrentnessMeta(summary, rows) {
  const metaEl = document.getElementById('currentnessLabMeta');
  if (!metaEl) return;

  if (!summary || summary.rankedRows === 0) {
    metaEl.innerHTML = '';
    return;
  }

  metaEl.innerHTML = `
    ${buildHeroLine(summary)}
    ${buildCategoryBreakdown(rows)}
    <div class="lab-filters">${buildFilterChips(rows)}</div>
    ${buildIdentityRankingPanel(summary)}
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
      ? `<span class="lab-tag lab-tone-${escapeHtml(row.identityFitTone || 'neutral')}">${escapeHtml(row.identityFitLabel)}</span>`
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
  const dispositionTone = escapeHtml(row.dispositionTone || 'neutral');
  const priorityClass = row.isPriority ? ' lab-cred-priority' : '';

  const reuseMarker = row.reuseCount > 1
    ? ` <span class="lab-reuse-tag" title="${escapeHtml('Password reused across ' + row.reuseCount.toLocaleString() + ' sites')}">reused × ${row.reuseCount.toLocaleString()}</span>`
    : '';

  const actionDotTitle = `Actionability: ${action}`;
  const display = row.displayLabel || row.dispositionLabel || row.bucketLabel || '';

  // Four rows in five are uncategorised or land in one of the broad lists that
  // say only "people use this site". A badge on those is noise beside the
  // breakdown strip and the filter chips, which count the same rows.
  const catKey = row.categoryKey || 'unknown';
  const isSensitive = !!row.categories?.includes('sensitive');
  const catSource = getCategorySource(catKey) || CATEGORY_SOURCE_NOTE;
  const catTitle = isSensitive ? `${SENSITIVE_CATEGORY_NOTE}. ${catSource}` : catSource;
  const catBadge = catKey === 'unknown' || isGenericCategory(catKey)
    ? ''
    : `<span class="lab-cat-tag${isSensitive ? ' lab-tone-danger' : ''}" title="${escapeHtml(catTitle)}">${escapeHtml(categoryPillLabel(catKey))}</span>`;

  return `<tr class="lab-cred${priorityClass}" tabindex="0" aria-expanded="false">
    <td class="lab-cred-site" title="${escapeHtml(row.url)}"><span class="lab-cred-site-host">${escapeHtml(row.siteHost || row.siteDomain || '—')}</span>${catBadge}</td>
    <td class="lab-cred-user" title="${escapeHtml(row.username)}">${escapeHtml(row.username || '—')}${reuseMarker}</td>
    <td class="lab-cred-action" title="${escapeHtml(actionDotTitle)}"><span class="lab-cred-score-num lab-score-${escapeHtml(action)}">${row.score}</span></td>
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
    summaryEl.textContent = 'No credential currentness data.';
    renderCurrentnessMeta(null);
    contentEl.innerHTML = '<div class="no-data">No scored credentials.</div>';
    return;
  }

  const summary = currentnessModel.summary;
  const activeFilter = getCurrentnessFilterDefinition(currentnessActiveFilter);
  const searched = applySearch(currentnessModel.rows, searchQuery);
  currentnessFiltered = currentnessSort.apply(searched.filter((row) => activeFilter.predicate(row)));
  currentnessShown = Math.min(PAGE_SIZE, currentnessFiltered.length);
  const filterText = activeFilter.key !== 'all' ? ` · ${activeFilter.label}` : '';
  summaryEl.textContent = currentnessFiltered.length !== currentnessModel.rows.length
    ? `${currentnessFiltered.length.toLocaleString()} of ${currentnessModel.rows.length.toLocaleString()} ranked rows${filterText}`
    : `${currentnessModel.rows.length.toLocaleString()} ranked rows${filterText}`;

  renderCurrentnessMeta(summary, searched);

  if (currentnessFiltered.length === 0) {
    contentEl.innerHTML = '<div class="no-data">No credential rows match the current search and analyst filters.</div>';
    return;
  }

  let html = currentnessSort.order === 'none' ? `<div class="data-table-caption">${RANK_CAPTION}</div>` : '';
  html += '<div class="data-table-container"><table class="lab-creds-table">';
  html += `<thead><tr>${labTh('site', 'Site', 'lab-col-site')}${labTh('user', 'User', 'lab-col-user')}${labTh('score', 'Score', 'lab-col-score')}${labTh('triage', 'Triage', 'lab-col-disp')}<th class="lab-col-bar">Signals</th></tr></thead><tbody>`;
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
    capture = null;
    credentialsAnalysis = null;
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
  bindTableSort(contentEl, currentnessSort, () => renderCurrentnessPage(searchInput?.value || ''));

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

  // Cookie validity is re-judged when the capture instant lands, so a model
  // built before it has to be scored again.
  on('analysis:capture', (data) => {
    capture = data;
    if (modelReady) rebuildCurrentnessModel();
  });

  on('analysis:credentials', (data) => { credentialsAnalysis = data; });

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
    currentnessSort.reset();
    document.getElementById('navCurrentnessLab').disabled = true;
    const metaEl = document.getElementById('currentnessLabMeta');
    if (metaEl) metaEl.innerHTML = '';
    if (searchInput) searchInput.value = '';
  });
}

export { initCurrentnessLab };
