// Dashboard/overview rendering and analysis event handling.

import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { copyToClipboard, parseTimestampValue, parseArchiveTimestamp, extractCountryFromFilename, isValidCountryCode, classifyIpAddress } from '../core/shared.js';
import { CAPTURE_TIME_KEYS } from '../core/definitions/patterns.js';
import { escapeHtml, escapeAttr, capitalise } from '../core/utils.js';
import { formatDateTimeLabel } from '../pages/shared.js';
let sysInfoSourcePath = null;
let overviewScreenshotUrl = null;
let sysinfoIocs = [];
let clipboardIocs = [];
let clipboardLures = [];

const LURE_LABELS = {
  clickfix: 'ClickFix',
  powershell: 'PowerShell',
  mshta: 'mshta',
  certutil: 'certutil',
  'base64-blob': 'Base64 blob',
  'crypto-swap': 'Clipper / address swap',
};

const overviewState = {
  credentials: null,
  cookies: null,
  history: null,
  sysinfo: null,
  downloads: null,
  domainDetect: null,
  fingerprint: null,
  screenshot: null,
  creditCards: null,
  accountTokens: null,
  serviceArtifacts: null,
  wallets: null,
  notes: null,
  grabbedFiles: null,
  autofill: null,
  identity: null,
  readErrors: null,
};

function setOverviewState(key, value) {
  overviewState[key] = value || null;
  renderTriageOverview();
}

function pluralise(value, singular, plural = singular + 's') {
  return `${value.toLocaleString()} ${value === 1 ? singular : plural}`;
}

function joinNaturalList(values, conjunction = 'and') {
  const items = (values || []).filter(Boolean);
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, ${conjunction} ${items[items.length - 1]}`;
}

function inferLikelyExfilDate(sysinfo) {
  const sysinfoDate = findSysinfoValue(sysinfo, CAPTURE_TIME_KEYS);
  const parsedSysinfoDate = parseTimestampValue(sysinfoDate);
  if (parsedSysinfoDate) return { date: parsedSysinfoDate, source: 'sysinfo' };

  const archiveDate = parseArchiveTimestamp(state.rootZipName || '');
  if (archiveDate) return { date: archiveDate, source: 'archive-name' };

  if (state.sourceFile?.lastModified) {
    const fallback = new Date(state.sourceFile.lastModified);
    if (!isNaN(fallback.getTime())) return { date: fallback, source: 'file-modified' };
  }

  return null;
}

function findSysinfoValue(data, patterns) {
  if (!data || !data.entries) return '';
  for (const [key, value] of Object.entries(data.entries)) {
    if (patterns.some(pattern => pattern.test(key)) && value) return value;
  }
  return '';
}

function deriveVictimCountry(sysinfo, autofill) {
  const fromSysinfo = findSysinfoValue(sysinfo, [/^country$/i, /^location$/i, /^region$/i]);
  if (fromSysinfo && isValidCountryCode(fromSysinfo)) return { value: fromSysinfo, source: 'sysinfo' };
  const autofillCountry = (autofill?.entries || []).find(e => /country/i.test(e?.name || '') && (e?.value || '').trim());
  if (autofillCountry) return { value: autofillCountry.value.trim(), source: 'autofill' };
  if (fromSysinfo) return { value: fromSysinfo, source: 'sysinfo' };
  const fromFilename = extractCountryFromFilename(state.rootZipName || '');
  if (fromFilename) return { value: fromFilename, source: 'filename' };
  return { value: '', source: 'unknown' };
}

function renderCaseContext({ computer, resolvedUser, userSource, countryInfo, exfilInfo }) {
  const el = document.getElementById('dashCaseContext');
  if (!el) return;
  const items = [];
  const push = (key, val) => items.push(`<span class="ctx-item"><span class="ctx-key">${key}</span> <span class="ctx-val">${escapeHtml(val)}</span></span>`);
  if (computer) push('host', computer);
  if (resolvedUser) push('user', userSource && userSource !== 'sysinfo' ? `${resolvedUser} (${userSource})` : resolvedUser);
  if (countryInfo?.value) push('location', countryInfo.source === 'sysinfo' ? countryInfo.value : `${countryInfo.value} (${countryInfo.source})`);
  if (exfilInfo?.date) push('captured', formatDateTimeLabel(exfilInfo.date));
  if (state.rootZipName) push('source', state.rootZipName);
  if (items.length === 0) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.classList.remove('hidden');
  el.innerHTML = items.join('<span class="ctx-sep">·</span>');
}

function buildVerdictCard({ label, value, note, target }) {
  const link = target ? `<button class="verdict-card-link" data-nav="${escapeAttr(target)}">View &rarr;</button>` : '';
  return `<div class="verdict-card">
    <div class="verdict-card-label">${escapeHtml(label)}</div>
    <div class="verdict-card-value">${escapeHtml(value)}</div>
    <div class="verdict-card-note">${escapeHtml(note)}</div>
    ${link}
  </div>`;
}

// The four questions an IR responder asks first: what is still live, how wide
// is the credential blast radius, what money/identity is exposed, what did the
// operator capture. Each card links straight to the detail.
function renderVerdictCards({ credentials, cookies, cards, history, grabbed, screenshot, autofill, nationalIds }) {
  const el = document.getElementById('dashVerdictCards');
  if (!el) return;
  const out = [];

  if (cookies?.totalCookies > 0) {
    const live = cookies.validSessionTokens || 0;
    out.push(buildVerdictCard({
      label: 'Live sessions',
      value: live.toLocaleString(),
      note: live > 0
        ? 'Session tokens still valid at capture. May grant account access without a password; verify before relying.'
        : 'No session tokens were still valid at capture.',
      target: 'cookies',
    }));
  }

  if (credentials?.uniqueCredentials > 0) {
    const topDomain = credentials.topDomains?.[0]?.value;
    out.push(buildVerdictCard({
      label: 'Credentials',
      value: credentials.uniqueCredentials.toLocaleString(),
      note: topDomain
        ? `Recovered logins, heaviest on ${topDomain}. Rank live and reused ones in Credential Triage.`
        : 'Recovered logins. Rank live and reused ones in Credential Triage.',
      target: 'currentnesslab',
    }));
  }

  const finBits = [];
  if (cards?.totalCards > 0) finBits.push(pluralise(cards.totalCards, 'stored card') + (cards.withCvc > 0 ? ' with CVC' : ''));
  const idTotal = (nationalIds || []).reduce((sum, n) => sum + n.count, 0);
  if (idTotal > 0) finBits.push('government IDs');
  if (autofill?.totalEntries > 0) finBits.push(pluralise(autofill.totalEntries, 'autofill PII record'));
  if (finBits.length > 0) {
    const value = cards?.totalCards > 0
      ? cards.totalCards.toLocaleString()
      : (idTotal > 0 ? idTotal.toLocaleString() : (autofill?.totalEntries || 0).toLocaleString());
    out.push(buildVerdictCard({
      label: 'Financial & identity',
      value,
      note: `${joinNaturalList(finBits)}.`,
      target: cards?.totalCards > 0 ? 'cards' : 'autofills',
    }));
  }

  const capBits = [];
  if (screenshot?.entries?.length > 0) capBits.push(pluralise(screenshot.entries.length, 'desktop screenshot'));
  if (grabbed?.fileCount > 0) capBits.push(pluralise(grabbed.fileCount, 'grabbed file'));
  if (history?.totalEntries > 0) capBits.push(pluralise(history.totalEntries, 'history entry', 'history entries'));
  if (capBits.length > 0) {
    const value = history?.totalEntries > 0
      ? history.totalEntries.toLocaleString()
      : (grabbed?.fileCount || screenshot?.entries?.length || 0).toLocaleString();
    out.push(buildVerdictCard({
      label: 'Capture evidence',
      value,
      note: `${joinNaturalList(capBits)}.`,
      target: screenshot?.entries?.length > 0 ? 'screenshots' : 'browser',
    }));
  }

  if (out.length === 0) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.classList.remove('hidden');
  el.innerHTML = out.join('');
}

function renderSimpleList(container, items) {
  if (!items || items.length === 0) {
    container.innerHTML = '';
    return;
  }
  container.innerHTML = items.map(item => {
    const text = typeof item === 'string' ? item : item?.text || '';
    const variant = typeof item === 'object' && item?.variant ? ` dash-list-item-${item.variant}` : '';
    return `<div class="dash-list-item${variant}">${escapeHtml(text)}</div>`;
  }).join('');
}

function renderBarList(container, items, maxItems = 10) {
  if (items.length === 0) {
    container.innerHTML = '<div class="dash-bar-empty">None found</div>';
    return;
  }
  const top = items.slice(0, maxItems);
  const maxCount = top[0].count;
  container.innerHTML = top.map(item => {
    const pct = Math.round((item.count / maxCount) * 100);
    const aria = `role="meter" aria-valuenow="${item.count}" aria-valuemin="0" aria-valuemax="${maxCount}" aria-label="${escapeAttr(item.value)}: ${item.count}"`;
    return `<div class="dash-bar-row" ${aria}>
      <div class="dash-bar-fill" style="width:${pct}%"></div>
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count}</span>
    </div>`;
  }).join('');
}

function renderCookieBarList(container, items, maxItems = 10) {
  if (items.length === 0) {
    container.innerHTML = '<div class="dash-bar-empty">None found</div>';
    return;
  }
  const top = items.slice(0, maxItems);
  const maxCount = top[0].count;

  let html = '<div class="dash-bar-legend"><span class="dash-bar-legend-item"><span class="dash-bar-legend-swatch dash-bar-legend-valid"></span>Valid</span><span class="dash-bar-legend-item"><span class="dash-bar-legend-swatch dash-bar-legend-expired"></span>Expired</span></div>';

  html += top.map(item => {
    const validPct = Math.round((item.valid / maxCount) * 100);
    const expiredPct = Math.round((item.expired / maxCount) * 100);
    const ariaLabel = `${item.value}: ${item.count} cookies (${item.valid} valid, ${item.expired} expired)`;
    const aria = `role="meter" aria-valuenow="${item.count}" aria-valuemin="0" aria-valuemax="${maxCount}" aria-label="${escapeAttr(ariaLabel)}"`;
    return `<div class="dash-bar-row dash-bar-row-stacked" ${aria}>
      <div class="dash-bar-fill dash-bar-fill-valid" style="width:${validPct}%"></div>
      <div class="dash-bar-fill dash-bar-fill-expired" style="width:${expiredPct}%; left:${validPct}%"></div>
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count}</span>
    </div>`;
  }).join('');

  container.innerHTML = html;
}

function resolveSysInfoSourcePath(sourceFiles) {
  const firstSource = (sourceFiles || []).find(Boolean);
  if (!firstSource) return null;
  if (firstSource.includes('/')) return firstSource;

  const matches = state.flatFiles.filter(file => file._sysInfoHint && file.name === firstSource);
  return matches.length === 1 ? matches[0].path : null;
}

function renderDashboardIocs() {
  const victimSection = document.getElementById('dashIOCs');
  const victimBody = document.getElementById('dashIOCBody');
  const infraSection = document.getElementById('dashStealerInfra');
  const infraBody = document.getElementById('dashStealerInfraBody');
  if (!victimSection || !victimBody) return;

  const victim = [];
  const infra = [];
  const seen = new Set();
  for (const item of [...sysinfoIocs, ...clipboardIocs]) {
    const label = String(item?.label || '').trim();
    const value = String(item?.value || '').trim();
    if (!label || !value) continue;
    const key = `${label}\u0000${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const out = { label, value };
    if (item.family) out.family = item.family;
    (item?.kind === 'stealer-infra' ? infra : victim).push(out);
  }

  function renderItems(items) {
    return items.map((ioc) => {
      const family = ioc.family ? `<span class="dash-ioc-family">${escapeHtml(ioc.family)}</span>` : '';
      const ipClass = classifyIpAddress(ioc.value);
      const badge = ipClass?.synthetic
        ? `<span class="dash-ioc-badge" title="${escapeAttr(ipClass.label)}">synthetic / non-victim IP</span>`
        : '';
      return `<div class="dash-ioc-item">
        <span class="dash-ioc-label">${escapeHtml(ioc.label)}</span>${family}
        <span class="dash-ioc-value">${escapeHtml(ioc.value)}</span>${badge}
        <button class="dash-ioc-copy" title="Copy" data-copy="${escapeAttr(ioc.value)}">Copy</button>
      </div>`;
    }).join('');
  }

  if (victim.length === 0) {
    victimSection.classList.add('hidden');
    victimBody.innerHTML = '';
  } else {
    victimSection.classList.remove('hidden');
    victimBody.innerHTML = renderItems(victim);
  }

  if (!infraSection || !infraBody) return;
  if (infra.length === 0) {
    infraSection.classList.add('hidden');
    infraBody.innerHTML = '';
  } else {
    infraSection.classList.remove('hidden');
    infraBody.innerHTML = renderItems(infra);
  }
}

function renderClipboardLures() {
  const section = document.getElementById('dashClipboardLures');
  const body = document.getElementById('dashClipboardLuresBody');
  if (!section || !body) return;

  if (clipboardLures.length === 0) {
    section.classList.add('hidden');
    body.innerHTML = '';
    return;
  }

  section.classList.remove('hidden');
  body.innerHTML = clipboardLures.map((lure) => {
    const label = LURE_LABELS[lure.category] || lure.category;
    const preview = lure.text.length > 280 ? lure.text.slice(0, 280) + '…' : lure.text;
    return `<div class="dash-ioc-item">
      <span class="dash-ioc-family dash-ioc-family-warn">${escapeHtml(label)}</span>
      <span class="dash-ioc-value">${escapeHtml(preview)}</span>
      <button class="dash-ioc-copy" title="Copy" data-copy="${escapeAttr(lure.text)}">Copy</button>
    </div>`;
  }).join('');
}

function renderTriageOverview() {
  const riskSection = document.getElementById('dashRiskSignals');
  const riskBody = document.getElementById('dashRiskSignalsBody');

  const sysinfo = overviewState.sysinfo;
  const credentials = overviewState.credentials;
  const cookies = overviewState.cookies;
  const history = overviewState.history;
  const wallets = overviewState.wallets;
  const cards = overviewState.creditCards;
  const grabbed = overviewState.grabbedFiles;
  const screenshot = overviewState.screenshot;
  const autofill = overviewState.autofill;
  const readErrors = overviewState.readErrors;

  const osUser = findSysinfoValue(sysinfo, [/^user\s*name$/i, /^username$/i, /^os user$/i]);
  const pi = overviewState.identity?.primaryIdentity;
  const resolvedUser = osUser || (pi?.osUsername || '');
  const userSource = osUser ? 'sysinfo' : (pi?.userSource || null);
  const computer = findSysinfoValue(sysinfo, [/^computer\s*name$/i, /^pc\s*name$/i, /^machine\s*name$/i]);
  const countryInfo = deriveVictimCountry(sysinfo, autofill);
  const exfilInfo = inferLikelyExfilDate(sysinfo);

  renderCaseContext({ computer, resolvedUser, userSource, countryInfo, exfilInfo });
  renderVerdictCards({ credentials, cookies, cards, history, grabbed, screenshot, autofill, nationalIds: credentials?.nationalIds });

  // Assessment: genuine, actionable findings only, never a restatement of the
  // counts already carried by the verdict cards above.
  const riskItems = [];
  if (credentials?.onionCredentials > 0) {
    riskItems.push({
      text: `Tor hidden-service (.onion) credentials in ${pluralise(credentials.onionCredentials, 'domain')}: strong indicator of darknet-market or carding activity.`,
      variant: 'warn',
    });
  }
  if (clipboardLures.length > 0) {
    riskItems.push({
      text: 'Clipboard holds a likely social-engineering lure or clipper (ClickFix / PowerShell / address-swap).',
      variant: 'warn',
    });
  }
  if (cards?.withCvc > 0) {
    riskItems.push({
      text: `${pluralise(cards.withCvc, 'payment card')} recovered with a CVC value; treat as full card compromise.`,
      variant: 'warn',
    });
  }
  if (credentials?.failedFiles?.length > 0) {
    riskItems.push(`${pluralise(credentials.failedFiles.length, 'password file')} could not be parsed cleanly; review manually.`);
  }
  if (readErrors?.failedFiles?.length > 0) {
    riskItems.push(`${pluralise(readErrors.failedFiles.length, 'file')} could not be read or decoded and were skipped.`);
  }

  if (riskItems.length > 0) {
    riskSection.classList.remove('hidden');
    renderSimpleList(riskBody, riskItems);
  } else {
    riskSection.classList.add('hidden');
    riskBody.innerHTML = '';
  }

  renderSeedBanner(wallets);
  renderNationalIds(credentials);
  renderConsistencyChecks({ credentials, cookies, history, countryInfo });
}

function renderSeedBanner(wallets) {
  const banner = document.getElementById('dashSeedBanner');
  if (!banner) return;
  if (wallets?.withSeedHints > 0) {
    banner.classList.remove('hidden');
    banner.textContent = `${pluralise(wallets.withSeedHints, 'wallet store')} contain seed / recovery-phrase material — treat as full account compromise.`;
  } else {
    banner.classList.add('hidden');
    banner.textContent = '';
  }
}

function renderNationalIds(credentials) {
  const section = document.getElementById('dashNationalIds');
  const body = document.getElementById('dashNationalIdsBody');
  if (!section || !body) return;
  const ids = credentials?.nationalIds || [];
  if (ids.length === 0) {
    section.classList.add('hidden');
    body.innerHTML = '';
    return;
  }
  section.classList.remove('hidden');
  renderSimpleList(body, ids.map((n) => {
    const where = n.country ? ` (${n.country})` : '';
    return `${n.type}${where}: ${pluralise(n.count, 'field')}`;
  }));
}

const CCTLD_COUNTRY = {
  au: 'AU', nz: 'NZ', uk: 'GB', 'co.uk': 'GB', de: 'DE', fr: 'FR', es: 'ES', it: 'IT',
  nl: 'NL', se: 'SE', no: 'NO', fi: 'FI', dk: 'DK', pl: 'PL', pt: 'PT', ie: 'IE',
  br: 'BR', mx: 'MX', ar: 'AR', cl: 'CL', co: 'CO', ru: 'RU', ua: 'UA', tr: 'TR',
  in: 'IN', cn: 'CN', jp: 'JP', kr: 'KR', id: 'ID', th: 'TH', vn: 'VN', ph: 'PH',
  za: 'ZA', ng: 'NG', eg: 'EG', sa: 'SA', ae: 'AE', il: 'IL', ca: 'CA', us: 'US',
};

const CORPORATE_DOMAIN_RX = /(?:login\.microsoftonline\.com|accounts\.google\.com|sharepoint\.com|atlassian\.net|onelogin\.com|okta\.com)$/i;

function dominantCcTld(domains) {
  const counts = {};
  for (const d of domains) {
    const m = String(d || '').toLowerCase().match(/\.(co\.uk|[a-z]{2})$/);
    if (!m) continue;
    const tld = m[1];
    if (!CCTLD_COUNTRY[tld]) continue;
    counts[tld] = (counts[tld] || 0) + 1;
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return sorted.length ? sorted[0][0] : null;
}

function renderConsistencyChecks({ credentials, cookies, history, countryInfo }) {
  const section = document.getElementById('dashConsistency');
  const body = document.getElementById('dashConsistencyBody');
  if (!section || !body) return;

  const checks = [];
  const credDomains = (credentials?.topDomains || []).map(d => d.value);
  const histDomains = (history?.topDomains || []).map(d => d.value);

  if (cookies?.totalCookies > 0 && (!credentials || credentials.uniqueCredentials === 0)) {
    checks.push({ text: 'Session cookies recovered but no credentials parsed — credential files may be encrypted, missing, or unparsed.', variant: 'warn' });
  }

  const corpInHistory = histDomains.find(d => CORPORATE_DOMAIN_RX.test(d));
  if (corpInHistory && !credDomains.some(d => CORPORATE_DOMAIN_RX.test(d))) {
    checks.push({ text: `Corporate SSO domain ${corpInHistory} appears in browsing history but not in recovered credentials.`, variant: 'warn' });
  }

  const tld = dominantCcTld([...credDomains, ...histDomains]);
  const victimCode = String(countryInfo?.value || '').trim().toUpperCase();
  if (tld && victimCode.length === 2) {
    const tldCountry = CCTLD_COUNTRY[tld];
    if (tldCountry && tldCountry !== victimCode) {
      checks.push({ text: `Browsing/credential domains are predominantly .${tld} (${tldCountry}) but victim location resolves to ${victimCode}; verify geolocation.`, variant: 'warn' });
    }
  }

  if (checks.length > 0) {
    section.classList.remove('hidden');
    renderSimpleList(body, checks);
  } else {
    section.classList.add('hidden');
    body.innerHTML = '';
  }
}

function updateDashboardVisibility() {
  const credFiles = state.flatFiles.filter(f => f._passwordFileHint);
  const cookieFiles = state.flatFiles.filter(f => f._cookieFileHint);
  const autofillFiles = state.flatFiles.filter(f => f._autofillHint);
  const notesFiles = state.flatFiles.filter(f => f._notesHint);
  const historyFiles = state.flatFiles.filter(f => f._historyHint);
  const bookmarkFiles = state.flatFiles.filter(f => f._bookmarkHint);
  const browserMetaFiles = state.flatFiles.filter(f => f._browserMetadataHint);
  const sysInfoFiles = state.flatFiles.filter(f => f._sysInfoHint);
  const creditCardFiles = state.flatFiles.filter(f => f._creditCardHint);
  const cryptoWalletFiles = state.flatFiles.filter(f => f._cryptoWalletHint);
  const tokenFiles = state.flatFiles.filter(f => f._accountTokenHint);
  const serviceFiles = state.flatFiles.filter(f => f._serviceArtifactHint);
  const messengerFiles = state.flatFiles.filter(f => f._messengerHint);
  const downloadFiles = state.flatFiles.filter(f => f._downloadHint);
  const domainDetectFiles = state.flatFiles.filter(f => f._domainDetectHint);
  const clipboardFiles = state.flatFiles.filter(f => f._clipboardHint);
  const grabbedFiles = state.flatFiles.filter(f => f._grabbedFileHint);
  const screenshotFiles = state.flatFiles.filter(f => f._screenshotHint);
  const browserPluginFiles = state.flatFiles.filter(f => f._browserPluginHint);
  const softwareFiles = state.flatFiles.filter(f => f._softwareFileHint);
  const processFiles = state.flatFiles.filter(f => f._processListHint);

  const dashCred = document.getElementById('dashCredIntel');
  const dashCookie = document.getElementById('dashCookieIntel');
  const noData = document.getElementById('overviewNoData');

  dashCred.classList.toggle('hidden', credFiles.length === 0);
  dashCookie.classList.toggle('hidden', cookieFiles.length === 0);

  const hasAnyData = credFiles.length > 0 || cookieFiles.length > 0 ||
    autofillFiles.length > 0 || notesFiles.length > 0 || historyFiles.length > 0 || bookmarkFiles.length > 0 ||
    browserMetaFiles.length > 0 || sysInfoFiles.length > 0 ||
    creditCardFiles.length > 0 || cryptoWalletFiles.length > 0 || messengerFiles.length > 0 ||
    tokenFiles.length > 0 || serviceFiles.length > 0 ||
    downloadFiles.length > 0 || domainDetectFiles.length > 0 || clipboardFiles.length > 0 ||
    grabbedFiles.length > 0 || screenshotFiles.length > 0 || softwareFiles.length > 0 || processFiles.length > 0;
  noData.classList.toggle('hidden', hasAnyData);

  const extraEl = document.getElementById('dashExtraIntel');
  const extraBody = document.getElementById('dashExtraBody');

  if (creditCardFiles.length > 0 || cryptoWalletFiles.length > 0 || tokenFiles.length > 0 || serviceFiles.length > 0 || messengerFiles.length > 0 || downloadFiles.length > 0 || clipboardFiles.length > 0 || notesFiles.length > 0 || grabbedFiles.length > 0 || browserPluginFiles.length > 0 || bookmarkFiles.length > 0 || browserMetaFiles.length > 0 || softwareFiles.length > 0 || processFiles.length > 0) {
    extraEl.classList.remove('hidden');

    let html = '<div class="dash-extra-items">';
    if (creditCardFiles.length > 0) {
      html += `<div class="dash-extra-item dash-extra-warning"><span class="dash-extra-icon">CC</span><span>${creditCardFiles.length} credit card file(s) detected</span></div>`;
    }
    if (cryptoWalletFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">W</span><span>${cryptoWalletFiles.length} crypto wallet file(s) detected</span></div>`;
    }
    if (tokenFiles.length > 0) {
      html += `<div class="dash-extra-item dash-extra-warning"><span class="dash-extra-icon">TK</span><span>${tokenFiles.length} account token file(s) detected</span></div>`;
    }
    if (serviceFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">SV</span><span>${serviceFiles.length} service artifact file(s) detected</span></div>`;
    }
    if (messengerFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">M</span><span>${messengerFiles.length} unclassified service file(s) detected</span></div>`;
    }
    if (downloadFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">DL</span><span>${downloadFiles.length} download history file(s) detected</span></div>`;
    }
    if (clipboardFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">CL</span><span>${clipboardFiles.length} clipboard file(s) detected</span></div>`;
    }
    if (notesFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">NT</span><span>${notesFiles.length} note file(s) detected</span></div>`;
    }
    if (grabbedFiles.length > 0) {
      html += `<div class="dash-extra-item dash-extra-warning"><span class="dash-extra-icon">GF</span><span>${grabbedFiles.length} grabbed file(s) detected</span></div>`;
    }
    if (bookmarkFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">BM</span><span>${bookmarkFiles.length} bookmark file(s) detected</span></div>`;
    }
    if (browserMetaFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">MD</span><span>${browserMetaFiles.length} browser metadata file(s) detected</span></div>`;
    }
    if (browserPluginFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">EXT</span><span>${browserPluginFiles.length} browser extension/plugin file(s) detected</span></div>`;
    }
    if (softwareFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">SW</span><span>${softwareFiles.length} installed software file(s) detected</span></div>`;
    }
    if (processFiles.length > 0) {
      html += `<div class="dash-extra-item"><span class="dash-extra-icon">PS</span><span>${processFiles.length} process list file(s) detected</span></div>`;
    }
    html += '</div>';
    extraBody.innerHTML = html;
  } else {
    extraEl.classList.add('hidden');
    extraBody.innerHTML = '';
  }
}

export function getSysInfoSourcePath() {
  return sysInfoSourcePath;
}

export function resetOverviewState() {
  sysInfoSourcePath = null;
  sysinfoIocs = [];
  clipboardIocs = [];
  clipboardLures = [];

  if (overviewScreenshotUrl) {
    URL.revokeObjectURL(overviewScreenshotUrl);
    overviewScreenshotUrl = null;
  }

  for (const key of Object.keys(overviewState)) {
    overviewState[key] = null;
  }
}

export { updateDashboardVisibility };

export function initDashboard() {
  const loadingText = document.getElementById('loadingText');

  function bindCopy(node) {
    node?.addEventListener('click', (event) => {
      const btn = event.target.closest('.dash-ioc-copy');
      if (!btn) return;
      copyToClipboard(btn.dataset.copy).then((ok) => {
        if (ok) {
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        }
      });
    });
  }
  bindCopy(document.getElementById('dashIOCBody'));
  bindCopy(document.getElementById('dashStealerInfraBody'));
  bindCopy(document.getElementById('dashClipboardLuresBody'));

  // Verdict cards and demoted summaries drill straight into the detail page.
  document.getElementById('pageOverview')?.addEventListener('click', (event) => {
    const link = event.target.closest('.verdict-card-link');
    if (!link) return;
    const target = link.dataset.nav;
    if (target) document.querySelector(`.sidebar-nav-item[data-page="${target}"]`)?.click();
  });

  on('loading', () => {
    loadingText.textContent = state.loadingText;
  });

  on('analysis:credentials', (data) => {
    setOverviewState('credentials', data);
    const summaryEl = document.getElementById('dashCredSummary');
    summaryEl.classList.remove('dash-loading');
    const skipped = data.failedFiles?.length || 0;

    if (data.totalCredentials > 0) {
      let summary = `${data.uniqueCredentials.toLocaleString()} unique credentials from ${data.fileCount} file(s)`;
      if (data.totalCredentials !== data.uniqueCredentials) {
        summary += ` (${data.totalCredentials.toLocaleString()} total, ${(data.totalCredentials - data.uniqueCredentials).toLocaleString()} duplicates removed)`;
      }
      if (skipped > 0) {
        summary += `; ${skipped.toLocaleString()} file(s) skipped`;
      }
      summaryEl.textContent = summary;
      renderBarList(document.getElementById('dashTopDomains'), data.topDomains);
      renderBarList(document.getElementById('dashTopUsernames'), data.topUsernames);
      const localCol = document.getElementById('dashLocalNetworkCol');
      if (data.localNetwork?.length) {
        localCol.classList.remove('hidden');
        renderBarList(document.getElementById('dashLocalNetwork'), data.localNetwork);
      } else {
        localCol.classList.add('hidden');
        document.getElementById('dashLocalNetwork').innerHTML = '';
      }
    } else {
      summaryEl.textContent = skipped > 0
        ? `No structured credential data could be parsed; ${skipped.toLocaleString()} file(s) were skipped.`
        : 'No structured credential data could be parsed.';
      document.getElementById('dashLocalNetworkCol').classList.add('hidden');
    }
  });

  on('analysis:cookies', (data) => {
    setOverviewState('cookies', data);
    const summaryEl = document.getElementById('dashCookieSummary');
    summaryEl.classList.remove('dash-loading');

    if (data.totalCookies > 0) {
      let summaryHtml = `${data.totalCookies.toLocaleString()} cookies across ${data.uniqueDomains} domains from ${data.fileCount} file(s) &mdash; <span class="cookie-valid">${data.totalValid.toLocaleString()} valid</span>, <span class="cookie-expired">${data.totalExpired.toLocaleString()} expired</span>`;
      if (data.totalSession > 0) {
        summaryHtml += `, <span class="cookie-session">${data.totalSession.toLocaleString()} session</span>`;
      }
      if (data.totalUnknown > 0) {
        summaryHtml += `, <span class="cookie-unknown">${data.totalUnknown.toLocaleString()} unparseable expiry</span>`;
      }
      if (data.totalNoDomain > 0) {
        summaryHtml += `, <span class="cookie-unknown">${data.totalNoDomain.toLocaleString()} no domain</span>`;
      }
      if (data.sessionTokens > 0) {
        summaryHtml += ` &mdash; <span class="cookie-auth">${data.sessionTokens.toLocaleString()} session token${data.sessionTokens !== 1 ? 's' : ''}</span>`;
        if (data.validSessionTokens > 0) {
          summaryHtml += ` (<span class="cookie-auth-valid">${data.validSessionTokens.toLocaleString()} valid</span>)`;
        }
      }
      if (data.trackingTokens > 0) {
        summaryHtml += ` &mdash; <span class="cookie-session">${data.trackingTokens.toLocaleString()} ad-tracking token${data.trackingTokens !== 1 ? 's' : ''}</span>`;
      }
      summaryEl.innerHTML = summaryHtml;
      renderCookieBarList(document.getElementById('dashTopCookieDomains'), data.topDomains);
    } else {
      summaryEl.textContent = 'No structured cookie data could be parsed.';
    }
  });

  on('analysis:history', (data) => {
    setOverviewState('history', data);
  });

  on('analysis:sysinfo', (data) => {
    setOverviewState('sysinfo', data);
    const navBtn = document.getElementById('navSysInfo');
    const body = document.getElementById('dashSysInfoBody');
    const actions = document.getElementById('sysInfoActions');
    const openBtn = document.getElementById('sysInfoOpenBtn');
    sysInfoSourcePath = null;
    sysinfoIocs = [];

    if (!data || !data.entries) {
      navBtn.disabled = true;
      body.innerHTML = '<div class="no-data" id="sysInfoNoData">No system information files detected.</div>';
      actions.classList.add('hidden');
      openBtn.classList.add('hidden');
      openBtn.textContent = 'View Source';
      renderDashboardIocs();
      return;
    }

    navBtn.disabled = false;
    body.innerHTML = Object.entries(data.entries).map(([key, value]) =>
      `<div class="dash-kv-row">
      <span class="dash-kv-key">${escapeHtml(key)}</span>
      <span class="dash-kv-value">${escapeHtml(value)}</span>
    </div>`
    ).join('');

    actions.classList.remove('hidden');

    const resolvedSourcePath = resolveSysInfoSourcePath(data.sourceFiles);
    if (resolvedSourcePath) {
      sysInfoSourcePath = resolvedSourcePath;
      openBtn.classList.remove('hidden');
      openBtn.textContent = `View Source: ${sysInfoSourcePath}`;
    } else {
      openBtn.classList.add('hidden');
      openBtn.textContent = 'View Source';
    }

    sysinfoIocs = data.iocs || [];
    renderDashboardIocs();
  });

  on('analysis:clipboard', (data) => {
    clipboardIocs = [];
    clipboardLures = [];
    for (const entry of data?.entries || []) {
      if (entry.lure) {
        clipboardLures.push({ category: entry.lure, text: entry.text });
        continue;
      }
      if (entry.urls.length > 0) {
        for (const url of entry.urls) {
          clipboardIocs.push({ label: 'Clipboard URL', value: url });
        }
      } else if (entry.text.length <= 500) {
        clipboardIocs.push({ label: 'Clipboard', value: entry.text });
      }
    }
    renderClipboardLures();
    renderDashboardIocs();
  });

  on('analysis:autofill', (data) => {
    setOverviewState('autofill', data);
    const section = document.getElementById('dashAutofillIntel');
    const summaryEl = document.getElementById('dashAutofillSummary');
    const body = document.getElementById('dashAutofillBody');
    summaryEl.classList.remove('dash-loading');

    if (!data) {
      section.classList.add('hidden');
      body.innerHTML = '';
      return;
    }

    section.classList.remove('hidden');
    summaryEl.textContent = `${data.totalEntries} entries from ${data.fileCount} file(s)`;

    // Overview shows a counted summary and a few sample emails, not the whole
    // PII wall. The full parsed data lives on the Autofills page.
    const counts = [
      ['email', data.emails.length],
      ['phone', data.phones.length],
      ['name', data.names.length],
      ['address', data.addresses.length],
      ['other field', data.other.length],
    ].filter(([, n]) => n > 0);
    const plural = (label, n) => label === 'address' ? (n === 1 ? 'address' : 'addresses') : (n === 1 ? label : label + 's');
    const chips = counts.map(([label, n]) => `<span class="dash-chip">${n.toLocaleString()} ${plural(label, n)}</span>`).join('');
    const sample = data.emails.slice(0, 3).map(v => `<span class="dash-autofill-entry">${escapeHtml(v)}</span>`).join('');
    body.innerHTML = `
      <div class="dash-chip-row">${chips}</div>
      ${sample ? `<div class="dash-autofill-sample">${sample}</div>` : ''}
      <button class="verdict-card-link" data-nav="autofills">View all autofill data &rarr;</button>
    `;
  });

  on('analysis:downloads', (data) => {
    setOverviewState('downloads', data);
    const section = document.getElementById('dashDownloadIntel');
    const summaryEl = document.getElementById('dashDownloadSummary');
    const body = document.getElementById('dashDownloadBody');

    if (!data || data.totalDownloads === 0) {
      section.classList.add('hidden');
      body.innerHTML = '';
      summaryEl.textContent = 'Analysing download files...';
      return;
    }

    section.classList.remove('hidden');
    summaryEl.textContent = `${data.totalDownloads.toLocaleString()} download entr${data.totalDownloads === 1 ? 'y' : 'ies'} from ${data.fileCount} file(s)`;
    renderBarList(body, data.topDomains);
  });

  on('analysis:fingerprint', (data) => {
    setOverviewState('fingerprint', data);
    const section = document.getElementById('dashFingerprint');
    const body = document.getElementById('dashFingerprintBody');

    if (!data) {
      section.classList.add('hidden');
      return;
    }

    section.classList.remove('hidden');

    const confidenceLabel = capitalise(data.confidence) + ' confidence';
    const signalsId = 'fingerprintSignals_' + Date.now();
    const structureOnly = data.source === 'structure-only'
      ? `<span class="dash-fingerprint-source" title="No sysinfo file present; family inferred from folder/file layout only.">structure-only</span>`
      : '';

    body.innerHTML = `
    <div>
      <div class="dash-fingerprint-result">
        <span class="dash-fingerprint-badge">${escapeHtml(data.family)}</span>
        <span class="dash-fingerprint-confidence">
          <span class="dash-fingerprint-dot dash-fingerprint-dot-${data.confidence}"></span>
          ${escapeHtml(confidenceLabel)}
        </span>
        ${structureOnly}
      </div>
      <div class="dash-fingerprint-signals">
        <button class="dash-fingerprint-toggle" id="${signalsId}Btn">&#9656; Matched signals (${data.matchedSignals.length})</button>
        <ul class="dash-fingerprint-list" id="${signalsId}">
          ${data.matchedSignals.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
        </ul>
      </div>
    </div>`;

    const toggleBtn = document.getElementById(signalsId + 'Btn');
    const signalList = document.getElementById(signalsId);
    toggleBtn.addEventListener('click', () => {
      const expanded = signalList.classList.toggle('expanded');
      toggleBtn.innerHTML = (expanded ? '&#9662;' : '&#9656;') + ` Matched signals (${data.matchedSignals.length})`;
    });
  });

  on('analysis:screenshot', async (data) => {
    setOverviewState('screenshot', data);
    const section = document.getElementById('dashScreenshot');
    const body = document.getElementById('dashScreenshotBody');

    if (overviewScreenshotUrl) {
      URL.revokeObjectURL(overviewScreenshotUrl);
      overviewScreenshotUrl = null;
    }
    if (!data || !data.node) {
      section.classList.add('hidden');
      body.innerHTML = '';
      return;
    }

    try {
      const content = await loadFileContent(data.node);
      if (!content) return;

      const ext = data.node.name.split('.').pop().toLowerCase();
      const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', bmp: 'image/bmp', gif: 'image/gif', webp: 'image/webp' };
      const mime = mimeMap[ext] || 'image/png';
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      overviewScreenshotUrl = url;

      const subtitle = data.entries && data.entries.length > 1
        ? `<div class="dash-section-subtitle">${data.entries.length} screenshots detected</div>`
        : '';
      body.innerHTML = `${subtitle}<img class="dash-screenshot-img dash-screenshot-clickable" src="${url}" alt="Screenshot from log (click to enlarge)">`;
      section.classList.remove('hidden');

      const img = body.querySelector('.dash-screenshot-img');
      img.addEventListener('click', () => {
        const lightbox = document.createElement('div');
        lightbox.className = 'screenshot-lightbox';
        lightbox.innerHTML = `<img src="${url}" alt="Screenshot enlarged">`;
        lightbox.addEventListener('click', () => lightbox.remove());
        document.body.appendChild(lightbox);
      });
    } catch {
      // skip if screenshot fails to load
    }
  });

  on('analysis:domainDetect', (data) => {
    setOverviewState('domainDetect', data);
    const section = document.getElementById('dashDomainDetect');
    const body = document.getElementById('dashDomainDetectBody');
    if (!section || !body) return;

    if (!data || !data.totalHits) {
      section.classList.add('hidden');
      body.innerHTML = '';
      return;
    }

    section.classList.remove('hidden');
    let html = data.synthesized
      ? '<div class="dash-section-subtitle">Synthesised from credential and cookie hosts (no domain-detect file present).</div>'
      : '';
    for (const [label, entries] of Object.entries(data.categories)) {
      const domains = entries.map((e) => {
        const tag = e.label && e.label.toLowerCase() !== String(label).toLowerCase()
          ? ` <span class="dash-domain-tag">${escapeHtml(e.label)}</span>`
          : '';
        return `${escapeHtml(e.domain)} (${e.count})${tag}`;
      }).join(', ');
      html += `<div class="dash-kv-row">
      <span class="dash-kv-key">${escapeHtml(label)}</span>
      <span class="dash-kv-value">${domains}</span>
    </div>`;
    }
    body.innerHTML = html;
  });

  on('analysis:creditCards', (data) => {
    setOverviewState('creditCards', data);
  });

  on('analysis:accountTokens', (data) => {
    setOverviewState('accountTokens', data);
  });

  on('analysis:serviceArtifacts', (data) => {
    setOverviewState('serviceArtifacts', data);
  });

  on('analysis:wallets', (data) => {
    setOverviewState('wallets', data);
  });

  on('analysis:notes', (data) => {
    setOverviewState('notes', data);
  });

  on('analysis:grabbedFiles', (data) => {
    setOverviewState('grabbedFiles', data);
  });

  on('analysis:identity', (data) => setOverviewState('identity', data));

  on('analysis:readErrors', (data) => setOverviewState('readErrors', data));
}
