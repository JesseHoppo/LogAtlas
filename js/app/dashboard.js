// Dashboard/overview rendering and analysis event handling.

import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { copyToClipboard, extractCountryFromFilename, isValidCountryCode, classifyIpAddress } from '../core/shared.js';
import { escapeHtml, capitalise } from '../core/utils.js';
import { getCategoryLabel } from '../core/domainCategories.js';
import { captureProvenance, countLabel, formatInstantLabel } from '../pages/shared.js';
import { openScreenshotLightbox } from '../pages/activity.js';
let sysInfoSourcePath = null;
let overviewScreenshotUrl = null;
let screenshotGeneration = 0;
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
  capture: null,
};

function setOverviewState(key, value) {
  overviewState[key] = value || null;
  renderTriageOverview();
}

// Rows with no captured password are tallied separately, so "nothing parsed"
// only holds when all three credential tallies are zero.
function parsedCredentialRows(credentials) {
  return (credentials?.uniqueCredentials || 0)
    + (credentials?.accountsWithoutPasswords || 0)
    + (credentials?.urlsWithoutCredentials || 0);
}

function joinNaturalList(values, conjunction = 'and') {
  const items = (values || []).filter(Boolean);
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, ${conjunction} ${items[items.length - 1]}`;
}

function findSysinfoValue(data, patterns) {
  if (!data || !data.entries) return '';
  for (const [key, value] of Object.entries(data.entries)) {
    if (patterns.some(pattern => pattern.test(key)) && value) return value;
  }
  return '';
}

// Resolution order for the victim's country: a sysinfo key holding a country
// code, then an autofill country *field*, then whatever sysinfo said even if
// it is a full country name, then the market's prefix on the archive name.
// Exported so no other surface has to re-derive it and disagree.
export function deriveVictimCountry(sysinfo, autofill) {
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
  // Only a sysinfo capture key is evidence of when the log was taken; the rest
  // are inference, so the chip always names which.
  if (exfilInfo?.date) {
    push('captured', `${formatInstantLabel(exfilInfo.date)} (${captureProvenance(exfilInfo)})`);
  }
  if (state.rootZipName) push('source', state.rootZipName);
  if (items.length === 0) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  el.classList.remove('hidden');
  el.innerHTML = items.join('');
}

// `targets` is a priority list: the click handler takes the first page that is
// actually available, so a card never offers a dead link.
// A card carries either one headline number or a row of counted chips; a card
// whose strands are incommensurable has no honest single total.
function buildVerdictCard({ label, value, chips, note, targets }) {
  const nav = (targets || []).filter(Boolean).join(' ');
  const link = nav ? `<button class="verdict-card-link" data-nav="${escapeHtml(nav)}">View &rarr;</button>` : '';
  const head = chips
    ? `<div class="dash-chip-row">${chips.map((chip) => `<span class="dash-chip">${escapeHtml(chip)}</span>`).join('')}</div>`
    : `<div class="verdict-card-value">${escapeHtml(value)}</div>`;
  return `<div class="verdict-card">
    <div class="verdict-card-label">${escapeHtml(label)}</div>
    ${head}
    <div class="verdict-card-note">${escapeHtml(note)}</div>
    ${link}
  </div>`;
}

// The headline number and the card's link have to come from the same metric,
// or the card counts one thing and drills into another.
function pickHeadline(candidates) {
  for (const [count, target] of candidates) {
    if (count > 0) return { value: count, target };
  }
  return { value: 0, target: null };
}

// Rows with no captured password are reported wherever credentials are
// summarised, so the Overview and the generated report never disagree about
// the same case.
function noPasswordBits(credentials) {
  const bits = [];
  if (credentials?.accountsWithoutPasswords > 0) {
    bits.push(countLabel(credentials.accountsWithoutPasswords, 'account with a username only', 'accounts with a username only'));
  }
  if (credentials?.urlsWithoutCredentials > 0) {
    bits.push(countLabel(credentials.urlsWithoutCredentials, 'saved site'));
  }
  return bits;
}

function gapLabel(minutes) {
  if (minutes < 120) return countLabel(minutes, 'minute');
  const hours = minutes / 60;
  if (hours < 48) return countLabel(Math.round(hours), 'hour');
  return countLabel(Math.round(hours / 24), 'day');
}

// A log cannot predate its own newest browsing event. Where it appears to, either
// the capture stamp is wrong or the log was edited after collection, and every
// currentness judgement in the case rests on that stamp. Analysis only reports
// the gap once it has resolved the frame the visit times were written in — two
// clocks in unknown frames disagreeing says nothing about either.
function captureBeforeHistory(capture) {
  const minutes = capture?.historyAheadMinutes;
  if (!minutes || !capture.date || !capture.historyLatestIso) return null;
  const latest = new Date(capture.historyLatestIso);
  if (isNaN(latest.getTime())) return null;
  return {
    text: `Newest browsing event is ${gapLabel(minutes)} after the capture stamp `
      + `(${formatInstantLabel(latest)} against ${formatInstantLabel(capture.date)}) — the capture date is wrong, or the log was altered after collection.`,
    variant: 'warn',
  };
}

// The four questions an IR responder asks first: what is still live, how wide
// is the credential blast radius, what money/identity is exposed, what did the
// operator capture. Each card links straight to the detail.
function renderVerdictCards({ credentials, cookies, cards, history, grabbed, screenshot, autofill, nationalIds }) {
  const el = document.getElementById('dashVerdictCards');
  if (!el) return;
  const out = [];

  if (cookies?.totalCookies > 0) {
    const tokens = cookies.sessionTokens || 0;
    const live = cookies.validSessionTokens || 0;
    // Zero live tokens out of zero recognised tokens is not a clean negative;
    // it means nothing in the cookie set was identified as a session token.
    let note = 'No cookie was recognised as a session token; check the cookie set manually.';
    if (live > 0) note = 'Unexpired or no-expiry session tokens.';
    else if (tokens > 0) note = `${countLabel(tokens, 'session token')} recognised, none live at capture.`;
    out.push(buildVerdictCard({
      label: 'Live sessions',
      value: live.toLocaleString(),
      note,
      targets: ['cookies'],
    }));
  }

  const accountsOnly = credentials?.accountsWithoutPasswords || 0;
  const savedSites = credentials?.urlsWithoutCredentials || 0;
  const topDomain = credentials?.topDomains?.[0]?.value;
  const heaviest = topDomain ? `, heaviest on ${topDomain}` : '';
  if (credentials?.uniqueCredentials > 0) {
    const alsoWithout = noPasswordBits(credentials);
    const plus = alsoWithout.length > 0 ? `; plus ${joinNaturalList(alsoWithout)}` : '';
    out.push(buildVerdictCard({
      label: 'Credentials',
      value: credentials.uniqueCredentials.toLocaleString(),
      note: `Unique by domain, username and password${heaviest}${plus}.`,
      targets: ['currentnesslab', 'passwords'],
    }));
  } else if (accountsOnly > 0) {
    const plus = savedSites > 0 ? `; plus ${countLabel(savedSites, 'saved site')}` : '';
    out.push(buildVerdictCard({
      label: 'Accounts',
      value: accountsOnly.toLocaleString(),
      note: `Site and username only, no passwords${heaviest}${plus}.`,
      targets: ['passwords'],
    }));
  } else if (savedSites > 0) {
    // A URL-only row carries no username, so nothing feeds the domain ranking
    // and there is no heaviest domain to name.
    out.push(buildVerdictCard({
      label: 'Saved sites',
      value: savedSites.toLocaleString(),
      note: 'Sites only, no username or password stored.',
      targets: ['passwords'],
    }));
  }

  const finBits = [];
  if (cards?.totalCards > 0) {
    const cvc = cards.withCvc > 0
      ? (cards.withCvc === cards.totalCards ? ' with CVC' : ` (${cards.withCvc.toLocaleString()} with CVC)`)
      : '';
    finBits.push(countLabel(cards.totalCards, 'stored card') + cvc);
  }
  const idTotal = (nationalIds || []).reduce((sum, n) => sum + n.count, 0);
  if (idTotal > 0) finBits.push(countLabel(idTotal, 'government ID field'));
  // Distinct field/value pairs, so this sits in the same unit as the deduped
  // credential and session-token counts on the cards either side of it.
  const autofillRecords = autofill?.uniqueEntries ?? autofill?.totalEntries ?? 0;
  if (autofillRecords > 0) finBits.push(countLabel(autofillRecords, 'distinct autofill entry', 'distinct autofill entries'));
  if (finBits.length > 0) {
    // Cards, identifiers and autofill PII do not add up to anything, so each is
    // shown on its own. The link still follows what is most actionable, and
    // government IDs are matched in credential usernames, so that count is read
    // on the Passwords page.
    const headline = pickHeadline([
      [cards?.totalCards, 'cards'],
      [idTotal, 'passwords'],
      [autofillRecords, 'autofills'],
    ]);
    const NOTE_BY_TARGET = {
      cards: 'Card details on the Cards page.',
      passwords: 'Identifiers matched in credential usernames.',
      autofills: 'PII captured from saved browser form data.',
    };
    out.push(buildVerdictCard({
      label: 'Financial & identity',
      chips: finBits,
      note: NOTE_BY_TARGET[headline.target] || '',
      targets: [headline.target],
    }));
  }

  const capBits = [];
  if (screenshot?.entries?.length > 0) capBits.push(countLabel(screenshot.entries.length, 'desktop screenshot'));
  if (grabbed?.fileCount > 0) capBits.push(countLabel(grabbed.fileCount, 'grabbed file'));
  if (history?.totalEntries > 0) capBits.push(countLabel(history.totalEntries, 'history entry', 'history entries'));
  if (capBits.length > 0) {
    const headline = pickHeadline([
      [history?.totalEntries, 'history'],
      [grabbed?.fileCount, 'grabbed'],
      [screenshot?.entries?.length, 'screenshots'],
    ]);
    out.push(buildVerdictCard({
      label: 'Capture evidence',
      value: headline.value.toLocaleString(),
      note: `${joinNaturalList(capBits)}.`,
      targets: [headline.target],
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
    const aria = `role="meter" aria-valuenow="${item.count}" aria-valuemin="0" aria-valuemax="${maxCount}" aria-label="${escapeHtml(item.value)}: ${item.count.toLocaleString()}"`;
    return `<div class="dash-bar-row" ${aria}>
      <div class="dash-bar-fill" style="width:${pct}%"></div>
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count.toLocaleString()}</span>
    </div>`;
  }).join('');
}

// Every bucket a cookie can land in. All four are drawn, so the segments of a
// row sum to the count printed beside it. "Session" is a live state too, hence
// the qualifier — it reads as the opposite of "Valid" otherwise.
const COOKIE_BUCKETS = [
  ['valid', 'Valid'],
  ['expired', 'Expired'],
  ['session', 'Session (no expiry)'],
  ['unknown', 'Unparseable expiry'],
];

function renderCookieBarList(container, items, maxItems = 10) {
  if (items.length === 0) {
    container.innerHTML = '<div class="dash-bar-empty">None found</div>';
    return;
  }
  const top = items.slice(0, maxItems);
  const maxCount = top[0].count;
  const present = COOKIE_BUCKETS.filter(([key]) => top.some((item) => (item[key] || 0) > 0));

  let html = `<div class="dash-bar-legend">${present.map(([key, label]) =>
    `<span class="dash-bar-legend-item"><span class="dash-bar-legend-swatch dash-bar-legend-${key}"></span>${label}</span>`
  ).join('')}</div>`;

  html += top.map(item => {
    let offset = 0;
    const fills = COOKIE_BUCKETS.map(([key]) => {
      const n = item[key] || 0;
      if (n <= 0) return '';
      const left = offset;
      const width = (n / maxCount) * 100;
      offset += width;
      return `<div class="dash-bar-fill dash-bar-fill-${key}" style="left:${left.toFixed(2)}%; width:${width.toFixed(2)}%"></div>`;
    }).join('');
    const breakdown = COOKIE_BUCKETS
      .filter(([key]) => (item[key] || 0) > 0)
      .map(([key, label]) => `${(item[key] || 0).toLocaleString()} ${label.toLowerCase()}`);
    const ariaLabel = `${item.value}: ${countLabel(item.count, 'cookie')}${breakdown.length > 0 ? ` — ${breakdown.join(', ')}` : ''}`;
    const aria = `role="meter" aria-valuenow="${item.count}" aria-valuemin="0" aria-valuemax="${maxCount}" aria-label="${escapeHtml(ariaLabel)}"`;
    return `<div class="dash-bar-row dash-bar-row-stacked" ${aria}>
      ${fills}
      <span class="dash-bar-label">${escapeHtml(item.value)}</span>
      <span class="dash-bar-count">${item.count.toLocaleString()}</span>
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
        ? `<span class="dash-ioc-badge" title="${escapeHtml(ipClass.label)}">synthetic / non-victim IP</span>`
        : '';
      return `<div class="dash-ioc-item">
        <span class="dash-ioc-label">${escapeHtml(ioc.label)}</span>${family}
        <span class="dash-ioc-value">${escapeHtml(ioc.value)}</span>${badge}
        <button class="dash-ioc-copy" title="Copy" data-copy="${escapeHtml(ioc.value)}">Copy</button>
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
      <button class="dash-ioc-copy" title="Copy" data-copy="${escapeHtml(lure.text)}">Copy</button>
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
  const notes = overviewState.notes;
  const readErrors = overviewState.readErrors;

  const osUser = findSysinfoValue(sysinfo, [/^user\s*name$/i, /^username$/i, /^os user$/i]);
  const pi = overviewState.identity?.primaryIdentity;
  const resolvedUser = osUser || (pi?.osUsername || '');
  const userSource = osUser ? 'sysinfo' : (pi?.userSource || null);
  const computer = findSysinfoValue(sysinfo, [/^computer\s*name$/i, /^pc\s*name$/i, /^machine\s*name$/i]);
  const countryInfo = deriveVictimCountry(sysinfo, autofill);
  const exfilInfo = overviewState.capture;

  renderCaseContext({ computer, resolvedUser, userSource, countryInfo, exfilInfo });
  renderVerdictCards({ credentials, cookies, cards, history, grabbed, screenshot, autofill, nationalIds: credentials?.nationalIds });

  // Assessment: genuine, actionable findings only, never a restatement of the
  // counts already carried by the verdict cards above.
  const riskItems = [];
  if (credentials?.onionCredentials > 0) {
    riskItems.push({
      text: `Tor hidden-service (.onion) credentials in ${countLabel(credentials.onionCredentials, 'domain')} — darknet-market or carding indicator.`,
      variant: 'warn',
    });
  }
  if (clipboardLures.length > 0) {
    riskItems.push({
      text: 'Clipboard lure or clipper (ClickFix / PowerShell / address-swap).',
      variant: 'warn',
    });
  }
  if (cards?.withCvc > 0) {
    riskItems.push({
      text: `${countLabel(cards.withCvc, 'payment card')} recovered with a CVC value; treat as full card compromise.`,
      variant: 'warn',
    });
  }
  if (credentials?.failedFiles?.length > 0) {
    riskItems.push(`${countLabel(credentials.failedFiles.length, 'password file')} could not be parsed cleanly; review manually.`);
  }
  if (readErrors?.failedFiles?.length > 0) {
    riskItems.push(`${countLabel(readErrors.failedFiles.length, 'file')} could not be read or decoded and were skipped.`);
  }

  if (riskItems.length > 0) {
    riskSection.classList.remove('hidden');
    renderSimpleList(riskBody, riskItems);
  } else {
    riskSection.classList.add('hidden');
    riskBody.innerHTML = '';
  }

  renderSeedBanner(wallets, notes);
  renderNationalIds(credentials);
  renderConsistencyChecks({ credentials, cookies, history, countryInfo, capture: exfilInfo });
}

// A recovery phrase is as good as the wallet whether it sits in the wallet
// store or in a text file the victim kept it in, so both sources raise the
// same banner and it names the ones that fired.
function renderSeedBanner(wallets, notes) {
  const banner = document.getElementById('dashSeedBanner');
  if (!banner) return;
  const stores = wallets?.withSeedHints || 0;
  const seedNotes = notes?.seedPhraseNotes || 0;
  if (stores === 0 && seedNotes === 0) {
    banner.classList.add('hidden');
    banner.textContent = '';
    return;
  }
  const bits = [];
  if (stores > 0) bits.push(countLabel(stores, 'wallet store'));
  if (seedNotes > 0) bits.push(countLabel(seedNotes, 'note'));
  banner.classList.remove('hidden');
  banner.textContent = `${joinNaturalList(bits)} with seed / recovery-phrase material — treat as full wallet compromise.`;
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
    return `${n.type}${where}: ${countLabel(n.count, 'field')}`;
  }));
}

const CCTLD_COUNTRY = {
  au: 'AU', nz: 'NZ', uk: 'GB', 'co.uk': 'GB', de: 'DE', fr: 'FR', es: 'ES', it: 'IT',
  nl: 'NL', se: 'SE', no: 'NO', fi: 'FI', dk: 'DK', pl: 'PL', pt: 'PT', ie: 'IE',
  br: 'BR', mx: 'MX', ar: 'AR', cl: 'CL', co: 'CO', ru: 'RU', ua: 'UA', tr: 'TR',
  in: 'IN', cn: 'CN', jp: 'JP', kr: 'KR', id: 'ID', th: 'TH', vn: 'VN', ph: 'PH',
  za: 'ZA', ng: 'NG', eg: 'EG', sa: 'SA', ae: 'AE', il: 'IL', ca: 'CA', us: 'US',
};

// Both domain lists have been rolled up to eTLD+1 before they get here, so the
// hosts to match on are the base domains, not the sign-in hostnames. google.com
// is deliberately absent: after the rollup it fires on every consumer account.
const CORPORATE_DOMAIN_RX = /(?:microsoftonline\.com|sharepoint\.com|atlassian\.net|onelogin\.com|okta\.com)$/i;

// One foreign domain in a ranked list of thirty is not a geolocation signal.
// A ccTLD only leads if it clears a floor, holds most of the ccTLD-bearing
// domains, and takes a visible share of the whole ranked set.
const CCTLD_MIN_DOMAINS = 3;
const CCTLD_MIN_SHARE = 0.4;
const CCTLD_MIN_RANKED_SHARE = 0.15;

function leadingCcTld(domains) {
  const counts = {};
  let ranked = 0;
  for (const d of domains) {
    ranked++;
    const m = String(d || '').toLowerCase().match(/\.(co\.uk|[a-z]{2})$/);
    if (!m || !CCTLD_COUNTRY[m[1]]) continue;
    counts[m[1]] = (counts[m[1]] || 0) + 1;
  }

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (sorted.length === 0) return null;
  // A tie has no leader; object key order must not get to decide one.
  if (sorted.length > 1 && sorted[1][1] === sorted[0][1]) return null;

  const [tld, count] = sorted[0];
  const bearing = sorted.reduce((sum, [, n]) => sum + n, 0);
  if (count < CCTLD_MIN_DOMAINS) return null;
  if (count / bearing < CCTLD_MIN_SHARE) return null;
  if (count / ranked < CCTLD_MIN_RANKED_SHARE) return null;
  return { tld, count, ranked };
}

function renderConsistencyChecks({ credentials, cookies, history, countryInfo, capture }) {
  const section = document.getElementById('dashConsistency');
  const body = document.getElementById('dashConsistencyBody');
  if (!section || !body) return;

  const checks = [];
  const credDomains = (credentials?.topDomains || []).map(d => d.value);
  const histDomains = (history?.topDomains || []).map(d => d.value);

  // Leads: a capture instant that cannot be right undermines every other line.
  const captureConflict = captureBeforeHistory(capture);
  if (captureConflict) checks.push(captureConflict);

  if (cookies?.totalCookies > 0 && parsedCredentialRows(credentials) === 0) {
    checks.push({ text: 'Cookies recovered, no credentials parsed — credential files may be encrypted or missing.', variant: 'warn' });
  }

  // Matched per domain: another corporate host in the credential list says
  // nothing about the one that is missing from it.
  const credDomainSet = new Set(credDomains.map(d => String(d).toLowerCase()));
  const corpInHistory = histDomains.find(d => CORPORATE_DOMAIN_RX.test(d) && !credDomainSet.has(String(d).toLowerCase()));
  if (corpInHistory) {
    checks.push({ text: `Corporate SSO domain ${corpInHistory} appears in browsing history but not in recovered credentials.`, variant: 'warn' });
  }

  const lead = leadingCcTld([...credDomains, ...histDomains]);
  const victimCode = String(countryInfo?.value || '').trim().toUpperCase();
  if (lead && victimCode.length === 2) {
    const tldCountry = CCTLD_COUNTRY[lead.tld];
    if (tldCountry && tldCountry !== victimCode) {
      checks.push({ text: `${lead.count.toLocaleString()} of ${lead.ranked.toLocaleString()} top browsing/credential domains are .${lead.tld} (${tldCountry}) while victim location resolves to ${victimCode}; verify geolocation.`, variant: 'warn' });
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

// Each fingerprint render needs its own element ids; a counter is enough and
// keeps a wall-clock reading out of the markup.
let fingerprintRenderCount = 0;

// The Overview names only the categories where a single account changes what the
// response has to cover, in the order they change it. The consumer bulk — social,
// search, the merely known — is what Domain explorer is for.
const NOTABLE_DETECTION_LABELS = ['gov', 'military', 'bank', 'finance', 'rmm', 'ddns', 'gambling', 'edu']
  .map(getCategoryLabel);

const DOMAIN_DETECT_CATEGORIES = 4;
const DOMAIN_DETECT_PER_CATEGORY = 5;

const COUNTED_HINTS = [
  '_passwordFileHint',
  '_cookieFileHint',
  '_autofillHint',
  '_notesHint',
  '_historyHint',
  '_bookmarkHint',
  '_browserMetadataHint',
  '_stealerDebugHint',
  '_sysInfoHint',
  '_creditCardHint',
  '_cryptoWalletHint',
  '_accountTokenHint',
  '_serviceArtifactHint',
  '_ftpCredentialHint',
  '_keylogHint',
  '_messengerHint',
  '_downloadHint',
  '_domainDetectHint',
  '_clipboardHint',
  '_grabbedFileHint',
  '_screenshotHint',
  '_browserPluginHint',
  '_softwareFileHint',
  '_processListHint',
];

// Extension/plugin files on their own aren't a recognised dataset; they are
// only listed under Other artifacts.
const RECOGNISED_HINTS = COUNTED_HINTS.filter((key) => key !== '_browserPluginHint');

const EXTRA_ARTIFACTS = [
  { hint: '_creditCardHint', icon: 'CC', noun: 'credit card file', warning: true },
  { hint: '_cryptoWalletHint', icon: 'W', noun: 'crypto wallet file' },
  { hint: '_accountTokenHint', icon: 'TK', noun: 'account token file', warning: true },
  { hint: '_serviceArtifactHint', icon: 'SV', noun: 'service artifact file' },
  { hint: '_ftpCredentialHint', icon: 'FTP', noun: 'FTP client credential file', warning: true },
  { hint: '_keylogHint', icon: 'KL', noun: 'keylog file', warning: true },
  { hint: '_messengerHint', icon: 'M', noun: 'unclassified service file' },
  { hint: '_downloadHint', icon: 'DL', noun: 'download history file' },
  { hint: '_clipboardHint', icon: 'CL', noun: 'clipboard file' },
  { hint: '_notesHint', icon: 'NT', noun: 'note file' },
  { hint: '_grabbedFileHint', icon: 'GF', noun: 'grabbed file', warning: true },
  { hint: '_bookmarkHint', icon: 'BM', noun: 'bookmark file' },
  { hint: '_browserMetadataHint', icon: 'MD', noun: 'browser metadata file' },
  { hint: '_stealerDebugHint', icon: 'DBG', noun: 'stealer debug trace file' },
  { hint: '_browserPluginHint', icon: 'EXT', noun: 'browser extension file' },
  { hint: '_softwareFileHint', icon: 'SW', noun: 'installed software file' },
  { hint: '_processListHint', icon: 'PS', noun: 'process list file' },
];

function countHintedFiles() {
  const counts = {};
  for (const key of COUNTED_HINTS) counts[key] = 0;
  for (const file of state.flatFiles) {
    for (const key of COUNTED_HINTS) {
      if (file[key]) counts[key]++;
    }
  }
  return counts;
}

function updateDashboardVisibility() {
  const counts = countHintedFiles();

  const dashCred = document.getElementById('dashCredIntel');
  const dashCookie = document.getElementById('dashCookieIntel');
  const noData = document.getElementById('overviewNoData');

  dashCred.classList.toggle('hidden', counts._passwordFileHint === 0);
  dashCookie.classList.toggle('hidden', counts._cookieFileHint === 0);
  noData.classList.toggle('hidden', RECOGNISED_HINTS.some((key) => counts[key] > 0));

  const extraEl = document.getElementById('dashExtraIntel');
  const extraBody = document.getElementById('dashExtraBody');
  const extras = EXTRA_ARTIFACTS.filter(({ hint }) => counts[hint] > 0);

  if (extras.length === 0) {
    extraEl.classList.add('hidden');
    extraBody.innerHTML = '';
    return;
  }

  extraEl.classList.remove('hidden');
  extraBody.innerHTML = `<div class="dash-extra-items">${extras.map(({ hint, icon, noun, warning }) =>
    `<div class="dash-extra-item${warning ? ' dash-extra-warning' : ''}"><span class="dash-extra-icon">${icon}</span><span>${countLabel(counts[hint], noun)}</span></div>`
  ).join('')}</div>`;
}

export function getSysInfoSourcePath() {
  return sysInfoSourcePath;
}

export function resetOverviewState() {
  sysInfoSourcePath = null;
  sysinfoIocs = [];
  clipboardIocs = [];
  clipboardLures = [];
  screenshotGeneration++;

  if (overviewScreenshotUrl) {
    URL.revokeObjectURL(overviewScreenshotUrl);
    overviewScreenshotUrl = null;
  }

  for (const key of Object.keys(overviewState)) {
    overviewState[key] = null;
  }
}

const OVERVIEW_SECTION_IDS = [
  'dashSeedBanner',
  'dashFingerprint',
  'dashCaseContext',
  'dashVerdictCards',
  'dashRiskSignals',
  'dashConsistency',
  'dashScreenshot',
  'dashStealerInfra',
  'dashClipboardLures',
  'dashIOCs',
  'dashNationalIds',
  'dashCredIntel',
  'dashLocalNetworkCol',
  'dashCookieIntel',
  'dashAutofillIntel',
  'dashDownloadIntel',
  'dashDomainDetect',
  'dashExtraIntel',
  'overviewNoData',
];

const OVERVIEW_BODY_IDS = [
  'dashSeedBanner',
  'dashFingerprintBody',
  'dashCaseContext',
  'dashVerdictCards',
  'dashRiskSignalsBody',
  'dashConsistencyBody',
  'dashScreenshotBody',
  'dashStealerInfraBody',
  'dashClipboardLuresBody',
  'dashIOCBody',
  'dashNationalIdsBody',
  'dashTopDomains',
  'dashTopUsernames',
  'dashLocalNetwork',
  'dashTopCookieDomains',
  'dashAutofillBody',
  'dashDownloadBody',
  'dashDomainDetectBody',
  'dashExtraBody',
];

const OVERVIEW_SUMMARIES = [
  { id: 'dashCredSummary', text: 'Analysing credential files...', loading: true },
  { id: 'dashCookieSummary', text: 'Analysing cookie files...', loading: true },
  { id: 'dashAutofillSummary', text: 'Analysing autofill files...', loading: true },
  { id: 'dashDownloadSummary', text: 'Analysing download files...' },
];

const SYSINFO_EMPTY_STATE = '<div class="no-data" id="sysInfoNoData">No system information files.</div>';

// Every element the overview writes into. A case with no parsed credentials or
// cookies takes branches that never repaint, so the previous victim's data has
// to be wiped rather than overwritten.
function clearOverview() {
  resetOverviewState();

  for (const id of OVERVIEW_SECTION_IDS) {
    document.getElementById(id)?.classList.add('hidden');
  }

  for (const id of OVERVIEW_BODY_IDS) {
    const element = document.getElementById(id);
    if (element) element.innerHTML = '';
  }

  for (const { id, text, loading } of OVERVIEW_SUMMARIES) {
    const element = document.getElementById(id);
    if (!element) continue;
    element.textContent = text;
    element.classList.toggle('dash-loading', Boolean(loading));
  }

  const sysInfoBody = document.getElementById('dashSysInfoBody');
  if (sysInfoBody) sysInfoBody.innerHTML = SYSINFO_EMPTY_STATE;
  document.getElementById('sysInfoActions')?.classList.add('hidden');

  document.getElementById('sysInfoOpenBtn')?.classList.add('hidden');

  const navSysInfo = document.getElementById('navSysInfo');
  if (navSysInfo) navSysInfo.disabled = true;
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
    for (const target of (link.dataset.nav || '').split(' ')) {
      const navItem = document.querySelector(`.sidebar-nav-item[data-page="${target}"]`);
      if (navItem && !navItem.disabled) {
        navItem.click();
        return;
      }
    }
  });

  on('loading', () => {
    loadingText.textContent = state.loadingText;
  });

  on('reset', clearOverview);
  on('reanalyze', clearOverview);

  on('analysis:credentials', (data) => {
    setOverviewState('credentials', data);
    const summaryEl = document.getElementById('dashCredSummary');
    summaryEl.classList.remove('dash-loading');
    const skipped = data.failedFiles?.length || 0;
    const skippedNote = skipped > 0 ? `; ${countLabel(skipped, 'file')} skipped` : '';
    const parsedRows = parsedCredentialRows(data);

    if (data.totalCredentials > 0) {
      // The dedupe key is the base domain, not the URL as saved, which is why
      // this count sits below the Passwords page's row count. Naming the key is
      // what keeps the two numbers from reading as a contradiction.
      let summary = `${countLabel(data.uniqueCredentials, 'credential')} from ${countLabel(data.fileCount, 'file')}, unique by domain, username and password`;
      const duplicates = data.totalCredentials - data.uniqueCredentials;
      if (duplicates > 0) {
        summary += `; ${countLabel(duplicates, 'duplicate row')} collapsed`;
      }
      const alsoWithout = noPasswordBits(data);
      if (alsoWithout.length > 0) summary += `; plus ${joinNaturalList(alsoWithout)}`;
      summaryEl.textContent = summary + skippedNote;
    } else if (parsedRows > 0) {
      summaryEl.textContent = `No passwords captured; ${joinNaturalList(noPasswordBits(data))} from ${countLabel(data.fileCount, 'file')}${skippedNote}`;
    } else {
      summaryEl.textContent = skipped > 0
        ? `No credentials parsed; ${countLabel(skipped, 'file')} skipped.`
        : 'No credentials parsed.';
    }

    if (parsedRows > 0) {
      renderBarList(document.getElementById('dashTopDomains'), data.topDomains);
      renderBarList(document.getElementById('dashTopUsernames'), data.topUsernames);
    }

    const localCol = document.getElementById('dashLocalNetworkCol');
    if (data.localNetwork?.length) {
      localCol.classList.remove('hidden');
      renderBarList(document.getElementById('dashLocalNetwork'), data.localNetwork);
    } else {
      localCol.classList.add('hidden');
      document.getElementById('dashLocalNetwork').innerHTML = '';
    }
  });

  on('analysis:cookies', (data) => {
    setOverviewState('cookies', data);
    const summaryEl = document.getElementById('dashCookieSummary');
    summaryEl.classList.remove('dash-loading');

    if (data.totalCookies > 0) {
      let summaryHtml = `${data.totalCookies.toLocaleString()} cookies across ${data.uniqueDomains.toLocaleString()} domains from ${countLabel(data.fileCount, 'file')} &mdash; <span class="cookie-valid">${data.totalValid.toLocaleString()} valid</span>, <span class="cookie-expired">${data.totalExpired.toLocaleString()} expired</span>`;
      if (data.totalSession > 0) {
        summaryHtml += `, <span class="cookie-session">${data.totalSession.toLocaleString()} session</span>`;
      }
      if (data.totalUnknown > 0) {
        summaryHtml += `, <span class="cookie-unknown">${data.totalUnknown.toLocaleString()} unparseable expiry</span>`;
      }
      if (data.totalNoDomain > 0) {
        summaryHtml += ` <span class="cookie-unknown">(${data.totalNoDomain.toLocaleString()} of these carried no domain)</span>`;
      }
      if (data.sessionTokens > 0) {
        summaryHtml += ` &mdash; <span class="cookie-auth">${data.sessionTokens.toLocaleString()} session token${data.sessionTokens !== 1 ? 's' : ''}</span>`;
        if (data.validSessionTokens > 0) {
          summaryHtml += ` (<span class="cookie-auth-valid">${data.validSessionTokens.toLocaleString()} live</span>)`;
        }
      }
      if (data.trackingTokens > 0) {
        summaryHtml += ` &mdash; <span class="cookie-session">${data.trackingTokens.toLocaleString()} ad-tracking token${data.trackingTokens !== 1 ? 's' : ''}</span>`;
      }
      summaryEl.innerHTML = summaryHtml;
      renderCookieBarList(document.getElementById('dashTopCookieDomains'), data.topDomains);
    } else {
      summaryEl.textContent = 'No cookies parsed.';
    }
  });

  on('analysis:history', (data) => {
    setOverviewState('history', data);
  });

  on('analysis:capture', (data) => {
    setOverviewState('capture', data);
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
      body.innerHTML = '<div class="no-data" id="sysInfoNoData">No system information files.</div>';
      actions.classList.add('hidden');
      openBtn.classList.add('hidden');
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
      openBtn.textContent = `View source: ${sysInfoSourcePath}`;
    } else {
      openBtn.classList.add('hidden');
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
    // Browsers repeat a field across profiles and sites, so the row count and the
    // distinct count are both worth stating — the verdict card carries the latter.
    const distinct = data.uniqueEntries ?? data.totalEntries;
    const distinctNote = distinct < data.totalEntries ? `, ${distinct.toLocaleString()} distinct` : '';
    summaryEl.textContent = `${countLabel(data.totalEntries, 'entry', 'entries')} from ${countLabel(data.fileCount, 'file')}${distinctNote}`;

    // Overview shows a counted summary and a few sample emails, not the whole
    // PII wall. The full parsed data lives on the Autofills page. `other` is a
    // display sample capped by the analysis; the chip has to carry the tally.
    const counts = [
      ['email', data.emails.length],
      ['phone', data.phones.length],
      ['name', data.names.length],
      ['address', data.addresses.length],
      ['other field', data.otherTotal ?? data.other.length],
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
    summaryEl.textContent = `${countLabel(data.totalDownloads, 'download entry', 'download entries')} from ${countLabel(data.fileCount, 'file')}`;
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
    const signalsId = 'fingerprintSignals_' + (++fingerprintRenderCount);
    const structureOnly = data.source === 'structure-only'
      ? `<span class="dash-fingerprint-source" title="No sysinfo file; family inferred from layout alone.">structure-only</span>`
      : '';
    // Who sold the log, kept apart from what stole it.
    const distributor = data.distributor
      ? `<span class="dash-fingerprint-source" title="Resale brand stamped on the log.">via ${escapeHtml(data.distributor)}</span>`
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
        ${distributor}
      </div>
      <div class="dash-fingerprint-signals">
        <button class="dash-fingerprint-toggle" id="${signalsId}Btn" aria-expanded="false" aria-controls="${signalsId}">&#9656; Matched signals (${data.matchedSignals.length.toLocaleString()})</button>
        <ul class="dash-fingerprint-list" id="${signalsId}">
          ${data.matchedSignals.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
        </ul>
      </div>
    </div>`;

    const toggleBtn = document.getElementById(signalsId + 'Btn');
    const signalList = document.getElementById(signalsId);
    toggleBtn.addEventListener('click', () => {
      const expanded = signalList.classList.toggle('expanded');
      toggleBtn.setAttribute('aria-expanded', String(expanded));
      toggleBtn.innerHTML = (expanded ? '&#9662;' : '&#9656;') + ` Matched signals (${data.matchedSignals.length.toLocaleString()})`;
    });
  });

  on('analysis:screenshot', async (data) => {
    setOverviewState('screenshot', data);
    const generation = ++screenshotGeneration;
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
      // A reset or a newer screenshot event landed while this one was decoding.
      if (!content || generation !== screenshotGeneration) return;

      const ext = data.node.name.split('.').pop().toLowerCase();
      const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', bmp: 'image/bmp', gif: 'image/gif', webp: 'image/webp' };
      const mime = mimeMap[ext] || 'image/png';
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      overviewScreenshotUrl = url;

      const subtitle = data.entries && data.entries.length > 1
        ? `<div class="dash-section-subtitle">${countLabel(data.entries.length, 'screenshot')}</div>`
        : '';
      body.innerHTML = `${subtitle}<button type="button" class="dash-screenshot-clickable" title="Enlarge screenshot"><img class="dash-screenshot-img" src="${url}" alt="Screenshot from log"></button>`;
      section.classList.remove('hidden');

      body.querySelector('.dash-screenshot-clickable')
        .addEventListener('click', () => openScreenshotLightbox(url, 'Screenshot from log'));
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

    // Re-listing every classified host made this a second, worse Domain
    // Explorer. What the Overview owes the analyst is the handful that change
    // the case, and a way through to the rest.
    const hosts = new Set();
    for (const entries of Object.values(data.categories)) {
      for (const entry of entries) hosts.add(entry.domain);
    }
    const notable = NOTABLE_DETECTION_LABELS
      .map((label) => [label, data.categories[label]])
      .filter(([, entries]) => entries?.length > 0)
      .slice(0, DOMAIN_DETECT_CATEGORIES);

    const source = data.synthesized
      ? `${countLabel(hosts.size, 'host')} classified from the credential and cookie sets`
      : `${countLabel(hosts.size, 'host')} on the detection list shipped with the log`;
    // A clean negative only means something if it names what was looked for,
    // and it is a statement about these hosts, not about the whole case.
    const scope = notable.length > 0
      ? 'notable categories only'
      : `none of them in ${joinNaturalList(NOTABLE_DETECTION_LABELS, 'or')}`;

    let html = `<div class="dash-section-subtitle">${escapeHtml(`${source} — ${scope}.`)}</div>`;
    for (const [label, entries] of notable) {
      // A detect file lists the same host once per section it was hit in, which
      // reads as a repeated row here. One host, its hits added up.
      const merged = new Map();
      for (const entry of entries) {
        const held = merged.get(entry.domain);
        if (held) held.count += entry.count;
        else merged.set(entry.domain, { ...entry });
      }
      const ranked = [...merged.values()].sort((a, b) => b.count - a.count);
      const shown = ranked.slice(0, DOMAIN_DETECT_PER_CATEGORY);
      const rest = ranked.length - shown.length;
      const domains = shown.map((e) => {
        const tag = e.label && e.label.toLowerCase() !== String(label).toLowerCase()
          ? ` <span class="dash-domain-tag">${escapeHtml(e.label)}</span>`
          : '';
        return `${escapeHtml(e.domain)} (${e.count.toLocaleString()})${tag}`;
      }).join(', ');
      const more = rest > 0 ? `<span class="dash-kv-more">+${rest.toLocaleString()}</span>` : '';
      html += `<div class="dash-kv-row">
      <span class="dash-kv-key">${escapeHtml(label)}</span>
      <span class="dash-kv-value">${domains}${more}</span>
    </div>`;
    }

    // A log that shipped its own detect file has a page holding it verbatim,
    // operator labels and all; a synthesised set only exists in the Explorer.
    html += data.synthesized
      ? '<button class="verdict-card-link" data-nav="domains">Every host in Domain explorer &rarr;</button>'
      : '<button class="verdict-card-link" data-nav="detections domains">The full detection list &rarr;</button>';
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
