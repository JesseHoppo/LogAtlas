// Dashboard/overview rendering and analysis event handling.

import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { copyToClipboard, parseTimestampValue, parseArchiveTimestamp } from '../core/shared.js';
import { CAPTURE_TIME_KEYS } from '../core/definitions/patterns.js';
import { escapeHtml, escapeAttr } from '../core/utils.js';
import { formatDateTimeLabel } from '../pages/shared.js';
let sysInfoSourcePath = null;
let overviewScreenshotUrl = null;
let sysinfoIocs = [];
let clipboardIocs = [];

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

function inferDeviceType(sysinfo, computerName = '') {
  const explicit = findSysinfoValue(sysinfo, [/^laptop$/i, /^device type$/i, /^form factor$/i, /^chassis$/i]);
  if (/^(true|yes|1)$/i.test(explicit) || /laptop|notebook|portable/i.test(explicit)) return 'laptop';
  if (/^(false|no|0)$/i.test(explicit) || /desktop|workstation/i.test(explicit)) return 'desktop';
  if (/^laptop[-_]/i.test(computerName) || /^notebook[-_]/i.test(computerName)) return 'laptop';
  if (/^desktop[-_]/i.test(computerName)) return 'desktop';
  return '';
}

function topValuesText(items, limit = 3) {
  return joinNaturalList((items || []).slice(0, limit).map(item => item.value));
}

function buildCaseBriefing({
  exfilInfo,
  totalFiles,
  computer,
  os,
  deviceType,
  user,
  credentials,
  cookies,
  history,
  tokens,
  wallets,
  cards,
  grabbed,
  notes,
  screenshot,
}) {
  const introParts = [];
  if (exfilInfo?.date) {
    introParts.push(`Likely exfil around ${formatDateTimeLabel(exfilInfo.date)}`);
  } else {
    introParts.push('This case appears to be a single victim log');
  }

  const deviceDescriptor = [os, deviceType].filter(Boolean).join(' ');
  let deviceText = '';
  if (computer && deviceDescriptor) deviceText = `${computer}, a ${deviceDescriptor}`;
  else if (computer) deviceText = computer;
  else if (deviceDescriptor) deviceText = `a ${deviceDescriptor}`;

  if (deviceText) introParts[introParts.length - 1] += ` from ${deviceText}`;
  if (user) introParts[introParts.length - 1] += ` used by ${user}`;

  const scopeParts = [];
  if (totalFiles > 0) scopeParts.push(pluralise(totalFiles, 'file'));
  if (credentials?.uniqueCredentials > 0) scopeParts.push(pluralise(credentials.uniqueCredentials, 'unique credential'));
  if (cookies?.validSessionTokens > 0) scopeParts.push(pluralise(cookies.validSessionTokens, 'valid browser session'));
  if (history?.totalEntries > 0) scopeParts.push(pluralise(history.totalEntries, 'history entry', 'history entries'));
  if (tokens?.totalEntries > 0) scopeParts.push(pluralise(tokens.totalEntries, 'token entry', 'token entries'));
  if (wallets?.totalEntries > 0) scopeParts.push(pluralise(wallets.totalEntries, 'wallet/store artifact'));
  if (cards?.totalCards > 0) scopeParts.push(pluralise(cards.totalCards, 'card entry', 'card entries'));
  if (grabbed?.fileCount > 0) scopeParts.push(pluralise(grabbed.fileCount, 'grabbed file'));
  else if (notes?.totalNotes > 0) scopeParts.push(pluralise(notes.totalNotes, 'note file'));
  else if (screenshot?.entries?.length > 0) scopeParts.push(pluralise(screenshot.entries.length, 'screenshot'));

  const scopeText = joinNaturalList(scopeParts.slice(0, 5));
  return scopeText ? `${introParts.join('')}. It contains ${scopeText}.` : `${introParts.join('')}.`;
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
      return `<div class="dash-ioc-item">
        <span class="dash-ioc-label">${escapeHtml(ioc.label)}</span>${family}
        <span class="dash-ioc-value">${escapeHtml(ioc.value)}</span>
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

function renderTriageOverview() {
  const summarySection = document.getElementById('dashTriageSummary');
  const summaryBody = document.getElementById('dashTriageSummaryBody');
  const riskSection = document.getElementById('dashRiskSignals');
  const riskBody = document.getElementById('dashRiskSignalsBody');

  const sysinfo = overviewState.sysinfo;
  const fingerprint = overviewState.fingerprint;
  const credentials = overviewState.credentials;
  const cookies = overviewState.cookies;
  const history = overviewState.history;
  const tokens = overviewState.accountTokens;
  const wallets = overviewState.wallets;
  const cards = overviewState.creditCards;
  const notes = overviewState.notes;
  const grabbed = overviewState.grabbedFiles;
  const downloads = overviewState.downloads;
  const services = overviewState.serviceArtifacts;
  const domainDetect = overviewState.domainDetect;
  const screenshot = overviewState.screenshot;

  const summaryItems = [];
  const osUser = findSysinfoValue(sysinfo, [/^user\s*name$/i, /^username$/i, /^os user$/i]);
  const computer = findSysinfoValue(sysinfo, [/^computer\s*name$/i, /^pc\s*name$/i, /^machine\s*name$/i]);
  const country = findSysinfoValue(sysinfo, [/^country$/i, /^location$/i, /^region$/i]);
  const os = findSysinfoValue(sysinfo, [/^os$/i, /^operating system$/i, /^system$/i]);
  const deviceType = inferDeviceType(sysinfo, computer);
  const totalFiles = state.flatFiles.filter(file => file.type === 'file').length;
  const exfilInfo = inferLikelyExfilDate(sysinfo);

  if (fingerprint) summaryItems.push({ label: 'Family', value: fingerprint.family });
  if (computer) summaryItems.push({ label: 'Host', value: computer });
  if (osUser) summaryItems.push({ label: 'User', value: osUser });
  if (country) summaryItems.push({ label: 'Location', value: country });
  if (credentials?.uniqueCredentials > 0) summaryItems.push({ label: 'Credentials', value: credentials.uniqueCredentials.toLocaleString() });
  if (credentials?.failedFiles?.length > 0) summaryItems.push({ label: 'Skipped Password Files', value: credentials.failedFiles.length.toLocaleString() });
  if (cookies?.validSessionTokens > 0) summaryItems.push({ label: 'Active Sessions', value: cookies.validSessionTokens.toLocaleString() });
  if (history?.totalEntries > 0) summaryItems.push({ label: 'History', value: history.totalEntries.toLocaleString() });
  if (tokens?.totalEntries > 0) summaryItems.push({ label: 'Tokens', value: tokens.totalEntries.toLocaleString() });
  if (wallets?.totalEntries > 0) summaryItems.push({ label: 'Wallet Stores', value: wallets.totalEntries.toLocaleString() });
  if (cards?.totalCards > 0) summaryItems.push({ label: 'Cards', value: cards.totalCards.toLocaleString() });
  if (notes?.totalNotes > 0) summaryItems.push({ label: 'Notes', value: notes.totalNotes.toLocaleString() });
  if (grabbed?.fileCount > 0) summaryItems.push({ label: 'Grabbed Files', value: grabbed.fileCount.toLocaleString() });
  if (downloads?.totalDownloads > 0) summaryItems.push({ label: 'Downloads', value: downloads.totalDownloads.toLocaleString() });
  if (screenshot?.entries?.length > 0) summaryItems.push({ label: 'Screenshot', value: screenshot.entries.length.toLocaleString() });

  if (summaryItems.length > 0) {
    summarySection.classList.remove('hidden');
    summaryBody.innerHTML = summaryItems.map(item => `
      <div class="dash-triage-item">
        <div class="dash-triage-value">${escapeHtml(item.value)}</div>
        <div class="dash-triage-label">${escapeHtml(item.label)}</div>
      </div>
    `).join('');
  } else {
    summarySection.classList.add('hidden');
    summaryBody.innerHTML = '';
  }

  const riskItems = [];
  const briefing = buildCaseBriefing({
    exfilInfo,
    totalFiles,
    computer,
    os,
    deviceType,
    user: osUser,
    credentials,
    cookies,
    history,
    tokens,
    wallets,
    cards,
    grabbed,
    notes,
    screenshot,
  });
  if (briefing) {
    riskItems.push({ text: briefing, variant: 'brief' });
  }

  if (fingerprint) {
    const confidenceLabel = fingerprint.confidence.charAt(0).toUpperCase() + fingerprint.confidence.slice(1);
    riskItems.push(`File layout and markers most closely match ${fingerprint.family} (${confidenceLabel} confidence).`);
  }
  if (credentials?.uniqueCredentials > 0) {
    const domainText = topValuesText(credentials.topDomains);
    riskItems.push(
      domainText
        ? `${pluralise(credentials.uniqueCredentials, 'unique credential')} recovered, with the heaviest credential volume tied to ${domainText}.`
        : `${pluralise(credentials.uniqueCredentials, 'unique credential')} recovered across the parsed credential files.`
    );
  }
  if (credentials?.failedFiles?.length > 0) {
    riskItems.push(`${pluralise(credentials.failedFiles.length, 'password file')} could not be parsed cleanly and may require manual review.`);
  }
  if (cookies?.validSessionTokens > 0) {
    const domainText = topValuesText(cookies.topDomains);
    riskItems.push(
      domainText
        ? `${pluralise(cookies.validSessionTokens, 'valid browser session')} recovered, most heavily concentrated in cookies for ${domainText}.`
        : `${pluralise(cookies.validSessionTokens, 'valid browser session')} recovered from the cookie data.`
    );
  }
  if (history?.totalEntries > 0) {
    const domainText = topValuesText(history.topDomains);
    const latestVisit = history.mostRecent?.[0]?.lastVisit || '';
    const recentText = latestVisit ? ` Most recent parsed visit: ${latestVisit}.` : '';
    riskItems.push(
      domainText
        ? `${pluralise(history.totalEntries, 'history entry', 'history entries')} parsed across ${pluralise(history.uniqueDomains || 0, 'domain')}, with the most visited domains including ${domainText}.${recentText}`.trim()
        : `${pluralise(history.totalEntries, 'history entry', 'history entries')} parsed from browser history.${recentText}`.trim()
    );
  }
  if (tokens?.totalEntries > 0) {
    const servicesText = topValuesText(tokens.services);
    riskItems.push(`Account-token material is present${servicesText ? ` for ${servicesText}` : ''}${tokens.uniqueAccounts ? ` across ${pluralise(tokens.uniqueAccounts, 'account identifier')}` : ''}.`);
  }
  if (wallets?.totalEntries > 0) {
    const servicesText = topValuesText(wallets.services);
    const extra = [];
    if (wallets.withSeedHints > 0) extra.push(pluralise(wallets.withSeedHints, 'seed/recovery hit'));
    if (wallets.withTokenSignals > 0) extra.push(pluralise(wallets.withTokenSignals, 'token-bearing store'));
    riskItems.push(`${pluralise(wallets.totalEntries, 'wallet or raw-store artifact')} detected${servicesText ? ` for ${servicesText}` : ''}${extra.length ? `, including ${joinNaturalList(extra)}` : ''}.`);
  }
  if (cards?.totalCards > 0) {
    const parts = [];
    if (cards.withHolder > 0) parts.push(pluralise(cards.withHolder, 'named cardholder'));
    if (cards.withExpiry > 0) parts.push(pluralise(cards.withExpiry, 'expiry value'));
    if (cards.withCvc > 0) parts.push(pluralise(cards.withCvc, 'CVC value'));
    riskItems.push(`${pluralise(cards.totalCards, 'payment-card entry', 'payment-card entries')} recovered${parts.length ? `, with ${joinNaturalList(parts)}` : ''}.`);
  }
  if (notes?.credentialNotes > 0 || notes?.walletNotes > 0) {
    const notableNoteCount = notes.entries
      ? notes.entries.filter(entry => entry.credentialHints > 0 || entry.walletHints > 0).length
      : Math.max(notes.credentialNotes || 0, notes.walletNotes || 0);
    riskItems.push(`Notes contain credential or wallet language in ${pluralise(notableNoteCount, 'file')}.`);
  } else if (notes?.totalNotes > 0) {
    riskItems.push(`${pluralise(notes.totalNotes, 'note file')} may contain victim context, account notes, or operator comments.`);
  }
  if (grabbed?.fileCount > 0) {
    riskItems.push(`${pluralise(grabbed.fileCount, 'grabbed file')} recovered from FileGrabber / Important Files.`);
  }
  if (services?.totalEntries > 0) {
    const servicesText = topValuesText(services.services);
    riskItems.push(`Service configuration artifacts present${servicesText ? ` for ${servicesText}` : ''}.`);
  }
  if (downloads?.totalDownloads > 0) {
    const domainText = topValuesText(downloads.topDomains);
    riskItems.push(
      domainText
        ? `${pluralise(downloads.totalDownloads, 'download entry', 'download entries')} logged, with the most common source domains including ${domainText}.`
        : `${pluralise(downloads.totalDownloads, 'download entry', 'download entries')} logged in the recovered history.`
    );
  }
  if (domainDetect?.totalHits > 0) {
    const categoryCount = Object.keys(domainDetect.categories || {}).length;
    riskItems.push(`${pluralise(domainDetect.totalHits, 'domain-detection hit')} recorded across ${pluralise(categoryCount, 'category')}.`);
  }
  if (screenshot?.entries?.length > 0) {
    riskItems.push(`${pluralise(screenshot.entries.length, 'desktop screenshot')} captured during collection.`);
  }

  if (riskItems.length > 0) {
    riskSection.classList.remove('hidden');
    renderSimpleList(riskBody, riskItems);
  } else {
    riskSection.classList.add('hidden');
    riskBody.innerHTML = '';
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
  const dashAutofill = document.getElementById('dashAutofillIntel');
  const noData = document.getElementById('overviewNoData');

  dashCred.classList.toggle('hidden', credFiles.length === 0);
  dashCookie.classList.toggle('hidden', cookieFiles.length === 0);
  dashAutofill.classList.toggle('hidden', autofillFiles.length === 0);

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
    } else {
      summaryEl.textContent = skipped > 0
        ? `No structured credential data could be parsed; ${skipped.toLocaleString()} file(s) were skipped.`
        : 'No structured credential data could be parsed.';
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

    // Show sysinfo actions toolbar
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
    for (const entry of data?.entries || []) {
      if (entry.urls.length > 0) {
        for (const url of entry.urls) {
          clipboardIocs.push({ label: 'Clipboard URL', value: url });
        }
      } else if (entry.text.length <= 500) {
        clipboardIocs.push({ label: 'Clipboard', value: entry.text });
      }
    }
    renderDashboardIocs();
  });

  on('analysis:autofill', (data) => {
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

    let html = '<div class="dash-autofill-categories">';

    if (data.emails.length > 0) {
      html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Emails</div>
      ${data.emails.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
    }
    if (data.phones.length > 0) {
      html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Phone Numbers</div>
      ${data.phones.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
    }
    if (data.names.length > 0) {
      html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Names</div>
      ${data.names.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
    }
    if (data.addresses.length > 0) {
      html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Addresses</div>
      ${data.addresses.map(v => `<div class="dash-autofill-entry">${escapeHtml(v)}</div>`).join('')}
    </div>`;
    }
    if (data.other.length > 0) {
      html += `<div class="dash-autofill-cat">
      <div class="dash-autofill-cat-title">Other</div>
      ${data.other.map(e => `<div class="dash-autofill-entry"><span class="dash-autofill-field">${escapeHtml(e.name)}:</span> ${escapeHtml(e.value)}</div>`).join('')}
    </div>`;
    }

    html += '</div>';
    body.innerHTML = html;
  });

  on('analysis:downloads', (data) => {
    setOverviewState('downloads', data);
    const section = document.getElementById('dashDownloadIntel');
    const summaryEl = document.getElementById('dashDownloadSummary');
    const body = document.getElementById('dashDownloadBody');

    if (!data || data.totalDownloads === 0) {
      section.classList.add('hidden');
      body.innerHTML = '';
      summaryEl.textContent = 'Analyzing download files...';
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

    const confidenceLabel = data.confidence.charAt(0).toUpperCase() + data.confidence.slice(1) + ' confidence';
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
    let html = '';
    for (const [label, entries] of Object.entries(data.categories)) {
      const domains = entries.map(e => `${escapeHtml(e.domain)} (${e.count})`).join(', ');
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
}
