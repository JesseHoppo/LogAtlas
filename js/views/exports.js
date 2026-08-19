// Exports

import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { escapeHtml, capitalise } from '../core/utils.js';
import {
  classifyAutofillEntries,
  credentialColumnIndices,
  downloadBlob,
  copyToClipboard,
  baseDomainFromUrl,
  extractDomain,
  randomPassword,
  showNotification as notify,
} from '../core/shared.js';
import {
  buildCsvText,
  downloadCsvRows,
  captureProvenance,
  countLabel,
  formatBytes,
  formatInstantLabel,
  getImageMimeFromName,
  maskValue,
  openTransientModal,
  shapeCookiesCsv,
  shapeNotesCsv,
} from '../pages/shared.js';
import {
  areCategoriesLoaded,
  classifySiteDomain,
  getCategoryLabel,
} from '../core/domainCategories.js';
import {
  getPasswordsData,
  getCookiesData,
  getAutofillsData,
  getNotesData,
} from '../pages/credentials.js';
import {
  getHistoryData,
  getBookmarksData,
  getBrowserMetadataData,
  shapeHistoryCsv,
} from '../pages/browser.js';
import {
  getAccountTokensData,
  getServiceArtifactsData,
  getWalletArtifactsData,
  getCreditCardsData,
} from '../pages/assets.js';
import {
  CSV_SPECS,
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getGrabbedFilesData,
  getScreenshotsData,
  getSoftwareData,
  getProcessesData,
} from '../pages/activity.js';
import { isLiveSessionToken } from '../analysis/sessionCookies.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';

// Stamped into every export so a handed-over report can be tied back to the
// build that wrote it. Calendar-versioned: the tool ships straight from the
// branch and has no release train to carry a semantic number.
const TOOL_NAME = 'Log Atlas';
const TOOL_VERSION = '2026.08';

let sysinfoEntries = null;
let sysinfoIocs = null;
let fingerprintResult = null;
let identityResult = null;
let credentialsAnalysis = null;
let cookiesAnalysis = null;
let capture = null;

function collectAllDatasets() {
  return {
    passwords: getPasswordsData(),
    cookies: getCookiesData(),
    autofills: getAutofillsData(),
    notes: getNotesData(),
    history: getHistoryData(),
    bookmarks: getBookmarksData(),
    browserMetadata: getBrowserMetadataData(),
    accountTokens: getAccountTokensData(),
    serviceArtifacts: getServiceArtifactsData(),
    wallets: getWalletArtifactsData(),
    downloads: getDownloadsData(),
    detections: getDomainDetectionsData(),
    clipboard: getClipboardData(),
    grabbedFiles: getGrabbedFilesData(),
    cards: getCreditCardsData(),
    screenshots: getScreenshotsData(),
    software: getSoftwareData(),
    processes: getProcessesData(),
  };
}

// Credentials and cookies are row-shaped, everything else entry-shaped; the
// package is worth writing if any one of them holds something.
function hasAnyDataset(datasets) {
  return Object.values(datasets).some((set) => (set?.rows?.length || set?.entries?.length || 0) > 0);
}

// Obfuscated Credentials CSV

function exportObfuscatedCredentials() {
  const data = getPasswordsData();
  if (!data || data.rows.length === 0) {
    notify('No credential data available to export.', 'error');
    return;
  }

  const { passIdx } = credentialColumnIndices(data.headers);

  // The page rows are already one row per site + username + password.
  downloadCsvRows('credentials_obfuscated.csv', data.headers, data.rows.map(({ row }) =>
    row.map((cell, index) => (index === passIdx ? maskValue(cell) : cell))
  ));
  notify(`Downloaded ${countLabel(data.rows.length, 'credential row')} (passwords masked).`);
}

// Log Summary Report (HTML)

// The report quotes the analysis pass, so its credential and cookie totals are
// the ones the overview shows. The page rows are the fallback for a case whose
// analysis never emitted, and they are labelled as rows, not as credentials.
function buildCredStats(passwords) {
  const analysed = credentialsAnalysis;
  if (analysed) {
    if (analysed.totalCredentials === 0 && analysed.accountsWithoutPasswords === 0 && analysed.urlsWithoutCredentials === 0) return null;
    return {
      unique: analysed.uniqueCredentials,
      parsed: analysed.totalCredentials,
      accountsWithoutPasswords: analysed.accountsWithoutPasswords,
      savedSites: analysed.urlsWithoutCredentials,
      fileCount: analysed.fileCount,
      unparsedFiles: analysed.failedFiles?.length || 0,
      topDomains: analysed.topDomains.map(({ value, count }) => [value, count]),
      localNetwork: analysed.localNetwork.map(({ value, count }) => [value, count]),
      onionDomains: analysed.onionCredentials,
    };
  }

  if (passwords.rows.length === 0) return null;
  const { urlIdx } = credentialColumnIndices(passwords.headers);
  const domainCounts = Object.create(null);
  for (const { row } of passwords.rows) {
    const domain = baseDomainFromUrl(urlIdx >= 0 ? (row[urlIdx] || '') : '');
    if (domain) domainCounts[domain] = (domainCounts[domain] || 0) + 1;
  }
  return {
    rows: passwords.rows.length,
    fileCount: passwords.fileCount,
    topDomains: Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
  };
}

function buildCookStats(cookies) {
  const analysed = cookiesAnalysis;
  if (analysed && analysed.totalCookies > 0) {
    return {
      total: analysed.totalCookies,
      valid: analysed.totalValid,
      expired: analysed.totalExpired,
      session: analysed.totalSession,
      unknown: analysed.totalUnknown,
      // Domain-less rows are already inside the four buckets; kept only so the
      // report can say how many carried no domain.
      noDomain: analysed.totalNoDomain || 0,
      sessionTokens: analysed.sessionTokens,
      liveSessionTokens: analysed.validSessionTokens,
      fileCount: analysed.fileCount,
      topDomains: analysed.topDomains.map(({ value, count }) => [value, count]),
    };
  }

  if (cookies.rows.length === 0) return null;
  const domainIdx = cookies.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
  const domainCounts = Object.create(null);
  let valid = 0, expired = 0, session = 0, unknown = 0, sessionTokens = 0, liveSessionTokens = 0;
  for (const rowData of cookies.rows) {
    const status = rowData.validity.status;
    if (status === 'valid') valid++;
    else if (status === 'expired') expired++;
    else if (status === 'session') session++;
    else unknown++;
    if (rowData.sessionType === 'auth' || rowData.sessionType === 'session') sessionTokens++;
    if (isLiveSessionToken(rowData)) liveSessionTokens++;
    const d = (domainIdx >= 0 ? (rowData.row[domainIdx] || '') : '').replace(/^\./, '').toLowerCase();
    if (d) domainCounts[d] = (domainCounts[d] || 0) + 1;
  }
  return {
    total: cookies.rows.length,
    valid, expired, session, unknown,
    noDomain: 0,
    sessionTokens, liveSessionTokens,
    fileCount: cookies.fileCount,
    topDomains: Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
  };
}

// A single autofill store can hold tens of thousands of values. The report is
// written to be printed, so it states every total and prints only the head of
// each list.
const REPORT_LIST_SAMPLE = 20;

function sampleList(values) {
  return { total: values.length, sample: values.slice(0, REPORT_LIST_SAMPLE) };
}

// The classifier labels every host it recognises, but most of those labels only
// say what kind of site it is. These six change what the responder does next:
// government and military identity, money, and the remote-access or dynamic-DNS
// infrastructure an operator pivots through. This order is the printed order.
const INTEREST_CATEGORIES = ['gov', 'military', 'bank', 'finance', 'rmm', 'ddns'];

// Every domain in these categories, not a ranked head: an evidence handoff that
// truncates the government and banking list is worse than no list.
function buildDomainsOfInterest(passwords, cookies) {
  // The reference lists are requested at startup and awaited by the analysis
  // pass, so this only bites if a report is somehow written before either.
  if (!areCategoriesLoaded()) return { unavailable: true, rows: [] };

  const rank = new Map(INTEREST_CATEGORIES.map((key, index) => [key, index]));
  const hits = new Map();
  const credDomains = new Set();
  const cookieDomains = new Set();

  const record = (host, field, seen) => {
    if (!host) return;
    const { base, primaryKey } = classifySiteDomain(host);
    if (!base) return;
    seen.add(base);
    if (!rank.has(primaryKey)) return;
    let hit = hits.get(base);
    if (!hit) {
      hit = { domain: base, key: primaryKey, accounts: 0, cookies: 0 };
      hits.set(base, hit);
    }
    hit[field]++;
  };

  const { urlIdx } = credentialColumnIndices(passwords.headers);
  if (urlIdx >= 0) {
    for (const { row } of passwords.rows) record(extractDomain(row[urlIdx] || ''), 'accounts', credDomains);
  }

  const domainIdx = cookies.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
  if (domainIdx >= 0) {
    for (const { row } of cookies.rows) record((row[domainIdx] || '').replace(/^\./, ''), 'cookies', cookieDomains);
  }

  if (hits.size === 0) return null;
  return {
    rows: [...hits.values()].sort((a, b) =>
      (rank.get(a.key) - rank.get(b.key)) || a.domain.localeCompare(b.domain)),
    credDomains: credDomains.size,
    cookieDomains: cookieDomains.size,
  };
}

// What the case was built from, for the provenance block. A dropped folder has
// no archive of its own, so the extracted tally stands in for the source size.
function describeSource() {
  const members = state.flatFiles.filter(file => file.type === 'file');
  const bytes = members.reduce((sum, file) => sum + (file.size || 0), 0);
  const extracted = `${countLabel(members.length, 'file')}, ${formatBytes(bytes)} extracted`;
  const archive = state.sourceFile;
  if (archive && !state.isMultiFileMode) {
    return { name: archive.name, detail: `${formatBytes(archive.size)} archive; ${extracted}` };
  }
  return { name: state.rootZipName || 'Unknown', detail: extracted };
}

function gatherReportData() {
  const ds = collectAllDatasets();
  const {
    passwords, cookies, autofills, notes, history, bookmarks,
    browserMetadata, accountTokens, serviceArtifacts, wallets,
    downloads, detections, clipboard, grabbedFiles, cards, screenshots,
    software, processes,
  } = ds;

  const credStats = buildCredStats(passwords);
  const cookStats = buildCookStats(cookies);

  let autoStats = null;
  if (autofills.entries.length > 0) {
    const highlights = classifyAutofillEntries(autofills.entries);
    autoStats = {
      total: autofills.entries.length,
      fileCount: autofills.fileCount,
      emails: sampleList(highlights.emails),
      phones: sampleList(highlights.phones),
      names: sampleList(highlights.names),
      addresses: sampleList(highlights.addresses),
    };
  }

  let histStats = null;
  if (history.entries.length > 0) {
    // The history page already ranks the domains, and it drops local-file,
    // loopback and RFC1918 hosts; the report quotes that same tally.
    const { topDomains, uniqueDomains } = history.stats;
    histStats = {
      total: history.entries.length,
      fileCount: history.fileCount,
      uniqueDomains,
      topDomains,
    };
  }

  return {
    archiveName: state.rootZipName || 'Unknown',
    source: describeSource(),
    generatedAt: new Date(),
    domainsOfInterest: buildDomainsOfInterest(passwords, cookies),
    capture,
    sysinfoEntries,
    sysinfoIocs,
    fingerprintResult,
    identityResult,
    bookmarks,
    browserMetadata,
    accountTokens,
    serviceArtifacts,
    wallets,
    downloads,
    detections,
    clipboard,
    notes,
    grabbedFiles,
    cards,
    screenshots,
    software,
    processes,
    credStats, cookStats, autoStats, histStats,
  };
}

function buildLogSummaryHtml(data) {
  const e = escapeHtml;

  // countLabel, split into a weighted number and its noun so the stat rows keep
  // their typographic hierarchy and still read as English rather than "1 file(s)".
  function stat(value, singular, plural = singular + 's', className = '') {
    const cls = className ? ` ${className}` : '';
    return `<div class="stat"><span class="stat-num${cls}">${value.toLocaleString()}</span> ${value === 1 ? singular : plural}</div>`;
  }

  // Each of these tables counts something different, and a column headed
  // "Count" leaves the reader to guess whether it is accounts, cookies or visits.
  function domainTable(domains, countHeader) {
    if (!domains || domains.length === 0) return '';
    return `<table><thead><tr><th>Domain</th><th>${e(countHeader)}</th></tr></thead><tbody>${
      domains.map(([d, c]) => `<tr><td>${e(d)}</td><td>${c.toLocaleString()}</td></tr>`).join('')
    }</tbody></table>`;
  }

  const provenance = `<section>
    <h2>Report provenance</h2>
    <table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>
      <tr><td>Tool</td><td>${e(TOOL_NAME)} ${e(TOOL_VERSION)}</td></tr>
      <tr><td>Report generated</td><td>${e(formatInstantLabel(data.generatedAt))}</td></tr>
      <tr><td>Source</td><td>${e(data.source.name)}</td></tr>
      <tr><td>Source size</td><td>${e(data.source.detail)}</td></tr>
      <tr><td>Capture time</td><td>${data.capture?.date
        ? `${e(formatInstantLabel(data.capture.date))} (${e(captureProvenance(data.capture))})`
        : 'Not established from this log'}</td></tr>
      <tr><td>Timestamps</td><td>Every time in this report is UTC. Wall-clock values read from the log carry no zone of their own and are shown as written.</td></tr>
    </tbody></table>
  </section>`;

  let sections = '';

  if (data.fingerprintResult) {
    const fp = data.fingerprintResult;
    const confColor = fp.confidence === 'high' ? '#16a34a' : fp.confidence === 'medium' ? '#d97706' : '#5f6672';
    const signals = fp.matchedSignals || [];
    const caveats = [];
    if (fp.source === 'structure-only') caveats.push('Inferred from folder and file layout; no sysinfo present.');
    if (fp.distributor) caveats.push(`Sold under the ${fp.distributor} brand; the shop that resold the log is not the stealer that took it.`);
    sections += `<section>
      <h2>Stealer identification</h2>
      <div class="stat-row">
        <div class="stat" style="font-size:0.95rem;"><strong style="color:${confColor}">${e(fp.family)}</strong></div>
        <div class="stat">${e(capitalise(fp.confidence))} confidence</div>
      </div>
      ${caveats.map(caveat => `<p class="note">${e(caveat)}</p>`).join('')}
      ${signals.length > 0 ? `<h3>Matched signals</h3>
      <table><thead><tr><th>Signal</th></tr></thead><tbody>${
        signals.map(signal => `<tr><td>${e(signal)}</td></tr>`).join('')
      }</tbody></table>` : ''}
    </section>`;
  }

  if (data.identityResult) {
    const id = data.identityResult;
    const pi = id.primaryIdentity;
    let piRows = '';
    if (pi.names.length > 0) piRows += `<tr><td>Name</td><td>${pi.names.map(e).join(', ')}</td></tr>`;
    if (pi.emails.length > 0) piRows += `<tr><td>Email</td><td>${pi.emails.map(e).join(', ')}</td></tr>`;
    if (pi.phones.length > 0) piRows += `<tr><td>Phone</td><td>${pi.phones.map(e).join(', ')}</td></tr>`;
    if (pi.osUsername) piRows += `<tr><td>OS user</td><td>${e(pi.osUsername)}</td></tr>`;
    if (pi.computerName) piRows += `<tr><td>Computer</td><td>${e(pi.computerName)}</td></tr>`;
    if (pi.location) {
      const located = pi.locationSource && pi.locationSource !== 'sysinfo'
        ? `${pi.location} (from ${pi.locationSource})`
        : pi.location;
      piRows += `<tr><td>Location</td><td>${e(located)}</td></tr>`;
    }
    // A stored street address is a form value, not where the host sits.
    if (pi.autofillAddress) {
      const address = pi.autofillAddressCount > 1
        ? `${pi.autofillAddress} (1 of ${countLabel(pi.autofillAddressCount, 'autofill address', 'autofill addresses')})`
        : pi.autofillAddress;
      piRows += `<tr><td>Autofill address</td><td>${e(address)}</td></tr>`;
    }

    const es = id.exposureSummary;
    let acctRows = '';
    const sessionAccounts = (id.accounts || []).filter(a => a.hasLiveSession);
    for (const acct of sessionAccounts) {
      acctRows += `<tr><td>${e(acct.domain)}</td><td>${acct.emails.map(e).join(', ') || '-'}</td></tr>`;
    }

    sections += `<section>
      <h2>Victim profile</h2>
      ${piRows ? `<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${piRows}</tbody></table>` : ''}
      <div class="stat-row" style="margin-top:0.75rem;">
        ${stat(es.totalUniqueServices, 'service')}
        ${stat(es.servicesWithLiveSessions, 'service live at capture', 'services live at capture', 'review')}
        ${stat(es.servicesWithBothPasswordAndSession, 'password + live session', 'password + live session', 'risk')}
        ${stat(es.uniqueEmails, 'email address', 'email addresses')}
      </div>
      ${acctRows ? `<h3>Services with a live session at capture</h3><table><thead><tr><th>Domain</th><th>Linked Emails</th></tr></thead><tbody>${acctRows}</tbody></table>` : ''}
    </section>`;
  }

  const infraIocs = (data.sysinfoIocs || []).filter(i => i.kind === 'stealer-infra');
  if (infraIocs.length > 0) {
    sections += `<section>
      <h2>Stealer infrastructure</h2>
      <table><thead><tr><th>Label</th><th>Family</th><th>Value</th></tr></thead><tbody>${
        infraIocs.map(ioc =>
          `<tr><td>${e(ioc.label)}</td><td>${e(ioc.family || '')}</td><td>${e(ioc.value)}</td></tr>`
        ).join('')
      }</tbody></table>
    </section>`;
  }

  if (data.sysinfoEntries) {
    sections += `<section>
      <h2>System Information</h2>
      <table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>${
        Object.entries(data.sysinfoEntries).map(([k, v]) =>
          `<tr><td>${e(k)}</td><td>${e(v)}</td></tr>`
        ).join('')
      }</tbody></table>
    </section>`;
  }

  if (data.credStats) {
    const cs = data.credStats;
    const credCounts = cs.rows !== undefined
      ? stat(cs.rows, 'credential row')
      : [
        stat(cs.unique, 'credential unique by domain, username and password', 'credentials unique by domain, username and password'),
        stat(cs.parsed, 'parsed before dedupe', 'parsed before dedupe'),
        cs.accountsWithoutPasswords > 0 ? stat(cs.accountsWithoutPasswords, 'account with no captured password', 'accounts with no captured password') : '',
        cs.savedSites > 0 ? stat(cs.savedSites, 'saved site with no credentials', 'saved sites with no credentials') : '',
      ].filter(Boolean).join('');
    // Files holding the same rows in a second format are counted once, so this
    // is smaller than the number of credential files in the tree.
    const separateHosts = cs.onionDomains > 0 || cs.localNetwork?.length > 0;
    sections += `<section>
      <h2>Credential summary</h2>
      <div class="stat-row">
        ${credCounts}
        ${stat(cs.fileCount, 'distinct source file')}
      </div>
      <p class="note">Passwords are not included in this report.</p>
      ${cs.unparsedFiles > 0 ? `<p class="note">Not counted above: ${countLabel(cs.unparsedFiles, 'further candidate file')} that yielded no credentials.</p>` : ''}
      ${cs.onionDomains > 0 ? `<p class="note">${countLabel(cs.onionDomains, 'credential domain')} on the Tor network (.onion).</p>` : ''}
      <h3>Top credential domains</h3>
      ${domainTable(cs.topDomains, 'Accounts')}
      ${separateHosts ? '<p class="note">Local network hosts and .onion domains are counted separately and are not in the table above.</p>' : ''}
      ${cs.localNetwork?.length ? `<h3>Local network hosts</h3>${domainTable(cs.localNetwork, 'Accounts')}` : ''}
    </section>`;
  }

  if (data.cookStats) {
    const ck = data.cookStats;
    let sessionNote = '';
    if (ck.sessionTokens > 0) {
      sessionNote = `<p class="session-note"><strong>${countLabel(ck.sessionTokens, 'identified session token')}</strong>`;
      if (ck.liveSessionTokens > 0) {
        sessionNote += ` (<strong class="risk">${ck.liveSessionTokens.toLocaleString()} live at capture</strong>)`;
      }
      sessionNote += `</p>`;
    }
    sections += `<section>
      <h2>Cookie summary</h2>
      <div class="stat-row">
        ${stat(ck.total, 'cookie in total', 'cookies in total')}
        ${stat(ck.valid, 'valid at capture', 'valid at capture', 'valid')}
        ${stat(ck.expired, 'expired', 'expired', 'expired')}
        ${stat(ck.session, 'no expiry', 'no expiry')}
        ${ck.unknown > 0 ? stat(ck.unknown, 'unparseable expiry', 'unparseable expiry') : ''}
        ${stat(ck.fileCount, 'source file')}
      </div>
      ${sessionNote}
      ${ck.noDomain > 0 ? `<p class="note">No domain was recorded for ${countLabel(ck.noDomain, 'cookie')}; those rows sit inside the four states above rather than beside them.</p>` : ''}
      <h3>Top cookie domains</h3>
      ${domainTable(ck.topDomains, 'Cookies')}
    </section>`;
  }

  if (data.domainsOfInterest) {
    const di = data.domainsOfInterest;
    sections += `<section>
      <h2>Domains of interest</h2>
      ${di.unavailable ? '<p class="note">The bundled domain reference lists had not finished loading when this report was written, so no host could be categorised.</p>' : `<p class="note">Every credential and cookie host that the bundled domain reference lists place in a government, military, banking, finance, remote-access or dynamic-DNS category. Read from ${countLabel(di.credDomains, 'distinct credential domain')} and ${countLabel(di.cookieDomains, 'distinct cookie domain')}; a host absent from the lists carries no category and is not shown.</p>
      <table><thead><tr><th>Domain</th><th>Category</th><th>Accounts</th><th>Cookies</th></tr></thead><tbody>${
        di.rows.map(row => `<tr><td>${e(row.domain)}</td><td>${e(getCategoryLabel(row.key))}</td><td>${row.accounts.toLocaleString()}</td><td>${row.cookies.toLocaleString()}</td></tr>`).join('')
      }</tbody></table>`}
    </section>`;
  }

  if (data.autoStats) {
    const af = data.autoStats;
    const lists = [
      ['Emails', af.emails, 'email'],
      ['Phone numbers', af.phones, 'phone number'],
      ['Names', af.names, 'name'],
      ['Addresses', af.addresses, 'address', 'addresses'],
    ].filter(([, list]) => list.total > 0);
    const detail = lists.map(([label, list]) => {
      const shown = list.sample.length < list.total
        ? ` &mdash; first ${list.sample.length} of ${list.total.toLocaleString()}`
        : '';
      return `<p><strong>${label}${shown}:</strong> ${list.sample.map(e).join(', ')}</p>`;
    }).join('');
    sections += `<section>
      <h2>Autofill summary</h2>
      <div class="stat-row">
        ${stat(af.total, 'entry in total', 'entries in total')}
        ${lists.map(([, list, singular, plural]) => stat(list.total, singular, plural)).join('')}
        ${stat(af.fileCount, 'source file')}
      </div>
      ${detail}
    </section>`;
  }

  if (data.histStats) {
    const hs = data.histStats;
    sections += `<section>
      <h2>Browsing history summary</h2>
      <div class="stat-row">
        ${stat(hs.total, 'entry', 'entries')}
        ${stat(hs.uniqueDomains, 'unique domain')}
        ${stat(hs.fileCount, 'source file')}
      </div>
      <h3>Top visited domains</h3>
      ${domainTable(hs.topDomains, 'Visits')}
    </section>`;
  }

  const artifactSummary = [
    ['Bookmarks', data.bookmarks?.entries.length || 0],
    ['Notes', data.notes?.entries.length || 0],
    ['Browser metadata', data.browserMetadata?.entries.length || 0],
    ['Account tokens', data.accountTokens?.entries.length || 0],
    ['Service artifacts', data.serviceArtifacts?.entries.length || 0],
    ['Wallet / store artifacts', data.wallets?.entries.length || 0],
    ['Downloads', data.downloads?.entries.length || 0],
    ['Clipboard', data.clipboard?.entries.length || 0],
    ['Grabbed files', data.grabbedFiles?.entries.length || 0],
    ['Credit cards', data.cards?.entries.length || 0],
    ['Screenshots', data.screenshots?.entries.length || 0],
    ['Installed software', data.software?.entries.length || 0],
    ['Running processes', data.processes?.entries.length || 0],
  ].filter(([, count]) => count > 0);

  // The log's own domain-detect file is its tally of the passwords and cookies
  // it took, per host, under the operator's category names. Every host in it is
  // already in the credential and cookie summaries above, so it is named here
  // rather than reprinted as a second, differently-counted domain list.
  const detectFiles = data.detections?.fileCount || 0;
  const detectNote = detectFiles > 0
    ? `<p class="note">The log ships its own domain-detect roll-up (${countLabel(detectFiles, 'file')}), tallying the hosts it took credentials and cookies from. Those hosts are summarised above and are not repeated.</p>`
    : '';

  if (artifactSummary.length > 0 || detectNote) {
    sections += `<section>
      <h2>Additional artifacts</h2>
      ${artifactSummary.length > 0 ? `<table><thead><tr><th>Artifact</th><th>Entries</th></tr></thead><tbody>${
        artifactSummary.map(([label, count]) => `<tr><td>${e(label)}</td><td>${count.toLocaleString()}</td></tr>`).join('')
      }</tbody></table>` : ''}
      ${detectNote}
    </section>`;
  }

  if (!sections) {
    sections = '<section><p>No structured data was found in this archive.</p></section>';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Summary - ${e(data.archiveName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1a1d23; background: #f5f6f8; padding: 2rem; line-height: 1.5; }
  .container { max-width: 900px; margin: 0 auto; background: #fff; border: 1px solid #d0d4da; border-radius: 8px; padding: 2.5rem; }
  header { margin-bottom: 2rem; border-bottom: 2px solid #2563eb; padding-bottom: 1.5rem; }
  header h1 { font-size: 1.4rem; font-weight: 600; color: #1a1d23; margin-bottom: 0.25rem; }
  header .meta { font-size: 0.8rem; color: #5f6672; }
  header .meta span { margin-right: 1.5rem; }
  section { margin-bottom: 2rem; }
  h2 { font-size: 1.05rem; font-weight: 600; color: #1a1d23; margin-bottom: 0.75rem; padding-bottom: 0.35rem; border-bottom: 1px solid #ebedf0; }
  h3 { font-size: 0.85rem; font-weight: 600; color: #5f6672; margin: 1rem 0 0.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-bottom: 0.5rem; font-variant-numeric: tabular-nums; }
  th { text-align: left; padding: 0.4rem 0.75rem; background: #f5f6f8; border: 1px solid #ebedf0; font-weight: 600; color: #5f6672; }
  td { padding: 0.4rem 0.75rem; border: 1px solid #ebedf0; }
  .stat-row { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
  .stat { font-size: 0.8rem; color: #5f6672; }
  .stat-num { font-weight: 600; color: #1a1d23; font-size: 1rem; margin-right: 0.25rem; }
  .stat-num.valid { color: #16a34a; }
  .stat-num.expired, .risk { color: #dc2626; }
  .review { color: #d97706; }
  .session-note { font-size: 0.8rem; margin-top: 0.5rem; }
  .note { font-size: 0.75rem; color: #5f6672; font-style: italic; margin-bottom: 0.5rem; max-width: 68ch; }
  @media print { body { background: #fff; padding: 0; } .container { border: none; padding: 1rem; box-shadow: none; } }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Log summary</h1>
    <div class="meta">
      <span>${e(data.source.name)}</span>
    </div>
  </header>
  ${provenance}
  ${sections}
</div>
</body>
</html>`;
}

function exportLogSummary() {
  const data = gatherReportData();
  const html = buildLogSummaryHtml(data);

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  // A managed browser with popups blocked returns null here, and the report
  // would otherwise be reported as opened and then lost.
  const win = window.open(url, '_blank');
  if (!win) {
    URL.revokeObjectURL(url);
    downloadBlob(html, 'log_summary.html', 'text/html');
    notify('Popup blocked, so the log summary was downloaded instead. Open it and use browser Print to save as PDF.', 'info');
    return;
  }
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  notify('Log summary opened in new tab. Use browser Print to save as PDF.');
}

// Parsed Data ZIP (password-protected)

function showPasswordModal(password) {
  return new Promise((resolve) => {
    const modal = openTransientModal(`
      <div class="modal">
        <h3>ZIP password</h3>
        <p>Copy it before continuing. It is shown once.</p>
        <div class="export-password-display">
          <code class="export-password-value">${escapeHtml(password)}</code>
          <button class="export-password-copy" id="exportPwCopy">Copy</button>
        </div>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="exportPwCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="exportPwProceed">Download ZIP</button>
        </div>
      </div>
    `, { onDismiss: () => resolve(false) });
    if (!modal) { resolve(false); return; }
    const { overlay, close } = modal;

    overlay.querySelector('#exportPwCopy').addEventListener('click', async () => {
      const ok = await copyToClipboard(password);
      const btn = overlay.querySelector('#exportPwCopy');
      btn.textContent = ok ? 'Copied' : 'Failed';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });

    overlay.querySelector('#exportPwCancel').addEventListener('click', () => {
      overlay.remove(); resolve(false);
    });

    overlay.querySelector('#exportPwProceed').addEventListener('click', () => {
      overlay.remove(); resolve(true);
    });

    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) { overlay.remove(); resolve(false); }
    });
  });
}

async function exportParsedDataZip() {
  const {
    passwords, cookies, autofills, notes, history, bookmarks,
    browserMetadata, accountTokens, serviceArtifacts, wallets,
    downloads, detections, clipboard, grabbedFiles, cards, screenshots,
  } = collectAllDatasets();

  const hasData = passwords.rows.length > 0 || cookies.rows.length > 0 ||
                  autofills.entries.length > 0 || notes.entries.length > 0 || history.entries.length > 0 ||
                  bookmarks.entries.length > 0 || browserMetadata.entries.length > 0 ||
                  accountTokens.entries.length > 0 || serviceArtifacts.entries.length > 0 ||
                  wallets.entries.length > 0 ||
                  downloads.entries.length > 0 || detections.entries.length > 0 ||
                  clipboard.entries.length > 0 || grabbedFiles.entries.length > 0 || cards.entries.length > 0 ||
                  screenshots.entries.length > 0;
  if (!hasData) {
    notify('No parsed data available to package.', 'error');
    return;
  }

  const zipPassword = randomPassword(16);

  const acknowledged = await showPasswordModal(zipPassword);
  if (!acknowledged) return;

  notify('Generating parsed data package...', 'info');

  try {
    const blobWriter = new zip.BlobWriter('application/zip');
    const writer = new zip.ZipWriter(blobWriter, { password: zipPassword });

    async function addTextFile(filename, content) {
      const blob = new Blob([content], { type: 'text/plain' });
      await writer.add(filename, new zip.BlobReader(blob));
    }

    async function addCsvFile(filename, headers, rows) {
      await addTextFile(filename, buildCsvText(headers, rows));
    }

    // The page that owns a dataset owns its column set. Writing those columns
    // out a second time here is how the packaged CSV and the on-screen one
    // drifted apart, so the page's spec is used verbatim.
    async function addPageCsv(pageId, entries) {
      const spec = CSV_SPECS[pageId];
      await addCsvFile(spec.file, spec.headers, entries.map(spec.row));
    }

    if (passwords.rows.length > 0) {
      // A row merged from several dumps carries every path it came from, and a
      // log's own columns may already be called Source.
      await addCsvFile('credentials.csv', [...passwords.headers, 'Source File'],
        passwords.rows.map(({ row, source }) => [...row, source]));
    }

    if (cookies.rows.length > 0) {
      const shaped = shapeCookiesCsv(cookies);
      await addCsvFile('cookies.csv', shaped.headers, shaped.rows);
    }

    if (autofills.entries.length > 0) {
      await addCsvFile('autofills.csv', ['Field', 'Value'], autofills.entries.map(
        ({ name, value }) => [name, value]
      ));
    }

    if (notes.entries.length > 0) {
      const shaped = shapeNotesCsv(notes);
      await addCsvFile('notes.csv', shaped.headers, shaped.rows);
    }

    if (history.entries.length > 0) {
      const shaped = shapeHistoryCsv(history);
      await addCsvFile('history.csv', shaped.headers, shaped.rows);
    }

    if (bookmarks.entries.length > 0) {
      await addCsvFile('bookmarks.csv', ['URL', 'Title', 'Folder', 'Browser', 'Profile', 'Domain', 'Source'], bookmarks.entries.map(
        ({ url, title, folder, browser, profile, domain, source }) => [url, title, folder, browser, profile, domain, source]
      ));
    }

    if (browserMetadata.entries.length > 0) {
      await addCsvFile('browser_metadata.csv', ['Browser', 'Profile', 'Category', 'Key', 'Value', 'Source'], browserMetadata.entries.map(
        ({ browser, profile, category, key, value, source }) => [browser, profile, category, key, value, source]
      ));
    }

    if (accountTokens.entries.length > 0) {
      await addCsvFile('account_tokens.csv', ['Service', 'Type', 'Value', 'Account ID', 'Browser', 'Profile', 'Note', 'Source'], accountTokens.entries.map(
        ({ service, type, value, accountId, browser, profile, note, source }) => [service, type, value, accountId, browser, profile, note, source]
      ));
    }

    if (serviceArtifacts.entries.length > 0) {
      await addCsvFile('service_artifacts.csv', ['Service', 'Artifact Type', 'Section', 'Key', 'Value', 'Source'], serviceArtifacts.entries.map(
        ({ service, artifactType, section, key, value, source }) => [service, artifactType, section, key, value, source]
      ));
    }

    if (wallets.entries.length > 0) {
      await addCsvFile('wallet_artifacts.csv', ['Service', 'Category', 'Artifact Type', 'Store Type', 'Browser', 'Profile', 'Highlights', 'Email Count', 'Address Count', 'Token Count', 'Seed Hints', 'Source'], wallets.entries.map((entry) => [
          entry.service,
          entry.category,
          entry.artifactType,
          entry.storeType,
          entry.browser,
          entry.profile,
          entry.highlights,
          entry.emailCount,
          entry.addressCount,
          entry.tokenCount,
          entry.seedHints,
          entry.source,
        ]
      ));
    }

    if (downloads.entries.length > 0) {
      await addCsvFile('downloads.csv', ['File Path', 'Source URL', 'File Size', 'Extension', 'Domain'], downloads.entries.map(
        ({ filePath, sourceUrl, fileSizeRaw, fileSizeDisplay, extension, domain }) => [filePath, sourceUrl, fileSizeRaw || fileSizeDisplay, extension, domain]
      ));
    }

    if (detections.entries.length > 0) {
      await addCsvFile('domain_detections.csv', ['Section', 'Label', 'Target', 'Count', 'Source'], detections.entries.map(
        ({ section, label, target, count, source }) => [section, label, target, count, source]
      ));
    }

    if (clipboard.entries.length > 0) {
      await addCsvFile('clipboard.csv', ['Type', 'Text', 'URLs', 'Line Count', 'Length', 'Source'], clipboard.entries.map(
        ({ type, text, urls, lineCount, length, source }) => [type, text, urls, lineCount, length, source]
      ));
    }

    if (grabbedFiles.entries.length > 0) {
      await addCsvFile('grabbed_files.csv', ['Collection', 'Name', 'Path', 'Extension', 'Size Bytes', 'Modified', 'Source'], grabbedFiles.entries.map((entry) => [
          entry.collection,
          entry.name,
          entry.relativePath,
          entry.extension,
          entry.sizeBytes,
          entry.modifiedDate instanceof Date && !isNaN(entry.modifiedDate.getTime()) ? entry.modifiedDate.toLocaleString() : '',
          entry.source,
        ]
      ));
    }

    if (cards.entries.length > 0) {
      await addCsvFile('credit_cards.csv', ['Card Number', 'Last4', 'Name On Card', 'Expiration', 'CVC', 'Browser', 'Recovered From', 'Source'], cards.entries.map(
        ({ cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source }) => [cardNumber, last4, nameOnCard, expiration, cvc, browser, filePath, source]
      ));
    }

    if (screenshots.entries.length > 0) {
      await addCsvFile('screenshots.csv', ['Name', 'Path', 'Width', 'Height', 'Size Bytes'], screenshots.entries.map(
        ({ name, path, width, height, sizeBytes }) => [name, path, width || '', height || '', sizeBytes]
      ));
    }

    for (let i = 0; i < screenshots.entries.length; i++) {
      try {
        const entry = screenshots.entries[i];
        const content = await loadFileContent(entry.node);
        if (content) {
          const ext = entry.node.name.split('.').pop().toLowerCase();
          const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', bmp: 'image/bmp', gif: 'image/gif', webp: 'image/webp' };
          const mime = mimeMap[ext] || 'image/png';
          const blob = new Blob([content], { type: mime });
          const safeName = `${String(i + 1).padStart(2, '0')}_${entry.node.name}`;
          await writer.add('screenshots/' + safeName, new zip.BlobReader(blob));
        }
      } catch {
        // skip
      }
    }

    await writer.close();
    const zipBlob = await blobWriter.getData();

    downloadBlob(zipBlob, 'parsed_data.zip', 'application/zip');
    notify('Parsed data package downloaded. Share the password over a separate channel.');
  } catch (err) {
    notify(`Failed to generate data package: ${err.message}`, 'error');
  }
}

// Init

function initExports() {
  on('analysis:sysinfo', (data) => {
    sysinfoEntries = data ? data.entries : null;
    sysinfoIocs = data ? (data.iocs || null) : null;
  });
  on('analysis:fingerprint', (data) => { fingerprintResult = data; });
  on('analysis:identity', (data) => { identityResult = data; });
  on('analysis:credentials', (data) => { credentialsAnalysis = data; });
  on('analysis:cookies', (data) => { cookiesAnalysis = data; });
  on('analysis:capture', (data) => { capture = data; });

  document.getElementById('exportIncidentSummary').addEventListener('click', exportLogSummary);
  document.getElementById('exportObfuscatedCreds').addEventListener('click', exportObfuscatedCredentials);
  document.getElementById('exportEvidenceZip').addEventListener('click', exportParsedDataZip);

  on('extracted', () => { document.getElementById('navExports').disabled = false; });

  // Update export card counts when data is loaded
  on('data:loaded', () => {
    const {
      passwords, cookies, autofills, notes, history, bookmarks,
      browserMetadata, accountTokens, serviceArtifacts, wallets,
      downloads, detections, clipboard, grabbedFiles, cards, screenshots,
    } = collectAllDatasets();

    const parts = [];
    if (passwords.rows.length > 0) parts.push(`${passwords.rows.length} credential rows`);
    if (cookies.rows.length > 0) parts.push(`${cookies.rows.length} cookies`);
    if (autofills.entries.length > 0) parts.push(`${autofills.entries.length} autofills`);
    if (notes.entries.length > 0) parts.push(`${notes.entries.length} notes`);
    if (history.entries.length > 0) parts.push(`${history.entries.length} history entries`);
    if (bookmarks.entries.length > 0) parts.push(`${bookmarks.entries.length} bookmarks`);
    if (browserMetadata.entries.length > 0) parts.push(`${browserMetadata.entries.length} browser metadata`);
    if (accountTokens.entries.length > 0) parts.push(`${accountTokens.entries.length} tokens`);
    if (serviceArtifacts.entries.length > 0) parts.push(`${serviceArtifacts.entries.length} services`);
    if (wallets.entries.length > 0) parts.push(`${wallets.entries.length} wallets`);
    if (downloads.entries.length > 0) parts.push(`${downloads.entries.length} downloads`);
    if (cards.entries.length > 0) parts.push(`${cards.entries.length} cards`);
    if (clipboard.entries.length > 0) parts.push(`${clipboard.entries.length} clipboard`);
    if (grabbedFiles.entries.length > 0) parts.push(`${grabbedFiles.entries.length} grabbed files`);
    if (detections.entries.length > 0) parts.push(`${detections.entries.length} detections`);
    if (screenshots.entries.length > 0) parts.push(`${screenshots.entries.length} screenshots`);
    const countsText = parts.length > 0 ? parts.join(' \u00B7 ') : '';

    const summaryCounts = document.getElementById('exportSummaryCounts');
    const credsCounts = document.getElementById('exportCredsCounts');
    const zipCounts = document.getElementById('exportZipCounts');

    if (summaryCounts) summaryCounts.textContent = countsText;
    if (credsCounts) credsCounts.textContent = passwords.rows.length > 0 ? `${passwords.rows.length} credential rows from ${passwords.fileCount} file(s)` : 'No credentials available';
    if (zipCounts) zipCounts.textContent = countsText || 'No data available';
  });

  on('reset', () => {
    sysinfoEntries = null;
    sysinfoIocs = null;
    fingerprintResult = null;
    identityResult = null;
    credentialsAnalysis = null;
    cookiesAnalysis = null;
    capture = null;
    document.getElementById('navExports').disabled = true;

    const summaryCounts = document.getElementById('exportSummaryCounts');
    const credsCounts = document.getElementById('exportCredsCounts');
    const zipCounts = document.getElementById('exportZipCounts');
    if (summaryCounts) summaryCounts.textContent = '';
    if (credsCounts) credsCounts.textContent = '';
    if (zipCounts) zipCounts.textContent = '';
  });
}

export { initExports, TOOL_NAME, TOOL_VERSION };
