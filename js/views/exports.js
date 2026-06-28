// Exports

import { state, on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { escapeHtml, capitalise } from '../core/utils.js';
import {
  classifyAutofillEntries,
  downloadBlob,
  copyToClipboard,
  baseDomainFromUrl,
  randomPassword,
  showNotification as notify,
} from '../core/shared.js';
import {
  buildCsvText,
  downloadCsvRows,
  getFieldByPattern,
} from '../pages/shared.js';
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
} from '../pages/browser.js';
import {
  getAccountTokensData,
  getServiceArtifactsData,
  getWalletArtifactsData,
  getCreditCardsData,
} from '../pages/assets.js';
import {
  getDownloadsData,
  getDomainDetectionsData,
  getClipboardData,
  getGrabbedFilesData,
  getScreenshotsData,
} from '../pages/activity.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';

let sysinfoEntries = null;
let sysinfoIocs = null;
let fingerprintResult = null;
let identityResult = null;

const DEDUPE_KEY_SEP = '\u0000';

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
  };
}

function maskPassword(pw) {
  if (!pw || pw.length === 0) return '****';
  if (pw.length <= 2) return '****';
  return pw[0] + '*'.repeat(Math.min(pw.length - 2, 6)) + pw[pw.length - 1];
}

// Obfuscated Credentials CSV

function exportObfuscatedCredentials() {
  const data = getPasswordsData();
  if (!data || data.rows.length === 0) {
    notify('No credential data available to export.', 'error');
    return;
  }

  const urlIdx = data.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = data.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
  const passIdx = data.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

  const seen = new Set();
  const uniqueRows = [];
  for (const { row } of data.rows) {
    const url = urlIdx >= 0 ? (row[urlIdx] || '') : '';
    const user = userIdx >= 0 ? (row[userIdx] || '') : '';
    const pass = passIdx >= 0 ? (row[passIdx] || '') : '';
    const key = url + DEDUPE_KEY_SEP + user + DEDUPE_KEY_SEP + pass;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueRows.push(row);
    }
  }

  downloadCsvRows('credentials_obfuscated.csv', data.headers, uniqueRows.map((row) =>
    row.map((cell, index) => (index === passIdx ? maskPassword(cell) : cell))
  ));
  notify(`Exported ${uniqueRows.length} unique credentials (passwords masked).`);
}

// Log Summary Report (HTML)

function gatherReportData() {
  const ds = collectAllDatasets();
  const {
    passwords, cookies, autofills, notes, history, bookmarks,
    browserMetadata, accountTokens, serviceArtifacts, wallets,
    downloads, detections, clipboard, grabbedFiles, cards, screenshots,
  } = ds;

  let credStats = null;
  if (passwords.rows.length > 0) {
    const urlIdx = passwords.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
    const userIdx = passwords.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
    const passIdx = passwords.headers.findIndex(h => FIELD_PATTERNS.password.test(h));
    const domainCounts = {};
    const seen = new Set();
    for (const { row } of passwords.rows) {
      const url = urlIdx >= 0 ? (row[urlIdx] || '') : '';
      const user = userIdx >= 0 ? (row[userIdx] || '') : '';
      const pass = passIdx >= 0 ? (row[passIdx] || '') : '';
      seen.add(url + DEDUPE_KEY_SEP + user + DEDUPE_KEY_SEP + pass);
      const domain = baseDomainFromUrl(url);
      if (domain) domainCounts[domain] = (domainCounts[domain] || 0) + 1;
    }
    credStats = {
      total: passwords.rows.length,
      unique: seen.size,
      fileCount: passwords.fileCount,
      topDomains: Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
    };
  }

  let cookStats = null;
  if (cookies.rows.length > 0) {
    const valid = cookies.rows.filter(r => r.validity.status === 'valid').length;
    const expired = cookies.rows.filter(r => r.validity.status === 'expired').length;
    const session = cookies.rows.filter(r => r.validity.status === 'session').length;
    const sessionTokens = cookies.rows.filter(r => r.sessionType === 'auth' || r.sessionType === 'session').length;
    const validSessionTokens = cookies.rows.filter(r => (r.sessionType === 'auth' || r.sessionType === 'session') && r.validity.status === 'valid').length;
    const domainCounts = {};
    for (const rowData of cookies.rows) {
      const d = getFieldByPattern(rowData, FIELD_PATTERNS.cookieDomain).replace(/^\./, '').toLowerCase();
      if (d) domainCounts[d] = (domainCounts[d] || 0) + 1;
    }
    cookStats = {
      total: cookies.rows.length,
      valid, expired, session,
      sessionTokens, validSessionTokens,
      fileCount: cookies.fileCount,
      topDomains: Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
    };
  }

  let autoStats = null;
  if (autofills.entries.length > 0) {
    const highlights = classifyAutofillEntries(autofills.entries);
    autoStats = {
      total: autofills.entries.length,
      fileCount: autofills.fileCount,
      emails: highlights.emails,
      phones: highlights.phones,
      names: highlights.names,
    };
  }

  let histStats = null;
  if (history.entries.length > 0) {
    const domainCounts = {};
    for (const { url } of history.entries) {
      const domain = baseDomainFromUrl(url);
      if (domain) domainCounts[domain] = (domainCounts[domain] || 0) + 1;
    }
    histStats = {
      total: history.entries.length,
      fileCount: history.fileCount,
      uniqueDomains: Object.keys(domainCounts).length,
      topDomains: Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
    };
  }

  return {
    archiveName: state.rootZipName || 'Unknown',
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
    credStats, cookStats, autoStats, histStats,
  };
}

function buildLogSummaryHtml(data) {
  const e = escapeHtml;

  function domainTable(domains) {
    if (!domains || domains.length === 0) return '';
    return `<table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>${
      domains.map(([d, c]) => `<tr><td>${e(d)}</td><td>${c}</td></tr>`).join('')
    }</tbody></table>`;
  }

  let sections = '';

  if (data.fingerprintResult) {
    const fp = data.fingerprintResult;
    const confColor = fp.confidence === 'high' ? '#16a34a' : fp.confidence === 'medium' ? '#d97706' : '#8c919c';
    const structureNote = fp.source === 'structure-only'
      ? `<div class="stat" style="font-size:0.8rem;color:#8c919c;">Inferred from folder/file layout; no sysinfo present.</div>`
      : '';
    sections += `<section>
      <h2>Stealer Identification</h2>
      <div class="stat-row">
        <div class="stat" style="font-size:0.95rem;"><strong style="color:${confColor}">${e(fp.family)}</strong></div>
        <div class="stat">${e(capitalise(fp.confidence))} confidence (${Math.round(fp.score * 100)}%)</div>
        ${structureNote}
      </div>
    </section>`;
  }

  if (data.identityResult) {
    const id = data.identityResult;
    const pi = id.primaryIdentity;
    let piRows = '';
    if (pi.names.length > 0) piRows += `<tr><td>Name</td><td>${pi.names.map(e).join(', ')}</td></tr>`;
    if (pi.emails.length > 0) piRows += `<tr><td>Email</td><td>${pi.emails.map(e).join(', ')}</td></tr>`;
    if (pi.phones.length > 0) piRows += `<tr><td>Phone</td><td>${pi.phones.map(e).join(', ')}</td></tr>`;
    if (pi.osUsername) piRows += `<tr><td>OS User</td><td>${e(pi.osUsername)}</td></tr>`;
    if (pi.computerName) piRows += `<tr><td>Computer</td><td>${e(pi.computerName)}</td></tr>`;
    if (pi.location) piRows += `<tr><td>Location</td><td>${e(pi.location)}</td></tr>`;

    const es = id.exposureSummary;
    let acctRows = '';
    const sessionAccounts = (id.accounts || []).filter(a => a.hasValidSession);
    for (const acct of sessionAccounts) {
      acctRows += `<tr><td>${e(acct.domain)}</td><td>${acct.emails.map(e).join(', ') || '-'}</td></tr>`;
    }

    sections += `<section>
      <h2>Victim Profile</h2>
      ${piRows ? `<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${piRows}</tbody></table>` : ''}
      <div class="stat-row" style="margin-top:0.75rem;">
        <div class="stat"><span class="stat-num">${es.totalUniqueServices}</span> services</div>
        <div class="stat"><span class="stat-num" style="color:#d97706">${es.servicesWithValidSessions}</span> active sessions</div>
        <div class="stat"><span class="stat-num" style="color:#dc2626">${es.servicesWithBothPasswordAndSession}</span> cred + session</div>
        <div class="stat"><span class="stat-num">${es.uniqueEmails}</span> email addresses</div>
      </div>
      ${acctRows ? `<h3>Services with Active Sessions</h3><table><thead><tr><th>Domain</th><th>Linked Emails</th></tr></thead><tbody>${acctRows}</tbody></table>` : ''}
    </section>`;
  }

  const infraIocs = (data.sysinfoIocs || []).filter(i => i.kind === 'stealer-infra');
  if (infraIocs.length > 0) {
    sections += `<section>
      <h2>Stealer Infrastructure</h2>
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
    sections += `<section>
      <h2>Credential Summary</h2>
      <div class="stat-row">
        <div class="stat"><span class="stat-num">${cs.unique.toLocaleString()}</span> unique credentials</div>
        <div class="stat"><span class="stat-num">${cs.total.toLocaleString()}</span> total entries</div>
        <div class="stat"><span class="stat-num">${cs.fileCount}</span> source file(s)</div>
      </div>
      <p class="note">Passwords are not included in this report.</p>
      <h3>Top Credential Domains</h3>
      ${domainTable(cs.topDomains)}
    </section>`;
  }

  if (data.cookStats) {
    const ck = data.cookStats;
    let sessionNote = '';
    if (ck.sessionTokens > 0) {
      sessionNote = `<p style="margin-top:0.5rem;font-size:0.8rem;"><strong>${ck.sessionTokens}</strong> identified session token${ck.sessionTokens !== 1 ? 's' : ''}`;
      if (ck.validSessionTokens > 0) {
        sessionNote += ` (<strong style="color:#dc2626">${ck.validSessionTokens} valid</strong>)`;
      }
      sessionNote += `</p>`;
    }
    sections += `<section>
      <h2>Cookie Summary</h2>
      <div class="stat-row">
        <div class="stat"><span class="stat-num">${ck.total.toLocaleString()}</span> total cookies</div>
        <div class="stat"><span class="stat-num valid">${ck.valid.toLocaleString()}</span> valid</div>
        <div class="stat"><span class="stat-num expired">${ck.expired.toLocaleString()}</span> expired</div>
        <div class="stat"><span class="stat-num">${ck.session.toLocaleString()}</span> no expiry</div>
        <div class="stat"><span class="stat-num">${ck.fileCount}</span> source file(s)</div>
      </div>
      ${sessionNote}
      <h3>Top Cookie Domains</h3>
      ${domainTable(ck.topDomains)}
    </section>`;
  }

  if (data.autoStats) {
    const af = data.autoStats;
    let detail = '';
    if (af.emails.length > 0) detail += `<p><strong>Emails:</strong> ${af.emails.map(e).join(', ')}</p>`;
    if (af.phones.length > 0) detail += `<p><strong>Phone Numbers:</strong> ${af.phones.map(e).join(', ')}</p>`;
    if (af.names.length > 0) detail += `<p><strong>Names:</strong> ${af.names.map(e).join(', ')}</p>`;
    sections += `<section>
      <h2>Autofill Summary</h2>
      <div class="stat-row">
        <div class="stat"><span class="stat-num">${af.total}</span> total entries</div>
        <div class="stat"><span class="stat-num">${af.fileCount}</span> source file(s)</div>
      </div>
      ${detail}
    </section>`;
  }

  if (data.histStats) {
    const hs = data.histStats;
    sections += `<section>
      <h2>Browsing History Summary</h2>
      <div class="stat-row">
        <div class="stat"><span class="stat-num">${hs.total.toLocaleString()}</span> entries</div>
        <div class="stat"><span class="stat-num">${hs.uniqueDomains.toLocaleString()}</span> unique domains</div>
        <div class="stat"><span class="stat-num">${hs.fileCount}</span> source file(s)</div>
      </div>
      <h3>Top Visited Domains</h3>
      ${domainTable(hs.topDomains)}
    </section>`;
  }

  const artifactSummary = [
    ['Bookmarks', data.bookmarks?.entries.length || 0],
    ['Notes', data.notes?.entries.length || 0],
    ['Browser Metadata', data.browserMetadata?.entries.length || 0],
    ['Account Tokens', data.accountTokens?.entries.length || 0],
    ['Service Artifacts', data.serviceArtifacts?.entries.length || 0],
    ['Wallet / Store Artifacts', data.wallets?.entries.length || 0],
    ['Downloads', data.downloads?.entries.length || 0],
    ['Domain Detections', data.detections?.entries.length || 0],
    ['Clipboard', data.clipboard?.entries.length || 0],
    ['Grabbed Files', data.grabbedFiles?.entries.length || 0],
    ['Credit Cards', data.cards?.entries.length || 0],
    ['Screenshots', data.screenshots?.entries.length || 0],
  ].filter(([, count]) => count > 0);

  if (artifactSummary.length > 0) {
    sections += `<section>
      <h2>Additional Artifacts</h2>
      <table><thead><tr><th>Artifact</th><th>Entries</th></tr></thead><tbody>${
        artifactSummary.map(([label, count]) => `<tr><td>${e(label)}</td><td>${count.toLocaleString()}</td></tr>`).join('')
      }</tbody></table>
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
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-bottom: 0.5rem; }
  th { text-align: left; padding: 0.4rem 0.75rem; background: #f5f6f8; border: 1px solid #ebedf0; font-weight: 600; color: #5f6672; }
  td { padding: 0.4rem 0.75rem; border: 1px solid #ebedf0; }
  .stat-row { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
  .stat { font-size: 0.8rem; color: #5f6672; }
  .stat-num { font-weight: 600; color: #1a1d23; font-size: 1rem; margin-right: 0.25rem; }
  .stat-num.valid { color: #16a34a; }
  .stat-num.expired { color: #dc2626; }
  .note { font-size: 0.75rem; color: #8c919c; font-style: italic; margin-bottom: 0.5rem; }
  @media print { body { background: #fff; padding: 0; } .container { border: none; padding: 1rem; box-shadow: none; } }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Log Summary</h1>
    <div class="meta">
      <span>Archive: ${e(data.archiveName)}</span>
    </div>
  </header>
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
  window.open(url, '_blank');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  notify('Log summary opened in new tab. Use browser Print to save as PDF.');
}

// Parsed Data ZIP (password-protected)

function showPasswordModal(password) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay visible';
    overlay.id = 'exportPasswordModal';
    overlay.innerHTML = `
      <div class="modal">
        <h3>Parsed Data Password</h3>
        <p>The ZIP file will be encrypted with this password. Copy it before proceeding.</p>
        <div class="export-password-display">
          <code class="export-password-value">${escapeHtml(password)}</code>
          <button class="export-password-copy" id="exportPwCopy">Copy</button>
        </div>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="exportPwCancel">Cancel</button>
          <button class="modal-btn modal-btn-submit" id="exportPwProceed">Download ZIP</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

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

    if (passwords.rows.length > 0) {
      await addCsvFile('credentials.csv', passwords.headers, passwords.rows.map(({ row }) => row));
    }

    if (cookies.rows.length > 0) {
      await addCsvFile('cookies.csv', [...cookies.headers, 'Status', 'Session Type'], cookies.rows.map(({ row, validity, sessionType }) => {
        const typeLabel = sessionType === 'auth' ? 'Auth'
          : sessionType === 'session' ? 'Session'
          : sessionType === 'tracking' ? 'Tracking'
          : '';
        return [...row, validity.label, typeLabel];
      }));
    }

    if (autofills.entries.length > 0) {
      await addCsvFile('autofills.csv', ['Field', 'Value'], autofills.entries.map(
        ({ name, value }) => [name, value]
      ));
    }

    if (notes.entries.length > 0) {
      await addCsvFile('notes.csv', ['Title', 'Type', 'Indicators', 'Preview', 'URLs', 'Emails', 'Phones', 'Credential Hints', 'Wallet Hints', 'Source'], notes.entries.map((entry) => [
          entry.title,
          entry.noteType,
          entry.indicators,
          entry.preview,
          (entry.urls || []).join('; '),
          (entry.emails || []).join('; '),
          (entry.phones || []).join('; '),
          entry.credentialHints,
          entry.walletHints,
          entry.source,
        ]
      ));
    }

    if (history.entries.length > 0) {
      await addCsvFile('history.csv', ['URL', 'Title', 'Visits'], history.entries.map(
        ({ url, title, visitCount }) => [url, title, visitCount]
      ));
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
    if (passwords.rows.length > 0) parts.push(`${passwords.rows.length} credentials`);
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
    if (credsCounts) credsCounts.textContent = passwords.rows.length > 0 ? `${passwords.rows.length} credentials from ${passwords.fileCount} file(s)` : 'No credentials available';
    if (zipCounts) zipCounts.textContent = countsText || 'No data available';
  });

  on('reset', () => {
    sysinfoEntries = null;
    sysinfoIocs = null;
    fingerprintResult = null;
    identityResult = null;
    document.getElementById('navExports').disabled = true;

    const summaryCounts = document.getElementById('exportSummaryCounts');
    const credsCounts = document.getElementById('exportCredsCounts');
    const zipCounts = document.getElementById('exportZipCounts');
    if (summaryCounts) summaryCounts.textContent = '';
    if (credsCounts) credsCounts.textContent = '';
    if (zipCounts) zipCounts.textContent = '';
  });
}

export { initExports };
