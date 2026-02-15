// Exports

import { state, on } from './state.js';
import { loadFileContent } from './extractor.js';
import { escapeHtml } from './utils.js';
import { downloadBlob, copyToClipboard, extractDomain, extractBaseDomain, collectHintedNodes, showNotification } from './shared.js';
import { getPasswordsData, getCookiesData, getAutofillsData, getHistoryData, escapeCSV } from './dataPages.js';
import { FIELD_PATTERNS } from './definitions.js';

let sysinfoEntries = null;
let screenshotNode = null;
let fingerprintResult = null;
let identityResult = null;

function maskPassword(pw) {
  if (!pw || pw.length === 0) return '****';
  if (pw.length <= 2) return '****';
  return pw[0] + '*'.repeat(Math.min(pw.length - 2, 6)) + pw[pw.length - 1];
}

function notify(message, type = 'info') {
  showNotification(message, type);
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
    const key = `${url}\t${user}\t${pass}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueRows.push(row);
    }
  }

  let csv = data.headers.map(escapeCSV).join(',') + '\n';
  for (const row of uniqueRows) {
    const masked = row.map((cell, i) =>
      i === passIdx ? escapeCSV(maskPassword(cell)) : escapeCSV(cell)
    );
    csv += masked.join(',') + '\n';
  }

  downloadBlob(csv, 'credentials_obfuscated.csv', 'text/csv');
  notify(`Exported ${uniqueRows.length} unique credentials (passwords masked).`);
}

// Log Summary Report (HTML)

function gatherReportData() {
  const passwords = getPasswordsData();
  const cookies = getCookiesData();
  const autofills = getAutofillsData();
  const history = getHistoryData();

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
      seen.add(`${url}\t${user}\t${pass}`);
      const domain = extractBaseDomain(extractDomain(url));
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
    const sessionTokens = cookies.rows.filter(r => r.sessionType).length;
    const validSessionTokens = cookies.rows.filter(r => r.sessionType && r.validity.status === 'valid').length;
    const domainCounts = {};
    for (const { row } of cookies.rows) {
      const d = (row[0] || '').replace(/^\./, '').toLowerCase();
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
    const emails = [], phones = [], names = [];
    for (const { name, value } of autofills.entries) {
      const lower = name.toLowerCase();
      if (/email|e-mail/i.test(lower) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) emails.push(value);
      else if (/phone|mobile|tel/i.test(lower)) phones.push(value);
      else if (/first\s*name|last\s*name|^name$|full\s*name/i.test(lower)) names.push(value);
    }
    autoStats = {
      total: autofills.entries.length,
      fileCount: autofills.fileCount,
      emails: [...new Set(emails)],
      phones: [...new Set(phones)],
      names: [...new Set(names)],
    };
  }

  let histStats = null;
  if (history.entries.length > 0) {
    const domainCounts = {};
    for (const { url } of history.entries) {
      const domain = extractBaseDomain(extractDomain(url));
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
    timestamp: new Date().toISOString(),
    sysinfoEntries,
    fingerprintResult,
    identityResult,
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
    sections += `<section>
      <h2>Stealer Identification</h2>
      <div class="stat-row">
        <div class="stat" style="font-size:0.95rem;"><strong style="color:${confColor}">${e(fp.family)}</strong></div>
        <div class="stat">${e(fp.confidence.charAt(0).toUpperCase() + fp.confidence.slice(1))} confidence (${Math.round(fp.score * 100)}%)</div>
      </div>
      <h3>Matched Signals</h3>
      <ul style="font-size:0.8rem;color:#5f6672;padding-left:1.25rem;">${
        fp.matchedSignals.map(s => `<li>${e(s)}</li>`).join('')
      }</ul>
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
      <p class="note">Passwords are not included in this report for security.</p>
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
  const passwords = getPasswordsData();
  const cookies = getCookiesData();
  const autofills = getAutofillsData();
  const history = getHistoryData();

  const hasData = passwords.rows.length > 0 || cookies.rows.length > 0 ||
                  autofills.entries.length > 0 || history.entries.length > 0;
  if (!hasData) {
    notify('No parsed data available to package.', 'error');
    return;
  }

  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  const zipPassword = Array.from(array, b => charset[b % charset.length]).join('');

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

    if (passwords.rows.length > 0) {
      let csv = passwords.headers.map(escapeCSV).join(',') + '\n';
      for (const { row } of passwords.rows) {
        csv += row.map(escapeCSV).join(',') + '\n';
      }
      await addTextFile('credentials.csv', csv);
    }

    if (cookies.rows.length > 0) {
      const headers = [...cookies.headers, 'Status', 'Session Type'];
      let csv = headers.map(escapeCSV).join(',') + '\n';
      for (const { row, validity, sessionType } of cookies.rows) {
        const typeLabel = sessionType === 'auth' ? 'Auth' : sessionType === 'session' ? 'Session' : '';
        csv += [...row, validity.label, typeLabel].map(escapeCSV).join(',') + '\n';
      }
      await addTextFile('cookies.csv', csv);
    }

    if (autofills.entries.length > 0) {
      let csv = 'Field,Value\n';
      for (const { name, value } of autofills.entries) {
        csv += [name, value].map(escapeCSV).join(',') + '\n';
      }
      await addTextFile('autofills.csv', csv);
    }

    if (history.entries.length > 0) {
      let csv = 'URL,Title,Visits\n';
      for (const { url, title, visitCount } of history.entries) {
        csv += [url, title, visitCount].map(escapeCSV).join(',') + '\n';
      }
      await addTextFile('history.csv', csv);
    }

    if (screenshotNode) {
      try {
        const content = await loadFileContent(screenshotNode);
        if (content) {
          const ext = screenshotNode.name.split('.').pop().toLowerCase();
          const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', bmp: 'image/bmp', gif: 'image/gif', webp: 'image/webp' };
          const mime = mimeMap[ext] || 'image/png';
          const blob = new Blob([content], { type: mime });
          await writer.add('screenshot.' + ext, new zip.BlobReader(blob));
        }
      } catch {
        // skip
      }
    }

    await writer.close();
    const zipBlob = await blobWriter.getData();

    downloadBlob(zipBlob, 'parsed_data.zip', 'application/zip');
    notify('Parsed data package downloaded. Remember to securely share the password.');
  } catch (err) {
    notify(`Failed to generate data package: ${err.message}`, 'error');
  }
}

// Init

function initExports() {
  on('analysis:sysinfo', (data) => { if (data) sysinfoEntries = data.entries; });
  on('analysis:screenshot', (data) => { if (data && data.node) screenshotNode = data.node; });
  on('analysis:fingerprint', (data) => { fingerprintResult = data; });
  on('analysis:identity', (data) => { identityResult = data; });

  document.getElementById('exportIncidentSummary').addEventListener('click', exportLogSummary);
  document.getElementById('exportObfuscatedCreds').addEventListener('click', exportObfuscatedCredentials);
  document.getElementById('exportEvidenceZip').addEventListener('click', exportParsedDataZip);

  on('extracted', () => { document.getElementById('navExports').disabled = false; });

  // Update export card counts when data is loaded
  on('data:loaded', () => {
    const passwords = getPasswordsData();
    const cookies = getCookiesData();
    const autofills = getAutofillsData();
    const history = getHistoryData();

    const parts = [];
    if (passwords.rows.length > 0) parts.push(`${passwords.rows.length} credentials`);
    if (cookies.rows.length > 0) parts.push(`${cookies.rows.length} cookies`);
    if (autofills.entries.length > 0) parts.push(`${autofills.entries.length} autofills`);
    if (history.entries.length > 0) parts.push(`${history.entries.length} history entries`);
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
    screenshotNode = null;
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
