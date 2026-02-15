// Identity graph

import { on, emit } from './state.js';
import { getPasswordsData, getCookiesData, escapeCSV } from './dataPages.js';
import { extractDomain, extractBaseDomain, downloadBlob } from './shared.js';
import { escapeHtml } from './utils.js';
import { FIELD_PATTERNS, EMAIL_REGEX, IDENTITY_SYSINFO_KEYS } from './definitions.js';

function extractEmails(passwordsData, autofillEmails) {
  const emailMap = new Map();

  const urlIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.username.test(h));

  for (const { row } of passwordsData.rows) {
    const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
    const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
    if (user && EMAIL_REGEX.test(user)) {
      const lower = user.toLowerCase();
      if (!emailMap.has(lower)) emailMap.set(lower, new Set());
      const domain = extractBaseDomain(extractDomain(url));
      if (domain) emailMap.get(lower).add(domain);
    }
  }

  if (autofillEmails) {
    for (const email of autofillEmails) {
      const lower = email.toLowerCase();
      if (!emailMap.has(lower)) emailMap.set(lower, new Set());
    }
  }

  return emailMap;
}

function buildCookieLookup(cookiesData) {
  const lookup = new Map();
  for (const { row, validity, sessionType } of cookiesData.rows) {
    const domain = extractBaseDomain((row[0] || '').replace(/^\./, '').toLowerCase());
    if (!domain) continue;
    if (!lookup.has(domain)) lookup.set(domain, { hasValidSession: false, hasValidCookies: false });
    const entry = lookup.get(domain);
    if (validity.status === 'valid') {
      entry.hasValidCookies = true;
      if (sessionType) entry.hasValidSession = true;
    }
  }
  return lookup;
}

function extractPrimaryIdentity(sysinfoData, autofillData) {
  const identity = {
    names: [],
    emails: [],
    phones: [],
    location: null,
    osUsername: null,
    computerName: null,
  };

  if (sysinfoData && sysinfoData.entries) {
    for (const [key, value] of Object.entries(sysinfoData.entries)) {
      if (IDENTITY_SYSINFO_KEYS.osUsername.some(rx => rx.test(key))) identity.osUsername = value;
      if (IDENTITY_SYSINFO_KEYS.computerName.some(rx => rx.test(key))) identity.computerName = value;
      if (IDENTITY_SYSINFO_KEYS.country.some(rx => rx.test(key))) identity.location = value;
    }
  }

  if (autofillData) {
    if (autofillData.names) identity.names = [...autofillData.names];
    if (autofillData.emails) identity.emails = [...autofillData.emails];
    if (autofillData.phones) identity.phones = [...autofillData.phones];
    if (!identity.location && autofillData.addresses && autofillData.addresses.length > 0) {
      identity.location = autofillData.addresses[0];
    }
  }

  return identity;
}

function buildAccountList(credentialDomains, cookieLookup, emailMap) {
  const accounts = new Map();

  for (const domain of credentialDomains) {
    if (!accounts.has(domain)) {
      accounts.set(domain, {
        domain, hasCredentials: true,
        hasValidSession: false, emails: [],
      });
    }
    const entry = accounts.get(domain);
    const cookieInfo = cookieLookup.get(domain);
    if (cookieInfo && cookieInfo.hasValidSession) entry.hasValidSession = true;
  }

  for (const [email, domains] of emailMap) {
    for (const domain of domains) {
      if (accounts.has(domain)) {
        accounts.get(domain).emails.push(email);
      }
    }
  }

  for (const acct of accounts.values()) {
    acct.emails = [...new Set(acct.emails)];
  }

  return [...accounts.values()].sort((a, b) => {
    if (a.hasValidSession !== b.hasValidSession) return a.hasValidSession ? -1 : 1;
    return a.domain.localeCompare(b.domain);
  });
}

function buildIdentityProfile(passwordsData, cookiesData, sysinfoData, autofillData) {
  const hasCredentials = passwordsData.rows.length > 0;
  const hasCookies = cookiesData.rows.length > 0;
  const hasSysinfo = sysinfoData && sysinfoData.entries;
  const hasAutofill = autofillData && autofillData.totalEntries > 0;

  if (!hasCredentials && !hasCookies && !hasSysinfo && !hasAutofill) return null;

  const primaryIdentity = extractPrimaryIdentity(sysinfoData, autofillData);
  const emailMap = extractEmails(passwordsData, autofillData ? autofillData.emails : null);
  const cookieLookup = buildCookieLookup(cookiesData);

  // Unique credential domains (skip empty rows)
  const urlIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
  const passIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.password.test(h));
  const allCredDomains = new Set();
  for (const { row } of passwordsData.rows) {
    const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
    const pass = passIdx >= 0 ? (row[passIdx] || '').trim() : '';
    if (!user && !pass) continue;
    const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
    const domain = extractBaseDomain(extractDomain(url));
    if (domain) allCredDomains.add(domain);
  }

  const emailAccountMap = [];
  for (const [email, domains] of emailMap) {
    const services = [...domains].map(domain => {
      const cookieInfo = cookieLookup.get(domain);
      return {
        domain,
        hasValidSession: cookieInfo ? cookieInfo.hasValidSession : false,
      };
    }).sort((a, b) => {
      if (a.hasValidSession !== b.hasValidSession) return a.hasValidSession ? -1 : 1;
      return a.domain.localeCompare(b.domain);
    });
    emailAccountMap.push({ email, services });
  }
  emailAccountMap.sort((a, b) => b.services.length - a.services.length);

  const accounts = buildAccountList(allCredDomains, cookieLookup, emailMap);

  const servicesWithValidSessions = new Set();
  const servicesWithBoth = new Set();
  for (const domain of allCredDomains) {
    const cookieInfo = cookieLookup.get(domain);
    if (cookieInfo && cookieInfo.hasValidSession) {
      servicesWithValidSessions.add(domain);
      servicesWithBoth.add(domain);
    }
  }
  for (const [domain, info] of cookieLookup) {
    if (info.hasValidSession) servicesWithValidSessions.add(domain);
  }

  const exposureSummary = {
    totalUniqueServices: allCredDomains.size,
    servicesWithValidSessions: servicesWithValidSessions.size,
    servicesWithBothPasswordAndSession: servicesWithBoth.size,
    uniqueEmails: emailMap.size,
  };

  return {
    primaryIdentity, emailAccountMap, exposureSummary,
    accounts,
  };
}

function initIdentityGraph() {
  let dataLoaded = false;
  let sysinfoData = null;
  let sysinfoReceived = false;
  let autofillData = null;
  let autofillReceived = false;

  function tryBuild() {
    if (!dataLoaded || !sysinfoReceived || !autofillReceived) return;
    const result = buildIdentityProfile(
      getPasswordsData(), getCookiesData(), sysinfoData, autofillData
    );
    emit('analysis:identity', result);
  }

  on('data:loaded', () => { dataLoaded = true; tryBuild(); });
  on('analysis:sysinfo', (d) => { sysinfoData = d; sysinfoReceived = true; tryBuild(); });
  on('analysis:autofill', (d) => { autofillData = d; autofillReceived = true; tryBuild(); });

  on('reset', () => {
    dataLoaded = false;
    sysinfoData = null;
    sysinfoReceived = false;
    autofillData = null;
    autofillReceived = false;
  });
}

let identityData = null;

function renderIdentityPage(searchQuery = '') {
  const summary = document.getElementById('identitySummary');
  const statsEl = document.getElementById('identityStats');
  const primaryEl = document.getElementById('identityPrimary');
  const contentEl = document.getElementById('identityContent');
  const emailMapEl = document.getElementById('identityEmailMap');

  if (!identityData) {
    summary.textContent = 'No identity data available.';
    statsEl.innerHTML = '';
    primaryEl.innerHTML = '';
    contentEl.innerHTML = '<div class="no-data">No identity data available.</div>';
    emailMapEl.innerHTML = '';
    return;
  }

  const data = identityData;

  const emailCount = data.emailAccountMap.length;
  const sessions = data.exposureSummary.servicesWithValidSessions;
  summary.textContent = `${data.exposureSummary.totalUniqueServices} services with saved credentials \u2014 ${sessions} active session${sessions !== 1 ? 's' : ''}, ${emailCount} linked email${emailCount !== 1 ? 's' : ''}`;

  const es = data.exposureSummary;
  let statsHtml = '';
  statsHtml += `<div class="data-page-stat"><div class="data-page-stat-value">${es.totalUniqueServices}</div><div class="data-page-stat-label">Services</div></div>`;
  statsHtml += `<div class="data-page-stat"><div class="data-page-stat-value" style="color:var(--warning)">${es.servicesWithValidSessions}</div><div class="data-page-stat-label">Active Sessions</div></div>`;
  statsHtml += `<div class="data-page-stat"><div class="data-page-stat-value" style="color:var(--error)">${es.servicesWithBothPasswordAndSession}</div><div class="data-page-stat-label">Cred + Session</div></div>`;
  statsHtml += `<div class="data-page-stat"><div class="data-page-stat-value">${es.uniqueEmails}</div><div class="data-page-stat-label">Email Addresses</div></div>`;
  statsEl.innerHTML = statsHtml;

  const pi = data.primaryIdentity;
  const fields = [];
  if (pi.names.length > 0) fields.push({ label: 'Name', value: pi.names.join(', ') });
  if (pi.emails.length > 0) fields.push({ label: 'Email', value: pi.emails.join(', ') });
  if (pi.phones.length > 0) fields.push({ label: 'Phone', value: pi.phones.join(', ') });
  if (pi.osUsername) fields.push({ label: 'OS User', value: pi.osUsername });
  if (pi.computerName) fields.push({ label: 'Computer', value: pi.computerName });
  if (pi.location) fields.push({ label: 'Location', value: pi.location });

  if (fields.length > 0) {
    primaryEl.innerHTML = '<div class="identity-grid">' + fields.map(f =>
      `<div class="identity-field">
        <span class="identity-field-label">${escapeHtml(f.label)}</span>
        <span class="identity-field-value">${escapeHtml(f.value)}</span>
      </div>`
    ).join('') + '</div>';
  } else {
    primaryEl.innerHTML = '';
  }

  let accounts = data.accounts;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    accounts = accounts.filter(a =>
      a.domain.toLowerCase().includes(q) ||
      a.emails.some(e => e.toLowerCase().includes(q))
    );
  }

  if (accounts.length > 0) {
    let tableHtml = '<div class="data-table-container"><table class="data-table">';
    tableHtml += '<thead><tr><th>Domain</th><th>Credentials</th><th>Session</th><th>Emails</th></tr></thead><tbody>';
    for (const acct of accounts) {
      const sessionHtml = acct.hasValidSession
        ? '<span class="identity-session-badge">Active</span>'
        : '<span style="color:var(--text-muted)">\u2014</span>';
      const credHtml = acct.hasCredentials
        ? '<span style="color:var(--success)">Yes</span>'
        : '<span style="color:var(--text-muted)">\u2014</span>';
      const emailsHtml = acct.emails.length > 0
        ? acct.emails.map(e => escapeHtml(e)).join(', ')
        : '<span style="color:var(--text-muted)">\u2014</span>';
      tableHtml += `<tr>
        <td><span class="identity-account-domain">${escapeHtml(acct.domain)}</span></td>
        <td>${credHtml}</td>
        <td>${sessionHtml}</td>
        <td style="font-size:0.75rem">${emailsHtml}</td>
      </tr>`;
    }
    tableHtml += '</tbody></table></div>';
    contentEl.innerHTML = tableHtml;
  } else if (searchQuery) {
    contentEl.innerHTML = '<div class="no-data">No accounts match the search query.</div>';
  } else {
    contentEl.innerHTML = '<div class="no-data">No account data found.</div>';
  }

  if (data.emailAccountMap.length > 0 && !searchQuery) {
    let mapHtml = '<div class="identity-subsection"><div class="identity-subsection-title">Email &rarr; Account Mapping</div>';
    for (const entry of data.emailAccountMap) {
      mapHtml += '<div class="identity-email-group">';
      mapHtml += `<div class="identity-email-addr">${escapeHtml(entry.email)}</div>`;
      mapHtml += '<div class="identity-service-tags">';
      for (const svc of entry.services) {
        const cls = svc.hasValidSession ? ' has-session' : '';
        mapHtml += `<span class="identity-service-tag${cls}">${escapeHtml(svc.domain)}</span>`;
      }
      mapHtml += '</div></div>';
    }
    mapHtml += '</div>';
    emailMapEl.innerHTML = mapHtml;
  } else {
    emailMapEl.innerHTML = '';
  }
}

function exportIdentityCSV() {
  if (!identityData || identityData.accounts.length === 0) return;
  let csv = 'Domain,Credentials,Session Active,Emails\n';
  for (const acct of identityData.accounts) {
    csv += [
      acct.domain,
      acct.hasCredentials ? 'Yes' : 'No',
      acct.hasValidSession ? 'Yes' : 'No',
      acct.emails.join('; '),
    ].map(escapeCSV).join(',') + '\n';
  }

  downloadBlob(csv, 'identity_accounts.csv', 'text/csv');
}

function initIdentityPage() {
  on('analysis:identity', (data) => {
    identityData = data;
    if (data) {
      document.getElementById('navIdentity').disabled = false;
    }
  });

  on('page:identity', () => {
    const search = document.getElementById('identitySearch');
    renderIdentityPage(search?.value || '');
  });

  const search = document.getElementById('identitySearch');
  let debounce = null;
  search?.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      renderIdentityPage(search.value);
    }, 150);
  });

  document.getElementById('exportIdentityCsv')?.addEventListener('click', exportIdentityCSV);

  on('reset', () => {
    identityData = null;
    document.getElementById('navIdentity').disabled = true;
    const searchEl = document.getElementById('identitySearch');
    if (searchEl) searchEl.value = '';
  });
}

export { initIdentityGraph, initIdentityPage };
