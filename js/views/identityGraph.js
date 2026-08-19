import { on, emit } from '../core/state.js';
import { bindDebouncedInput, bindTableSort, countLabel, createTableSort, downloadCsvRows } from '../pages/shared.js';
import { getPasswordsData, getCookiesData } from '../pages/credentials.js';
import { getAccountTokensData } from '../pages/assets.js';
import { collectCurrentnessInput } from './currentnessLab.js';
import { credentialColumnIndices, extractBaseDomain, baseDomainFromUrl } from '../core/shared.js';
import { deriveVictimCountry } from '../app/dashboard.js';
import { isReplayableSessionToken } from '../analysis/sessionCookies.js';
import { resolvePrimaryIdentity } from '../analysis/credentialCurrentness.js';
import { escapeHtml } from '../core/utils.js';
import { FIELD_PATTERNS, EMAIL_REGEX, IDENTITY_SYSINFO_KEYS } from '../core/definitions/patterns.js';

const USER_SOURCE_LABEL = { sysinfo: 'system info', autofill: 'autofill', email: 'email', hostname: 'hostname', unknown: 'unknown' };

// A readable head plus the count of what was left off. Forty usernames in one
// cell is a comma run nobody reads; the full list stays on the cell's title.
function capList(values, limit = 3) {
  const list = values || [];
  if (list.length === 0) return '';
  return list.slice(0, limit).join(', ') + (list.length > limit ? ` +${list.length - limit} more` : '');
}

const accountsSort = createTableSort({
  service: (account) => account.domain,
  usernames: (account) => account.usernames.join(', '),
  session: (account) => (account.hasLiveSession ? 1 : 0),
  emails: (account) => account.emails.join(', '),
  tokens: (account) => [...account.tokenServices, ...account.accountIds].join(', '),
});

// Clicking back through the sort cycle returns the table to this ordering, so
// the caption has to name it.
const RANK_CAPTION = 'Ordered by exposure: live sessions first, then stored passwords.';

function classifyOS(raw) {
  const v = String(raw || '').toLowerCase();
  if (!v) return null;
  if (v.includes('windows') || /\bwin\s*\d/.test(v)) return 'Windows';
  if (v.includes('mac') || v.includes('darwin') || v.includes('os x')) return 'macOS';
  if (v.includes('linux') || v.includes('ubuntu') || v.includes('debian') || v.includes('fedora') || v.includes('arch')) return 'Linux';
  return null;
}

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
      const domain = baseDomainFromUrl(url);
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
  const domainIdx = cookiesData.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
  const valueIdx = cookiesData.headers.findIndex(h => /^value$/i.test(h));
  for (const rowData of cookiesData.rows) {
    const host = (domainIdx >= 0 ? (rowData.row[domainIdx] || '') : '').replace(/^\./, '').toLowerCase();
    const domain = extractBaseDomain(host);
    if (!domain) continue;
    if (!lookup.has(domain)) lookup.set(domain, { hasLiveSession: false });
    // The badge says the account can be walked into, so it takes a token that
    // was live *and* whose value survived: a decryption failure empties the
    // value column wholesale, and those rows hand over nothing.
    const value = valueIdx >= 0 ? rowData.row[valueIdx] : '';
    if (isReplayableSessionToken({ ...rowData, value })) {
      lookup.get(domain).hasLiveSession = true;
    }
  }
  return lookup;
}

function mapServiceToDomain(service) {
  const lower = String(service || '').toLowerCase();
  if (lower.includes('google')) return 'google.com';
  if (lower.includes('discord')) return 'discord.com';
  if (lower.includes('steam')) return 'steampowered.com';
  if (lower.includes('facebook')) return 'facebook.com';
  if (lower.includes('telegram')) return 'telegram.org';
  if (lower.includes('outlook')) return 'outlook.live.com';
  if (lower.includes('anydesk')) return 'anydesk.com';
  return '';
}

// A token whose service maps to no domain still evidences an account, and the
// Assets page lists it. It keeps a row of its own here, named by whatever
// provenance the entry carries, rather than disappearing from the join.
function unresolvedTokenKey(entry) {
  const service = String(entry.service || '').trim();
  const named = service && !/^unknown$/i.test(service) ? service : 'Unknown service';
  const file = String(entry.source || '').split(/[\\/]/).pop().replace(/\.[^.]+$/, '');
  const scope = entry.browser ? [entry.browser, entry.profile].filter(Boolean).join(' ') : file;
  return scope ? `${named} (${scope})` : named;
}

function buildTokenLookup(accountTokensData) {
  const lookup = new Map();
  for (const entry of accountTokensData?.entries || []) {
    // Mappings name each service's public host; every other key on this page is
    // a base domain, so an `outlook.live.com` would never meet its `live.com` row.
    const domain = extractBaseDomain(mapServiceToDomain(entry.service));
    const key = domain || unresolvedTokenKey(entry);
    if (!lookup.has(key)) {
      lookup.set(key, { services: new Set(), accountIds: new Set() });
    }
    const item = lookup.get(key);
    if (entry.service) item.services.add(entry.service);
    if (entry.accountId) item.accountIds.add(entry.accountId);
  }
  return lookup;
}

function extractPrimaryIdentity(sysinfoData, autofillData) {
  const identity = {
    names: [],
    emails: [],
    phones: [],
    location: null,
    locationSource: null,
    autofillAddress: null,
    autofillAddressCount: 0,
    osUsername: null,
    computerName: null,
    os: null,
    osFamily: null,
    userSource: null,
  };

  if (sysinfoData && sysinfoData.entries) {
    for (const [key, value] of Object.entries(sysinfoData.entries)) {
      if (IDENTITY_SYSINFO_KEYS.osUsername.some(rx => rx.test(key))) identity.osUsername = value;
      if (IDENTITY_SYSINFO_KEYS.computerName.some(rx => rx.test(key))) identity.computerName = value;
      if (!identity.os && IDENTITY_SYSINFO_KEYS.os.some(rx => rx.test(key))) identity.os = value;
    }
  }
  identity.osFamily = classifyOS(identity.os);

  // The dashboard's resolver, not a second one: the two surfaces quote the
  // same country for the same archive, from the same order of evidence.
  const location = deriveVictimCountry(sysinfoData, autofillData);
  identity.location = location.value || null;
  identity.locationSource = location.value ? location.source : null;

  if (autofillData) {
    if (autofillData.names) identity.names = [...autofillData.names];
    if (autofillData.emails) identity.emails = [...autofillData.emails];
    if (autofillData.phones) identity.phones = [...autofillData.phones];
    // A stored street address is a form value, not where the host sits: it may
    // be a delivery address for someone else, a workplace or a former home. It
    // is reported as itself, with the number of candidates the longest one was
    // picked from. Bare postcodes / suburb names (`4113`) are dropped.
    const addresses = (autofillData.addresses || [])
      .map(addr => String(addr || '').trim())
      .filter(addr => addr.length >= 8);
    if (addresses.length > 0) {
      identity.autofillAddress = [...addresses].sort((a, b) => b.length - a.length)[0];
      identity.autofillAddressCount = addresses.length;
    }
  }

  const sysUser = (identity.osUsername || '').trim();
  if (sysUser) {
    identity.osUsername = sysUser;
    identity.userSource = 'sysinfo';
  } else if (identity.names.length > 0 && identity.names[0].trim()) {
    identity.osUsername = identity.names[0].trim();
    identity.userSource = 'autofill';
  } else {
    const emailSrc = identity.emails.find(em => em && em.includes('@'));
    if (emailSrc) {
      identity.osUsername = emailSrc.split('@')[0];
      identity.userSource = 'email';
    } else if (identity.computerName && identity.computerName.trim()) {
      identity.osUsername = identity.computerName.trim();
      identity.userSource = 'hostname';
    } else {
      identity.userSource = 'unknown';
    }
  }

  return identity;
}

function buildAccountList(domainUsernames, passwordDomains, cookieLookup, emailMap, tokenLookup) {
  const accounts = new Map();

  const allDomains = new Set([
    ...domainUsernames.keys(),
    ...[...cookieLookup.entries()].filter(([, value]) => value.hasLiveSession).map(([domain]) => domain),
    ...tokenLookup.keys(),
  ]);

  for (const domain of allDomains) {
    if (!accounts.has(domain)) {
      accounts.set(domain, {
        domain,
        usernames: [],
        hasLiveSession: false,
        hasCredentials: false,
        hasPassword: false,
        emails: [],
        tokenServices: [],
        accountIds: [],
      });
    }
    const entry = accounts.get(domain);
    if (domainUsernames.has(domain)) {
      entry.usernames = [...domainUsernames.get(domain)];
      entry.hasCredentials = true;
    }
    if (passwordDomains.has(domain)) entry.hasPassword = true;
    const cookieInfo = cookieLookup.get(domain);
    if (cookieInfo && cookieInfo.hasLiveSession) entry.hasLiveSession = true;
    const tokenInfo = tokenLookup.get(domain);
    if (tokenInfo) {
      entry.tokenServices = [...tokenInfo.services];
      entry.accountIds = [...tokenInfo.accountIds];
    }
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
    if (a.hasLiveSession !== b.hasLiveSession) return a.hasLiveSession ? -1 : 1;
    if (a.hasPassword !== b.hasPassword) return a.hasPassword ? -1 : 1;
    if (a.hasCredentials !== b.hasCredentials) return a.hasCredentials ? -1 : 1;
    return a.domain.localeCompare(b.domain);
  });
}

function buildIdentityProfile(passwordsData, cookiesData, accountTokensData, sysinfoData, autofillData, primaryEmail) {
  const hasCredentials = passwordsData.rows.length > 0;
  const hasCookies = cookiesData.rows.length > 0;
  const hasTokens = accountTokensData && accountTokensData.entries && accountTokensData.entries.length > 0;
  const hasSysinfo = sysinfoData && sysinfoData.entries;
  const hasAutofill = autofillData && autofillData.totalEntries > 0;

  if (!hasCredentials && !hasCookies && !hasTokens && !hasSysinfo && !hasAutofill) return null;

  const primaryIdentity = extractPrimaryIdentity(sysinfoData, autofillData);
  const emailMap = extractEmails(passwordsData, autofillData ? autofillData.emails : null);
  const cookieLookup = buildCookieLookup(cookiesData);
  const tokenLookup = buildTokenLookup(accountTokensData);

  // Credential domains with usernames (skip empty rows)
  const { urlIdx, userIdx, passIdx } = credentialColumnIndices(passwordsData.headers);
  const domainUsernames = new Map(); // domain -> Set<username>
  const passwordDomains = new Set();
  for (const { row } of passwordsData.rows) {
    const user = userIdx >= 0 ? (row[userIdx] || '').trim() : '';
    const pass = passIdx >= 0 ? (row[passIdx] || '').trim() : '';
    if (!user && !pass) continue;
    const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
    const domain = baseDomainFromUrl(url);
    if (domain) {
      if (!domainUsernames.has(domain)) domainUsernames.set(domain, new Set());
      if (user) domainUsernames.get(domain).add(user);
      if (pass) passwordDomains.add(domain);
    }
  }
  const allCredDomains = new Set(domainUsernames.keys());

  const emailAccountMap = [];
  for (const [email, domains] of emailMap) {
    const services = [...domains].map(domain => {
      const cookieInfo = cookieLookup.get(domain);
      return {
        domain,
        hasLiveSession: cookieInfo ? cookieInfo.hasLiveSession : false,
      };
    }).sort((a, b) => {
      if (a.hasLiveSession !== b.hasLiveSession) return a.hasLiveSession ? -1 : 1;
      return a.domain.localeCompare(b.domain);
    });
    emailAccountMap.push({ email, services });
  }
  // The index leads with whoever the shared resolver ranked first, so the
  // address at the top of this list is the one the Triage page names.
  const rank = new Map((primaryEmail?.candidates || []).map((entry, index) => [entry.email, index]));
  const rankOf = (email) => rank.get(email) ?? Number.MAX_SAFE_INTEGER;
  emailAccountMap.sort((a, b) => rankOf(a.email) - rankOf(b.email) || b.services.length - a.services.length);

  const accounts = buildAccountList(domainUsernames, passwordDomains, cookieLookup, emailMap, tokenLookup);

  const servicesWithBoth = new Set();
  for (const domain of passwordDomains) {
    const cookieInfo = cookieLookup.get(domain);
    if (cookieInfo && cookieInfo.hasLiveSession) servicesWithBoth.add(domain);
  }
  const servicesWithLiveSessions = new Set();
  for (const [domain, info] of cookieLookup) {
    if (info.hasLiveSession) servicesWithLiveSessions.add(domain);
  }
  const tokenDomains = new Set(tokenLookup.keys());

  const exposureSummary = {
    totalUniqueServices: new Set([...allCredDomains, ...servicesWithLiveSessions, ...tokenDomains]).size,
    servicesWithLiveSessions: servicesWithLiveSessions.size,
    servicesWithBothPasswordAndSession: servicesWithBoth.size,
    uniqueEmails: emailMap.size,
    tokenBackedServices: tokenDomains.size,
  };

  return {
    primaryIdentity, primaryEmail, emailAccountMap, exposureSummary,
    accounts,
  };
}

function initIdentityGraph() {
  let dataLoaded = false;
  let sysinfoData = null;
  let sysinfoReceived = false;
  let autofillData = null;
  let autofillReceived = false;

  function clearGating() {
    dataLoaded = false;
    sysinfoData = null;
    sysinfoReceived = false;
    autofillData = null;
    autofillReceived = false;
  }

  function tryBuild() {
    if (!dataLoaded || !sysinfoReceived || !autofillReceived) return;
    const result = buildIdentityProfile(
      getPasswordsData(), getCookiesData(), getAccountTokensData(), sysinfoData, autofillData,
      resolvePrimaryIdentity(collectCurrentnessInput())
    );
    emit('analysis:identity', result);
  }

  on('data:loaded', () => { dataLoaded = true; tryBuild(); });
  on('analysis:sysinfo', (d) => { sysinfoData = d; sysinfoReceived = true; tryBuild(); });
  on('analysis:autofill', (d) => { autofillData = d; autofillReceived = true; tryBuild(); });

  // Analysers run under allSettled, so a throwing one never emits its event.
  // Build from what did arrive rather than leaving the page blank forever.
  on('analysis:complete', () => {
    if (sysinfoReceived && autofillReceived) return;
    sysinfoReceived = true;
    autofillReceived = true;
    tryBuild();
  });

  on('reanalyze', clearGating);
  on('reset', clearGating);
}

let identityData = null;
let identityActiveEmail = null;
let identityShowAllEmails = false;

function isIdentityPageActive() {
  return document.querySelector('.sidebar-nav-item.active')?.dataset.page === 'identity';
}

// Compact, filterable index of identities. Replaces the wall of one-card-per
// -email chip grids: clicking an identity filters the accounts table.
function buildEmailIndex(data) {
  const map = data.emailAccountMap;
  if (!map.length) return '';
  const CAP = 15;
  const shown = identityShowAllEmails ? map : map.slice(0, CAP);
  const rows = shown.map((entry) => {
    const active = entry.email === identityActiveEmail ? ' active' : '';
    const hasSession = entry.services.some((s) => s.hasLiveSession);
    const dot = hasSession ? '<span class="identity-email-dot" title="Has a session live at capture"></span>' : '';
    return `<button class="identity-email-row${active}" type="button" data-email="${escapeHtml(entry.email)}">
      <span class="identity-email-addr">${escapeHtml(entry.email)}</span>
      <span class="identity-email-count">${entry.services.length}</span>${dot}
    </button>`;
  }).join('');
  const moreBtn = map.length > CAP
    ? `<button class="identity-email-more" type="button">${identityShowAllEmails ? 'Show fewer' : `Show all ${map.length}`}</button>`
    : '';
  return `<div class="identity-email-index">
    <div class="identity-subsection-title">Identities (${map.length})</div>
    <div class="identity-email-list">${rows}</div>
    ${moreBtn}
  </div>`;
}

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
    identityActiveEmail = null;
    return;
  }

  const data = identityData;
  const es = data.exposureSummary;

  const summaryText = `${es.totalUniqueServices} exposed services across ${es.uniqueEmails} email address${es.uniqueEmails !== 1 ? 'es' : ''}; ${es.servicesWithLiveSessions} with a session live at capture`;
  const osFamily = data.primaryIdentity.osFamily;
  summary.innerHTML = osFamily
    ? `${escapeHtml(summaryText)} <span class="identity-os-chip" data-os="${escapeHtml(osFamily)}">${escapeHtml(osFamily)}</span>`
    : escapeHtml(summaryText);

  // Counts are quantities, not statuses: neutral ink, weight for scanning.
  statsEl.innerHTML = [
    ['Services', es.totalUniqueServices],
    ['Live at capture', es.servicesWithLiveSessions],
    ['Password + session', es.servicesWithBothPasswordAndSession],
    ['Token-backed', es.tokenBackedServices],
    ['Email addresses', es.uniqueEmails],
  ].map(([label, value]) =>
    `<div class="data-page-stat"><div class="data-page-stat-value">${value.toLocaleString()}</div><div class="data-page-stat-label">${label}</div></div>`
  ).join('');

  // Primary identity: one compact block. Email addresses are a count that links
  // to the Identities index below, not a wall of every address in one cell.
  const pi = data.primaryIdentity;
  const pe = data.primaryEmail;
  const fields = [];
  // The address the case is about, and what put it first — the same ranking
  // Credential triage headlines, so the two pages cannot name different people.
  if (pe?.email) {
    const why = [...(pe.evidence || []), pe.tentative ? 'no corroborating activity' : ''].filter(Boolean).join(' · ');
    fields.push(['Primary identity', why ? `${pe.email} — ${why}` : pe.email]);
  }
  if (pi.names.length > 0) fields.push(['Name', capList(pi.names)]);
  if (pi.osUsername) fields.push(['OS user', pi.userSource && pi.userSource !== 'sysinfo' ? `${pi.osUsername} (from ${USER_SOURCE_LABEL[pi.userSource]})` : pi.osUsername]);
  if (pi.computerName) fields.push(['Computer', pi.computerName]);
  if (pi.os) fields.push(['OS', pi.os]);
  if (pi.location) fields.push(['Location', pi.locationSource && pi.locationSource !== 'sysinfo' ? `${pi.location} (from ${pi.locationSource})` : pi.location]);
  if (pi.autofillAddress) {
    fields.push(['Autofill address', pi.autofillAddressCount > 1
      ? `${pi.autofillAddress} (1 of ${countLabel(pi.autofillAddressCount, 'autofill address', 'autofill addresses')})`
      : pi.autofillAddress]);
  }
  if (pi.phones.length > 0) fields.push(['Phone', capList(pi.phones)]);

  const fieldsHtml = fields.length > 0
    ? '<div class="identity-grid">' + fields.map(([label, value]) =>
      `<div class="identity-field"><span class="identity-field-label">${escapeHtml(label)}</span><span class="identity-field-value">${escapeHtml(value)}</span></div>`
    ).join('') + '</div>'
    : '';
  primaryEl.innerHTML = fieldsHtml + buildEmailIndex(data);

  let accounts = data.accounts;
  if (identityActiveEmail) accounts = accounts.filter(a => a.emails.includes(identityActiveEmail));
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    accounts = accounts.filter(a =>
      a.domain.toLowerCase().includes(q) ||
      a.emails.some(e => e.toLowerCase().includes(q)) ||
      (a.usernames && a.usernames.some(u => u.toLowerCase().includes(q))) ||
      (a.tokenServices && a.tokenServices.some(s => s.toLowerCase().includes(q))) ||
      (a.accountIds && a.accountIds.some(id => id.toLowerCase().includes(q)))
    );
  }

  const filterCaption = identityActiveEmail
    ? `<div class="data-table-caption">Accounts for <strong>${escapeHtml(identityActiveEmail)}</strong> <button class="identity-clear-filter" type="button">show all</button></div>`
    : '';

  if (accounts.length > 0) {
    const dash = '<span class="cell-empty">\u2014</span>';
    let tableHtml = filterCaption + '<div class="data-table-container"><table class="data-table">';
    tableHtml += '<thead><tr><th>Domain</th><th>Usernames</th><th>Session</th><th>Emails</th><th>Tokens</th></tr></thead><tbody>';
    for (const acct of accounts) {
      const sessionHtml = acct.hasLiveSession ? '<span class="identity-session-badge">live at capture</span>' : dash;
      const usernames = acct.usernames && acct.usernames.length > 0 ? acct.usernames.join(', ') : '';
      const emails = acct.emails.length > 0 ? acct.emails.join(', ') : '';
      const tokens = [acct.tokenServices.join(', '), acct.accountIds.join(', ')].filter(Boolean).join(' \u00B7 ');
      tableHtml += `<tr>
        <td><span class="identity-account-domain">${escapeHtml(acct.domain)}</span></td>
        <td title="${escapeHtml(usernames)}">${usernames ? escapeHtml(usernames) : dash}</td>
        <td>${sessionHtml}</td>
        <td title="${escapeHtml(emails)}">${emails ? escapeHtml(emails) : dash}</td>
        <td title="${escapeHtml(tokens)}">${tokens ? escapeHtml(tokens) : dash}</td>
      </tr>`;
    }
    tableHtml += '</tbody></table></div>';
    contentEl.innerHTML = tableHtml;
  } else {
    contentEl.innerHTML = `${filterCaption}<div class="no-data">No accounts match the current filter.</div>`;
  }

  // Selected identity: full domain list as plain, copyable text, not a chip wall.
  if (identityActiveEmail) {
    const entry = data.emailAccountMap.find(e => e.email === identityActiveEmail);
    emailMapEl.innerHTML = entry && entry.services.length > 0
      ? `<div class="identity-subsection"><div class="identity-subsection-title">Domains for ${escapeHtml(identityActiveEmail)} (${entry.services.length})</div><div class="identity-domain-list">${entry.services.map(s => escapeHtml(s.domain)).join(', ')}</div></div>`
      : '';
  } else {
    emailMapEl.innerHTML = '';
  }
}

function exportIdentityCSV() {
  if (!identityData || identityData.accounts.length === 0) return;
  downloadCsvRows('identity_accounts.csv', ['Service', 'Usernames', 'Password', 'Live Session', 'Emails', 'Token Services', 'Account IDs'], identityData.accounts.map((account) => [
    account.domain,
    account.usernames.join('; '),
    account.hasPassword ? 'Yes' : 'No',
    account.hasLiveSession ? 'Yes' : 'No',
    account.emails.join('; '),
    account.tokenServices.join('; '),
    account.accountIds.join('; '),
  ]));
}

function initIdentityPage() {
  on('analysis:identity', (data) => {
    identityData = data;
    document.getElementById('navIdentity').disabled = !data;
    if (isIdentityPageActive()) {
      const search = document.getElementById('identitySearch');
      renderIdentityPage(search?.value || '');
    }
  });

  on('page:identity', () => {
    const search = document.getElementById('identitySearch');
    renderIdentityPage(search?.value || '');
  });

  const search = document.getElementById('identitySearch');
  bindDebouncedInput(search, (value) => renderIdentityPage(value));

  // Identities index: select an email to filter the accounts table to it.
  document.getElementById('identityPrimary')?.addEventListener('click', (event) => {
    const row = event.target.closest('.identity-email-row');
    if (row) {
      const email = row.dataset.email;
      identityActiveEmail = identityActiveEmail === email ? null : email;
      renderIdentityPage(search?.value || '');
      return;
    }
    if (event.target.closest('.identity-email-more')) {
      identityShowAllEmails = !identityShowAllEmails;
      renderIdentityPage(search?.value || '');
    }
  });

  document.getElementById('identityContent')?.addEventListener('click', (event) => {
    if (event.target.closest('.identity-clear-filter')) {
      identityActiveEmail = null;
      renderIdentityPage(search?.value || '');
    }
  });

  document.getElementById('exportIdentityCsv')?.addEventListener('click', exportIdentityCSV);

  on('reset', () => {
    identityData = null;
    identityActiveEmail = null;
    identityShowAllEmails = false;
    document.getElementById('navIdentity').disabled = true;
    const searchEl = document.getElementById('identitySearch');
    if (searchEl) searchEl.value = '';
  });
}

export { initIdentityGraph, initIdentityPage };
